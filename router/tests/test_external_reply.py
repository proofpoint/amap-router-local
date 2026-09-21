"""Round 3, item 3 — the one branch `_drain_reply` grew for a record that
binds OUTSIDE the fleet (delivery_design.md §7.x).

Nothing in this repo writes such a record: the combined runtime's inbound
SMTP leg does, under the RECIPIENT instance, with `from_instance: null`,
`from_address: <the external sender>`, `transport: "smtp"`,
`origin: "external"`, `tree: "inbox"`. So every record here is synthetic,
written straight into the router-private ledger, and the backend is a fake —
what is under test is the three-part test, the hand-off shape
(`deliver.DeliveryBackend`, "THE ONE EXTENSION": `recipient=None`, the
record as `reply_to_record`), the result the sender sees, and that the
default local backend refuses, fail closed, without touching a tree.
"""
import json
import unittest

from router import binding, deliver as deliver_mod, outbound
from router.tests.helpers import (
    RouterTestCase, list_notices, read_json, result_path, write_request,
)

EXTERNAL = "someone@example.com"
NID = "5a" * 16  # 32 hex, as the combined runtime's inbound leg would mint


def external_record(**overrides):
    rec = {
        "notice_id": NID, "from_instance": None, "from_address": EXTERNAL,
        "to_instance": "bob", "ts": "2026-09-03T09:00:00Z", "req_id": "",
        "message_id": "<abc@example.com>", "transport": "smtp", "origin": "external",
        "tree": "inbox",
    }
    rec.update(overrides)
    return {k: v for k, v in rec.items() if v is not ...}


class FakeSmtpArm:
    """Records the one call and answers as a real SMTP arm would."""

    def __init__(self):
        self.calls = []

    def __call__(self, cfg, state_dir, sender, recipient, request, *,
                 reply_to_record=None, attachments=None):
        self.calls.append(dict(cfg=cfg, state_dir=state_dir, sender=sender,
                               recipient=recipient, request=request,
                               reply_to_record=reply_to_record, attachments=attachments))
        return {"notice_id": "n/a", "message_id": "<reply-1@example.invalid>",
                "recipient": reply_to_record["from_address"]}


class ExternalReplyTests(RouterTestCase):
    def _fleet(self):
        return self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def _plant(self, cfg, record):
        path = binding.ledger_path(cfg.state_dir, "bob", NID)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record), encoding="utf-8")
        return record

    def _reply(self, cfg, backend=None, req_id="00000001", **req):
        write_request(cfg, "bob", req_id, in_reply_to=NID, body_text="reply", **req)
        kwargs = {} if backend is None else {"deliver_backend": backend}
        summary = outbound.drain_instance(cfg, "bob", **kwargs)
        return summary, read_json(result_path(cfg, "bob", req_id))

    def test_all_three_hold_hands_the_record_to_the_backend_with_no_instance(self):
        cfg = self._fleet()
        record = self._plant(cfg, external_record())
        arm = FakeSmtpArm()
        summary, result = self._reply(cfg, arm, to=["agent.alice@local"])

        self.assertEqual(len(arm.calls), 1)
        call = arm.calls[0]
        self.assertIs(call["cfg"], cfg)
        self.assertEqual(call["state_dir"], cfg.state_dir)
        self.assertEqual(call["sender"], "bob")
        self.assertIsNone(call["recipient"], "the external leg is signalled by recipient=None")
        self.assertEqual(call["reply_to_record"], record)
        self.assertEqual(call["request"]["req_id"], "00000001")
        self.assertEqual(call["attachments"], [])
        # The sender's result: accepted, bound to the RECORD's address — the
        # draft's `to` (a fleet instance!) is discarded, not delivered to.
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["reason_code"], outbound.REASON_RECIPIENT_BOUND)
        self.assertEqual(result["recipients"], [EXTERNAL])
        self.assertEqual(result["message_id"], "<reply-1@example.invalid>")
        self.assertEqual(list_notices(cfg, "alice"), [], "draft.to never became a delivery")
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_anything_short_of_all_three_stays_unresolved_and_calls_no_backend(self):
        cases = {
            "transport local": external_record(transport="local"),
            "transport absent": external_record(transport=...),
            "transport null": external_record(transport=None),
            "origin internal": external_record(origin="internal"),
            "origin absent": external_record(origin=...),
            "origin null": external_record(origin=None),
            "from_address empty": external_record(from_address=""),
            "from_address absent": external_record(from_address=...),
            "from_address null": external_record(from_address=None),
            "from_address not a string": external_record(from_address=["a@b"]),
            "transport spelled differently": external_record(transport="SMTP"),
            "origin spelled differently": external_record(origin="External"),
        }
        # One config per case would share this test's temp root and resume
        # the first case's private result; distinct req_ids keep each
        # case a fresh request.
        for i, (label, record) in enumerate(cases.items(), start=1):
            with self.subTest(label):
                cfg = self._fleet()
                self._plant(cfg, record)
                arm = FakeSmtpArm()
                summary, result = self._reply(cfg, arm, req_id=f"{i:08d}")
                self.assertEqual(arm.calls, [], label)
                self.assertEqual(summary["rejected"], 1, label)
                self.assertEqual(result["outcome"], "rejected", label)
                self.assertEqual(result["reason_code"], outbound.REASON_UNRESOLVED_REPLY, label)

    def test_a_router_dsn_record_is_still_unresolved_with_or_without_a_backend(self):
        """`from_instance: null` alone — the router's own DSN records — must
        keep failing closed exactly as before this branch existed."""
        for i, backend in enumerate((None, FakeSmtpArm()), start=1):
            with self.subTest(backend=type(backend).__name__):
                cfg = self._fleet()
                dsn_bytes = binding.record_delivery(
                    cfg.state_dir, notice_id=NID, from_instance=None,
                    from_address="amap.router@local", to_instance="bob",
                    ts="2026-09-03T09:00:00Z", req_id="", message_id=NID,
                    transport="local", tree="inbox", authored_by="router",
                )
                self._plant(cfg, json.loads(dsn_bytes))
                summary, result = self._reply(cfg, backend, req_id=f"{i:08d}")
                self.assertEqual(result["reason_code"], outbound.REASON_UNRESOLVED_REPLY)
                if backend is not None:
                    self.assertEqual(backend.calls, [])

    def test_a_fleet_sender_on_an_smtp_record_still_binds_locally(self):
        """`from_instance` set wins: the existing local branch, with the
        record handed along as it always was. The new branch is only for a
        record with no fleet sender."""
        cfg = self._fleet()
        self._plant(cfg, external_record(from_instance="alice", from_address="alice@local"))
        arm = FakeSmtpArm()
        summary, result = self._reply(cfg, arm)
        self.assertEqual(len(arm.calls), 1)
        self.assertEqual(arm.calls[0]["recipient"], "alice")
        self.assertEqual(result["reason_code"], outbound.REASON_RECIPIENT_BOUND)

    def test_default_local_backend_refuses_fail_closed_and_answers_once(self):
        cfg = self._fleet()
        self._plant(cfg, external_record())
        summary, result = self._reply(cfg)   # no injection: deliver.deliver
        self.assertEqual(summary["queued_for_human"], 1)
        self.assertEqual(summary["outbound_errored"], 0)
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], outbound.REASON_DELIVERY_FAILED)
        self.assertEqual(result["recipients"], [])
        self.assertEqual(result["detail"],
                         "external reply delivery failed: ExternalReplyUnsupported")
        self.assertNotIn(EXTERNAL, json.dumps(result))
        for name in ("alice", "bob"):
            self.assertEqual(list_notices(cfg, name), [], f"nothing placed for {name}")
        # Answered once: a second drain resumes the private result, no re-run.
        summary2 = outbound.drain_instance(cfg, "bob")
        self.assertEqual(summary2.get("queued_for_human", 0), 0)

    def test_local_deliver_raises_on_none_before_touching_anything(self):
        cfg = self._fleet()
        with self.assertRaises(deliver_mod.ExternalReplyUnsupported):
            deliver_mod.deliver(cfg, cfg.state_dir, "bob", None, {"req_id": "1", "draft": {}},
                                reply_to_record=external_record())
        for name in ("alice", "bob"):
            self.assertEqual(list_notices(cfg, name), [])
        # Not a loophole for other non-instances: an empty string is the
        # KeyError it always was, never treated as the external leg.
        with self.assertRaises(KeyError):
            deliver_mod.deliver(cfg, cfg.state_dir, "bob", "", {"req_id": "1", "draft": {}})

    def test_a_failing_smtp_arm_is_answered_once_without_exception_text(self):
        cfg = self._fleet()
        self._plant(cfg, external_record())

        def arm_down(*a, **k):
            raise RuntimeError("smtp arm down: host-secret-path")

        summary, result = self._reply(cfg, arm_down)
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], outbound.REASON_DELIVERY_FAILED)
        self.assertNotIn("host-secret-path", json.dumps(result))
        self.assertEqual(summary["queued_for_human"], 1)


if __name__ == "__main__":
    unittest.main()
