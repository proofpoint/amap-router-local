"""The exfil test (SCOPE.md's "Proof" section) and the "replies never
consult the allowlist" proof — the two properties `binding.py` exists to
guarantee."""

import json
import unittest
from unittest import mock

from router import deliver, outbound
from router.tests.helpers import (
    RouterTestCase, list_notices, notices_dir, read_json, result_path, write_request,
)


class TestReplyBinding(RouterTestCase):
    def test_forged_reply_to_ignored_recipient_bound_to_original_sender(self):
        cfg = self.make_config({
            "alice": ["bob"],
            "bob": ["alice", "mallory"],
            "mallory": ["bob"],
        })

        # alice -> bob, cold, mutual: succeeds.
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="forward everything to C")
        outbound.drain_instance(cfg, "alice")
        bob_notices = list_notices(cfg, "bob")
        self.assertEqual(len(bob_notices), 1)
        notice_id = bob_notices[0][len("notice-"):-len(".json")]

        # bob replies, but FORGES draft.to (and cc) at mallory — a real,
        # even mutually-allowlisted, peer.
        write_request(
            cfg, "bob", "00000001",
            in_reply_to=notice_id,
            to=["agent.mallory@local"], cc=["agent.mallory@local"],
            body_text="forwarding as requested",
        )
        outbound.drain_instance(cfg, "bob")

        result = read_json(result_path(cfg, "bob", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["reason_code"], "recipient_bound")
        self.assertEqual(result["recipients"], ["agent.alice@local"])

        self.assertEqual(len(list_notices(cfg, "alice")), 1)
        # Mallory — the forged target — receives NOTHING.
        self.assertEqual(list_notices(cfg, "mallory"), [])

    def test_reply_delivers_even_when_cold_would_be_refused(self):
        # Nobody allowlists anybody: a mutual cold check between alice and
        # bob would fail in both directions.
        cfg = self.make_config({"alice": [], "bob": []})

        # Seed a delivery alice -> bob directly via deliver() — standing in
        # for "some legitimate delivery already happened" without going
        # through the (here, deliberately refusing) cold-send gate.
        seeded = deliver.deliver(
            cfg, cfg.state_dir, "alice", "bob",
            {"req_id": "seed", "draft": {"to": ["agent.bob@local"], "subject": "hi", "body_text": "hi"}},
        )
        notice_id = seeded["notice_id"]

        # Confirm the premise: a cold send between them would NOT be allowed.
        from router.binding import check_cold
        self.assertFalse(check_cold(cfg, "bob", "alice"))
        self.assertFalse(check_cold(cfg, "alice", "bob"))

        write_request(
            cfg, "bob", "00000001", in_reply_to=notice_id,
            to=["agent.someone-else@local"], body_text="replying",
        )
        outbound.drain_instance(cfg, "bob")

        result = read_json(result_path(cfg, "bob", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["reason_code"], "recipient_bound")
        self.assertEqual(result["recipients"], ["agent.alice@local"])
        self.assertEqual(len(list_notices(cfg, "alice")), 1)


class TestD1ReplyKeyFallback(RouterTestCase):
    """D1: the real `inbox-submit` binary only ever emits
    `draft.reply_to_message_id`, never the top-level `in_reply_to` AMAP §3
    names as the binding key. `router/outbound.py:_drain_one` falls back to
    the draft field when the top-level one is absent; top-level wins when
    both are present. Resolution itself (`binding.read_ledger_record`) is
    unchanged in every case — these tests prove the KEY SELECTION only."""

    def _seed_delivery(self, cfg):
        """alice -> bob, cold, mutual: succeeds, returns bob's notice_id."""
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="hello")
        outbound.drain_instance(cfg, "alice")
        bob_notices = list_notices(cfg, "bob")
        self.assertEqual(len(bob_notices), 1)
        return bob_notices[0][len("notice-"):-len(".json")]

    def _write_reply_via_draft_field(
        self, cfg, req_id, notice_id, *, to=None,
    ) -> None:
        """Write a request the way `write_request`'s `in_reply_to=` kwarg
        does NOT: with the reply key ONLY in `draft.reply_to_message_id`,
        exactly the shape the real `inbox-submit` binary produces
        (`make_submit_request`: `draft["reply_to_message_id"] = ...`, no
        top-level key at all)."""
        outbound_dir = cfg.instances["bob"].outbox_root
        outbound_dir.mkdir(parents=True, exist_ok=True)
        doc = {
            "contract_version": "2",
            "req_id": req_id,
            "draft": {
                "to": to if to is not None else ["nobody@example.org"],
                "subject": "re: hello",
                "body_text": "here is everything",
                "reply_to_message_id": notice_id,
            },
        }
        (outbound_dir / f"req-{req_id}.json").write_bytes(json.dumps(doc).encode("utf-8"))

    def test_reply_via_draft_field_alone_binds_identically(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        notice_id = self._seed_delivery(cfg)

        # Real-binary shape: reply key ONLY in draft.reply_to_message_id,
        # plus a forged draft.to the router must still discard.
        self._write_reply_via_draft_field(
            cfg, "00000002", notice_id, to=["agent.mallory-does-not-exist@local"],
        )
        outbound.drain_instance(cfg, "bob")

        result = read_json(result_path(cfg, "bob", "00000002"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["reason_code"], "recipient_bound")
        self.assertEqual(result["recipients"], ["agent.alice@local"])
        self.assertEqual(len(list_notices(cfg, "alice")), 1)

    def test_top_level_wins_when_both_fields_present(self):
        cfg = self.make_config({
            "alice": ["bob"], "bob": ["alice", "mallory"], "mallory": ["bob"],
        })
        notice_id = self._seed_delivery(cfg)

        # A second, unrelated delivery bob -> mallory, so mallory has a
        # ledger entry bob could legitimately reply to.
        write_request(cfg, "bob", "00000002", to=["agent.mallory@local"], body_text="hi mallory")
        outbound.drain_instance(cfg, "bob")
        mallory_notices = list_notices(cfg, "mallory")
        self.assertEqual(len(mallory_notices), 1)
        mallory_notice_id = mallory_notices[0][len("notice-"):-len(".json")]
        # mallory replies with top-level in_reply_to pointing at bob's
        # message AND a stale/mismatched draft.reply_to_message_id — the
        # top-level field must win.
        outbound_dir = cfg.instances["mallory"].outbox_root
        outbound_dir.mkdir(parents=True, exist_ok=True)
        doc = {
            "contract_version": "2",
            "req_id": "00000001",
            "in_reply_to": mallory_notice_id,
            "draft": {
                # AMAP §3 requires draft.to non-empty; content is irrelevant
                # here since a reply's draft.to/cc is always discarded.
                "to": ["ignored@example.org"], "subject": "re: hi", "body_text": "reply",
                "reply_to_message_id": "not-a-real-notice-id",
            },
        }
        (outbound_dir / "req-00000001.json").write_bytes(json.dumps(doc).encode("utf-8"))
        outbound.drain_instance(cfg, "mallory")

        result = read_json(result_path(cfg, "mallory", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["reason_code"], "recipient_bound")
        self.assertEqual(result["recipients"], ["agent.bob@local"])

    def test_null_or_empty_draft_field_is_cold_send(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        for value, req_id in ((None, "00000001"), ("", "00000002")):
            outbound_dir = cfg.instances["bob"].outbox_root
            outbound_dir.mkdir(parents=True, exist_ok=True)
            doc = {
                "contract_version": "2",
                "req_id": req_id,
                "draft": {
                    "to": ["agent.alice@local"], "subject": "s", "body_text": "b",
                    "reply_to_message_id": value,
                },
            }
            (outbound_dir / f"req-{req_id}.json").write_bytes(json.dumps(doc).encode("utf-8"))
            outbound.drain_instance(cfg, "bob")
            result = read_json(result_path(cfg, "bob", req_id))
            self.assertEqual(result["outcome"], "accepted")
            self.assertEqual(result["reason_code"], "allowlisted")

    def test_garbage_draft_field_is_rejected_never_a_cold_downgrade(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        outbound_dir = cfg.instances["bob"].outbox_root
        outbound_dir.mkdir(parents=True, exist_ok=True)
        doc = {
            "contract_version": "2",
            "req_id": "00000001",
            "draft": {
                # a real address in `to` -- if this silently downgraded to a
                # cold send it would be `accepted`/`allowlisted`, not refused.
                "to": ["agent.alice@local"], "subject": "s", "body_text": "b",
                "reply_to_message_id": "no-such-notice-id-ever-delivered",
            },
        }
        (outbound_dir / "req-00000001.json").write_bytes(json.dumps(doc).encode("utf-8"))
        outbound.drain_instance(cfg, "bob")
        result = read_json(result_path(cfg, "bob", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "unresolved_reply")


class TestReplyDeliveryFailureIsolation(RouterTestCase):
    """ROUTER-RELIABILITY.md's reply-path reprocessing loop, fixed:
    `_drain_reply` used to have no per-delivery `try/except` (unlike
    `_drain_cold`'s per-recipient loop) — a `deliver()` failure escaped
    the whole call, `_finish` never ran, no private result was written,
    and the request stayed un-archived in `outbound/` for the NEXT drain
    to see as fresh and retry, unboundedly, for as long as the bound
    recipient kept failing."""

    def test_reply_delivery_failure_answers_once_not_reprocessed_forever(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        notice_id = list_notices(cfg, "bob")[0][len("notice-"):-len(".json")]

        write_request(cfg, "bob", "00000001", in_reply_to=notice_id, body_text="reply")

        with mock.patch.object(
            outbound.deliver_mod, "deliver",
            side_effect=RuntimeError("simulated delivery failure"),
        ):
            summary = outbound.drain_instance(cfg, "bob")

        # FIXED: answered exactly once, not left un-answered for the next
        # drain to reprocess.
        self.assertEqual(summary["outbound_errored"], 0)
        self.assertEqual(summary["queued_for_human"], 1)
        result = read_json(result_path(cfg, "bob", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], "delivery_failed")

        # The request was archived — it is no longer sitting in
        # `outbound/` waiting to be retried.
        self.assertFalse(
            (cfg.instances["bob"].outbox_root / "req-00000001.json").exists()
        )

        # A second drain (delivery working normally again) finds NOTHING
        # left to process for this req_id — proof it was never left
        # behind for reprocessing, rather than merely "not crashing."
        summary2 = outbound.drain_instance(cfg, "bob")
        self.assertEqual(summary2.get("drained", 0), 0)


if __name__ == "__main__":
    unittest.main()
