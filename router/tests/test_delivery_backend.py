"""The delivery-backend seam: injected, or the local `deliver` by default.

`outbound.py` used to name `deliver_mod.deliver` directly at both delivery
sites. A runtime that has more than one way to deliver (this one does not,
and must not learn one) needs to substitute its own without forking the
routing logic, so `drain_instance` takes a `deliver_backend` keyword and
threads it down to both.

Two of the assertions below exist because the local backend HIDES them:
`deliver.py` sets `message_id = notice_id`, so every existing test passes
whichever of the two ids `outbound.py` copies into the `result` document.
An injected backend that returns a distinct `message_id` — the only reason
the seam exists — is what makes that distinction observable at all.
"""
from unittest import mock

from router import deliver as deliver_mod, outbound
from router.tests import helpers
from router.tests.helpers import (
    list_notices, read_json, result_path, write_request,
)


class Recorder:
    """A backend that records every call, then delegates to the local
    `deliver` so the delivery genuinely happens. `message_id_override`,
    if set, stands in for a provider-assigned id the local path can never
    produce."""

    def __init__(self, message_id_override=None):
        self.calls = []
        self.message_id_override = message_id_override

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        real = deliver_mod.deliver(*args, **kwargs)
        if self.message_id_override is not None:
            return {**real, "message_id": self.message_id_override}
        return real


class DeliveryBackendSeamTest(helpers.RouterTestCase):
    def _pair(self):
        return self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def test_cold_backend_receives_the_same_arguments_the_local_path_would(self):
        cfg = self._pair()
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        backend = Recorder()

        outbound.drain_instance(cfg, "alice", deliver_backend=backend)

        self.assertEqual(len(backend.calls), 1)
        args, kwargs = backend.calls[0]
        self.assertEqual(len(args), 5)
        self.assertIs(args[0], cfg)
        self.assertEqual(args[1], cfg.state_dir)
        self.assertEqual(args[2], "alice")
        self.assertEqual(args[3], "bob")
        self.assertEqual(args[4]["req_id"], "00000001")
        self.assertEqual(kwargs, {"attachments": []})
        # It really delivered — the seam is a substitution, not a stub.
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

    def test_backend_message_id_reaches_the_result_document(self):
        cfg = self._pair()
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        outbound.drain_instance(
            cfg, "alice", deliver_backend=Recorder("provider-abc123"),
        )

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["message_id"], "provider-abc123")

    def test_reply_backend_gets_the_ledger_record_and_its_message_id_reaches_the_result(self):
        cfg = self._pair()
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        notice_id = list_notices(cfg, "bob")[0][len("notice-"):-len(".json")]

        write_request(cfg, "bob", "00000001", in_reply_to=notice_id, body_text="reply")
        backend = Recorder("provider-abc123")
        outbound.drain_instance(cfg, "bob", deliver_backend=backend)

        self.assertEqual(len(backend.calls), 1)
        args, kwargs = backend.calls[0]
        self.assertEqual((args[2], args[3]), ("bob", "alice"))
        # The binding came from the router's private ledger, not the draft.
        self.assertEqual(kwargs["reply_to_record"]["notice_id"], notice_id)

        result = read_json(result_path(cfg, "bob", "00000001"))
        self.assertEqual(result["reason_code"], outbound.REASON_RECIPIENT_BOUND)
        self.assertEqual(result["message_id"], "provider-abc123")

    def test_default_backend_is_the_local_deliver_resolved_late(self):
        cfg = self._pair()
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        # Patched AFTER import: a def-time default would have frozen the
        # original function object and this wrapper would never be seen.
        with mock.patch.object(
            outbound.deliver_mod, "deliver", side_effect=deliver_mod.deliver,
        ) as wrapper:
            outbound.drain_instance(cfg, "alice")

        self.assertEqual(wrapper.call_count, 1)
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

    def test_backend_failure_is_answered_once_like_a_local_failure(self):
        cfg = self._pair()
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        def always_fails(*args, **kwargs):
            raise RuntimeError("injected backend is down")

        summary = outbound.drain_instance(
            cfg, "alice", deliver_backend=always_fails,
        )

        self.assertEqual(summary["queued_for_human"], 1)
        self.assertEqual(summary["outbound_errored"], 0)
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], outbound.REASON_DELIVERY_FAILED)
        # Exception TEXT never reaches an agent-readable artifact.
        self.assertNotIn("injected backend is down", result.get("detail", ""))
