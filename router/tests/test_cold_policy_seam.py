"""The cold-send POLICY seam: injected, or this router's own decision.

The delivery seam alone was not enough, and this test file exists because of
exactly why. `_resolve_cold_recipients` returns `None` for any address that is
not a known instance, so a cold send to an EXTERNAL address is refused with
`recipient_unknown` LONG BEFORE any delivery backend is consulted. A combined
local+external runtime therefore could not reach the backend it had been given:
the seam was one step too late in the pipeline.

`cold_policy` sits at the decision itself. What it may NOT do is skip the one
governing outcome — a policy chooses the verdict, never whether there is one.
"""
from unittest import mock

from router import outbound
from router.tests import helpers
from router.tests.helpers import read_json, result_path, write_request


class ColdPolicySeamTest(helpers.RouterTestCase):
    def _pair(self):
        return self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def _result(self, cfg, req_id, sender="alice"):
        return read_json(result_path(cfg, sender, req_id))

    # -- the default is this router's own decision, unchanged ------------

    def test_default_policy_is_used_when_none_is_injected(self):
        cfg = self._pair()
        write_request(cfg, "alice", "0000001", to=["agent.nobody@local"])
        outbound.drain_instance(cfg, "alice")
        r = self._result(cfg, "0000001")
        self.assertEqual(r["outcome"], "rejected")
        self.assertEqual(r["reason_code"], outbound.REASON_RECIPIENT_UNKNOWN)

    def test_the_default_is_resolved_late_not_bound_at_def_time(self):
        """A module-level default bound into the signature cannot be patched
        by a test that imports this module — the same reason the delivery
        backend resolves late."""
        cfg = self._pair()
        calls = []

        def spy(c, sender, draft):
            calls.append(sender)
            return outbound.ColdRefusal("rejected", outbound.REASON_SELF_SEND)

        with mock.patch.object(outbound, "default_cold_policy", spy):
            write_request(cfg, "alice", "0000001", to=["agent.bob@local"])
            outbound.drain_instance(cfg, "alice")
        self.assertEqual(calls, ["alice"])

    # -- what the seam exists for ----------------------------------------

    def test_a_policy_may_authorize_a_recipient_this_router_would_refuse(self):
        """THE POINT. `you@example.com` is not an instance, so the default
        policy refuses it outright with `recipient_unknown`. A combined
        runtime's policy authorizes it and its own backend carries it — which
        the delivery seam alone could never reach."""
        cfg = self._pair()
        carried = []

        def external_ok(c, sender, draft):
            return ["you@example.com"]

        def backend(c, state_dir, sender, recipient, request, **kw):
            carried.append(recipient)
            return {"notice_id": "n-ext-1", "message_id": "<provider@id>",
                    "recipient": recipient}

        write_request(cfg, "alice", "0000001", to=["you@example.com"])
        outbound.drain_instance(cfg, "alice",
                                deliver_backend=backend, cold_policy=external_ok)

        self.assertEqual(carried, ["you@example.com"])
        r = self._result(cfg, "0000001")
        self.assertEqual(r["outcome"], "accepted")
        self.assertEqual(r["message_id"], "<provider@id>")

    def test_a_policy_refusal_carries_its_own_outcome_and_reason(self):
        cfg = self._pair()

        def refuse(c, sender, draft):
            return outbound.ColdRefusal(
                "queued_for_human", "mixed_recipient_classes",
                detail="local and external in one request")

        write_request(cfg, "alice", "0000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice", cold_policy=refuse)
        r = self._result(cfg, "0000001")
        self.assertEqual(r["outcome"], "queued_for_human")
        self.assertEqual(r["reason_code"], "mixed_recipient_classes")
        self.assertIn("one request", r["detail"])

    def test_hold_is_the_policys_choice_not_the_outcomes(self):
        """`hold` is a separate field on purpose: a policy miss is worth an
        operator's eyes, a malformed request nobody could act on is not."""
        cfg = self._pair()
        held = cfg.state_dir / "alice" / "held" / "req-0000001.json"

        def refuse_no_hold(c, sender, draft):
            return outbound.ColdRefusal("rejected", outbound.REASON_MALFORMED)

        write_request(cfg, "alice", "0000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice", cold_policy=refuse_no_hold)
        self.assertFalse(held.exists())

        def refuse_hold(c, sender, draft):
            return outbound.ColdRefusal(
                "queued_for_human", outbound.REASON_RECIPIENT_NOT_ALLOWLISTED,
                hold=True)

        write_request(cfg, "alice", "0000002", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice", cold_policy=refuse_hold)
        self.assertTrue((cfg.state_dir / "alice" / "held" / "req-0000002.json").exists())

    # -- what a policy must NOT be able to do -----------------------------

    def test_a_policy_authorizing_nobody_still_gets_one_governing_outcome(self):
        """Silence is not a delivery. An empty list is answered, archived, and
        never left in `outbound/` for every later poll to retry."""
        cfg = self._pair()

        def authorize_nobody(c, sender, draft):
            return []

        write_request(cfg, "alice", "0000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice", cold_policy=authorize_nobody)
        r = self._result(cfg, "0000001")
        self.assertEqual(r["outcome"], "rejected")
        self.assertEqual(r["reason_code"], outbound.REASON_MALFORMED)
        self.assertFalse((cfg.instances["alice"].outbox_root / "req-0000001.json").exists(),
                         "the request must be archived, not left to be retried forever")

    def test_no_notice_is_delivered_on_a_policy_refusal(self):
        cfg = self._pair()

        def refuse(c, sender, draft):
            return outbound.ColdRefusal("rejected", outbound.REASON_SELF_SEND)

        write_request(cfg, "alice", "0000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice", cold_policy=refuse)
        self.assertEqual(helpers.list_notices(cfg, "bob"), [])
