"""The cold-send POLICY seam: injected, or this router's own decision.

The delivery seam alone was not enough, and this test file exists because of
exactly why: a cold send to an EXTERNAL address used to be refused with
`recipient_unknown` LONG BEFORE any delivery backend was consulted, so a
combined local+external runtime could not reach the backend it had been
given. `cold_policy` sits at the decision itself.

Since the classification order (`router/classify.py`) the seam is NARROW: the
order's non-negotiables run outside it, always, and a policy decides only a
request whose recipients are all in ONE cross-host class of item 6 or item 7
(a fleet host outside the trusted list, or the internet). What it may NOT do
is skip the one governing outcome, decide a same-host request, or route a
recipient into a class it is not in.
"""
from unittest import mock

from router import outbound
from router.tests import helpers
from router.tests.helpers import read_json, result_path, write_request
from router.tests.test_inflight import FakeTransport

EXT = "you@example.com"


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

    def test_a_policy_may_authorize_a_recipient_the_default_would_refuse(self):
        """THE POINT. With no egress configured, the default answers an
        internet address `no_route`. A combined runtime's policy routes it to
        the external leg instead."""
        cfg = self._pair()
        port = FakeTransport()

        def external_ok(c, sender, draft):
            return outbound.ExternalRoute((EXT,))

        write_request(cfg, "alice", "0000001", to=[EXT])
        outbound.drain_instance(cfg, "alice", transport=port, cold_policy=external_ok)
        self.assertEqual(port.writes, ["00000001"])
        write_request(cfg, "alice", "0000002", to=[EXT])
        outbound.drain_instance(cfg, "alice", transport=port)
        r = self._result(cfg, "0000002")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "no_route"))

    def test_a_policy_refusal_carries_its_own_outcome_and_reason(self):
        cfg = self._pair()

        def refuse(c, sender, draft):
            return outbound.ColdRefusal(
                "queued_for_human", "recipient_not_allowlisted",
                detail="held by one request's policy")

        write_request(cfg, "alice", "0000001", to=[EXT])
        outbound.drain_instance(cfg, "alice", transport=FakeTransport(), cold_policy=refuse)
        r = self._result(cfg, "0000001")
        self.assertEqual(r["outcome"], "queued_for_human")
        self.assertEqual(r["reason_code"], "recipient_not_allowlisted")
        self.assertIn("one request", r["detail"])

    def test_hold_is_the_policys_choice_not_the_outcomes(self):
        """`hold` is a separate field on purpose: a policy miss is worth an
        operator's eyes, a malformed request nobody could act on is not."""
        cfg = self._pair()
        held = cfg.state_dir / "alice" / "held" / "req-0000001.json"

        def refuse_no_hold(c, sender, draft):
            return outbound.ColdRefusal("rejected", outbound.REASON_MALFORMED)

        write_request(cfg, "alice", "0000001", to=[EXT])
        outbound.drain_instance(cfg, "alice", transport=FakeTransport(),
                                cold_policy=refuse_no_hold)
        self.assertFalse(held.exists())

        def refuse_hold(c, sender, draft):
            return outbound.ColdRefusal(
                "queued_for_human", outbound.REASON_RECIPIENT_NOT_ALLOWLISTED,
                hold=True)

        write_request(cfg, "alice", "0000002", to=[EXT])
        outbound.drain_instance(cfg, "alice", transport=FakeTransport(),
                                cold_policy=refuse_hold)
        self.assertTrue((cfg.state_dir / "alice" / "held" / "req-0000002.json").exists())

    # -- what a policy must NOT be able to do -----------------------------

    def test_a_policy_never_decides_a_same_host_request(self):
        """The same-host decision is this router's: a policy that would
        refuse is never asked, and the notice is delivered."""
        cfg = self._pair()
        called = []

        def refuse(c, sender, draft):
            called.append(sender)
            return outbound.ColdRefusal("rejected", "custom")

        write_request(cfg, "alice", "0000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice", transport=FakeTransport(), cold_policy=refuse)
        self.assertEqual(called, [])
        self.assertEqual(self._result(cfg, "0000001")["outcome"], "accepted")
        self.assertEqual(len(helpers.list_notices(cfg, "bob")), 1)

    def test_a_policy_cannot_route_outside_the_class(self):
        """Local delivery, a peer route, or an external route naming someone
        the request did not: each answered `transport_anomaly`, nothing sent,
        nothing delivered."""
        cfg = self._pair()
        answers = {
            "0000001": ["bob"],
            "0000002": outbound.PeerRoute("bob"),
            "0000003": outbound.ExternalRoute(("other@example.com",)),
            "0000004": [],
        }
        port = FakeTransport()
        for req_id, answer in answers.items():
            write_request(cfg, "alice", req_id, to=[EXT])
            outbound.drain_instance(cfg, "alice", transport=port,
                                    cold_policy=lambda c, s, d, a=answer: a)
            r = self._result(cfg, req_id)
            self.assertEqual((r["outcome"], r["reason_code"]),
                             ("queued_for_human", "transport_anomaly"), req_id)
            # The class check is the only producer of this detail; the
            # in-flight recipient check would answer the external case with
            # the same code and a different detail.
            self.assertEqual(r["detail"], "the cold policy routed outside this request's "
                                          "recipient class; nothing was sent", req_id)
            self.assertFalse((cfg.instances["alice"].outbox_root / f"req-{req_id}.json").exists(),
                             "the request must be archived, not left to be retried forever")
        self.assertEqual(port.writes, [])
        self.assertEqual(helpers.list_notices(cfg, "bob"), [])
