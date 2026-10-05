"""Operator-visible logging for two surfaces the code previously only
CLAIMED were logged: a hostile outbound filename, and a reply whose
agent-supplied draft.to/cc got discarded in favor of the bound recipient.
Raw recipient addresses must never be echoed verbatim into the log for the
discarded-to/cc case."""

import unittest

from router import outbound
from router.tests.helpers import RouterTestCase, list_notices, write_request


class TestLogging(RouterTestCase):
    def test_hostile_filename_is_logged(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        ob = cfg.instances["alice"].outbox_root
        ob.mkdir(parents=True, exist_ok=True)
        (ob / "evil.json").write_bytes(b"{}")

        with self.assertLogs("amap_router_local.outbound", level="WARNING") as cm:
            outbound.drain_instance(cfg, "alice")

        self.assertTrue(any("evil.json" in msg for msg in cm.output))

    def test_discarded_reply_recipients_logged_without_echoing_addresses(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"], "mallory": ["bob"]})

        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        notice_id = list_notices(cfg, "bob")[0][len("notice-"):-len(".json")]

        write_request(
            cfg, "bob", "00000001", in_reply_to=notice_id,
            to=["agent.mallory@local"], body_text="reply",
        )

        with self.assertLogs("amap_router_local.outbound", level="WARNING") as cm:
            outbound.drain_instance(cfg, "bob")

        matching = [msg for msg in cm.output if "discarded" in msg]
        self.assertEqual(len(matching), 1)
        # The forged/agent-supplied recipient address is never echoed
        # verbatim into the operator log.
        self.assertNotIn("agent.mallory@local", matching[0])
        # But the log is still actionable: it names the instance and the
        # request it happened for.
        self.assertIn("bob", matching[0])
        self.assertIn("00000001", matching[0])

    def _reply(self, **draft):
        """alice delivers to bob; bob replies with the given to/cc. Returns
        (cfg, records of the outbound logger at DEBUG and above)."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"], "mallory": ["bob"]})
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        notice_id = list_notices(cfg, "bob")[0][len("notice-"):-len(".json")]
        write_request(cfg, "bob", "00000001", in_reply_to=notice_id,
                      body_text="reply", **draft)
        with self.assertLogs("amap_router_local.outbound", level="DEBUG") as cm:
            outbound.drain_instance(cfg, "bob")
        return cfg, cm.records

    def test_a_reply_addressed_to_its_bound_sender_does_NOT_warn(self):
        """The spec requires draft.to, and a correct reply names its sender.
        That is the normal case, and it used to warn on every reply.

        Companions: the DEBUG line for this case IS emitted (so "no warning"
        is not "the branch never ran"), and the reply really was delivered to
        alice (so the binding is unchanged). `assertNoLogs` is 3.10+, and CI
        runs 3.9, hence the records check."""
        cfg, records = self._reply(to=["agent.alice@local"])
        discarded = [r for r in records if "discarded" in r.getMessage()]
        self.assertEqual([r.levelname for r in discarded], ["DEBUG"])
        self.assertEqual(len(list_notices(cfg, "alice")), 1)

    def test_the_match_is_casefolded(self):
        _cfg, records = self._reply(to=["Agent.Alice@LOCAL"])
        discarded = [r for r in records if "discarded" in r.getMessage()]
        self.assertEqual([r.levelname for r in discarded], ["DEBUG"])

    def test_a_cc_naming_someone_else_still_warns(self):
        """To is right, cc is not: the cc alone must be enough to warn. Pins
        that cc is checked, not only to."""
        _cfg, records = self._reply(to=["agent.alice@local"], cc=["agent.mallory@local"])
        warned = [r for r in records if r.levelname == "WARNING" and "discarded" in r.getMessage()]
        self.assertEqual(len(warned), 1)
        self.assertIn("1 recipient(s)", warned[0].getMessage())
        self.assertNotIn("agent.mallory@local", warned[0].getMessage())


if __name__ == "__main__":
    unittest.main()
