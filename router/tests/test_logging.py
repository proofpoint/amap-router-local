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


if __name__ == "__main__":
    unittest.main()
