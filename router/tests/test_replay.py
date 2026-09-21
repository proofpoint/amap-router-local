"""Idempotency: the anchor is the router-PRIVATE result
(`state_dir/<name>/results/<req_id>.json`), never the agent-writable
namespace copy — re-dropping (or replaying) the same `req-<id>.json` must
never deliver a second notice."""

import unittest

from router import outbound
from router.tests.helpers import RouterTestCase, list_notices, read_json, result_path, write_request


class TestReplay(RouterTestCase):
    def test_redrop_same_req_id_no_second_delivery(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        req_path = write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        raw_bytes = req_path.read_bytes()

        outbound.drain_instance(cfg, "alice")
        self.assertEqual(len(list_notices(cfg, "bob")), 1)
        first_result = read_json(result_path(cfg, "alice", "00000001"))

        # Simulate a replay: the same req-00000001.json reappears at
        # outbound/ (e.g. a naive resync, or an agent re-submitting).
        outbound_dir = cfg.instances["alice"].outbox_root
        (outbound_dir / "req-00000001.json").write_bytes(raw_bytes)

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["outbound_resumed"], 1)

        # Still exactly one notice delivered to bob — not two.
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

        second_result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(second_result, first_result)


if __name__ == "__main__":
    unittest.main()
