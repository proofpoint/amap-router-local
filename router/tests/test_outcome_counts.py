"""`drain_instance`'s summary carries per-outcome counts learned from the
governing `outcome` each request actually resolved to (not from log
scraping) — see `outbound.py`'s `_finish`/`_drain_one`/`_drain_reply`/
`_drain_cold` return-value plumbing."""

import unittest

from router import outbound
from router.tests.helpers import RouterTestCase, write_request


class TestOutcomeCounts(RouterTestCase):
    def test_mixed_drain_tallies_each_outcome(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"], "carol": []})

        # accepted: alice -> bob, mutual peers.
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        # queued_for_human: alice -> carol, known instance but not mutual.
        write_request(cfg, "alice", "00000002", to=["agent.carol@local"])
        # rejected: malformed (bad JSON).
        write_request(cfg, "alice", "00000003", raw_override=b"not json at all")

        summary = outbound.drain_instance(cfg, "alice")

        self.assertEqual(
            {k: summary[k] for k in ("accepted", "rejected", "queued_for_human")},
            {"accepted": 1, "rejected": 1, "queued_for_human": 1},
        )
        self.assertEqual(summary["drained"], 3)


if __name__ == "__main__":
    unittest.main()
