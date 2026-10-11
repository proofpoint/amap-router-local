"""status.json carries the held lists as STATE (replaced each poll, never
added to the totals), and the console shows their counts."""
from __future__ import annotations

import unittest

from router.status import StatusTracker

HELD = [{"req_id": "00000001", "since": "2026-10-11T00:00:00Z", "block": None,
         "targets": [{"recipient": "bravo", "state": "held", "reason": "not_registered"}]}]
DSN = [{"notice_id": "a" * 32, "outcome": "denied", "target": "alpha", "reason": "not_registered"}]


class StatusTests(unittest.TestCase):

    def test_the_lists_are_state_not_counters(self):
        t = StatusTracker(interval_s=5.0)
        t.record_poll({"alpha": {"drained": 0, "held_local": HELD, "dsn_held": DSN}})
        inst = t.to_doc()["instances"]["alpha"]
        self.assertEqual((inst["held_local"], inst["dsn_held"]), (HELD, DSN))
        self.assertNotIn("held_local", inst["totals"])
        t.record_poll({"alpha": {"drained": 0, "held_local": [], "dsn_held": []}})
        inst = t.to_doc()["instances"]["alpha"]
        self.assertEqual((inst["held_local"], inst["dsn_held"]), ([], []))

    def test_absent_without_a_registry(self):
        t = StatusTracker(interval_s=5.0)
        t.record_poll({"alpha": {"drained": 1}})
        inst = t.to_doc()["instances"]["alpha"]
        self.assertNotIn("held_local", inst)
        self.assertNotIn("dsn_held", inst)


if __name__ == "__main__":
    unittest.main()
