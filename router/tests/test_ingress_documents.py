"""Conformance proof for `ingress.check_notice_doc` and
`ingress.check_message_doc`: every AMAP `notice-*` and `message-*` fixture
lands on the expected side, the invalid ones included. The same arrangement
as `test_validate_fixtures` for submit requests: the hand-rolled checks are
proven against the golden fixtures here, in tests only."""
from __future__ import annotations

import json
import unittest

from router import ingress
from router.tests.helpers import AMP_ROOT

CHECKS = {"notice": ingress.check_notice_doc, "message": ingress.check_message_doc}


class FixtureTests(unittest.TestCase):

    def run_side(self, side: str):
        d = AMP_ROOT / "fixtures" / side
        self.assertTrue(d.is_dir(), f"AMAP fixtures not found at {d}")
        counts = {}
        for prefix, check in CHECKS.items():
            for f in sorted(d.glob(f"{prefix}-*.json")):
                counts[prefix] = counts.get(prefix, 0) + 1
                doc = json.loads(f.read_text())
                with self.subTest(fixture=f.name):
                    try:
                        check(doc)
                    except ingress.BundleRefused as e:
                        self.assertEqual(side, "invalid", f"{f.name} refused: {e}")
                        self.assertEqual(e.reason, "bundle_invalid")
                    else:
                        self.assertEqual(side, "valid", f"{f.name} should be INVALID but passed")
        return counts

    def test_valid_fixtures_pass(self):
        counts = self.run_side("valid")
        self.assertGreater(counts.get("notice", 0), 0)
        self.assertGreater(counts.get("message", 0), 0)

    def test_invalid_fixtures_are_refused(self):
        counts = self.run_side("invalid")
        self.assertGreater(counts.get("notice", 0), 0)
        self.assertGreater(counts.get("message", 0), 0)


if __name__ == "__main__":
    unittest.main()
