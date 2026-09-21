"""Conformance proof for `router/validate.py`: every AMAP submit-request
fixture must land on the expected side. This is what stands in for
importing the AMAP fixtures validator into the shipped code path — the
router's OWN hand-rolled validator is proven against the golden fixtures,
here, in tests only.
"""

import json
import unittest

from router.tests.helpers import AMP_ROOT
from router.validate import validate_request


class TestValidateFixtures(unittest.TestCase):
    def test_all_request_fixtures(self):
        valid_dir = AMP_ROOT / "fixtures" / "valid"
        invalid_dir = AMP_ROOT / "fixtures" / "invalid"
        self.assertTrue(valid_dir.is_dir(), f"AMAP fixtures not found at {valid_dir}")

        checked = 0
        for f in sorted(valid_dir.glob("request-*.json")):
            checked += 1
            doc = json.loads(f.read_text())
            ok, reason, detail = validate_request(doc)
            self.assertTrue(ok, f"{f.name} should be VALID but failed: {reason} {detail}")

        for f in sorted(invalid_dir.glob("request-*.json")):
            checked += 1
            doc = json.loads(f.read_text())
            ok, reason, detail = validate_request(doc)
            self.assertFalse(ok, f"{f.name} should be INVALID but passed")

        self.assertGreater(checked, 0, "no request-*.json fixtures found")


if __name__ == "__main__":
    unittest.main()
