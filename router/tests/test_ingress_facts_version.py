"""`ingress.facts_version`, driven DIRECTLY (the guard unit): the plugin's
reader refuses these inputs before this router's guard would see them end to
end, so the guard's own witnesses and mutants must reach it here."""
from __future__ import annotations

import unittest

from router import ingress

V2 = {"facts_version": 2, "attachments": [], "notice_id": "1-1"}


class FactsVersionTests(unittest.TestCase):

    def refused(self, facts):
        with self.assertRaises(Exception) as cm:
            ingress.facts_version(facts)
        self.assertIsInstance(cm.exception, ingress.FactsInvalid)

    def test_absent_is_version_1_and_two_is_version_2(self):
        self.assertEqual(ingress.facts_version({"notice_id": "1-1"}), 1)
        self.assertEqual(ingress.facts_version(V2), 2)

    def test_every_other_present_value_is_refused(self):
        for v in (3, True, 2.0, "2", 1, None, [2], 0, -2):
            with self.subTest(facts_version=v):
                self.refused(dict(V2, facts_version=v))

    def test_version_1_carrying_attachments_is_refused(self):
        self.refused({"notice_id": "1-1", "attachments": []})

    def test_version_2_without_attachments_is_refused(self):
        self.refused({"facts_version": 2, "notice_id": "1-1"})

    def test_not_an_object(self):
        for facts in (None, [], "x", 2):
            with self.subTest(facts=facts):
                self.refused(facts)


if __name__ == "__main__":
    unittest.main()
