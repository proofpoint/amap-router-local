"""The policy digest: exactly the pinned form, over a canonicalised
object, checked against known answers shared with the external leg's runtime
(`tests/vectors/policy_digest.json`)."""
import hashlib
import json
import unittest
from pathlib import Path

from router import classify
from router.tests import helpers
from router.tests.test_classify import HUB2, T1, T2, make_cfg

VECTORS = json.loads((Path(__file__).parent / "vectors" / "policy_digest.json").read_text())


class KnownAnswerTests(unittest.TestCase):

    def test_every_vector(self):
        checked = 0
        for c in VECTORS["cases"]:
            with self.subTest(why=c["why"]):
                self.assertEqual(classify.digest_of(c["object"]), c["digest"])
                if not c.get("object_only"):
                    obj = classify.policy_object_from(**c["input"])
                    self.assertEqual(obj, c["object"])
                    self.assertEqual(classify.digest_of(obj), c["digest"])
                checked += 1
        self.assertEqual(checked, len(VECTORS["cases"]))
        self.assertGreaterEqual(checked, 5)

    def test_case_variant_and_duplicate_inputs_give_one_digest(self):
        """The canonicaliser runs before the digest, so a case variant
        and a duplicate cannot give a second digest for one policy."""
        by_why = {c["why"].split(":")[0]: c["digest"] for c in VECTORS["cases"]}
        canonical = by_why["every input, already canonical"]
        self.assertEqual(by_why["case variants"], canonical)
        self.assertEqual(by_why["duplicates (after canonicalisation) and reordering"],
                         canonical)

    def test_a_local_part_case_change_is_a_different_policy(self):
        a = classify.policy_object_from(send_to=["bob@example.com"], remote_fleet=[],
                                        task_deny=[], trusted_fleet_hosts=[], egress=True)
        b = classify.policy_object_from(send_to=["Bob@example.com"], remote_fleet=[],
                                        task_deny=[], trusted_fleet_hosts=[], egress=True)
        self.assertNotEqual(classify.digest_of(a), classify.digest_of(b))


class PinnedFormTests(unittest.TestCase):
    """Each parameter of the pinned form changes the bytes for some object,
    so a digest built with any one of them altered fails a vector."""

    OBJ = {"v": 1, "send_to": ["café@example.com"], "remote_fleet": [],
           "task_deny": [], "trusted_fleet_hosts": [], "egress": False}

    def test_the_exact_expression(self):
        text = json.dumps(self.OBJ, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
        self.assertEqual(classify.digest_of(self.OBJ),
                         "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest())

    def test_it_is_utf8_unescaped_compact_and_sorted(self):
        d = classify.digest_of(self.OBJ)
        for variant in (
            json.dumps(self.OBJ, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            json.dumps(self.OBJ, sort_keys=True, ensure_ascii=False),
            json.dumps(self.OBJ, separators=(",", ":"), ensure_ascii=False),
        ):
            self.assertNotEqual(d, "sha256:" + hashlib.sha256(variant.encode()).hexdigest())
        self.assertTrue(classify.DIGEST_RE.fullmatch(d))

    def test_non_finite_numbers_are_refused(self):
        with self.assertRaises(ValueError):
            classify.digest_of({"v": float("nan")})

    def test_egress_must_be_a_boolean(self):
        with self.assertRaises(classify.Malformed):
            classify.policy_object_from(send_to=[], remote_fleet=[], task_deny=[],
                                        trusted_fleet_hosts=[], egress=1)


class ConfigDigestTests(helpers.RouterTestCase):

    def test_the_digest_covers_exactly_the_policy_inputs(self):
        base = classify.policy_digest(make_cfg(self), "alice")
        changes = [
            {"alice": {"send_to": ["x@example.com"]}},
            {"alice": {"remote_fleet": [HUB2]}},
            {"alice": {"task_deny": [f"@{T1}"]}},
            {"top": {"egress": True}},
            {"top": {"trusted_fleet_hosts": [T1]}},
        ]
        for ch in changes:
            with self.subTest(ch=ch):
                self.assertNotEqual(
                    classify.policy_digest(make_cfg(self, **ch), "alice"), base)
        # Not in the digest: fleet_hosts beyond the trusted ones, and the
        # quarantine retention.
        same = make_cfg(self, top={"fleet_hosts": [T1, T2, HUB2, "hub3.fleet.example"],
                                   "ingress_quarantine_days": 3})
        self.assertEqual(classify.policy_digest(same, "alice"), base)

    def test_bob_is_not_alice(self):
        cfg = make_cfg(self, alice={"send_to": ["x@example.com"]})
        self.assertNotEqual(classify.policy_digest(cfg, "alice"),
                            classify.policy_digest(cfg, "bob"))


if __name__ == "__main__":
    unittest.main()
