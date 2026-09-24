"""The fleet roster against the spec: amap-spec's `schemas/roster.schema.json`
and its `roster-*` fixtures (draft section "The Fleet Roster").

NEEDS THE SPEC CHECKOUT, and fails loudly rather than skipping without it —
the repo's rule, from a probe that stopped running under a `skipTest` while
the suite stayed green. Kept apart from `test_roster.py` so the writer's own
behaviour is tested everywhere and only THIS module depends on the spec.

THE SCHEMA IS PASSED EXPLICITLY, never selected by filename. The spec's
validator picks a schema by fixture-name prefix, and a roster document the
writer produced has no fixture name — routing it through `check_document`
would validate it against whatever the chosen name mapped to.

A validator that passes everything proves nothing, so before the writer's
output is trusted to pass, the validator is shown to REJECT each invalid
roster fixture and accept each valid one.
"""

import json
import unittest

from router import roster
from router.tests.peer_helpers import AMP_ROOT, load_amp_validate
from router.tests.test_roster import _RosterTree

SCHEMA_PATH = AMP_ROOT / "schemas" / "roster.schema.json"
VALID = ("roster-basic", "roster-empty", "roster-unknown-member")
INVALID = ("roster-display-name-address", "roster-missing-members",
           "roster-member-missing-state", "roster-version-1")


class _Spec:
    @classmethod
    def setUpClass(cls):
        cls.amp = load_amp_validate()
        cls.schema = json.loads(SCHEMA_PATH.read_text())

    def errors(self, doc):
        return self.amp.validate(doc, self.schema)


class TheValidatorIsLiveTests(_Spec, unittest.TestCase):
    """The positive control for everything below it."""

    def test_every_invalid_roster_fixture_is_REJECTED(self):
        for name in INVALID:
            with self.subTest(name):
                doc = json.loads((AMP_ROOT / "fixtures" / "invalid" / f"{name}.json").read_text())
                self.assertTrue(self.errors(doc), f"{name} passed a validator that should reject it")

    def test_every_valid_roster_fixture_is_accepted(self):
        for name in VALID:
            with self.subTest(name):
                doc = json.loads((AMP_ROOT / "fixtures" / "valid" / f"{name}.json").read_text())
                self.assertEqual(self.errors(doc), [])

    def test_the_fixture_sets_are_the_ones_the_spec_ships(self):
        """If the spec adds a roster fixture, this module should hear about
        it rather than keep proving itself against a stale list."""
        found = {p.stem for d in ("valid", "invalid")
                 for p in (AMP_ROOT / "fixtures" / d).glob("roster-*.json")}
        self.assertEqual(found, set(VALID) | set(INVALID))


class TheWritersOutputConformsTests(_Spec, _RosterTree):

    def published(self, *, selected, interval_s):
        roster.publish(self.fleet(selected=selected), interval_s)
        return json.loads(self.roster_file.read_text())

    def test_a_real_roster_validates(self):
        """The writer's actual file, not a hand-built document. Non-empty
        members is asserted too: an empty roster validates, so passing on one
        would say nothing about the member shape."""
        doc = self.published(selected=("alice-deadbeef", "bravo-0badcafe"), interval_s=5.0)
        self.assertEqual(len(doc["members"]), 2)
        self.assertEqual(self.errors(doc), [])

    def test_a_roster_without_interval_validates(self):
        doc = self.published(selected=("alice-deadbeef",), interval_s=None)
        self.assertNotIn("interval_s", doc)
        self.assertEqual(self.errors(doc), [])

    def test_an_answered_empty_fleet_validates(self):
        doc = self.published(selected=(), interval_s=5.0)
        self.assertEqual(doc["members"], [])
        self.assertEqual(self.errors(doc), [])

    def test_the_router_is_never_a_member(self):
        """Normative in the draft, and true here by construction —
        `config.load` refuses an instance named for the router — but asserted
        on the output, since that is the surface a reader sees."""
        doc = self.published(selected=("alice-deadbeef", "bravo-0badcafe"), interval_s=5.0)
        self.assertNotIn(doc["router"], [m["address"] for m in doc["members"]])


if __name__ == "__main__":
    unittest.main()
