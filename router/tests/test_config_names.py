"""The instance name is the sandy slug, and what that widening cost.

A sandbox has ONE name — sandbox directory, container, instance,
`state_dir/<name>`, address local part. Nothing derives one name from another
and nothing holds a mapping, which removes the single largest source of
confusion across this family.

Widening `_NAME_RE` from `[a-z0-9-]` to sandy's `[A-Za-z0-9._-]` gave back two
properties that used to be free, and this file pins both:

  CASE. `state_dir/<name>/` holds the approval marker, the reply ledger and
  the quarantine. On a case-insensitive filesystem two names that fold
  together are ONE directory — two agents sharing one ledger. That was
  unrepresentable while names were lowercase-only; it is now guarded and
  loud.

  THE DOT. `amap.router` used to be unreachable as an instance name because
  names could not contain `.`. Slugs can (`example-1a2b3c4d.bak` is the
  shape), so the exclusion is now a check in two places: the loader refuses
  the name, and `instance_for` refuses to resolve the address.
"""

import json
import unittest

from router.config import (
    ROUTER_LOCAL_PART, ConfigError, address_for, instance_for, loads, router_address,
)

DOMAIN = "example.invalid"


def _doc(names, *, domain=DOMAIN):
    doc = {
        "state_dir": "/tmp/state",
        "instances": {n: {"handoff_dir": f"/tmp/sandboxes/{n}"} for n in names},
    }
    if domain:
        doc["fleet_domain"] = domain
    return json.dumps(doc)


class SlugAlphabetTests(unittest.TestCase):
    """The names sandy actually emits are accepted verbatim."""

    REAL_SHAPES = [
        "plain-deadbeef",              # already legal under the old rule
        "Mixed-Case_name-0badcafe",    # uppercase and underscore
        "snake_case_lab-c0ffee01",     # underscores
        "example-1a2b3c4d.bak",        # a dot, from a backup-suffixed directory
    ]

    def test_every_shape_loads_and_keeps_its_spelling(self):
        cfg = loads(_doc(self.REAL_SHAPES))
        self.assertEqual(sorted(cfg.instances), sorted(self.REAL_SHAPES))
        for name in self.REAL_SHAPES:
            self.assertEqual(cfg.instances[name].name, name,
                             "the name is stored exactly as sandy emits it")

    def test_the_name_is_the_address_local_part_verbatim(self):
        for name in self.REAL_SHAPES:
            self.assertEqual(address_for(name, DOMAIN), f"{name}@{DOMAIN}")

    def test_a_leading_dot_or_dash_is_still_refused(self):
        """Not fussiness: a leading `.` makes the state directory hidden, and
        a leading `-` reads as a flag to every command-line tool that will
        ever be pointed at it."""
        for bad in (".hidden-deadbeef", "-dashed-deadbeef"):
            with self.subTest(name=bad), self.assertRaises(ConfigError):
                loads(_doc([bad]))

    def test_characters_outside_the_slug_alphabet_are_still_refused(self):
        for bad in ("has space-deadbeef", "has/slash-deadbeef", "has:colon-deadbeef"):
            with self.subTest(name=bad), self.assertRaises(ConfigError):
                loads(_doc([bad]))


class CasefoldTests(unittest.TestCase):
    """The property the old charset gave for free."""

    def test_two_names_differing_only_by_case_are_refused(self):
        """They would be one directory under `state_dir` on a
        case-insensitive filesystem: one approval marker and one reply ledger
        between two agents. Approving one would approve the other."""
        with self.assertRaises(ConfigError) as ctx:
            loads(_doc(["SunRoom-deadbeef", "sunroom-deadbeef"]))
        message = str(ctx.exception)
        self.assertIn("SunRoom-deadbeef", message)
        self.assertIn("sunroom-deadbeef", message,
                      "the refusal must name BOTH, or the operator has to hunt")

    def test_names_that_merely_share_a_prefix_are_fine(self):
        """The guard is about folding, not similarity. Two real slugs sharing
        a basename differ in their path digest and must both load."""
        cfg = loads(_doc(["sunroom-deadbeef", "sunroom-c0ffee01"]))
        self.assertEqual(len(cfg.instances), 2)

    def test_the_guard_does_not_fire_on_a_normal_fleet(self):
        """It should never fire in practice — a slug's hex half is never
        folded, so two slugs collide only on an identical path digest. This
        pins that the common case is untouched."""
        cfg = loads(_doc(SlugAlphabetTests.REAL_SHAPES))
        self.assertEqual(len(cfg.instances), len(SlugAlphabetTests.REAL_SHAPES))


class ReservedNameTests(unittest.TestCase):
    """`amap.router` was unreachable by charset; now it is refused by check."""

    def test_the_routers_own_local_part_cannot_be_an_instance(self):
        """Such an instance would receive this router's own DSNs and could be
        named as the sender of a peer notice."""
        with self.assertRaises(ConfigError) as ctx:
            loads(_doc([ROUTER_LOCAL_PART]))
        self.assertIn(ROUTER_LOCAL_PART, str(ctx.exception))

    def test_the_refusal_is_case_insensitive_too(self):
        with self.assertRaises(ConfigError):
            loads(_doc([ROUTER_LOCAL_PART.upper()]))

    def test_the_routers_address_never_resolves(self):
        """The other half, and the one that matters at delivery time: a reply
        to a DSN must not bind, so the address must not parse to an
        instance."""
        self.assertIsNone(instance_for(router_address(DOMAIN), DOMAIN))
        self.assertIsNone(
            instance_for(router_address(DOMAIN), DOMAIN, ["a-deadbeef"]))

    def test_an_ordinary_name_still_resolves(self):
        """The control. Without it, a resolver broken into returning None for
        everything would pass every test above."""
        self.assertEqual(
            instance_for(address_for("a-deadbeef", DOMAIN), DOMAIN), "a-deadbeef")


if __name__ == "__main__":
    unittest.main()
