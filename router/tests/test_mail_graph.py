"""`mail_graph: "all"` — the mail lane's fleet-level shorthand.

The peer lane's `task_graph` (see `test_task_graph.py`) for the other lane,
expanded at load into the same per-instance `peers` sets an explicit list
produces, so `binding.check_cold`, `derive_matrix` and the `peers`/`matrix`
artifact see one shape and none of them knows the word exists.

WHY IT IS A WORD AND NOT A RENDERED MAP. A map is expanded by whoever writes
it, over the instances THEY know about. Under discovery the instance set is
found at poll time, so a map written earlier can never include an instance
that appears later — the mesh silently stops being "all". The word is
expanded HERE, over the instances this loader actually has.

WHY IT IS NOT SPELLED `peers`. `peers` is an INSTANCE key holding a LIST. A
top-level `peers` holding a STRING would put one word at two nesting levels
with two types. `task_graph`/`mail_graph` is a pair; `task_graph`/`peers`
is a puzzle.

AND WHY IT IS NOT `ALLOW_ANY`. That is a member of ONE list and relaxes only
the side declaring it; mutuality is still owed by the other end. This
declares both directions for every pair, so mutuality is satisfied by
construction rather than waived. `MeshIsMutualNotWaivedTests` pins the
difference, because a future "these mean the same thing" refactor is exactly
the change that would look tidy and be wrong.
"""

import json
import unittest

from router import binding
from router.config import (
    ALLOW_ANY, MAIL_GRAPH_ALL, TASK_GRAPH_ALL, ConfigError, derive_matrix, loads,
)

MODES = {"handoff": "handoff_dir", "namespace": "namespace"}


def _doc(names=("a-deadbeef", "b-c0ffee01"), *, modes=None, **top):
    modes = modes or {}
    doc = {
        "state_dir": "/tmp/state",
        "instances": {
            n: {MODES[modes.get(n, "handoff")]: f"/tmp/sandboxes/{n}"} for n in names
        },
    }
    doc.update(top)
    return json.dumps(doc)


class ExpansionTests(unittest.TestCase):
    def test_all_expands_to_every_other_instance(self):
        cfg = loads(_doc(("a-deadbeef", "b-c0ffee01", "c-0badcafe"),
                         mail_graph=MAIL_GRAPH_ALL))
        self.assertEqual(
            {n: sorted(i.peers) for n, i in cfg.instances.items()},
            {"a-deadbeef": ["b-c0ffee01", "c-0badcafe"],
             "b-c0ffee01": ["a-deadbeef", "c-0badcafe"],
             "c-0badcafe": ["a-deadbeef", "b-c0ffee01"]})

    def test_nobody_is_their_own_peer(self):
        cfg = loads(_doc(mail_graph=MAIL_GRAPH_ALL))
        for name, inst in cfg.instances.items():
            self.assertNotIn(name, inst.peers)

    def test_the_expansion_is_what_enforcement_reads(self):
        """Expanded into the real field, so nothing downstream learns a
        second way to ask 'may A cold-send B'."""
        cfg = loads(_doc(mail_graph=MAIL_GRAPH_ALL))
        self.assertTrue(binding.check_cold(cfg, "a-deadbeef", "b-c0ffee01"))
        self.assertTrue(binding.check_cold(cfg, "b-c0ffee01", "a-deadbeef"))

    def test_the_matrix_renders_the_expansion_not_the_word(self):
        cfg = loads(_doc(mail_graph=MAIL_GRAPH_ALL))
        matrix = derive_matrix(cfg)
        self.assertTrue(matrix["a-deadbeef"]["b-c0ffee01"])
        self.assertTrue(matrix["b-c0ffee01"]["a-deadbeef"])


class MeshIsMutualNotWaivedTests(unittest.TestCase):
    """The distinction from `ALLOW_ANY`, pinned so a tidy-up cannot erase it."""

    def test_the_word_never_appears_in_an_expanded_list(self):
        """If someone ever renders the word into per-instance `ALLOW_ANY`
        members "because they mean the same thing", they will have replaced a
        MUTUAL mesh with N UNILATERAL declarations — which mesh today and stop
        meshing the moment one instance's list is edited."""
        cfg = loads(_doc(("a-deadbeef", "b-c0ffee01", "c-0badcafe"),
                         mail_graph=MAIL_GRAPH_ALL))
        for name, inst in cfg.instances.items():
            with self.subTest(instance=name):
                self.assertNotIn(ALLOW_ANY, inst.peers)
                self.assertNotIn(MAIL_GRAPH_ALL, inst.peers)

    def test_a_one_sided_allow_any_still_grants_nothing(self):
        """The control that gives the test above its meaning: `ALLOW_ANY` on
        one side is not a mesh and never was. Without this, "expansion
        contains no ALLOW_ANY" could be satisfied by an implementation for
        which the two really were interchangeable."""
        cfg = loads(_doc())
        doc = json.loads(_doc())
        doc["instances"]["a-deadbeef"]["peers"] = [ALLOW_ANY]
        cfg = loads(json.dumps(doc))
        self.assertFalse(binding.check_cold(cfg, "a-deadbeef", "b-c0ffee01"))
        self.assertFalse(binding.check_cold(cfg, "b-c0ffee01", "a-deadbeef"))


class NamespaceModeTests(unittest.TestCase):
    def test_a_namespace_instance_is_IN_the_mail_mesh(self):
        """THE ASYMMETRY WITH `task_graph`, WHICH IS DELIBERATE AND LOOKS LIKE
        A BUG. `task_graph` excludes namespace-mode instances because that
        tree is agent-writable, so a peer notice placed there asserts nothing
        about who sent it. That is the PEER lane's trust story. `namespace` is
        the older, still-supported MAIL layout, and a deliver notice in it is
        as meaningful as it has always been — so excluding it here would drop
        a working instance out of the mesh and report nothing."""
        cfg = loads(_doc(("a-deadbeef", "n-1a2b3c4d"),
                         modes={"n-1a2b3c4d": "namespace"},
                         mail_graph=MAIL_GRAPH_ALL))
        self.assertEqual(sorted(cfg.instances["n-1a2b3c4d"].peers), ["a-deadbeef"])
        self.assertTrue(binding.check_cold(cfg, "a-deadbeef", "n-1a2b3c4d"))

    def test_task_graph_still_excludes_it(self):
        """The other half, in one place, so the asymmetry is visible rather
        than inferred from two files."""
        cfg = loads(_doc(("a-deadbeef", "n-1a2b3c4d"),
                         modes={"n-1a2b3c4d": "namespace"},
                         fleet_domain="example.invalid",
                         task_graph=TASK_GRAPH_ALL))
        self.assertEqual(cfg.instances["n-1a2b3c4d"].peer_senders, frozenset())


class RefusalTests(unittest.TestCase):
    def test_a_value_other_than_all_is_refused(self):
        for bad in ("ALL", "All", "everyone", True, ["a-deadbeef"]):
            with self.subTest(value=bad), self.assertRaises(ConfigError) as ctx:
                loads(_doc(mail_graph=bad))
            self.assertIn("config.mail_graph", str(ctx.exception))

    def test_all_alongside_an_explicit_list_is_refused(self):
        """Two sources for one graph is the drift the word exists to remove.
        Refused rather than merged, and the message names who declared what."""
        doc = json.loads(_doc(mail_graph=MAIL_GRAPH_ALL))
        doc["instances"]["b-c0ffee01"]["peers"] = ["a-deadbeef"]
        with self.assertRaises(ConfigError) as ctx:
            loads(json.dumps(doc))
        self.assertIn("config.mail_graph", str(ctx.exception))
        self.assertIn("'b-c0ffee01'", str(ctx.exception))

    def test_the_wildcard_member_is_still_accepted_in_a_list(self):
        """`mail_graph` does not retire `ALLOW_ANY`. They are different
        statements and both remain expressible."""
        doc = json.loads(_doc())
        doc["instances"]["b-c0ffee01"]["peers"] = [ALLOW_ANY]
        self.assertEqual(sorted(loads(json.dumps(doc)).instances["b-c0ffee01"].peers),
                         [ALLOW_ANY])


class NoFleetDomainNeededTests(unittest.TestCase):
    def test_the_mail_mesh_loads_without_a_fleet_domain(self):
        """`task_graph` REQUIRES one — a peer address is
        `<name>@<fleet_domain>`. The mail lane addresses instances as
        `agent.<name>@local` and never needed a domain, so requiring one here
        would refuse a configuration that works."""
        cfg = loads(_doc(mail_graph=MAIL_GRAPH_ALL))
        self.assertIsNone(cfg.fleet_domain)
        self.assertTrue(binding.check_cold(cfg, "a-deadbeef", "b-c0ffee01"))


if __name__ == "__main__":
    unittest.main()
