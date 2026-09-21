"""`task_graph: "all"` — the fleet-level shorthand, expanded at load.

A fully-connected fleet was previously expanded by the adapter, which meant
the expansion lived on the side of the seam that cannot be held to it. It is
expanded here now, ONCE, into the same per-instance `peer_senders` sets an
explicit graph produces — so validation, `binding.check_peer_edge`,
`peers --json` and the lane-disjointness check all see one shape and none of
them knows the shorthand exists.

A WILDCARD IN `peer_senders` IS STILL REFUSED, and the difference is not
cosmetic. `peer_senders: ["ALL"]` on one instance is a local statement with a
global effect: reading that entry does not tell you the fleet is fully
connected, and a later instance silently joins the mesh. A top-level key is a
global statement with a global effect.
"""

import json
import unittest

from router import binding
from router.config import ALLOW_ANY, ConfigError, TASK_GRAPH_ALL, loads
from router.peers import render_peers_json


def _doc(names=("a", "b", "c"), *, domain="example.invalid", modes=None, **top):
    modes = modes or {}
    doc = {
        "state_dir": "/tmp/state",
        "instances": {
            n: {("namespace" if modes.get(n) == "namespace" else "handoff_dir"):
                f"/tmp/sandboxes/{n}"}
            for n in names
        },
    }
    if domain:
        doc["fleet_domain"] = domain
    doc.update(top)
    return json.dumps(doc)


class ExpansionTests(unittest.TestCase):
    def test_all_expands_to_every_other_instance(self):
        cfg = loads(_doc(task_graph=TASK_GRAPH_ALL))
        self.assertEqual(
            {n: sorted(i.peer_senders) for n, i in cfg.instances.items()},
            {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]})

    def test_nobody_is_their_own_sender(self):
        """Self-edges are not merely useless — `_drain_cold` refuses a
        self-send, so an expansion that produced one would declare an edge the
        router then rejects."""
        cfg = loads(_doc(task_graph=TASK_GRAPH_ALL))
        for name, inst in cfg.instances.items():
            self.assertNotIn(name, inst.peer_senders)

    def test_the_expansion_is_what_enforcement_reads(self):
        """Expanded at load into the real field, so nothing downstream learns
        a second way to ask 'may A task B'."""
        cfg = loads(_doc(task_graph=TASK_GRAPH_ALL))
        self.assertTrue(binding.check_peer_edge(cfg, "a", "b"))
        self.assertTrue(binding.check_peer_edge(cfg, "c", "a"))
        self.assertFalse(binding.check_peer_edge(cfg, "a", "a"))

    def test_peers_json_renders_the_expansion_not_the_shorthand(self):
        """The audit surface is unchanged: the adapter's `--verify` diffs this
        against what it rendered, and it must see edges rather than a word."""
        cfg = loads(_doc(task_graph=TASK_GRAPH_ALL))
        rendered = json.loads(render_peers_json(cfg))
        self.assertEqual(sorted(rendered["a@example.invalid"]),
                         ["b@example.invalid", "c@example.invalid"])
        self.assertNotIn(TASK_GRAPH_ALL, json.dumps(rendered))

    def test_a_namespace_mode_instance_is_left_out_of_the_mesh(self):
        """`all` cannot mean "including the one that can never be a peer
        target". A namespace-mode tree is agent-writable end to end, so a peer
        notice placed there asserts nothing — the per-instance check refuses
        such an edge, and the expansion must not generate one for the refusal
        to catch."""
        cfg = loads(_doc(("a", "b", "n"), modes={"n": "namespace"},
                         task_graph=TASK_GRAPH_ALL))
        self.assertEqual(cfg.instances["n"].peer_senders, frozenset())
        for name in ("a", "b"):
            self.assertNotIn("n", cfg.instances[name].peer_senders)


class RefusalTests(unittest.TestCase):
    def test_a_value_other_than_all_is_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            loads(_doc(task_graph="everyone"))
        self.assertIn("task_graph", str(ctx.exception))

    def test_all_without_a_fleet_domain_is_refused_by_the_task_graph_check(self):
        """Same rule the per-instance field follows: no domain, no peer lane,
        so no edge can be declared by any spelling.

        ASSERTS WHICH GUARD REFUSED IT. Two checks reject this config — the
        `task_graph` one and, downstream, the per-instance
        `peer_senders`-without-a-domain one — and both mention `fleet_domain`.
        A test that only looked for that word passed with the `task_graph`
        check deleted, because the downstream guard caught the expansion it
        had already produced. Found by mutation; it is the same defect as an
        assertion satisfied by output it was not pinning, one layer down."""
        with self.assertRaises(ConfigError) as ctx:
            loads(_doc(domain=None, task_graph=TASK_GRAPH_ALL))
        message = str(ctx.exception)
        self.assertIn("fleet_domain", message)
        self.assertIn("config.task_graph", message,
                      "refused by the wrong guard — the task_graph check is "
                      "what should reject this, before any expansion happens")

    def test_all_alongside_an_explicit_edge_is_refused(self):
        """Two sources for one graph is the drift this key exists to remove.
        Refused rather than merged, and the message names who declared what."""
        doc = json.loads(_doc(task_graph=TASK_GRAPH_ALL))
        doc["instances"]["b"]["peer_senders"] = ["a"]
        with self.assertRaises(ConfigError) as ctx:
            loads(json.dumps(doc))
        self.assertIn("peer_senders", str(ctx.exception))
        self.assertIn("'b'", str(ctx.exception))

    def test_the_wildcard_in_peer_senders_is_still_refused(self):
        """The whole point of putting the shorthand at the top level: a
        per-instance wildcard stays refused, so a fully-connected fleet can
        only be declared as a fleet-level fact."""
        doc = json.loads(_doc())
        doc["instances"]["b"]["peer_senders"] = [ALLOW_ANY]
        with self.assertRaises(ConfigError):
            loads(json.dumps(doc))


if __name__ == "__main__":
    unittest.main()
