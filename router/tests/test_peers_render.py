"""`peers.render_peers` is a pure display function over `config.derive_matrix`
— no filesystem access, so these drive it directly off `config.load_obj`
without needing namespace directories on disk (mirrors `test_config.py`)."""

import unittest

from router.config import load_obj
import router.peers as peers_mod
from router.peers import render_peers


def _cfg(instances):
    return load_obj({
        "state_dir": "/x/state",
        "instances": {
            name: {"namespace": f"/x/{name}", "peers": list(peers)}
            for name, peers in instances.items()
        },
    })


def cells_for(out: str, name: str):
    """The matrix row for `name`, as a list of glyphs.

    Parses the grid rather than substring-matching. The old tests asserted
    `"yes" in row` / `"yes" not in row`, which worked only while the glyph was
    a word no instance name could contain. With `y` that is false — half the
    names in a real fleet contain the letter — so a substring test would pass
    on any row mentioning `sandy` and prove nothing.
    """
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped or "peers:" in line:
            continue
        parts = stripped.split()
        # "<idx> <name>  <glyph> <glyph> ..."
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].rstrip("*") == name:
            return parts[2:]
    raise AssertionError(f"no matrix row for {name!r} in:\n{out}")


class TestPeersRender(unittest.TestCase):
    def test_one_sided_listing_renders_dash_both_directions(self):
        # alice lists bob, but bob does NOT list alice back -> not mutual.
        cfg = _cfg({"alice": ["bob"], "bob": []})
        out = render_peers(cfg)

        lines = out.splitlines()
        matrix_lines = [ln for ln in lines if ln.strip().startswith("alice") or ln.strip().startswith("bob")]
        # Find the matrix row for alice and bob (not the "peers:" declared lines).
        alice_cells = cells_for(out, "alice")
        bob_cells = cells_for(out, "bob")
        self.assertNotIn("y", alice_cells, "one-sided listing must not render reachable")
        self.assertNotIn("y", bob_cells)
        self.assertNotIn("FULL MESH", out)

    def test_allow_any_declarer_marked_but_non_reciprocating_third_still_dash(self):
        # bob declares ALLOW_ANY. alice lists bob (mutual: alice<->bob).
        # carol does NOT list bob at all -> bob's ALLOW_ANY doesn't help;
        # mutuality still fails for carol<->bob.
        cfg = _cfg({"alice": ["bob"], "bob": ["ALLOW_ANY"], "carol": []})
        out = render_peers(cfg)

        self.assertIn("ALLOW_ANY", out)
        self.assertIn("** ANY", out)
        self.assertIn(
            "declares ALLOW_ANY; mutuality still required", out
        )
        self.assertNotIn("FULL MESH", out)

        # alice <-> bob is mutual (alice lists bob, bob's ALLOW_ANY covers
        # the other direction) -> "yes" appears at least once.
        self.assertIn("y", cells_for(out, "alice"))

        # carol never listed bob, so carol<->bob is NOT mutual despite
        # bob's ALLOW_ANY — the matrix row/col for carol must show at
        # least one '-' against bob (not "yes" everywhere for carol).
        self.assertIn("-", cells_for(out, "carol"))
        self.assertIn("-", cells_for(out, "carol"))

    def test_all_allow_any_full_mesh_banner(self):
        cfg = _cfg({"alice": ["ALLOW_ANY"], "bob": ["ALLOW_ANY"], "carol": ["ALLOW_ANY"]})
        out = render_peers(cfg)
        self.assertIn("!! FULL MESH", out)
        self.assertIn(
            "derived from per-instance peers at render time — never stored", out
        )

    def test_single_instance_is_not_full_mesh(self):
        # A valid one-instance config (config.load_obj permits it) declares
        # no peers and can cold-initiate to nobody -> the off-diagonal
        # iteration over a single name is empty, which must NOT be treated
        # as vacuously "every instance may cold-initiate to every other".
        cfg = _cfg({"alice": []})
        out = render_peers(cfg)
        self.assertNotIn("FULL MESH", out)

    def test_long_names_do_not_widen_the_grid(self):
        """Columns are NUMBERED, so a long slug costs one row label and not a
        whole column. Fifteen 30-character names as column headers is 450
        characters of header, which wraps in any terminal and stops being a
        grid — that is why the numbering exists."""
        cfg = _cfg({"a": ["a-very-long-instance-name"], "a-very-long-instance-name": ["a"]})
        out = render_peers(cfg)
        self.assertIn("a-very-long-instance-name", out)          # row label kept
        self.assertIn("y", cells_for(out, "a"))                  # and they are mutual
        # The header carries digits, never the names.
        header = [ln for ln in out.splitlines()
                  if ln.strip() and "peers:" not in ln][0]
        self.assertNotIn("a-very-long-instance-name", header)
        self.assertEqual(len(cells_for(out, "a")), 2)            # one cell per instance


if __name__ == "__main__":
    unittest.main()


class ClusterOrderingTest(unittest.TestCase):
    """Ordering is the point of this change, not the glyph width. Alphabetical
    interleaves separate meshes and hides the structure that explains a fleet's
    topology."""

    def _fleet(self):
        """Names chosen so ALPHABETICAL and CLUSTERED orders differ.

        The first version used amp-*, bridge-*, sandy-*, which sort into their
        own clusters — so alphabetical and clustered were the same sequence and
        the test passed with the clustering removed entirely. A fixture that
        cannot distinguish the two orderings cannot test the one that matters.
        Here each cluster's members are spread across the alphabet: sorting
        gives a1,a2,a3, b1,b2,b3, c1... interleaved, clustering gives
        a1,b1,c1 | a2,b2,c2 | a3,b3.
        """
        amp = ["a1", "b1", "c1", "d1", "e1"]
        bridge = ["a2", "b2"]
        sandy = ["a3", "b3"]
        spec = {}
        for n in amp:
            spec[n] = sorted(set(amp + bridge) - {n})
        for n in bridge:
            spec[n] = sorted(set(amp + bridge + sandy) - {n})
        for n in sandy:
            spec[n] = sorted(set(sandy + bridge) - {n})
        return _cfg(spec), amp, bridge, sandy

    def test_members_of_one_mesh_are_contiguous(self):
        cfg, amp, bridge, sandy = self._fleet()
        order = peers_mod.cluster_order(cfg, sorted(cfg.instances))
        for group in (amp, bridge, sandy):
            pos = sorted(order.index(n) for n in group)
            self.assertEqual(pos, list(range(pos[0], pos[0] + len(group))),
                             f"{group} is not contiguous in {order}")

    def test_ordering_is_deterministic(self):
        cfg, *_ = self._fleet()
        names = sorted(cfg.instances)
        self.assertEqual(peers_mod.cluster_order(cfg, names),
                         peers_mod.cluster_order(cfg, list(reversed(names))))

    def test_bands_change_exactly_at_cluster_boundaries(self):
        cfg, amp, bridge, sandy = self._fleet()
        order = peers_mod.cluster_order(cfg, sorted(cfg.instances))
        bands = peers_mod.cluster_index(cfg, order)
        self.assertEqual(len(set(bands)), 3)
        changes = sum(1 for i in range(1, len(bands)) if bands[i] != bands[i - 1])
        self.assertEqual(changes, 2)


class PeersHtmlTest(unittest.TestCase):
    """The page is written to a local file and never published — this fleet's
    real instance names and reachability are deployment detail."""

    def _cfg2(self):
        return _cfg({"alice": ["bob"], "bob": ["alice"], "carol": []})

    def test_it_is_self_contained(self):
        """No stylesheet, font, script or image fetched. Opening a review
        artifact must not become a network request."""
        html = peers_mod.render_peers_html(self._cfg2())
        for probe in ("http://", "https://", "<script", "@import", "src="):
            self.assertNotIn(probe, html, f"{probe!r} would reach outside the file")

    def test_it_renders_one_cell_per_pair_and_marks_self(self):
        html = peers_mod.render_peers_html(self._cfg2())
        self.assertEqual(html.count('class="c '), 9)      # 3x3
        self.assertEqual(html.count('class="c s"'), 3)    # the diagonal

    def test_unreachable_pairs_are_not_rendered_reachable(self):
        html = peers_mod.render_peers_html(self._cfg2())
        self.assertEqual(html.count('class="c y"'), 2)    # alice<->bob only

    def test_the_source_path_is_escaped(self):
        """Instance names cannot carry markup — `_NAME_RE` refuses anything
        outside `[a-z0-9-]` at config load, which is why the first version of
        this test was unwritable. The config PATH is under no such constraint
        and is rendered in the header, so that is where escaping earns its
        keep."""
        html = peers_mod.render_peers_html(self._cfg2(), "/tmp/<script>x</script>/r.json")
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
