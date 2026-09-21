"""Step 2 of the peer-lane build, the loader half: `peer_senders` is directed,
validated, refused in `namespace` mode at EITHER end, refused without a
domain, and DISJOINT from `peers` per ordered pair by `ConfigError` — the
guarantee the whole lane rests on, since it is what makes "no edge -> the
mail-lane decision" safe. Plus `intake_dir` containment and the two windows."""

import unittest

from router.binding import check_cold, check_peer_edge
from router.config import (
    PEER_REPLY_WINDOW_SECONDS_DEFAULT, SENDER_EXPOSURE_WINDOW_SECONDS_DEFAULT,
    ConfigError, derive_peer_graph, load_obj,
)


def _doc(instances, **top):
    d = {"state_dir": "/x/state", "fleet_domain": "example.invalid", "instances": instances}
    d.update(top)
    return d


def _h(name, **spec):
    spec.setdefault("handoff_dir", f"/x/{name}")
    return spec


class PeerSendersValidationTests(unittest.TestCase):
    def test_directed_edge_loads_and_is_one_way(self):
        cfg = load_obj(_doc({"a": _h("a"), "b": _h("b", peer_senders=["a"])}))
        self.assertEqual(cfg.instances["b"].peer_senders, frozenset({"a"}))
        self.assertEqual(cfg.instances["a"].peer_senders, frozenset())
        self.assertTrue(check_peer_edge(cfg, "a", "b"))
        self.assertFalse(check_peer_edge(cfg, "b", "a"), "an edge is directed")
        self.assertFalse(check_cold(cfg, "a", "b"), "an edge is not a mail pair")

    def test_refused_without_fleet_domain(self):
        d = _doc({"a": _h("a"), "b": _h("b", peer_senders=["a"])})
        del d["fleet_domain"]
        with self.assertRaises(ConfigError) as ctx:
            load_obj(d)
        self.assertIn("fleet_domain", str(ctx.exception))
        self.assertIn("config.instances.b.peer_senders", str(ctx.exception))

    def test_empty_list_without_fleet_domain_is_fine(self):
        """An empty `peer_senders` declares nothing, so there is nothing to refuse."""
        d = _doc({"a": _h("a"), "b": _h("b", peer_senders=[])})
        del d["fleet_domain"]
        cfg = load_obj(d)
        self.assertEqual(cfg.instances["b"].peer_senders, frozenset())

    def test_unknown_wildcard_self_and_duplicate_refused(self):
        cases = {
            "unknown": ["mallory"],
            "wildcard": ["ALLOW_ANY"],
            "self": ["b"],
            "duplicate": ["a", "a"],
        }
        for label, senders in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ConfigError) as ctx:
                    load_obj(_doc({"a": _h("a"), "b": _h("b", peer_senders=senders)}))
                self.assertIn("config.instances.b.peer_senders", str(ctx.exception))

    def test_not_an_array_of_strings_refused(self):
        for bad in ("a", [1], {"a": 1}, None):
            with self.subTest(value=bad):
                with self.assertRaises(ConfigError):
                    load_obj(_doc({"a": _h("a"), "b": _h("b", peer_senders=bad)}))

    def test_namespace_mode_recipient_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj(_doc({"a": _h("a"), "b": {"namespace": "/x/b", "peer_senders": ["a"]}}))
        self.assertIn("namespace-mode", str(ctx.exception))

    def test_namespace_mode_sender_refused(self):
        """Forced by two accepted rules together: a reply travels the
        reverse edge as a PEER notice into the SENDER's tree, and a
        namespace-mode tree can hold no peer notice. So both ends of an
        edge are handoff-mode."""
        with self.assertRaises(ConfigError) as ctx:
            load_obj(_doc({"a": {"namespace": "/x/a"}, "b": _h("b", peer_senders=["a"])}))
        self.assertIn("'a'", str(ctx.exception))
        self.assertIn("reverse edge", str(ctx.exception))

    def test_peer_root_set_iff_handoff_mode_and_domain(self):
        cfg = load_obj(_doc({"a": _h("a"), "b": {"namespace": "/x/b"}}))
        self.assertEqual(str(cfg.instances["a"].peer_root), "/x/a/peer")
        self.assertIsNone(cfg.instances["b"].peer_root)
        no_domain = _doc({"a": _h("a")})
        del no_domain["fleet_domain"]
        self.assertIsNone(load_obj(no_domain).instances["a"].peer_root)

    def test_extra_instance_keys_cannot_redeclare_peer_senders(self):
        with self.assertRaises(ConfigError):
            load_obj(_doc({"a": _h("a")}), extra_instance_keys=["peer_senders"],
                     validate_extra=lambda n, k, v: v)


class LaneDisjointnessTests(unittest.TestCase):
    def test_pair_in_both_declarations_is_a_config_error_naming_the_pair(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj(_doc({
                "a": _h("a", peers=["b"]),
                "b": _h("b", peers=["a"], peer_senders=["a"]),
            }))
        msg = str(ctx.exception)
        self.assertIn("'a' -> 'b'", msg)
        self.assertIn("disjoint", msg)

    def test_allow_any_counts_as_the_mail_side_of_the_pair(self):
        with self.assertRaises(ConfigError):
            load_obj(_doc({
                "a": _h("a", peers=["ALLOW_ANY"]),
                "b": _h("b", peers=["ALLOW_ANY"], peer_senders=["a"]),
            }))

    def test_one_sided_mail_listing_is_not_a_mail_pair_so_no_conflict(self):
        """`peers` is mutual; a one-sided listing grants nothing on the mail
        lane, so it cannot overlap an edge."""
        cfg = load_obj(_doc({
            "a": _h("a", peers=["b"]),
            "b": _h("b", peer_senders=["a"]),
        }))
        self.assertTrue(check_peer_edge(cfg, "a", "b"))
        self.assertFalse(check_cold(cfg, "a", "b"))

    def test_edge_one_way_and_mail_pair_between_others_coexist(self):
        cfg = load_obj(_doc({
            "a": _h("a", peers=["c"]),
            "b": _h("b", peer_senders=["a"]),
            "c": _h("c", peers=["a"]),
        }))
        self.assertTrue(check_peer_edge(cfg, "a", "b"))
        self.assertTrue(check_cold(cfg, "a", "c"))
        self.assertEqual(derive_peer_graph(cfg), {"a": [], "b": ["a"], "c": []})


class WindowsAndIntakeTests(unittest.TestCase):
    def test_window_defaults(self):
        cfg = load_obj(_doc({"a": _h("a")}))
        self.assertEqual(cfg.sender_exposure_window_seconds, SENDER_EXPOSURE_WINDOW_SECONDS_DEFAULT)
        self.assertEqual(cfg.peer_reply_window_seconds, PEER_REPLY_WINDOW_SECONDS_DEFAULT)
        self.assertEqual((cfg.sender_exposure_window_seconds, cfg.peer_reply_window_seconds),
                         (86400, 604800))

    def test_windows_configurable_positive_ints_only(self):
        cfg = load_obj(_doc({"a": _h("a")}, sender_exposure_window_seconds=60,
                            peer_reply_window_seconds=120))
        self.assertEqual((cfg.sender_exposure_window_seconds, cfg.peer_reply_window_seconds), (60, 120))
        for key in ("sender_exposure_window_seconds", "peer_reply_window_seconds"):
            for bad in (0, -1, "60", True, 1.5):
                with self.subTest(key=key, value=bad):
                    with self.assertRaises(ConfigError):
                        load_obj(_doc({"a": _h("a")}, **{key: bad}))

    def test_intake_dir_loads_and_is_contained(self):
        cfg = load_obj(_doc({"a": _h("a")}, intake_dir="/x/intake"))
        self.assertEqual(str(cfg.intake_dir), "/x/intake")
        self.assertIsNone(load_obj(_doc({"a": _h("a")})).intake_dir)
        for bad in ("relative/intake", "/x/state/intake", "/x", "/x/a/intake", "/x/a"):
            with self.subTest(intake_dir=bad):
                with self.assertRaises(ConfigError):
                    load_obj(_doc({"a": _h("a")}, intake_dir=bad))

    def test_unknown_top_level_key_still_refused(self):
        with self.assertRaises(ConfigError):
            load_obj(_doc({"a": _h("a")}, peer_domain="x"))


if __name__ == "__main__":
    unittest.main()
