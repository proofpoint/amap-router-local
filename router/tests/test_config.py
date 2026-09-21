import unittest
from pathlib import Path

from router.binding import check_cold
from router.config import (
    ALLOW_ANY, MODE_HANDOFF, MODE_NAMESPACE, ConfigError, address_for, derive_matrix,
    instance_for, load_obj,
)


class TestConfigLoad(unittest.TestCase):
    def test_good_load(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {
                "alice": {"namespace": "/x/alice", "peers": ["bob"]},
                "bob": {"namespace": "/x/bob", "peers": ["alice"]},
            },
        })
        self.assertEqual(set(cfg.instances), {"alice", "bob"})
        self.assertEqual(cfg.instances["alice"].peers, frozenset({"bob"}))
        self.assertEqual(str(cfg.state_dir), "/x/state")

    def test_allow_any_accepted(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {
                "alice": {"namespace": "/x/alice", "peers": ["bob"]},
                "bob": {"namespace": "/x/bob", "peers": [ALLOW_ANY]},
            },
        })
        self.assertIn(ALLOW_ANY, cfg.instances["bob"].peers)

    def test_missing_state_dir(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({"instances": {"alice": {"namespace": "/x/alice", "peers": []}}})
        self.assertIn("state_dir", str(ctx.exception))

    def test_unknown_top_key(self):
        with self.assertRaises(ConfigError):
            load_obj({
                "state_dir": "/x/state",
                "instances": {"alice": {"namespace": "/x/alice", "peers": []}},
                "bogus": 1,
            })

    def test_unknown_instance_key(self):
        with self.assertRaises(ConfigError):
            load_obj({
                "state_dir": "/x/state",
                "instances": {"alice": {"namespace": "/x/alice", "peers": [], "extra": 1}},
            })

    def test_bad_instance_name(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/state",
                "instances": {"Alice!": {"namespace": "/x/alice", "peers": []}},
            })
        self.assertIn("Alice!", str(ctx.exception))

    def test_unknown_peer(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/state",
                "instances": {"alice": {"namespace": "/x/alice", "peers": ["mallory"]}},
            })
        self.assertIn("mallory", str(ctx.exception))

    def test_relative_namespace_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj({
                "state_dir": "/x/state",
                "instances": {"alice": {"namespace": "relative/path", "peers": []}},
            })

    def test_relative_state_dir_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj({
                "state_dir": "relative/state",
                "instances": {"alice": {"namespace": "/x/alice", "peers": []}},
            })

    def test_state_dir_inside_namespace_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/alice/state",
                "instances": {"alice": {"namespace": "/x/alice", "peers": []}},
            })
        self.assertIn("state_dir", str(ctx.exception))

    def test_namespace_inside_state_dir_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj({
                "state_dir": "/x/state",
                "instances": {"alice": {"namespace": "/x/state/alice", "peers": []}},
            })

    def test_overlapping_namespaces_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/state",
                "instances": {
                    "alice": {"namespace": "/x/shared", "peers": []},
                    "bob": {"namespace": "/x/shared/sub", "peers": []},
                },
            })
        self.assertIn("overlap", str(ctx.exception))

    def test_duplicate_namespace_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj({
                "state_dir": "/x/state",
                "instances": {
                    "alice": {"namespace": "/x/same", "peers": []},
                    "bob": {"namespace": "/x/same", "peers": []},
                },
            })

    def test_non_object_config_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj([1, 2, 3])

    def test_empty_instances_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj({"state_dir": "/x/state", "instances": {}})


class TestTwoRootModel(unittest.TestCase):
    """`handoff_dir` (the host's split-root pair, primary/documented
    mode) and `namespace` (the pre-existing single-tree AMAP layout) are
    the two root shapes an instance may declare — exactly one, ever."""

    def test_handoff_dir_derives_inbox_outbox(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {"alice": {"handoff_dir": "/x/alice/handoff", "peers": []}},
        })
        inst = cfg.instances["alice"]
        self.assertEqual(inst.mode, MODE_HANDOFF)
        self.assertEqual(inst.root, Path("/x/alice/handoff"))
        self.assertEqual(inst.inbox_root, Path("/x/alice/handoff/inbox"))
        self.assertEqual(inst.outbox_root, Path("/x/alice/handoff/outbox"))

    def test_namespace_derives_inbound_outbound(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {"alice": {"namespace": "/x/alice", "peers": []}},
        })
        inst = cfg.instances["alice"]
        self.assertEqual(inst.mode, MODE_NAMESPACE)
        self.assertEqual(inst.root, Path("/x/alice"))
        self.assertEqual(inst.inbox_root, Path("/x/alice/inbound"))
        self.assertEqual(inst.outbox_root, Path("/x/alice/outbound"))

    def test_both_keys_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/state",
                "instances": {
                    "alice": {
                        "handoff_dir": "/x/alice/handoff", "namespace": "/x/alice/ns",
                        "peers": [],
                    },
                },
            })
        msg = str(ctx.exception)
        self.assertIn("handoff_dir", msg)
        self.assertIn("namespace", msg)
        self.assertIn("not both", msg)

    def test_neither_key_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/state",
                "instances": {"alice": {"peers": []}},
            })
        msg = str(ctx.exception)
        self.assertIn("handoff_dir", msg)
        self.assertIn("namespace", msg)

    def test_mixed_mode_config_both_load(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {
                "alice": {"handoff_dir": "/x/alice/handoff", "peers": ["bob"]},
                "bob": {"namespace": "/x/bob", "peers": ["alice"]},
            },
        })
        self.assertEqual(cfg.instances["alice"].mode, MODE_HANDOFF)
        self.assertEqual(cfg.instances["bob"].mode, MODE_NAMESPACE)
        self.assertTrue(check_cold(cfg, "alice", "bob"))

    def test_handoff_relative_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj({
                "state_dir": "/x/state",
                "instances": {"alice": {"handoff_dir": "relative/path", "peers": []}},
            })

    def test_state_dir_inside_handoff_dir_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/alice/handoff/state",
                "instances": {"alice": {"handoff_dir": "/x/alice/handoff", "peers": []}},
            })
        self.assertIn("state_dir", str(ctx.exception))

    def test_namespace_nested_inside_handoff_dir_overlap_rejected(self):
        """A `namespace`-mode instance's declared root nested inside a
        `handoff_dir`-mode instance's declared root must be caught — the
        overlap check runs over the DECLARED root, not the derived
        inbox_root/outbox_root leaves, precisely so a cross-mode nesting
        like this can't slip through."""
        with self.assertRaises(ConfigError) as ctx:
            load_obj({
                "state_dir": "/x/state",
                "instances": {
                    "alice": {"handoff_dir": "/x/shared", "peers": []},
                    "bob": {"namespace": "/x/shared/sub", "peers": []},
                },
            })
        self.assertIn("overlap", str(ctx.exception))


class TestAttachmentCapConfig(unittest.TestCase):
    def _doc(self, **extra):
        return {
            "state_dir": "/x/state",
            "instances": {
                "alice": {"namespace": "/x/alice", "peers": ["bob"]},
                "bob": {"namespace": "/x/bob", "peers": ["alice"]},
            },
            **extra,
        }

    def test_defaults_when_omitted(self):
        cfg = load_obj(self._doc())
        self.assertEqual(cfg.attachment_max_bytes, 8 * 1024 * 1024)
        self.assertEqual(cfg.attachment_max_count, 16)
        self.assertEqual(cfg.attachment_max_total_bytes, 32 * 1024 * 1024)

    def test_all_three_configurable(self):
        cfg = load_obj(self._doc(
            attachment_max_bytes=1024, attachment_max_count=3,
            attachment_max_total_bytes=2048,
        ))
        self.assertEqual(cfg.attachment_max_bytes, 1024)
        self.assertEqual(cfg.attachment_max_count, 3)
        self.assertEqual(cfg.attachment_max_total_bytes, 2048)

    def test_zero_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj(self._doc(attachment_max_count=0))

    def test_negative_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj(self._doc(attachment_max_bytes=-1))

    def test_non_int_rejected(self):
        with self.assertRaises(ConfigError):
            load_obj(self._doc(attachment_max_bytes="8388608"))

    def test_bool_rejected_despite_being_an_int_subclass(self):
        with self.assertRaises(ConfigError):
            load_obj(self._doc(attachment_max_count=True))

    def test_total_below_per_file_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj(self._doc(attachment_max_bytes=2048, attachment_max_total_bytes=1024))
        self.assertIn("attachment_max_total_bytes", str(ctx.exception))


class TestAddressing(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(address_for("alice"), "agent.alice@local")
        self.assertEqual(instance_for("agent.alice@local"), "alice")

    def test_instance_for_lowercases(self):
        self.assertEqual(instance_for("agent.Alice@local".lower()), "alice")

    def test_instance_for_rejects_garbage(self):
        for bad in ("not-an-address", "agent.alice@remote", "alice@local", "", None, 42):
            self.assertIsNone(instance_for(bad))


class TestMatrix(unittest.TestCase):
    def test_derive_matrix_mutual_only(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {
                "alice": {"namespace": "/x/alice", "peers": ["bob"]},
                "bob": {"namespace": "/x/bob", "peers": []},
                "carol": {"namespace": "/x/carol", "peers": ["alice"]},
            },
        })
        matrix = derive_matrix(cfg)
        # alice -> bob: alice allows bob, bob does not allow alice -> False
        self.assertFalse(matrix["alice"]["bob"])
        self.assertFalse(matrix["bob"]["alice"])
        # alice -> carol: alice does not list carol, carol lists alice -> False
        self.assertFalse(matrix["alice"]["carol"])
        # self-entries always False
        self.assertFalse(matrix["alice"]["alice"])

    def test_derive_matrix_allow_any_still_needs_mutuality(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {
                "alice": {"namespace": "/x/alice", "peers": [ALLOW_ANY]},
                "bob": {"namespace": "/x/bob", "peers": []},
            },
        })
        matrix = derive_matrix(cfg)
        # alice allows anyone (including bob), but bob doesn't allow alice.
        self.assertFalse(matrix["alice"]["bob"])
        self.assertFalse(matrix["bob"]["alice"])

    def test_derive_matrix_mutual_allow_any(self):
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {
                "alice": {"namespace": "/x/alice", "peers": [ALLOW_ANY]},
                "bob": {"namespace": "/x/bob", "peers": [ALLOW_ANY]},
            },
        })
        matrix = derive_matrix(cfg)
        self.assertTrue(matrix["alice"]["bob"])
        self.assertTrue(matrix["bob"]["alice"])

    def test_derive_matrix_agrees_with_check_cold_enforcement(self):
        """`derive_matrix` (the review artifact) and `binding.check_cold`
        (the enforcement path) must never disagree — `derive_matrix` calls
        `check_cold` directly rather than re-implementing its rule, and this
        pins that for every ordered pair across a handful of peer shapes
        (one-sided, mutual, ALLOW_ANY on one/both sides, isolated third
        party)."""
        cfg = load_obj({
            "state_dir": "/x/state",
            "instances": {
                "alice": {"namespace": "/x/alice", "peers": ["bob"]},
                "bob": {"namespace": "/x/bob", "peers": [ALLOW_ANY]},
                "carol": {"namespace": "/x/carol", "peers": []},
                "dave": {"namespace": "/x/dave", "peers": ["alice", ALLOW_ANY]},
            },
        })
        matrix = derive_matrix(cfg)
        names = sorted(cfg.instances)
        for a in names:
            for b in names:
                expected = False if a == b else check_cold(cfg, a, b)
                self.assertEqual(
                    matrix[a][b], expected, f"matrix[{a!r}][{b!r}] disagrees with check_cold"
                )


if __name__ == "__main__":
    unittest.main()
