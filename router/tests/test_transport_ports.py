"""The ports a plugin's factories receive (`router/transport.py`):
`HopFsOps`, `KeyOps`, `Signer`, `Verifier` and the factory signatures.

Interface only, so the tests pin the INTERFACE: the method list and
parameter names against the contract's (B §e.2), the result vocabularies,
that every annotation resolves, and that `runtime_checkable` conformance
accepts a complete stub and refuses an incomplete one. No static type
checker runs here (the package is stdlib-only); these are its stand-in.
"""
from __future__ import annotations

import inspect
import typing
import unittest

from router import transport

#: B §e.2, verbatim: method -> parameter names (excluding self).
CONTRACT_HOPFSOPS = {
    "open_root_nofollow": ["path"],
    "descend_pinned": ["root_fd", "rel"],
    "mkdir_and_pin": ["parent_fd", "name", "mode"],
    "stage_tree": ["parent_fd", "staging_name"],
    "commit_durable": ["stage_dirfd", "dest_dirfd", "name", "data", "mode"],
    "open_stage_dir": ["tree_fd", "side"],
    "replace_durable": ["dir_fd", "name", "data", "mode"],
    "rename_noreplace": ["src_fd", "src", "dst_fd", "dst"],
    "open_regular_pinned": ["dir_fd", "name", "max_bytes"],
    "stat_owner_pinned": ["dir_fd", "name"],
    "remove_pinned": ["dir_fd", "name"],
    "fsync_file": ["fd"],
    "fsync_dir": ["fd"],
}


def _protocol_methods(proto):
    return {name for name, v in vars(proto).items()
            if callable(v) and not name.startswith("_")}


class HopFsOpsShapeTests(unittest.TestCase):

    def test_exactly_the_contracts_methods(self):
        self.assertEqual(_protocol_methods(transport.HopFsOps), set(CONTRACT_HOPFSOPS))
        self.assertEqual(list(transport.HOPFSOPS_METHODS), list(CONTRACT_HOPFSOPS))

    def test_each_methods_parameters(self):
        for name, params in CONTRACT_HOPFSOPS.items():
            with self.subTest(method=name):
                sig = inspect.signature(getattr(transport.HopFsOps, name))
                self.assertEqual([p for p in sig.parameters if p != "self"], params)

    def test_not_yet_is_a_port_attribute_and_the_dispatch_is_stated(self):
        self.assertIn("NOT_YET", transport.HopFsOps.__annotations__)
        doc = " ".join(transport.HopFsOps.__doc__.split())
        self.assertIn("r is fsops.NOT_YET", doc)
        self.assertIn("type(r) is bytes", doc)
        self.assertIn("protocol violation, never a skip", doc)

    def test_the_stage_sides(self):
        self.assertEqual(typing.get_args(transport.StageSide), ("up", "down", "intake"))
        hints = typing.get_type_hints(transport.HopFsOps.open_stage_dir)
        self.assertEqual(hints["side"], transport.StageSide)
        import router.transport as mod
        src = inspect.getsource(mod)
        block = src[src.index("#: `open_stage_dir`'s sides"):src.index("StageSide = ")]
        block = " ".join(block.replace("#:", " ").split())
        for phrase in ("BEFORE anything is opened", "disagrees with `tree_fd`'s binding",
                       "mode exactly 0700", "never repaired or chmodded",
                       "creates neither", "same inode", "One `\"intake\"` value"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, block)

    def test_per_item_tags_final_role_hop_only_not_yet_and_barriers(self):
        doc = " ".join(transport.HopFsOps.__doc__.split())
        for phrase in ("examples, not the list", "INCLUDES THE ITEM'S IDENTITY",
                       "`[A-Za-z0-9._-]+`", "NAME_MAX",
                       "RELATIVE TO THE `stage_tree` ROOT",
                       "ON A HOP-TREE OR HOST-INTAKE BINDING ONLY",
                       "(an agent-writable source)",
                       "a link count of 2 raises like any other count but 1",
                       "THE BARRIER EACH METHOD OWES",
                       "whether or not this call created the directory",
                       "no fallback to link-then-unlink",
                       "returns its root fd UNPUBLISHED", "It never renames",
                       "even when the name was already missing",
                       "then publishes it with `rename_noreplace`"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, doc)

    def test_stage_tree_never_publishes(self):
        """Admission commits the identity marker INSIDE the staging subtree
        before the no-replace rename; `stage_tree` has neither the marker
        nor the final name, so it must not publish."""
        doc = " ".join(transport.HopFsOps.__doc__.split())
        self.assertNotIn("published by a no-replace rename", doc)

    def test_entry_kind_precisions(self):
        import router.transport as mod
        src = inspect.getsource(mod)
        block = src[src.index("#: `stat_owner_pinned`'s kinds"):src.index("EntryKind = ")]
        for phrase in ("S_ISREG", "S_ISDIR", "NON-following", "FileNotFoundError",
                       "never folded into a kind"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, block)

    def test_max_bytes_is_keyword_only(self):
        sig = inspect.signature(transport.HopFsOps.open_regular_pinned)
        self.assertIs(sig.parameters["max_bytes"].kind, inspect.Parameter.KEYWORD_ONLY)

    def test_the_result_vocabularies(self):
        self.assertEqual(typing.get_args(transport.CommitResult),
                         ("created", "exists_same", "exists_different"))
        self.assertEqual(typing.get_args(transport.RenameResult),
                         ("moved", "src_gone", "dst_exists"))
        self.assertEqual(typing.get_args(transport.EntryKind), ("file", "dir", "other"))
        hints = typing.get_type_hints(transport.HopFsOps.commit_durable)
        self.assertEqual(hints["return"], transport.CommitResult)
        hints = typing.get_type_hints(transport.HopFsOps.rename_noreplace)
        self.assertEqual(hints["return"], transport.RenameResult)

    def test_the_destination_tag_is_not_a_parameter_and_its_rules_are_stated(self):
        """The frozen five-argument signature, and the invariants the
        implementation owes in its place (the dest-tag adjudication)."""
        # Whitespace-normalised: docstring indentation differs by Python version.
        doc = " ".join(transport.HopFsOps.__doc__.split())
        for phrase in ("open_root_nofollow", "stage_tree", "fd-number reuse",
                       "stable across restarts", "unique among destinations",
                       "FINAL role", "RAISES before anything is staged",
                       "best-effort fallback", "(`st_dev`, `st_ino`) with different tags",
                       "never from registration order"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, doc)


class AnnotationsResolveTests(unittest.TestCase):
    """The stand-in for a type checker: every annotation in every port
    resolves to a real type."""

    def test_every_port_method_resolves(self):
        for proto in (transport.HopFsOps, transport.KeyOps, transport.Signer,
                      transport.Verifier, transport.TransportPort, transport.InboundPort):
            for name in _protocol_methods(proto):
                with self.subTest(port=proto.__name__, method=name):
                    hints = typing.get_type_hints(getattr(proto, name))
                    self.assertIn("return", hints)

    def test_the_factory_types(self):
        expected = {
            "MakeSender": ([transport.Settings, transport.HopFsOps], transport.TransportPort),
            "MakeIntakeReader": ([transport.Settings, transport.HopFsOps], transport.InboundPort),
            "MakeSigner": ([transport.Settings, transport.KeyOps], transport.Signer),
            "MakeVerifier": ([transport.Settings], transport.Verifier),
        }
        for alias, (args, ret) in expected.items():
            with self.subTest(alias=alias):
                got = typing.get_args(getattr(transport, alias))
                self.assertEqual(list(got[0]), args)
                self.assertIs(got[1], ret)
        for alias in ("MakeHopReceiver", "MakeIntakeWriter", "MakeMarkerStore", "MakeHopSender"):
            with self.subTest(alias=alias):
                got = typing.get_args(getattr(transport, alias))
                self.assertEqual(list(got[0]), [transport.Settings, transport.HopFsOps])

    def test_the_factory_table_names_every_factory_and_its_port(self):
        self.assertEqual(dict(transport.FACTORY_PORTS), {
            "make_sender": "HopFsOps", "make_intake_reader": "HopFsOps",
            "make_signer": "KeyOps", "make_verifier": None,
            "make_hop_receiver": "HopFsOps", "make_intake_writer": "HopFsOps",
            "make_marker_store": "HopFsOps", "make_hop_sender": "HopFsOps",
        })
        self.assertLessEqual(set(transport.REQUIRED_FACTORIES), set(transport.FACTORY_PORTS))


class _CompleteFsOps:
    NOT_YET = object()
    def open_root_nofollow(self, path): return 3
    def descend_pinned(self, root_fd, rel): return None
    def mkdir_and_pin(self, parent_fd, name, mode): return 4
    def stage_tree(self, parent_fd, staging_name): return 5
    def commit_durable(self, stage_dirfd, dest_dirfd, name, data, mode): return "created"
    def open_stage_dir(self, tree_fd, side): return 6
    def replace_durable(self, dir_fd, name, data, mode): return None
    def rename_noreplace(self, src_fd, src, dst_fd, dst): return "moved"
    def open_regular_pinned(self, dir_fd, name, *, max_bytes): return b""
    def stat_owner_pinned(self, dir_fd, name): return (0, 0o640, "file")
    def remove_pinned(self, dir_fd, name): return None
    def fsync_file(self, fd): return None
    def fsync_dir(self, fd): return None


class ConformanceTests(unittest.TestCase):

    def test_a_complete_implementation_conforms(self):
        self.assertIsInstance(_CompleteFsOps(), transport.HopFsOps)

    def test_each_missing_member_breaks_conformance(self):
        """Paired with the positive case: a check that accepted everything
        would pass that one alone. NOT_YET is a member like the methods."""
        for name in list(CONTRACT_HOPFSOPS) + ["NOT_YET"]:
            with self.subTest(missing=name):
                cls = type("Partial", (), {k: v for k, v in vars(_CompleteFsOps).items()
                                           if k != name and not k.startswith("__")})
                self.assertNotIsInstance(cls(), transport.HopFsOps)

    def test_keyops_signer_verifier(self):
        class K:
            def signing_key(self): return b"\0" * 32
            def key_id(self): return "k1"

        class S:
            key_id = "k1"
            def sign(self, msg): return b"\0" * 64

        class V:
            def verify(self, pub, msg, sig): return False

        self.assertIsInstance(K(), transport.KeyOps)
        self.assertIsInstance(S(), transport.Signer)
        self.assertIsInstance(V(), transport.Verifier)
        self.assertNotIsInstance(V(), transport.Signer)
        self.assertNotIsInstance(S(), transport.KeyOps)

    def test_keyops_has_no_path(self):
        """The signer never opens a path: nothing in KeyOps takes or
        returns one."""
        for name in _protocol_methods(transport.KeyOps):
            with self.subTest(method=name):
                sig = inspect.signature(getattr(transport.KeyOps, name))
                self.assertEqual([p for p in sig.parameters if p != "self"], [])
        self.assertIn("never opens a path", " ".join(transport.KeyOps.__doc__.split()))


class InterfaceOnlyTests(unittest.TestCase):
    """No implementation: every port method body is `...`."""

    def test_every_port_method_is_a_stub(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path(transport.__file__).read_text(encoding="utf-8"))
        ports = {"HopFsOps", "KeyOps", "Signer", "Verifier", "TransportPort", "InboundPort"}
        seen = 0
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name in ports:
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        seen += 1
                        body = [b for b in item.body
                                if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant)
                                        and isinstance(b.value.value, str))]
                        self.assertEqual(len(body), 1, item.name)
                        self.assertIsInstance(body[0], ast.Expr, item.name)
                        self.assertIs(body[0].value.value, Ellipsis, item.name)
        self.assertEqual(seen, 13 + 2 + 1 + 1 + 5 + 2)


class PluginApiCoversThePortsTests(unittest.TestCase):

    def test_the_major_is_documented_to_cover_them(self):
        import router.transport as mod
        src = inspect.getsource(mod)
        start = src.index("PLUGIN_API: Tuple[int, int]")
        comment = src[src.rindex("#: `(major, minor)`", 0, start):start]
        for name in ("HopFsOps", "KeyOps", "Signer", "Verifier", "factory signatures"):
            with self.subTest(name=name):
                self.assertIn(name, comment)


if __name__ == "__main__":
    unittest.main()
