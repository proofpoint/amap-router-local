"""The optional intake remover's seam at PLUGIN_API (3, 1): the loader's
minor-gated precedence for optional factories, the capability members, and
the public-surface delta, exactly.

The precedence, for each optional factory: below the minor that introduces
it the name is IGNORED whatever it is (never type-checked, never called);
at or above it, absent means OFF, callable means ON, and present but not
callable is refused `missing_factory`."""
from __future__ import annotations

import ast
import logging
from pathlib import Path

from router import transport
from router.tests.test_transport import GOOD, _PluginDir

#: The (3, 0) public surface, and the names (3, 1) adds to it: exactly these.
SURFACE_3_0 = ['CLASSES', 'CommitResult', 'Dependency', 'EntryKind', 'FACTORY_PORTS', 'HOPFSOPS_ATTRIBUTES', 'HOPFSOPS_METHODS', 'HOP_FACTS_MAX', 'HopFsOps', 'INBOUNDPORT_ATTRIBUTES', 'INBOUND_KINDS', 'InboundPort', 'KeyOps', 'LIST_LIMIT_MAX', 'LIST_SCAN_MAX', 'LoadedPlugin', 'MAX_PLUGIN_BYTES', 'MakeHopReceiver', 'MakeHopSender', 'MakeIntakeReader', 'MakeIntakeWriter', 'MakeMarkerStore', 'MakeSender', 'MakeSigner', 'MakeUpstreamMarkerStore', 'MakeVerifier', 'NOTICE_BUNDLE_SCHEMA', 'NOTICE_REFUSAL_REASONS', 'NullTransport', 'PLUGIN_API', 'PluginRefused', 'REFUSAL_REASONS', 'REQUIRED_FACTORIES', 'RETIRED_AT_RE', 'RETIRE_RESULTS', 'RUNTIME_ROLES', 'RenameResult', 'RetireResult', 'SEAM_REFUSAL_REASONS', 'SeamRefused', 'Settings', 'Signer', 'StageSide', 'TRANSPORT_REASONS', 'TRUSTED_UIDS', 'TransportPort', 'UNSAFE_READ_REASONS', 'UPSTREAM_MARKER_ATTRIBUTES', 'UpstreamMarkers', 'Verifier', 'WITHDRAW_RESULTS', 'WithdrawResult', 'capture_verdict_class', 'check_disjoint', 'check_fsops_classes', 'check_list_args', 'check_retired_at', 'classify', 'is_current_bundle_schema', 'load_plugin']
ADDED_AT_3_1 = ['HOPFSOPS_OPTIONAL_METHODS', 'IntakeRemover', 'OPTIONAL_FACTORIES', 'REMOVE_DIR_ENTRIES_MAX', 'REMOVE_RESULTS', 'REQUIRED_MINOR', 'RemoveResult']

ABSENT = b""
CALLABLE = (b"\nREMOVER_CALLS = []\n"
            b"def make_intake_remover(settings, fsops):\n"
            b"    REMOVER_CALLS.append(settings)\n"
            b"    return ('remover', settings, fsops)\n")
NOT_CALLABLE = b"\nmake_intake_remover = 7\n"


class MatrixTests(_PluginDir):

    def plugin(self, minor, variant, major=3):
        self.write(GOOD.replace(b"PLUGIN_API = (3, 0)",
                                b"PLUGIN_API = (%d, %d)" % (major, minor)) + variant)

    def loaded(self):
        try:
            return self.load()
        except transport.PluginRefused as e:
            self.fail(f"refused: {e.reason}: {e}")

    def test_below_the_minor_the_name_is_ignored_whatever_it_is(self):
        for variant in (ABSENT, CALLABLE, NOT_CALLABLE):
            with self.subTest(variant=variant[:30]):
                self.plugin(0, variant)
                got = self.loaded()
                self.assertEqual(got.optional_capabilities, frozenset())
                with self.assertRaises(AttributeError):
                    got.make_intake_remover({}, None)
                if variant is CALLABLE:
                    self.assertEqual(got.namespace["REMOVER_CALLS"], [],
                                     "a (3, 0) plugin's remover was called")

    def test_one_info_line_for_an_ignored_present_name(self):
        self.plugin(0, CALLABLE)
        with self.assertLogs("amap_router_local.transport", logging.INFO) as logs:
            self.loaded()
        self.assertEqual(len(logs.output), 1)
        self.assertIn("make_intake_remover", logs.output[0])

    def test_at_or_above_the_minor(self):
        for minor in (1, 2):
            with self.subTest(minor=minor, variant="absent"):
                self.plugin(minor, ABSENT)
                self.assertEqual(self.loaded().optional_capabilities, frozenset())
            with self.subTest(minor=minor, variant="callable"):
                self.plugin(minor, CALLABLE)
                got = self.loaded()
                self.assertEqual(got.optional_capabilities,
                                 frozenset({"make_intake_remover"}))
                self.assertEqual(got.make_intake_remover({"k": 1}, "fsops"),
                                 ("remover", {"k": 1}, "fsops"))
            with self.subTest(minor=minor, variant="not callable"):
                self.plugin(minor, NOT_CALLABLE)
                self.refused("missing_factory")

    def test_other_majors_are_refused(self):
        for major in (2, 4):
            with self.subTest(major=major):
                self.plugin(1, CALLABLE, major=major)
                self.refused("api_mismatch")

    def test_a_newer_minor_s_unknown_extras_are_ignored(self):
        self.plugin(2, CALLABLE + b"\nmake_something_later = 7\n")
        self.assertEqual(self.loaded().optional_capabilities,
                         frozenset({"make_intake_remover"}))

    def test_the_null_transport_offers_nothing(self):
        self.assertEqual(transport.NullTransport.optional_capabilities, frozenset())


class SurfaceTests(_PluginDir):

    def test_the_public_surface_is_3_0_plus_exactly_the_3_1_names(self):
        tree = ast.parse(Path(transport.__file__).read_text(encoding="utf-8"))
        names = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
        public = {n for n in names if not n.startswith("_")}
        self.assertEqual(public, set(SURFACE_3_0) | set(ADDED_AT_3_1))

    def test_remove_results_are_their_own_vocabulary(self):
        self.assertEqual(transport.REMOVE_RESULTS, ("removed", "absent"))
        for vocab in (transport.TRANSPORT_REASONS, transport.NOTICE_REFUSAL_REASONS,
                      transport.UNSAFE_READ_REASONS, transport.REFUSAL_REASONS):
            self.assertEqual(set(transport.REMOVE_RESULTS) & set(vocab), set())
        self.assertEqual(transport.REMOVE_DIR_ENTRIES_MAX, transport.LIST_LIMIT_MAX)

    def test_the_optional_fsops_method_is_only_listed_optionally(self):
        self.assertEqual(dict(transport.HOPFSOPS_OPTIONAL_METHODS), {"stat_group_pinned": (3, 1)})
        self.assertNotIn("stat_group_pinned", transport.HOPFSOPS_METHODS)
        doc = " ".join(transport.HopFsOps.__doc__.split())
        self.assertIn("OPTIONAL AT (3, 1)", doc)
        self.assertIn("`stat_group_pinned(dir_fd, name) -> (uid, gid, mode, kind)`", doc)
