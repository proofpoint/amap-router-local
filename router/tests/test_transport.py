"""`router/transport.py`: the plugin seam.

Every loader refusal has a witness here, and every witness has a valid twin
(`test_a_valid_plugin_loads`) so a loader that refused everything could not
pass them. The test suite cannot create root-owned files, so the loader's
trusted uids are widened to include this process's own; the root-only
default is asserted separately (`test_the_default_trusts_only_root`).
"""
from __future__ import annotations

import ast
import hashlib
import logging
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import config as config_mod
from router import inflight, service, transport
from router.tests import helpers
from router.tests.helpers import write_request
from router.tests.test_inflight import EXT, FakeTransport, _InflightCase

GOOD = b'''
PLUGIN_API = (1, 0)
LOADS = []
LOADS.append("executed")

def make_sender(settings, fsops):
    return ("sender", settings, fsops)

def make_intake_reader(settings, fsops):
    return ("reader", settings, fsops)
'''

ME = (0, os.getuid())


class _PluginDir(unittest.TestCase):
    """A plugin file in a private directory whose parents all pass."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(os.path.realpath(self._tmp.name)) / "plugins"
        self.dir.mkdir(mode=0o755)
        os.chmod(self.dir, 0o755)
        os.chmod(self.dir.parent, 0o755)
        self.path = self.dir / "plugin.py"
        self.write(GOOD)
        # The whole chain up to `/` must pass the parent checks. Where the
        # temp root does not, every test here ERRORS rather than skips: a
        # skip would also hide a loader that refused every parent (a
        # mutation of the sticky rule did exactly that while this was a skip).

    def tearDown(self):
        os.chmod(self.dir, 0o755)
        self._tmp.cleanup()

    def write(self, data: bytes, mode: int = 0o644):
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        self.path.write_bytes(data)
        os.chmod(self.path, mode)
        self.sha = hashlib.sha256(data).hexdigest()

    def load(self, **kw):
        kw.setdefault("trusted_uids", ME)
        path = kw.pop("path", str(self.path))
        sha = kw.pop("sha", self.sha)
        return transport.load_plugin(path, sha, **kw)

    def refused(self, reason, **kw):
        with self.assertRaises(transport.PluginRefused) as cm:
            self.load(**kw)
        self.assertEqual(cm.exception.reason, reason, str(cm.exception))
        return cm.exception


class LoaderTests(_PluginDir):

    def test_a_valid_plugin_loads(self):
        """The twin every refusal below is measured against."""
        p = self.load()
        self.assertEqual(p.api, (1, 0))
        self.assertEqual(p.sha256, self.sha)
        self.assertEqual(p.path, str(self.path))
        self.assertEqual(p.make_sender({"k": 1}, "fs")[0], "sender")
        self.assertEqual(p.make_intake_reader({}, "fs")[0], "reader")
        self.assertEqual(p.namespace["LOADS"], ["executed"])

    def test_the_default_trusts_only_root(self):
        self.assertEqual(transport.TRUSTED_UIDS, (0,))
        if os.getuid() != 0:
            self.refused("parent_owner", trusted_uids=transport.TRUSTED_UIDS)

    # -- missing --------------------------------------------------------

    def test_a_configured_plugin_that_is_absent_is_refused(self):
        self.path.unlink()
        self.refused("missing")

    # -- PLUGIN_API -----------------------------------------------------

    def test_a_different_major_is_refused(self):
        self.write(GOOD.replace(b"PLUGIN_API = (1, 0)", b"PLUGIN_API = (2, 0)"))
        self.refused("api_mismatch")

    def test_an_older_minor_is_refused(self):
        self.refused("api_mismatch", api=(1, 1))

    def test_a_newer_minor_is_accepted(self):
        self.write(GOOD.replace(b"PLUGIN_API = (1, 0)", b"PLUGIN_API = (1, 7)"))
        self.assertEqual(self.load().api, (1, 7))

    def test_a_malformed_or_missing_api_is_refused(self):
        for bad in (b"PLUGIN_API = '1.0'", b"PLUGIN_API = (1,)", b"PLUGIN_API = (True, 0)",
                    b"NOT_THE_API = (1, 0)"):
            with self.subTest(bad=bad):
                self.write(GOOD.replace(b"PLUGIN_API = (1, 0)", bad))
                self.refused("api_mismatch")

    # -- the hash, and which bytes run ----------------------------------

    def test_a_hash_mismatch_is_refused_before_anything_runs(self):
        marker = self.dir.parent / "ran"
        self.write(GOOD + f"open({str(marker)!r}, 'w').close()\n".encode())
        self.refused("hash_mismatch", sha="0" * 64)
        self.assertFalse(marker.exists(), "plugin code ran before its hash was checked")

    def test_only_the_hashed_bytes_are_executed(self):
        """The bytes compiled are the very bytes hashed, read once from the
        pinned descriptor; the file is never read again by path."""
        hashed, compiled = [], []
        real_sha, real_compile = hashlib.sha256, compile

        def sha(data=b""):
            hashed.append(data)
            return real_sha(data)

        def comp(source, *a, **k):
            compiled.append(source)
            return real_compile(source, *a, **k)

        with mock.patch.object(transport.hashlib, "sha256", sha), \
                mock.patch("router.transport.compile", comp, create=True):
            self.load()
        self.assertEqual(len(hashed), 1)
        self.assertEqual(compiled, hashed)

    def test_a_file_swapped_after_loading_changes_nothing(self):
        p = self.load()
        self.write(GOOD.replace(b'"sender"', b'"evil"'))
        self.assertEqual(p.make_sender({}, None)[0], "sender")

    # -- owner, path, permissions ---------------------------------------

    def test_a_file_owned_by_an_untrusted_uid_is_refused(self):
        real_fstat = os.fstat

        def fstat(fd):
            st = real_fstat(fd)
            if stat.S_ISREG(st.st_mode):
                fields = list(st)
                fields[stat.ST_UID] = 4242
                return os.stat_result(fields)
            return st

        with mock.patch.object(transport.os, "fstat", fstat):
            self.refused("owner")

    def test_a_parent_owned_by_an_untrusted_uid_is_refused(self):
        if os.getuid() == 0:
            self.skipTest("as root every parent is trusted")
        self.refused("parent_owner", trusted_uids=(0,))

    def test_a_parent_writable_by_others_is_refused(self):
        os.chmod(self.dir, 0o777)
        self.refused("parent_writable")
        os.chmod(self.dir, 0o775)
        self.refused("parent_writable")

    def test_a_sticky_world_writable_parent_is_accepted(self):
        """Like /tmp: others cannot rename or remove an entry they do not own."""
        os.chmod(self.dir, 0o1777)
        self.assertEqual(self.load().sha256, self.sha)

    def test_a_relative_path_is_refused(self):
        self.refused("path_not_absolute", path="plugins/plugin.py")

    def test_a_symlinked_component_is_refused(self):
        link = self.dir.parent / "via"
        link.symlink_to(self.dir)
        self.refused("path_not_canonical", path=str(link / "plugin.py"))
        final = self.dir / "alias.py"
        final.symlink_to(self.path)
        self.refused("path_not_canonical", path=str(final))

    def test_a_plugin_inside_an_agent_reachable_directory_is_refused(self):
        self.refused("agent_reachable", forbidden_roots=[self.dir])
        self.refused("agent_reachable", forbidden_roots=[self.dir.parent])

    def test_wrong_permissions_are_refused(self):
        for mode in (0o600, 0o664, 0o666, 0o755, 0o4644):
            with self.subTest(mode=oct(mode)):
                self.write(GOOD, mode=mode)
                self.refused("mode")
        for mode in (0o444, 0o644):
            with self.subTest(mode=oct(mode)):
                self.write(GOOD, mode=mode)
                self.load()

    def test_the_pinned_open_refuses_a_symlink(self):
        """The second line behind `path_not_canonical`: a symlink swapped in
        after the path checks is refused by the O_NOFOLLOW open itself."""
        target = self.dir / "real.py"
        os.rename(self.path, target)
        self.path.symlink_to(target)
        with self.assertRaises(transport.PluginRefused) as cm:
            transport._read_pinned(self.path, ME)
        self.assertEqual(cm.exception.reason, "symlink")

    def test_a_non_regular_file_is_refused(self):
        self.path.unlink()
        self.path.mkdir(mode=0o755)
        os.chmod(self.path, 0o755)
        self.refused("not_regular")
        self.path.rmdir()

    def test_an_oversized_plugin_is_refused_before_it_is_read(self):
        reads = []
        real_read = os.read

        def read(fd, n):
            reads.append(n)
            return real_read(fd, n)

        with mock.patch.object(transport, "MAX_PLUGIN_BYTES", 16), \
                mock.patch.object(transport.os, "read", read):
            self.refused("too_large")
        self.assertEqual(reads, [], "read before the size was checked")

    def test_a_plugin_that_grows_past_the_cap_while_read_is_refused(self):
        """fstat said small; the bytes said otherwise. The read loop is the
        second check, for a file growing between the two."""
        real_fstat = os.fstat

        def fstat(fd):
            st = real_fstat(fd)
            if stat.S_ISREG(st.st_mode):
                fields = list(st)
                fields[stat.ST_SIZE] = 1
                return os.stat_result(fields)
            return st

        with mock.patch.object(transport, "MAX_PLUGIN_BYTES", 16), \
                mock.patch.object(transport.os, "fstat", fstat):
            self.refused("too_large")

    # -- the plugin's own content ---------------------------------------

    def test_a_plugin_that_fails_to_run_is_refused(self):
        self.write(b"PLUGIN_API = (1, 0)\ndef broken(:\n")
        self.refused("exec_failed")
        self.write(b"raise RuntimeError('no')\n")
        self.refused("exec_failed")

    def test_a_missing_factory_is_refused(self):
        self.write(GOOD.replace(b"def make_intake_reader", b"def make_something_else"))
        self.refused("missing_factory")
        self.write(GOOD + b"make_sender = 3\n")
        self.refused("missing_factory")


class NoPluginImportTests(unittest.TestCase):
    """The interface module imports no plugin and never imports by name."""

    ALLOWED = {"__future__", "errno", "hashlib", "hmac", "os", "stat", "types",
               "dataclasses", "pathlib", "typing"}

    def test_transport_imports_only_the_standard_modules_it_needs(self):
        tree = ast.parse(Path(transport.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertTrue(imported, "parsed no imports at all")
        self.assertLessEqual(imported, self.ALLOWED)

    def test_nothing_imports_by_name_at_run_time(self):
        source = Path(transport.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertNotIn("__import__", names)
        self.assertNotIn("import_module", attrs)
        self.assertNotIn("importlib", names)


class RefusalVocabularyTests(unittest.TestCase):

    def test_the_shared_reasons(self):
        """One vocabulary for both loaders, agreed with the sibling runtime."""
        self.assertEqual(set(transport.REFUSAL_REASONS), {
            "path_not_absolute", "path_not_canonical", "agent_reachable",
            "parent_owner", "parent_writable", "missing", "symlink", "not_regular",
            "owner", "mode", "too_large", "hash_mismatch", "exec_failed",
            "api_mismatch", "missing_factory", "fsops_unavailable", "role_mismatch",
        })


class NullTransportTests(unittest.TestCase):

    def test_every_factory_returns_none(self):
        n = transport.NullTransport()
        self.assertIsNone(n.make_sender({}, None))
        self.assertIsNone(n.make_intake_reader({}, None))
        self.assertEqual(n.api, transport.PLUGIN_API)


class ConfigTests(helpers.RouterTestCase):

    def _write_and_load(self, extra):
        root = self.tmp / "alice"
        root.mkdir(exist_ok=True)
        doc = {"state_dir": str(self.state_dir),
               "instances": {"alice": {"namespace": str(root)}}}
        doc.update(extra)
        return config_mod.load_obj(doc)

    def test_absent_means_no_plugin(self):
        self.assertIsNone(self._write_and_load({}).transport_plugin)

    def test_path_and_sha256_together(self):
        sha = "a" * 64
        cfg = self._write_and_load({"transport_plugin": {"path": "/opt/p.py", "sha256": sha}})
        self.assertEqual(cfg.transport_plugin, config_mod.TransportPluginPin("/opt/p.py", sha))

    def test_both_or_neither_and_the_shapes(self):
        bad = [
            {"path": "/opt/p.py"},
            {"sha256": "a" * 64},
            {"path": "/opt/p.py", "sha256": "a" * 64, "extra": 1},
            {"path": "opt/p.py", "sha256": "a" * 64},
            {"path": "/opt/p.py", "sha256": "A" * 64},
            {"path": "/opt/p.py", "sha256": "a" * 63},
            "/opt/p.py",
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(config_mod.ConfigError) as cm:
                    self._write_and_load({"transport_plugin": value})
                self.assertIn("transport_plugin", str(cm.exception))


class CanonicalPathTests(_PluginDir):
    """The plugin path must be its own realpath, compared as WRITTEN: no
    lexical normalisation runs first, in the loader or in the config."""

    def symlink_decoy(self):
        """`<root>/a/b` is a symlink to `<root>/x/y`. The kernel resolves
        `<root>/a/b/../c/p.py` to `<root>/x/c/p.py`; its lexical normal form
        is `<root>/a/c/p.py`, a DIFFERENT file: the decoy, whose sha256 is
        the pinned one. Returns (the configured path, the decoy's sha)."""
        root = self.dir
        for d in ("a/c", "x/y", "x/c"):
            (root / d).mkdir(parents=True, mode=0o755)
            os.chmod(root / d, 0o755)
        os.chmod(root / "a", 0o755)
        os.chmod(root / "x", 0o755)
        (root / "a" / "b").symlink_to(root / "x" / "y")
        decoy = root / "a" / "c" / "p.py"
        decoy.write_bytes(GOOD)
        os.chmod(decoy, 0o644)
        other = root / "x" / "c" / "p.py"
        other.write_bytes(GOOD.replace(b'"sender"', b'"other"'))
        os.chmod(other, 0o644)
        return f"{root}/a/b/../c/p.py", hashlib.sha256(GOOD).hexdigest()

    def test_dotdot_after_a_symlink_is_refused_and_neither_file_is_opened(self):
        """THE WITNESS. Before this check compared the raw string, the path
        was normalised to the decoy's, which passed and was loaded."""
        path, sha = self.symlink_decoy()
        # A WRAPPING spy, not a raising one: under the old check the decoy is
        # opened and LOADED, so the refusal assertion FAILS (not errors).
        with mock.patch.object(transport, "_read_pinned", wraps=transport._read_pinned) as spy:
            self.refused("path_not_canonical", path=path, sha=sha)
        spy.assert_not_called()

    def test_every_lexical_spelling_is_refused(self):
        name = self.dir.name
        spellings = [
            f"{self.dir}/../{name}/plugin.py",
            f"{self.dir}/./plugin.py",
            f"{self.dir}//plugin.py",
            f"{self.dir}/plugin.py/",
            "/" + str(self.path),          # a leading "//": normpath keeps it, realpath does not
        ]
        for path in spellings:
            with self.subTest(path=path):
                self.refused("path_not_canonical", path=path)
        self.assertEqual(self.load().sha256, self.sha, "the plain spelling still loads")

    def test_accepted_means_equal_to_both_forms(self):
        """The acceptance's `path == normpath(path) == realpath(path)`: the
        realpath equality the loader checks implies the normpath one, on
        every case here, and every refused case breaks at least one."""
        decoy, _sha = self.symlink_decoy()
        name = self.dir.name
        link = self.dir.parent / "via"
        link.symlink_to(self.dir)
        cases = [str(self.path), decoy, f"{self.dir}/../{name}/plugin.py",
                 f"{self.dir}/./plugin.py", f"{self.dir}//plugin.py",
                 f"{self.dir}/plugin.py/", "/" + str(self.path), str(link / "plugin.py")]
        accepted = 0
        for path in cases:
            with self.subTest(path=path):
                try:
                    transport._check_path(path, (), ME)
                except transport.PluginRefused as e:
                    self.assertEqual(e.reason, "path_not_canonical")
                    self.assertFalse(path == os.path.normpath(path) == os.path.realpath(path))
                else:
                    accepted += 1
                    self.assertTrue(path == os.path.normpath(path) == os.path.realpath(path))
        self.assertEqual(accepted, 1)

    def test_the_config_keeps_the_path_as_written_and_startup_refuses_it(self):
        path, sha = self.symlink_decoy()
        cfg = config_mod.load_obj({
            "state_dir": str(self.dir.parent / "state"),
            "instances": {"alice": {"namespace": str(self.dir.parent / "alice")}},
            "transport_plugin": {"path": path, "sha256": sha}})
        self.assertEqual(cfg.transport_plugin.path, path, "the config rewrote the pin")
        real = transport.load_plugin
        with mock.patch.object(transport, "load_plugin",
                               lambda p, h, **kw: real(p, h, **dict(kw, trusted_uids=ME))), \
                mock.patch.object(transport, "_read_pinned",
                                  wraps=transport._read_pinned) as spy:
            with self.assertRaises(transport.PluginRefused) as cm:
                service.start_transport(cfg)
        self.assertEqual(cm.exception.reason, "path_not_canonical")
        spy.assert_not_called()

    def test_a_spelling_only_change_on_reload_is_refused(self):
        """A consequence, stated in the README: the pin is compared as
        written, so respelling the same file is a changed plugin, and the
        reload is refused (fail closed) like any other plugin change."""
        doc = {"state_dir": str(self.dir.parent / "state"),
               "instances": {"alice": {"namespace": str(self.dir.parent / "alice")}},
               "transport_plugin": {"path": str(self.path), "sha256": self.sha}}
        cfg = config_mod.load_obj(doc)
        respelled = config_mod.load_obj(dict(doc, transport_plugin={
            "path": f"{self.dir}/./plugin.py", "sha256": self.sha}))
        with mock.patch.object(service, "load", return_value=respelled):
            with self.assertLogs("amap_router_local", logging.ERROR) as logs:
                kept = service.reload_config("/unused", cfg)
        self.assertTrue(kept.reload_failed)
        self.assertEqual(kept.transport_plugin.path, str(self.path))
        self.assertTrue(any("changed transport_plugin" in m for m in logs.output))


class StartupTests(_PluginDir):
    """`service.start_transport`: loaded once, refusal stops startup."""

    def _cfg(self, pin=None):
        base = helpers.RouterTestCase("run")
        base.setUp()
        self.addCleanup(base.tearDown)
        cfg = base.make_config({"alice": []})
        from dataclasses import replace
        return replace(cfg, transport_plugin=pin)

    def test_no_plugin_configured_gives_no_transport(self):
        self.assertIsNone(service.start_transport(self._cfg()))

    def _trusting_me(self):
        """`service` calls the loader with its root-only default; widen it
        to this process's uid, which is all the suite can own."""
        real = transport.load_plugin

        def load(path, sha, **kw):
            kw["trusted_uids"] = ME
            return real(path, sha, **kw)

        return mock.patch.object(transport, "load_plugin", load)

    def test_a_configured_but_absent_plugin_stops_startup(self):
        self.path.unlink()
        cfg = self._cfg(config_mod.TransportPluginPin(str(self.path), self.sha))
        with self._trusting_me():
            with self.assertRaises(transport.PluginRefused) as cm:
                service.start_transport(cfg)
        self.assertEqual(cm.exception.reason, "missing")

    def test_a_valid_plugin_is_refused_until_the_filesystem_port_exists(self):
        cfg = self._cfg(config_mod.TransportPluginPin(str(self.path), self.sha))
        with self._trusting_me(), mock.patch.object(service, "logger") as log:
            with self.assertRaises(transport.PluginRefused) as cm:
                service.start_transport(cfg)
        self.assertEqual(cm.exception.reason, "fsops_unavailable")
        log.info.assert_not_called()  # no success line for a refused plugin
        self.assertIn(self.sha, cm.exception.detail)
        self.assertIn(str(self.path), cm.exception.detail)

    def test_run_forever_refuses_to_start_and_never_polls(self):
        self.path.unlink()
        cfg = self._cfg(config_mod.TransportPluginPin(str(self.path), self.sha))
        with self._trusting_me(), mock.patch.object(service, "poll_once") as poll, \
                mock.patch.object(service.time, "sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(transport.PluginRefused):
                service.run_forever(cfg, 0.01)
        poll.assert_not_called()

    def test_a_reload_that_changes_the_plugin_is_refused(self):
        cfg = self._cfg()
        changed = config_mod.TransportPluginPin("/opt/other.py", "b" * 64)
        from dataclasses import replace
        with mock.patch.object(service, "load", return_value=replace(cfg, transport_plugin=changed)):
            with self.assertLogs("amap_router_local", logging.ERROR):
                kept = service.reload_config("/unused", cfg)
        self.assertEqual(kept, cfg)  # the last good config, with the failure flagged
        self.assertTrue(kept.reload_failed)
        self.assertFalse(cfg.reload_failed)


class ClaimedIsPendingTests(_InflightCase):
    """`TransportPort.has_pending` is true for a CLAIMED request as well as
    an unclaimed one. A transport that reported a claimed request as not
    pending would make the in-flight step hand it over again (or settle it
    as an anomaly) while the downstream runtime is sending it."""

    def setUp(self):
        super().setUp()
        self.port = ClaimingTransport()

    def test_a_claimed_request_is_waited_on_not_rewritten_or_settled(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.claim("00000001")
        s = self.drain()
        # The fake RECORDS a rewrite attempt before refusing it: the drain
        # isolates the refusal, so a refusal alone would never be seen.
        self.assertEqual(self.port.writes, ["00000001"], "handed over again while claimed")
        self.assertEqual(s["inflight_errored"], 0)
        self.assertFalse(self.has_result(), "settled while the downstream runtime held it")
        self.assertEqual(s["outbound_inflight_waiting"], 1)
        self.port.send("00000001", recipients=[EXT])
        self.drain()
        self.assertEqual(self.result()["outcome"], "accepted")
        self.assertEqual(self.port.writes, ["00000001"])

    def test_the_protocol_says_so(self):
        doc = transport.TransportPort.__doc__
        self.assertIn("WHETHER OR NOT the downstream runtime has claimed it", doc)
        self.assertIs(inflight.TransportPort, transport.TransportPort)


class ClaimingTransport(FakeTransport):
    """A downstream runtime that CLAIMS a request before sending it: the
    request leaves `pending` for `claimed`, and `has_pending` covers both."""

    def __init__(self):
        super().__init__()
        self.claimed = {}

    def claim(self, n):
        self.claimed[n] = self.pending.pop(n)

    def has_pending(self, n):
        return n in self.pending or n in self.claimed

    def write_request(self, n, data):
        if n in self.claimed:
            self.writes.append(n)  # recorded BEFORE the refusal, as in FakeTransport
            raise AssertionError(f"transport request {n} rewritten while claimed")
        super().write_request(n, data)

    def send(self, n, **kw):
        if n in self.claimed:
            self.pending[n] = self.claimed.pop(n)
        super().send(n, **kw)


if __name__ == "__main__":
    unittest.main()
