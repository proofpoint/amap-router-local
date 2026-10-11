"""`router/registry.py`: reading the host registry, read-only.

The fixtures are the registry owner's own (`fixtures/registry/SOURCE.md`):
the shared skeleton vectors, and a snapshot its writer produced. Both are
pinned by sha256 here, so a change on either side fails loudly.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import config as config_mod
from router import registry, service
from router.status import StatusTracker
from router.tests import helpers

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "registry"
#: amap-host 3f28c782b41df5b701e259c535732e859553ddef:tests/fixtures/skeleton_vectors.json
SKELETON_SOURCE_SHA = "3f28c782b41df5b701e259c535732e859553ddef"
SKELETON_SHA256 = "7d4088dc1686aa8daa9a65a4a820ec118bf214ebd51ed112880a81a2955a6d1c"
SNAPSHOT_SHA256 = "98e5fd3f521e89a4d1ab74574e33a1a2cdb030652ba9c56402f6f16ef7a8e81d"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class FixtureTests(unittest.TestCase):

    def test_the_fixtures_are_the_pinned_ones(self):
        self.assertEqual(_sha(FIXTURES / "skeleton_vectors.json"), SKELETON_SHA256)
        self.assertEqual(_sha(FIXTURES / "snapshot.json"), SNAPSHOT_SHA256)
        self.assertIn(SKELETON_SOURCE_SHA, (FIXTURES / "SOURCE.md").read_text())


class SkeletonTests(unittest.TestCase):
    """This router's stdlib skeleton() gives exactly the registry owner's
    answers."""

    @classmethod
    def setUpClass(cls):
        cls.v = json.loads((FIXTURES / "skeleton_vectors.json").read_text())

    def test_fold_definition(self):
        self.assertEqual(tuple(self.v["reserved_local_parts"]), registry.RESERVED_LOCAL_PARTS)
        self.assertEqual(self.v["fold"]["confusables"],
                         {chr(k): v for k, v in registry._CONFUSABLES.items()})
        for sep in self.v["fold"]["separators_removed"]:
            self.assertEqual(registry.skeleton("a" + sep + "b"), "ab")

    def test_every_vector(self):
        checked = 0
        for name, want in self.v["skeletons"]:
            with self.subTest(name=name):
                self.assertEqual(registry.skeleton(name), want)
                checked += 1
        reserved = {registry.skeleton(r) for r in registry.RESERVED_LOCAL_PARTS}
        for name in self.v["reserved"]:
            with self.subTest(reserved=name):
                self.assertIn(registry.skeleton(name), reserved)
                checked += 1
        for name in self.v["not_reserved"]:
            with self.subTest(not_reserved=name):
                self.assertNotIn(registry.skeleton(name), reserved)
                checked += 1
        for a, b in self.v["collide"]:
            with self.subTest(collide=(a, b)):
                self.assertEqual(registry.skeleton(a), registry.skeleton(b))
                checked += 1
        for a, b in self.v["distinct"]:
            with self.subTest(distinct=(a, b)):
                self.assertNotEqual(registry.skeleton(a), registry.skeleton(b))
                checked += 1
        self.assertGreater(checked, 20, "the fixture yielded almost nothing to check")


class _Dir(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.reg = base / "registry"
        self.state = base / "state"
        self.reg.mkdir()
        self.state.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def doc(self):
        return json.loads((FIXTURES / "snapshot.json").read_text())

    def put(self, doc=None, raw=None):
        data = raw if raw is not None else json.dumps(doc if doc is not None else self.doc()).encode()
        (self.reg / registry.SNAPSHOT).write_bytes(data)

    def unavailable(self, code):
        with self.assertRaises(registry.RegistryUnavailable) as cm:
            registry.load(self.reg, self.state)
        self.assertEqual(cm.exception.code, code, str(cm.exception))


class ParseTests(_Dir):

    def test_the_real_snapshot(self):
        self.put(raw=(FIXTURES / "snapshot.json").read_bytes())
        reg = registry.load(self.reg, self.state)
        self.assertEqual(reg.seq, 3)
        self.assertEqual([(e.name, e.state) for e in reg.entries],
                         [("alpha", "active"), ("beta", "retired")])
        resolved, held = reg.resolve()
        self.assertEqual(list(resolved), ["alpha"])
        self.assertEqual(held, [])
        self.assertEqual(resolved["alpha"].stable_key, "/srv/work/alpha")

    def test_absent_symlink_fifo_directory_and_oversize(self):
        self.unavailable("absent")
        target = self.reg / "real.json"
        target.write_text("{}")
        (self.reg / registry.SNAPSHOT).symlink_to(target)
        self.unavailable("symlink")
        (self.reg / registry.SNAPSHOT).unlink()
        os.mkfifo(self.reg / registry.SNAPSHOT)
        # Under an alarm: a reader that blocks on the FIFO must FAIL this
        # test, not hang the suite.
        import signal

        def _timeout(*_):
            raise AssertionError("the reader blocked on a FIFO")

        old = signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(5)
        try:
            self.unavailable("not_regular")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        (self.reg / registry.SNAPSHOT).unlink()
        (self.reg / registry.SNAPSHOT).mkdir()
        self.unavailable("not_regular")
        (self.reg / registry.SNAPSHOT).rmdir()
        self.put()
        with mock.patch.object(registry, "MAX_SNAPSHOT_BYTES", 10):
            self.unavailable("too_large")

    def test_strict_json(self):
        for raw in (b'{"seq": 1, "seq": 2}', b'{"seq": NaN}', b"\xff", b"[]", b"{nope"):
            with self.subTest(raw=raw):
                self.put(raw=raw)
                self.unavailable("invalid")

    def test_unknown_schema_token(self):
        d = self.doc()
        d["schema"] = "amap-host.registry/2"
        self.put(d)
        self.unavailable("schema")

    def test_every_used_field_is_shape_checked(self):
        bad = {
            "logical_id": "XYZ", "name": "alpha\n", "adapter": "docker",
            "stable_key": "", "binding_seq": 0, "name_seq": True,
            "enrollment_epoch": "1", "first_registered_ts": "2026-10-11 04:00:00",
            "state": "deleted",
        }
        for field, value in bad.items():
            with self.subTest(field=field):
                d = self.doc()
                d["entries"][0][field] = value
                self.put(d)
                self.unavailable("invalid")
            with self.subTest(missing=field):
                d = self.doc()
                del d["entries"][0][field]
                self.put(d)
                self.unavailable("invalid")
        for field, value in (("seq", 0), ("written_at", "now"), ("entries", {})):
            with self.subTest(top=field):
                d = self.doc()
                d[field] = value
                self.put(d)
                self.unavailable("invalid")

    def test_a_duplicate_logical_id(self):
        d = self.doc()
        d["entries"][1]["logical_id"] = d["entries"][0]["logical_id"]
        self.put(d)
        self.unavailable("invalid")


class SeqTests(_Dir):

    def test_seq_is_persisted_and_never_goes_backwards(self):
        self.put()
        registry.load(self.reg, self.state)
        self.assertEqual(registry.seq_path(self.state).read_text(), "3")
        registry.load(self.reg, self.state)  # equal is fine
        d = self.doc()
        d["seq"] = 7
        self.put(d)
        registry.load(self.reg, self.state)
        self.assertEqual(registry.seq_path(self.state).read_text(), "7")
        d["seq"] = 5
        self.put(d)
        with self.assertRaises(registry.RegistryRolledBack):
            registry.load(self.reg, self.state)
        self.assertEqual(registry.seq_path(self.state).read_text(), "7", "lowered by a rollback")

    def test_the_operator_acknowledges_a_restore_by_removing_the_file(self):
        d = self.doc()
        d["seq"] = 9
        self.put(d)
        registry.load(self.reg, self.state)
        d["seq"] = 4
        self.put(d)
        with self.assertRaises(registry.RegistryRolledBack):
            registry.load(self.reg, self.state)
        registry.seq_path(self.state).unlink()
        self.assertEqual(registry.load(self.reg, self.state).seq, 4)

    def test_a_corrupt_seq_file_holds(self):
        self.put()
        registry.seq_path(self.state).parent.mkdir(parents=True)
        registry.seq_path(self.state).write_text("lots")
        self.unavailable("seq_unreadable")


class ReportTests(_Dir):

    def test_off_changes_nothing(self):
        r = registry.report_for(None, self.state, ["a", "b"])
        self.assertEqual(r.state, "off")
        self.assertEqual(registry.state_key(r, "a"), "a")
        with self.assertRaises(registry.RegistryUnavailable):
            registry.hop_key(r, "a")

    def test_resolved_and_held(self):
        self.put()
        r = registry.report_for(self.reg, self.state, ["alpha", "beta", "gamma"])
        self.assertEqual(r.state, "ok")
        self.assertEqual(list(r.resolved), ["alpha"])
        self.assertEqual(r.held, {"beta": registry.HELD_NOT_REGISTERED,
                                  "gamma": registry.HELD_NOT_REGISTERED})
        lid = r.resolved["alpha"].logical_id
        self.assertEqual(registry.state_key(r, "alpha"), lid)
        self.assertEqual(registry.hop_key(r, "alpha"), lid)
        with self.assertRaises(KeyError):
            registry.state_key(r, "gamma")

    def test_a_skeleton_collision_holds_both_names(self):
        d = self.doc()
        d["entries"][1]["state"] = "active"
        d["entries"][1]["name"] = "a1pha"
        self.put(d)
        r = registry.report_for(self.reg, self.state, ["alpha", "a1pha"])
        self.assertEqual(r.resolved, {})
        self.assertEqual(r.held, {"alpha": registry.HELD_COLLISION,
                                  "a1pha": registry.HELD_COLLISION})

    def test_an_unusable_or_rolled_back_registry_holds_everything(self):
        r = registry.report_for(self.reg, self.state, ["alpha"])
        self.assertEqual((r.state, r.held), ("unavailable", {"alpha": registry.HELD_UNAVAILABLE}))
        d = self.doc()
        d["seq"] = 9
        self.put(d)
        registry.report_for(self.reg, self.state, ["alpha"])
        d["seq"] = 2
        self.put(d)
        r = registry.report_for(self.reg, self.state, ["alpha"])
        self.assertEqual((r.state, r.held), ("rolled_back", {"alpha": registry.HELD_ROLLED_BACK}))


class ServiceTests(helpers.RouterTestCase):
    """Under a registry, only resolved instances are drained, and status
    reports the rest as held."""

    def setUp(self):
        super().setUp()
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        doc = json.loads((FIXTURES / "snapshot.json").read_text())
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(doc))
        from dataclasses import replace
        self.cfg = replace(self.make_config({"alpha": [], "beta": []}), registry_dir=self.reg)
        service._REGISTRY_LOGGED.clear()

    def test_only_resolved_instances_are_drained(self):
        drained = []
        real = service.outbound.drain_instance

        def spy(cfg, name, **kw):
            drained.append(name)
            return real(cfg, name, **kw)

        with mock.patch.object(service.outbound, "drain_instance", spy), \
                self.assertLogs("amap_router_local", logging.WARNING):
            summary = service.run_once(self.cfg, None)
        self.assertEqual(drained, ["alpha"])
        self.assertEqual(list(summary), ["alpha"])

    def test_status_shows_the_registry_and_what_is_held(self):
        tracker = StatusTracker(interval_s=5.0)
        with self.assertLogs("amap_router_local", logging.WARNING):
            service.poll_once(self.cfg, tracker, None)
        doc = tracker.to_doc()
        self.assertEqual(doc["registry"]["state"], "ok")
        self.assertEqual(doc["registry"]["seq"], 3)
        self.assertEqual(doc["registry"]["held"], {"beta": registry.HELD_NOT_REGISTERED})

    def test_no_registry_means_no_registry_key_and_everything_drains(self):
        from dataclasses import replace
        cfg = replace(self.cfg, registry_dir=None)
        tracker = StatusTracker(interval_s=5.0)
        summary = service.poll_once(cfg, tracker, None)
        self.assertNotIn("registry", tracker.to_doc())
        self.assertEqual(sorted(summary), ["alpha", "beta"])


class ConfigTests(helpers.RouterTestCase):

    def _load(self, extra):
        root = self.tmp / "alpha"
        root.mkdir(exist_ok=True)
        doc = {"state_dir": str(self.state_dir), "instances": {"alpha": {"namespace": str(root)}}}
        doc.update(extra)
        return config_mod.load_obj(doc)

    def test_registry_dir(self):
        self.assertIsNone(self._load({}).registry_dir)
        cfg = self._load({"registry_dir": str(self.tmp / "reg")})
        self.assertEqual(cfg.registry_dir, self.tmp / "reg")
        for bad in (str(self.state_dir / "reg"), str(self.tmp / "alpha" / "reg"), "reg"):
            with self.subTest(registry_dir=bad):
                with self.assertRaises(config_mod.ConfigError):
                    self._load({"registry_dir": bad})

    def test_an_instance_name_with_a_trailing_newline_is_refused(self):
        """`$` with `match` accepted "alpha\\n"."""
        root = self.tmp / "nl"
        root.mkdir()
        with self.assertRaises(config_mod.ConfigError):
            config_mod.load_obj({"state_dir": str(self.state_dir),
                                 "instances": {"alpha\n": {"namespace": str(root)}}})
        self.assertIsNone(config_mod._NAME_RE.fullmatch("alpha\n"))
        self.assertIsNotNone(config_mod._NAME_RE.fullmatch("alpha"))


if __name__ == "__main__":
    unittest.main()
