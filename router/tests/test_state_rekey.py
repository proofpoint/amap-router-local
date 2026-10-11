"""Under a registry, an instance's private state is keyed by its logical_id.

`state_dir/<logical_id>/` replaces `state_dir/<name>/` for every resolved
instance. A name that still has state under the old key is HELD until the
operator moves it (README, "Moving private state under a registry"), and a
name shaped like a logical_id cannot run under a registry at all.

Every path assertion here is on a directory that only the keyed join could
have produced: the logical_id directory is created by nothing else, and the
name directory's ABSENCE is checked beside it, so an unkeyed drain (which
would create `state_dir/alpha/`) cannot pass.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from router import config as config_mod
from router import registry, reset, service
from router.config import ConfigError, load_obj
from router.tests import helpers

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "registry"
ALPHA_LID = "72a96bbced1aa04414517b96ebbb6179"  # snapshot.json's active entry
HEX_NAME = "0123456789abcdef0123456789abcdef"


def _snapshot(**rename):
    doc = json.loads((FIXTURES / "snapshot.json").read_text())
    for e in doc["entries"]:
        if e["name"] in rename:
            new = rename[e["name"]]
            e["name"] = new
            for n in e["names"]:
                n["name"] = new
    return doc


class ReportHoldsTests(unittest.TestCase):
    """`registry.report_for`: which resolved names may be keyed by logical_id."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.reg, self.state = base / "registry", base / "state"
        self.reg.mkdir()
        self.state.mkdir()
        self.put(_snapshot())

    def tearDown(self):
        self._tmp.cleanup()

    def put(self, doc):
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(doc))

    def report(self, names=("alpha",)):
        return registry.report_for(self.reg, self.state, list(names))

    def test_no_state_anywhere_resolves(self):
        """The twin of every hold below: a fresh instance is drained."""
        r = self.report()
        self.assertEqual((list(r.resolved), r.held), (["alpha"], {}))

    def test_state_under_the_logical_id_only_resolves(self):
        (self.state / ALPHA_LID).mkdir()
        r = self.report()
        self.assertEqual((list(r.resolved), r.held), (["alpha"], {}))

    def test_state_under_the_name_only_is_not_migrated(self):
        (self.state / "alpha").mkdir()
        r = self.report()
        self.assertEqual((r.resolved, r.held), ({}, {"alpha": registry.HELD_NOT_MIGRATED}))

    def test_a_legacy_entry_of_any_shape_counts(self):
        """A file, or a dangling symlink, where the name's directory was is
        still something the operator has to deal with."""
        for make in (lambda p: p.write_text("x"), lambda p: p.symlink_to(self.state / "gone")):
            with self.subTest(make=make):
                p = self.state / "alpha"
                make(p)
                self.assertEqual(self.report().held, {"alpha": registry.HELD_NOT_MIGRATED})
                p.unlink()

    def test_state_under_both_is_a_conflict(self):
        (self.state / "alpha").mkdir()
        (self.state / ALPHA_LID).mkdir()
        r = self.report()
        self.assertEqual((r.resolved, r.held), ({}, {"alpha": registry.HELD_STATE_CONFLICT}))

    def test_an_unreadable_legacy_entry_counts_as_present(self):
        """Unreadable is not absent: a failed `lstat` other than ENOENT holds."""
        real = os.lstat

        def lstat(path, *a, **kw):
            if Path(path) == self.state / "alpha":
                raise PermissionError(13, "denied")
            return real(path, *a, **kw)

        with mock.patch.object(registry.os, "lstat", lstat):
            self.assertEqual(self.report().held, {"alpha": registry.HELD_NOT_MIGRATED})

    def test_an_id_shaped_name_is_held(self):
        for name in (HEX_NAME, HEX_NAME.upper()):
            with self.subTest(name=name):
                self.put(_snapshot(alpha=name))
                r = registry.report_for(self.reg, self.state, [name])
                self.assertEqual((r.resolved, r.held), ({}, {name: registry.HELD_NAME_SHAPE}))

    def test_this_routers_own_state_entries_are_held(self):
        """`state_dir/registry/` (the seq floor) and `status.json` are this
        router's; a name equal to one would read them as its legacy state."""
        for name in ("registry", "Registry", "status.json"):
            with self.subTest(name=name):
                self.put(_snapshot(alpha=name))
                r = registry.report_for(self.reg, self.state, [name])
                self.assertEqual(r.held, {name: registry.HELD_NAME_SHAPE})


class KeyedDrainTests(helpers.RouterTestCase):
    """A drain under a registry writes `state_dir/<logical_id>/`, never
    `state_dir/<name>/`."""

    def setUp(self):
        super().setUp()
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(_snapshot()))
        self.plain = self.make_config({"alpha": []})
        self.cfg = replace(self.plain, registry_dir=self.reg)
        service._REGISTRY_LOGGED.clear()

    def migrate(self):
        (self.state_dir / "alpha").rename(self.state_dir / ALPHA_LID)

    def test_private_results_land_under_the_logical_id(self):
        self.migrate()
        helpers.write_request(self.cfg, "alpha", "00000001")
        with self.assertLogs("amap_router_local"):
            summary = service.run_once(self.cfg, None)
        self.assertEqual(list(summary), ["alpha"])
        self.assertTrue((self.state_dir / ALPHA_LID / "results" / "00000001.json").is_file())
        self.assertFalse((self.state_dir / "alpha").exists(),
                         "an unkeyed join recreated the name's directory")

    def test_without_a_registry_state_stays_under_the_name(self):
        """The twin: no registry, no change."""
        helpers.write_request(self.plain, "alpha", "00000001")
        service.run_once(self.plain, None)
        self.assertTrue((self.state_dir / "alpha" / "results" / "00000001.json").is_file())
        self.assertFalse((self.state_dir / ALPHA_LID).exists())

    def test_an_unmigrated_instance_is_not_drained(self):
        helpers.write_request(self.cfg, "alpha", "00000001")
        with self.assertLogs("amap_router_local"):
            summary = service.run_once(self.cfg, None)
        self.assertEqual(summary, {})
        self.assertFalse((self.state_dir / "alpha" / "results").exists())
        self.assertFalse((self.state_dir / ALPHA_LID).exists())

    def test_keyed_config_is_identity_without_a_registry(self):
        self.assertIs(registry.keyed_config(self.plain, registry.OFF), self.plain)
        self.assertEqual(config_mod.state_key(self.plain, "alpha"), "alpha")


BETA_LID = "5f0c3e1d2b4a69788796a5b4c3d2e1f0"


def _two_active():
    """snapshot.json with its retired beta replaced by a second ACTIVE entry."""
    doc = _snapshot()
    alpha = next(e for e in doc["entries"] if e["name"] == "alpha")
    beta = json.loads(json.dumps(alpha))
    beta.update(logical_id=BETA_LID, name="beta", stable_key="/srv/work/beta")
    beta["names"][0]["name"] = "beta"
    beta["bindings"][0]["stable_key"] = "/srv/work/beta"
    doc["entries"] = [alpha, beta]
    return doc


class KeyedDeliveryTests(helpers.RouterTestCase):
    """A local delivery between two resolved instances ledgers the notice
    under the RECIPIENT's logical_id, and nothing in `state_dir` is named
    after an instance afterwards."""

    def setUp(self):
        super().setUp()
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(_two_active()))
        plain = self.make_config({"alpha": ["beta"], "beta": ["alpha"]})
        self.cfg = replace(plain, registry_dir=self.reg)
        for name, lid in (("alpha", ALPHA_LID), ("beta", BETA_LID)):
            (self.state_dir / name).rename(self.state_dir / lid)
        service._REGISTRY_LOGGED.clear()

    def test_the_reply_ledger_is_keyed_by_the_recipients_logical_id(self):
        helpers.write_request(self.cfg, "alpha", "00000001", to=[config_mod.address_for("beta")])
        with self.assertLogs("amap_router_local"):
            service.run_once(self.cfg, None)
        self.assertEqual(len(helpers.list_notices(self.cfg, "beta")), 1)
        delivered = self.state_dir / BETA_LID / "delivered"
        self.assertEqual(len(list(delivered.iterdir())), 1)
        self.assertEqual(sorted(p.name for p in self.state_dir.iterdir()
                                if p.name in ("alpha", "beta")), [])


class KeyedConsoleTests(helpers.RouterTestCase):
    """The console reads keyed state and stores nothing, the seq floor
    included."""

    def setUp(self):
        super().setUp()
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(_snapshot()))
        self.cfg = replace(self.make_config({"alpha": []}), registry_dir=self.reg)
        (self.state_dir / "alpha").rename(self.state_dir / ALPHA_LID)

    def test_the_marker_is_read_under_the_logical_id(self):
        from router import console
        data = console.gather(self.cfg)
        self.assertTrue(data["instances"]["alpha"]["seen"])

    def test_the_seq_floor_is_not_written(self):
        from router import console
        console.gather(self.cfg)
        self.assertFalse(registry.seq_path(self.state_dir).exists())
        # The twin: a poll's read does write it.
        registry.report_for(self.reg, self.state_dir, ["alpha"])
        self.assertTrue(registry.seq_path(self.state_dir).exists())


class KeyedResetTests(helpers.RouterTestCase):
    """`reset` under a registry clears `state_dir/<logical_id>/`, and refuses
    an instance the registry holds."""

    def setUp(self):
        super().setUp()
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(_snapshot()))
        self.cfg = replace(self.make_config({"alpha": []}), registry_dir=self.reg)

    def test_reset_clears_the_logical_id_directory(self):
        (self.state_dir / "alpha").rename(self.state_dir / ALPHA_LID)
        stale = self.state_dir / ALPHA_LID / "results"
        stale.mkdir()
        (stale / "00000001.json").write_text("{}")
        summary = reset.reset_instances(self.cfg, ["alpha"])[0]
        self.assertGreater(summary["state_removed"], 0)
        self.assertFalse(stale.exists())
        self.assertFalse((self.state_dir / "alpha").exists())
        # The reset's own audit line lands under the logical_id too.
        self.assertTrue((self.state_dir / ALPHA_LID / "audit").is_dir())

    def test_a_held_instance_is_refused_and_nothing_is_removed(self):
        marker = self.state_dir / "alpha" / "first-seen.json"
        self.assertTrue(marker.is_file())
        with self.assertRaises(reset.ResetError) as cm:
            reset.reset_instances(self.cfg, ["alpha"])
        self.assertIn(registry.HELD_NOT_MIGRATED, str(cm.exception))
        self.assertTrue(marker.is_file())


class IdShapedNameConfigTests(helpers.RouterTestCase):
    """A static instance named like a logical_id is refused under a registry;
    a discovered one is skipped."""

    def doc(self, name, registry_dir=True):
        root = self.tmp / "instances" / name
        root.mkdir(parents=True, exist_ok=True)
        d = {"state_dir": str(self.state_dir),
             "instances": {name: {"namespace": str(root), "peers": []}}}
        if registry_dir:
            reg = self.tmp / "registry"
            reg.mkdir(exist_ok=True)
            d["registry_dir"] = str(reg)
        return d

    def test_refused_under_a_registry(self):
        for name in (HEX_NAME, HEX_NAME.upper()):
            with self.subTest(name=name):
                with self.assertRaises(ConfigError) as cm:
                    load_obj(self.doc(name))
                self.assertIn("shaped like a logical_id", str(cm.exception))

    def test_allowed_without_a_registry(self):
        """The twin: the name rule itself is unchanged."""
        cfg = load_obj(self.doc(HEX_NAME, registry_dir=False))
        self.assertIn(HEX_NAME, cfg.instances)

    def test_discovery_skips_an_id_shaped_slug_under_a_registry(self):
        from router.config import LANE_LEAVES
        base = self.tmp / "fleet"
        for slug in (HEX_NAME, "alice-deadbeef"):
            for lane, leaves in LANE_LEAVES.items():
                for leaf in leaves:
                    (base / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        sel = self.tmp / "selected.json"
        sel.write_text(json.dumps({"schema": 1, "not_selected": [], "selected": [
            {"slug": s, "at": "2026-10-11T00:00:00Z"} for s in (HEX_NAME, "alice-deadbeef")]}))
        reg = self.tmp / "registry"
        reg.mkdir()
        doc = {"state_dir": str(self.state_dir), "instances_dir": str(base),
               "selected_json": str(sel)}
        plain = load_obj(doc)
        self.assertIn(HEX_NAME, plain.instances)          # the twin
        keyed = load_obj(dict(doc, registry_dir=str(reg)))
        self.assertNotIn(HEX_NAME, keyed.instances)
        self.assertIn("alice-deadbeef", keyed.instances)
        self.assertIn("shaped like a logical_id", keyed.discovery.skipped[HEX_NAME])


if __name__ == "__main__":
    unittest.main()
