"""The `hop` config object (`router/config.py`): the hop tree a transport
plugin writes. Each refusal has a witness beside the valid twin it is
measured against, so a loader that refused everything could not pass."""
from __future__ import annotations

import unittest

from router import config as config_mod
from router.config import ConfigError
from router.tests import helpers

SHA = "a" * 64


class HopConfigTests(helpers.RouterTestCase):

    def doc(self, **hop_overrides):
        root = self.tmp / "alice"
        root.mkdir(exist_ok=True)
        doc = helpers.with_hop({
            "state_dir": str(self.state_dir),
            "instances": {"alice": {"namespace": str(root)}},
            "transport_plugin": {"path": "/opt/p.py", "sha256": SHA}}, self.tmp)
        doc["hop"].update(hop_overrides)
        return doc

    def refused(self, doc, *phrases):
        with self.assertRaises(ConfigError) as cm:
            config_mod.load_obj(doc)
        for phrase in phrases:
            self.assertIn(phrase, str(cm.exception))
        return cm.exception

    def test_the_valid_twin_loads_with_the_root_verbatim(self):
        cfg = config_mod.load_obj(self.doc())
        self.assertEqual(cfg.hop.root, str(self.tmp / "hop"))
        self.assertIsInstance(cfg.hop.root, str)
        self.assertEqual(cfg.hop.peer_uid, 0)
        self.assertEqual(cfg.hop.version_write, 1)
        self.assertEqual(dict(cfg.hop.caps), helpers.TEST_HOP_CAPS)
        self.assertEqual(cfg.hop.cap("request"), 1 << 20)

    def test_hop_and_the_plugin_come_together(self):
        doc = self.doc()
        del doc["hop"]
        self.refused(doc, "config.hop: required with config.transport_plugin")
        doc = self.doc()
        del doc["transport_plugin"]
        self.refused(doc, "config.hop: only with config.transport_plugin")

    def test_a_registry_is_required(self):
        doc = self.doc()
        del doc["registry_dir"]
        self.refused(doc, "config.hop: requires config.registry_dir")

    def test_the_root_is_absolute_and_in_normal_form(self):
        base = str(self.tmp / "hop")
        for bad in ("relative/hop", base + "/", base + "/.", base + "/../hop",
                    str(self.tmp) + "//hop", ""):
            with self.subTest(root=bad):
                self.refused(self.doc(root=bad), "config.hop.root")

    def test_the_root_never_overlaps_state_registry_or_an_agent_root(self):
        cases = {
            "state_dir itself": str(self.state_dir),
            "inside state_dir": str(self.state_dir / "hop"),
            "containing state_dir": str(self.state_dir.parent),
            "inside the registry": str(self.tmp / "registry" / "hop"),
            "an instance root": str(self.tmp / "alice"),
            "inside an instance root": str(self.tmp / "alice" / "hop"),
        }
        for why, root in cases.items():
            with self.subTest(why=why):
                self.refused(self.doc(root=root), "must not be nested")

    def test_the_members_and_their_types(self):
        doc = self.doc()
        doc["hop"]["extra"] = 1
        self.refused(doc, "config.hop: needs exactly")
        for key, bad in (("peer_uid", -1), ("peer_uid", True), ("peer_uid", "0"),
                         ("version_write", 0), ("version_write", 1.0)):
            with self.subTest(key=key, bad=bad):
                self.refused(self.doc(**{key: bad}), f"config.hop.{key}")
        doc = self.doc()
        doc["hop"]["caps"] = {"document": 1, "request": 1, "attachment": 1}
        self.refused(doc, "config.hop.caps: needs exactly")
        for cap in config_mod.HOP_CAPS:
            for bad in (0, -1, True, 1.5):
                with self.subTest(cap=cap, bad=bad):
                    doc = self.doc()
                    doc["hop"]["caps"][cap] = bad
                    self.refused(doc, f"config.hop.caps.{cap}")

    def test_version_write_is_at_most_the_envelopes_maximum(self):
        top = config_mod.HOP_CONTRACT_MAX
        self.assertEqual(config_mod.load_obj(self.doc(version_write=top)).hop.version_write, top)
        self.refused(self.doc(version_write=top + 1), "config.hop.version_write")

    def test_peer_uid_zero_is_allowed(self):
        self.assertEqual(config_mod.load_obj(self.doc(peer_uid=0)).hop.peer_uid, 0)


if __name__ == "__main__":
    unittest.main()
