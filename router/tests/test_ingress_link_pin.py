"""The inbound link, pinned per generation: written once at first use, read
before every listing, and a config value that differs latches that
generation's inbound off rather than re-keying a single record."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from router import ingress

LID = "a" * 32
GEN = "1" * 32
G2 = "2" * 32


class LinkPinTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name)

    def pin(self, configured, gen=GEN):
        return ingress.pinned_link(self.state, LID, gen, configured)

    def test_first_use_pins_and_later_uses_agree(self):
        self.assertEqual(self.pin("hub"), ("hub", None))
        path = ingress.link_pin_path(self.state, LID, GEN)
        self.assertEqual(json.loads(path.read_bytes()),
                         {"schema": ingress.LINK_PIN_SCHEMA, "link": "hub"})
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        self.assertEqual(self.pin("hub"), ("hub", None))
        self.assertEqual(os.listdir(path.parent), [path.name], "a temporary file was left")

    def test_a_changed_config_latches_off_and_never_rewrites(self):
        self.pin("hub")
        before = ingress.link_pin_path(self.state, LID, GEN).read_bytes()
        self.assertEqual(self.pin("hub-2"), (None, ingress.HELD_LINK_CHANGED))
        self.assertEqual(ingress.link_pin_path(self.state, LID, GEN).read_bytes(), before)

    def test_a_new_generation_pins_the_new_value(self):
        self.pin("hub")
        self.assertEqual(self.pin("hub-2", gen=G2), ("hub-2", None))

    def test_unset_is_off(self):
        self.assertEqual(self.pin(None), (None, ingress.HELD_LINK_UNSET))
        self.assertFalse(ingress.link_pin_path(self.state, LID, GEN).exists())

    def test_records_without_a_pin_are_damage(self):
        ingress.write(self.state, LID, GEN, "notice", "hub", "1700000000-1", ingress.HELD,
                      reason="x")
        self.assertEqual(self.pin("hub"), (None, ingress.HELD_LINK_PIN_DAMAGED))
        self.assertFalse(ingress.link_pin_path(self.state, LID, GEN).exists())

    def test_a_damaged_pin_latches(self):
        self.pin("hub")
        path = ingress.link_pin_path(self.state, LID, GEN)
        for raw in (b"{not json", b'{"schema": "x", "link": "hub"}',
                    json.dumps({"schema": ingress.LINK_PIN_SCHEMA, "link": "Hub"}).encode(),
                    json.dumps({"schema": ingress.LINK_PIN_SCHEMA, "link": "hub",
                                "x": 1}).encode()):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                self.assertEqual(self.pin("hub"), (None, ingress.HELD_LINK_PIN_DAMAGED))
        path.unlink()
        os.symlink(self.state / "elsewhere", path)
        self.assertEqual(self.pin("hub"), (None, ingress.HELD_LINK_PIN_DAMAGED))


if __name__ == "__main__":
    unittest.main()
