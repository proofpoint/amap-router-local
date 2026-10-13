"""`hoplink.reader_for`: one intake reader per (logical_id, generation) per
process, its `NoticeRefused` captured once, construction failures classified
as holds (latched or retried, never escaped), and eviction on fence."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from router import config as config_mod
from router import hoplink, transport
from router.tests import helpers

LID = "a1" * 16
G1, G2 = "b2" * 16, "c3" * 16


class _Reasoned(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class _UnsafeRead(Exception):
    pass


class _ListingTooLarge(Exception):
    pass


class _NoticeRefused(Exception):
    pass


class FakeReader:
    NoticeRefused = _NoticeRefused

    def __init__(self, settings):
        self.settings, self.closes = settings, 0

    def close(self):
        self.closes += 1


class Plugin:
    def __init__(self):
        self.calls, self.made = [], []
        self.fail, self.fail_times = None, 0
        self.reader_class = FakeReader

    def make_intake_reader(self, settings, fsops):
        self.calls.append(dict(settings))
        if self.fail_times:
            self.fail_times -= 1
            raise self.fail
        r = self.reader_class(settings)
        self.made.append(r)
        return r


class _R(unittest.TestCase):

    def setUp(self):
        hoplink.forget_senders()
        self.addCleanup(hoplink.forget_senders)
        hoplink._RUNTIME_CLASSES.clear()
        self.addCleanup(hoplink._RUNTIME_CLASSES.clear)
        self.plugin = Plugin()
        fsops = SimpleNamespace(UnsafeRead=_UnsafeRead, ListingTooLarge=_ListingTooLarge)
        hop = config_mod.HopConfig(root="/srv/hop", peer_uid=1001, version_write=1,
                                   caps=tuple(helpers.TEST_HOP_CAPS.items()))
        self.cfg = SimpleNamespace(state_dir="/state", hop=hop)
        self.rt = SimpleNamespace(plugin=self.plugin, fsops=fsops, hop=hop)

    def get(self, gen=G1):
        return hoplink.reader_for(self.rt, self.cfg, LID, gen)


class ConstructionTests(_R):

    def test_settings_are_exactly_the_core_and_the_reader_is_cached(self):
        r = self.get()
        self.assertEqual(self.plugin.calls, [{"hop_root": "/srv/hop", "logical_id": LID,
                                              "generation": G1, "peer_uid": 1001}])
        self.assertIs(self.get(), r)
        self.assertEqual(len(self.plugin.calls), 1, "constructed twice")
        self.assertIs(r.notice_refused, _NoticeRefused)

    def test_a_fenced_generation_gets_its_own_reader(self):
        self.assertIsNot(self.get(G1), self.get(G2))
        self.assertEqual([c["generation"] for c in self.plugin.calls], [G1, G2])

    def test_the_refusal_class_is_captured_once(self):
        r = self.get()
        self.plugin.made[0].NoticeRefused = ValueError    # swapped afterwards
        self.assertIs(self.get().notice_refused, _NoticeRefused)
        self.assertIs(r.notice_refused, _NoticeRefused)

    def test_a_class_that_is_not_disjoint_latches_the_vocabulary_hold_and_closes_it(self):
        class Bad(FakeReader):
            NoticeRefused = OSError
        self.plugin.reader_class = Bad
        with self.assertRaises(hoplink.HopHold) as cm:
            self.get()
        self.assertEqual((cm.exception.reason, cm.exception.latched, cm.exception.scope),
                         (hoplink.HOLD_READER_VOCABULARY, True, "instance"))
        self.assertEqual(self.plugin.made[0].closes, 1, "the refused reader leaked")
        with self.assertRaises(hoplink.HopHold):
            self.get()
        self.assertEqual(len(self.plugin.calls), 1, "a latched hold was re-attempted")

    def test_settings_invalid_latches(self):
        self.plugin.fail, self.plugin.fail_times = _Reasoned("settings_invalid"), 1
        for _ in range(3):
            with self.assertRaises(hoplink.HopHold) as cm:
                self.get()
            self.assertEqual((cm.exception.reason, cm.exception.latched),
                             (hoplink.HOLD_READER_SETTINGS_REFUSED, True))
        self.assertEqual(len(self.plugin.calls), 1)

    def test_layout_and_anything_else_are_retried(self):
        for exc, want in ((_Reasoned("layout"), "hop_reader_construct_failed:layout"),
                          (OSError(5, "EIO"), "hop_reader_construct_failed:EIO"),
                          (ValueError("bare"), "hop_reader_construct_failed:other")):
            with self.subTest(exc=exc):
                hoplink.forget_senders()
                self.plugin.calls.clear()
                self.plugin.fail, self.plugin.fail_times = exc, 1
                with self.assertRaises(hoplink.HopHold) as cm:
                    self.get()
                self.assertEqual((cm.exception.reason, cm.exception.latched), (want, False))
                self.get()                                    # retried, and recovers
                self.assertEqual(len(self.plugin.calls), 2)


class EvictionTests(_R):

    def test_eviction_closes_and_the_next_call_rebuilds(self):
        r1, r2 = self.get(G1), self.get(G2)
        self.assertEqual(hoplink.evict_readers(self.cfg, LID, G1), 1)
        self.assertEqual((r1.port.closes, r2.port.closes), (1, 0))
        self.assertIsNot(self.get(G1), r1)
        self.assertEqual(hoplink.evict_readers(self.cfg, LID), 2)
        self.assertEqual(hoplink.evict_readers(self.cfg, LID), 0, "control: nothing left")

    def test_forget_closes_readers_too(self):
        r = self.get()
        hoplink.forget_senders()
        self.assertEqual(r.port.closes, 1)


if __name__ == "__main__":
    unittest.main()
