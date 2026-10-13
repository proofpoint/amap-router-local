"""The sender side's fence order (`router/hoplink.py`, `fence_step`): the
private record, then retire every fenced predecessor this router pinned, then
admit the current generation. Driven through the real drain under a
registry, with a stand-in plugin whose marker stores are doubles.

  * the order, with `retired_at` the predecessor's fence time, never the clock;
  * the test-only hook (`service.FENCE_STOP_AT`) at each point: a stop leaves
    the poll whole, as `FenceStopped`, and the next start completes the rest;
  * the absent table: no confirmation means nothing to retire; a confirmed
    tree gone holds the instance (`hop_tree_lost`) until it is acknowledged;
  * the retire row: any exception blocks the successor, retried, the store
    kept; the construction rows; a root the pin does not name;
  * the fenced leg: each fenced generation's own sender only after its
    retire, a record never handed over settled `no_route`, a generation
    without a tree never served, and its sender closed once it drains;
  * one construction per poll at most, and objects closed (descriptor
    counts and close counts).
"""
from __future__ import annotations

import json
import os
from unittest import mock

from router import config as config_mod
from router import generations, hoplink, inflight, outbound, service
from router.tests.helpers import keyed_for_poll, read_json, result_path, write_request
from router.tests.test_hoplink_senders import (
    EXTERNAL, GenerationAbsent, StandInPlugin, _Reasoned, _Senders)
from router.tests.test_inflight import _external


def _fd_count():
    return len(os.listdir("/proc/self/fd"))


class OrderPlugin(StandInPlugin):
    """Logs every retire and every sender construction, with its generation,
    into `log` (the fence hook logs its points there too)."""

    def __init__(self, log):
        super().__init__()
        self.log = log

    def make_sender(self, settings, fsops):
        self.log.append(("admit", settings["generation"]))
        return super().make_sender(settings, fsops)

    def make_upstream_marker_store(self, settings, fsops):
        store = super().make_upstream_marker_store(settings, fsops)
        log, retire = self.log, store.retire

        def logged(retired_at):
            log.append(("retire", settings["generation"], retired_at))
            return retire(retired_at)
        store.retire = logged
        return store


class _Fence(_Senders):

    def setUp(self):
        super().setUp()
        self.log = []
        self.plugin = OrderPlugin(self.log)
        self.rt = service.HopRuntime(plugin=self.plugin, fsops=None, hop=self.cfg.hop)
        hoplink.FENCE_HOLDS.clear()
        self.addCleanup(hoplink.reset_process_state)

    def gen(self, k=None):
        k = k or keyed_for_poll(self.cfg)
        return hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))[1]

    def admitted_g1(self, request=True):
        """G1 admitted (and, with `request`, one request handed over in it)."""
        if request:
            write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        k, _ = self.drain()
        return self.gen(k)

    def fence(self):
        """A rebind fences the current generation (the record is written by
        the next poll's pre-pass)."""
        self.put(alpha={"binding_seq": 9})

    def fenced_ts(self, gen):
        doc = generations.read_doc(self.state_dir, self.lid())
        return next(g for g in doc["gens"] if g["gen"] == gen)["fenced_ts"]

    def lid(self):
        return hoplink.split_gen_key(config_mod.gen_key(keyed_for_poll(self.cfg), "alpha"))[0]

    def hold(self, k=None):
        k = k or keyed_for_poll(self.cfg)
        return hoplink.HOLDS.get((str(k.state_dir), "alpha"))

    def held(self, k=None):
        """The hold that must be there (its absence is a FAILURE)."""
        hold = self.hold(k)
        self.assertIsNotNone(hold, "no hold: the successor was admitted")
        return hold

    def restart(self):
        hoplink.reset_process_state()


class FenceOrderTests(_Fence):

    def test_record_then_retire_at_the_fence_time_then_admit(self):
        g1 = self.admitted_g1()
        self.fence()
        with mock.patch.object(service, "FENCE_STOP_AT", lambda p: self.log.append(("hook", p))):
            k, _ = self.drain()
        g2 = self.gen(k)
        self.assertNotEqual(g1, g2)
        tail = self.log[1:]                       # after G1's own admission
        self.assertEqual(tail[0], ("hook", "fence_recorded"))
        self.assertEqual(tail[1], ("retire", g1, self.fenced_ts(g1)))
        self.assertEqual(tail[2], ("hook", "retired_written"))
        self.assertEqual(tail[3], ("admit", g2), "the successor was admitted out of order")

    def test_retired_at_is_the_record_never_the_clock(self):
        g1 = self.admitted_g1()
        self.fence()
        keyed_for_poll(self.cfg)                  # the pre-pass writes the fence record
        path = generations.gen_file(self.state_dir, self.lid())
        doc = json.loads(path.read_text())
        for g in doc["gens"]:
            if g["gen"] == g1:
                g["fenced_ts"] = "2001-02-03T04:05:06Z"
        path.write_text(json.dumps(doc))
        self.drain()
        self.assertIn(("retire", g1, "2001-02-03T04:05:06Z"), self.log)

    def test_a_second_poll_retires_nothing_more(self):
        self.admitted_g1()
        self.fence()
        self.drain()
        retires = [e for e in self.log if e[0] == "retire"]
        self.drain()
        self.assertEqual([e for e in self.log if e[0] == "retire"], retires)

    def test_a_generation_never_pinned_has_nothing_to_retire(self):
        k = keyed_for_poll(self.cfg)              # G1 begun, never drained under the hop
        self.assertIsNone(hoplink.read_pin(k, "alpha"))
        self.fence()
        self.drain()
        self.assertEqual(self.plugin.stores, [], "a store was built for an unpinned generation")
        self.assertIsNone(self.hold())


class FenceStopTests(_Fence):

    def assert_retire_then_admit(self, mark, g1, g2):
        events = [e[:2] for e in self.log[mark:] if e[0] in ("retire", "admit")]
        self.assertIn(("retire", g1), events)
        self.assertIn(("admit", g2), events)
        self.assertLess(events.index(("retire", g1)), events.index(("admit", g2)))

    def stopper(self, point):
        def hook(p):
            self.log.append(("hook", p))
            if p == point:
                raise RuntimeError(f"stop at {p}")
        return hook

    def test_a_stop_at_fence_recorded_leaves_the_poll_and_retires_nothing(self):
        g1 = self.admitted_g1()
        self.fence()
        with mock.patch.object(service, "FENCE_STOP_AT", self.stopper("fence_recorded")):
            with self.assertRaises(hoplink.FenceStopped) as cm:
                self.drain()
        self.assertEqual(cm.exception.point, "fence_recorded")
        self.assertIsInstance(cm.exception.raised, RuntimeError)
        self.assertNotIn("retire", [e[0] for e in self.log])
        self.restart()
        mark = len(self.log)
        k, _ = self.drain()
        self.assert_retire_then_admit(mark, g1, self.gen(k))

    def test_a_stop_at_retired_written_retires_and_admits_nothing(self):
        g1 = self.admitted_g1()
        self.fence()
        with mock.patch.object(service, "FENCE_STOP_AT", self.stopper("retired_written")):
            with self.assertRaises(hoplink.FenceStopped):
                self.drain()
        self.assertEqual([e[:2] for e in self.log if e[0] in ("retire", "admit")][-1],
                         ("retire", g1))
        self.restart()
        self.plugin.store_result = "exists_same"  # the replay after the stop
        mark = len(self.log)
        k, _ = self.drain()
        self.assert_retire_then_admit(mark, g1, self.gen(k))

    def test_the_stop_is_never_swallowed_by_the_poll(self):
        self.admitted_g1()
        self.fence()
        with mock.patch.object(service, "FENCE_STOP_AT", self.stopper("fence_recorded")):
            with self.assertRaises(hoplink.FenceStopped):
                service.run_once(self.cfg, self.rt)

    def test_without_the_hook_nothing_is_called(self):
        self.assertIsNone(service.FENCE_STOP_AT)
        self.admitted_g1()
        self.fence()
        self.drain()
        self.assertIsNone(self.hold())


class AbsentTableTests(_Fence):

    def test_a_pin_without_a_confirmation_and_no_tree_admits_the_successor(self):
        """A crash after the pin (or a factory that failed once after it),
        then a fence: nothing was admitted, so nothing to retire and nothing
        held."""
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.plugin.fail, self.plugin.fail_times = OSError(5, "EIO"), 1
        k, _ = self.drain()                       # pinned, construction failed
        self.assertIsNotNone(hoplink.read_pin(k, "alpha"))
        self.assertFalse(hoplink.admitted(k, "alpha"))
        self.fence()
        self.plugin.store_result = "absent"
        k, _ = self.drain()
        self.assertIsNone(self.hold(k))
        self.assertEqual(self.log[-1], ("admit", self.gen(k)))

    def test_a_confirmed_tree_gone_holds_the_instance(self):
        self.admitted_g1()
        self.fence()
        self.plugin.store_result = "absent"
        self.drain()                              # G2's first sight
        write_request(self.cfg, "alpha", "00000002", to=[EXTERNAL])
        for _ in range(2):
            k, _ = self.drain()
            hold = self.held(k)
            self.assertEqual((hold.reason, hold.scope, hold.latched),
                             ("hop_tree_lost", "instance", True))
        self.assertNotIn(("admit", self.gen(k)), self.log, "admitted over a lost tree")
        doc = hoplink.status_doc(k, k.instances)["instances"]["alpha"]["sender_hold"]
        self.assertIn("router generation new", doc.get("hint", ""))
        self.assertTrue((k.instances["alpha"].outbox_root / "req-00000002.json").exists())

    def test_an_acknowledged_loss_admits_the_successor_and_never_serves_the_lost(self):
        g1 = self.admitted_g1()
        lid = self.lid()
        self.fence()
        self.plugin.store_result = "absent"
        self.drain()
        hoplink.write_lost_acks(self.cfg, lid, [g1], "the disk died", "ref")
        self.restart()                            # no cached sender for G1 survives
        mark = len(self.log)
        k, _ = self.drain()
        self.assertIsNone(self.hold(k))
        self.assertIn(("admit", self.gen(k)), self.log[mark:])
        self.assertNotIn(("admit", g1), self.log[mark:],
                         "a sender was built for the lost generation")
        self.assertEqual(inflight.settlement_record(self.state_dir, lid, g1,
                                                    self.plugin.ports[0].writes[0])["state"],
                         "inflight", "the lost generation's record was settled")


class RetireRowTests(_Fence):

    def test_a_retire_failure_blocks_and_retries_with_the_store_kept(self):
        self.admitted_g1()
        self.fence()
        self.plugin.store_raises = _Reasoned("marker_unreadable")
        before = None
        for i in range(20):
            k, _ = self.drain()
            hold = self.held(k)
            self.assertEqual(hoplink.status_doc(k, k.instances)["marker_stores_open"], 1,
                             "the held store is not counted open")
            self.assertEqual((hold.reason, hold.scope),
                             ("hop_retire_failed:marker_unreadable", "instance"))
            before = _fd_count() if i == 0 else before
        self.assertEqual(_fd_count(), before, "descriptors grew under an unretirable predecessor")
        [store] = self.plugin.stores
        self.assertEqual(len(store.retires), 20)
        self.assertEqual(store.closes, 0)
        store.raises = None
        k, _ = self.drain()
        self.assertIsNone(self.hold(k))
        self.assertEqual(store.closes, 1, "the store was not closed once retired")
        self.assertEqual(hoplink.status_doc(k, k.instances)["marker_stores_open"], 0)

    def test_exists_is_retired(self):
        self.admitted_g1()
        self.fence()
        self.plugin.store_result = "exists"
        k, _ = self.drain()
        self.assertIsNone(self.hold(k))

    def test_an_unknown_retire_result_blocks(self):
        self.admitted_g1()
        self.fence()
        self.plugin.store_result = "gone"
        k, _ = self.drain()
        self.assertEqual(self.held(k).reason, "hop_retire_failed:protocol")

    def test_a_closed_store_is_dropped_and_rebuilt(self):
        self.admitted_g1()
        self.fence()
        self.plugin.store_raises = _Reasoned("closed")
        self.drain()
        self.plugin.store_raises = None
        k, _ = self.drain()
        self.assertEqual(len(self.plugin.stores), 2)
        self.assertIsNone(self.hold(k))

    def test_store_settings_refused_latch_and_are_never_retried(self):
        self.admitted_g1()
        self.fence()
        calls = []
        self.plugin.store_fail = _Reasoned("settings_invalid")
        real = StandInPlugin.make_upstream_marker_store

        def counting(plugin, settings, fsops):
            calls.append(settings)
            return real(plugin, settings, fsops)
        with mock.patch.object(StandInPlugin, "make_upstream_marker_store", counting):
            for _ in range(3):
                k, _ = self.drain()
        self.assertEqual(len(calls), 1, "a latched store construction was re-attempted")
        self.assertEqual((self.hold(k).reason, self.hold(k).scope),
                         ("hop_settings_refused", "instance"))

    def test_any_other_store_construction_failure_retries_once_per_poll(self):
        self.admitted_g1()
        self.fence()
        self.plugin.store_fail = ValueError("bare")
        calls = []
        real = StandInPlugin.make_upstream_marker_store

        def counting(plugin, settings, fsops):
            calls.append(1)
            return real(plugin, settings, fsops)
        before = _fd_count()
        with mock.patch.object(StandInPlugin, "make_upstream_marker_store", counting):
            for _ in range(20):
                k, _ = self.drain()
        self.assertEqual(len(calls), 20, "not exactly one construction per poll")
        self.assertTrue(self.hold(k).reason.startswith("hop_construct_failed:"))
        self.assertFalse(self.hold(k).latched)
        self.assertEqual(_fd_count(), before)
        self.assertEqual(hoplink.status_doc(k, k.instances)["marker_stores_open"], 0)

    def test_the_store_is_built_from_the_pin_with_the_four_key_core(self):
        g1 = self.admitted_g1()
        lid = self.lid()
        self.fence()
        self.drain()
        [store] = self.plugin.stores
        self.assertEqual(store.settings, {"hop_root": str(self.tmp / "hop"), "logical_id": lid,
                                          "generation": g1, "peer_uid": 0})

    def test_a_pin_naming_another_root_holds_latched(self):
        g1 = self.admitted_g1()
        k = keyed_for_poll(self.cfg)
        pin_path = hoplink.transport_dir(k, "alpha") / hoplink.PIN_FILE
        pin = json.loads(pin_path.read_text())
        pin["hop_root"] = str(self.tmp / "elsewhere")
        pin_path.write_text(json.dumps(pin))
        self.fence()
        k, _ = self.drain()
        self.assertEqual((self.held(k).reason, self.held(k).latched),
                         ("hop_binding_changed", True))
        self.assertEqual(self.plugin.stores, [])
        self.assertNotIn(g1, [e[1] for e in self.log if e[0] == "retire"])


class FencedLegTests(_Fence):

    def test_a_record_never_handed_over_settles_no_route_after_the_retire(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        real = inflight._effect

        def crash_at_handed(label, fn, *a, **kw):
            if label == "handed":
                raise OSError(28, "crash before the handed marker")
            return real(label, fn, *a, **kw)
        with mock.patch.object(inflight, "_effect", crash_at_handed):
            self.drain()                          # G1: a record, no marker, nothing written
        self.assertEqual(self.plugin.ports[0].writes, [])
        self.fence()
        k, _ = self.drain()
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(),
                        "the fenced record was not answered")
        res = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual((res["outcome"], res["reason_code"]), ("rejected", "no_route"))
        self.assertEqual(res["detail"], inflight.DETAIL_FENCED_UNHANDED)
        self.assertEqual(self.plugin.ports[0].writes, [], "handed over into a retired tree")

    def test_nothing_fenced_is_served_before_its_retire(self):
        self.admitted_g1()
        self.fence()
        self.plugin.store_raises = OSError(5, "EIO")
        self.plugin.ports[0].send_all()           # G1's result is there to be read
        self.drain()
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "fenced work settled before its generation was retired")

    def test_the_fenced_sender_settles_then_is_closed_once_drained(self):
        g1 = self.admitted_g1()
        self.fence()
        self.drain()                              # retired; G1's request still pending
        g1_ports = [p for p, c in zip(self.plugin.ports, self.plugin.calls)
                    if c["generation"] == g1]
        port = g1_ports[-1]
        self.assertFalse(getattr(port, "closed", False))
        port.send_all()
        k, _ = self.drain()
        res = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual(res["outcome"], "accepted")
        self.assertTrue(getattr(port, "closed", False), "the drained fenced sender stays open")
        self.assertFalse(any(key[3] == g1 for key in hoplink._SENDERS))

    def test_the_fenced_sender_is_kept_while_its_records_live(self):
        g1 = self.admitted_g1()
        self.fence()
        for _ in range(3):
            self.drain()
        self.assertTrue(any(key[3] == g1 for key in hoplink._SENDERS))

    def test_a_fenced_sender_is_constructed_only_after_its_retire(self):
        g1 = self.admitted_g1()
        self.fence()
        self.restart()                            # no cached G1 sender
        self.drain()
        retire_at = next(i for i, e in enumerate(self.log) if e[:2] == ("retire", g1))
        rebuilt = [i for i, e in enumerate(self.log) if e == ("admit", g1) and i > 0]
        self.assertTrue(rebuilt, "the fenced generation's sender was never rebuilt")
        self.assertGreater(rebuilt[0], retire_at)


class FencedSenderUnitTests(_Fence):
    """`FencedSenders` itself. Through the drain an unretired predecessor
    also holds the CURRENT generation instance-wide, which holds the fenced
    leg too; this is the fenced leg's own guard, asked directly."""

    def view_of(self, gen):
        k = keyed_for_poll(self.cfg)
        lid = self.lid()
        keys = dict(k.gen_keys)
        keys["alpha"] = generations.gen_key(lid, gen)
        return generations.keyed(k, keys)

    def test_an_unretired_generation_gets_held_and_nothing_is_built(self):
        g1 = self.admitted_g1()
        self.fence()
        keyed_for_poll(self.cfg)                  # the fence record
        self.restart()
        got = hoplink.FencedSenders(self.rt).for_view(self.view_of(g1), "alpha")
        self.assertIsInstance(got, hoplink.Held)
        self.assertEqual(got.hold.reason, "hop_fenced_unretired")
        self.assertNotIn(("admit", g1), self.log[1:])

    def test_a_retired_absent_generation_gets_held_and_nothing_is_built(self):
        g1 = self.admitted_g1()
        lid = self.lid()
        self.fence()
        self.plugin.store_result = "absent"
        hoplink.write_lost_acks(self.cfg, lid, [g1], "gone", "ref")
        self.restart()
        self.drain()                              # retired as absent
        got = hoplink.FencedSenders(self.rt).for_view(self.view_of(g1), "alpha")
        self.assertIsInstance(got, hoplink.Held)
        self.assertEqual(got.hold.reason, "hop_fenced_tree_absent")
        self.assertNotIn(("admit", g1), self.log[1:])

    def test_a_retired_generation_gets_its_own_sender(self):
        g1 = self.admitted_g1()
        self.fence()
        self.restart()
        self.drain()
        got = hoplink.FencedSenders(self.rt).for_view(self.view_of(g1), "alpha")
        self.assertNotIsInstance(got, hoplink.Held)


class ProcessResetTests(_Fence):

    def test_the_restart_forgets_the_retired_cache_and_retires_again(self):
        g1 = self.admitted_g1()
        self.fence()
        self.drain()
        n = len([e for e in self.log if e[:2] == ("retire", g1)])
        self.restart()
        self.plugin.store_result = "exists_same"
        self.drain()
        self.assertEqual(len([e for e in self.log if e[:2] == ("retire", g1)]), n + 1)


if __name__ == "__main__":
    import unittest
    unittest.main()
