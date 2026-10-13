"""The external leg's failure paths through the real drain: what is held,
what is left unconsumed, and what never leaks or aborts the instance.

  * an undecidable frontier, and a record that cannot make a valid
    handover, LATCH this generation's hold before anything is handed over;
  * any failure on the way to a sender is a retried construction hold:
    the constructed sender is closed when the admission confirmation cannot
    be written, and the instance's local mail still drains that poll;
  * a fenced generation that was PINNED blocks its successor, whether or not
    its admission was confirmed, and its own work is left alone;
  * a latched construction hold is not re-attempted in the same process,
    and the runtime's own classes are seen before a plugin `.reason`;
  * a latched hand-over hold leaves new external requests unconsumed;
  * mail only: a request outside the cold mail classes is refused
    `no_route` before anything is allocated;
  * an attachment-bearing request is still refused at begin under a real
    runtime.
"""
from __future__ import annotations

import json
import os
from unittest import mock

from router import config as config_mod
from router import hoplink, inflight, outbound, service
from router.fsops import UnsafeRead
from router.tests import helpers
from router.tests.helpers import keyed_for_poll, read_json, result_path, write_request
from router.tests.peer_helpers import addr
from router.tests.test_hoplink_senders import EXTERNAL, StandInPlugin, _Reasoned, _Senders
from router.tests.test_hoplink_write_table import _FailingPort
from router.tests.test_inflight import EXT, _InflightCase


def _fd_count():
    return len(os.listdir("/proc/self/fd"))


class CountingPort(_FailingPort):
    instances = []

    def __init__(self):
        super().__init__()
        self.closes = 0
        CountingPort.instances.append(self)

    def close(self):
        self.closes += 1
        super().close()


class CountingPlugin(StandInPlugin):
    def make_sender(self, settings, fsops):
        self.calls.append(dict(settings))
        if self.fail_times:
            self.fail_times -= 1
            raise self.fail
        port = CountingPort()
        self.ports.append(port)
        return port


class _Runtime(_Senders):

    def setUp(self):
        super().setUp()
        CountingPort.instances = []
        hoplink.RETRIES.clear()
        self.addCleanup(hoplink.RETRIES.clear)
        hoplink._RUNTIME_CLASSES.clear()
        self.addCleanup(hoplink._RUNTIME_CLASSES.clear)
        self.plugin = CountingPlugin()
        self.rt = service.HopRuntime(plugin=self.plugin, fsops=None, hop=self.cfg.hop)

    def hold(self, k):
        return hoplink.HOLDS.get((str(k.state_dir), "alpha"))


class FrontierAndFieldHoldTests(_InflightCase):
    """Undecidable frontier / missing pinned field: latched BEFORE the handed
    marker, with the record and its transport id unchanged."""

    def test_an_undecidable_frontier_latches_before_anything_is_handed(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        d = inflight._inflight_dir(self.cfg, "alice")
        d.mkdir(parents=True, exist_ok=True)
        (d / "a0000099.json").write_text("{damaged")      # an unreadable live entry
        self.drain()
        held = hoplink.write_hold(self.cfg, "alice")
        self.assertIsNotNone(held, "no hold latched")
        self.assertEqual((held["reason"], held["transport_req_id"]),
                         ("hop_frontier_undecidable", "00000001"))
        self.assertEqual(self.port.writes, [])
        self.assertFalse(inflight.handed_path(self.cfg, "alice", "00000001").exists(),
                         "the handed marker was written")
        self.assertIn("00000001", inflight.list_records(self.cfg, "alice"))
        (d / "a0000099.json").unlink()                     # readable again: still latched
        self.drain()
        self.drain()
        self.assertEqual(self.port.writes, [], "the frontier hold released itself")

    def test_control_a_readable_frontier_hands_over(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])
        self.assertIsNone(hoplink.write_hold(self.cfg, "alice"))

    def test_a_record_without_its_pinned_from_address_latches_handover_invalid(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.port = _FailingPort()
        self.port.raise_on_write = OSError(5, "EIO")       # handed, then not written
        self.drain()
        rec = inflight.read_record(self.cfg, "alice", "00000001")
        del rec["from_address"]                            # an older record's shape
        inflight._write_record(self.cfg, "alice", "00000001", rec, "record")
        self.drain()
        held = hoplink.write_hold(self.cfg, "alice")
        self.assertIsNotNone(held, "no hold latched")
        self.assertEqual(held["reason"], "hop_handover_invalid")
        self.assertEqual(self.port.writes, [], "a handover was written without its from_address")


class ConstructionFailureTests(_Runtime):

    def test_a_failed_admission_write_closes_the_sender_and_the_poll_goes_on(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        write_request(self.cfg, "alpha", "00000002", to=[addr("bravo")])   # local mail
        real = hoplink.atomic_write

        def failing(path, *a, **kw):
            if path.name == hoplink.ADMITTED_FILE:
                raise OSError(28, "ENOSPC")
            return real(path, *a, **kw)

        before = _fd_count()
        with mock.patch.object(hoplink, "atomic_write", failing):
            for _ in range(3):
                k, _summary = self.drain()
        self.assertEqual(len(self.plugin.calls), 3, "one construction per poll")
        self.assertEqual([p.closes for p in CountingPort.instances], [1, 1, 1],
                         "a constructed sender was not closed")
        self.assertEqual(hoplink._SENDERS, {}, "a sender was cached without admitted.json")
        self.assertLessEqual(_fd_count(), before)
        hold = self.hold(k)
        self.assertIsNotNone(hold)
        self.assertTrue(hold.reason.startswith("hop_construct_failed"), hold.reason)
        self.assertFalse(hold.latched)
        self.assertTrue(helpers.list_notices(self.cfg, "bravo"),
                        "the instance's local mail did not drain")
        self.assertTrue((k.instances["alpha"].outbox_root / "req-00000001.json").exists(),
                        "the external request was consumed while the sender was held")
        k, _ = self.drain()                                # recovers
        self.assertEqual(CountingPort.instances[-1].writes, ["00000001"])
        self.assertEqual(len(hoplink._SENDERS), 1)

    def test_a_damaged_pin_is_a_construction_hold_not_an_aborted_drain(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        write_request(self.cfg, "alpha", "00000002", to=[addr("bravo")])
        k = keyed_for_poll(self.cfg)
        pin = hoplink.transport_dir(k, "alpha") / hoplink.PIN_FILE
        pin.parent.mkdir(parents=True, exist_ok=True)
        pin.write_text("{not json")
        try:
            k, summary = self.drain()
        except Exception as e:  # noqa: BLE001 -- a wrong outcome is a FAILURE
            self.fail(f"the instance's drain raised {type(e).__name__}: {e}")
        self.assertFalse(summary.get("instance_errored"), "the instance's drain was aborted")
        hold = self.hold(k)
        self.assertIsNotNone(hold)
        self.assertTrue(hold.reason.startswith("hop_construct_failed"), hold.reason)
        self.assertTrue(helpers.list_notices(self.cfg, "bravo"))
        self.assertEqual(self.plugin.calls, [], "constructed over a damaged pin")

    def test_a_latched_construction_hold_is_not_reattempted(self):
        self.plugin.fail, self.plugin.fail_times = _Reasoned("settings_invalid"), 1
        k, _ = self.drain()
        self.drain()
        self.drain()
        self.assertEqual(len(self.plugin.calls), 1, "a latched hold was re-attempted")
        hold = self.hold(k)
        self.assertEqual((hold.reason, hold.latched), ("hop_settings_refused", True))

    def test_a_runtime_class_with_a_colliding_reason_is_never_latched(self):
        hoplink._RUNTIME_CLASSES.extend([(UnsafeRead, "unsafe_read")])
        e = UnsafeRead.__new__(UnsafeRead)
        Exception.__init__(e, "collides")
        e.reason = "settings_invalid"
        self.plugin.fail, self.plugin.fail_times = e, 1
        k, _ = self.drain()
        hold = self.hold(k)
        self.assertNotEqual(hold.reason, "hop_settings_refused")
        self.assertFalse(hold.latched)
        self.drain()
        self.assertEqual(len(self.plugin.calls), 2, "a retried hold was not retried")


class PinnedPredecessorTests(_Runtime):

    def test_a_pinned_but_unconfirmed_predecessor_blocks_the_successor(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        k, _ = self.drain()                                 # G1 pinned and admitted
        (hoplink.transport_dir(k, "alpha") / hoplink.ADMITTED_FILE).unlink()   # never confirmed
        self.put(alpha={"binding_seq": 9})                  # a rebind fences G1
        hoplink.forget_senders()
        self.drain()
        write_request(self.cfg, "alpha", "00000002", to=[EXTERNAL])
        k, _ = self.drain()
        hold = self.hold(k)
        self.assertIsNotNone(hold, "no hold: a successor sender was constructed")
        self.assertEqual((hold.reason, hold.scope), ("hop_predecessor_unretired", "instance"))
        self.assertEqual(len(self.plugin.calls), 1, "G2 admitted while G1's tree is unretired")

    def test_the_fenced_generations_work_is_left_alone(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.drain()                                        # handed over in G1, pending
        self.assertEqual(self.plugin.ports[0].writes, ["00000001"])
        self.put(alpha={"binding_seq": 9})
        hoplink.forget_senders()
        for _ in range(2):
            self.drain()
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "the fenced generation's in-flight request was settled")
        self.assertEqual(self.plugin.ports[0].writes, ["00000001"])


class WriteHoldUnconsumedTests(_InflightCase):

    def test_a_latched_handover_hold_leaves_new_requests_unconsumed(self):
        hoplink.set_write_hold(self.cfg, "alice", "hop_request_conflict", "x", "00000009")
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.assertTrue((self.cfg.instances["alice"].outbox_root / "req-00000001.json").exists(),
                        "consumed under a latched hold")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.assertFalse(inflight.counter_path(self.cfg, "alice").exists(),
                         "a transport id was allocated under a latched hold")
        self.assertFalse(result_path(self.cfg, "alice", "00000001").exists())


class MailOnlyTests(_InflightCase):

    def test_a_request_outside_the_cold_mail_classes_is_no_route(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        path = self.cfg.instances["alice"].outbox_root / "req-00000001.json"
        doc = json.loads(path.read_text())
        route = outbound.ExternalRoute(recipients=(EXT,))
        for klass in ("trusted_fleet_host", "local", None):
            with self.subTest(klass=klass):
                outbound._begin_external(self.cfg, "alice", "00000001", doc, route,
                                         req_digest=None, attachments=None,
                                         transport=self.port, klass=klass)
                self.assertEqual(self.port.writes, [], "handed over as mail")
                self.assertTrue(result_path(self.cfg, "alice", "00000001").exists(), "not answered")
                r = read_json(result_path(self.cfg, "alice", "00000001"))
                self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "no_route"))
                self.assertEqual(self.port.writes, [])
                self.assertFalse(inflight.counter_path(self.cfg, "alice").exists())
                self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
                os.unlink(result_path(self.cfg, "alice", "00000001"))

    def test_control_the_cold_mail_classes_go(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])


class AttachmentsUnderARuntimeTests(_Runtime):

    def test_an_attachment_bearing_request_is_refused_at_begin(self):
        data = b"bytes"
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL],
                      attachments=[helpers.attachment_descriptor(data)])
        helpers.stage_outbound_sidecars(self.cfg, "alpha", "00000001", [data])
        k0 = keyed_for_poll(self.cfg)                       # begins the generation
        counter = inflight.counter_path(k0, "alpha")
        before = counter.read_bytes() if counter.exists() else None
        k, _ = self.drain()
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual((r["outcome"], r["reason_code"]), ("queued_for_human", "transport_anomaly"))
        self.assertEqual(inflight.list_records(k, "alpha"), [])
        after = counter.read_bytes() if counter.exists() else None
        self.assertEqual(after, before, "a transport id was allocated")
        self.assertEqual([p.writes for p in self.plugin.ports], [[]] * len(self.plugin.ports))


if __name__ == "__main__":
    import unittest
    unittest.main()
