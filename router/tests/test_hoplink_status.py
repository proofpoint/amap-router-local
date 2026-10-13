"""`status.json`'s `hop` section (`hoplink.status_doc`, `StatusTracker.record_hop`)
and the write_request row's RETRIES: each named with its status and age, logged
quietly only while a routine retry is young, and kept out of the drained
summary line. Driven through the real drain under a registry."""
from __future__ import annotations

import json
import logging

from router import config as config_mod
from router import hoplink, inflight, service
from router.status import StatusTracker
from router.tests.helpers import write_request
from router.tests.test_hoplink_senders import EXTERNAL, StandInPlugin, _Senders
from router.tests.test_hoplink_write_table import _FailingPort, _Reasoned


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FailingPlugin(StandInPlugin):
    def make_sender(self, settings, fsops):
        self.calls.append(dict(settings))
        if self.fail_times:
            self.fail_times -= 1
            raise self.fail
        port = _FailingPort()
        self.ports.append(port)
        return port


class _Status(_Senders):

    def setUp(self):
        super().setUp()
        self.clock = _Clock()
        orig = hoplink._clock
        hoplink._clock = self.clock
        self.addCleanup(setattr, hoplink, "_clock", orig)
        hoplink.RETRIES.clear()
        self.addCleanup(hoplink.RETRIES.clear)
        self.plugin = FailingPlugin()
        self.rt = service.HopRuntime(plugin=self.plugin, fsops=None, hop=self.cfg.hop)

    def section(self, k):
        return hoplink.status_doc(k, k.instances)

    def logs(self, fn):
        """Run `fn` with the router's loggers live; the inflight records."""
        log = logging.getLogger("amap_router_local")
        log.disabled = False
        try:
            with self.assertLogs("amap_router_local.inflight", level="WARNING") as cm:
                result = fn()
        finally:
            log.disabled = True
        return result, cm.records


class RetryStatusTests(_Status):

    def first_poll_with(self, exc):
        """Request 1 handed over (the sender constructed), then request 2
        waiting, whose hand-over raises `exc` on the next drain."""
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.drain()
        port = self.plugin.ports[0]
        self.assertEqual(port.writes, ["00000001"], "control: the first hand-over went")
        write_request(self.cfg, "alpha", "00000002", to=[EXTERNAL])
        port.raise_on_write = exc
        return port

    def test_a_routine_retry_is_named_quiet_then_loud_once_stale(self):
        port = self.first_poll_with(_Reasoned("version"))
        (k, summary), records = self.logs(self.drain)
        self.assertEqual([r.levelname for r in records], ["WARNING"])
        retry = self.section(k)["instances"]["alpha"]["retry"]
        self.assertEqual((retry["status"], retry["transport_req_id"], retry["age_s"]),
                         ("hop_version_unavailable", "00000002", 0))
        self.assertEqual(summary.get("inflight_errored", 0), 0, "a named retry is not an error")
        self.clock.t += inflight.STALE_AFTER_S
        port.raise_on_write = _Reasoned("version")
        (k, _), records = self.logs(self.drain)
        self.assertEqual([r.levelname for r in records], ["ERROR"], "stale: loud")
        retry = self.section(k)["instances"]["alpha"]["retry"]
        self.assertEqual(retry["age_s"], inflight.STALE_AFTER_S, "the first sighting is kept")
        k, _ = self.drain()                              # it goes
        self.assertEqual(port.writes, ["00000001", "00000002"])
        self.assertNotIn("retry", self.section(k)["instances"].get("alpha", {}),
                         "cleared once handed over")

    def test_every_named_retry_status(self):
        cases = {   # the frozen table's statuses, written out: never read from the module
            "version": "hop_version_unavailable", "layout": "hop_layout",
            "heal_state": "hop_anomaly:heal_state",
            "protocol_violation": "hop_anomaly:protocol_violation",
            "marker_unreadable": "hop_anomaly:marker_unreadable"}
        # "closed" evicts: its own test below.
        self.assertEqual(set(hoplink.RETRY_WRITE_REASONS), set(cases) | {"closed"})
        for reason, status in cases.items():
            with self.subTest(reason=reason):
                self.setUp()
                self.first_poll_with(_Reasoned(reason))
                k, _ = self.drain()
                got = self.section(k)["instances"].get("alpha", {}).get("retry", {})
                self.assertEqual(got.get("status"), status)

    def test_an_anomaly_is_loud_on_the_first_poll(self):
        self.first_poll_with(_Reasoned("protocol_violation"))
        _, records = self.logs(self.drain)
        self.assertEqual([r.levelname for r in records], ["ERROR"])

    def test_owner_from_a_sender_is_unexpected(self):
        """Only an intake reader raises `owner`: from write_request it is no
        row of the table, so it is retried as unexpected, with its traceback."""
        self.first_poll_with(_Reasoned("owner"))
        k, summary = self.drain()
        retry = self.section(k)["instances"].get("alpha", {}).get("retry", {})
        self.assertEqual(retry.get("status"), hoplink.RETRY_UNEXPECTED)
        self.assertEqual(summary["outbound_errored"], 1)

    def test_layout_names_both_causes(self):
        self.first_poll_with(_Reasoned("layout"))
        k, _ = self.drain()
        retry = self.section(k)["instances"].get("alpha", {}).get("retry", {})
        self.assertEqual(retry.get("status"), "hop_layout")
        self.assertIn("down/", retry.get("hint", ""))
        self.assertIn("own tree directories", retry.get("hint", ""))

    def test_an_io_error_is_hop_io_error(self):
        self.first_poll_with(OSError(5, "EIO"))
        k, _ = self.drain()
        self.assertEqual(self.section(k)["instances"]["alpha"]["retry"]["status"],
                         "hop_io_error")

    def test_closed_evicts_and_the_next_poll_reconstructs(self):
        self.first_poll_with(_Reasoned("closed"))
        k, _ = self.drain()
        self.assertEqual(self.section(k)["instances"]["alpha"]["retry"]["status"],
                         "hop_object_closed")
        self.assertEqual(self.section(k)["senders_open"], 0, "evicted")
        self.drain()
        self.assertEqual(len(self.plugin.calls), 2)
        # A fresh port knows nothing pending, so record 1 is handed over again
        # too: each under its own transport id, never a new one.
        self.assertEqual(sorted(self.plugin.ports[1].writes), ["00000001", "00000002"])

    def test_an_unexpected_exception_is_an_errored_record(self):
        self.first_poll_with(ValueError("bare"))
        k, summary = self.drain()
        self.assertEqual(summary["outbound_errored"], 1, "logged with its traceback")
        self.assertEqual(self.section(k)["instances"]["alpha"]["retry"]["status"],
                         hoplink.RETRY_UNEXPECTED)


class HoldStatusTests(_Status):

    def test_a_sender_hold_with_its_first_sighting(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.plugin.fail, self.plugin.fail_times = ValueError("bare"), 2
        k, _ = self.drain()
        self.clock.t += 30
        k, _ = self.drain()
        hold = self.section(k)["instances"]["alpha"]["sender_hold"]
        self.assertTrue(hold["reason"].startswith("hop_construct_failed"))
        self.assertEqual((hold["latched"], hold["scope"], hold["age_s"]), (False, "gen", 30))

    def test_a_latched_write_hold(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.drain()
        self.plugin.ports[0].raise_on_write = _Reasoned("handover_invalid")
        write_request(self.cfg, "alpha", "00000002", to=[EXTERNAL])
        k, _ = self.drain()
        held = self.section(k)["instances"].get("alpha", {}).get("write_hold", {})
        self.assertEqual((held.get("reason"), held.get("transport_req_id")),
                         ("hop_handover_invalid", "00000002"))
        self.assertIn("router generation new <name> --reason <text>", held.get("hint", ""),
                      "a latched hold's status does not name its exit")
        self.assertIn("left for disposal", held["hint"])

    def test_a_binding_change_names_its_exit(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        k, _ = self.drain()
        pin_path = hoplink.transport_dir(k, "alpha") / hoplink.PIN_FILE
        pin = json.loads(pin_path.read_text())
        pin["peer_uid"] = 7
        pin_path.write_text(json.dumps(pin))
        hoplink.forget_senders()
        k, _ = self.drain()
        hold = self.section(k)["instances"]["alpha"]["sender_hold"]
        self.assertEqual(hold["reason"], "hop_binding_changed")
        self.assertIn("fixed for the life of state_dir", hold.get("hint", ""))

    def test_a_quiet_instance_has_no_entry_and_the_senders_are_counted(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        k, _ = self.drain()
        doc = self.section(k)
        self.assertEqual(doc["instances"], {})
        self.assertEqual(doc["senders_open"], 1)


class PollTests(_Status):
    """Through `service.poll_once`: the section is in status.json, and the
    per-instance summary (what the drained line logs) carries no hop key."""

    def test_status_json_carries_it_and_the_summary_does_not(self):
        self.plugin.fail, self.plugin.fail_times = _Reasoned("settings_invalid"), 99
        tracker = StatusTracker()
        summary = service.poll_once(self.cfg, tracker, self.rt)
        doc = tracker.to_doc()
        self.assertIn("hop", doc)
        hold = doc["hop"]["instances"].get("alpha", {}).get("sender_hold", {})
        self.assertEqual((hold.get("reason"), hold.get("latched")), ("hop_settings_refused", True))
        self.assertTrue(summary["alpha"], "control: alpha was drained")
        for name, s in summary.items():
            self.assertFalse([key for key in s if "hop" in key], name)
        self.assertNotIn("hop_", str(summary))

    def test_no_section_without_a_hop_runtime(self):
        tracker = StatusTracker()
        service.poll_once(self.cfg, tracker, None)
        self.assertNotIn("hop", tracker.to_doc())


if __name__ == "__main__":
    import unittest
    unittest.main()
