"""The handover a record makes (`inflight.transport_request_bytes`) and the
settled frontier it carries (`inflight.settled_through`), plus the
begin-time refusals through the real drain (`outbound._begin_external`).
"""
from __future__ import annotations

import json
import os
import unittest
from dataclasses import replace
from unittest import mock

from router import config as config_mod
from router import hoplink, inflight, outbound
from router.tests import helpers
from router.tests.helpers import read_json, result_path, write_request
from router.tests.test_inflight import EXT, _InflightCase


def _rec(n, req_id, **extra):
    rec = {"transport_req_id": n, "recipients": [EXT], "written_ts": "2026-10-12T00:00:00Z",
           "from_address": "alice@example.org",
           "request": {"contract_version": "2", "req_id": req_id,
                       "draft": {"to": [EXT], "subject": "s", "body_text": "b"}}}
    rec.update(extra)
    return rec


class FrontierTests(_InflightCase):

    def put(self, n, req_id):
        rec = _rec(n, req_id)
        inflight._write_record(self.cfg, "alice", req_id, rec, "record")
        return rec

    def test_lowest_live_minus_one(self):
        self.put("00000003", "a0000001")
        self.put("00000007", "a0000002")
        self.assertEqual(inflight.settled_through(self.cfg, "alice"), 2)

    def test_a_burned_first_id_is_not_live(self):
        """Ids 1-4 were burned (allocated, never recorded): the frontier is
        the first live id less one, at or above the carried counter less one."""
        self.put("00000005", "a0000001")
        self.assertEqual(inflight.settled_through(self.cfg, "alice"), 4)

    def test_a_settled_record_not_yet_deleted_still_counts(self):
        rec = self.put("00000002", "a0000001")
        self.put("00000006", "a0000002")
        # Its anchor may already be durable; its record is not gone, so it is live.
        self.assertEqual(inflight.settled_through(self.cfg, "alice"), 1)
        os.unlink(inflight.record_path(self.cfg, "alice", "a0000001"))
        self.assertEqual(inflight.settled_through(self.cfg, "alice"), 5)
        del rec

    def test_any_unreadable_entry_makes_it_undecidable(self):
        self.put("00000005", "a0000002")
        d = inflight._inflight_dir(self.cfg, "alice")
        cases = {
            "damaged": lambda: (d / "a0000001.json").write_text("{not json"),
            "wrong schema": lambda: (d / "a0000001.json").write_text(json.dumps({"x": 1})),
            "a symlink": lambda: os.symlink(str(d / "a0000002.json"), str(d / "a0000001.json")),
            "a directory": lambda: (d / "a0000001.json").mkdir(),
        }
        for why, make in cases.items():
            with self.subTest(why=why):
                make()
                with self.assertRaises(inflight.FrontierUndecidable):
                    inflight.settled_through(self.cfg, "alice")
                p = d / "a0000001.json"
                if p.is_dir() and not p.is_symlink():
                    p.rmdir()
                else:
                    p.unlink()
        self.assertEqual(inflight.settled_through(self.cfg, "alice"), 4, "control")

    def test_a_listing_failure_is_undecidable_never_empty(self):
        self.put("00000005", "a0000002")
        with mock.patch.object(inflight.os, "listdir", side_effect=OSError(5, "EIO")):
            with self.assertRaises(inflight.FrontierUndecidable):
                inflight.settled_through(self.cfg, "alice")

    def test_no_live_record_is_undecidable(self):
        with self.assertRaises(inflight.FrontierUndecidable):
            inflight.settled_through(self.cfg, "alice")


class HandoverTests(_InflightCase):

    def test_a_retry_changes_only_settled_through(self):
        low = _rec("00000003", "a0000001")
        high = _rec("00000005", "a0000002")
        for req_id, rec in (("a0000001", low), ("a0000002", high)):
            inflight._write_record(self.cfg, "alice", req_id, rec, "record")
        first = json.loads(inflight.transport_request_bytes(self.cfg, "alice", high))
        self.assertEqual(first["settled_through"], 2)
        os.unlink(inflight.record_path(self.cfg, "alice", "a0000001"))   # 3 settled
        second = json.loads(inflight.transport_request_bytes(self.cfg, "alice", high))
        self.assertEqual(second["settled_through"], 4)
        for key in ("attachments", "envelope", "request", "schema"):
            self.assertEqual(first[key], second[key], key)

    def test_the_bytes_are_canonical(self):
        rec = _rec("00000003", "a0000001")
        inflight._write_record(self.cfg, "alice", "a0000001", rec, "record")
        data = inflight.transport_request_bytes(self.cfg, "alice", rec)
        self.assertEqual(hoplink.canonical(json.loads(data)), data)
        self.assertFalse(data.endswith(b"\n"))

    def test_the_from_address_is_the_pinned_one_never_filled_in(self):
        rec = _rec("00000003", "a0000001")
        del rec["from_address"]
        inflight._write_record(self.cfg, "alice", "a0000001", rec, "record")
        with self.assertRaises(Exception) as cm:
            inflight.transport_request_bytes(self.cfg, "alice", rec)
        self.assertIsInstance(cm.exception, inflight.HandoverUnavailable)

    def test_the_frontier_must_be_below_the_id(self):
        rec = _rec("00000003", "a0000001")
        inflight._write_record(self.cfg, "alice", "a0000001", rec, "record")
        with mock.patch.object(inflight, "settled_through", return_value=3):
            with self.assertRaises(inflight.FrontierUndecidable):
                inflight.transport_request_bytes(self.cfg, "alice", rec)


class PinnedVersionTests(_InflightCase):
    """With `hop` configured, the envelope's version is the PIN's, never the
    current config's, and a generation with no pin cannot make a handover."""

    def hop_cfg(self, version_write):
        return replace(self.cfg, hop=config_mod.HopConfig(
            root=str(self.tmp / "hop"), peer_uid=0, version_write=version_write,
            caps=tuple(helpers.TEST_HOP_CAPS.items())))

    def pin(self, cfg, version_write):
        p = hoplink.transport_dir(cfg, "alice") / hoplink.PIN_FILE
        p.parent.mkdir(parents=True, exist_ok=True)
        doc = dict(hoplink.pin_doc(cfg.hop, "2026-10-12T00:00:00Z"), version_write=version_write)
        p.write_bytes(hoplink.canonical(doc))

    def test_the_version_is_the_pins(self):
        cfg = self.hop_cfg(2)
        self.pin(cfg, 1)
        rec = _rec("00000003", "a0000001")
        inflight._write_record(cfg, "alice", "a0000001", rec, "record")
        doc = json.loads(inflight.transport_request_bytes(cfg, "alice", rec))
        self.assertEqual(doc["envelope"]["hop_contract"], 1, "taken from the current config")

    def test_no_pin_is_no_handover(self):
        cfg = self.hop_cfg(1)
        rec = _rec("00000003", "a0000001")
        inflight._write_record(cfg, "alice", "a0000001", rec, "record")
        with self.assertRaises(Exception) as cm:
            inflight.transport_request_bytes(cfg, "alice", rec)
        self.assertIsInstance(cm.exception, inflight.HandoverUnavailable)


class BeginRefusalTests(_InflightCase):
    """Refused at begin: answered at once, with NO in-flight record, no
    transport id allocated and nothing written to the transport."""

    def assert_refused_at_begin(self, code):
        self.drain()
        self.assertEqual(self.port.writes, [], "handed over: not refused at begin")
        self.assertTrue(result_path(self.cfg, "alice", "00000001").exists(), "not answered")
        r = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", code))
        self.assertEqual(self.port.writes, [])
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.assertFalse(inflight.counter_path(self.cfg, "alice").exists(),
                         "a transport id was allocated")

    def test_101_recipients(self):
        write_request(self.cfg, "alice", "00000001",
                      to=[f"r{i}@example.com" for i in range(101)])
        self.assert_refused_at_begin("too_many_recipients")

    def test_100_recipients_go(self):
        write_request(self.cfg, "alice", "00000001",
                      to=[f"r{i}@example.com" for i in range(100)])
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])

    def test_an_over_long_local_part(self):
        write_request(self.cfg, "alice", "00000001", to=["l" * 65 + "@example.com"])
        self.drain()
        r = read_json(result_path(self.cfg, "alice", "00000001"))
        # The classifier answers first (the address grammar); begin's own
        # octet check is the same bound (BeginCheckTests).
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "malformed_request"))
        self.assertIn("address grammar", r["detail"])
        self.assertEqual(self.port.writes, [])
        self.assertFalse(inflight.counter_path(self.cfg, "alice").exists())

    def test_an_address_that_cannot_be_a_from_address(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        with mock.patch.object(outbound, "address_for", return_value="Alice <alice@x.org>"):
            self.drain()
        self.assertEqual(self.port.writes, [], "handed over: the address was not checked")
        self.assertTrue(result_path(self.cfg, "alice", "00000001").exists(), "not answered")
        r = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", outbound.REASON_TRANSPORT_ANOMALY))
        self.assertEqual(self.port.writes, [])
        self.assertFalse(inflight.counter_path(self.cfg, "alice").exists())

    def test_the_from_address_octet_bounds_at_begin(self):
        """The same bounds as at load, through the drain: the whole address
        at 254 octets and the local part at 64 go; 255 and 65 are refused
        before anything is allocated."""
        dom254 = "b" * 63 + "." + "c" * 63 + "." + "d" * 61        # 64 + 1 + 189 = 254
        cases = [("a" * 64 + "@" + dom254, True), ("a" * 64 + "@" + dom254 + "e", False),
                 ("l" * 64 + "@x.org", True), ("l" * 65 + "@x.org", False)]
        for address, goes in cases:
            with self.subTest(octets=len(address), goes=goes):
                self.tearDown()
                self.setUp()
                write_request(self.cfg, "alice", "00000001", to=[EXT])
                with mock.patch.object(outbound, "address_for", return_value=address):
                    self.drain()
                if goes:
                    self.assertEqual(self.port.writes, ["00000001"])
                    continue
                self.assertEqual(self.port.writes, [])
                r = read_json(result_path(self.cfg, "alice", "00000001"))
                self.assertEqual((r["outcome"], r["reason_code"]),
                                 ("queued_for_human", outbound.REASON_TRANSPORT_ANOMALY))
                self.assertFalse(inflight.counter_path(self.cfg, "alice").exists())

    def test_the_record_pins_the_address_at_begin(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        rec = inflight.read_record(self.cfg, "alice", "00000001")
        self.assertEqual(rec["from_address"],
                         config_mod.address_for("alice", self.cfg.fleet_domain))

    def test_the_cap_is_checked_at_the_longest_transport_id(self):
        """A request that fits the cap under transport id 1 but not under an
        18-digit one is refused at begin: a later id cannot make it fit."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        doc = read_json(self.cfg.instances["alice"].outbox_root / "req-00000001.json")
        doc = dict(doc, req_id="00000001", agent_id=config_mod.state_key(self.cfg, "alice"))
        size8 = hoplink.request_bytes_len(doc)

        def with_request_cap(cap):
            caps = dict(helpers.TEST_HOP_CAPS, request=cap)
            self.cfg = replace(self.cfg, hop=config_mod.HopConfig(
                root=str(self.tmp / "hop"), peer_uid=0, version_write=1,
                caps=tuple(caps.items())))

        with_request_cap(size8 + 9)        # 18 digits are 10 more than 8
        self.assert_refused_at_begin("malformed_request")
        write_request(self.cfg, "alice", "00000002", to=[EXT])   # the same size
        with_request_cap(size8 + 10)
        # A sender's construction pins the generation first; this stand-in
        # port has none, so pin it as the construction would.
        pin_path = hoplink.transport_dir(self.cfg, "alice") / hoplink.PIN_FILE
        pin_path.parent.mkdir(parents=True, exist_ok=True)
        pin_path.write_bytes(hoplink.canonical(hoplink.pin_doc(self.cfg.hop, "2026-10-12T00:00:00Z")))
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"], "control: it fits")

if __name__ == "__main__":
    unittest.main()
