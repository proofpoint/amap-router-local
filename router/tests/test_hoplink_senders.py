"""One sender per (logical_id, generation, pin), through the plugin-object
seam (`service.HopRuntime`, `router/hoplink.py`): the binding pin written
before the first construction, `admitted.json` after it, the per-process
cache, and the construction rows of the closed exception table. Driven
through the real drain under a registry, with a stand-in plugin."""
from __future__ import annotations

import json
from dataclasses import replace

from router import config as config_mod
from router import generations, hoplink, inflight, outbound, service
from router.tests import helpers
from router.tests.helpers import keyed_for_poll, write_request
from router.tests.test_generations import LIDS, _Gens
from router.tests.test_inflight import FakeTransport, _external

EXTERNAL = "you@example.com"


class _Reasoned(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class StandInPlugin:
    """Plugin-shaped: `make_sender` returns a fake port per call, or raises
    what `fail` says, the next `fail_times` calls."""

    def __init__(self):
        self.calls = []
        self.fail, self.fail_times = None, 0
        self.ports = []

    def make_sender(self, settings, fsops):
        self.calls.append(dict(settings))
        if self.fail_times:
            self.fail_times -= 1
            raise self.fail
        port = FakeTransport()
        self.ports.append(port)
        return port

    def make_intake_reader(self, settings, fsops):
        raise AssertionError("not used here")

    def make_upstream_marker_store(self, settings, fsops):
        raise AssertionError("not used here")


class _Senders(_Gens):

    def setUp(self):
        super().setUp()
        hoplink.forget_senders()
        hoplink.HOLDS.clear()
        self.addCleanup(hoplink.forget_senders)
        self.cfg = replace(self.cfg, hop=self.hop_config(str(self.tmp / "hop")))
        self.plugin = StandInPlugin()
        self.rt = service.HopRuntime(plugin=self.plugin, fsops=None, hop=self.cfg.hop)

    @staticmethod
    def hop_config(root):
        return config_mod.HopConfig(root=root, peer_uid=0, version_write=1,
                                    caps=tuple(helpers.TEST_HOP_CAPS.items()))

    def drain(self, cfg=None):
        k = keyed_for_poll(cfg or self.cfg)
        return k, outbound.drain_instance(k, "alpha", transport=self.rt,
                                          cold_policy=_external)

    def tdir(self, k):
        return hoplink.transport_dir(k, "alpha")


class SenderTests(_Senders):

    def test_the_pin_then_the_sender_then_admitted_once_per_process(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        k, _ = self.drain()
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        self.assertEqual(lid, LIDS["alpha"])
        pin = json.loads((self.tdir(k) / "hop.json").read_text())
        minted = next(g for g in generations.read_doc(self.state_dir, lid)["gens"]
                      if g["gen"] == gen)["minted_ts"]
        self.assertEqual(pin, {"hop_root": str(self.tmp / "hop"), "peer_uid": 0,
                               "version_write": 1, "admitted_at": minted})
        self.assertTrue((self.tdir(k) / "admitted.json").is_file())
        [settings] = self.plugin.calls
        self.assertEqual(settings, {
            "hop_root": str(self.tmp / "hop"), "logical_id": lid, "generation": gen,
            "peer_uid": 0, "version_write": 1, "caps": helpers.TEST_HOP_CAPS,
            "admitted_at": minted, "role": "hop1"})
        self.assertEqual(self.plugin.ports[0].writes, ["00000001"])
        sent = json.loads(self.plugin.ports[0].pending["00000001"])
        self.assertEqual(sent["request"]["agent_id"], lid, "agent_id is the logical_id")
        for _ in range(3):
            self.drain()
        self.assertEqual(len(self.plugin.calls), 1, "constructed more than once")

    def test_admitted_at_comes_from_the_record_never_the_clock(self):
        """A distinctive minted_ts planted in the durable record before the
        first construction is exactly what the settings and the pin carry."""
        k = keyed_for_poll(self.cfg)                     # begins the generation
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        path = generations.gen_file(self.state_dir, lid)
        doc = json.loads(path.read_text())
        for g in doc["gens"]:
            if g["gen"] == gen:
                g["minted_ts"] = "2001-02-03T04:05:06Z"
        path.write_text(json.dumps(doc))
        outbound.drain_instance(k, "alpha", transport=self.rt, cold_policy=_external)
        self.assertEqual(self.plugin.calls[0]["admitted_at"], "2001-02-03T04:05:06Z")
        pin = json.loads((self.tdir(k) / "hop.json").read_text())
        self.assertEqual(pin["admitted_at"], "2001-02-03T04:05:06Z")


class SettlementRecordTests(_Senders):
    """`inflight.settlement_record`, the fixture's probe, on the real layout."""

    def test_inflight_then_settled_then_none(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        k, _ = self.drain()
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        n = self.plugin.ports[0].writes[0]
        self.assertEqual(inflight.settlement_record(self.state_dir, lid, gen, n),
                         {"state": "inflight", "req_id": "00000001", "outcome": None})
        self.plugin.ports[0].send_all()
        self.drain()
        self.assertEqual(inflight.settlement_record(self.state_dir, lid, gen, n),
                         {"state": "settled", "req_id": "00000001", "outcome": "accepted"})
        self.assertIsNone(inflight.settlement_record(self.state_dir, lid, gen, "99999999"))
        for bad in (1, "1", "0000000x"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    inflight.settlement_record(self.state_dir, lid, gen, bad)

    def test_a_damaged_record_raises_never_absent(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        k, _ = self.drain()
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        inflight.record_path(k, "alpha", "00000001").write_text("{not json")
        with self.assertRaises(Exception):
            inflight.settlement_record(self.state_dir, lid, gen, "00000002")


class PinTests(_Senders):

    def test_a_changed_binding_holds_and_constructs_nothing(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.drain()
        self.assertEqual(len(self.plugin.calls), 1)
        moved = replace(self.cfg, hop=self.hop_config(str(self.tmp / "hop-moved")))
        hoplink.forget_senders()   # a restart: nothing cached
        write_request(self.cfg, "alpha", "00000002", to=[EXTERNAL])
        k, summary = self.drain(moved)
        self.assertEqual(len(self.plugin.calls), 1, "constructed at the new root")
        hold = hoplink.HOLDS[(str(k.state_dir), "alpha")]
        self.assertEqual((hold.reason, hold.latched), ("hop_binding_changed", True))
        self.assertTrue((k.instances["alpha"].outbox_root / "req-00000002.json").exists(),
                        "the request was consumed while the sender is held")
        self.assertFalse(helpers.result_path(self.cfg, "alpha", "00000002").exists())


class ConstructionTests(_Senders):

    def test_a_failure_caches_nothing_and_the_next_poll_recovers(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.plugin.fail, self.plugin.fail_times = ValueError("bare"), 1
        k, _ = self.drain()
        hold = hoplink.HOLDS[(str(k.state_dir), "alpha")]
        self.assertFalse(hold.latched)
        self.assertTrue(hold.reason.startswith("hop_construct_failed"))
        self.assertFalse((self.tdir(k) / "admitted.json").exists())
        self.assertEqual(inflight.list_records(k, "alpha"), [], "put in flight while held")
        self.assertTrue((k.instances["alpha"].outbox_root / "req-00000001.json").exists())
        self.drain()
        self.assertEqual(len(self.plugin.calls), 2)
        self.assertEqual(self.plugin.ports[0].writes, ["00000001"])
        self.assertNotIn((str(k.state_dir), "alpha"), hoplink.HOLDS)

    def test_the_latched_construction_reasons(self):
        for reason, hold_reason in (("settings_invalid", "hop_settings_refused"),
                                    ("exists_different", "hop_identity_conflict")):
            with self.subTest(reason=reason):
                hoplink.forget_senders()
                hoplink.HOLDS.clear()
                self.plugin.fail, self.plugin.fail_times = _Reasoned(reason), 1
                k, _ = self.drain()
                hold = hoplink.HOLDS[(str(k.state_dir), "alpha")]
                self.assertEqual((hold.reason, hold.latched), (hold_reason, True))

    def test_a_bare_value_error_is_never_the_settings_hold(self):
        self.plugin.fail, self.plugin.fail_times = ValueError("settings"), 1
        k, _ = self.drain()
        hold = hoplink.HOLDS[(str(k.state_dir), "alpha")]
        self.assertNotEqual(hold.reason, "hop_settings_refused")
        self.assertFalse(hold.latched)


class PredecessorTests(_Senders):

    def test_no_successor_sender_while_an_admitted_predecessor_is_unretired(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.drain()                                     # G1 admitted
        self.put(alpha={"binding_seq": 9})               # a rebind fences G1
        hoplink.forget_senders()
        self.drain()                                     # G2's first sight
        write_request(self.cfg, "alpha", "00000002", to=[EXTERNAL])
        k, _ = self.drain()
        hold = hoplink.HOLDS[(str(k.state_dir), "alpha")]
        self.assertEqual((hold.reason, hold.scope), ("hop_predecessor_unretired", "instance"))
        self.assertEqual(len(self.plugin.calls), 1, "G2 was admitted before G1 was retired")
        self.assertTrue((k.instances["alpha"].outbox_root / "req-00000002.json").exists())


if __name__ == "__main__":
    import unittest
    unittest.main()
