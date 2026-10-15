"""The real-plugin matrix for the runtime capability at PLUGIN_API (3, 5):
this router's verbs and control pass against the transport plugin's REAL
runtime sender and lister, over this router's REAL filesystem port, in a
throwaway hop root. Not a test module (its name keeps it out of discovery):
the plugin is not part of this repository, so the matrix runs where a copy
of it is available, and its evidence is the run, recorded with the plugin
file's sha256. Continuous integration does not run it.

Run from the repository root:

    python3 -B router/tests/run_realhop.py --plugin <path to the plugin file>

The plugin file must hash to `ARTIFACT_SHA256`, and it is loaded through
this router's own loader with that digest as the pin. Without `--plugin`,
or with a file of another digest, the run is REFUSED (exit 2) by name: it
never skips and never passes vacuously. Each row prints PASS or FAIL, then
the total; exit 0 only when every row passes.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import types
import unittest
from pathlib import Path
from typing import Any, List, Optional, Sequence
from unittest import mock

#: The plugin artifact this router's re-point is pinned to: PLUGIN_API (3, 5).
ARTIFACT_SHA256 = "f15855c974df021c2ae5c551aff2448d934725a6796fb03434e573305d24fe93"
PLUGIN_API = (3, 5)
#: The hop caps the real plugin requires (positive byte counts, exactly these).
REAL_CAPS = {"document": 1 << 16, "request": 1 << 16, "attachment": 1 << 12, "total": 1 << 20}
#: The matrix, by row name, in order (the PR body names the same rows).
ROWS = (
    "w15_capability_table", "adopt", "retire", "new", "restore_listed_live", "restore_unlisted",
    "adopt_after_unlisted_restore", "abandon_attempt", "abandon_plan",
    "settle_generation_retired", "hold_before_hand_over",
    "crash_adopt_audited_once", "crash_retire_audited_once", "crash_new_audited_once",
)
#: The resend workflow's rows, through the plugin's REAL agent sender.
RESEND_ROWS = ("peer_block_republished_under_new_n",)
#: The inbound round trip (RL-INBOUND-LIFT design v1.3 §3, row (b)): RL to RL over the REAL
#: plugin, its REAL Ed25519 backend (openssl) and a REAL hop tree per host; only the hub step
#: between the two trees is emulated, through the plugin's own downstream factories.
INBOUND_ROWS = ("inbound_round_trip",)
#: The openssl binary the row's crypto backend runs (the plugin's openssl_path).
OPENSSL = "/usr/bin/openssl"

_PLUGIN_PATH: Optional[str] = None


class Refused(Exception):
    """The run cannot start: named, exit 2."""


def check_plugin(path: Optional[str]) -> str:
    """The canonical plugin path, or `Refused` naming why not."""
    if not path:
        raise Refused("no --plugin given: the matrix needs the real plugin file")
    p = os.path.realpath(path)
    try:
        digest = hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError as e:
        raise Refused(f"the plugin file cannot be read: {e}") from None
    if digest != ARTIFACT_SHA256:
        raise Refused(f"digest mismatch: the plugin file is {digest}, the pin is "
                      f"{ARTIFACT_SHA256}")
    return p


def load(path: str) -> Any:
    """Through this router's own loader, with the pinned digest. The harness
    owns the file, so it trusts its own uid as well as root."""
    from router import transport as transport_mod
    plugin = transport_mod.load_plugin(path, ARTIFACT_SHA256, trusted_uids=(0, os.geteuid()))
    if tuple(plugin.api) != PLUGIN_API:
        raise Refused(f"the plugin declares PLUGIN_API {tuple(plugin.api)}, not {PLUGIN_API}")
    if not transport_mod.runtime_capability_declared(plugin):
        raise Refused("the plugin does not declare the runtime capability")
    return plugin


def _cases():
    """The matrix's TestCase, built late so importing this module for its
    refusal checks needs no test fixtures."""
    from router import config as config_mod
    from router import fsops as fsops_mod
    from router import inflight, peercontrol
    from router import transport as transport_mod
    from router.tests import test_peercontrol as tpc

    NOW, AT = tpc.NOW, tpc.AT
    LATER = NOW.replace(minute=30)
    LATER_AT = LATER.strftime("%Y-%m-%dT%H:%M:%SZ")

    class Matrix(tpc._Control):

        def setUp(self):
            super().setUp()
            root = self.tmp / "hop"
            root.mkdir(mode=0o750)
            self.cfg.hop.caps = dict(REAL_CAPS)
            self.plugin = load(_PLUGIN_PATH)
            self.fsops = fsops_mod.FsOps(hop_root=str(root))
            self.runtime = types.SimpleNamespace(plugin=self.plugin, fsops=self.fsops)
            self.addCleanup(self.fsops.close)

        # -- helpers ---------------------------------------------------------
        def cap(self):
            return peercontrol.capability(self.cfg, self.runtime)

        def listed(self):
            return dict(self.cap().generations())

        def raw_sender(self, gen):
            """The plugin's runtime sender, built as this router builds one."""
            settings = {"hop_root": str(self.cfg.hop.root), "generation": gen,
                        "peer_uid": self.cfg.hop.peer_uid,
                        "address": peercontrol.runtime_address(self.cfg),
                        "version_write": 1, "caps": dict(REAL_CAPS)}
            return transport_mod.runtime_factory(self.plugin, "factory")(settings, self.fsops)

        def downstream(self, gen):
            """The receiving side's first sight of the generation, as the
            hub does it, through the plugin's own marker store."""
            store = self.plugin.namespace["make_marker_store"](
                {"hop_root": str(self.cfg.hop.root), "logical_id": ".runtime",
                 "generation": gen, "peer_uid": self.cfg.hop.peer_uid}, self.fsops)
            store.first_sight()
            store.write_versions([1], version_write=1)

        def admitted_out_of_band(self, gen, at=AT):
            self.assertEqual(self.raw_sender(gen).admit(at), "admitted")
            self.downstream(gen)

        def handed(self, key):
            n = self.record(key)["control"]["attempt"]["n"]
            gen = self.record(key)["control"]["attempt"]["gen"]
            return self.raw_sender(gen).has_pending(n)

        def frozen(self):
            """A pending notice whose attempt froze before its record."""
            key = self.refused()
            with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
                self.send()
            return key, self.record(key)["control"]["attempt"]["gen"]

        def lose_record(self):
            (peercontrol.runtime_dir(self.cfg) / config_mod.RUNTIME_GENERATION_FILE).unlink()

        def acts(self, verb):
            return [a for a in peercontrol._audit_lines(self.state_dir) if a.get("act") == verb]

        def send_and_hand(self, key):
            """A first pass admits; the hub's first sight; a second pass hands over."""
            self.send()
            gen = self.record(key)["control"]["attempt"]["gen"]
            if not (Path(self.cfg.hop.root) / ".runtime" / gen / "down").exists():
                self.downstream(gen)
            self.send()
            self.assertTrue(self.handed(key), "handed over through the real port")

        # -- rows ------------------------------------------------------------
        def test_w15_capability_table(self):
            """The drift row: every name in this router's table is on the
            plugin's real objects, both factories at the minor this router
            expects, and the capability is ON at that minor."""
            names = transport_mod.RUNTIME_CAPABILITY
            self.assertEqual(tuple(self.plugin.api), transport_mod.RUNTIME_MINOR)
            self.assertTrue(transport_mod.runtime_capability_declared(self.plugin))
            for role in ("factory", "lister"):
                self.assertIn(names[role], self.plugin.optional_capabilities)
                self.assertEqual(transport_mod.OPTIONAL_FACTORIES[names[role]][0],
                                 transport_mod.RUNTIME_MINOR)
            sender = self.raw_sender("a" * 32)
            for name in ("retire", "retired", "retired_at", "identity", "admit"):
                self.assertTrue(callable(getattr(sender, names[name], None)), name)
            for name in ("has_pending", "has_result", "has_archived", "read_result",
                         "write_request", "withdraw_request"):
                self.assertTrue(callable(getattr(sender, name, None)), name)
            lister = self.cap().lister()
            self.assertTrue(callable(getattr(lister, names["generations"], None)))
            self.assertEqual(getattr(sender, "RuntimeRetired")("x").reason, "generation_retired")

        def test_adopt(self):
            gen = "a" * 32
            self.admitted_out_of_band(gen, at="2026-10-01T09:00:00Z")
            peercontrol.operator_adopt(self.cfg, self.cap(), gen, now=NOW, evidence="row")
            self.assertEqual(peercontrol.recorded_admitted_at(self.cfg),
                             (gen, "2026-10-01T09:00:00Z"))
            self.assertEqual(peercontrol.runtime_pin(self.cfg, gen)["admitted_at"],
                             "2026-10-01T09:00:00Z")
            self.send_and_hand(self.refused())

        def test_retire(self):
            gen = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(gen, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            peercontrol.operator_retire(self.cfg, self.cap(), gen, now=NOW, evidence="row")
            self.assertEqual(self.listed()[gen], "retired")
            self.assertIsNone(peercontrol.recorded_admitted_at(self.cfg))

        def test_new(self):
            old = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(old, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            out = peercontrol.operator_new(self.cfg, self.cap(), now=NOW, evidence="row")
            new, at = peercontrol.recorded_admitted_at(self.cfg)
            self.assertNotEqual(new, old)
            self.assertEqual(self.listed()[old], "retired")
            self.assertEqual(at, AT, "the plan's time")
            key = self.refused()
            self.send_and_hand(key)
            self.assertEqual(self.raw_sender(new).identity()["admitted_at"], AT, out)

        def test_restore_listed_live(self):
            key, gen = self.frozen()
            self.admitted_out_of_band(gen, at="2026-10-02T09:00:00Z")
            self.lose_record()
            self.send()
            self.assertEqual(peercontrol.recorded_admitted_at(self.cfg),
                             (gen, "2026-10-02T09:00:00Z"))
            self.assertTrue(self.handed(key))

        def unlisted_restore(self):
            key, gen = self.frozen()
            self.assertNotIn(gen, self.listed(), "never admitted")
            self.lose_record()
            (peercontrol.runtime_dir(self.cfg) / gen / "transport" / "hop.json").unlink()
            self.send(now=LATER)
            self.assertEqual(peercontrol.recorded_admitted_at(self.cfg), (gen, LATER_AT))
            self.assertEqual(self.raw_sender(gen).identity()["admitted_at"], LATER_AT)
            return key, gen

        def test_restore_unlisted(self):
            key, gen = self.unlisted_restore()
            self.downstream(gen)
            self.send(now=LATER)
            self.assertTrue(self.handed(key))

        def test_adopt_after_unlisted_restore(self):
            key, gen = self.unlisted_restore()
            d = peercontrol.runtime_dir(self.cfg)
            before = ((d / config_mod.RUNTIME_GENERATION_FILE).read_bytes(),
                      (d / gen / "transport" / "hop.json").read_bytes())
            peercontrol.operator_adopt(self.cfg, self.cap(), gen, now=NOW.replace(hour=15),
                                       evidence="row")
            after = ((d / config_mod.RUNTIME_GENERATION_FILE).read_bytes(),
                     (d / gen / "transport" / "hop.json").read_bytes())
            self.assertEqual(after, before, "a byte-equal no-op")

        def test_abandon_attempt(self):
            key, gen = self.frozen()
            self.admitted_out_of_band(gen)
            self.raw_sender(gen).retire(AT)
            self.lose_record()
            roles = []
            real = transport_mod.runtime_factory

            def spy(plugin, role):
                roles.append(role)
                return real(plugin, role)
            with mock.patch.object(transport_mod, "runtime_factory", spy):
                peercontrol.operator_abandon_attempt(self.cfg, self.cap(), key, now=NOW,
                                                     evidence="row")
            self.assertEqual(self.record(key)["control"]["suppressed"],
                             peercontrol.SUPPRESS_ABANDONED)
            self.assertEqual(set(roles), {"lister"}, "lister-only")

        def test_abandon_plan(self):
            live = "b" * 32
            self.admitted_out_of_band(live)
            peercontrol.record_generation(self.cfg, "c" * 32, admitted_at=AT)
            peercontrol._begin_verb_audit(self.cfg, peercontrol.NEW_VERB, NOW,
                                          retired="c" * 32, minted="d" * 32, evidence="row")
            out = peercontrol.operator_abandon_plan(self.cfg, self.cap(), now=NOW,
                                                    evidence="row")
            self.assertFalse(peercontrol._verb_marker_path(self.cfg).exists(), out)
            self.assertNotIn("d" * 32, self.listed())
            # The PLAN's own audit line, once, saying it was abandoned.
            lines = self.acts(peercontrol.NEW_VERB)
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].get("result", "").startswith("abandoned"), lines)

        def frozen_unhanded(self):
            """An attempt whose generation is admitted (admit runs before the
            first port call) and which crashed before its first hand-over:
            no handed marker."""
            key = self.refused()
            with mock.patch.object(inflight, "advance", side_effect=RuntimeError("crash")):
                self.send()
            gen = self.record(key)["control"]["attempt"]["gen"]
            self.assertIsNotNone(self.raw_sender(gen).identity(), "admitted")
            self.assertEqual(peercontrol._inflight_entries(self.cfg, gen),
                             [f"{self.record(key)['control']['attempt']['id']}.json"],
                             "a record and no handed marker")
            self.downstream(gen)
            return key, gen

        def test_settle_generation_retired(self):
            key, gen = self.frozen_unhanded()
            if self.handed(key):
                self.skipTest("handed before the crash point")   # never reached: FAIL below
            self.raw_sender(gen).retire(AT)
            with mock.patch.object(peercontrol, "_require_writable"):   # the plugin's backstop
                self.send()
            c = self.record(key)["control"]
            self.assertEqual((c.get("sent"), (c.get("settled") or {}).get("outcome"),
                              (c.get("settled") or {}).get("reason_code")),
                             (True, "rejected", "generation_retired"))
            self.assertFalse(self.handed(key), "the plugin wrote nothing")
            self.assertEqual(peercontrol._inflight_entries(self.cfg, gen), [])
            # Settled IS finished: nothing left unsettled, and a following
            # `new` is not refused by it.
            self.assertEqual(peercontrol.unsettled_attempts(self.cfg), [])
            peercontrol.operator_new(self.cfg, self.cap(), now=NOW, evidence="row")
            self.assertNotEqual(peercontrol.recorded_admitted_at(self.cfg)[0], gen)

        def test_hold_before_hand_over(self):
            key, gen = self.frozen_unhanded()
            self.raw_sender(gen).retire(AT)
            self.assertEqual(self.send(), {peercontrol.UNAVAILABLE: 1})
            self.assertFalse(self.record(key)["control"].get("sent"), "held, not settled")

        def crash_after_effect(self, verb, effect, run):
            real = getattr(peercontrol, effect)

            def then_crash(*a, **k):
                real(*a, **k)
                raise SystemExit("crash right after the effect")
            with mock.patch.object(peercontrol, effect, then_crash):
                with self.assertRaises(SystemExit):
                    run()
            self.assertEqual(self.acts(verb), [], "the audit is owed")
            peercontrol.repair_audits(self.cfg, self.cap())
            peercontrol.repair_audits(self.cfg, self.cap())
            self.assertEqual(len(self.acts(verb)), 1, "exactly once")

        def test_crash_adopt_audited_once(self):
            gen = "e" * 32
            self.admitted_out_of_band(gen)
            self.crash_after_effect(peercontrol.ADOPT_VERB, "record_generation", lambda:
                                    peercontrol.operator_adopt(self.cfg, self.cap(), gen,
                                                               now=NOW, evidence="row"))

        def test_crash_retire_audited_once(self):
            gen = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(gen, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            self.crash_after_effect(peercontrol.RETIRE_VERB, "_retire_idempotent", lambda:
                                    peercontrol.operator_retire(self.cfg, self.cap(), gen,
                                                                now=NOW, evidence="row"))

        def test_crash_new_audited_once(self):
            old = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(old, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            self.crash_after_effect(peercontrol.NEW_VERB, "record_generation", lambda:
                                    peercontrol.operator_new(self.cfg, self.cap(), now=NOW,
                                                             evidence="row"))

    return Matrix


class _Result(unittest.TextTestResult):

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.rows: List[tuple] = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.rows.append((test._testMethodName[5:], "PASS", ""))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows.append((test._testMethodName[5:], "FAIL", self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        super().addError(test, err)
        self.rows.append((test._testMethodName[5:], "FAIL", self._exc_info_to_string(err, test)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows.append((test._testMethodName[5:], "FAIL", f"skipped: {reason}"))


def _resend_cases():
    """The resend workflow against the plugin's real agent sender: a signed
    peer task handed over, then retransmitted under a new transport id, the
    hub publishing both (it has no cross-`n` Message-ID check)."""
    import dataclasses
    import datetime
    import json
    from router import config as config_mod
    from router import fsops as fsops_mod
    from router import hoplink, inflight, peerresend, service
    from router.tests import test_peerresend as tpr
    from router.util import parse_utc_ts

    class ResendMatrix(tpr._Retransmit):

        def setUp(self):
            super().setUp()
            root = Path(self.cfg.hop.root)
            root.mkdir(mode=0o750, exist_ok=True)
            self.cfg = dataclasses.replace(self.cfg, hop=dataclasses.replace(
                self.cfg.hop, caps=tuple(REAL_CAPS.items()), peer_uid=os.getuid()))
            self.real = load(_PLUGIN_PATH)
            self.fs = fsops_mod.FsOps(hop_root=str(root))
            self.addCleanup(self.fs.close)
            self.rt = service.HopRuntime(plugin=self.real, fsops=self.fs, hop=self.cfg.hop)

        def downstream(self, k):
            lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
            store = self.real.namespace["make_marker_store"](
                {"hop_root": str(self.cfg.hop.root), "logical_id": lid, "generation": gen,
                 "peer_uid": self.cfg.hop.peer_uid}, self.fs)
            store.first_sight()
            store.write_versions([1], version_write=1)
            return Path(self.cfg.hop.root) / lid / gen / "outbound"

        def published(self, outbound, n):
            path = outbound / f"req-{n}.hop.json"
            self.assertTrue(path.is_file(), f"the hub published req-{n}")
            return json.loads(path.read_text())

        def test_peer_block_republished_under_new_n(self):
            k, _ = self.send()
            outbound = self.downstream(k)
            k, _ = self.drain()                   # handed over through the real sender
            k, _ = self.drain()                   # the pass that finds the marker
            first = self.published(outbound, "00000001")
            pid = next(peerresend.sent_root(self.state_dir, tpr.LIDS["alpha"]).iterdir()).name
            d = peerresend.copy_dir(self.state_dir, tpr.LIDS["alpha"], pid)
            handed = parse_utc_ts(json.loads((d / peerresend.HANDED).read_text())["handed_ts"])
            later = handed + datetime.timedelta(seconds=inflight.STALE_AFTER_S + 1)
            from router import clock as clock_mod
            n = peerresend.operator_retransmit(k, pid, now=later, evidence="row",
                                               allow_pending=True)["n"]
            with mock.patch.object(clock_mod, "now", return_value=later):
                k, _ = self.drain()
            again = self.published(outbound, n)
            self.assertNotEqual(n, "00000001")
            self.assertEqual(again.get("peer"), first.get("peer"), "the identical peer block")
            self.assertIsNotNone(first.get("peer"), "a peer block was published")
            self.assertEqual(again.get("from_address"), first.get("from_address"))

    return ResendMatrix


def _ed25519_public_hex(seed: bytes) -> str:
    """The REAL Ed25519 public key of `seed`, by the openssl CLI (PKCS#8 in, SPKI out): the row
    signs and verifies with real keys, never the stand-in's synthetic ones."""
    import subprocess
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    out = subprocess.run([OPENSSL, "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, capture_output=True, check=True).stdout
    return out[-32:].hex()


def _inbound_cases():
    """Row (b): host A's agent's signed peer task, placed on host B by B's production profile,
    answered by B's agent and delivered back to A as the endpoint-bound result, over the REAL
    plugin loaded through this router's loader (`load`, trusted_uids (0, euid): the harness owns
    the file; the production owner check, root only, is NOT witnessed here), injected through
    `run_once`'s `transport` argument (never the service's own load), with the REAL openssl
    Ed25519 backend and a REAL hop tree per host through this router's FsOps.

    EMULATED, and only this: the hub step ([2]'s) between A's tree and B's, both ways. It claims
    and reads the sent request with the plugin's own HopReceiver, builds the candidate with the
    plugin's own IntakeWriter.encode_candidate from [2]'s field set (never the request's bytes),
    publishes it, then commits the sender's Result and archives. Every value the hub FABRICATES
    is in `Hub.FABRICATED`.

    ABSENT, not emulated (Opus L2): both routers run in ONE process under ONE uid, so there is no
    uid partition, no hop_root ownership split and no key-unreadable-by-[2] witness (contract
    §11 steps 1, 2 and 7). No attachment is carried. NOT exercised of [2], HAR-14's: the MIME
    round trip, the hub prefix and admission, the registry resolve, the carriage switch, the
    reduce and encode refusals that park, and the Result leg's sender gate and single-recipient
    check."""
    import hashlib
    import json
    import shutil
    import tempfile
    from router import generations, hoplink, peerjournal, peerlane
    from router.tests import test_inbound_e2e as e2e
    from router.tests.helpers import write_request
    from router.util import format_utc_ts

    class Hub:
        #: What the hub makes up rather than carries, by name, with its value (design v1.2 Δ1).
        FABRICATED = {
            "received_at": "the harness clock at the hub step",
            "admission": "fleet_hosts (the peer's host is a trusted fleet host)",
            "admission_rule": "trusted_fleet_host",
            "recipient": "the receiving agent's address (the hub prefix's Delivered-To)",
            "subject": "the draft's subject (under [2]'s cap)",
            "Date header": "the harness clock at the hub step",
            "candidate_id": "hex(sha256(Message-ID))[:32]",
            "transport Result": "accepted / allowlisted, message_id = the peer Message-ID",
        }
        #: DIRECT TEST WRITES, by name (Codex): what the row puts on disk itself rather than
        #: through a router or plugin path. The host intakes and their disposal trees are the
        #: deploy's (test_inbound_e2e._Host); [2]'s first sight of each generation goes through
        #: the plugin's own marker store, and every hub write through its HopReceiver and
        #: IntakeWriter, so neither is a direct write.
        DIRECT_WRITES = {
            "hop/.disposed/{.unresolved,.control}, hop/{.unresolved,.control}":
                "the deploy's host intakes and disposal trees (_Host), which the router never "
                "creates",
            "<instance outbox>/req-<n>.json (helpers.write_request), steps 1 and 5":
                "the test plays both agents: A's task, and B's answer to the placed notice",
        }

        def __init__(self, plugin):
            self.plugin, self.carried = plugin, []

        def carry(self, src, dst):
            lid_s = e2e.LIDS[src.name]
            gen_s = generations.read_doc(src.cfg.state_dir, lid_s)["current"]
            lid_d = e2e.LIDS[dst.name]
            gen_d = generations.read_doc(dst.cfg.state_dir, lid_d)["current"]
            # The downstream ([2]'s) factories, from the SAME module the loader pinned: the
            # LoadedPlugin surface carries only the factories this router itself calls.
            ns = self.plugin.namespace
            receiver = ns["make_hop_receiver"](
                hoplink.reader_settings(src.cfg, lid_s, gen_s), src.fsops)
            writer = ns["make_intake_writer"](
                hoplink.reader_settings(dst.cfg, lid_d, gen_d), dst.fsops)
            try:
                outbound = Path(src.cfg.hop.root) / lid_s / gen_s / "outbound"
                names = sorted(p.name for p in outbound.glob("req-*.json")
                               if not p.name.endswith(".hop.json"))
                for name in names:
                    n = name[len("req-"):-len(".json")]
                    assert receiver.claim(n) == "claimed", f"claim {n}"
                    claimed = receiver.read_claimed(n)
                    env, draft = claimed.envelope, json.loads(claimed.request)["draft"]
                    peer = env["peer"]
                    kind, _kid, statement, _sig = ns["make_peer_codec"]({}).check1(
                        [("AMAP-Peer-Statement", peer["statement_header"])])
                    sender = json.loads(statement)["from"]
                    now = format_utc_ts(clock_now())
                    header = [("From", sender.encode()), ("To", ", ".join(draft["to"]).encode()),
                              ("Subject", draft["subject"].encode()),
                              ("Message-ID", peer["message_id"].encode()),
                              ("Date", now.encode()),
                              # UNFOLDED, on both legs (RE N1): the field exactly as the
                              # envelope holds it, as raw bytes in one line. [2] passes the
                              # header RAW AS TRANSMITTED, folds included, and the codec
                              # unfolds; a folded field is not exercised here (HAR-14's MIME
                              # round trip).
                              ("AMAP-Peer-Statement", peer["statement_header"].encode())]
                    if peer.get("in_reply_to"):
                        header.append(("In-Reply-To", peer["in_reply_to"].encode()))
                    raw = writer.encode_candidate(
                        header=header, body=("utf-8", draft["body_text"].encode("utf-8")),
                        attachments=[], sender=sender, recipient=dst.address,
                        subject=draft["subject"], received_at=now, admission="fleet_hosts",
                        admission_rule="trusted_fleet_host", over_cap=None)
                    cid = hashlib.sha256(peer["message_id"].encode()).hexdigest()[:32]
                    assert writer.publish_candidate(cid, raw) == "created", f"publish {cid}"
                    result = json.dumps({"contract_version": "2", "req_id": n,
                                         "outcome": "accepted", "reason_code": "allowlisted",
                                         "detail": None, "message_id": peer["message_id"]},
                                        sort_keys=True).encode()
                    assert receiver.commit_result(n, result) == "created", f"result {n}"
                    assert receiver.archive(n) == "archived", f"archive {n}"
                    self.carried.append((src.name, n, dst.name, cid, peer["message_id"]))
            finally:
                for o in (receiver, writer):
                    o.close()

    def clock_now():
        from router import clock
        return clock.now()

    class InboundMatrix(unittest.TestCase):

        def setUp(self):
            hoplink.reset_process_state()
            self.addCleanup(hoplink.reset_process_state)
            peerlane.forget_all()
            self.addCleanup(peerlane.forget_all)
            td = tempfile.mkdtemp(prefix="rh.")
            self.addCleanup(shutil.rmtree, td, ignore_errors=True)
            tmp = Path(os.path.realpath(td))
            self.plugin = load(_PLUGIN_PATH)
            crypto = {"crypto_backend": "openssl", "openssl_path": OPENSSL}
            sa, sb = e2e._seed(b"a"), e2e._seed(b"b")
            kw = dict(plugin=self.plugin, crypto=crypto, public_key=_ed25519_public_hex)
            self.a = e2e._Host(tmp / "a", name="planner", domain=e2e.A_D, other=e2e.B_D,
                               seed=sa, other_seed=sb, **kw)
            self.b = e2e._Host(tmp / "b", name="builder", domain=e2e.B_D, other=e2e.A_D,
                               seed=sb, other_seed=sa, **kw)
            for h in (self.a, self.b):
                h.start()
                h.poll()
                # [2]'s first sight of the new generation, as the hub does it, through the
                # plugin's OWN marker store (as this matrix's other rows do): its down/ side and
                # the hop contract versions it reads. RL hands nothing over before that.
                lid = e2e.LIDS[h.name]
                gen = generations.read_doc(h.cfg.state_dir, lid)["current"]
                store = self.plugin.namespace["make_marker_store"](
                    hoplink.reader_settings(h.cfg, lid, gen), h.fsops)
                store.first_sight()
                store.write_versions([1], version_write=1)

        def notices(self, h):
            return e2e._notices(h)

        def test_inbound_round_trip(self):
            hub = Hub(self.plugin)
            write_request(self.a.cfg, "planner", "00000001", to=[self.b.address],
                          subject="Run the suite", body_text="Please run the suite.\n")
            self.a.poll()
            hub.carry(self.a, self.b)
            self.assertEqual(len(hub.carried), 1, "A handed over exactly one request")
            task_id = hub.carried[-1][4]
            self.b.poll()
            placed = self.notices(self.b)
            self.assertEqual(len(placed), 1, "B placed exactly one notice")
            self.assertEqual(f"<{placed[0]['message']['id']}@{e2e.A_D}>", task_id,
                             "THIS statement, placed on B")
            write_request(self.b.cfg, "builder", "00000001", to=[self.a.address],
                          subject="Re: Run the suite", body_text="Done.\n",
                          in_reply_to=placed[0]["message"]["id"])
            self.b.poll()
            hub.carry(self.b, self.a)
            self.assertEqual(len(hub.carried), 2, "B handed over exactly one answer")
            self.a.poll()
            result = json.loads((self.a.cfg.instances["planner"].outbox_root / "results"
                                 / "00000001.json").read_text())
            self.assertEqual((result["req_id"], result["outcome"]), ("00000001", "accepted"))
            got = self.notices(self.a)
            self.assertEqual(len(got), 1, "one endpoint-bound result on A")
            self.assertEqual((got[0]["message"].get("in_reply_to"), got[0]["message"]["from"]),
                             (placed[0]["message"]["id"], self.b.address),
                             "B's answer, resolved to THIS issued task")
            self.a.poll()
            self.b.poll()
            self.assertEqual(len(hub.carried), 2)
            hub.carry(self.a, self.b)
            hub.carry(self.b, self.a)
            self.assertEqual(len(hub.carried), 2, "no second hand-over on either side")

    return InboundMatrix


def main(argv: Optional[Sequence[str]] = None) -> int:
    global _PLUGIN_PATH
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plugin", help="the plugin file (must hash to the pinned digest)")
    args = ap.parse_args(argv)
    try:
        _PLUGIN_PATH = check_plugin(args.plugin)
        load(_PLUGIN_PATH)
    except Refused as e:
        print(f"run_realhop: REFUSED: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 -- the loader's refusal, named
        print(f"run_realhop: REFUSED: the loader refused the plugin: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 2
    matrix, resend, inbound = _cases(), _resend_cases(), _inbound_cases()
    suite = unittest.TestSuite([matrix(f"test_{row}") for row in ROWS]
                               + [resend(f"test_{row}") for row in RESEND_ROWS]
                               + [inbound(f"test_{row}") for row in INBOUND_ROWS])
    runner = unittest.TextTestRunner(stream=open(os.devnull, "w"), resultclass=_Result,
                                     verbosity=0)
    result = runner.run(suite)
    print(f"plugin sha256 {ARTIFACT_SHA256} PLUGIN_API {PLUGIN_API}")
    for name, verdict, detail in result.rows:
        print(f"{verdict} {name}")
        if detail:
            print("    " + detail.strip().splitlines()[-1])
    passed = sum(1 for _n, v, _d in result.rows if v == "PASS")
    total = len(ROWS) + len(RESEND_ROWS) + len(INBOUND_ROWS)
    print(f"{passed}/{total} rows PASS")
    return 0 if passed == total == len(result.rows) else 1


if __name__ == "__main__":
    # Run as a script from the repository root: the package is beside it.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    sys.exit(main())
