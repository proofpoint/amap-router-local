"""The no-resign resend workflow (`router/peerresend.py`), driven through the
real drain under a registry and a hop, with a delegation activated."""
from __future__ import annotations

import dataclasses
import unittest
import json
import os
from unittest import mock

from router import config as config_mod
from router import exposure, hoplink, inflight, peerlane, peerresend
from router.tests import peer_standin as si
from router.tests.helpers import keyed_for_poll, write_request
from router.tests.test_classify import STAMP, T1, T2
from router.tests.test_generations import LIDS
from router.tests.test_hoplink_senders import _Senders
from router.tests.test_peerlane import KEY_ID, NOW, PEER_KEY_ID, _seed

TRUSTED = f"carol@{T1}"


class _Resend(_Senders):

    def setUp(self):
        super().setUp()
        peerlane.forget_all()
        self.addCleanup(peerlane.forget_all)
        keys = self.tmp / "keys"
        keys.mkdir(mode=0o700)
        seed = _seed(b"rl")
        path = keys / "seed"
        path.write_bytes(seed)
        os.chmod(path, 0o400)
        self.signer = si.Plugin(si.namespace(calls=[], sign_fails=[False], verify_fails=[False]))
        dconf = config_mod.DelegationConfig(
            partition_verified="probe-evidence-1", signing_key_path=str(path),
            signing_key_id=KEY_ID, signing_public_key=si.public_key(seed).hex(),
            runtimes=(config_mod.DelegationRuntime(
                name="host-a", runtime=f"amap.router@{T1}", domains=(T1,),
                keys=({"key_id": PEER_KEY_ID, "public_key": si.public_key(_seed(b"peer")).hex()},)),),
            crypto_backend="pyca", openssl_path=None, forbidden_roots=(str(self.state_dir),))
        self.cfg = dataclasses.replace(self.cfg, delegation=dconf,
                                       trusted_fleet_hosts=(T1, T2), fleet_hosts=(T1, T2))
        peerlane.install(self.cfg, peerlane.activate(self.cfg, self.signer, now=NOW))
        # The peer store and its clock: the receive journal (a received
        # Result) is readable only while the clock is trusted.
        from router import peerjournal
        peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=())
        p = mock.patch.object(exposure, "assess", return_value=STAMP)
        p.start()
        self.addCleanup(p.stop)

    def send(self, req_id="00000001"):
        write_request(self.cfg, "alpha", req_id, to=[TRUSTED], body_text="do the thing")
        return self.drain()


class PreservationTests(_Resend):
    """The original is preserved, committed, before the handed marker, as the
    record handed over, and its time is never compared."""

    def copy(self):
        root = peerresend.sent_root(self.state_dir, LIDS["alpha"])
        dirs = sorted(root.iterdir()) if root.is_dir() else []
        self.assertEqual(len(dirs), 1, dirs)
        return dirs[0]

    def test_the_copy_is_committed_before_the_marker_and_before_the_transport(self):
        seen = {}
        real_write = inflight.atomic_write

        def write(path, *a, **k):
            if str(path).endswith(inflight.HANDED_SUFFIX):
                root = peerresend.sent_root(self.state_dir, LIDS["alpha"])
                seen.setdefault("at_marker", any(peerresend.committed(d) for d in root.iterdir())
                                if root.is_dir() else False)
            return real_write(path, *a, **k)
        from router.tests.test_inflight import FakeTransport
        real_req = FakeTransport.write_request

        def request(port, n, data):
            root = peerresend.sent_root(self.state_dir, LIDS["alpha"])
            seen.setdefault("at_transport", any(peerresend.committed(d) for d in root.iterdir())
                            if root.is_dir() else False)
            return real_req(port, n, data)
        with mock.patch.object(inflight, "atomic_write", write), \
                mock.patch.object(FakeTransport, "write_request", request):
            k, _ = self.send()
        self.assertEqual(seen, {"at_marker": True, "at_transport": True})

    def test_the_copy_is_the_record_as_handed(self):
        k, _ = self.send()
        d = self.copy()
        rec = inflight.read_record(k, "alpha", "00000001")
        self.assertEqual((d / peerresend.RECORD).read_bytes(), peerresend._canonical(rec))
        origin = json.loads((d / peerresend.ORIGIN).read_text())
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        self.assertEqual({k2: origin[k2] for k2 in ("id", "logical_id", "generation",
                                                    "transport_req_id", "req_id")},
                         {"id": rec["peer"]["id"], "logical_id": lid, "generation": gen,
                          "transport_req_id": "00000001", "req_id": "00000001"})
        self.assertEqual(d.name, rec["peer"]["id"])

    def test_a_crash_before_commit_is_never_read_and_is_rewritten(self):
        real = peerresend._link_once

        def crash(path, *a, **k):
            if path.name == peerresend.COMMIT:
                raise OSError("crash before COMMIT")
            return real(path, *a, **k)
        with mock.patch.object(peerresend, "_link_once", crash):
            k, _ = self.send()
        d = self.copy()
        self.assertFalse(peerresend.committed(d))
        self.assertEqual(self.plugin.ports[-1].writes, [], "nothing handed without its copy")
        self.assertEqual(peerresend.find(k, d.name), [], "an uncommitted copy is never read")
        k, _ = self.drain()
        self.assertTrue(peerresend.committed(self.copy()))
        self.assertEqual(self.plugin.ports[-1].writes, ["00000001"])

    def test_a_crash_after_commit_keeps_the_first_preserved_time(self):
        real = inflight.atomic_write

        def crash(path, *a, **k):
            if str(path).endswith(inflight.HANDED_SUFFIX):
                raise OSError("crash after COMMIT, before the marker")
            return real(path, *a, **k)
        with mock.patch.object(inflight, "atomic_write", crash):
            self.send()
        first = json.loads((self.copy() / peerresend.ORIGIN).read_text())["preserved_ts"]
        later = NOW.replace(hour=13)
        from router import clock as clock_mod
        with mock.patch.object(clock_mod, "now", return_value=later):
            k, _ = self.drain()
        self.assertEqual(self.plugin.ports[-1].writes, ["00000001"], "accepted, handed over")
        self.assertEqual(json.loads((self.copy() / peerresend.ORIGIN).read_text())["preserved_ts"],
                         first)

    def test_a_different_committed_copy_holds_and_nothing_is_handed(self):
        real = inflight.atomic_write

        def crash(path, *a, **k):
            if str(path).endswith(inflight.HANDED_SUFFIX):
                raise OSError("crash after COMMIT")
            return real(path, *a, **k)
        with mock.patch.object(inflight, "atomic_write", crash):
            self.send()
        d = self.copy()
        rec = json.loads((d / peerresend.RECORD).read_text())
        rec["written_ts"] = "2000-01-01T00:00:00Z"
        os.chmod(d / peerresend.RECORD, 0o600)
        (d / peerresend.RECORD).write_bytes(peerresend._canonical(rec))
        k, _ = self.drain()
        self.assertEqual(self.plugin.ports[-1].writes, [], "a conflict holds")
        self.assertFalse(inflight.handed_path(k, "alpha", "00000001").exists())
        self.assertEqual(json.loads((d / peerresend.RECORD).read_text())["written_ts"],
                         "2000-01-01T00:00:00Z", "never silently replaced")

    def test_a_staging_failure_holds_named_and_nothing_is_handed(self):
        import errno
        real = peerresend.atomic_write

        def full(path, *a, **k):
            if path.name == peerresend.RECORD:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real(path, *a, **k)
        with mock.patch.object(peerresend, "atomic_write", full):
            k, _ = self.send()
        self.assertEqual(self.plugin.ports[-1].writes, [])
        self.assertFalse(inflight.handed_path(k, "alpha", "00000001").exists())
        key = (str(k.state_dir), "alpha", config_mod.gen_key(k, "alpha"))
        self.assertEqual((hoplink.RETRIES.get(key) or {}).get("status"),
                         inflight.PRESERVATION_FAILED)


class _Retransmit(_Resend):

    def unknown(self):
        """A signed task handed over, then settled queued_for_human /
        delivery_unknown: trigger 1. Returns (keyed cfg, peer id)."""
        k, _ = self.send()
        self.plugin.ports[-1].send("00000001", outcome="queued_for_human",
                                   reason_code="delivery_unknown")
        k, _ = self.drain()
        root = peerresend.sent_root(self.state_dir, LIDS["alpha"])
        [d] = list(root.iterdir())
        return k, d.name

    def now(self):
        from router import clock as clock_mod
        return clock_mod.now()

    def retransmit(self, k, peer_id, **kw):
        return peerresend.operator_retransmit(k, peer_id, now=self.now(),
                                              evidence=kw.pop("evidence", "ticket 1"), **kw)


class RetransmitFlowTests(_Retransmit):

    def test_trigger_1_hands_the_original_bytes_under_a_new_n_and_settles_apart(self):
        k, pid = self.unknown()
        port = self.plugin.ports[-1]
        original = json.loads(port.archived["00000001"])
        agent_result = (k.instances["alpha"].outbox_root / "results" / "00000001.json").read_bytes()
        out = self.retransmit(k, pid)
        n = out["n"]
        self.assertNotEqual(n, "00000001")
        k, _ = self.drain()
        self.assertIn(n, port.pending, "handed over under the new n")
        sent = json.loads(port.pending[n])
        self.assertEqual(sent["request"]["req_id"], n, "the downstream sees an ordinary n")
        self.assertNotIn(b"rtx.", port.pending[n], "the record's own name never leaves")
        self.assertEqual(sent["envelope"]["peer"], original["envelope"]["peer"], "never re-signed")
        self.assertEqual(sent["envelope"]["from_address"], original["envelope"]["from_address"])
        self.assertEqual(sent["request"]["draft"], original["request"]["draft"])
        port.send(n, outcome="accepted", reason_code="allowlisted")
        k, _ = self.drain()
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        path = d / peerresend.RETRANSMITS / f"{gen}-{n}.json"
        self.assertTrue(path.is_file(), "settled as itself")
        self.assertEqual(sorted(p.name for p in (k.instances["alpha"].outbox_root / "results")
                                .iterdir()), ["00000001.json"], "no Result for the retransmit")
        doc = json.loads(path.read_text())
        self.assertEqual((doc["outcome"], doc["n"]), ("accepted", n))
        self.assertEqual((k.instances["alpha"].outbox_root / "results" / "00000001.json").read_bytes(),
                         agent_result, "the agent's Result is never replaced")
        self.assertFalse((d / peerresend.CLAIM).exists(), "the claim goes last")
        self.assertIsNone(inflight.read_record(k, "alpha", peerresend.rtx_name(n)))


class RefusalTests(_Retransmit):
    """Every refusal names its code and writes nothing: no claim, no audit
    line, no transport id, no record."""

    def snapshot(self, k, pid):
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        from router import peerjournal
        audit = self.state_dir / peerjournal.REPLAY_DIR / peerjournal.OPERATOR_AUDIT
        return ((d / peerresend.CLAIM).exists(),
                audit.read_bytes() if audit.exists() else b"",
                inflight.counter_path(k, "alpha").read_bytes(),
                sorted(inflight.list_records(k, "alpha")))

    def refused(self, code, k, pid, **kw):
        before = self.snapshot(k, pid)
        now = kw.pop("now", None)
        try:
            peerresend.operator_retransmit(k, pid, now=now or self.now(),
                                           evidence=kw.pop("evidence", "ticket 1"), **kw)
        except peerresend.Refused as e:
            self.assertEqual(e.code, code, e.detail)
        else:
            self.fail(f"not refused; expected {code}")
        self.assertEqual(self.snapshot(k, pid), before, "nothing written")

    def test_evidence_is_required(self):
        k, pid = self.unknown()
        self.refused("evidence_required", k, pid, evidence="  ")

    def test_an_id_with_no_committed_copy_is_not_preserved(self):
        k, pid = self.unknown()
        self.refused("not_preserved", k, pid[:-1] + ("A" if pid[-1] != "A" else "B"))

    def test_a_second_retransmit_while_one_is_claimed_is_pending(self):
        k, pid = self.unknown()
        self.retransmit(k, pid)
        self.refused("retransmit_pending", k, pid)

    def test_a_rotated_signing_key_refuses(self):
        k, pid = self.unknown()
        k = dataclasses.replace(k, delegation=dataclasses.replace(k.delegation,
                                                                  signing_key_id="rl-key-2"))
        self.refused("key_rotated", k, pid)

    def test_one_second_past_the_window_refuses_and_inside_it_does_not(self):
        k, pid = self.unknown()
        copy = peerresend.load(peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid))
        end = peerresend.window_end(k, copy["statement"])
        import datetime
        self.refused("outside_window", k, pid, now=end + datetime.timedelta(seconds=1))
        try:
            out = peerresend.operator_retransmit(k, pid, now=end, evidence="ticket 1")
        except peerresend.Refused as e:
            self.fail(f"refused at the window's last second: {e.code}")
        self.assertIn("claimed", out["result"])

    def test_a_received_control_notice_answers_it(self):
        k, pid = self.unknown()
        from router import peerledger
        p = peerledger.notified_path(self.state_dir, LIDS["alpha"], pid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"{}")
        self.refused("answered", k, pid)

    def test_an_accepted_original_needs_allow_pending_and_staleness(self):
        k, _ = self.send()
        port = self.plugin.ports[-1]
        port.send("00000001", outcome="accepted", reason_code="allowlisted")
        k, _ = self.drain()
        pid = next(peerresend.sent_root(self.state_dir, LIDS["alpha"]).iterdir()).name
        import datetime
        self.refused("not_yet_stale", k, pid, allow_pending=True)
        later = self.now() + datetime.timedelta(seconds=inflight.STALE_AFTER_S + 1)
        self.refused("not_eligible", k, pid, now=later)

    def test_a_rejected_original_is_not_eligible(self):
        k, _ = self.send()
        self.plugin.ports[-1].send("00000001", outcome="rejected", reason_code="recipient_refused")
        k, _ = self.drain()
        pid = next(peerresend.sent_root(self.state_dir, LIDS["alpha"]).iterdir()).name
        self.refused("not_eligible", k, pid)

    def test_a_changed_sender_policy_refuses(self):
        k, pid = self.unknown()
        from router import outbound
        with mock.patch.object(outbound, "_recheck_peer",
                               lambda cfg, name, rec, refuse, **kw: refuse("task_denied")):
            self.refused("policy_changed", k, pid)


class CancellationTests(_Retransmit):
    """Before its FIRST hand-over a retransmit re-runs every dynamic refusal;
    a failure is a terminal cancellation: nothing handed, settled
    cancelled/<code>, both audit lines, the claim removed last."""

    def acts(self):
        from router import peerjournal
        audit = self.state_dir / peerjournal.REPLAY_DIR / peerjournal.OPERATOR_AUDIT
        return [json.loads(line) for line in audit.read_text().splitlines()] \
            if audit.exists() else []

    def cancelled(self, k, pid, n, code):
        port = self.plugin.ports[-1]
        self.assertNotIn(n, port.pending)
        self.assertNotIn(n, port.writes)
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        path = d / peerresend.RETRANSMITS / f"{gen}-{n}.json"
        self.assertTrue(path.is_file(), "settled in this pass")
        doc = json.loads(path.read_text())
        self.assertEqual((doc["outcome"], doc["reason_code"]), (peerresend.CANCELLED, code))
        settled = [a for a in self.acts() if a.get("act") == peerresend.SETTLED_ACT]
        self.assertEqual([(a["id"], a["n"], a["outcome"], a["reason_code"]) for a in settled],
                         [(pid, n, peerresend.CANCELLED, code)])
        self.assertFalse((d / peerresend.CLAIM).exists())

    def test_the_window_closing_before_the_first_hand_over_cancels_it(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        copy = peerresend.load(peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid))
        import datetime
        late = peerresend.window_end(k, copy["statement"]) + datetime.timedelta(seconds=1)
        from router import clock as clock_mod
        with mock.patch.object(clock_mod, "now", return_value=late):
            k, _ = self.drain()
        self.cancelled(k, pid, n, "outside_window")

    def test_an_answer_arriving_before_the_first_hand_over_cancels_it(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        from router import peerledger
        p = peerledger.notified_path(self.state_dir, LIDS["alpha"], pid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"{}")
        k, _ = self.drain()
        self.cancelled(k, pid, n, "answered")

    def test_a_key_rotated_before_the_first_hand_over_cancels_it(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        from router import peerlane
        active = peerlane.active(self.cfg)
        with mock.patch.object(type(active), "key_id", new_callable=mock.PropertyMock,
                               return_value="rl-key-2"):
            k, _ = self.drain()
        self.cancelled(k, pid, n, "key_rotated")

    def test_recovery_after_a_crash_before_the_record_runs_the_gate(self):
        k, pid = self.unknown()
        with mock.patch.object(peerresend, "begin_record", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.retransmit(k, pid)
        claim = json.loads((peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
                            / peerresend.CLAIM).read_text())
        p = __import__("router.peerledger", fromlist=["x"]).notified_path(
            self.state_dir, LIDS["alpha"], pid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"{}")
        real_begin = inflight.begin_reserved
        begun = []

        def spy(cfg, name, rid, *a, **kw):
            begun.append(rid)
            return real_begin(cfg, name, rid, *a, **kw)
        with mock.patch.object(inflight, "begin_reserved", spy):
            k, _ = self.drain()
        self.assertEqual(begun, [], "the gate runs before any record is begun")
        self.cancelled(k, pid, claim["n"], "answered")

    def test_once_handed_nothing_cancels_it(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        k, _ = self.drain()
        port = self.plugin.ports[-1]
        self.assertIn(n, port.pending)
        from router import peerledger
        p = peerledger.notified_path(self.state_dir, LIDS["alpha"], pid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"{}")
        k, _ = self.drain()
        self.assertIn(n, port.pending, "a handed retransmit is never withdrawn")
        self.assertIsNotNone(inflight.read_record(k, "alpha", peerresend.rtx_name(n)))


class NeverResignTests(_Retransmit):
    """No resend re-signs: statically and at runtime."""

    SIX = ("sign_statement", "sign_control", "build_statement", "mint_peer_id",
           "message_id", "write_issued")

    def test_the_module_references_none_of_the_six(self):
        import ast
        tree = ast.parse(open(peerresend.__file__, encoding="utf-8").read())
        used = sorted({n.attr for n in ast.walk(tree)
                       if isinstance(n, ast.Attribute) and n.attr in self.SIX}
                      | {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id in self.SIX})
        self.assertEqual(used, [])

    def test_a_full_retransmit_with_the_six_raising_hands_the_preserved_header(self):
        k, pid = self.unknown()
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        preserved = json.loads((d / peerresend.RECORD).read_text())["peer"]
        patches = [mock.patch.object(peerlane, f, side_effect=AssertionError(f"{f} called"))
                   for f in self.SIX]
        for p in patches:
            p.start()
        try:
            n = self.retransmit(k, pid)["n"]
            k, _ = self.drain()
            port = self.plugin.ports[-1]
            sent = json.loads(port.pending[n])["envelope"]["peer"]
            port.send(n, outcome="accepted", reason_code="allowlisted")
            k, _ = self.drain()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(sent["statement_header"], preserved["statement_header"])
        self.assertEqual(sent["message_id"], preserved["message_id"])
        self.assertFalse((d / peerresend.CLAIM).exists(), "the whole workflow ran")


class RecoveryTests(_Retransmit):
    """A crash at each step: one hand-over, one settlement, each audit line
    exactly once, its inputs (by, evidence) read from the claim verbatim."""

    def acts(self, act):
        from router import peerjournal
        audit = self.state_dir / peerjournal.REPLAY_DIR / peerjournal.OPERATOR_AUDIT
        return [json.loads(line) for line in audit.read_text().splitlines()
                if json.loads(line).get("act") == act] if audit.exists() else []

    def run_through(self, k, pid, n):
        port = self.plugin.ports[-1]
        for _ in range(3):
            k, _ = self.drain()
            if n in port.pending:
                port.send(n, outcome="accepted", reason_code="allowlisted")
        for _ in range(2):
            k, _ = self.drain()
        return k

    def check_once(self, k, pid, n):
        port = self.plugin.ports[-1]
        self.assertEqual(port.writes.count(n), 1, "one hand-over")
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        self.assertEqual(sorted(p.name for p in (d / peerresend.RETRANSMITS).iterdir()),
                         [f"{gen}-{n}.json"], "one settlement")
        req = self.acts(peerresend.REQUESTED)
        done = self.acts(peerresend.SETTLED_ACT)
        self.assertEqual([(a["id"], a["n"]) for a in req], [(pid, n)])
        self.assertEqual([(a["id"], a["n"], a["outcome"]) for a in done], [(pid, n, "accepted")])
        self.assertEqual(req[0]["evidence"], "ticket 1: verbatim")
        self.assertEqual(done[0]["by"], req[0]["by"])
        self.assertFalse((d / peerresend.CLAIM).exists())

    def crash_in(self, target, attr, when=lambda *a, **k: True):
        real = getattr(target, attr)
        state = {"done": False}

        def f(*a, **k):
            if not state["done"] and when(*a, **k):
                state["done"] = True
                raise RuntimeError(f"crash in {attr}")
            return real(*a, **k)
        return mock.patch.object(target, attr, f)

    def verb_crashing(self, k, pid, target, attr, when=lambda *a, **k: True):
        with self.crash_in(target, attr, when):
            try:
                out = self.retransmit(k, pid, evidence="ticket 1: verbatim")
                return out["n"]
            except RuntimeError:
                pass
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        return json.loads((d / peerresend.CLAIM).read_text())["n"]

    def test_a_crash_after_the_claim_before_the_requested_line(self):
        k, pid = self.unknown()
        n = self.verb_crashing(k, pid, peerresend, "_audit")
        self.assertEqual(self.acts(peerresend.REQUESTED), [])
        k = self.run_through(k, pid, n)
        self.check_once(k, pid, n)

    def test_a_crash_after_the_requested_line_before_the_record(self):
        k, pid = self.unknown()
        n = self.verb_crashing(k, pid, peerresend, "begin_record")
        k = self.run_through(k, pid, n)
        self.check_once(k, pid, n)

    def test_a_crash_at_the_hand_over(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid, evidence="ticket 1: verbatim")["n"]
        with self.crash_in(inflight, "advance"):
            try:
                self.drain()
            except RuntimeError:
                pass
        k = self.run_through(k, pid, n)
        self.check_once(k, pid, n)

    def test_a_crash_after_the_settlement_before_the_settled_line(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid, evidence="ticket 1: verbatim")["n"]
        k, _ = self.drain()
        self.plugin.ports[-1].send(n, outcome="accepted", reason_code="allowlisted")
        with self.crash_in(peerresend, "_audit",
                           lambda cfg, act, *a, **kw: act == peerresend.SETTLED_ACT):
            try:
                self.drain()
            except RuntimeError:
                pass
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        self.assertTrue((d / peerresend.CLAIM).exists(), "the claim outlives the missing line")
        k = self.run_through(k, pid, n)
        self.check_once(k, pid, n)

    def test_a_crash_after_the_settled_line_before_the_claim_goes(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid, evidence="ticket 1: verbatim")["n"]
        k, _ = self.drain()
        self.plugin.ports[-1].send(n, outcome="accepted", reason_code="allowlisted")
        with self.crash_in(peerresend.os, "unlink",
                           lambda path, *a, **kw: str(path).endswith(peerresend.CLAIM)):
            try:
                self.drain()
            except RuntimeError:
                pass
        k = self.run_through(k, pid, n)
        self.check_once(k, pid, n)


class OneResultWriterTests(_Retransmit):

    def test_the_original_settling_after_a_retransmit_writes_its_own_result_once(self):
        self.send()
        k, _ = self.drain()                       # the pass that finds the marker
        port = self.plugin.ports[-1]
        import datetime
        pid = next(peerresend.sent_root(self.state_dir, LIDS["alpha"]).iterdir()).name
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        handed = json.loads((d / peerresend.HANDED).read_text())["handed_ts"]
        from router.util import parse_utc_ts
        later = parse_utc_ts(handed) + datetime.timedelta(seconds=inflight.STALE_AFTER_S + 1)
        n = peerresend.operator_retransmit(k, pid, now=later, evidence="t",
                                           allow_pending=True)["n"]
        from router import clock as clock_mod
        with mock.patch.object(clock_mod, "now", return_value=later):
            k, _ = self.drain()
            port.send(n, outcome="accepted", reason_code="allowlisted")
            k, _ = self.drain()
            results = k.instances["alpha"].outbox_root / "results"
            result = results / "00000001.json"
            self.assertEqual(sorted(p.name for p in results.iterdir()) if results.is_dir() else [],
                             [], "a retransmit never writes an agent Result")
            lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
            self.assertTrue((d / peerresend.RETRANSMITS / f"{gen}-{n}.json").is_file(),
                            "settled as itself")
            port.send("00000001", outcome="accepted", reason_code="allowlisted")
            k, _ = self.drain()
        self.assertEqual(json.loads(result.read_text())["outcome"], "accepted")
        self.assertTrue((d / peerresend.SETTLED).is_file())


class HandedTimeTests(_Retransmit):

    def test_handed_is_linked_by_the_pass_that_finds_the_marker(self):
        real = peerresend.note_handed
        with mock.patch.object(peerresend, "note_handed", return_value=False):
            k, _ = self.send()
        d = next(peerresend.sent_root(self.state_dir, LIDS["alpha"]).iterdir())
        self.assertFalse((d / peerresend.HANDED).exists(), "never before a pass finds the marker")
        k, _ = self.drain()
        self.assertTrue((d / peerresend.HANDED).is_file())
        self.assertTrue(callable(real))


class ShowTests(_Retransmit):

    def test_show_names_the_copy_and_each_action(self):
        k, pid = self.unknown()
        out = peerresend.show(k, pid, now=self.now())
        self.assertEqual(out["id"], pid)
        self.assertEqual(out["preserved"]["transport_req_id"], "00000001")
        self.assertEqual(out["settled"]["reason_code"], "delivery_unknown")
        self.assertNotIn("body_text", json.dumps(out), "never the body")
        self.assertIsNone(out["claim"])

    def test_show_is_read_only(self):
        k, pid = self.unknown()
        def tree():
            return sorted((str(p), p.stat().st_mtime_ns) for p in self.state_dir.rglob("*")
                          if p.is_file())
        before = tree()
        peerresend.show(k, pid, now=self.now())
        self.assertEqual(tree(), before)


class PruneTests(_Retransmit):

    def test_the_sweep_is_on_by_default(self):
        [f] = [f for f in dataclasses.fields(config_mod.RouterConfig) if f.name == "peer_sent_prune"]
        self.assertIs(f.default, True)
        self.assertIs(self.cfg.peer_sent_prune, True, "a loaded config without the key")

    def test_a_settled_unclaimed_copy_past_retention_is_pruned_and_one_inside_is_kept(self):
        k, pid = self.unknown()
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        copy = peerresend.load(d)
        end = peerresend.window_end(k, copy["statement"])
        self.assertEqual(peerresend.sweep(k, "alpha", end + peerresend.PRUNE_GRACE), 0)
        self.assertTrue(d.is_dir())
        import datetime
        self.assertEqual(peerresend.sweep(
            k, "alpha", end + peerresend.PRUNE_GRACE + datetime.timedelta(seconds=1)), 1)
        self.assertFalse(d.exists())

    def test_a_claimed_copy_is_never_pruned(self):
        k, pid = self.unknown()
        self.retransmit(k, pid)
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        import datetime
        far = self.now() + datetime.timedelta(days=60)
        self.assertEqual(peerresend.sweep(k, "alpha", far), 0)
        self.assertTrue(d.is_dir())

    def test_with_the_sweep_off_nothing_is_pruned(self):
        k, pid = self.unknown()
        k = dataclasses.replace(k, peer_sent_prune=False)
        import datetime
        far = self.now() + datetime.timedelta(days=60)
        self.assertEqual(peerresend.sweep(k, "alpha", far), 0)


class StaleFromHandedTests(_Retransmit):

    def test_trigger_2_is_measured_from_handed_never_from_preserved(self):
        import datetime
        from router import clock as clock_mod
        t0 = self.now()
        with mock.patch.object(peerresend, "note_handed", return_value=False):
            k, _ = self.send()
        # The hand-over is found 200 s after the preservation: inside the
        # window (P + F = 3900 s at the defaults), so trigger 2 is reachable.
        t1 = t0 + datetime.timedelta(seconds=200)
        with mock.patch.object(clock_mod, "now", return_value=t1):
            k, _ = self.drain()                   # the pass that finds the marker
        pid = next(peerresend.sent_root(self.state_dir, LIDS["alpha"]).iterdir()).name
        early = t1 + datetime.timedelta(seconds=inflight.STALE_AFTER_S - 1)
        try:
            peerresend.operator_retransmit(k, pid, now=early, evidence="t", allow_pending=True)
        except peerresend.Refused as e:
            self.assertEqual(e.code, "not_yet_stale")
        else:
            self.fail("stale already: measured from the preservation, not the hand-over")
        late = t1 + datetime.timedelta(seconds=inflight.STALE_AFTER_S + 1)
        out = peerresend.operator_retransmit(k, pid, now=late, evidence="t", allow_pending=True)
        self.assertIn("claimed", out["result"])


class FencedGenerationTests(_Retransmit):
    """A claim belongs to its generation: a generation fenced after the verb
    still settles and finishes its retransmit, by its own pass."""

    def fence(self):
        self.put(alpha={"binding_seq": 9})        # a rebind fences the current generation

    def test_a_handed_retransmit_settles_as_itself_in_its_fenced_generation(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        k, _ = self.drain()
        port = self.plugin.ports[-1]
        self.assertIn(n, port.pending)
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        self.fence()
        k, _ = self.drain()
        self.assertNotEqual(hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))[1], gen,
                            "fenced: a new generation is current")
        port.send(n, outcome="accepted", reason_code="allowlisted")
        k, _ = self.drain()
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        path = d / peerresend.RETRANSMITS / f"{gen}-{n}.json"
        self.assertTrue(path.is_file(), "settled as itself, in its own generation")
        self.assertEqual(json.loads(path.read_text())["outcome"], "accepted")
        self.assertFalse((d / peerresend.CLAIM).exists(), "finished by its generation's pass")

    def unhanded_then_fenced(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        lid, gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        self.fence()
        k, _ = self.drain()
        k, _ = self.drain()
        self.assertFalse(any(n in p.writes for p in self.plugin.ports), "never handed")
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        path = d / peerresend.RETRANSMITS / f"{gen}-{n}.json"
        self.assertTrue(path.is_file(), "settled as itself")
        doc = json.loads(path.read_text())
        self.assertFalse((d / peerresend.CLAIM).exists(), "finished by its generation's pass")
        return doc

    def test_an_unhanded_retransmit_in_a_fenced_retired_generation_settles_no_route(self):
        # The shared rule decides first: never a FIRST hand-over into a
        # retired tree (`inflight.advance`, rejected/no_route).
        doc = self.unhanded_then_fenced()
        self.assertEqual((doc["outcome"], doc["reason_code"]), ("rejected", "no_route"))

    def test_a_claim_never_begun_in_a_fenced_generation_is_cancelled(self):
        k, pid = self.unknown()
        with mock.patch.object(peerresend, "begin_record", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.retransmit(k, pid)
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        claim = json.loads((d / peerresend.CLAIM).read_text())
        self.fence()
        begun = []
        real = inflight.begin_reserved

        def spy(cfg, name, rid, *a, **kw):
            begun.append(rid)
            return real(cfg, name, rid, *a, **kw)
        with mock.patch.object(inflight, "begin_reserved", spy):
            k, _ = self.drain()
        self.assertEqual(begun, [], "never begun in a fenced generation")
        path = d / peerresend.RETRANSMITS / f"{claim['generation']}-{claim['n']}.json"
        self.assertTrue(path.is_file(), "settled by its generation's pass")
        doc = json.loads(path.read_text())
        self.assertEqual((doc["outcome"], doc["reason_code"]),
                         (peerresend.CANCELLED, "generation_unavailable"))
        self.assertFalse((d / peerresend.CLAIM).exists())


class StatusTests(_Retransmit):

    def test_the_drain_summary_reports_the_copies(self):
        k, pid = self.unknown()
        self.retransmit(k, pid)
        k, summary = self.drain()
        self.assertEqual({key: summary.get("peer_sent", {}).get(key) for key in
                          ("preserved", "settled", "in_flight", "claimed")},
                         {"preserved": 1, "settled": 1, "in_flight": 0, "claimed": 1}, summary)
        self.plugin.ports[-1].send(next(iter(self.plugin.ports[-1].pending)),
                                   outcome="accepted", reason_code="allowlisted")
        k, summary = self.drain()
        self.assertEqual(summary.get("peer_sent", {}).get("retransmit_accepted"), 1, summary)
        self.assertEqual(summary.get("peer_sent", {}).get("claimed"), 0)


class UpgradeTests(_Retransmit):

    def test_a_record_handed_before_preservation_is_preserved_on_its_next_pass(self):
        with mock.patch.object(peerresend, "preservable", return_value=False):
            k, _ = self.send()                    # the old layout: handed, no copy
        root = peerresend.sent_root(self.state_dir, LIDS["alpha"])
        self.assertFalse(root.is_dir() and any(root.iterdir()))
        self.assertEqual(self.plugin.ports[-1].writes, ["00000001"])
        k, _ = self.drain()
        dirs = list(root.iterdir()) if root.is_dir() else []
        self.assertEqual(len(dirs), 1, "preserved on its next pass")
        d = dirs[0]
        self.assertTrue(peerresend.committed(d))
        self.assertEqual((d / peerresend.RECORD).read_bytes(),
                         peerresend._canonical(inflight.read_record(k, "alpha", "00000001")))
        self.assertTrue((d / peerresend.HANDED).is_file())
        self.assertEqual(self.plugin.ports[-1].writes, ["00000001"], "never handed again")

    def test_one_cleaned_before_preservation_is_not_preserved(self):
        with mock.patch.object(peerresend, "preservable", return_value=False):
            k, _ = self.send()
            env = json.loads(self.plugin.ports[-1].pending["00000001"])["envelope"]
            self.plugin.ports[-1].send("00000001", outcome="queued_for_human",
                                       reason_code="delivery_unknown")
            k, _ = self.drain()
        self.assertIsNone(inflight.read_record(k, "alpha", "00000001"), "cleaned")
        stmt = env["peer"]["statement_header"]
        from router.tests import peer_standin as si2
        _kind, _k, statement, _sig = si2.check1([(peerlane.STATEMENT_FIELD, stmt)])
        pid = json.loads(statement)["id"]
        try:
            self.retransmit(k, pid)
        except peerresend.Refused as e:
            self.assertEqual(e.code, "not_preserved")
        else:
            self.fail("a cleaned original was retransmitted")


class UntrustedClockTests(_Retransmit):
    """While the peer clock is untrusted a received Result cannot be seen:
    the verb refuses, and a claimed retransmit is HELD, never handed and
    never cancelled, until it recovers."""

    def untrusted(self):
        from router import peerclock
        return mock.patch.object(peerclock, "read",
                                 side_effect=peerclock.ClockUntrusted("lost"))

    def test_the_verb_refuses_and_writes_nothing(self):
        k, pid = self.unknown()
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        counter = inflight.counter_path(k, "alpha").read_bytes()
        with self.untrusted():
            try:
                self.retransmit(k, pid)
            except peerresend.Refused as e:
                self.assertEqual(e.code, "clock_untrusted")
            else:
                self.fail("retransmitted under an untrusted clock")
        self.assertFalse((d / peerresend.CLAIM).exists())
        self.assertEqual(inflight.counter_path(k, "alpha").read_bytes(), counter)

    def test_a_claimed_retransmit_is_held_then_handed_once_the_clock_recovers(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        port = self.plugin.ports[-1]
        with self.untrusted():
            k, _ = self.drain()
            k, _ = self.drain()
        self.assertNotIn(n, port.writes, "held: never handed")
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        self.assertFalse((d / peerresend.RETRANSMITS).is_dir()
                         and any((d / peerresend.RETRANSMITS).iterdir()), "never cancelled")
        k, _ = self.drain()
        self.assertIn(n, port.writes, "handed once the clock recovers")

    def test_a_claim_never_begun_is_held_then_recovered(self):
        k, pid = self.unknown()
        with mock.patch.object(peerresend, "begin_record", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.retransmit(k, pid)
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        n = json.loads((d / peerresend.CLAIM).read_text())["n"]
        with self.untrusted():
            k, _ = self.drain()
        self.assertIsNone(inflight.read_record(k, "alpha", peerresend.rtx_name(n)))
        self.assertFalse((d / peerresend.RETRANSMITS).is_dir()
                         and any((d / peerresend.RETRANSMITS).iterdir()), "never cancelled")
        k, _ = self.drain()
        k, _ = self.drain()
        self.assertIn(n, self.plugin.ports[-1].writes)


class SignedResultAnswersTests(_Retransmit):

    def test_a_placed_statement_replying_to_it_answers_it(self):
        k, pid = self.unknown()
        from router import peerjournal
        rec = {"key": "r" * 22, "disposed": "placed"}
        with mock.patch.object(peerjournal, "all_records", return_value=[rec]), \
                mock.patch.object(peerjournal, "read_snapshot",
                                  return_value=json.dumps({"in_reply_to": pid}).encode()):
            try:
                self.retransmit(k, pid)
            except peerresend.Refused as e:
                self.assertEqual(e.code, "answered")
                self.assertIn("signed Result", e.detail)
            else:
                self.fail("retransmitted an answered task")


class FrontierTests(_Retransmit):
    """`rtx.<n>.json` passes `read_record`, so it holds the frontier while it
    lives and never blocks it."""

    def test_a_live_retransmit_record_holds_the_frontier_and_its_cleanup_releases_it(self):
        k, pid = self.unknown()
        n = self.retransmit(k, pid)["n"]
        write_request(self.cfg, "alpha", "00000002", to=["you@example.com"])
        k, _ = self.drain()
        self.assertEqual(inflight.settled_through(k, "alpha"), int(n) - 1,
                         "the live retransmit is the lowest live id")
        port = self.plugin.ports[-1]
        port.send(n, outcome="accepted", reason_code="allowlisted")
        k, _ = self.drain()
        self.assertGreaterEqual(inflight.settled_through(k, "alpha"), int(n),
                                "released once cleaned up")


class GenerationKeyingTests(_Retransmit):

    def test_a_rotation_reusing_n_keeps_two_distinct_settlements(self):
        d = None
        k, pid = self.unknown()
        n1 = self.retransmit(k, pid)["n"]
        k, _ = self.drain()
        port = self.plugin.ports[-1]
        port.send(n1, outcome="queued_for_human", reason_code="delivery_unknown")
        k, _ = self.drain()
        g1 = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))[1]
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        # The same n in another generation: a distinct settlement entry.
        rec = {"retransmit": {"id": pid}, "transport_req_id": n1}
        with mock.patch.object(peerresend, "_gen_of", return_value=(LIDS["alpha"], "f" * 32)):
            peerresend.settle_retransmit(k, "alpha", rec, {"outcome": "accepted",
                                                           "reason_code": "allowlisted"})
        self.assertEqual(sorted(p.name for p in (d / peerresend.RETRANSMITS).iterdir()),
                         sorted([f"{g1}-{n1}.json", f"{'f' * 32}-{n1}.json"]))


class CompleteAloneTests(_Retransmit):
    """The copy alone is enough: the original record and its snapshot are
    gone, and the retransmit hands the same request, attachments included,
    shaped as the design's hop request says."""

    def test_the_retransmit_from_the_copy_alone_carries_every_attachment(self):
        from router.tests import helpers as h
        blobs = [b"first attachment", b"second \x00 attachment"]
        descs = [h.attachment_descriptor(b, filename=f"a{i}.txt") for i, b in enumerate(blobs)]
        h.stage_outbound_sidecars(self.cfg, "alpha", "00000001", blobs)
        write_request(self.cfg, "alpha", "00000001", to=[TRUSTED], body_text="with files",
                      attachments=descs)
        k, _ = self.drain()
        port = self.plugin.ports[-1]
        original = json.loads(port.pending["00000001"])
        port.send("00000001", outcome="queued_for_human", reason_code="delivery_unknown")
        k, _ = self.drain()
        self.assertIsNone(inflight.read_record(k, "alpha", "00000001"), "the original is gone")
        self.assertFalse((config_mod.gen_state_dir(k, "alpha") / inflight.SNAPSHOT_DIR
                          / "00000001").exists(), "its snapshot is gone")
        pid = next(peerresend.sent_root(self.state_dir, LIDS["alpha"]).iterdir()).name
        try:
            n = self.retransmit(k, pid)["n"]
        except Exception as e:  # noqa: BLE001 -- a wrong outcome must FAIL
            self.fail(f"the copy alone could not be retransmitted: {type(e).__name__}: {e}")
        k, _ = self.drain()
        self.assertIn(n, port.pending, "handed over")
        sent = json.loads(port.pending[n])
        lid, _gen = hoplink.split_gen_key(config_mod.gen_key(k, "alpha"))
        self.assertEqual(sent["request"]["agent_id"], lid)
        self.assertEqual(sent["request"]["req_id"], n)
        self.assertEqual(sent["request"]["draft"], original["request"]["draft"])
        self.assertEqual(sent["envelope"]["peer"], original["envelope"]["peer"])
        self.assertEqual(sent["envelope"]["from_address"], original["envelope"]["from_address"])
        import base64
        def carried(doc):
            return [base64.b64decode(a) for a in (doc.get("envelope") or {}).get("attachments")
                    or doc.get("attachments") or []]
        self.assertEqual(carried(original), blobs, "the original carried both")
        self.assertEqual(carried(sent), blobs, "the retransmit carries both, in order")
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        self.assertEqual([(d / peerresend.ATTACHMENTS / str(i)).read_bytes() for i in range(2)],
                         blobs)


class PendingRowsTests(unittest.TestCase):
    """The real-downstream rows wait, PENDING by name, never skipped: each is
    named in the README's resend section until it runs."""

    PENDING = ("realre_check2_duplicate_silent", "realre_first_arrival_placed")

    def test_each_pending_row_is_named(self):
        from pathlib import Path
        text = (Path(peerresend.__file__).parent / "README.md").read_text(encoding="utf-8")
        section = text[text.index("### Resending a signed peer task"):]
        section = section[:section.index("\n## ")]
        self.assertIn("PENDING, by name", section)
        for row in self.PENDING:
            self.assertIn(f"`{row}`", section, row)


class NoActiveDelegationTests(_Retransmit):
    """An operator command is a fresh process: no delegation is activated in
    it. The verb and `show` work on the CONFIGURED key alone."""

    def test_the_verb_claims_with_no_delegation_installed(self):
        k, pid = self.unknown()
        peerlane.forget_all()
        try:
            out = self.retransmit(k, pid)
        except peerresend.Refused as e:
            self.fail(f"refused without an active delegation: {e.code}: {e.detail}")
        self.assertIn("claimed", out["result"])

    def test_show_reports_it_available_with_no_delegation_installed(self):
        k, pid = self.unknown()
        peerlane.forget_all()
        self.assertEqual(peerresend.show(k, pid, now=self.now())["actions"]["retransmit"],
                         "available")

    def test_show_names_a_changed_policy_like_the_verb(self):
        k, pid = self.unknown()
        from router import outbound
        with mock.patch.object(outbound, "_recheck_peer",
                               lambda cfg, name, rec, refuse, **kw: refuse("task_denied")):
            self.assertEqual(peerresend.show(k, pid, now=self.now())["actions"]["retransmit"],
                             "refused: policy_changed")


class UntrustedClockShowAndPruneTests(_Retransmit):

    def untrusted(self):
        from router import peerclock
        return mock.patch.object(peerclock, "read",
                                 side_effect=peerclock.ClockUntrusted("lost"))

    def test_show_never_says_not_answered_under_an_untrusted_clock(self):
        k, pid = self.unknown()
        with self.untrusted():
            out = peerresend.show(k, pid, now=self.now())
        self.assertEqual(out["answered"], "unknown (clock untrusted)")
        self.assertEqual(out["actions"]["retransmit"], "refused: clock_untrusted")

    def test_the_sweep_holds_under_an_untrusted_clock(self):
        k, pid = self.unknown()
        d = peerresend.copy_dir(self.state_dir, LIDS["alpha"], pid)
        import datetime
        far = self.now() + datetime.timedelta(days=60)
        with self.untrusted():
            self.assertEqual(peerresend.sweep(k, "alpha", far), 0)
        self.assertTrue(d.is_dir())
        self.assertEqual(peerresend.sweep(k, "alpha", far), 1, "pruned once trusted")
