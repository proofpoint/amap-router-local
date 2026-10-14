"""The candidate journal's evaluation (`peerjournal.evaluate`): one signed
candidate from take to `done`, every pre-reservation outcome, the holds,
and the reserved and decided rows of recovery, over a real journal, a real
decision key and bob's real peer tree. The codec is the stand-in
(`peer_standin`); the hooks are explicit stand-ins, as `test_peerbind` drives
checks 7 and 8."""
import base64
import dataclasses
import hashlib
import json
import shutil
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from router import config as config_mod
from router import deliver, peerbind, peerclock, peerjournal, peerlane
from router.tests import peer_standin as si
from router.tests.test_peerbind import FD, KEY_ID, STATEMENT_ID, T1, _Base, statement

NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
OWNER = "lid-bob"
SEED = hashlib.sha256(b"evaluate-peer-seed").digest()


def ok(*_a, **_k):
    return None


def hold(rec):
    """(reason, detail) of a record's hold, or None: compared, never subscripted."""
    h = rec.get("hold")
    return (h.get("reason"), h.get("detail")) if isinstance(h, dict) else None


def control(rec):
    c = rec.get("control")
    return c.get("outcome") if isinstance(c, dict) else None


def marker(state_dir, rec):
    if not rec.get("replay_ref"):
        return None
    rt, idk = rec["replay_ref"].split("/")
    m = peerjournal.done_marker(state_dir, rt, idk)
    return m and m["disposition"]


class Effects:
    def __init__(self):
        self.quarantined, self.removed, self.disposed = [], [], []

    def quarantine(self, record):
        self.quarantined.append((record["key"], record["state"], record["cause"]))

    def dispose(self, record):
        self.disposed.append(record["key"])

    def remove(self, record):
        self.removed.append(record["key"])


def hooks(**over):
    parts = dict(check8=ok, reply=lambda _p: peerjournal.Resolved(None), edge=ok, policy=ok,
                 control_receive=lambda *_a: peerjournal.Hold("hook_absent", "control_receive"))
    parts.update(over)
    return peerjournal.DecideHooks(**parts)


class _Eval(_Base):

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        peerjournal.init_store(self.state_dir, NOW - timedelta(hours=1), hop_root=None,
                               peer_roots=())
        peerbind.ensure_decision_key(self.state_dir)
        pub = si.public_key(SEED)
        table = si.load_key_table([{"domains": [T1], "runtime": f"amap.router@{T1}",
                                    "keys": [{"key_id": KEY_ID, "public_key": pub.hex()}]}])
        self.lane = peerlane.Delegation(
            config=self.dc, signer=None, verifier=si.Verifier([False]), codec=si.PeerCodec(),
            errors=types.MappingProxyType({"CodecError": si.CodecError,
                                           "KeyConfigError": si.KeyConfigError,
                                           "BackendError": si.BackendError,
                                           "ConfigError": si.ConfigError}),
            key_table=table, reasons=si.REASONS, key_config_reasons=si.KEY_CONFIG_REASONS)
        self.effects = Effects()
        self.n = 0

    # -- candidates -------------------------------------------------------

    def raw(self, *, signed=True, body="Please run the suite.\n", **over):
        over.setdefault("ts", "2026-10-13T11:59:00Z")
        doc, st = statement(body_text=body, **over)
        fields = [["Message-ID", f"<{doc['id']}@{doc['from'].rsplit('@', 1)[1]}>"]]
        if signed:
            fields.append(["AMAP-Peer-Statement",
                           si.format_field(KEY_ID, st, si._sign(SEED, st))])
        view = {"fields": fields,
                "body": {"charset": "utf-8",
                         "octets_b64": base64.b64encode(body.encode()).decode()},
                "attachments": []}
        return json.dumps(view, sort_keys=True).encode()

    def take(self, raw, entry=None):
        self.n += 1
        key, _ = peerjournal.take(self.state_dir, OWNER, intake="candidates", gen="g1",
                                  entry_id=entry or f"e{self.n}", raw=raw, now=NOW)
        return key

    def ctx(self, *, now=NOW, hk=None, view=None, retired=None, cfg=None):
        clock = peerclock.advance(self.state_dir, now)
        return peerjournal.Ctx(state_dir=self.state_dir, cfg=cfg or self.cfg, delegation=self.lane,
                               hooks=hk or hooks(), now=now, clock=clock,
                               view=view or (lambda raw: json.loads(raw)), effects=self.effects,
                               retired=retired or (lambda _r: False))

    def evaluate(self, key, **kw):
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        return peerjournal.evaluate(self.ctx(**kw), rec)

    def notices(self):
        d = self.cfg.instances["bob"].peer_root / "notices"
        return sorted(p.name for p in d.glob("notice-*.json")) if d.is_dir() else []

    def replay_files(self):
        root = self.state_dir / "peer-replay"
        return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()
                      and p.name != ".witness")


class PlacementTests(_Eval):

    def test_a_signed_candidate_is_placed_and_settled(self):
        key = self.take(self.raw())
        rec = self.evaluate(key)
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"))
        self.assertEqual(len(self.notices()), 1)
        self.assertEqual(marker(self.state_dir, rec), "placed")
        rt, idk = rec["replay_ref"].split("/")
        self.assertEqual(self.effects.removed, [key])
        self.assertEqual(self.effects.quarantined, [])
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])
        notice = json.loads((self.cfg.instances["bob"].peer_root / "notices"
                             / self.notices()[0]).read_text())
        res = json.loads((self.state_dir / "peer-replay" / rt / f"{idk}.json").read_text())
        self.assertEqual(self.notices()[0], f"notice-{res['notice_id']}.json",
                         "the notice is placed under the reservation's notice_id")
        self.assertEqual(notice["message"]["id"], STATEMENT_ID)

    def test_an_exact_replay_is_dropped_with_no_notice_and_no_replay_mutation(self):
        self.evaluate(self.take(self.raw()))
        before = self.replay_files()
        rec = self.evaluate(self.take(self.raw()))
        self.assertEqual((rec["state"], rec["disposed"], rec["cause"]), ("done", "dropped",
                                                                        "duplicate"))
        self.assertIsNone(rec["control"])
        self.assertEqual(self.replay_files(), before)
        self.assertEqual(len(self.notices()), 1)

    def test_a_check12_collision_is_dropped_with_control_and_the_prior_untouched(self):
        first = self.evaluate(self.take(self.raw()))
        rt, idk = first["replay_ref"].split("/")
        prior = (self.state_dir / "peer-replay" / rt / f"{idk}.json").read_bytes()
        rec = self.evaluate(self.take(self.raw(subject="A different statement, same id")))
        self.assertEqual((rec["disposed"], rec["cause"]), ("dropped", "duplicate"))
        self.assertEqual(control(rec), "dropped")
        self.assertEqual((self.state_dir / "peer-replay" / rt / f"{idk}.json").read_bytes(), prior)
        self.assertEqual(len(self.notices()), 1)


class PreReservationOutcomeTests(_Eval):

    def test_no_statement_is_mail_without_control(self):
        rec = self.evaluate(self.take(self.raw(signed=False)))
        self.assertEqual((rec["disposed"], rec["cause"], rec["control"]),
                         ("mail", "no_statement", None))
        self.assertEqual([q[1:] for q in self.effects.quarantined], [("mail", "no_statement")])
        self.assertEqual(self.replay_files(), [])

    def test_outside_the_window_is_demoted_with_control(self):
        rec = self.evaluate(self.take(self.raw(ts="2026-10-13T09:00:00Z")))
        self.assertEqual((rec["disposed"], rec["cause"]), ("demoted", "ts_window"))
        self.assertEqual(control(rec), "demoted")
        self.assertEqual(self.replay_files(), [], "nothing reserved")
        self.assertEqual(self.notices(), [])
        self.assertEqual([q[1:] for q in self.effects.quarantined], [("demoted", "ts_window")])

    def test_a_codec_demotion_carries_control_only_for_statement_value(self):
        def bad_sig(raw):
            v = json.loads(raw)
            v["fields"][1][1] = v["fields"][1][1][:-4] + "AAAA"
            return v
        rec = self.evaluate(self.take(self.raw()), view=bad_sig)
        self.assertEqual((rec["disposed"], rec["cause"], rec["control"]),
                         ("demoted", "signature", None))

    def test_admission_closed_holds_and_reserves_nothing(self):
        clock = peerclock.read(self.state_dir)
        peerclock.close(self.state_dir, clock, "test")
        key = self.take(self.raw())
        rec = self.evaluate(key)
        self.assertEqual((rec["state"], hold(rec)), ("pending", ("admission_closed", None)))
        self.assertEqual(self.replay_files(), [])
        self.assertEqual(self.effects.removed, [])

    def test_a_misrouted_statement_is_dropped_with_control(self):
        rec = self.evaluate(self.take(self.raw(to=f"nobody@{FD}")))
        self.assertEqual((rec["disposed"], rec["cause"]), ("dropped", "misrouted"))
        self.assertEqual(control(rec), "dropped")


class ViewTests(_Eval):

    def refusing(self, reason):
        def view(_raw):
            raise si.CodecError("codec", reason)
        return view

    def test_over_cap_is_terminal_mail(self):
        rec = self.evaluate(self.take(self.raw()), view=self.refusing("over_cap"))
        self.assertEqual((rec["disposed"], rec["cause"], rec["control"]),
                         ("mail", "candidate_over_cap", None))

    def test_a_refused_view_holds_until_the_operator_acts(self):
        key = self.take(self.raw())
        rec = self.evaluate(key, view=self.refusing("candidate_json"))
        self.assertEqual((rec["state"], hold(rec)),
                         ("pending", ("candidate_view_refused", "candidate_json")))
        rec = self.evaluate(key)          # the view would now succeed: still held
        self.assertEqual(hold(rec), ("candidate_view_refused", "candidate_json"))

    def test_an_unavailable_view_holds_and_clears_by_itself(self):
        def unavailable(_raw):
            raise peerjournal.ViewUnavailable()
        key = self.take(self.raw())
        self.assertEqual(hold(self.evaluate(key, view=unavailable)),
                         ("candidate_view_unavailable", None))
        self.assertEqual(self.evaluate(key)["disposed"], "placed")

    def test_a_view_error_that_is_not_the_codecs_propagates(self):
        def bug(_raw):
            raise ValueError("candidate_json")
        with self.assertRaises(ValueError):
            self.evaluate(self.take(self.raw()), view=bug)


class HookTests(_Eval):

    def test_absent_hooks_hold_with_nothing_reserved_or_written(self):
        key = self.take(self.raw())
        rec = self.evaluate(key, hk=peerjournal.absent_hooks())
        self.assertEqual((rec["state"], rec["hold"]),
                         ("pending", {"reason": "hook_absent", "detail": "check8",
                                      "since": "2026-10-13T12:00:00Z"}))
        self.assertEqual(self.replay_files(), [])
        self.assertEqual((self.effects.quarantined, self.effects.removed), ([], []))

    def test_a_post_reservation_hold_is_decided_later_without_rechecking(self):
        """Reserved, held on the reply hook for longer than P + F; the hook
        arrives and row 2 decides it: never demoted by check 7."""
        key = self.take(self.raw())
        rec = self.evaluate(key, hk=hooks(reply=lambda _p: peerjournal.Hold("hook_absent", "reply")))
        self.assertEqual((rec["state"], hold(rec)), ("reserved", ("hook_absent", "reply")))
        later = NOW + timedelta(seconds=3600 + 300 + 60)
        rec = self.evaluate(key, now=later)
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"))

    def test_a_policy_refusal_is_refused_with_its_code_and_control(self):
        rec = self.evaluate(self.take(self.raw()),
                       hk=hooks(policy=lambda _p, _h: peerjournal.Refuse("policy", "not_today")))
        self.assertEqual((rec["disposed"], rec["cause"], rec["policy_code"]),
                         ("refused", "policy", "not_today"))
        self.assertEqual((rec.get("control") or {}).get("policy_code"), "not_today")
        self.assertEqual(self.notices(), [])
        self.assertEqual(marker(self.state_dir, rec), "refused")

    def test_hooks_are_required(self):
        with self.assertRaises(TypeError):
            peerjournal.DecideHooks(check8=ok, reply=ok, edge=ok, policy=ok)


class RecoveryTests(_Eval):

    def test_a_crash_after_the_reservation_is_decided_now_not_rechecked(self):
        """The reservation is durable but record.json still says pending;
        the router is down past ts + P + F. Row 2 decides it."""
        key = self.take(self.raw())
        real = peerjournal.write_record

        def crash(state_dir, record):
            if record["state"] == "reserved":
                raise SystemExit("crash")
            return real(state_dir, record)

        with mock.patch.object(peerjournal, "write_record", crash):
            with self.assertRaises(SystemExit):
                self.evaluate(key)
        self.assertEqual(peerjournal.read_record(self.state_dir, OWNER, key)["state"], "pending")
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])
        rec = self.evaluate(key, now=NOW + timedelta(hours=2))
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"))
        self.assertEqual(len([f for f in self.replay_files() if f.endswith(".json")]), 1,
                         "never reserved twice")

    def test_a_crash_after_the_decision_resumes_it_without_deciding_again(self):
        key = self.take(self.raw())
        real = peerjournal.transition

        def crash(state_dir, record, to, now, **f):
            if to == "decided":
                raise SystemExit("crash")
            return real(state_dir, record, to, now, **f)

        with mock.patch.object(peerjournal, "transition", crash):
            with self.assertRaises(SystemExit):
                self.evaluate(key)

        def never(*_a):
            raise AssertionError("a decided record is never decided again")
        rec = self.evaluate(key, hk=hooks(reply=never, edge=never, policy=never),
                       now=NOW + timedelta(hours=2))
        self.assertEqual((rec["disposed"], rec["decided_sticky"]), ("placed", True))

    def test_recipient_held_is_a_transient_retry(self):
        key = self.take(self.raw())
        with mock.patch.object(deliver, "deliver_signed_peer",
                               side_effect=deliver.RecipientHeld("bob", "held")):
            rec = self.evaluate(key)
        self.assertEqual((rec["state"], hold(rec), (rec.get("retry") or {}).get("retry")),
                         ("decided", None, "recipient_held"))
        rec = self.evaluate(key)
        self.assertEqual(rec["disposed"], "placed")

    def test_decided_sticky_without_a_decision_holds(self):
        key = self.take(self.raw())
        rec = self.evaluate(key, hk=hooks(reply=lambda _p: peerjournal.Hold("hook_absent", "reply")))
        rec = peerjournal.write_record(self.state_dir, dict(rec, decided_sticky=True))
        rec = self.evaluate(key)
        self.assertEqual((rec["state"], hold(rec)),
                         ("reserved", ("recovery_corrupt", "decision_missing")))

    def test_a_runtime_changed_while_down_holds_visibly(self):
        key = self.take(self.raw())
        self.evaluate(key, hk=hooks(reply=lambda _p: peerjournal.Hold("hook_absent", "reply")))
        rt = self.dc.runtimes[0]
        renamed = dataclasses.replace(self.dc, runtimes=(dataclasses.replace(
            rt, runtime=f"amap.router@{rt.domains[1]}"),))
        rec = self.evaluate(key, cfg=dataclasses.replace(self.cfg, delegation=renamed))
        self.assertEqual((rec["state"], hold(rec)), ("reserved", ("key_runtime_changed", None)))
        self.assertEqual(self.evaluate(key)["disposed"], "placed", "restoring the config clears it")


class TransitionTests(_Eval):

    def test_a_decided_record_never_returns_to_pending_or_reserved(self):
        key = self.take(self.raw())
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        rec = peerjournal.write_record(self.state_dir, dict(rec, state="decided"))
        for to in ("pending", "reserved", "demoted", "dropped", "mail"):
            with self.subTest(to=to):
                with self.assertRaises(peerjournal.TransitionRefused):
                    peerjournal.transition(self.state_dir, rec, to, NOW)

    def test_done_is_terminal(self):
        rec = self.evaluate(self.take(self.raw()))
        for to in peerjournal.TRANSITIONS:
            with self.subTest(to=to):
                with self.assertRaises(peerjournal.TransitionRefused):
                    peerjournal.transition(self.state_dir, rec, to, NOW)


class SupersedeTests(_Eval):
    """decided -> refused only through supersede.json, never for a placed
    message; the operator's key-loss drop."""

    def decided(self):
        key = self.take(self.raw())
        with mock.patch.object(deliver, "deliver_signed_peer",
                               side_effect=deliver.RecipientHeld("bob", "held")):
            rec = self.evaluate(key)
        self.assertEqual(rec["state"], "decided")
        return key

    def sup_path(self, key):
        return self.state_dir / OWNER / "peer-candidates" / key / "supersede.json"

    def lose_the_key(self):
        (self.state_dir / peerbind.DECISION_KEY_FILE).unlink()
        peerbind.ensure_decision_key(self.state_dir)

    def placed_then_crash_before_done(self):
        key = self.take(self.raw())
        real = peerjournal.transition

        def crash(state_dir, record, to, now, **f):
            if to == "done":
                raise SystemExit("crash")
            return real(state_dir, record, to, now, **f)

        with mock.patch.object(peerjournal, "transition", crash):
            with self.assertRaises(SystemExit):
                self.evaluate(key)
        self.assertEqual(len(self.notices()), 1)
        return key

    def test_the_generation_fence_supersedes_a_decided_record(self):
        key = self.decided()
        rec = self.evaluate(key, retired=lambda _r: True)
        self.assertEqual((rec["disposed"], rec["cause"], rec["policy_code"], control(rec)),
                         ("refused", "policy", "generation_retired", "refused"))
        self.assertTrue(self.sup_path(key).is_file())
        self.assertEqual(marker(self.state_dir, rec), "refused")
        self.assertEqual(self.notices(), [])

    def test_a_placed_message_is_never_superseded(self):
        key = self.placed_then_crash_before_done()
        rec = self.evaluate(key, retired=lambda _r: True)
        self.assertEqual((rec["disposed"], control(rec)), ("placed", None))
        self.assertFalse(self.sup_path(key).exists())
        self.assertEqual(marker(self.state_dir, rec), "placed")

    def test_the_key_loss_drop_refuses_an_unrecoverable_decision(self):
        key = self.decided()
        self.lose_the_key()
        rec = self.evaluate(key)
        self.assertEqual((rec["state"], hold(rec)), ("decided", ("recovery_corrupt", "mac")))
        rec = peerjournal.drop(self.ctx(), rec, by="uid=0(root)")
        self.assertEqual((rec["disposed"], rec["policy_code"], control(rec)),
                         ("refused", "decision_unrecoverable", "refused"))
        self.assertTrue(self.sup_path(key).is_file())
        self.assertEqual(self.notices(), [])

    def test_the_key_loss_drop_of_a_placed_message_is_done_placed(self):
        key = self.placed_then_crash_before_done()
        self.lose_the_key()
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        rec = peerjournal.drop(self.ctx(), rec, by="uid=0(root)")
        self.assertEqual((rec["disposed"], control(rec)), ("placed", None))
        self.assertFalse(self.sup_path(key).exists())

    def test_the_drop_refuses_a_decision_that_verifies(self):
        key = self.decided()
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        with self.assertRaises(peerjournal.DropRefused):
            peerjournal.drop(self.ctx(), rec, by="uid=0(root)")
        self.assertFalse(self.sup_path(key).exists())
        self.assertEqual(peerjournal.read_record(self.state_dir, OWNER, key)["state"], "decided")

    def test_the_drop_exits_a_runtime_changed_hold(self):
        key = self.take(self.raw())
        self.evaluate(key, hk=hooks(reply=lambda _p: peerjournal.Hold("hook_absent", "reply")))
        rt = self.dc.runtimes[0]
        cfg = dataclasses.replace(self.cfg, delegation=dataclasses.replace(
            self.dc, runtimes=(dataclasses.replace(rt, runtime=f"amap.router@{rt.domains[1]}"),)))
        rec = self.evaluate(key, cfg=cfg)
        rec = peerjournal.drop(self.ctx(cfg=cfg), rec, by="uid=0(root)")
        self.assertEqual((rec["disposed"], rec["policy_code"]), ("refused", "decision_unrecoverable"))

    def test_a_crash_after_the_supersession_never_resurrects_decided(self):
        key = self.decided()
        real = peerjournal.transition

        def crash(state_dir, record, to, now, **f):
            if to == "refused":
                raise SystemExit("crash")
            return real(state_dir, record, to, now, **f)

        with mock.patch.object(peerjournal, "transition", crash):
            with self.assertRaises(SystemExit):
                self.evaluate(key, retired=lambda _r: True)
        self.assertTrue(self.sup_path(key).is_file())
        for _ in range(3):
            rec = self.evaluate(key)              # the fence no longer applies; still refused
        self.assertEqual((rec["disposed"], rec["policy_code"]), ("refused", "generation_retired"))
        self.assertEqual(self.notices(), [])

    def test_an_invalid_supersession_holds_and_never_places(self):
        key = self.decided()
        dec = (self.state_dir / OWNER / "peer-candidates" / key / "decision.json").read_bytes()
        rec = peerbind.supersede_record(self.state_dir, record_id=key, decision=dec,
                                        policy_code="generation_retired", by="router",
                                        at="2026-10-13T12:00:00Z")
        doc = json.loads(rec)
        doc["mac"] = "0" * 64
        p = self.sup_path(key)
        p.write_bytes(json.dumps(doc, sort_keys=True).encode())
        p.chmod(0o600)
        rec = self.evaluate(key)
        self.assertEqual((rec["state"], hold(rec)), ("decided", ("recovery_corrupt",
                                                                 "supersede_invalid")))
        self.assertEqual(self.notices(), [])

    def test_a_decision_mac_never_verifies_a_supersession(self):
        key = self.decided()
        dec = (self.state_dir / OWNER / "peer-candidates" / key / "decision.json").read_bytes()
        raw = peerbind.supersede_record(self.state_dir, record_id=key, decision=dec,
                                        policy_code="generation_retired", by="router",
                                        at="2026-10-13T12:00:00Z")
        doc = json.loads(raw)
        members = {k: v for k, v in doc.items() if k != "mac"}
        k = peerbind._decision_key(self.state_dir)
        crossed = json.dumps(dict(members, mac=peerbind._record_mac(members, k))).encode()
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.parse_supersede(crossed, k, record_id=key, decision_sha256=None)
        self.assertEqual((cm.exception.reason, cm.exception.detail), ("supersede_invalid", "mac"))
        self.assertEqual(peerbind.parse_supersede(raw, k, record_id=key,
                                                  decision_sha256=None)["policy_code"],
                         "generation_retired")


class OperatorCliTests(_Eval):
    """The operator verbs through `router.__main__`, under the drain lock."""

    def cli(self, *argv, cfg=None):
        import contextlib
        import io
        from router import __main__ as cli
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "load", lambda path: cfg or self.cfg), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--config", "unused", *argv])
        last = out.getvalue().strip().splitlines()
        return code, (json.loads(last[-1]) if last else None), err.getvalue()

    def decided(self):
        return SupersedeTests.decided(self)

    def test_init_is_refused_over_an_existing_store(self):
        code, _out, err = self.cli("peer-store", "init", "--never-admitted")
        self.assertEqual(code, 1)
        self.assertIn("peer artefacts already exist", err)

    def test_init_needs_the_attestation(self):
        with self.assertRaises(SystemExit):
            self.cli("peer-store", "init")

    def test_init_on_a_fresh_state_dir_opens_admission(self):
        fresh = self.tmp / "fresh-state"
        fresh.mkdir()
        cfg = dataclasses.replace(self.cfg, state_dir=fresh)
        code, out, _err = self.cli("peer-store", "init", "--never-admitted", cfg=cfg)
        self.assertEqual((code, out["admission"]), (0, "open"))
        log = fresh / "peer-replay" / "operator.audit.jsonl"
        audit = log.read_text() if log.is_file() else ""
        self.assertIn("peer-store init --never-admitted", audit)

    def test_declare_restored_closes_and_a_bound_reopens(self):
        self.take(self.raw())
        code, out, _ = self.cli("peer-store", "declare-restored", "--evidence", "restored ticket 9")
        self.assertEqual((code, out), (0, {"admission": "closed"}))
        code, _, err = self.cli("peer-bound", "--at", "2026-10-13T11:00:00Z", "--evidence", "log")
        self.assertEqual(code, 1)
        self.assertIn("record.json", err, "the refusal names the observed source")
        code, out, err = self.cli("peer-bound", "--at", "2026-10-13T12:30:00Z", "--evidence",
                                  "hub log line 4411")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out["admission"], "open")
        self.assertEqual(peerjournal.startup(self.state_dir, datetime.now(timezone.utc))["why"],
                         None)

    def test_peer_bound_rebuilds_the_bookkeeping_after_a_clock_rollback(self):
        older = (self.state_dir / peerclock.CLOCK_FILE).read_bytes()
        self.evaluate(self.take(self.raw()))
        (self.state_dir / peerclock.CLOCK_FILE).write_bytes(older)
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["why"], "clock_behind_stores")
        # Placement's audit lines carry the real wall clock: B is above them.
        b = datetime.now(timezone.utc) + timedelta(minutes=5)
        code, out, err = self.cli("peer-bound", "--at", b.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                  "--evidence", "hub log line 4411")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out["admission"], "open")
        rep = peerjournal.startup(self.state_dir, b + timedelta(hours=2))
        self.assertEqual((rep["admission"], rep["why"], rep["problems"]), ("open", None, []))

    def test_drop_through_the_cli(self):
        key = self.decided()
        code, _, err = self.cli("peer-decision", "drop", key)
        self.assertEqual(code, 1)
        self.assertIn("the decision verifies", err)
        SupersedeTests.lose_the_key(self)
        code, out, _ = self.cli("peer-decision", "drop", key)
        self.assertEqual((code, out), (0, {"result": "refused: decision_unrecoverable, "
                                                     "control pending"}))

    def test_restore_key_needs_the_original(self):
        key = self.decided()
        original = (self.state_dir / peerbind.DECISION_KEY_FILE).read_bytes()
        code, _, err = self.cli("peer-decision", "restore-key", "--from",
                                str(self.state_dir / peerbind.DECISION_KEY_FILE))
        self.assertEqual(code, 1)
        self.assertIn("not lost", err)
        SupersedeTests.lose_the_key(self)
        wrong = self.tmp / "wrong.key"
        wrong.write_bytes(b"w" * 32)
        code, _, err = self.cli("peer-decision", "restore-key", "--from", str(wrong))
        self.assertEqual(code, 1)
        self.assertIn("not the original", err)
        good = self.tmp / "orig.key"
        good.write_bytes(original)
        code, out, _ = self.cli("peer-decision", "restore-key", "--from", str(good))
        self.assertEqual((code, out), (0, {"restored": True, "decisions": 1}))
        self.assertEqual(self.evaluate(key)["disposed"], "placed")

    def test_the_verbs_refuse_while_the_router_runs(self):
        from router.lock import acquire
        lk = acquire(self.state_dir)
        self.addCleanup(lk.release)
        code, _, err = self.cli("peer-store", "declare-restored", "--evidence", "x")
        self.assertEqual(code, 1)
        self.assertIn("refusing to run 'peer-store declare-restored'", err)
        self.assertEqual(peerclock.read(self.state_dir).admission, "open")


class RetentionTests(_Eval):
    """The sweeper prunes only the contiguous settled prefix, past each
    record's horizon; off unless configured."""

    def placed(self):
        key = self.take(self.raw())
        rec = self.evaluate(key)
        self.assertEqual(rec["disposed"], "placed")
        return rec

    def past(self, rec):
        rt, idk = rec["replay_ref"].split("/")
        ts = json.loads((self.state_dir / "peer-replay" / rt / f"{idk}.json").read_text())["ts"]
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) \
            + timedelta(seconds=3600 + 300 + 1)

    def test_off_prunes_nothing(self):
        rec = self.placed()
        peerjournal.advance_frontier(self.state_dir)
        peerclock.advance(self.state_dir, self.past(rec))
        self.assertEqual(peerjournal.sweep(self.state_dir, self.past(rec), enabled=False),
                         {"pruned": 0})
        self.assertTrue(peerjournal.record_dir(self.state_dir, OWNER, rec["key"]).is_dir())

    def test_a_settled_record_is_pruned_only_past_its_horizon(self):
        rec = self.placed()
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), 1)
        horizon = self.past(rec)
        peerclock.advance(self.state_dir, horizon - timedelta(seconds=1))
        self.assertEqual(peerjournal.sweep(self.state_dir, horizon, enabled=True), {"pruned": 0})
        peerclock.advance(self.state_dir, horizon)
        self.assertEqual(peerjournal.sweep(self.state_dir, horizon, enabled=True), {"pruned": 1})
        self.assertFalse(peerjournal.record_dir(self.state_dir, OWNER, rec["key"]).exists())
        self.assertEqual(self.replay_files(), [], "reservation, marker and digest pruned together")
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_out_of_order_settlement_prunes_only_the_contiguous_prefix(self):
        held = self.take(self.raw(signed=True, subject="first"))
        self.evaluate(held, hk=hooks(reply=lambda _p: peerjournal.Hold("hook_absent", "reply")))
        doc_id = "qB2c3D4e5F6g7H8i9J0kLm"
        later = self.evaluate(self.take(self.raw(id=doc_id + "x", subject="second")))
        self.assertEqual(later["disposed"], "placed")
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), 0, "seq 1 is held")
        peerclock.advance(self.state_dir, self.past(later))
        self.assertEqual(peerjournal.sweep(self.state_dir, self.past(later), enabled=True),
                         {"pruned": 0})
        self.assertTrue(peerjournal.record_dir(self.state_dir, OWNER, later["key"]).is_dir())

    def test_a_record_without_a_reservation_keeps_its_presentation_horizon(self):
        rec = self.evaluate(self.take(self.raw(signed=False)))
        self.assertEqual(rec["disposed"], "mail")
        peerjournal.advance_frontier(self.state_dir)
        soon = NOW + timedelta(days=29)
        self.assertEqual(peerjournal.sweep(self.state_dir, soon, enabled=True), {"pruned": 0})
        later = NOW + timedelta(days=30, seconds=1)
        self.assertEqual(peerjournal.sweep(self.state_dir, later, enabled=True), {"pruned": 1})
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_the_frontier_never_decreases(self):
        self.placed()
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), 1)
        self.take(self.raw(subject="pending forever"))
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), 1)


GEN = "ab" * 16


class FakePort:
    def __init__(self, entries):
        self.entries = dict(entries)
        self.reads = []

    def list_entries(self, kind, *, limit, after=None):
        assert kind == "candidate"
        ids = sorted(i for i in self.entries if after is None or i > after)
        return ids[:limit], len(ids) > limit

    def read_entry(self, kind, entry_id):
        assert kind == "candidate"
        self.reads.append(entry_id)
        return self.entries[entry_id]


class FakeRemover:
    def __init__(self, port, fail=False, result=None):
        self.port, self.fail, self.result, self.calls = port, fail, result, []

    def remove_entry(self, kind, entry_id):
        self.calls.append((kind, entry_id))
        if self.fail:
            raise OSError(5, "io")
        if self.result is not None:
            return self.result
        return "removed" if self.port.entries.pop(entry_id, None) is not None else "absent"


class _Polling(_Eval):
    """A delegation with a candidate view, and one generation's poll."""

    def setUp(self):
        super().setUp()
        self.lane = dataclasses.replace(self.lane, candidate_view=lambda raw: json.loads(raw))

    def poll(self, port, remover="default", lane="default", limit=256, hk=None, now=NOW):
        rem = FakeRemover(port) if remover == "default" else remover
        return peerjournal.poll_generation(
            self.cfg, delegation=self.lane if lane == "default" else lane, hooks=hk or hooks(),
            clock=peerclock.advance(self.state_dir, now), now=now, logical_id=OWNER, gen=GEN,
            link="hub", reader=types.SimpleNamespace(port=port), remover=rem,
            retired=lambda _r: False, limit=limit)

    def key(self, entry):
        return peerjournal.record_key(intake="candidates", gen=GEN, owner=OWNER, entry_id=entry)



class PollTests(_Polling):

    def test_a_listed_candidate_is_taken_placed_and_removed(self):
        port = FakePort({"c1": self.raw()})
        got = self.poll(port)
        self.assertEqual((got.get("taken"), got.get("state_done"), got["removed"]), (1, 1, 1))
        self.assertEqual((port.entries, len(self.notices())), ({}, 1))
        self.assertEqual(self.poll(port), {"removed": 0, "remove_held": 0})

    def test_without_the_view_candidates_hold_and_stay(self):
        port = FakePort({"c1": self.raw()})
        got = self.poll(port, lane=dataclasses.replace(self.lane, candidate_view=None))
        self.assertEqual(got.get("held_candidate_view_unavailable"), 1)
        self.assertIn("c1", port.entries)
        self.assertEqual(self.poll(port).get("state_done"), 1)
        self.assertEqual(port.reads, ["c1"], "the bytes are read once, into the snapshot")

    def test_without_a_remover_a_done_entry_is_settled_again_never_retaken(self):
        port = FakePort({"c1": self.raw()})
        self.poll(port, remover=None)
        seq = peerjournal.read_meta(self.state_dir)["take_seq"]
        got = self.poll(port, remover=None)
        self.assertEqual((got.get("settled_again"), got["remove_held"]), (1, 1))
        self.assertEqual(peerjournal.read_meta(self.state_dir)["take_seq"], seq)
        self.assertEqual(len(self.notices()), 1)

    def test_a_failed_removal_is_retried_next_poll(self):
        port = FakePort({"c1": self.raw()})
        self.assertEqual(self.poll(port, remover=FakeRemover(port, fail=True))["remove_held"], 1)
        self.assertEqual(self.poll(port)["removed"], 1)
        self.assertEqual(port.entries, {})

    def test_a_removal_result_outside_the_vocabulary_is_not_success(self):
        port = FakePort({"c1": self.raw()})
        got = self.poll(port, remover=FakeRemover(port, result="pending"))
        self.assertEqual((got["removed"], got["remove_held"]), (0, 1))

    def test_a_demoted_candidate_is_quarantined_with_its_cause(self):
        port = FakePort({"c1": self.raw(ts="2026-10-13T09:00:00Z")})
        self.assertEqual(self.poll(port).get("state_done"), 1)
        from router import generations, quarantine
        qdir = generations.gen_dir(self.state_dir, OWNER, GEN) / quarantine.DIR_NAME
        items = [json.loads(p.read_text()) for p in qdir.glob("*.json")]
        self.assertEqual([(i["causes"], i["evidence"].get("peer_cause"),
                           i["evidence"].get("kind")) for i in items],
                         [(["cold_fleet_mail"], "ts_window", "candidate")])

    def test_the_cursor_passes_a_page_of_held_candidates(self):
        port = FakePort({"c1": self.raw(signed=True), "c2": self.raw(id="qB2c3D4e5F6g7H8i9J0kLmx",
                                                                       subject="two")})
        hold_c1 = hooks(check8=lambda p, _k: peerjournal.Hold("hook_absent", "check8")
                        if p["subject"] == "Run it" else None)
        self.poll(port, limit=1, hk=hold_c1)
        got = self.poll(port, limit=1, hk=hold_c1)
        self.assertEqual(got.get("state_done"), 1, "the second page reached c2")
        self.assertEqual(sorted(port.entries), ["c1"])


class PollGateTests(_Eval):

    def test_inbound_off_polls_nothing(self):
        """Everything else in place (a hop, an untrusted clock that a poll
        would report): inbound off returns before any of it."""
        cfg = dataclasses.replace(self.cfg, hop=types.SimpleNamespace())
        (self.state_dir / peerclock.CLOCK_FILE).unlink()
        self.assertEqual(peerjournal.poll(cfg, None, None, delegation=self.lane,
                                          hooks=hooks(), now=NOW), {})

    def test_an_untrusted_clock_takes_nothing(self):
        from router import config as config_mod
        cfg = dataclasses.replace(self.cfg, delegation=dataclasses.replace(self.dc, inbound=True),
                                  hop=types.SimpleNamespace())
        (self.state_dir / peerclock.CLOCK_FILE).unlink()
        self.assertEqual(peerjournal.poll(cfg, None, None, delegation=self.lane, hooks=hooks(),
                                          now=NOW), {"held": "clock_untrusted"})


HID = "0123456789abcdef0123456789abcdef"


class HostIntakeTests(_Eval):
    """A host-intake candidate is disposed of by a tombstone committed
    from frozen bytes before `done`; this router never removes the entry."""

    def setUp(self):
        super().setUp()
        from router import fsops as fsops_mod
        self.hop = self.tmp / "hop"
        for intake in (".unresolved", ".control"):
            (self.hop / ".disposed" / intake).mkdir(parents=True)
            (self.hop / intake).mkdir(parents=True)
        self.ops = fsops_mod.FsOps(hop_root=str(self.hop))
        self.addCleanup(self.ops.close)
        self.addCleanup(peerjournal._DISPOSED.clear)
        self.cfg = dataclasses.replace(self.cfg, hop=types.SimpleNamespace(root=str(self.hop)))
        self.lane = dataclasses.replace(self.lane, candidate_view=lambda raw: json.loads(raw))

    def entry(self, raw, ident=HID, intake=".unresolved"):
        d = self.hop / intake / ident
        d.mkdir()
        (d / "candidate.json").write_bytes(raw)
        return d

    def tomb(self, ident=HID, intake=".unresolved"):
        return self.hop / ".disposed" / intake / ident

    def poll(self, intake=".unresolved", hk=None, now=NOW):
        return peerjournal.poll_host(self.cfg, self.ops, delegation=self.lane, hooks=hk or hooks(),
                                     clock=peerclock.advance(self.state_dir, now), now=now,
                                     intake=intake)

    def rec(self, ident=HID, intake=".unresolved"):
        key = peerjournal.record_key(intake=intake, gen="", owner="_host", entry_id=ident)
        return peerjournal.read_record(self.state_dir, "_host", key)

    def test_a_placed_host_candidate_is_tombstoned_never_removed(self):
        raw = self.raw()
        d = self.entry(raw)
        got = self.poll()
        self.assertEqual((got.get("taken"), got.get("state_done"), got["tombstones_committed"]),
                         (1, 1, 1))
        rec = self.rec()
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"))
        self.assertEqual(self.tomb().read_bytes(), rec["tombstone"].encode("ascii"),
                         "the committed bytes are exactly the frozen ones")
        doc = json.loads(self.tomb().read_bytes())
        self.assertEqual((doc["disposition"], doc["candidate_sha256"]),
                         ("placed", hashlib.sha256(raw).hexdigest()))
        from router import quarantine
        self.assertTrue(quarantine.tombstone_valid(self.hop / ".disposed" / ".unresolved",
                                                   ".unresolved", HID, doc["candidate_sha256"]))
        self.assertTrue((d / "candidate.json").is_file(), "the downstream runtime removes it")
        self.assertEqual(len(self.notices()), 1)

    def test_the_tombstone_precedes_done(self):
        self.entry(self.raw())
        real = peerjournal.transition

        def crash(state_dir, record, to, now, **f):
            if to == "done":
                raise SystemExit("crash")
            return real(state_dir, record, to, now, **f)

        with mock.patch.object(peerjournal, "transition", crash):
            with self.assertRaises(SystemExit):
                self.poll()
        self.assertTrue(self.tomb().is_file())
        self.assertEqual(self.rec()["state"], "decided")
        self.poll()
        self.assertEqual(self.rec()["state"], "done")
        self.assertEqual(len(self.notices()), 1)

    def test_a_demoted_host_candidate_is_tombstoned_without_a_quarantine_item(self):
        self.entry(self.raw(ts="2026-10-13T09:00:00Z"))
        self.poll()
        doc = json.loads(self.tomb().read_bytes())
        self.assertEqual((self.rec()["disposed"], doc["disposition"]), ("demoted", "demoted"))

    def test_a_record_without_its_frozen_tombstone_holds_visibly(self):
        self.entry(self.raw())
        with mock.patch.object(deliver, "deliver_signed_peer",
                               side_effect=deliver.RecipientHeld("bob", "held")):
            self.poll()
        rec = peerjournal.write_record(self.state_dir, dict(self.rec(), tombstone=None))
        self.poll()
        self.assertEqual((self.rec()["state"], hold(self.rec())),
                         ("decided", ("recovery_corrupt", "no frozen tombstone in the record")))
        self.assertFalse(self.tomb().exists())

    def test_a_crash_after_done_before_the_marker_is_repaired_at_startup(self):
        """The entry is gone (its tombstone was valid), so no poll lists it
        again: startup writes the marker."""
        d = self.entry(self.raw())
        with mock.patch.object(peerjournal, "mark_done", side_effect=SystemExit("crash")):
            with self.assertRaises(SystemExit):
                self.poll()
        rec = self.rec()
        self.assertEqual(rec["state"], "done")
        self.assertIsNone(marker(self.state_dir, rec))
        shutil.rmtree(d)
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((rep["markers_repaired"], marker(self.state_dir, rec)), (1, "placed"))
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["markers_repaired"], 0)

    def test_a_missing_marker_is_written_by_the_next_poll_while_listed(self):
        self.entry(self.raw())
        with mock.patch.object(peerjournal, "mark_done", side_effect=SystemExit("crash")):
            with self.assertRaises(SystemExit):
                self.poll()
        self.assertIsNone(marker(self.state_dir, self.rec()))
        self.assertEqual(self.poll().get("disposed_again"), 1)
        self.assertEqual(marker(self.state_dir, self.rec()), "placed")

    def test_an_entry_in_flight_is_not_taken(self):
        (self.hop / ".unresolved" / HID).mkdir()
        self.assertEqual(self.poll().get("in_flight"), 1)
        self.assertEqual(peerjournal.read_meta(self.state_dir)["take_seq"], 0)

    def test_the_tombstone_is_pruned_only_after_the_entry_is_gone(self):
        d = self.entry(self.raw())
        self.poll()
        self.assertEqual(self.poll()["tombstones_pruned"], 0, "the entry is still listed")
        self.assertTrue(self.tomb().is_file())
        shutil.rmtree(d)
        self.assertEqual(self.poll()["tombstones_pruned"], 1)
        self.assertFalse(self.tomb().exists())
        self.assertEqual(self.rec()["state"], "done")

    def test_the_sweep_keeps_a_host_record_while_its_tombstone_exists(self):
        d = self.entry(self.raw(signed=False))
        self.poll()
        peerjournal.advance_frontier(self.state_dir)
        later = NOW + timedelta(days=31)
        self.assertEqual(peerjournal.sweep(self.state_dir, later, enabled=True,
                                           hop_root=self.hop), {"pruned": 0})
        shutil.rmtree(d)
        self.poll(now=later)
        self.assertEqual(peerjournal.sweep(self.state_dir, later, enabled=True,
                                           hop_root=self.hop), {"pruned": 1})

    def test_no_disposed_directory_means_nothing_is_taken(self):
        shutil.rmtree(self.hop / ".disposed" / ".control")
        self.entry(self.raw(), intake=".control")
        with self.assertRaises(peerjournal.DisposedUnavailable):
            self.poll(intake=".control")
        self.assertEqual(peerjournal.read_meta(self.state_dir)["take_seq"], 0)

    def test_a_supersession_refreezes_the_tombstone(self):
        self.entry(self.raw())
        with mock.patch.object(deliver, "deliver_signed_peer",
                               side_effect=deliver.RecipientHeld("bob", "held")):
            self.poll()
        rec = self.rec()
        self.assertEqual(json.loads(rec["tombstone"])["disposition"], "placed")
        ctx = peerjournal.Ctx(state_dir=self.state_dir, cfg=self.cfg, delegation=self.lane,
                              hooks=hooks(), now=NOW, clock=peerclock.read(self.state_dir),
                              view=None, effects=peerjournal.HostEffects(self.ops, self.hop,
                                                                         ".unresolved"),
                              retired=lambda _r: True)
        out = peerjournal.supersede(ctx, rec, policy_code="generation_retired", by="router")
        self.assertEqual(out["disposed"], "refused")
        self.assertEqual(json.loads(self.tomb().read_bytes())["disposition"], "refused")


class CandidateQuarantineVerbTests(_Polling):
    """The operator exit: a candidate whose view can never be read is mailed by
    the operator, then quarantined (or tombstoned) and settled."""

    def refusing(self, raw):
        raise si.CodecError("parse", "candidate_json", "not_json")

    def cli(self, *argv):
        return OperatorCliTests.cli(self, *argv)

    def test_a_held_tree_candidate_is_mailed_quarantined_and_settled(self):
        port = FakePort({"c1": self.raw()})
        self.poll(port, lane=dataclasses.replace(self.lane, candidate_view=self.refusing))
        key = self.key("c1")
        self.assertEqual(hold(peerjournal.read_record(self.state_dir, OWNER, key)),
                         ("candidate_view_refused", "candidate_json"))
        code, out, err = self.cli("peer-candidate", "quarantine", key, "--evidence", "ticket 7")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("mail: candidate_view_refused", out["result"])
        got = self.poll(port)
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        self.assertEqual((rec["state"], rec["disposed"], rec["cause"]),
                         ("done", "mail", "candidate_view_refused"))
        self.assertEqual(got["removed"], 1)
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), 1)
        from router import generations, quarantine
        qdir = generations.gen_dir(self.state_dir, OWNER, GEN) / quarantine.DIR_NAME
        self.assertEqual([json.loads(p.read_text())["evidence"].get("peer_cause")
                          for p in qdir.glob("*.json")], ["candidate_view_refused"])

    def test_only_a_held_candidate_is_quarantined(self):
        port = FakePort({"c1": self.raw()})
        self.poll(port, hk=peerjournal.absent_hooks())
        code, _out, err = self.cli("peer-candidate", "quarantine", self.key("c1"), "--evidence",
                                   "x")
        self.assertEqual(code, 1)
        self.assertIn("only a pending candidate held on", err)

    def test_evidence_is_required(self):
        code, _out, err = self.cli("peer-candidate", "quarantine", "a" * 64, "--evidence", " ")
        self.assertEqual(code, 1)
        self.assertIn("evidence is required", err)


if __name__ == "__main__":
    unittest.main()
