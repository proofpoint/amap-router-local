"""Control notices out (`router/peercontrol.py`), through the runtime
capability, driven against the test-only stand-in (`runtime_standin`).

The capability's shape is provisional until the runtime identity unit
freezes; these witnesses pin the router's side of it: the gate (no factory
is called, nothing is written, without it), the lister's read-only use, the
mint rule, the attempt transaction with its crash points, the frozen signed
bytes, the request shape, coalescing, the rate bucket on H, suppression, and
the operator verbs."""
from __future__ import annotations

import ast
import base64
import dataclasses
import json
import os
import pathlib
import types
import unittest
from datetime import timedelta
from unittest import mock

import router
from router import config as config_mod
from router import inflight, peerclock, peercontrol, peerjournal
from router.tests import peer_standin as si
from router.tests import runtime_standin as rs
from router.tests import test_peerevaluate as tpe
from router.tests.helpers import ClockMixin
from router.tests.test_peerbind import FD, KEY_ID, STATEMENT_ID, T1

NOW = tpe.NOW
DEST = f"amap.router@{T1}"
ROUTER = pathlib.Path(router.__file__).parent


class _Control(ClockMixin, tpe._Eval):

    def setUp(self):
        super().setUp()
        self.install_clock(lambda: NOW)
        hop = types.SimpleNamespace(root=str(self.tmp / "hop"), peer_uid=os.getuid(),
                                    version_write=1, caps={})
        self.cfg = dataclasses.replace(self.cfg, hop=hop)
        self.signs = []
        signer = si.Signer("rl-key", b"\x01" * 32, [False])
        real_sign = signer.sign

        def sign(msg):
            self.signs.append(msg)
            return real_sign(msg)
        signer.sign = sign
        self.signing = types.SimpleNamespace(config=self.dc, key_id="rl-key",
                                             codec=si.PeerCodec(), signer=signer)
        self.tree = rs.Tree()
        self.runtime = rs.runtime(self.tree)
        from router import peerlane
        p = mock.patch.object(peerlane, "active", return_value=self.signing)
        p.start()
        self.addCleanup(p.stop)

    def refused(self, **over):
        """A statement refused after its reservation: a pending control."""
        key = self.take(self.raw(**over))
        rec = self.evaluate(key, hk=tpe.hooks(
            policy=lambda _p, _h: peerjournal.Refuse("policy", "not_today")))
        self.assertEqual(rec["control"]["sent"], False)
        return key

    def record(self, key):
        return peerjournal.read_record(self.state_dir, tpe.OWNER, key)

    def send(self, runtime="default", now=NOW):
        return peercontrol.send_pending(self.cfg, self.runtime if runtime == "default" else runtime,
                                        delegation=self.signing, now=now)

    def gen(self):
        return config_mod.runtime_generation(self.cfg)

    def port(self):
        return self.tree.senders[self.gen()]

    def handover(self, key):
        attempt = self.record(key)["control"].get("attempt") or {}
        n = attempt.get("n")
        pending = self.port().pending if self.tree.senders else {}
        self.assertIn(n, pending, "nothing was handed over")
        return n, json.loads(pending[n])


class PendingNoticeTests(_Control):

    def test_the_pending_notice_records_its_destination(self):
        rec = self.record(self.refused())
        self.assertEqual(rec["control"]["to"], DEST)
        self.assertEqual((rec["control"]["outcome"], rec["control"]["cause"],
                          rec["control"]["about"]), ("refused", "policy", STATEMENT_ID))


class GateTests(_Control):
    """Without the capability: nothing is attempted, written or called."""

    def test_no_capability_attempts_nothing_and_calls_no_factory(self):
        key = self.refused()
        before = self.record(key)
        off = types.SimpleNamespace(plugin=types.SimpleNamespace(
            optional_capabilities=frozenset(), namespace=self.runtime.plugin.namespace),
            fsops=object())
        got = self.send(runtime=off)
        self.assertEqual(got, {peercontrol.UNAVAILABLE: 1})
        self.assertEqual(self.record(key), before, "the record is unchanged")
        self.assertEqual(self.tree.calls, [], "no runtime factory was called")
        self.assertFalse((self.state_dir / config_mod.RUNTIME_NS).exists(),
                         "nothing was written for the runtime tree")

    def test_no_plugin_at_all_is_unavailable(self):
        self.refused()
        self.assertEqual(self.send(runtime=None), {peercontrol.UNAVAILABLE: 1})
        self.assertEqual(peercontrol.status_doc(self.cfg, None)["runtime_tree"], "unavailable")

    def test_the_verbs_refuse_without_the_capability(self):
        for fn, args in ((peercontrol.operator_adopt, ("a" * 32,)),
                         (peercontrol.operator_retire, ("a" * 32,)),
                         (peercontrol.operator_new, ())):
            with self.subTest(fn.__name__):
                with self.assertRaises(peercontrol.Unavailable) as cm:
                    fn(self.cfg, None, *args, now=NOW, evidence="x")
                self.assertEqual(cm.exception.reason, peercontrol.UNAVAILABLE)

    def test_no_production_module_reaches_the_runtime_tree_but_through_the_port(self):
        """No production module but fsops (which names the directory for its
        binding classification) mentions the `.runtime` tree, by its literal
        or by fsops's `RUNTIME_DIR` (a name, an attribute or an import), or
        calls a runtime factory by name outside transport's table."""
        bad = []
        for path in sorted(ROUTER.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
            for n in ast.walk(tree):
                if isinstance(n, ast.Constant) and n.value == ".runtime" \
                        and path.name != "fsops.py":
                    bad.append(f"{path.name}:{n.lineno}: the .runtime literal")
                if path.name != "fsops.py" and (
                        (isinstance(n, ast.Name) and n.id == "RUNTIME_DIR")
                        or (isinstance(n, ast.Attribute) and n.attr == "RUNTIME_DIR")
                        or (isinstance(n, ast.alias) and n.name == "RUNTIME_DIR")):
                    bad.append(f"{path.name}:{getattr(n, 'lineno', '?')}: fsops.RUNTIME_DIR")
                if isinstance(n, ast.Constant) and n.value in ("make_runtime_sender",
                                                               "make_runtime_lister") \
                        and path.name != "transport.py":
                    bad.append(f"{path.name}:{n.lineno}: a runtime factory named directly")
        self.assertEqual(bad, [])

    def test_no_production_module_imports_the_stand_in(self):
        for path in sorted(ROUTER.glob("*.py")):
            self.assertNotIn("runtime_standin", path.read_text(encoding="utf-8"), path.name)


class ListerTests(_Control):

    def test_the_lister_is_read_only_and_its_settings_closed(self):
        cap = peercontrol.capability(self.cfg, self.runtime)
        self.assertEqual(cap.generations(), [], "an absent tree lists empty")
        self.tree.gens.update({"a" * 32: "live", "b" * 32: "retired"})
        snapshot = dict(self.tree.gens)
        self.assertEqual(cap.generations(), [("a" * 32, "live"), ("b" * 32, "retired")])
        self.assertEqual(self.tree.gens, snapshot, "listing changed nothing")
        self.assertEqual([c for c in self.tree.calls if c[0] == "sender"], [],
                         "listing constructed no sender (no admission)")
        self.assertEqual({c[1] and tuple(sorted(c[1])) for c in self.tree.calls},
                         {("hop_root", "peer_uid")})

    def test_an_unreadable_generation_blocks_the_mint(self):
        self.refused()
        self.tree.gens["c" * 32] = "unreadable"
        self.assertEqual(self.send(), {peercontrol.UNAVAILABLE: 1})
        with self.assertRaises(config_mod.StateKeyUnresolved):
            self.gen()

    def test_a_live_generation_without_a_record_blocks_the_mint(self):
        self.refused()
        self.tree.gens["d" * 32] = "live"
        self.assertEqual(self.send(), {peercontrol.UNAVAILABLE: 1})

    def test_an_unknown_state_is_never_read_as_definite(self):
        cap = peercontrol.capability(self.cfg, self.runtime)
        self.tree.gens["e" * 32] = "maybe"
        self.assertEqual(cap.generations(), [("e" * 32, "unreadable")])


class AttemptTests(_Control):

    def test_a_pending_notice_is_signed_handed_over_and_settled(self):
        key = self.refused()
        got = self.send()
        self.assertEqual(sum(v for k, v in got.items() if k.startswith("attempt_")), 1, got)
        attempt = self.record(key)["control"]["attempt"]
        self.assertEqual(set(attempt), {"id", "at", "n", "gen", "ts", "statement_b64",
                                        "signature_b64", "header"})
        n, doc = self.handover(key)
        self.port().send(n)
        self.send()
        control = self.record(key)["control"]
        self.assertTrue(control["sent"])
        self.assertEqual(control["settled"]["outcome"], "accepted")
        self.assertEqual(len(self.signs), 1, "signed once")

    def test_the_request_shape(self):
        key = self.refused()
        self.send()
        n, doc = self.handover(key)
        env, req = doc["envelope"], doc["request"]
        self.assertEqual(env["kind"], "control")
        self.assertEqual(env["from_address"], f"amap.router@{FD}")
        self.assertEqual(req["agent_id"], "runtime")
        self.assertEqual(req["draft"]["to"], [DEST])
        self.assertEqual((req["draft"]["subject"], req["draft"]["body_text"]), ("", ""))
        # Zero body octets and nothing else: no content type or charset is
        # RL's to set (the downstream runtime composes them).
        self.assertEqual(set(req["draft"]), {"to", "subject", "body_text"})
        self.assertEqual(set(env), {"from_address", "hop_contract", "kind", "peer"})
        self.assertEqual(doc["attachments"], [])
        rid = self.record(key)["control"]["attempt"]["id"]
        flight = inflight.read_record(self.cfg, config_mod.RUNTIME_NS, rid) or {}
        self.assertEqual(flight.get("recipients"), [DEST], "exactly one recipient")
        peer = env["peer"]
        attempt = self.record(key)["control"]["attempt"]
        self.assertEqual(peer["message_id"], f"<{attempt['id']}@{FD}>")
        self.assertIsNone(peer["in_reply_to"])
        self.assertEqual(peer["references"], [])
        kind, _k, statement, _sig = si.check1([("AMAP-Peer-Control", peer["statement_header"])])
        st = json.loads(statement)
        self.assertEqual(kind, "control")
        self.assertEqual((st["to"], st["about"], st["outcome"], st["cause"], st["policy_code"],
                          st["from"]), (DEST, STATEMENT_ID, "refused", "policy", "not_today",
                                        f"amap.router@{FD}"))

    def test_the_statement_is_signed_at_the_attempt_not_the_intent(self):
        key = self.refused()
        rec = self.record(key)
        peerjournal.write_record(self.state_dir, dict(rec, control=dict(
            rec["control"], attempt={"id": "x" * 23, "at": "2026-10-13T01:00:00Z"})))
        self.send()
        attempt = self.record(key)["control"]["attempt"]
        self.assertEqual(attempt["ts"], "2026-10-13T12:00:00Z")
        self.assertEqual(json.loads(base64.b64decode(attempt["statement_b64"]))["ts"],
                         "2026-10-13T12:00:00Z")

    def test_a_crash_after_the_bytes_are_frozen_re_begins_them_unsigned(self):
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        frozen = self.record(key)["control"]["attempt"]
        self.assertEqual(len(self.signs), 1)
        self.send()
        self.assertEqual(self.record(key)["control"]["attempt"], frozen, "nothing re-signed")
        self.assertEqual(len(self.signs), 1)
        n, doc = self.handover(key)
        self.assertEqual(n, frozen["n"])
        self.assertEqual(doc["envelope"]["peer"]["statement_header"], frozen["header"])

    def frozen_then_record_lost(self):
        """A signed attempt frozen in generation A, a crash in begin_reserved
        (before the in-flight record and the sender's admission), then
        generation.json lost."""
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        attempt = self.record(key)["control"]["attempt"]
        (self.state_dir / config_mod.RUNTIME_NS / config_mod.RUNTIME_GENERATION_FILE).unlink()
        return key, attempt

    def audit(self):
        p = self.state_dir / peerjournal.REPLAY_DIR / peerjournal.OPERATOR_AUDIT
        return [json.loads(l) for l in p.read_text().splitlines()] if p.is_file() else []

    def test_a_never_admitted_generation_is_restored_and_no_other_is_minted(self):
        """The exact sequence over two passes, a second notice arriving: A
        (frozen, never admitted, its record lost) is restored, audited; the
        attempt is handed over under its n, signed once; B is never minted."""
        key, attempt = self.frozen_then_record_lost()
        second = self.refused(id="qSecond0123456789abcde")
        self.send()
        try:
            recorded = self.gen()
        except config_mod.StateKeyUnresolved:
            recorded = None
        self.assertEqual(recorded, attempt["gen"], "A restored, never another")
        self.assertEqual(list(self.tree.gens), [attempt["gen"]], "no B minted")
        n, doc = self.handover(key)
        self.assertEqual(n, attempt["n"])
        self.assertEqual(doc["envelope"]["peer"]["statement_header"], attempt["header"])
        self.assertEqual(self.record(second)["control"]["attempt"]["gen"], attempt["gen"])
        self.assertEqual(len(self.signs), 2, "the frozen attempt signed once, the second once")
        restores = [a for a in self.audit() if a.get("act") == peercontrol.RESTORE_VERB]
        self.assertEqual([(a.get("key"), a.get("generation")) for a in restores],
                         [(key, attempt["gen"])])

    def test_no_mint_while_any_attempt_is_frozen_elsewhere_whatever_the_order(self):
        """A fresh notice with a LOWER take_seq than the frozen attempt (its
        record lost): no B is minted. The guard reads the journal, so it
        holds even before the frozen record is visited."""
        fresh = self.refused(id="qFresh01234567890abcdef")
        hidden = self.record(fresh)
        peerjournal.write_record(self.state_dir, dict(hidden, control=dict(hidden["control"],
                                                                            sent=True)))
        key, attempt = self.frozen_then_record_lost()
        rec = self.record(fresh)
        peerjournal.write_record(self.state_dir, dict(rec, control=dict(rec["control"],
                                                                         sent=False)))
        self.assertLess(self.record(fresh)["take_seq"], self.record(key)["take_seq"])
        cap = peercontrol.capability(self.cfg, self.runtime)
        with self.assertRaises(peercontrol.Unavailable):
            peercontrol.generation(self.cfg, cap, now=NOW)
        self.assertEqual(list(self.tree.gens), [], "nothing minted by a direct selection")
        self.send()
        self.assertEqual(list(self.tree.gens), [attempt["gen"]], "no B minted")
        fresh_attempt = self.record(fresh)["control"].get("attempt")
        self.assertIn((fresh_attempt or {}).get("gen"), (None, attempt["gen"]))
        n, _doc = self.handover(key)
        self.assertEqual(n, attempt["n"])

    def test_an_unlisted_generation_with_traffic_in_flight_is_held_not_restored(self):
        """Unlisted reads as never admitted only while nothing is in flight
        in that generation: one that carried traffic and lost both its tree
        and its record is held, never re-admitted."""
        key, attempt = self.frozen_then_record_lost()
        d = peercontrol._inflight_dir(self.cfg, attempt["gen"])
        d.mkdir(parents=True, exist_ok=True)
        (d / ("other-request" + inflight.HANDED_SUFFIX)).write_text("00000009")
        got = self.send()
        self.assertEqual(got, {"held_" + peercontrol.HELD_GENERATION_UNRECORDED: 1})
        self.assertFalse((self.state_dir / config_mod.RUNTIME_NS
                          / config_mod.RUNTIME_GENERATION_FILE).exists(), "not restored")
        self.assertEqual(self.audit(), [])
        self.assertEqual(self.tree.senders, {}, "no sender for it")

    def restores(self):
        return [a for a in self.audit() if a.get("act") == peercontrol.RESTORE_VERB]

    def test_a_restore_whose_audit_fails_is_repaired_before_any_hand_over(self):
        key, attempt = self.frozen_then_record_lost()
        with mock.patch.object(peerjournal, "_audit", side_effect=OSError("disk full")):
            self.assertEqual(self.send(), {"errored": 1})
        control = self.record(key)["control"]
        self.assertEqual((control.get("audit_pending") or {}).get("verb"), peercontrol.RESTORE_VERB)
        self.assertEqual(self.restores(), [])
        real = inflight.begin_reserved
        seen = []

        def begin(*a, **k):
            seen.append(len(self.restores()))
            return real(*a, **k)
        with mock.patch.object(inflight, "begin_reserved", begin):
            self.send()
        self.assertEqual(seen, [1], "the audit line was there before the hand-over began")
        self.assertEqual([r.get("key") for r in self.restores()], [key])
        self.assertIsNone(self.record(key)["control"].get("audit_pending"))
        n, _doc = self.handover(key)
        self.assertEqual(n, attempt["n"])

    def test_a_crash_between_the_marker_and_the_restore_audits_once(self):
        key, attempt = self.frozen_then_record_lost()
        with mock.patch.object(peercontrol, "record_generation", side_effect=OSError("crash")):
            self.send()
        self.assertIsNotNone(self.record(key)["control"].get("audit_pending"))
        self.send()
        self.assertEqual(len(self.restores()), 1, "one line, for the restore that happened")
        self.assertIsNone(self.record(key)["control"].get("audit_pending"))

    def test_an_audit_line_is_appended_once_when_clearing_the_marker_fails(self):
        key, attempt = self.frozen_then_record_lost()
        real = peercontrol._update

        def update(sd, record, **changes):
            if "audit_pending" in changes and changes["audit_pending"] is None and not update.done:
                update.done = True
                raise OSError("crash after the audit line")
            return real(sd, record, **changes)
        update.done = False
        with mock.patch.object(peercontrol, "_update", update):
            self.send()
        self.assertEqual(len(self.restores()), 1)
        self.send()
        self.assertEqual(len(self.restores()), 1, "repaired without a second line")
        self.assertIsNone(self.record(key)["control"].get("audit_pending"))

    def held_beside_live_b(self):
        key, attempt = self.frozen_then_record_lost()
        self.tree.gens["b" * 32] = "live"
        self.send()
        return key

    def abandons(self):
        return [a for a in self.audit() if a.get("act") == peercontrol.ABANDON_VERB]

    def test_an_abandon_whose_audit_fails_is_committed_and_repaired_by_the_next_pass(self):
        key = self.held_beside_live_b()
        cap = peercontrol.capability(self.cfg, self.runtime)
        with mock.patch.object(peerjournal, "_audit", side_effect=OSError("disk full")):
            with self.assertRaises(peercontrol.AuditPending):
                peercontrol.operator_abandon_attempt(self.cfg, cap, key, now=NOW, evidence="x")
        control = self.record(key)["control"]
        self.assertEqual(control.get("suppressed"), peercontrol.SUPPRESS_ABANDONED)
        self.assertEqual((control.get("audit_pending") or {}).get("verb"), peercontrol.ABANDON_VERB)
        got = self.send()
        self.assertEqual(got.get("audit_repaired"), 1, got)
        self.assertEqual([a.get("key") for a in self.abandons()], [key])
        self.assertIsNone(self.record(key)["control"].get("audit_pending"))

    def cli(self, command="abandon-attempt", **args):
        import contextlib
        import io
        from router import __main__ as cli
        ns = types.SimpleNamespace(runtime_generation_command=command,
                                   evidence="operator evidence", **args)
        err = io.StringIO()
        with mock.patch.object(peercontrol, "capability",
                               return_value=peercontrol.Capability(
                                   self.runtime.plugin, self.runtime.fsops, self.cfg)), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            try:
                code = cli._runtime_generation(self.cfg, ns)
            except Exception as e:  # noqa: BLE001 -- a wrong outcome must FAIL, not error
                code = f"raised {type(e).__name__}"
        return code, err.getvalue()

    def test_the_cli_reports_a_committed_abandon_with_its_audit_pending_never_refused(self):
        key = self.held_beside_live_b()
        with mock.patch.object(peerjournal, "_audit", side_effect=OSError("disk full")):
            code, err = self.cli(key=key)
        self.assertEqual(code, 3)
        self.assertIn("COMMITTED", err)
        self.assertNotIn("refused", err)
        self.assertEqual(self.abandons(), [])
        # The next verb invocation repairs it first (this one is then refused:
        # the attempt is already abandoned).
        code, err = self.cli(key=key)
        self.assertEqual(code, 1)
        self.assertEqual([a.get("key") for a in self.abandons()], [key])
        self.assertIsNone(self.record(key)["control"].get("audit_pending"))

    def acts(self, verb):
        return [a for a in self.audit() if a.get("act") == verb]

    def recorded(self):
        try:
            return self.gen()
        except config_mod.StateKeyUnresolved:
            return None

    def frozen_in_live_a(self):
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        gen = self.record(key)["control"]["attempt"]["gen"]
        self.tree.gens[gen] = "live"
        return key, gen

    def assert_refused_untouched(self, command, live, **args):
        code, err = self.cli(command, **args)
        self.assertEqual(code, 1, err)
        self.assertIn("refused", err)
        self.assertEqual(self.tree.gens[live], "live", "nothing retired")
        self.assertEqual(self.recorded(), live, "generation.json intact")
        self.assertEqual(self.acts(peercontrol.NEW_VERB) + self.acts(peercontrol.RETIRE_VERB), [])

    def test_retire_and_new_refuse_a_frozen_attempt_before_any_effect(self):
        key, gen = self.frozen_in_live_a()
        self.assert_refused_untouched("new", gen)
        self.assert_refused_untouched("retire", gen, gen=gen)

    def test_retire_and_new_refuse_a_handed_marker_without_its_record(self):
        key = self.refused()
        self.send()
        gen = self.gen()
        n, _doc = self.handover(key)
        self.port().send(n)
        self.send()
        self.send()
        self.assertTrue(self.record(key)["control"]["sent"])
        d = peercontrol._inflight_dir(self.cfg, gen)
        d.mkdir(parents=True, exist_ok=True)
        (d / ("orphan-request" + inflight.HANDED_SUFFIX)).write_text("00000099")
        self.assert_refused_untouched("new", gen)
        self.assert_refused_untouched("retire", gen, gen=gen)

    def test_new_succeeds_once_the_attempt_has_settled_and_is_audited_once(self):
        key, gen = self.frozen_in_live_a()
        self.send()
        n, _doc = self.handover(key)
        self.port().send(n)
        self.send()
        self.send()
        code, err = self.cli("new")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.tree.gens[gen], "retired")
        self.assertNotIn(self.recorded(), (None, gen))
        self.assertEqual(len(self.acts(peercontrol.NEW_VERB)), 1)

    def test_new_refuses_before_retiring_when_the_mint_would_be_refused(self):
        live = "a" * 32
        self.tree.gens.update({live: "live", "b" * 32: "live"})
        peercontrol.record_generation(self.cfg, live, now=NOW)
        self.assert_refused_untouched("new", live)

    def test_every_verb_whose_audit_fails_reports_committed_and_is_repaired(self):
        a, b = "a" * 32, "b" * 32
        cases = (("adopt", {"gen": a}, peercontrol.ADOPT_VERB),
                 ("retire", {"gen": b}, peercontrol.RETIRE_VERB),
                 ("new", {}, peercontrol.NEW_VERB))
        self.tree.gens[a] = "live"
        for command, args, verb in cases:
            with self.subTest(command=command):
                if command == "retire":
                    self.tree.gens[b] = "live"
                with mock.patch.object(peerjournal, "_audit", side_effect=OSError("disk full")):
                    code, err = self.cli(command, **args)
                self.assertEqual(code, 3, err)
                self.assertIn("COMMITTED", err)
                self.assertNotIn("refused", err)
                self.assertEqual(self.acts(verb), [])
                # The next verb (refused: an unlisted generation) repairs it first.
                code, _err = self.cli("retire", gen="9" * 32)
                self.assertEqual(code, 1)
                self.assertEqual(len(self.acts(verb)), 1, f"{verb} repaired once")

    def test_a_crash_right_after_a_verbs_effect_is_still_audited(self):
        """Intent first: the marker is durable before the act, so a crash
        between the act and its audit line still leaves the line owed."""
        a = "a" * 32
        self.tree.gens[a] = "live"
        real = peercontrol.record_generation

        def record_then_crash(*args, **kwargs):
            real(*args, **kwargs)
            raise SystemExit("crash right after the effect")
        with mock.patch.object(peercontrol, "record_generation", record_then_crash):
            with self.assertRaises(SystemExit):
                self.cli("adopt", gen=a)
        self.assertEqual(self.recorded(), a, "the act took effect")
        self.assertEqual(self.acts(peercontrol.ADOPT_VERB), [])
        self.cli("retire", gen="9" * 32)
        self.assertEqual(len(self.acts(peercontrol.ADOPT_VERB)), 1, "owed, and repaired")

    def test_a_blocked_store_is_a_clean_refusal(self):
        key = self.held_beside_live_b()
        with mock.patch.object(peercontrol, "operator_abandon_attempt",
                               side_effect=peerjournal.StoreBlocked("an operation is unreconciled")):
            code, err = self.cli(key=key)
        self.assertEqual(code, 1)
        self.assertIn("refused", err)

    def test_an_unlisted_generation_whose_earlier_traffic_settled_is_held(self):
        """A generation that carried a settled attempt leaves no in-flight
        file behind; the journal still names it, so it is never re-admitted."""
        first = self.refused()
        self.send()
        gen = self.gen()
        n, _doc = self.handover(first)
        self.port().send(n)
        self.send()
        self.send()
        second = self.refused(id="qSecond0123456789abcde")
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        self.assertEqual(self.record(second)["control"]["attempt"]["gen"], gen)
        self.assertEqual(peercontrol._inflight_entries(self.cfg, gen), [])
        del self.tree.gens[gen]
        self.tree.senders.pop(gen, None)
        (self.state_dir / config_mod.RUNTIME_NS / config_mod.RUNTIME_GENERATION_FILE).unlink()
        got = self.send()
        self.assertEqual(got, {"held_" + peercontrol.HELD_GENERATION_UNRECORDED: 1})
        self.assertIsNone(self.recorded(), "not restored")

    def test_a_lost_record_beside_another_live_generation_holds_and_restores_nothing(self):
        key, attempt = self.frozen_then_record_lost()
        self.tree.gens.update({attempt["gen"]: "live", "b" * 32: "live"})
        got = self.send()
        self.assertEqual(got, {"held_" + peercontrol.HELD_GENERATION_UNRECORDED: 1})
        self.assertFalse((self.state_dir / config_mod.RUNTIME_NS
                          / config_mod.RUNTIME_GENERATION_FILE).exists(), "nothing restored")
        self.assertEqual(self.audit(), [])
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)
        self.assertEqual(doc["held"], {peercontrol.HELD_GENERATION_UNRECORDED: 1})
        self.assertEqual(self.send(), got, "the same visible hold, never an error")

    def test_no_generation_is_minted_while_an_attempt_is_held_unrecorded(self):
        key, attempt = self.frozen_then_record_lost()
        self.tree.gens[attempt["gen"]] = "retired"
        second = self.refused(id="qSecond0123456789abcde")
        got = self.send()
        self.assertEqual(got.get("held_" + peercontrol.HELD_GENERATION_UNRECORDED), 1, got)
        self.assertEqual(got.get(peercontrol.UNAVAILABLE), 1, got)
        self.assertEqual(list(self.tree.gens), [attempt["gen"]], "nothing minted")
        self.assertNotIn("attempt", self.record(second)["control"])
        # The audited exit, then the second notice goes out in a new generation.
        cap = peercontrol.capability(self.cfg, self.runtime)
        peercontrol.operator_abandon_attempt(self.cfg, cap, key, now=NOW, evidence="lost")
        control = self.record(key)["control"]
        self.assertEqual((control.get("suppressed"), control.get("held")),
                         (peercontrol.SUPPRESS_ABANDONED, None))
        self.send()
        self.assertNotEqual(self.record(second)["control"]["attempt"]["gen"], attempt["gen"])
        self.assertEqual(self.tree.senders[attempt["gen"]].writes
                         if attempt["gen"] in self.tree.senders else [], [],
                         "the abandoned attempt was never handed over")
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)
        self.assertEqual(doc["suppressed"].get(peercontrol.SUPPRESS_ABANDONED), 1)

    def test_abandon_ends_a_held_attempt_never_resent(self):
        key, attempt = self.frozen_then_record_lost()
        self.tree.gens["b" * 32] = "live"                  # another generation was live
        self.send()
        cap = peercontrol.capability(self.cfg, self.runtime)
        out = peercontrol.operator_abandon_attempt(self.cfg, cap, key, now=NOW, evidence="x")
        self.assertIn("abandoned", out["result"])
        self.assertEqual(self.record(key)["control"].get("suppressed"),
                         peercontrol.SUPPRESS_ABANDONED)
        self.send()
        self.assertEqual(len(self.signs), 1, "never re-signed")
        self.assertNotIn(attempt["gen"], self.tree.senders, "never handed over")

    def test_abandon_refuses_a_live_or_unreadable_generation_and_an_attempt_in_flight(self):
        key, attempt = self.frozen_then_record_lost()
        cap = peercontrol.capability(self.cfg, self.runtime)
        for state in ("live", "unreadable"):
            with self.subTest(state=state):
                self.tree.gens[attempt["gen"]] = state
                with self.assertRaises(ValueError):
                    peercontrol.operator_abandon_attempt(self.cfg, cap, key, now=NOW,
                                                         evidence="x")
        del self.tree.gens[attempt["gen"]]
        d = self.state_dir / config_mod.RUNTIME_NS / attempt["gen"] / inflight.INFLIGHT_DIR
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{attempt['id']}{inflight.HANDED_SUFFIX}").write_text(attempt["n"])
        with self.assertRaises(ValueError):
            peercontrol.operator_abandon_attempt(self.cfg, cap, key, now=NOW, evidence="x")
        self.assertIsNone(self.record(key)["control"].get("suppressed"))

    def test_a_lost_record_beside_its_live_generation_is_restored_under_the_same_n(self):
        key, attempt = self.frozen_then_record_lost()
        self.tree.gens[attempt["gen"]] = "live"
        self.send()
        self.assertEqual(self.gen(), attempt["gen"], "the record is restored to it")
        n, doc = self.handover(key)
        self.assertEqual(n, attempt["n"], "begun under the recorded n")
        self.assertEqual(doc["envelope"]["peer"]["statement_header"], attempt["header"])
        self.assertIsNone(self.record(key)["control"].get("held"))
        self.assertEqual(len(self.signs), 1, "never re-signed")

    def test_a_handed_marker_without_its_record_is_stuck_never_resent(self):
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        attempt = self.record(key)["control"]["attempt"]
        handed = inflight.handed_path(self.cfg, config_mod.RUNTIME_NS, attempt["id"])
        handed.parent.mkdir(parents=True, exist_ok=True)
        handed.write_text(attempt["n"])
        self.assertEqual(self.send(), {"stuck_" + peercontrol.STUCK_HANDED: 1})
        self.assertEqual(self.port().writes if self.gen() in self.tree.senders else [], [])
        stuck = self.record(key)["control"].get("stuck") or {}
        self.assertEqual(stuck.get("reason"), peercontrol.STUCK_HANDED, "recorded on the record")
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=NOW + timedelta(minutes=5))
        self.assertEqual(doc["stuck"], 1)
        self.assertEqual([(r["key"], r["reason"]) for r in doc["stuck_records"]],
                         [(key, peercontrol.STUCK_HANDED)])
        self.assertEqual(doc["pending"], 0, "a stuck notice is counted as stuck")

    def test_an_attempt_unsettled_past_the_horizon_is_recorded_stuck_never_resent(self):
        key = self.refused()
        self.send()
        n, _doc = self.handover(key)
        writes = list(self.port().writes)
        later = NOW + timedelta(seconds=peercontrol.SETTLE_HORIZON_S + 60)
        self.assertEqual(self.send(now=NOW + timedelta(minutes=5)).get(
            "stuck_" + peercontrol.STUCK_UNSETTLED), None, "not stuck within the horizon")
        got = self.send(now=later)
        self.assertEqual(got, {"stuck_" + peercontrol.STUCK_UNSETTLED: 1})
        stuck = self.record(key)["control"].get("stuck") or {}
        self.assertEqual(stuck.get("reason"), peercontrol.STUCK_UNSETTLED)
        self.assertEqual((self.port().writes, len(self.signs)), (writes, 1),
                         "never re-sent, never re-signed")
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=later)
        self.assertEqual(doc["stuck"], 1)
        self.assertEqual(doc["stuck_records"][0]["age_s"], peercontrol.SETTLE_HORIZON_S + 60)
        # A late result still settles it, and it is no longer stuck.
        self.port().send(n)
        self.send(now=later)
        control = self.record(key)["control"]
        self.assertTrue(control["sent"])
        self.assertIsNone(control.get("stuck"))


class SuppressionTests(_Control):

    def test_a_destination_no_longer_configured_is_suppressed_not_redirected(self):
        key = self.refused()
        other = dataclasses.replace(self.dc, runtimes=(dataclasses.replace(
            self.dc.runtimes[0], runtime=f"amap.router@{tpe.T2 if hasattr(tpe, 'T2') else T1}x"),))
        self.signing = types.SimpleNamespace(**dict(vars(self.signing), config=other))
        got = self.send()
        self.assertEqual(got, {"suppressed_" + peercontrol.SUPPRESS_UNCONFIGURED: 1})
        self.assertEqual(self.record(key)["control"]["suppressed"],
                         peercontrol.SUPPRESS_UNCONFIGURED)
        self.assertEqual(self.tree.senders, {}, "nothing handed over anywhere")

    def test_the_coalescing_owner_is_link_once_for_the_whole_triple(self):
        c = {"about": "a1", "cause": "policy"}
        self.assertEqual(peercontrol.coalesce_owner(self.cfg, DEST, c, "k1"), "k1")
        self.assertEqual(peercontrol.coalesce_owner(self.cfg, DEST, c, "k2"), "k1")
        self.assertEqual(peercontrol.coalesce_owner(self.cfg, DEST, dict(c, cause="no_edge"),
                                                    "k2"), "k2")

    def test_nothing_is_attempted_while_the_clock_is_untrusted(self):
        key = self.refused()
        (self.state_dir / peerclock.CLOCK_FILE).unlink()
        before = (self.state_dir / "lid-bob").exists() and self.record(key)
        got = self.send()
        # The bookkeeping lives in the clock file, so nothing can even be
        # counted; what matters is that nothing was attempted or written.
        self.assertEqual(set(got), {"held_clock_untrusted"})
        self.assertFalse((self.state_dir / config_mod.RUNTIME_NS).exists())
        self.assertEqual(self.tree.calls, [])


class RateTests(_Control):

    def test_over_the_limit_defers_then_suppresses_after_24_hours_of_h(self):
        key = self.refused()
        with mock.patch.object(peercontrol, "take_token", return_value=False):
            self.assertEqual(self.send(), {"deferred": 1})
            self.assertEqual(self.record(key)["control"]["deferred_since"], "2026-10-13T12:00:00Z")
            self.assertEqual(self.send(), {"deferred": 1}, "still within the day")
            # H is raised only by the store's clock: a day later.
            peerclock.advance(self.state_dir, NOW + timedelta(days=1))
            self.assertEqual(self.send(), {"suppressed_" + peercontrol.SUPPRESS_RATE: 1})
        self.assertEqual(self.record(key)["control"]["suppressed"], peercontrol.SUPPRESS_RATE)
        self.assertNotIn("attempt", self.record(key)["control"])

    def test_a_deferred_notice_is_sent_when_the_bucket_refills(self):
        first = self.refused()
        second = self.refused(id="qB2c3D4e5F6g7H8i9J0kLmx")
        with mock.patch.object(peercontrol, "_rate", return_value=1):
            got = self.send()
            self.assertEqual(got.get("deferred"), 1, got)
            self.assertIn("attempt", self.record(first)["control"], "the oldest goes first")
            peerclock.advance(self.state_dir, NOW + timedelta(hours=1))
            self.send()
        self.assertIn("attempt", self.record(second)["control"])

    def test_the_bucket_is_measured_on_h_never_raw_time(self):
        h = NOW
        with mock.patch.object(peercontrol, "_rate", return_value=1):
            self.assertTrue(peercontrol.take_token(self.cfg, DEST, h))
            self.assertFalse(peercontrol.take_token(self.cfg, DEST, h - timedelta(hours=5)),
                             "an earlier H refills nothing")
            self.assertTrue(peercontrol.take_token(self.cfg, DEST, h + timedelta(hours=1)))


class VerbTests(_Control):

    def cap(self):
        return peercontrol.capability(self.cfg, self.runtime)

    def test_adopt_retire_and_new_through_the_capability(self):
        live = "f" * 32
        self.tree.gens[live] = "live"
        self.assertEqual(peercontrol.operator_adopt(self.cfg, self.cap(), live, now=NOW,
                                                    evidence="x")["result"], f"adopted {live}")
        self.assertEqual(self.gen(), live)
        out = peercontrol.operator_new(self.cfg, self.cap(), now=NOW, evidence="rotate")
        self.assertEqual(self.tree.gens[live], "retired")
        self.assertNotEqual(self.gen(), live)
        self.assertIn("minted", out["result"])

    def test_adopt_needs_the_only_live_generation(self):
        self.tree.gens.update({"1" * 32: "live", "2" * 32: "live"})
        with self.assertRaises(ValueError):
            peercontrol.operator_adopt(self.cfg, self.cap(), "1" * 32, now=NOW, evidence="x")


class ReservedIdTests(_Control):
    """inflight.begin_reserved begins only under an id already reserved,
    and never under a second id for a request in flight."""

    def begin(self, n, req_id="r1"):
        try:
            inflight.begin_reserved(self.cfg, "bob", req_id, n, digest=None,
                                    request_doc={"req_id": req_id, "draft": {"to": ["x@y.example"]}},
                                    recipients=["x@y.example"])
            return "begun"
        except ValueError as e:
            return str(e)

    def test_an_unallocated_id_and_a_second_id_are_refused(self):
        self.assertIn("never allocated", self.begin("00000001"))
        n = inflight.reserve_transport_id(self.cfg, "bob")
        self.assertEqual(self.begin(n), "begun")
        m = inflight.reserve_transport_id(self.cfg, "bob")
        self.assertIn("already in flight", self.begin(m))
        self.assertEqual(self.begin(m, req_id="r2"), "begun")


class RuntimeBindingTests(unittest.TestCase):
    """fsops binds `.runtime/` as its own kind (never an agent's
    `<logical_id>/`), and a generation under it as a generation tree."""

    def test_the_runtime_directory_is_its_own_kind(self):
        import tempfile
        from router import fsops as fsops_mod
        with tempfile.TemporaryDirectory() as d:
            hop = pathlib.Path(d) / "hop"
            for sub in (".runtime/" + "a" * 32, "agent/" + "b" * 32):
                (hop / sub).mkdir(parents=True)
            ops = fsops_mod.FsOps(hop_root=hop)
            try:
                root = ops.open_root_nofollow(str(hop))
                rt = ops.descend_pinned(root, ".runtime")
                gen = ops.descend_pinned(root, ".runtime/" + "a" * 32)
                agent = ops.descend_pinned(root, "agent")
                self.assertEqual(ops.binding(rt).kind, fsops_mod.RUNTIME)
                self.assertEqual(ops.binding(gen).kind, fsops_mod.GENERATION)
                self.assertEqual(ops.binding(agent).kind, fsops_mod.HOP_ROOT)
                # Opened directly, not walked to (a fresh instance: no
                # earlier binding of the same directory): the same kind.
                other = fsops_mod.FsOps(hop_root=hop)
                try:
                    direct = other.open_root_nofollow(str(hop / ".runtime"))
                    self.assertEqual(other.binding(direct).kind, fsops_mod.RUNTIME)
                finally:
                    other.close()
            finally:
                ops.close()


class StatementTests(unittest.TestCase):

    def doc(self, **over):
        d = {"v": 1, "key_id": "k", "kind": "control", "id": "abc", "from": "a@b", "to": "c@d",
             "ts": "2026-10-13T12:00:00Z", "about": "s1", "outcome": "refused",
             "cause": "policy", "policy_code": "x"}
        d.update(over)
        return d

    def test_every_outcome_cause_pair_of_the_schema_is_accepted(self):
        for outcome, causes in peercontrol.CAUSES.items():
            for cause in causes:
                d = self.doc(outcome=outcome, cause=cause)
                if cause != "policy":
                    d.pop("policy_code")
                with self.subTest(outcome=outcome, cause=cause):
                    peercontrol.check_statement(d)

    def test_a_mismatch_raises_before_signing(self):
        for label, d in (("wrong set", self.doc(outcome="dropped")),
                         ("policy_code without policy", dict(self.doc(cause="no_edge"))),
                         ("no policy_code with policy", {k: v for k, v in self.doc().items()
                                                         if k != "policy_code"}),
                         ("an id outside the grammar", self.doc(id="a.b"))):
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    peercontrol.check_statement(d)


class AdmissionClosedTests(_Control):

    def test_nothing_is_attempted_minted_or_refilled_while_admission_is_closed(self):
        key = self.refused()
        before = self.record(key)
        peerclock.close(self.state_dir, peerclock.read(self.state_dir), "restored")
        got = self.send()
        self.assertEqual(got, {"held_admission_closed": 1})
        self.assertEqual(self.record(key), before, "no intent, no attempt")
        self.assertFalse((self.state_dir / config_mod.RUNTIME_NS).exists(),
                         "no generation minted, no bucket written")
        self.assertEqual(self.tree.calls, [], "no runtime factory was called")


class ControlStatusTests(_Control):

    def poll_status(self, runtime):
        from router import service
        from router.status import StatusTracker
        t = StatusTracker(interval_s=5.0)
        service.poll_once(self.cfg, t, runtime)
        return t.to_doc().get("peer_store", {}).get("controls", {})

    def test_poll_once_records_the_controls_section(self):
        self.refused()
        doc = self.poll_status(self.runtime)
        self.assertEqual(doc.get("pending"), 1)
        self.assertEqual(doc.get("runtime_tree"), {"generation": None, "generations": []})

    def test_without_the_capability_the_runtime_tree_is_unavailable(self):
        self.refused()
        self.assertEqual(self.poll_status(None).get("runtime_tree"), "unavailable")

    def test_a_lost_record_lists_the_generations_to_adopt_or_retire(self):
        self.tree.gens.update({"1" * 32: "live", "2" * 32: "unreadable", "3" * 32: "retired"})
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)
        self.assertEqual(doc["runtime_tree"], {
            "generation": None,
            "generations": [["1" * 32, "live"], ["2" * 32, "unreadable"],
                            ["3" * 32, "retired"]]})

    def test_a_settled_failure_is_counted_as_failed_never_as_sent(self):
        ok, bad = self.refused(), self.refused(id="qB2c3D4e5F6g7H8i9J0kLmx")
        self.send()
        n_ok, _ = self.handover(ok)
        n_bad, _ = self.handover(bad)
        self.port().send(n_ok)
        self.port().send(n_bad, outcome="rejected", reason_code="no_route")
        self.send()
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)
        self.assertEqual((doc["sent"], doc["failed"]), (1, {"rejected": 1}))


class GenerationClassifiedTests(_Control):

    def cap(self):
        return peercontrol.capability(self.cfg, self.runtime)

    def recorded(self, gen):
        peercontrol.record_generation(self.cfg, gen, now=NOW)

    def test_a_recorded_generation_retired_before_its_record_was_removed_is_never_reused(self):
        old = "a" * 32
        self.recorded(old)
        self.tree.gens[old] = "retired"     # retired through the capability, then a crash
        got = peercontrol.generation(self.cfg, self.cap(), now=NOW)
        self.assertNotEqual(got, old)
        self.assertEqual(self.gen(), got, "the fresh generation is recorded")
        self.assertEqual(self.tree.gens[old], "retired")

    def test_a_recorded_generation_beside_another_live_one_holds(self):
        self.recorded("a" * 32)
        self.tree.gens.update({"a" * 32: "live", "b" * 32: "live"})
        with self.assertRaises(peercontrol.Unavailable):
            peercontrol.generation(self.cfg, self.cap(), now=NOW)

    def test_a_recorded_generation_beside_an_unreadable_one_holds(self):
        self.recorded("a" * 32)
        self.tree.gens.update({"a" * 32: "live", "b" * 32: "unreadable"})
        with self.assertRaises(peercontrol.Unavailable):
            peercontrol.generation(self.cfg, self.cap(), now=NOW)

    def test_an_unreadable_recorded_generation_holds(self):
        self.recorded("a" * 32)
        self.tree.gens["a" * 32] = "unreadable"
        with self.assertRaises(peercontrol.Unavailable):
            peercontrol.generation(self.cfg, self.cap(), now=NOW)

    def test_a_recorded_generation_alone_and_not_yet_listed_is_used(self):
        self.recorded("a" * 32)
        self.assertEqual(peercontrol.generation(self.cfg, self.cap(), now=NOW), "a" * 32)
        self.tree.gens["a" * 32] = "live"
        self.assertEqual(peercontrol.generation(self.cfg, self.cap(), now=NOW), "a" * 32)

    def not_handed_over_when(self, state):
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        gen = self.record(key)["control"]["attempt"]["gen"]
        self.tree.gens[gen] = state
        self.assertEqual(self.send(), {peercontrol.UNAVAILABLE: 1})
        port = self.tree.senders.get(gen)
        self.assertEqual(port.writes if port is not None else [], [], "nothing handed over")

    def test_an_attempt_whose_generation_was_retired_is_not_handed_over(self):
        self.not_handed_over_when("retired")

    def test_an_attempt_whose_generation_is_unreadable_is_not_handed_over(self):
        self.not_handed_over_when("unreadable")


class DeferralHorizonTests(_Control):

    def test_a_notice_deferred_24_hours_is_suppressed_though_the_bucket_refilled(self):
        with mock.patch.object(peercontrol, "_rate", return_value=1):
            self.assertTrue(peercontrol.take_token(self.cfg, DEST, NOW), "the bucket emptied")
            key = self.refused()
            self.assertEqual(self.send(), {"deferred": 1})
            peerclock.advance(self.state_dir, NOW + timedelta(days=1))
            self.assertEqual(self.send(), {"suppressed_" + peercontrol.SUPPRESS_RATE: 1})
            self.assertNotIn("attempt", self.record(key)["control"])
            self.assertTrue(peercontrol.take_token(self.cfg, DEST, NOW + timedelta(days=1)),
                            "the suppression took no token")


class RetireListedOnlyTests(_Control):

    def test_retire_refuses_a_generation_the_lister_does_not_show(self):
        cap = peercontrol.capability(self.cfg, self.runtime)
        with self.assertRaises(ValueError):
            peercontrol.operator_retire(self.cfg, cap, "9" * 32, now=NOW, evidence="x")
        self.assertEqual([c for c in self.tree.calls if c[0] == "sender"], [],
                         "no sender constructed for an unlisted generation")

    def test_retire_makes_the_record_removal_durable(self):
        live = "f" * 32
        self.tree.gens[live] = "live"
        peercontrol.record_generation(self.cfg, live, now=NOW)
        cap = peercontrol.capability(self.cfg, self.runtime)
        # The audit's own bookkeeping (which fsyncs the same directory) is
        # stubbed, so only the retire's fsync can satisfy this.
        with mock.patch.object(peercontrol, "fsync_dir") as fsync, \
                mock.patch.object(peercontrol, "_finish_verb_audit"):
            peercontrol.operator_retire(self.cfg, cap, live, now=NOW, evidence="x")
        self.assertIn(mock.call(peercontrol.runtime_dir(self.cfg)), fsync.call_args_list)


class DestinationUnknownTests(_Control):

    def test_a_notice_without_about_or_to_is_held_never_unconfigured(self):
        key = self.refused()
        rec = self.record(key)
        peerjournal.write_record(self.state_dir, dict(rec, control=dict(
            rec["control"], about=None, to=None)))
        # No statement snapshot to read them back from either.
        with mock.patch.object(peerjournal, "read_snapshot", return_value=None):
            self.assertEqual(self.send(), {"held_" + peercontrol.HELD_NO_DESTINATION: 1})
        control = self.record(key)["control"]
        self.assertIsNone(control.get("suppressed"), "never suppressed")
        self.assertEqual(control.get("held"), peercontrol.HELD_NO_DESTINATION)
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)
        self.assertEqual((doc["held"], doc["suppressed"]),
                         ({peercontrol.HELD_NO_DESTINATION: 1}, {}))


class DelegationInactiveTests(_Control):

    def test_no_delegation_is_one_count_and_nothing_is_tried(self):
        key = self.refused()
        before = self.record(key)
        got = peercontrol.send_pending(self.cfg, self.runtime, delegation=None, now=NOW)
        self.assertEqual(got, {peercontrol.DELEGATION_INACTIVE: 1})
        self.assertEqual(self.record(key), before)


class StageUnderRuntimeTests(unittest.TestCase):

    def test_a_tree_staged_under_the_runtime_directory_binds_as_a_generation(self):
        import tempfile
        from router import fsops as fsops_mod
        with tempfile.TemporaryDirectory() as d:
            hop = pathlib.Path(d) / "hop"
            (hop / ".runtime").mkdir(parents=True)
            ops = fsops_mod.FsOps(hop_root=hop)
            try:
                root = ops.open_root_nofollow(str(hop))
                rt = ops.descend_pinned(root, ".runtime")
                try:
                    staged = ops.stage_tree(rt, ".adm-r")
                except fsops_mod.FsOpsError as e:
                    self.fail(f"stage_tree refused the runtime directory: {e}")
                up = ops.descend_pinned(staged, "up")
                stage = ops.open_stage_dir(staged, "up")
                self.assertEqual(ops.commit_durable(stage, up, "identity", b"{}", 0o640),
                                 "created")
                self.assertEqual(ops.rename_noreplace(rt, ".adm-r", rt, "a" * 32), "moved")
                gen = ops.descend_pinned(root, ".runtime/" + "a" * 32)
                self.assertEqual(ops.binding(gen).kind, fsops_mod.GENERATION)
            finally:
                ops.close()


if __name__ == "__main__":
    unittest.main()
