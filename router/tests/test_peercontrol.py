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
        n = self.record(key)["control"]["attempt"]["n"]
        return n, json.loads(self.port().pending[n])


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
        binding classification) mentions the `.runtime` tree or calls a
        runtime factory by name outside transport's table."""
        bad = []
        for path in sorted(ROUTER.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
            for n in ast.walk(tree):
                if isinstance(n, ast.Constant) and n.value == ".runtime" \
                        and path.name != "fsops.py":
                    bad.append(f"{path.name}:{n.lineno}: the .runtime literal")
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
        self.assertEqual(doc["attachments"], [])
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


if __name__ == "__main__":
    unittest.main()
