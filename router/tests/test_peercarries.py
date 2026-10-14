"""Three carries into the candidate journal: the digest index records the
kind it files (statement or control), a 5(b) value demotion names the
statement it is about, and the bound B's floor sees every in-flight record's
`written_ts` and each issued record's issue time."""
from __future__ import annotations

import dataclasses
import json
import unittest
from datetime import timedelta

from router import peerbind, peercontrol, peerjournal, peerlane
from router.tests import peer_standin as si
from router.tests import test_peercontrol as tpc
from router.tests import test_peerevaluate as tpe
from router.tests.test_peerbind import STATEMENT_ID, T1

SHA = "ab" * 32
RT, IDK = "cd" * 16, "ef" * 32


class DigestKindTests(tpe._Eval):

    def test_an_entry_names_its_kind_and_matches_only_it(self):
        peerjournal._link_digest(self.state_dir, SHA, RT, IDK, "control")
        self.assertEqual(peerjournal.known(self.state_dir, SHA, "control"), (RT, IDK))
        self.assertIsNone(peerjournal.known(self.state_dir, SHA, "statement"),
                          "an entry of the other kind is not a match")
        raw = (self.state_dir / peerjournal.REPLAY_DIR / peerjournal.DIGESTS_DIR / SHA).read_text()
        self.assertEqual(raw, f"control {RT}/{IDK}")

    def test_an_entry_without_a_kind_is_corrupt_never_guessed(self):
        d = self.state_dir / peerjournal.REPLAY_DIR / peerjournal.DIGESTS_DIR
        d.mkdir(parents=True)
        (d / SHA).write_text(f"{RT}/{IDK}")
        for kind in ("statement", "control"):
            with self.subTest(kind=kind):
                with self.assertRaises(peerbind.RecoveryCorrupt):
                    peerjournal.known(self.state_dir, SHA, kind)

    def test_a_placed_statement_files_a_statement_entry(self):
        rec = self.evaluate(self.take(self.raw()))
        rt, idk = rec["replay_ref"].split("/")
        files = list((self.state_dir / peerjournal.REPLAY_DIR / peerjournal.DIGESTS_DIR).iterdir())
        self.assertEqual([f.read_text() for f in files], [f"statement {rt}/{idk}"])


class _ValueRefusing:
    """The stand-in codec, except that check 5(b) refuses after check 4."""

    def __init__(self, inner, reason):
        self._inner, self._reason = inner, reason

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def verify_checked(self, kind, k, statement, signature, key_table, verifier, now):
        if self._reason == "signature":
            raise si.CodecError("crypto", "signature")
        self._inner.verify_checked(kind, k, statement, signature, key_table, verifier, now)
        raise si.CodecError("value", self._reason)


class ValueDemotionTests(tpe._Eval):

    def demote(self, reason):
        self.lane = dataclasses.replace(self.lane, codec=_ValueRefusing(self.lane.codec, reason))
        key = self.take(self.raw())
        return key, self.evaluate(key)

    def test_a_value_demotion_names_its_statement_and_its_destination(self):
        key, rec = self.demote("statement_value")
        self.assertEqual((rec["disposed"], rec["cause"]), ("demoted", "statement_value"))
        control = rec["control"] or {}
        self.assertEqual(control.get("about"), STATEMENT_ID)
        self.assertEqual(control.get("to"), f"amap.router@{T1}")
        snap = peerjournal.read_snapshot(self.state_dir, rec, peerjournal.SNAPSHOT_STATEMENT)
        self.assertIsNotNone(snap, "the statement was snapshotted")
        self.assertEqual(json.loads(snap)["id"], STATEMENT_ID)

    def test_a_signature_refusal_snapshots_nothing_and_sends_no_control(self):
        key, rec = self.demote("signature")
        self.assertEqual(rec["cause"], "signature")
        self.assertIsNone(rec["control"])
        self.assertIsNone(peerjournal.read_snapshot(self.state_dir, rec,
                                                    peerjournal.SNAPSHOT_STATEMENT))


class ObservedTimesTests(tpe._Eval):

    def test_in_flight_written_ts_and_issued_records_are_sources(self):
        inflight_dir = self.state_dir / "bob" / "inflight"
        inflight_dir.mkdir(parents=True)
        (inflight_dir / "00000001.json").write_text(json.dumps({"written_ts": "2026-10-13T12:30:00Z"}))
        runtime_dir = self.state_dir / "_runtime" / ("a" * 32) / "inflight"
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "x.json").write_text(json.dumps({"written_ts": "2026-10-13T12:40:00Z"}))
        peerlane.write_issued(self.cfg, peerlane.issued_record(
            peer_id="i" * 23, logical_id="bob", local_address="bob@x.example", remote="p@y.example",
            generation="g", expires_at="2026-10-20T13:00:00Z"))
        got = peerjournal.observed_times(self.state_dir, None, reply_window_s=7 * 86400)
        sources = {src.rsplit(" ", 1)[-1] if "written_ts" in src else src.split(" ", 1)[1]: t
                   for t, src in got if "written_ts" in src or "issued" in src}
        times = {t for t, src in got}
        from router.util import parse_utc_ts
        self.assertIn(parse_utc_ts("2026-10-13T12:30:00Z"), times, "an agent's in-flight record")
        self.assertIn(parse_utc_ts("2026-10-13T12:40:00Z"), times, "the runtime's in-flight record")
        self.assertIn(parse_utc_ts("2026-10-13T13:00:00Z"), times, "the issued record's issue time")
        self.assertTrue(any("issued" in src for _t, src in got), "each source is named")


class DemotionDestinationTests(tpc._Control):
    """A 5(b) demotion's control reaches the sender with its destination,
    and one an earlier build suppressed without one is pending again."""

    def demoted(self):
        self.lane = dataclasses.replace(
            self.lane, codec=_ValueRefusing(self.lane.codec, "statement_value"))
        key = self.take(self.raw())
        self.assertEqual(self.evaluate(key)["cause"], "statement_value")
        return key

    def attempts(self, got):
        return sum(v for k, v in got.items() if k.startswith("attempt_"))

    def test_a_value_demotions_control_is_attempted_not_suppressed(self):
        key = self.demoted()
        got = self.send()
        self.assertEqual(self.attempts(got), 1, got)
        self.assertIsNone(self.record(key)["control"].get("suppressed"))

    def test_a_misaddressed_suppression_is_pending_again_with_its_destination(self):
        key = self.demoted()
        rec = self.record(key)
        peerjournal.write_record(self.state_dir, dict(rec, control=dict(
            rec["control"], about=None, to=None, suppressed=peercontrol.SUPPRESS_UNCONFIGURED)))
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=tpc.NOW)
        self.assertEqual((doc["pending"], doc["suppressed"]), (1, {}),
                         "counted as pending, not as suppressed")
        got = self.send()
        control = self.record(key)["control"]
        self.assertEqual((control.get("about"), control.get("to"), control.get("suppressed")),
                         (STATEMENT_ID, tpc.DEST, None))
        self.assertEqual(self.attempts(got), 1, got)


if __name__ == "__main__":
    unittest.main()
