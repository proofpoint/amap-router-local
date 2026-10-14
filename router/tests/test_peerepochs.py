"""The receiver's exposure check and sender-age policy (`router/peerpolicy.py`)
and the epoch store (`router/peerepochs.py`, `store.v` 2 in `peerjournal`).

Pinned here: check 8's case rules against the key owner's runtime; the
policy order (age missing, consistency, quarantined, exposure missing); an
earlier `sender_since` persisting nothing; a later one persisted and audited
before the age test; the 24 h boundary on the router's own clock; the epoch
store untouched with no age policy; a read fault holding and setting the
fail-closed flag; the flag sparing what never reaches the consistency step;
one file per pair; `store.v` 2's migration; loss and BEHIND findings; the
recount under a bound B; the trust verb; and the config refusal of either
overlay."""
from __future__ import annotations

import dataclasses
import json
import os
from datetime import datetime, timedelta, timezone
from unittest import mock

from router import config as config_mod
from router import peerclock, peerepochs, peerjournal, peerpolicy
from router.tests import test_peerevaluate as tpe
from router.tests.test_peerbind import FD, KEY_ID, T1

NOW = tpe.NOW
RUNTIME = f"amap.router@{T1}"
SENDER = f"planner@{T1}"
DAY = 86400


def ts(delta_s: int) -> str:
    return (NOW + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def payload(**over):
    doc = {"v": 1, "key_id": KEY_ID, "kind": "peer", "id": "s" * 23, "from": SENDER,
           "to": f"bob@{FD}", "ts": ts(-60)}
    doc.update(over)
    return doc


class _Epochs(tpe._Eval):

    def hooks(self, policy, now=NOW):
        clock = peerclock.read(self.state_dir)
        hctx = peerpolicy.hook_context(self.cfg, delegation=self.lane, state_dir=self.state_dir,
                                       now=now, clock=clock)
        return peerpolicy.decide_hooks(peerpolicy.Profile(
            hctx, peerpolicy.TRUSTED_HOST_DEFAULT, policy))

    def decide(self, p, policy=peerpolicy.PRODUCTION_POLICY, now=NOW):
        try:
            out = self.hooks(policy, now).policy(p, "bob", RUNTIME)
        except Exception as e:  # noqa: BLE001 -- a wrong outcome must FAIL, not error
            return ("raised", type(e).__name__)
        if isinstance(out, peerjournal.Refuse):
            return out.policy_code
        if isinstance(out, peerjournal.Hold):
            return ("hold", out.reason)
        return out

    def accepted(self, sender=SENDER):
        return peerepochs.accepted(self.state_dir, RUNTIME, peerepochs.canonical_from(sender))

    def epoch_files(self):
        r = peerepochs.root(self.state_dir)
        return sorted(str(p.relative_to(r)) for p in r.rglob("*.json"))

    def meta(self):
        return peerjournal.read_meta(self.state_dir)

    def audit_lines(self):
        p = self.state_dir / peerjournal.REPLAY_DIR / peerepochs.AUDIT_FILE
        return [json.loads(l) for l in p.read_text().splitlines()] if p.is_file() else []


AGE = peerpolicy.PolicyPart(exposure_required=False, min_sender_age_s=DAY)
AGE_OFF = peerpolicy.PolicyPart(exposure_required=False, min_sender_age_s=None)
EXPOSED = {"asserted_by": RUNTIME, "exposure": "internal"}


class PolicyOrderTests(_Epochs):

    def test_age_missing_records_nothing(self):
        self.assertEqual(self.decide(payload()), "sender_age_missing")
        self.assertEqual(self.epoch_files(), [])

    def test_a_later_epoch_is_persisted_and_audited_before_the_age_test(self):
        self.assertEqual(self.decide(payload(sender_since=ts(-60))), "quarantined")
        self.assertEqual(self.accepted(), ts(-60), "persisted though quarantined")
        lines = self.audit_lines()
        self.assertEqual([(l["event"], l["old"], l["new"], l["from"]) for l in lines],
                         [("peer_epoch_changed", None, ts(-60), SENDER)])

    def test_an_earlier_epoch_is_inconsistent_and_persists_nothing(self):
        self.maxDiff = None
        self.decide(payload(sender_since=ts(-2 * DAY)))
        before = (self.epoch_files(), len(self.audit_lines()))
        self.assertEqual(self.decide(payload(sender_since=ts(-3 * DAY))),
                         "sender_since_inconsistent")
        self.assertEqual((self.epoch_files(), len(self.audit_lines())), before)
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY)), AGE), None,
                         "the original value is EQUAL afterwards")

    def test_exposure_missing_comes_last_and_may_advance_the_epoch(self):
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY))), "exposure_missing")
        self.assertEqual(self.accepted(), ts(-2 * DAY))
        self.assertIsNone(self.decide(payload(sender_since=ts(-2 * DAY),
                                              sender_exposure=EXPOSED)))

    def test_inconsistent_before_quarantined(self):
        self.decide(payload(sender_since=ts(-60)))
        self.assertEqual(self.decide(payload(sender_since=ts(-120))), "sender_since_inconsistent")

    def test_a_future_sender_since_is_quarantined_and_persisted(self):
        self.assertEqual(self.decide(payload(sender_since=ts(30))), "quarantined")
        self.assertEqual(self.accepted(), ts(30))

    def test_age_is_measured_on_the_routers_clock_not_ts(self):
        # sender_since 23 h 55 m before ts; now is ts + 10 m: 24 h 5 m old.
        p = payload(ts=ts(-600), sender_since=ts(-600 - (DAY - 300)))
        self.assertIsNone(self.decide(p, AGE))

    def test_exactly_24_hours_passes_and_one_second_less_is_quarantined(self):
        self.assertEqual(self.decide(payload(sender_since=ts(-(DAY - 1))), AGE), "quarantined")
        self.assertIsNone(self.decide(payload(sender_since=ts(-DAY), **{"from": f"other@{T1}"}),
                                      AGE))

    def test_with_no_age_policy_the_epoch_store_is_never_consulted(self):
        self.assertIsNone(self.decide(payload(sender_since=ts(-60)), AGE_OFF))
        self.assertIsNone(self.decide(payload(), AGE_OFF))
        self.assertEqual(self.epoch_files(), [])

    def test_a_zero_age_policy_is_active(self):
        zero = peerpolicy.PolicyPart(exposure_required=False, min_sender_age_s=0)
        self.decide(payload(sender_since=ts(-60)), zero)
        self.assertEqual(self.decide(payload(sender_since=ts(-120)), zero),
                         "sender_since_inconsistent")

    def test_the_epoch_key_is_canonical_and_never_alias_merged(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        variant = f"planner@{T1.upper()}"
        self.assertEqual(self.decide(payload(sender_since=ts(-3 * DAY), **{"from": variant})),
                         "sender_since_inconsistent", "a domain-case variant is the same pair")
        other = f"Planner@{T1}"
        self.assertEqual(self.decide(payload(sender_since=ts(-3 * DAY), **{"from": other}),
                                     AGE), None, "the local part is exact: another pair")

    def test_one_file_per_pair(self):
        self.decide(payload(sender_since=ts(-3 * DAY)))
        self.decide(payload(sender_since=ts(-2 * DAY)))
        self.assertEqual(len(self.epoch_files()), 1)
        self.assertEqual(self.accepted(), ts(-2 * DAY))

    def test_no_sender_age_invalid_anywhere(self):
        import router
        for p in sorted(os.listdir(os.path.dirname(router.__file__))):
            if p.endswith(".py"):
                with open(os.path.join(os.path.dirname(router.__file__), p)) as f:
                    self.assertNotIn("sender_age_invalid", f.read(), p)


class ConformanceMappingTests(_Epochs):

    def test_the_receiver_patch_maps_absent_to_none_and_keeps_zero(self):
        hctx = peerpolicy.hook_context(self.cfg, delegation=self.lane, state_dir=self.state_dir,
                                       now=NOW, clock=peerclock.read(self.state_dir))
        for patch, want in ((None, None), ({}, None), ({"min_sender_age_s": 0}, 0),
                            ({"min_sender_age_s": DAY}, DAY)):
            with self.subTest(patch=patch):
                part = peerpolicy.conformance_profile(hctx, patch, []).policy
                self.assertEqual((part.exposure_required, part.min_sender_age_s), (False, want))


class HeldRecordTests(_Epochs):

    def test_a_record_held_on_the_epoch_store_is_decided_once_the_flag_clears(self):
        real = self.hooks(AGE).policy
        key = self.take(self.raw(sender_since=ts(-2 * DAY)))
        peerepochs.set_untrusted(self.state_dir, "test")
        rec = self.evaluate(key, hk=tpe.hooks(policy=real))
        self.assertEqual((rec["state"], (rec["hold"] or {}).get("reason")),
                         ("reserved", "epoch_store_unavailable"))
        rec = self.evaluate(key, hk=tpe.hooks(policy=real))
        self.assertEqual(rec["state"], "reserved", "an operator hold: never re-tried while set")
        peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        rec = self.evaluate(key, hk=tpe.hooks(policy=self.hooks(AGE).policy))
        self.assertEqual(rec["disposed"], "placed")


class Check8Tests(_Epochs):

    def check8(self, asserted_by, profile=peerpolicy.PRODUCTION_POLICY):
        return self.hooks(profile).check8(payload(sender_exposure={"asserted_by": asserted_by}),
                                          KEY_ID)

    def test_the_key_owners_runtime_passes_and_a_domain_case_variant_too(self):
        self.assertIsNone(self.check8(RUNTIME))
        self.assertIsNone(self.check8(f"amap.router@{T1.upper()}"))

    def test_a_local_part_case_variant_and_the_receivers_own_runtime_fail(self):
        self.assertEqual(self.check8(f"AMAP.router@{T1}"), "exposure_signer")
        self.assertEqual(self.check8(f"amap.router@{FD}"), "exposure_signer")

    def test_absence_is_never_check_8s(self):
        self.assertIsNone(self.hooks(peerpolicy.PRODUCTION_POLICY).check8(payload(), KEY_ID))

    def test_check_8_is_profile_independent(self):
        for asserted in (RUNTIME, f"amap.router@{FD}"):
            self.assertEqual(self.check8(asserted), self.check8(asserted, AGE_OFF))


class FaultTests(_Epochs):

    def corrupt_the_pair(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        (path,) = list(peerepochs.root(self.state_dir).rglob("*.json"))
        path.write_text("{not json")

    def test_a_read_fault_holds_and_sets_the_flag(self):
        self.corrupt_the_pair()
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY))),
                         ("hold", "epoch_store_unavailable"))
        self.assertTrue(self.meta()["epochs_untrusted"])

    def test_a_body_naming_another_pair_is_a_fault(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        (path,) = list(peerepochs.root(self.state_dir).rglob("*.json"))
        doc = json.loads(path.read_text())
        doc["from"] = f"someone@{T1}"
        path.write_text(json.dumps(doc, sort_keys=True))
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY))),
                         ("hold", "epoch_store_unavailable"))

    def test_a_non_canonical_name_is_a_fault(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        (path,) = list(peerepochs.root(self.state_dir).rglob("*.json"))
        # A body that agrees with its non-canonical name: only the
        # canonical-name rule can refuse it.
        odd = ts(-2 * DAY).replace("Z", "+00:00")
        doc = json.loads(path.read_text())
        doc["sender_since"] = odd
        path.with_name(f"{odd}.json").write_text(json.dumps(doc, sort_keys=True))
        path.unlink()
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY))),
                         ("hold", "epoch_store_unavailable"))

    def test_the_flag_spares_what_never_reaches_the_consistency_step(self):
        self.corrupt_the_pair()
        self.decide(payload(sender_since=ts(-2 * DAY)))       # sets the flag
        self.assertEqual(self.decide(payload()), "sender_age_missing")
        self.assertIsNone(self.decide(payload(sender_since=ts(-60)), AGE_OFF))
        self.assertEqual(self.decide(payload(sender_since=ts(-5 * DAY), **{"from": f"x@{T1}"})),
                         ("hold", "epoch_store_unavailable"), "every pair holds")


class StoreTests(_Epochs):

    def test_init_writes_store_v2_with_the_epoch_root(self):
        meta = self.meta()
        self.assertEqual((meta["v"], meta["epochs_untrusted"], meta["epochs"]["live"]),
                         (2, False, 0))
        self.assertTrue((peerepochs.root(self.state_dir) / peerjournal.WITNESS).is_file())

    def to_v1(self):
        doc = peerclock.read_doc(self.state_dir)
        store = dict(doc["store"])
        for k in ("epochs", "epochs_untrusted"):
            store.pop(k)
        store["v"] = 1
        doc["store"] = store
        peerclock.write_doc(self.state_dir, doc)

    def test_a_v1_store_is_never_read_as_an_empty_epoch_store(self):
        self.to_v1()
        try:
            peerjournal.read_meta(self.state_dir)
            got = "read"
        except Exception as e:  # noqa: BLE001 -- the wrong outcome must FAIL
            got = type(e).__name__
        self.assertEqual(got, "StoreV1")

    def test_a_v1_store_migrates_when_no_epoch_files_exist(self):
        import shutil
        shutil.rmtree(peerepochs.root(self.state_dir))
        self.to_v1()
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual(rep["problems"], [])
        self.assertEqual((self.meta()["v"], self.meta()["epochs_untrusted"]), (2, False))

    def test_a_leftover_root_from_a_crashed_migration_is_readopted(self):
        token = (peerepochs.root(self.state_dir) / peerjournal.WITNESS).read_text()
        self.to_v1()
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual(rep["problems"], [], "re-adopted: no loss is found")
        self.assertEqual(self.meta()["epochs"]["token"], token)

    def test_a_v1_store_beside_epoch_files_is_behind_and_flagged(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        self.to_v1()
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((rep["admission"], rep["why"]), ("closed", "clock_behind_stores"))
        self.assertTrue(any("beside a v1 record" in p for p in rep["problems"]), rep["problems"])
        self.assertTrue(self.meta()["epochs_untrusted"])

    def behind_crash_then_restart(self, patch):
        """The BEHIND migration with one crash injected by `patch`, then a
        restart: (the restart's report, the PERSISTED admission)."""
        self.decide(payload(sender_since=ts(-2 * DAY)))
        self.assertEqual(peerclock.read(self.state_dir).admission, "open", "open before")
        self.to_v1()
        with patch, self.assertRaises(SystemExit):
            peerjournal.startup(self.state_dir, NOW)
        rep = peerjournal.startup(self.state_dir, NOW)
        return rep, peerclock.read(self.state_dir).admission

    def test_a_crash_at_the_behind_close_leaves_admission_closed_on_restart(self):
        rep, persisted = self.behind_crash_then_restart(
            mock.patch.object(peerclock, "close", side_effect=SystemExit("crash")))
        self.assertEqual((rep["admission"], persisted), ("closed", "closed"))
        self.assertTrue(self.meta()["epochs_untrusted"])

    def test_a_crash_at_the_behind_v2_write_leaves_admission_closed_on_restart(self):
        real = peerclock.write_doc

        def write_doc(state_dir, doc, *a, **k):
            if doc.get("store", {}).get("v") == 2:
                raise SystemExit("crash")
            return real(state_dir, doc, *a, **k)
        rep, persisted = self.behind_crash_then_restart(
            mock.patch.object(peerclock, "write_doc", write_doc))
        self.assertEqual((rep["admission"], persisted), ("closed", "closed"))
        self.assertEqual((self.meta()["v"], self.meta()["epochs_untrusted"]), (2, True))

    def test_deleting_the_only_file_is_loss_and_sets_the_flag(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        (path,) = list(peerepochs.root(self.state_dir).rglob("*.json"))
        path.unlink()
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertTrue(any("epoch store" in p for p in rep["problems"]), rep)
        self.assertTrue(self.meta()["epochs_untrusted"], "the rebase never clears it")
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["problems"], [],
                         "the next start is clean")

    def test_a_journal_loss_with_the_clock_intact_leaves_the_flag_clear(self):
        key = self.take(self.raw())
        self.evaluate(key, hk=tpe.hooks(policy=lambda _p, _h, _r: None))
        import shutil
        shutil.rmtree(peerjournal.record_dir(self.state_dir, tpe.OWNER, key))
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertTrue(rep["problems"])
        self.assertFalse(self.meta()["epochs_untrusted"])

    def test_a_crash_between_link_and_prune_is_completed_at_reconcile(self):
        self.decide(payload(sender_since=ts(-3 * DAY)))
        real = peerepochs.prune_older
        peerepochs.prune_older = lambda *a, **k: 0
        try:
            self.decide(payload(sender_since=ts(-2 * DAY)))
        finally:
            peerepochs.prune_older = real
        self.assertEqual(len(self.epoch_files()), 2)
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["problems"], [])
        self.assertEqual(len(self.epoch_files()), 1)
        self.assertEqual(self.accepted(), ts(-2 * DAY))

    def test_a_two_file_pair_beside_a_loss_is_kept(self):
        self.decide(payload(sender_since=ts(-3 * DAY), **{"from": f"other@{T1}"}))
        self.decide(payload(sender_since=ts(-3 * DAY)))
        real = peerepochs.prune_older
        peerepochs.prune_older = lambda *a, **k: 0
        try:
            self.decide(payload(sender_since=ts(-2 * DAY)))
        finally:
            peerepochs.prune_older = real
        other = peerepochs.pair_dir(self.state_dir, RUNTIME, f"other@{T1}")
        for f in other.iterdir():
            f.unlink()                                       # a LOSS elsewhere
        peerjournal.startup(self.state_dir, NOW)
        self.assertEqual(len(peerepochs.pair_files(
            self.state_dir, RUNTIME, peerepochs.canonical_from(SENDER))), 2, "both files kept")
        self.assertTrue(self.meta()["epochs_untrusted"])

    def test_the_epoch_intent_is_reconciled_at_each_crash_point(self):
        p = peerepochs.pair_dir(self.state_dir, RUNTIME, peerepochs.canonical_from(SENDER))
        meta = self.meta()
        data = peerepochs.body_bytes(RUNTIME, SENDER, ts(-2 * DAY))
        path = p / f"{ts(-2 * DAY)}.json"
        delta = peerjournal._delta("epochs", None, peerepochs._contribution(path, data), 0, 1)
        meta["pending_op"] = {"op": "epoch", "owner": None, "target": str(path), "delta": [delta]}
        peerjournal._write_meta(self.state_dir, meta)
        self.assertEqual(peerjournal.reconcile(self.state_dir), [], "not run")
        meta = self.meta()
        meta["pending_op"] = {"op": "epoch", "owner": None, "target": str(path), "delta": [delta]}
        peerjournal._write_meta(self.state_dir, meta)
        peerepochs._link(path, data)
        self.assertEqual(peerjournal.reconcile(self.state_dir), [], "ran completely")
        self.assertEqual(self.meta()["epochs"]["live"], 1)

    def bound(self):
        peerclock.record_bound(self.state_dir, NOW + timedelta(hours=1),
                               at=NOW + timedelta(minutes=30), evidence="a measured bound",
                               not_from_wall_clock=True, observed=[])

    def test_a_rebuild_under_bound_b_without_prior_bookkeeping_sets_the_flag(self):
        from unittest import mock
        self.bound()
        with mock.patch.object(peerjournal, "_old_meta", return_value=None):  # a lost clock file
            peerjournal.rebuild_meta(self.state_dir)
        self.assertTrue(self.meta()["epochs_untrusted"])

    def test_a_rebuild_with_its_prior_bookkeeping_leaves_the_flag_clear(self):
        self.bound()
        peerjournal.rebuild_meta(self.state_dir)
        self.assertFalse(self.meta()["epochs_untrusted"])

    def test_declare_restored_sets_the_flag(self):
        peerjournal.operator_declare_restored(self.state_dir, NOW, evidence="restored")
        self.assertTrue(self.meta()["epochs_untrusted"])

    def test_status_shows_the_epoch_section(self):
        self.decide(payload(sender_since=ts(-60)))
        doc = peerjournal.status_doc(self.state_dir, NOW)["epochs"]
        self.assertEqual((doc["pairs"], doc["pairs_mid_prune"], doc["untrusted"]), (1, 0, False))


class TrustVerbTests(_Epochs):

    def place_with_since(self, since, ident):
        key = self.take(self.raw(sender_since=since, id=ident))
        rec = self.evaluate(key, hk=tpe.hooks(policy=lambda _p, _h, _r: None))
        self.assertEqual(rec["disposed"], "placed")
        return rec

    def test_reseed_from_placed_records_then_clear(self):
        self.place_with_since(ts(-3 * DAY), "qPlaced0123456789abcde")
        peerepochs.set_untrusted(self.state_dir, "test")
        out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertTrue(out["cleared"], out)
        self.assertEqual(self.accepted(), ts(-3 * DAY))
        self.assertFalse(self.meta()["epochs_untrusted"])

    def assert_not_reseeded(self, needle):
        peerepochs.set_untrusted(self.state_dir, "test")
        try:
            out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        except Exception as e:  # noqa: BLE001 -- a wrong outcome must FAIL, not error
            out = {"cleared": f"raised {type(e).__name__}: {e}", "problems": []}
        self.assertIs(out["cleared"], False, out)
        self.assertTrue(any("cannot be read reliably" in p and needle in p
                            for p in out["problems"]), out["problems"])
        self.assertIsNone(self.accepted(), "nothing reseeded from a partial view")
        self.assertTrue(self.meta()["epochs_untrusted"], "the flag stays")

    def test_an_unreadable_record_reseeds_nothing_and_keeps_the_flag(self):
        rec = self.place_with_since(ts(-3 * DAY), "qPlaced0123456789abcde")
        (peerjournal.record_dir(self.state_dir, rec["owner"], rec["key"])
         / peerjournal.RECORD).write_text("{")
        self.assertEqual(peerjournal.all_records(self.state_dir), [], "a plain read skips it")
        self.assert_not_reseeded("cannot be read")

    def test_a_record_directory_without_its_record_reseeds_nothing(self):
        rec = self.place_with_since(ts(-3 * DAY), "qPlaced0123456789abcde")
        (peerjournal.record_dir(self.state_dir, rec["owner"], rec["key"])
         / peerjournal.RECORD).unlink()
        self.assert_not_reseeded("has no regular record")

    def test_a_record_that_is_not_a_record_reseeds_nothing(self):
        rec = self.place_with_since(ts(-3 * DAY), "qPlaced0123456789abcde")
        (peerjournal.record_dir(self.state_dir, rec["owner"], rec["key"])
         / peerjournal.RECORD).write_text("[]")
        self.assert_not_reseeded("is not a record")

    def test_a_malformed_roots_reseeds_nothing_and_keeps_the_flag(self):
        self.place_with_since(ts(-3 * DAY), "qPlaced0123456789abcde")
        path = self.state_dir / peerclock.CLOCK_FILE
        doc = json.loads(path.read_text())
        doc["store"]["roots"] = []
        path.write_text(json.dumps(doc))
        self.assert_not_reseeded("not the shape this router writes")

    def test_every_pending_op_the_real_writers_emit_passes_the_shape_check(self):
        """Positive witnesses from the WRITERS themselves: every pending_op
        written during a real take, evaluation (reservation, done marker,
        epoch), trust verb and retention prune is captured as written, and
        each passes `_check_meta_shape`. A form the check refuses would be a
        refusal of a live router's own state."""
        import copy
        from unittest import mock
        seen = []
        real = peerjournal._write_meta

        def capture(state_dir, meta):
            if meta.get("pending_op") is not None:
                seen.append(copy.deepcopy(meta))
            return real(state_dir, meta)
        with mock.patch.object(peerjournal, "_write_meta", capture):
            rec = self.place_with_since(ts(-3 * DAY), "qPlaced0123456789abcde")
            peerepochs.set_untrusted(self.state_dir, "test")
            peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
            # A newer sender_since for the same sender prunes the older epoch.
            self.decide(payload(sender_since=ts(-2 * DAY)))
            # The retention sweep past the record's horizon prunes it.
            rt, idk = rec["replay_ref"].split("/")
            stamp = json.loads((self.state_dir / peerjournal.REPLAY_DIR / rt
                                / f"{idk}.json").read_text())["ts"]
            horizon = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc) + timedelta(seconds=3600 + 300 + 1)
            peerjournal.advance_frontier(self.state_dir)
            peerclock.advance(self.state_dir, horizon)
            peerjournal.sweep(self.state_dir, horizon, enabled=True)
        ops = sorted({m["pending_op"]["op"] for m in seen})
        for m in seen:
            with self.subTest(op=m["pending_op"]["op"]):
                try:
                    peerjournal._check_meta_shape(m)
                    refused = None
                except peerjournal.JournalBlind as e:
                    refused = str(e)
                self.assertIsNone(refused, "a real writer's own form refused")
        self.assertEqual(set(ops), set(peerjournal.PENDING_OP_FORMS),
                         "every form the check knows was emitted by a real writer here")

    def test_a_never_journaled_store_still_clears(self):
        self.assertFalse(peerjournal.journal_present(self.state_dir))
        peerepochs.set_untrusted(self.state_dir, "test")
        out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertTrue(out["cleared"], out)

    def test_an_inconsistent_record_is_never_reseeded(self):
        key = self.take(self.raw(sender_since=ts(-DAY * 9), id="qIncons0123456789abcde"))
        self.evaluate(key, hk=tpe.hooks(
            policy=lambda _p, _h, _r: peerjournal.Refuse("policy", "sender_since_inconsistent")))
        peerepochs.set_untrusted(self.state_dir, "test")
        peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertIsNone(self.accepted())

    def test_an_unsafe_object_keeps_the_flag(self):
        peerepochs.set_untrusted(self.state_dir, "test")
        (peerepochs.root(self.state_dir) / ("a" * 32)).symlink_to("/tmp")
        out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertFalse(out["cleared"])
        self.assertTrue(self.meta()["epochs_untrusted"])

    def test_a_held_record_is_decided_once_the_flag_clears(self):
        peerepochs.set_untrusted(self.state_dir, "test")
        self.assertTrue(peerjournal._retry_due is not None)
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY))),
                         ("hold", "epoch_store_unavailable"))
        peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY))), "exposure_missing")


class RepairTests(_Epochs):
    """The trust verb repairs what the fail-closed flag holds on: a counted
    file corrupted, an unexpected root entry, each across its crash seam,
    ending with the flag clear and the next start clean."""

    def trust(self):
        try:
            return peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        except Exception as e:  # noqa: BLE001 -- a wrong outcome must FAIL
            return {"cleared": ("raised", type(e).__name__), "problems": [str(e)]}

    def corrupt_counted(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        (path,) = list(peerepochs.root(self.state_dir).rglob("*.json"))
        path.write_text("{not json")
        self.assertEqual(self.decide(payload(sender_since=ts(-2 * DAY))),
                         ("hold", "epoch_store_unavailable"))
        self.assertTrue(self.meta()["epochs_untrusted"], "the fault set the flag")
        return path

    def assert_repaired(self, out):
        self.assertIs(out["cleared"], True, out)
        self.assertFalse(self.meta()["epochs_untrusted"])
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual(rep["problems"], [], "the next start is clean")
        self.assertFalse(self.meta()["epochs_untrusted"], "and stays clear")

    def test_a_corrupted_counted_file_is_repaired(self):
        path = self.corrupt_counted()
        out = self.trust()
        self.assertFalse(path.exists(), "the invalid file is removed")
        self.assert_repaired(out)

    def test_a_corrupted_counted_file_is_repaired_after_a_restart(self):
        self.corrupt_counted()
        self.assertTrue(peerjournal.startup(self.state_dir, NOW)["problems"], "a finding")
        self.assert_repaired(self.trust())

    def test_a_crash_inside_the_recount_is_completed_at_reconcile(self):
        path = self.corrupt_counted()
        with mock.patch.object(peerepochs, "complete_prune",
                               side_effect=SystemExit("crash")):
            with self.assertRaises(SystemExit):
                peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertTrue(path.exists(), "crashed before the removal")
        self.assertTrue(self.meta()["epochs_untrusted"], "the flag survives the crash")
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual(rep["problems"], [], "the recount is completed, not a loss")
        self.assertFalse(path.exists(), "reconcile removed the target")
        self.assert_repaired(self.trust())

    def test_every_unexpected_root_entry_is_removed_or_keeps_the_flag(self):
        r = peerepochs.root(self.state_dir)
        for name, make, cleared in (
                (".rogue", lambda p: p.write_text("x"), True),
                ("rogue", lambda p: p.write_text("x"), True),
                (".rogue-dir", lambda p: p.mkdir(), False),
                (".rogue-link", lambda p: p.symlink_to(self.state_dir), False)):
            with self.subTest(name=name):
                peerepochs.set_untrusted(self.state_dir, "test")
                make(r / name)
                self.assertTrue(any("epoch store" in p for p in
                                    peerjournal.reconcile(self.state_dir)),
                                "a finding at reconcile")
                out = self.trust()
                self.assertIs(out["cleared"], cleared, out)
                self.assertEqual(self.meta()["epochs_untrusted"], not cleared)
                if cleared:
                    self.assertFalse(os.path.lexists(r / name), "removed")
                else:
                    self.assertTrue(any(name in p for p in out["problems"]), out)
                    (r / name).unlink() if (r / name).is_symlink() else (r / name).rmdir()
                    self.assertIs(self.trust()["cleared"], True, "clears once it is gone")

    def test_a_v1_store_beside_any_other_root_entry_is_behind(self):
        import shutil
        for name, make in ((".rogue-dir", lambda p: p.mkdir()),
                           (".rogue", lambda p: p.write_text("x")),
                           ("a" * 32, lambda p: p.mkdir()),
                           (".rogue-link", lambda p: p.symlink_to(self.state_dir))):
            with self.subTest(name=name):
                r = peerepochs.root(self.state_dir)
                shutil.rmtree(r, ignore_errors=True)
                r.mkdir()
                (r / peerjournal.WITNESS).write_text("t" * 64)
                peerclock.write(self.state_dir, dataclasses.replace(
                    peerclock.read(self.state_dir), admission="open"),
                    previous=peerclock.read(self.state_dir))
                StoreTests.to_v1(self)
                make(r / name)
                rep = peerjournal.startup(self.state_dir, NOW)
                self.assertEqual((rep["admission"], rep["why"]),
                                 ("closed", "clock_behind_stores"))
                self.assertEqual(peerclock.read(self.state_dir).admission, "closed")
                self.assertTrue(self.meta()["epochs_untrusted"])

    def test_a_migrated_epoch_token_survives_a_journal_loss(self):
        import shutil
        shutil.rmtree(peerepochs.root(self.state_dir))
        StoreTests.to_v1(self)
        peerjournal.startup(self.state_dir, NOW)
        meta = self.meta()
        self.assertNotEqual(meta["epochs"]["token"], meta["replay"]["token"],
                            "the migration gave the epoch store its own token")
        key = self.take(self.raw())
        self.evaluate(key, hk=tpe.hooks(policy=lambda _p, _h, _r: None))
        shutil.rmtree(peerjournal.record_dir(self.state_dir, tpe.OWNER, key))
        self.assertTrue(peerjournal.startup(self.state_dir, NOW)["problems"], "the journal loss")
        self.assertEqual(self.meta()["epochs"]["token"], meta["epochs"]["token"])
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["problems"], [],
                         "no false epoch loss at the second start")
        self.assertFalse(self.meta()["epochs_untrusted"])


class RootObjectTests(_Epochs):
    """The epoch root itself, and its witness token across a BEHIND
    migration."""

    def test_a_behind_migration_keeps_the_epoch_stores_own_token(self):
        import shutil
        shutil.rmtree(peerepochs.root(self.state_dir))
        StoreTests.to_v1(self)
        peerjournal.startup(self.state_dir, NOW)
        token = self.meta()["epochs"]["token"]
        self.assertNotEqual(token, self.meta()["replay"]["token"], "distinct tokens")
        self.decide(payload(sender_since=ts(-2 * DAY)))
        StoreTests.to_v1(self)                           # the clock restored to v1
        first = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((first["admission"], first["why"]), ("closed", "clock_behind_stores"))
        self.assertEqual(self.meta()["epochs"]["token"], token, "the witness's token carried")
        second = peerjournal.startup(self.state_dir, NOW)
        self.assertFalse([p for p in second["problems"] if "witness" in p], second["problems"])

    def make_root(self, kind):
        import shutil
        r = peerepochs.root(self.state_dir)
        shutil.rmtree(r)
        if kind == "file":
            r.write_text("x")
        else:
            (self.state_dir / "elsewhere").mkdir()
            r.symlink_to(self.state_dir / "elsewhere")
        return r

    def test_a_root_that_is_not_a_directory_is_a_scan_fault(self):
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind):
                self.make_root(kind)
                doc = peerjournal.status_doc(self.state_dir, NOW)["epochs"]
                self.assertIn("not a directory", doc.get("fault") or "", doc)
                self.setUp()

    def test_trust_never_clears_over_a_root_that_is_not_a_directory(self):
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind):
                r = self.make_root(kind)
                peerepochs.set_untrusted(self.state_dir, "test")
                out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
                self.assertIs(out["cleared"], False, out)
                self.assertTrue([p for p in out["problems"] if p.startswith("unsafe object")
                                 and str(r) in p], out["problems"])
                self.assertTrue(os.path.lexists(r), "never removed")
                self.assertTrue(self.meta()["epochs_untrusted"])
                self.setUp()


class UnsafeRootStartupTests(_Epochs):
    """A root that is not a directory survives startup and a bound-B
    rebuild as found: no crash, nothing written through a link or over a
    file, the flag set and the finding repeated at every start."""

    def unsafe(self, kind):
        r = RootObjectTests.make_root(self, kind)
        target = self.state_dir / "elsewhere"
        return r, target

    def assert_left_as_found(self, r, target, kind):
        self.assertEqual(r.is_symlink(), kind == "symlink")
        if kind == "file":
            self.assertEqual(r.read_text(), "x", "never written over")
        else:
            self.assertEqual(list(target.iterdir()), [], "nothing written through the link")
        self.assertTrue(self.meta()["epochs_untrusted"])

    def test_two_startups_over_an_unsafe_root(self):
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind):
                r, target = self.unsafe(kind)
                for n in (1, 2):
                    try:
                        rep = peerjournal.startup(self.state_dir, NOW)
                    except Exception as e:  # noqa: BLE001 -- a crash must FAIL
                        rep = {"problems": [], "raised": type(e).__name__}
                    self.assertNotIn("raised", rep, f"startup {n}")
                    self.assertTrue([p for p in rep["problems"] if "epoch store" in p],
                                    f"startup {n}: {rep}")
                    self.assert_left_as_found(r, target, kind)
                self.setUp()

    def test_a_rebuild_under_bound_b_over_an_unsafe_root(self):
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind):
                r, target = self.unsafe(kind)
                StoreTests.bound(self)
                try:
                    peerjournal.rebuild_meta(self.state_dir)
                    raised = None
                except Exception as e:  # noqa: BLE001 -- a crash must FAIL
                    raised = type(e).__name__
                self.assertIsNone(raised)
                self.assert_left_as_found(r, target, kind)
                self.setUp()


class TrustWitnessTests(_Epochs):
    """The trust verb leaves the epoch root holding the exact witness with
    the recorded token, and the next start finds no witness loss."""

    def shape(self, kind):
        import shutil
        r = peerepochs.root(self.state_dir)
        if kind == "absent root":
            shutil.rmtree(r)
        elif kind == "no witness":
            (r / peerjournal.WITNESS).unlink()
        else:
            (r / peerjournal.WITNESS).write_text("f" * 64)
        peerepochs.set_untrusted(self.state_dir, "test")

    def test_each_witness_shape_is_restored_and_the_next_start_is_clean(self):
        for kind in ("absent root", "no witness", "another token"):
            with self.subTest(kind=kind):
                self.shape(kind)
                out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
                self.assertIs(out["cleared"], True, out)
                w = peerepochs.root(self.state_dir) / peerjournal.WITNESS
                self.assertEqual(w.read_text(), self.meta()["epochs"]["token"])
                rep = peerjournal.startup(self.state_dir, NOW)
                self.assertFalse([p for p in rep["problems"] if "witness" in p], rep["problems"])
                self.assertFalse(self.meta()["epochs_untrusted"], "and stays clear")
                self.setUp()

    def test_without_the_restore_the_final_check_keeps_the_flag(self):
        for kind in ("absent root", "no witness", "another token"):
            with self.subTest(kind=kind):
                self.shape(kind)
                with mock.patch.object(peerepochs, "_restore_root_witness", lambda _sd: None):
                    out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
                self.assertIs(out["cleared"], False, out)
                self.assertTrue([p for p in out["problems"] if "exact witness" in p], out)
                self.assertTrue(self.meta()["epochs_untrusted"])
                self.setUp()

    def test_the_v1_path_with_the_witness_removed_ends_clean(self):
        self.decide(payload(sender_since=ts(-2 * DAY)))
        (peerepochs.root(self.state_dir) / peerjournal.WITNESS).unlink()
        StoreTests.to_v1(self)
        first = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((first["admission"], first["why"]), ("closed", "clock_behind_stores"))
        self.assertIs(peerepochs.operator_trust(self.state_dir, NOW, evidence="x")["cleared"], True)
        second = peerjournal.startup(self.state_dir, NOW)
        self.assertFalse([p for p in second["problems"] if "witness" in p], second["problems"])

    def test_a_scan_fault_reports_no_derived_counts(self):
        RootObjectTests.make_root(self, "file")
        peerepochs.set_untrusted(self.state_dir, "test")
        out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertFalse([p for p in out["problems"] if "-1" in p or "two files" in p], out)


class TrustCrashTests(_Epochs):
    """The trust verb's crash seams: each crash leaves the flag set, and a
    re-run completes and clears it, idempotently."""

    place_with_since = TrustVerbTests.place_with_since

    def two_pairs(self):
        self.place_with_since(ts(-3 * DAY), "qPlaced0123456789abcde")
        key = self.take(self.raw(sender_since=ts(-4 * DAY), id="qOther00123456789abcde",
                                 **{"from": f"other@{T1}"}))
        self.evaluate(key, hk=tpe.hooks(policy=lambda _p, _h, _r: None))
        import shutil
        shutil.rmtree(peerepochs.root(self.state_dir))
        peerepochs.root(self.state_dir).mkdir()
        (peerepochs.root(self.state_dir) / peerjournal.WITNESS).write_text(
            self.meta()["epochs"]["token"])
        meta = self.meta()
        meta["epochs"] = dict(meta["epochs"], live=0, content_sum="0")
        meta["epochs_untrusted"] = True
        peerjournal._write_meta(self.state_dir, meta)

    def rerun_clears(self):
        out = peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertIs(out["cleared"], True, out)
        self.assertEqual((self.accepted(), self.accepted(f"other@{T1}")),
                         (ts(-3 * DAY), ts(-4 * DAY)), "both pairs reseeded")
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["problems"], [])
        again = peerepochs.operator_trust(self.state_dir, NOW, evidence="again")
        self.assertIs(again["cleared"], True, "idempotent")

    def test_a_crash_mid_reseed_then_a_rerun_completes(self):
        self.two_pairs()
        real, calls = peerepochs._link, []

        def link(path, data):
            calls.append(path)
            real(path, data)
            if len(calls) == 2:
                raise SystemExit("crash after the second file, before its counts")
        with mock.patch.object(peerepochs, "_link", link), self.assertRaises(SystemExit):
            peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertTrue(self.meta()["epochs_untrusted"], "the flag survives the crash")
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["problems"], [],
                         "the reseed write is completed at reconcile")
        self.rerun_clears()

    def test_a_crash_before_the_final_clear_leaves_the_flag_set(self):
        self.two_pairs()
        real = peerjournal._write_meta

        def write_meta(state_dir, meta):
            if not meta["epochs_untrusted"]:
                raise SystemExit("crash at the clear")
            return real(state_dir, meta)
        with mock.patch.object(peerjournal, "_write_meta", write_meta), \
                self.assertRaises(SystemExit):
            peerepochs.operator_trust(self.state_dir, NOW, evidence="checked")
        self.assertTrue(self.meta()["epochs_untrusted"], "never cleared before its write")
        self.rerun_clears()


class SinceStartCountTests(_Epochs):
    """Status counts SINCE START: counted when written, through the real
    transition and hold paths; a new process starts again at zero while the
    records are still there."""

    def counts(self):
        doc = peerjournal.status_doc(self.state_dir, NOW)["epochs"]
        return (doc["refusals"]["quarantined"], doc["exposure_signer_demotions"],
                doc["epoch_store_unavailable_holds"])

    def test_counted_when_written_and_forgotten_by_a_new_process(self):
        from router import hoplink
        hoplink.reset_process_state()
        self.addCleanup(hoplink.reset_process_state)
        quarantine = tpe.hooks(policy=lambda _p, _h, _r: peerjournal.Refuse("policy",
                                                                            "quarantined"))
        self.evaluate(self.take(self.raw(id="qQuarant0123456789abcd")), hk=quarantine)
        self.evaluate(self.take(self.raw(id="qDemoted0123456789abcd")),
                      hk=tpe.hooks(check8=lambda _p, _k: "exposure_signer"))
        held = self.take(self.raw(id="qHeld0000123456789abcd"))
        hold = tpe.hooks(policy=lambda _p, _h, _r: peerjournal.Hold("epoch_store_unavailable"))
        self.evaluate(held, hk=hold)
        self.evaluate(held, hk=hold)                       # the same hold: counted once
        self.assertEqual(self.counts(), (1, 1, 1))
        hoplink.reset_process_state()
        self.assertEqual(self.counts(), (0, 0, 0), "since start, not over retained records")
        self.assertEqual(peerjournal.status_doc(self.state_dir, NOW)["epochs"]["counted"],
                         "since_start")


class ConfigRefusalTests(tpe._Eval):

    def test_a_delegation_naming_an_overlay_is_refused_by_its_own_check(self):
        from router.tests import test_peerlane as tpl
        base = tpl.DelegationConfigTests("test_" if False else "run")
        base.tmp, base.state_dir = self.tmp, self.state_dir
        for key in ("exposure_required", "min_sender_age_s", "sender_since_policy"):
            with self.subTest(key=key):
                doc = tpl.DelegationConfigTests.doc(base, **{key: False})
                with self.assertRaises(config_mod.ConfigError) as cm:
                    config_mod.load_obj(doc)
                self.assertIn("fixed by the production profile", str(cm.exception))
