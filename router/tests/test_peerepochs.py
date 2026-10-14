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
from datetime import timedelta

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
