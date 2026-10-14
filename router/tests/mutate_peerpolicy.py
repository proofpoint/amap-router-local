"""Single-rule mutants for the receiver's exposure check, sender-age policy
and epoch store (`router/peerpolicy.py`, `router/peerepochs.py`, `store.v` 2
in `router/peerjournal.py`, the overlay refusal in `router/config.py`), each
run against the test that names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_peerpolicy.py

Same discipline as `mutate_peerledger.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after, and a mutant is RED only when unittest reports the named test as a
FAILURE (an ERROR is not red). Exit 0 only when the named tests are green
unmutated and every mutant turns every named test red. Not a test module
itself (its name keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

E = "router.tests.test_peerepochs."
L = "router.tests.test_peerledger."
POL, EP, PJ, CF = ("router/peerpolicy.py", "router/peerepochs.py", "router/peerjournal.py",
                   "router/config.py")
HL = "router/hoplink.py"

M = [
 ("PP1 a delegation naming an overlay loads", CF,
  '    if overlays:\n        raise ConfigError(f"{where}: {overlays}: the exposure',
  '    if False:\n        raise ConfigError(f"{where}: {overlays}: the exposure',
  [E + "ConfigRefusalTests.test_a_delegation_naming_an_overlay_is_refused_by_its_own_check"]),
 ("PP2 production without an age policy", POL,
  'PRODUCTION_POLICY = PolicyPart(exposure_required=True, min_sender_age_s=86400)\n',
  'PRODUCTION_POLICY = PolicyPart(exposure_required=True, min_sender_age_s=None)\n',
  [L + "BuilderTests.test_production_is_the_pinned_real_policy"]),
 ("PP3 production with exposure optional", POL,
  'PRODUCTION_POLICY = PolicyPart(exposure_required=True, min_sender_age_s=86400)\n',
  'PRODUCTION_POLICY = PolicyPart(exposure_required=False, min_sender_age_s=86400)\n',
  [L + "BuilderTests.test_production_is_the_pinned_real_policy"]),
 ("PP4 a receiver patch of 0 read as no policy", POL,
  '    age = patch["min_sender_age_s"] if "min_sender_age_s" in patch else None\n',
  '    age = patch.get("min_sender_age_s") or None\n',
  [E + "ConformanceMappingTests.test_the_receiver_patch_maps_absent_to_none_and_keeps_zero"]),
 ("PP5 the epoch store consulted with no age policy", POL,
  '        if part.min_sender_age_s is not None:\n            since = payload.get("sender_since")\n',
  '        if True:\n            since = payload.get("sender_since")\n',
  [E + "PolicyOrderTests.test_with_no_age_policy_the_epoch_store_is_never_consulted"]),
 ("PP6 exposure missing before the age rules", POL,
  '        if part.min_sender_age_s is not None:\n            since = payload.get("sender_since")\n',
  '        if part.exposure_required and payload.get("sender_exposure") is None:\n'
  '            return peerjournal.Refuse("policy", EXPOSURE_MISSING)\n'
  '        if part.min_sender_age_s is not None:\n            since = payload.get("sender_since")\n',
  [E + "PolicyOrderTests.test_age_missing_records_nothing"]),
 ("PP7 quarantined before the consistency step", POL,
  '            try:\n                seen = peerepochs.consult(',
  '            if (ctx.now - parse_utc_ts(since)).total_seconds() < part.min_sender_age_s:\n'
  '                return peerjournal.Refuse("policy", QUARANTINED)\n'
  '            try:\n                seen = peerepochs.consult(',
  [E + "PolicyOrderTests.test_inconsistent_before_quarantined",
   E + "PolicyOrderTests.test_a_later_epoch_is_persisted_and_audited_before_the_age_test"]),
 ("PP8 an earlier epoch persisted", EP,
  '    if old is not None and claim < old:\n        return INCONSISTENT\n',
  '    if old is not None and claim < old:\n        write_epoch(state_dir, runtime, from_canon, claim)\n        return INCONSISTENT\n',
  [E + "PolicyOrderTests.test_an_earlier_epoch_is_inconsistent_and_persists_nothing"]),
 ("PP9 an accepted epoch not audited", EP,
  '    _audit(state_dir, now, runtime=runtime, **{"from": from_canon}, old=old, new=claim)\n',
  '',
  [E + "PolicyOrderTests.test_a_later_epoch_is_persisted_and_audited_before_the_age_test"]),
 ("PP10 a future sender_since passes", POL,
  '            if age < part.min_sender_age_s:\n',
  '            if 0 <= age < part.min_sender_age_s:\n',
  [E + "PolicyOrderTests.test_a_future_sender_since_is_quarantined_and_persisted"]),
 ("PP11 exactly 24 hours quarantined", POL,
  '            if age < part.min_sender_age_s:\n',
  '            if age <= part.min_sender_age_s:\n',
  [E + "PolicyOrderTests.test_exactly_24_hours_passes_and_one_second_less_is_quarantined"]),
 ("PP12 the age measured from ts", POL,
  '            age = (ctx.now - parse_utc_ts(since)).total_seconds()\n',
  '            age = (parse_utc_ts(payload["ts"]) - parse_utc_ts(since)).total_seconds()\n',
  [E + "PolicyOrderTests.test_age_is_measured_on_the_routers_clock_not_ts"]),
 ("PP13 check 8's domain compared case-sensitively", POL,
  '    return al == bl and ad.isascii() and bd.isascii() and ad.lower() == bd.lower()\n',
  '    return al == bl and ad.isascii() and bd.isascii() and ad == bd\n',
  [E + "Check8Tests.test_the_key_owners_runtime_passes_and_a_domain_case_variant_too"]),
 ("PP14 check 8's local part casefolded", POL,
  '    return al == bl and ad.isascii() and bd.isascii() and ad.lower() == bd.lower()\n',
  '    return al.lower() == bl.lower() and ad.isascii() and bd.isascii() and ad.lower() == bd.lower()\n',
  [E + "Check8Tests.test_a_local_part_case_variant_and_the_receivers_own_runtime_fail"]),
 ("PP15 check 8 accepting the receiver's own runtime", POL,
  '        if runtime is None or not _same_address(asserted, runtime.runtime):\n',
  '        if runtime is None or not (_same_address(asserted, runtime.runtime) or _same_address(asserted, f"amap.router@{ctx.cfg.fleet_domain}")):\n',
  [E + "Check8Tests.test_a_local_part_case_variant_and_the_receivers_own_runtime_fail"]),
 ("PP16 check 8 reading exposure_required", POL,
  '        if exposure is None:\n            return None\n',
  '        if exposure is None or not profile.policy.exposure_required:\n            return None\n',
  [E + "Check8Tests.test_check_8_is_profile_independent"]),
 ("PP17 the epoch key from the raw from", EP,
  '    from . import peerledger\n    return peerledger.canonical(address)\n',
  '    return address\n',
  [E + "PolicyOrderTests.test_the_epoch_key_is_canonical_and_never_alias_merged"]),
 ("PP18 a read fault read as no record", EP,
  '    except EpochFault as e:\n        set_untrusted(state_dir, e.reason)\n        raise\n',
  '    except EpochFault:\n        old = None\n',
  [E + "FaultTests.test_a_read_fault_holds_and_sets_the_flag"]),
 ("PP19 a read fault holds without the flag", EP,
  '    except EpochFault as e:\n        set_untrusted(state_dir, e.reason)\n        raise\n',
  '    except EpochFault as e:\n        raise\n',
  [E + "FaultTests.test_a_read_fault_holds_and_sets_the_flag"]),
 ("PP20 a fault refused, not held", POL,
  '                return peerjournal.Hold(EPOCH_STORE_UNAVAILABLE)\n',
  '                return peerjournal.Refuse("policy", EPOCH_STORE_UNAVAILABLE)\n',
  [E + "FaultTests.test_a_read_fault_holds_and_sets_the_flag"]),
 ("PP21 the flag holds every statement", POL,
  '        if part.min_sender_age_s is not None:\n            since = payload.get("sender_since")\n',
  '        if peerjournal.read_meta(ctx.state_dir)["epochs_untrusted"]:\n'
  '            return peerjournal.Hold(EPOCH_STORE_UNAVAILABLE)\n'
  '        if part.min_sender_age_s is not None:\n            since = payload.get("sender_since")\n',
  [E + "FaultTests.test_the_flag_spares_what_never_reaches_the_consistency_step"]),
 ("PP22 the prune skipped", EP,
  '    prune_older(state_dir, runtime, from_canon)\n    return ACCEPTED\n',
  '    return ACCEPTED\n',
  [E + "PolicyOrderTests.test_one_file_per_pair"]),
 ("PP23 a non-canonical name accepted", EP,
  '    if stem is None or not _CANON_TS.fullmatch(stem) or canonical_ts(stem) != stem:\n',
  '    if stem is None:\n',
  [E + "FaultTests.test_a_non_canonical_name_is_a_fault"]),
 ("PP24 a body naming another pair accepted", EP,
  '    if pair_dir(path.parents[2].parent, doc["runtime"], doc["from"]) != path.parent:\n',
  '    if False:\n',
  [E + "FaultTests.test_a_body_naming_another_pair_is_a_fault"]),
 ("PP25 the flag cleared by the rebase", PJ,
  '    meta["epochs_untrusted"] = fault or prior is None or bool(prior.get("epochs_untrusted"))\n',
  '    meta["epochs_untrusted"] = fault or prior is None\n',
  [E + "StoreTests.test_deleting_the_only_file_is_loss_and_sets_the_flag"]),
 ("PP26 the flag clear after a lost clock file", PJ,
  '    meta["epochs_untrusted"] = fault or prior is None or bool(prior.get("epochs_untrusted"))\n',
  '    meta["epochs_untrusted"] = fault or bool((prior or {}).get("epochs_untrusted"))\n',
  [E + "StoreTests.test_a_rebuild_under_bound_b_without_prior_bookkeeping_sets_the_flag"]),
 ("PP27 the flag set on a journal loss", PJ,
  '        clock = peerclock.raise_floor_for_loss(state_dir, now)\n',
  '        clock = peerclock.raise_floor_for_loss(state_dir, now)\n'
  '        from . import peerepochs as _pe\n        _pe.set_untrusted(state_dir, "any loss")\n',
  [E + "StoreTests.test_a_journal_loss_with_the_clock_intact_leaves_the_flag_clear"]),
 ("PP28 reconcile prunes a pair despite a finding", PJ,
  '    if found:\n        meta["epochs_untrusted"] = True\n    elif midprune:\n',
  '    if found:\n        meta["epochs_untrusted"] = True\n    if midprune:\n',
  [E + "StoreTests.test_a_two_file_pair_beside_a_loss_is_kept"]),
 ("PP29 a pair mid-prune never completed", PJ,
  '        peerepochs.complete_pairs(state_dir)\n        meta.update(read_meta(state_dir))\n',
  '        meta.update(read_meta(state_dir))\n',
  [E + "StoreTests.test_a_crash_between_link_and_prune_is_completed_at_reconcile"]),
 ("PP30 an epoch finding ignored", PJ,
  '    if found:\n        meta["epochs_untrusted"] = True\n    elif midprune:\n',
  '    if False:\n        meta["epochs_untrusted"] = True\n    elif midprune:\n',
  [E + "StoreTests.test_deleting_the_only_file_is_loss_and_sets_the_flag"]),
 ("PP31 migration over existing epoch files", PJ,
  '    if beside:\n        peerclock.close(',
  '    if False:\n        peerclock.close(',
  [E + "StoreTests.test_a_v1_store_beside_epoch_files_is_behind_and_flagged"]),
 ("PP32 a v1 store read as complete", PJ,
  '    if isinstance(store, dict) and store.get("v") == 1 and set(store) == set(_V1_MEMBERS):\n'
  '        raise StoreV1(',
  '    if False:\n        raise StoreV1(',
  [E + "StoreTests.test_a_v1_store_is_never_read_as_an_empty_epoch_store"]),
 ("PP33 a leftover migration root not re-adopted", PJ,
  '    token = leftover or secrets.token_hex(32)\n',
  '    token = secrets.token_hex(32)\n',
  [E + "StoreTests.test_a_leftover_root_from_a_crashed_migration_is_readopted"]),
 ("PP34 reconcile ignores the epoch delta", PJ,
  '    if _rolled(entry, d, live, total, 0):\n',
  '    if _rolled(entry, None, live, total, 0):\n',
  [E + "StoreTests.test_the_epoch_intent_is_reconciled_at_each_crash_point"]),
 ("PP35 the trust verb reseeds from an inconsistent record", EP,
  'RESEED_CODES = frozenset({"quarantined", "exposure_missing"})\n',
  'RESEED_CODES = frozenset({"quarantined", "exposure_missing", "sender_since_inconsistent"})\n',
  [E + "TrustVerbTests.test_an_inconsistent_record_is_never_reseeded"]),
 ("PP36 the flag cleared despite a problem", EP,
  '    if not problems:\n        meta = pj.read_meta(state_dir)\n        meta["epochs_untrusted"] = False\n',
  '    if True:\n        meta = pj.read_meta(state_dir)\n        meta["epochs_untrusted"] = False\n',
  [E + "TrustVerbTests.test_an_unsafe_object_keeps_the_flag"]),
 ("PP37 the trust verb does not reseed", EP,
  '            if old is None or claim > old:\n                write_epoch(state_dir, runtime, from_canon, claim)\n',
  '            if False:\n                write_epoch(state_dir, runtime, from_canon, claim)\n',
  [E + "TrustVerbTests.test_reseed_from_placed_records_then_clear"]),
 ("PP38 an epoch hold never re-tried", PJ,
  '            return not read_meta(ctx.state_dir)["epochs_untrusted"]\n',
  '            return False\n',
  [E + "HeldRecordTests.test_a_record_held_on_the_epoch_store_is_decided_once_the_flag_clears"]),
 ("PP39 declare-restored leaves the flag clear", PJ,
  '        peerepochs.set_untrusted(state_dir, "declared restored")\n',
  '        pass\n',
  [E + "StoreTests.test_declare_restored_sets_the_flag"]),
 ("PP40 status without the epoch section", PJ,
  '    doc["epochs"] = _epochs_status(state_dir, meta)\n',
  '    doc["epochs"] = {"pairs": None, "pairs_mid_prune": None, "untrusted": None}\n',
  [E + "StoreTests.test_status_shows_the_epoch_section"]),
 ("PP41 init without the epoch root", PJ,
  '    eroot.mkdir(mode=0o700)\n    atomic_write(eroot / WITNESS, clock.store_token.encode("ascii"), durable_root=state_dir)\n',
  '',
  [E + "StoreTests.test_init_writes_store_v2_with_the_epoch_root"]),
 ("PP42 the BEHIND migration writes v2 before it closes admission", PJ,
  '    if beside:\n'
  '        peerclock.close(state_dir, peerclock.read(state_dir),\n'
  '                        "a store.v 1 record beside epoch files")\n'
  '        doc = peerclock.read_doc(state_dir)\n'
  '        store = dict(doc["store"])\n'
  '        token = leftover or store["replay"]["token"]\n'
  '        live, total, _p, _m = (0, 0, 0, 0)\n'
  '        try:\n'
  '            live, total, _p, _m = peerepochs.scan(state_dir)\n'
  '        except peerepochs.EpochFault:\n'
  '            pass\n'
  '        store.update(v=STORE_V, epochs=dict(_epochs_entry(token), live=live,\n'
  '                                            content_sum=str(total)),\n'
  '                     epochs_untrusted=True)\n'
  '        doc["store"] = store\n'
  '        peerclock.write_doc(state_dir, doc)\n'
  '        return "behind"\n',
  '    if beside:\n'
  '        token = leftover or store["replay"]["token"]\n'
  '        live, total, _p, _m = (0, 0, 0, 0)\n'
  '        try:\n'
  '            live, total, _p, _m = peerepochs.scan(state_dir)\n'
  '        except peerepochs.EpochFault:\n'
  '            pass\n'
  '        store.update(v=STORE_V, epochs=dict(_epochs_entry(token), live=live,\n'
  '                                            content_sum=str(total)),\n'
  '                     epochs_untrusted=True)\n'
  '        doc["store"] = store\n'
  '        peerclock.write_doc(state_dir, doc)\n'
  '        peerclock.close(state_dir, peerclock.read(state_dir),\n'
  '                        "a store.v 1 record beside epoch files")\n'
  '        return "behind"\n',
  [E + "StoreTests.test_a_crash_at_the_behind_close_leaves_admission_closed_on_restart"]),
 ("PP43 the trust recount keeps the old counts", EP,
  '    meta["epochs"] = dict(meta["epochs"], live=live, content_sum=str(total))\n', '',
  [E + "RepairTests.test_a_corrupted_counted_file_is_repaired"]),
 ("PP44 the trust recount counts the files it removes", EP,
  '    live, total, _pairs, _mid = scan(state_dir, skip=frozenset(targets))\n',
  '    live, total, _pairs, _mid = scan(state_dir)\n',
  [E + "RepairTests.test_a_corrupted_counted_file_is_repaired"]),
 ("PP45 reconcile leaves a pending recount's targets", PJ,
  '        for target in op["targets"]:\n            peerepochs.complete_prune(Path(target))\n',
  '        pass\n',
  [E + "RepairTests.test_a_crash_inside_the_recount_is_completed_at_reconcile"]),
 ("PP46 scan skips dot-named root entries", EP,
  '        if is_witness(rtdir) or rtdir in skip:\n',
  '        if rtdir.name.startswith(".") or rtdir in skip:\n',
  [E + "RepairTests.test_every_unexpected_root_entry_is_removed_or_keeps_the_flag"]),
 ("PP47 the trust verb skips dot-named root entries", EP,
  '        if is_witness(rtdir):\n            continue\n        if not _real_dir(rtdir, _HEX32):\n'
  '            bad.append(rtdir)\n',
  '        if rtdir.name.startswith("."):\n            continue\n        if not _real_dir(rtdir, _HEX32):\n'
  '            bad.append(rtdir)\n',
  [E + "RepairTests.test_every_unexpected_root_entry_is_removed_or_keeps_the_flag"]),
 ("PP48 migration checks only for epoch files", PJ,
  '        beside = eroot.is_dir() and any(not peerepochs.is_witness(e) for e in eroot.iterdir())\n',
  '        beside = eroot.is_dir() and any(p.is_file() and p.name != WITNESS\n'
  '                                        for p in eroot.rglob("*"))\n',
  [E + "RepairTests.test_a_v1_store_beside_any_other_root_entry_is_behind"]),
 ("PP49 the loss rebase renames the epoch token", PJ,
  '        meta["epochs"])), epoch_token=meta["epochs"]["token"]))',
  '        meta["epochs"]))))',
  [E + "RepairTests.test_a_migrated_epoch_token_survives_a_journal_loss"]),
 ("PP50 the trust verb clears the flag before the reseed", EP,
  '    if not problems:\n        for (runtime, from_canon), claim in sorted(',
  '    if not problems:\n        _m = pj.read_meta(state_dir)\n        _m["epochs_untrusted"] = False\n'
  '        pj._write_meta(state_dir, _m)\n        for (runtime, from_canon), claim in sorted(',
  [E + "TrustCrashTests.test_a_crash_mid_reseed_then_a_rerun_completes"]),
 ("PP51 a disposition is not counted", PJ,
  '    EPOCH_COUNTS[key] = EPOCH_COUNTS.get(key, 0) + 1\n', '    return\n',
  [E + "SinceStartCountTests.test_counted_when_written_and_forgotten_by_a_new_process"]),
 ("PP52 the counts outlive the process", HL,
  '"_POLLED", "EPOCH_COUNTS"),', '"_POLLED"),',
  [E + "SinceStartCountTests.test_counted_when_written_and_forgotten_by_a_new_process"]),
 ("PP53 an epoch hold counted on every retry", PJ,
  '    if held and (held["reason"], held["detail"]) == (reason, detail):\n        return record\n',
  '    if held and (held["reason"], held["detail"]) == (reason, detail):\n'
  '        if reason == "epoch_store_unavailable":\n'
  '            EPOCH_COUNTS["held:epoch_store_unavailable"] = \\\n'
  '                EPOCH_COUNTS.get("held:epoch_store_unavailable", 0) + 1\n'
  '        return record\n',
  [E + "SinceStartCountTests.test_counted_when_written_and_forgotten_by_a_new_process"]),
]


def _red(r) -> bool:
    """RED only when the named test FAILED (an assertion in it did not
    hold); an ERROR proves the mutant broke something, not that the test
    pins the rule."""
    out = r.stdout + r.stderr
    return (r.returncode != 0 and "\nFAIL: " in "\n" + out
            and "FAILED (failures=" in out)


def _clear() -> None:
    for d in pathlib.Path("router").rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    ok = True
    _clear()
    named = sorted({t for *_, tests in M for t in tests})
    clean = subprocess.run([sys.executable, "-B", "-m", "unittest", *named],
                           capture_output=True, text=True)
    if clean.returncode != 0:
        print("the named tests are not green on unmutated code:\n" + clean.stderr[-2000:])
        return 1
    for label, f, old, new, tests in M:
        path = pathlib.Path(f)
        orig = path.read_text()
        if orig.count(old) != 1:
            print(f"{label}: ANCHOR FOUND {orig.count(old)} TIMES")
            ok = False
            continue
        path.write_text(orig.replace(old, new))
        _clear()
        try:
            for t in tests:
                r = subprocess.run([sys.executable, "-B", "-m", "unittest", t],
                                   capture_output=True, text=True)
                red = _red(r)
                ok &= red
                verdict = "RED" if red else ("ERROR only (not RED)" if r.returncode
                                             else "GREEN (survived)")
                print(f"{label:52s} {t.split('.')[-1][:58]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
