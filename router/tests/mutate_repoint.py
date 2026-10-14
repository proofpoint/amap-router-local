"""Single-rule mutants for the runtime capability at PLUGIN_API (3, 5)
(`router/peercontrol.py`, the settling write row in `router/inflight.py` and
`router/hoplink.py`, the own address in `router/config.py`), each run against
the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_repoint.py

Same discipline as `mutate_peerledger.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after, and a mutant is RED only when unittest reports the named test as a
FAILURE (an ERROR is not red). Not a test module itself. It mutates the
checkout in place: run it only in a private worktree.
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_runtime_repoint."
PC, INF, HL, TR, CF = ("router/peercontrol.py", "router/inflight.py", "router/hoplink.py",
                       "router/transport.py", "router/config.py")

M = [
 ("R1 the table does not name admit", TR,
  '    "admit": "admit",\n', '',
  [T + "SettingsTests.test_the_capability_table_names_admit"]),
 ("R1 caps left out of the sender settings", PC,
  '                    "version_write": version, "caps": dict(self.cfg.hop.caps)}\n',
  '                    "version_write": version}\n',
  [T + "SettingsTests.test_the_sender_settings_are_the_closed_six_from_the_pin_and_the_caps"]),
 ("R1 version_write from the config, not the pin", PC,
  '        version = pin.get("version_write") if isinstance(pin, dict) else None\n',
  '        version = None\n',
  [T + "SettingsTests.test_the_sender_settings_are_the_closed_six_from_the_pin_and_the_caps"]),
 ("R1 a port without its pin", PC,
  '            if port:\n                raise Unavailable(UNAVAILABLE, f"generation {generation} has no pinned "\n',
  '            if False:\n                raise Unavailable(UNAVAILABLE, f"generation {generation} has no pinned "\n',
  [T + "SettingsTests.test_a_port_needs_the_pin_and_a_reader_does_not"]),
 ("R2 no admission before the port", PC,
  '    _admit(cfg, cap, port, attempt["gen"])\n', '',
  [T + "AdmitTests.test_admit_is_the_first_port_call_with_the_minted_time"]),
 ("R2 a record/pin disagreement re-admits", PC,
  '    if rec is not None and rec[0] == gen and rec[1] != at:\n',
  '    if False:\n',
  [T + "AdmitTests.test_a_record_and_pin_that_disagree_hold_and_never_admit"]),
 ("R2 adopt stamps now", PC,
  '        record_generation(cfg, d["generation"], admitted_at=at)\n',
  '        record_generation(cfg, d["generation"], admitted_at=format_utc_ts(now))\n',
  [T + "AdmitTests.test_an_adopt_plan_replayed_writes_the_same_bytes"]),
 ("R2 a listed restore stamps now", PC,
  '    if listed is not None:\n        ident = cap.identity(gen)\n',
  '    if False:\n        ident = cap.identity(gen)\n',
  [T + "AdmitTests.test_a_listed_live_restore_copies_the_identity"]),
 ("R2 new stamps now", PC,
  '        record_generation(cfg, d["minted"], admitted_at=marker["at"])   # the plan\'s time\n',
  '        record_generation(cfg, d["minted"], admitted_at=format_utc_ts(now))\n',
  [T + "AdmitTests.test_a_new_plan_replayed_uses_the_plans_time"]),
 ("R3 no settling row", INF,
  '        settles = hoplink.settle_for_write(e) if name == config_mod.RUNTIME_NS else None\n',
  '        settles = None\n',
  [T + "SettleTests.test_a_retired_generation_at_write_request_settles_rejected_and_cleans_up"]),
 ("C4 the settling row asked after the latched row", INF,
  '        settles = hoplink.settle_for_write(e) if name == config_mod.RUNTIME_NS else None\n',
  '        settles = (hoplink.settle_for_write(e) if hoplink.latch_for_write(e) is None\n'
  '                   and name == config_mod.RUNTIME_NS else None)\n',
  [T + "SettleTests.test_the_settle_row_is_asked_before_the_latched_and_retried_rows"]),
 ("R3 generation_retired not a settling reason", HL,
  '    "generation_retired": "rejected",\n', '',
  [T + "SettleTests.test_a_retired_generation_at_write_request_settles_rejected_and_cleans_up"]),
 ("R3 the settlement's reason dropped", PC,
  '        if verdict.get("reason_code") is not None:\n            settled["reason_code"] = verdict["reason_code"]\n',
  '',
  [T + "SettleTests.test_a_retired_generation_at_write_request_settles_rejected_and_cleans_up"]),
 ("R3 a crashed cleanup never completed", PC,
  '    cleaned = finish_settled(cfg)\n', '    cleaned = 0\n',
  [T + "SettleTests.test_a_crash_between_the_settlement_and_the_cleanup_completes"]),
 ("R3/N3a a port anomaly before the hand-over escapes", PC,
  '        reason = anomaly_reason(e)\n        if reason is None:\n            raise\n        raise Unavailable(UNAVAILABLE, f"the runtime port for',
  '        reason = None\n        if reason is None:\n            raise\n        raise Unavailable(UNAVAILABLE, f"the runtime port for',
  [T + "SettleTests.test_a_retired_generation_before_the_handed_marker_holds",
   T + "AnomalyTests.test_a_sender_method_anomaly_holds"]),
 ("R4 retire plans over an unreadable target", PC,
  '    if listed[gen] == "unreadable":\n', '    if False:\n',
  [T + "UnreadableTests.test_retire_refuses_an_unreadable_target_before_any_plan"]),
 ("R4b the hold names retire for an unreadable one", PC,
  '    if unreadable:\n        return f"{unreadable[0]} is unreadable: {REPAIR_EXIT}"\n', '',
  [T + "UnreadableTests.test_each_exit_names_the_repair_for_unreadable_and_adopt_or_retire_for_live"]),
 ("R4b abandon-attempt names adopt or retire", PC,
  '    if state == "unreadable":\n        raise ValueError(f"the attempt\'s generation {gen} is unreadable: {REPAIR_EXIT}")\n',
  '',
  [T + "UnreadableTests.test_abandon_attempt_names_the_repair_for_an_unreadable_generation"]),
 ("R6 a capability anomaly escapes", PC,
  '            reason = anomaly_reason(e)\n            if reason is None:\n                raise\n            raise Unavailable(UNAVAILABLE, f"{what}: {reason}: {e}") from None\n',
  '            raise\n',
  [T + "AnomalyTests.test_a_stray_entry_holds_the_pass_and_status_names_it"]),
 ("N3b the own address keeps its case", CF,
  '    domain = fleet_domain.lower() if fleet_domain.isascii() else fleet_domain\n',
  '    domain = fleet_domain\n',
  [T + "AddressTests.test_the_one_construction_lowercases_and_every_surface_takes_it",
   T + "AddressTests.test_an_authored_dsn_is_from_the_lowercase_address",
   T + "AddressTests.test_an_exposure_stamp_is_asserted_by_the_lowercase_address",
   T + "AddressTests.test_the_handed_envelope_and_control_statement_are_from_the_lowercase_address"]),
 ("N3b the runtime address built apart", PC,
  '    address = config_mod.router_address(cfg.fleet_domain)\n    if address is None:\n',
  '    address = f"amap.router@{cfg.fleet_domain}"\n    if address is None:\n',
  [T + "AddressTests.test_no_module_but_config_builds_the_own_address"]),
 ("R3 the settling row ungated: an agent tree settles", INF,
  '        settles = hoplink.settle_for_write(e) if name == config_mod.RUNTIME_NS else None\n',
  '        settles = hoplink.settle_for_write(e)\n',
  ["router.tests.test_hoplink_write_table.RetryTests"
   ".test_generation_retired_from_an_agent_tree_is_retried_never_settled"]),
 ("R2 the record before the pin", PC,
  '    atomic_write(pin, hoplink.canonical(hoplink.pin_doc(cfg.hop, admitted_at)),\n'
  '                 durable_root=cfg.state_dir)\n'
  '    atomic_write(d / config_mod.RUNTIME_GENERATION_FILE,\n'
  '                 json.dumps({"generation": gen, "minted_ts": admitted_at},\n'
  '                            sort_keys=True).encode("utf-8"), durable_root=cfg.state_dir)\n',
  '    atomic_write(d / config_mod.RUNTIME_GENERATION_FILE,\n'
  '                 json.dumps({"generation": gen, "minted_ts": admitted_at},\n'
  '                            sort_keys=True).encode("utf-8"), durable_root=cfg.state_dir)\n'
  '    atomic_write(pin, hoplink.canonical(hoplink.pin_doc(cfg.hop, admitted_at)),\n'
  '                 durable_root=cfg.state_dir)\n',
  [T + "CrashBoundaryTests.test_a_crash_at_the_fresh_mints_record_then_the_next_pass_hands_over",
   T + "CrashBoundaryTests.test_a_crash_at_a_restores_record_then_the_next_pass_hands_over"]),
 ("R6 the runtime namespace retries a probe anomaly in production", INF,
  '        if not _is_hop(cfg) or name == config_mod.RUNTIME_NS:\n',
  '        if not _is_hop(cfg):\n',
  [T + "ProductionShapeTests.test_a_sender_method_anomaly_holds_named_in_the_production_shape"]),
 ("R6 why the tree is unavailable is not kept", PC,
  '    if not detail or (doc.get(e.reason) or {}).get("detail") == detail:\n',
  '    if True:\n',
  [T + "UnavailableNamedTests.test_an_identity_with_another_time_is_named_exists_different",
   T + "UnavailableNamedTests.test_a_missing_pin_is_named",
   T + "ProductionShapeTests.test_a_sender_method_anomaly_holds_named_in_the_production_shape"]),
 ("R3 the cleanup after the held pass's early returns", PC,
  '    cleaned = finish_settled(cfg)\n    if cleaned:\n        counts["settled_cleaned"] = cleaned\n'
  '    try:\n        clock = peerclock.read(state_dir)\n'
  '    except peerclock.ClockUntrusted:\n'
  '        return dict(counts, held_clock_untrusted=len(pending(state_dir)))\n'
  '    if clock.admission != "open":\n'
  '        # H is untrusted until admission reopens: no token, no mint, no attempt.\n'
  '        return dict(counts, held_admission_closed=len(pending(state_dir)))\n',
  '    try:\n        clock = peerclock.read(state_dir)\n'
  '    except peerclock.ClockUntrusted:\n'
  '        return dict(counts, held_clock_untrusted=len(pending(state_dir)))\n'
  '    if clock.admission != "open":\n'
  '        # H is untrusted until admission reopens: no token, no mint, no attempt.\n'
  '        return dict(counts, held_admission_closed=len(pending(state_dir)))\n'
  '    cleaned = finish_settled(cfg)\n    if cleaned:\n        counts["settled_cleaned"] = cleaned\n',
  [T + "HeldPassCleanupTests.test_closed_admission_still_cleans_up",
   T + "HeldPassCleanupTests.test_an_untrusted_clock_defers_the_cleanup_to_the_first_trusted_pass"]),
 ("R2 a resume admits with the clock's now", PC,
  '    return cap.admit(port, gen, at)\n',
  '    return cap.admit(port, gen, format_utc_ts(datetime.now()))\n',
  [T + "AdmitTests.test_every_resume_admits_again_and_a_steady_state_is_exists"]),
 ("R2 an unlisted restore re-stamps over its surviving pin", PC,
  '    return pin["admitted_at"] if isinstance(pin.get("admitted_at"), str) else format_utc_ts(now)\n',
  '    return format_utc_ts(now)\n',
  [T + "AdmitTests.test_an_unlisted_restore_with_a_surviving_pin_takes_the_pins_time"]),
 ("N3b the runtime address concatenated apart", PC,
  '    address = config_mod.router_address(cfg.fleet_domain)\n    if address is None:\n',
  '    address = config_mod.ROUTER_LOCAL_PART + "@" + cfg.fleet_domain\n    if address is None:\n',
  [T + "AddressTests.test_no_module_but_config_builds_the_own_address"]),
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
