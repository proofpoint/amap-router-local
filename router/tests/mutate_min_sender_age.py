"""Single-rule mutants for ENROL-AGE-CONFIG (`min_sender_age_s`, design d8):
the config key's validator, the one sender-age value on every enforcing path
(`router/classify.py`, `router/outbound.py`'s pre-publication re-check,
`router/peerpolicy.py`), the restart-only reload and the reporting surfaces
(`router/service.py`, `router/status.py`, `router/console.py`), each run
against the test that names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_min_sender_age.py

Same discipline as `mutate_peerpolicy.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after, and a mutant is RED only when unittest reports the named test as a
FAILURE (an ERROR is not red). Exit 0 only when the named tests are green
unmutated and every mutant turns every named test red. Not a test module
itself (its name keeps it out of discovery).

Numbering follows design d8 §6.3; d8's M24-M27 belonged to the operator
hold, which is not in this unit, so M24 here is a different rule (0 itself
refused, review b90b434 Opus (b)5). The bool guard in `_min_sender_age_s` is
redundant beside the exact-type test (`type(True) is bool`), so M3 loosens
the type test AND drops the guard: the rule pinned is "a bool is refused".
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_min_sender_age."
CF, CL, OB, PP, SV, CO = ("router/config.py", "router/classify.py", "router/outbound.py",
                          "router/peerpolicy.py", "router/service.py", "router/console.py")

M = [
 ("M1 item 5c reads the default", CL,
  "    threshold = cfg.min_sender_age_s\n",
  "    threshold = config_mod.MIN_SENDER_AGE_S_DEFAULT\n",
  [T + "SenderDivergenceTests.test_sender_5c_tracks_cfg"]),
 ("M2 production_policy returns the default", PP,
  "    return PolicyPart(exposure_required=True, min_sender_age_s=cfg.min_sender_age_s)\n",
  "    return PolicyPart(exposure_required=True, min_sender_age_s=86400)\n",
  [T + "ReceiverDivergenceTests.test_receiver_tracks_cfg"]),
 ("M3 a bool is accepted", CF,
  "    if isinstance(v, bool) or type(v) is not int or not (0 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  "    if not isinstance(v, int) or not (0 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  [T + "LoadTests.test_bool_refused"]),
 ("M4 a negative value is accepted", CF,
  "    if isinstance(v, bool) or type(v) is not int or not (0 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  "    if isinstance(v, bool) or type(v) is not int or not (-86400 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  [T + "LoadTests.test_negative_refused"]),
 ("M5 zero read by truthiness", CF,
  "            f\"{MIN_SENDER_AGE_S_MAX}, got {v!r}\")\n    return v\n",
  "            f\"{MIN_SENDER_AGE_S_MAX}, got {v!r}\")\n    return v or MIN_SENDER_AGE_S_DEFAULT\n",
  [T + "SenderZeroTests.test_zero_is_kept"]),
 ("M6 the receiver at 0 skips the epoch store", PP,
  "        if part.min_sender_age_s is not None:\n",
  "        if part.min_sender_age_s:\n",
  [T + "ReceiverZeroTests.test_receiver_zero_consults_epochs"]),
 ("M7 the reload guard is gone", SV,
  "    if fresh.min_sender_age_s != current.min_sender_age_s:\n",
  "    if False:\n",
  [T + "ReloadTests.test_change_refused"]),
 ("M8 the below-default WARNING is dropped", SV,
  "    if value < MIN_SENDER_AGE_S_DEFAULT:\n        logger.warning(\n",
  "    if False:\n        logger.warning(\n",
  [T + "ReportedTests.test_warning_exact_text_and_level"]),
 ("M9 the overlay guard is gone", CF,
  "    if overlays:\n        raise ConfigError(",
  "    if False:\n        raise ConfigError(",
  [T + "LoadTests.test_a_delegation_member_cannot_set_it"]),
 ("M10 the pre-publication re-check reads the default", OB,
  "    if classify_mod.sender_age_refusal(cfg, name, utc_ts()) is not None:\n",
  "    if classify_mod.sender_age_refusal(dataclasses.replace(cfg, min_sender_age_s=86400),"
  " name, utc_ts()) is not None:\n",
  [T + "RecheckDivergenceTests.test_recheck_tracks_cfg"]),
 ("M11 status.json reports the default", SV,
  "    value = cfg.min_sender_age_s\n    return {",
  "    value = MIN_SENDER_AGE_S_DEFAULT\n    return {",
  [T + "ReportedTests.test_status_reports_enforced"]),
 ("M12 the startup line prints the default", SV,
  "    value = cfg.min_sender_age_s\n    logger.info(",
  "    value = MIN_SENDER_AGE_S_DEFAULT\n    logger.info(",
  [T + "ReportedTests.test_startup_reports_enforced"]),
 ("M13 a float is accepted", CF,
  "    if isinstance(v, bool) or type(v) is not int or not (0 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  "    if isinstance(v, bool) or not isinstance(v, (int, float)) or not (0 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  [T + "LoadTests.test_float_refused"]),
 ("M14 max+1 is accepted", CF,
  "    if isinstance(v, bool) or type(v) is not int or not (0 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  "    if isinstance(v, bool) or type(v) is not int or not (0 <= v <= MIN_SENDER_AGE_S_MAX + 1):\n",
  [T + "LoadTests.test_above_max_refused"]),
 ("M15 the console shows the default", CO,
  "        age_pill = _pill(\"warn\" if below else \"ok\", f\"{value}s\")\n",
  "        age_pill = _pill(\"warn\" if below else \"ok\", f\"{default}s\")\n",
  [T + "ReportedTests.test_console_reports_enforced"]),
 ("M16 the reload refusal does not name the key", SV,
  "            \"config reload changed min_sender_age_s (%d -> %d) — REFUSED and \"\n",
  "            \"config reload changed a setting (%d -> %d) — REFUSED and \"\n",
  [T + "ReloadTests.test_refusal_names_key_and_restart"]),
 ("M17 the maximum shifted down", CF,
  "MIN_SENDER_AGE_S_MAX = 31536000\n",
  "MIN_SENDER_AGE_S_MAX = 31535999\n",
  [T + "LoadTests.test_max_accepted"]),
 ("M18 the absent default changed", CF,
  "MIN_SENDER_AGE_S_DEFAULT = 86400\n",
  "MIN_SENDER_AGE_S_DEFAULT = 86399\n",
  [T + "LoadTests.test_absent_is_86400"]),
 ("M19 the WARNING fires at the default", SV,
  "    if value < MIN_SENDER_AGE_S_DEFAULT:\n        logger.warning(\n",
  "    if value <= MIN_SENDER_AGE_S_DEFAULT:\n        logger.warning(\n",
  [T + "ReportedTests.test_no_warning_at_86400"]),
 ("M20 policy.digest is of the default", SV,
  "            \"digest\": sender_age_policy_digest(value)}\n",
  "            \"digest\": sender_age_policy_digest(MIN_SENDER_AGE_S_DEFAULT)}\n",
  [T + "ReportedTests.test_digest_reports_enforced"]),
 ("M21 an explicit default counts as a change", SV,
  "    if fresh.min_sender_age_s != current.min_sender_age_s:\n",
  "    if fresh.min_sender_age_s != current.min_sender_age_s or "
  "fresh.min_sender_age_s == MIN_SENDER_AGE_S_DEFAULT:\n",
  [T + "ReloadTests.test_absent_to_explicit_default_is_unchanged"]),
 ("M22 a refused reload adopts the rejected value", SV,
  "        return _refuse_reload(current, \"min_sender_age_s changed (restart required)\")\n",
  "        return _refuse_reload(fresh, \"min_sender_age_s changed (restart required)\")\n",
  [T + "ReloadTests.test_refused_reload_keeps_last_good_policy"]),
 ("M24 zero itself is refused", CF,
  "    if isinstance(v, bool) or type(v) is not int or not (0 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  "    if isinstance(v, bool) or type(v) is not int or not (1 <= v <= MIN_SENDER_AGE_S_MAX):\n",
  [T + "LoadTests.test_accepted_values", T + "SenderZeroTests.test_zero_is_kept"]),
 ("M23 production_profile bypasses production_policy", PP,
  "    return Profile(context=ctx, edges=TRUSTED_HOST_DEFAULT, policy=production_policy(ctx.cfg))\n",
  "    return Profile(context=ctx, edges=TRUSTED_HOST_DEFAULT,\n"
  "                   policy=PolicyPart(exposure_required=True, min_sender_age_s=86400))\n",
  [T + "ReceiverDivergenceTests.test_receiver_tracks_cfg"]),
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
