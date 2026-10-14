"""Single-rule mutants for the end-to-end sender-age refusals, the status
count and the 5(b) value demotion (`router/tests/test_peer_policy_e2e.py`),
each run against the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_policy_e2e.py

Same discipline as `mutate_peerpolicy.py`: one rule per mutant, bytecode
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

T = "router.tests.test_peer_policy_e2e."
R, V = T + "ProductionRefusalTests.", T + "ValueDemotionUnplacedTests."
POL, PJ = "router/peerpolicy.py", "router/peerjournal.py"

M = [
 ("A1 a missing sender_since passes the age policy", POL,
  '            if since is None:\n                return peerjournal.Refuse("policy", SENDER_AGE_MISSING)\n',
  '            if since is None:\n                return None\n',
  [R + "test_a_missing_sender_since_is_refused_and_never_placed"]),
 ("A2 a sender younger than a day is not quarantined", POL,
  '            if age < part.min_sender_age_s:\n                return peerjournal.Refuse("policy", QUARANTINED)\n',
  '            if False:\n                return peerjournal.Refuse("policy", QUARANTINED)\n',
  [R + "test_a_sender_younger_than_a_day_is_quarantined_and_never_placed",
   R + "test_a_quarantined_refusal_raises_the_status_count_by_one"]),
 ("A3 a sender exactly a day old is quarantined", POL,
  '            if age < part.min_sender_age_s:\n',
  '            if age <= part.min_sender_age_s:\n',
  [R + "test_the_positive_control_a_day_old_exposed_sender_is_placed"]),
 ("A4 a policy refusal is placed anyway", PJ,
  '        out = call()\n        if isinstance(out, Hold):\n            return set_hold(sd, record, out.reason, out.detail, now)\n        if isinstance(out, Refuse):\n            return _finish(ctx, transition(sd, record, "refused"',
  '        out = call()\n        out = None if isinstance(out, Refuse) else out\n        if isinstance(out, Hold):\n            return set_hold(sd, record, out.reason, out.detail, now)\n        if isinstance(out, Refuse):\n            return _finish(ctx, transition(sd, record, "refused"',
  [R + "test_a_missing_sender_since_is_refused_and_never_placed",
   R + "test_a_sender_younger_than_a_day_is_quarantined_and_never_placed"]),
 ("A5 a policy refusal is not counted", PJ,
  '    EPOCH_COUNTS[key] = EPOCH_COUNTS.get(key, 0) + 1\n\n\nHOST_INTAKES',
  '    pass\n\n\nHOST_INTAKES',
  [R + "test_a_quarantined_refusal_raises_the_status_count_by_one"]),
 ("B1 a value demotion carries no control", PJ,
  'CONTROL_CODEC_CAUSES = frozenset({"statement_value"})\n',
  'CONTROL_CODEC_CAUSES = frozenset()\n',
  [V + "test_a_statement_value_demotion_reserves_nothing_and_places_nothing"]),
 ("B2 a replay-store write ahead of the value demotion", PJ,
  '            add_snapshot(ctx.state_dir, record, SNAPSHOT_STATEMENT, verdict.statement)\n            about = _statement_id(verdict.statement)\n',
  '            _link_digest(ctx.state_dir, "ab" * 32, "cd" * 16, "ef" * 32, "statement")\n            add_snapshot(ctx.state_dir, record, SNAPSHOT_STATEMENT, verdict.statement)\n            about = _statement_id(verdict.statement)\n',
  [V + "test_a_statement_value_demotion_reserves_nothing_and_places_nothing"]),
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
