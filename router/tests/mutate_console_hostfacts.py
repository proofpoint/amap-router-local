"""Single-rule mutants for the console's host-facts schemas 2 and 3
(`router/console.py`; `router/tests/test_console.py`, `SchemaThreeTests`),
each run against the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_console_hostfacts.py

Same discipline as `mutate_classify.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after; every named test must pass unmutated first, and a mutant is RED only
when unittest reports a FAILURE of the named test (an ERROR is printed and
is not red). Exit 0 only when every mutant turns every named test red. Not a
test module itself (its name keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_console.SchemaThreeTests."
CO = "router/console.py"

M = [
 ('H1 an unknown phase is scored by its checks', CO,
  '    if not isinstance(phase, dict) or phase.get("id") not in KNOWN_PHASES.get(schema, ()):\n',
  '    if not isinstance(phase, dict):\n',
  [T + 'test_an_unknown_phase_is_never_pass',
   T + 'test_runtime_builds_is_unknown_in_a_schema_two_document']),
 ('H2 schema 3 is not read', CO,
  'HOST_FACTS_SCHEMAS = (2, 3)\n',
  'HOST_FACTS_SCHEMAS = (2,)\n',
  [T + 'test_schema_three_is_read_and_every_build_check_shown_by_id']),
 ('H3 schema 2 is no longer read', CO,
  'HOST_FACTS_SCHEMAS = (2, 3)\n',
  'HOST_FACTS_SCHEMAS = (3,)\n',
  [T + 'test_schema_two_is_still_read']),
 ('H4 a schema that only compares equal is read', CO,
  '    if type(schema) is not int or schema not in HOST_FACTS_SCHEMAS:\n',
  '    if schema not in HOST_FACTS_SCHEMAS:\n',
  [T + 'test_an_unknown_schema_is_refused']),
 ('H5 runtime-builds is in schema 2', CO,
  '    2: (PHASE_CONTAINER, PHASE_ROUTER_HEALTH),\n',
  '    2: (PHASE_CONTAINER, PHASE_ROUTER_HEALTH, PHASE_RUNTIME_BUILDS),\n',
  [T + 'test_runtime_builds_is_unknown_in_a_schema_two_document']),
 ('H6 passing build checks are hidden', CO,
  '        elif not known or phase.get("id") == PHASE_RUNTIME_BUILDS:\n',
  '        elif not known:\n',
  [T + 'test_schema_three_is_read_and_every_build_check_shown_by_id']),
 ('H7 host_role is not shown', CO,
  '           + (f" [{_esc(role)}]" if role is not None else "") + "</span> "\n',
  '           + "</span> "\n',
  [T + 'test_schema_three_is_read_and_every_build_check_shown_by_id']),
 ('H8 a build check without an id is ignored', CO,
  '    if phase.get("id") == PHASE_RUNTIME_BUILDS and verdict == "pass" and not all(\n',
  '    if False and not all(\n',
  [T + 'test_a_build_check_without_an_id_is_unknown_not_pass']),
 ('H9 a result outside the vocabulary is shown as given', CO,
  '    shown = result if result in _CHECK_RESULTS else "UNKNOWN"\n',
  '    shown = str(result)\n',
  [T + 'test_a_result_outside_the_vocabulary_is_shown_unknown']),
]


def _red(r) -> bool:
    out = r.stdout + r.stderr
    return (r.returncode != 0 and "\nFAIL: " in "\n" + out
            and "FAILED (failures=" in out)


def main() -> int:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    ok = True
    for d in pathlib.Path("router").rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)
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
        for d in pathlib.Path("router").rglob("__pycache__"):
            shutil.rmtree(d, ignore_errors=True)
        try:
            for t in tests:
                r = subprocess.run([sys.executable, "-B", "-m", "unittest", t],
                                   capture_output=True, text=True)
                red = _red(r)
                ok &= red
                verdict = "RED" if red else ("ERROR only (not RED)" if r.returncode else "GREEN (survived)")
                print(f"{label:52s} {t.split('.')[-1][:60]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
