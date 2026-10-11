"""Single-rule mutants for the plugin path's canonicality
(`router/tests/test_transport.py`, `CanonicalPathTests`), each run against
the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_pathcanon.py

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

T = "router.tests.test_transport.CanonicalPathTests."
TS = "router.tests.test_transport.LoaderTests."
TR = "router/transport.py"
CF = "router/config.py"

M = [
 ('M1 lexical normalisation before realpath (the old check)', TR,
  '    if os.path.realpath(path) != path:\n',
  '    if os.path.realpath(os.path.normpath(path)) != os.path.normpath(path):\n',
  [T + 'test_dotdot_after_a_symlink_is_refused_and_neither_file_is_opened',
   T + 'test_every_lexical_spelling_is_refused']),
 ('M3 the config re-normalises the plugin path', CF,
  '    path = raw["path"]\n',
  '    path = os.path.normpath(raw["path"])\n',
  [T + 'test_the_config_keeps_the_path_as_written_and_startup_refuses_it',
   T + 'test_a_spelling_only_change_on_reload_is_refused']),
 ('M4 a normpath-only check', TR,
  '    if os.path.realpath(path) != path:\n',
  '    if os.path.normpath(path) != path:\n',
  # Not the '..' witness: a normpath-only check refuses '..' too. What tells
  # it apart is a symlinked component and the leading '//'.
  [T + 'test_every_lexical_spelling_is_refused',
   TS + 'test_a_symlinked_component_is_refused']),
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
                print(f"{label:58s} {t.split('.')[-1][:58]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
