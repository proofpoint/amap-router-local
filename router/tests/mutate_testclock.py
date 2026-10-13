"""The delay witness for the ingress removal tests' clock
(`test_ingress_pump.later`), and its mutant.

Those tests need a time past the dedup horizon for records stamped during
the test. A constant taken at IMPORT had a 60-second margin, so a run that
took longer than that to reach the tests turned "past the horizon" into
"not yet", and they failed on a slow CI runner. The witness reproduces that
run for real: it imports the two modules, sleeps past the margin, then runs
the tests. They must stay green; with the import-time constant restored
(the one mutant) they must go red.

Run from the repository root:

    python3 -B router/tests/mutate_testclock.py

Slow by design (two sleeps of `DELAY` seconds). Same discipline as the other
harnesses: bytecode caching OFF and `__pycache__` cleared before each run,
the file restored after, and a mutant is RED only when unittest reports a
FAILURE (an ERROR is not red). Exit 0 only when the witness is green
unmutated and the mutant turns it red. Not a test module itself (its name
keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

P = "router.tests.test_ingress_pump."
TESTS = [
    P + "RemovalTests.test_gone_and_past_the_horizon_is_a_tombstone_that_still_dedups",
    P + "RemovalTests.test_a_tombstone_past_the_horizon_is_dropped_with_its_snapshot",
    P + "RemovalTests.test_a_quarantined_entry_follows_the_same_rule",
    "router.tests.test_ingress_remover.RemoverPassTests."
    "test_without_a_remover_the_interim_rule_still_applies",
]
#: Longer than the 60-second margin the import-time constant had.
DELAY = 62
FILE = "router/tests/test_ingress_pump.py"

#: The one mutant: `later()` returns a constant taken at import.
M = [
    ("TC1 later() taken at import", FILE,
     "def later() -> datetime:\n",
     "_AT_IMPORT = datetime.now(timezone.utc) + timedelta(seconds=HORIZON + 60)\n\n\n"
     "def later() -> datetime:\n    return _AT_IMPORT\n\n\ndef _was_later() -> datetime:\n"),
]

WITNESS = (
    "import sys, time, unittest\n"
    "import router.tests.test_ingress_pump, router.tests.test_ingress_remover\n"
    f"time.sleep({DELAY})\n"
    "suite = unittest.defaultTestLoader.loadTestsFromNames(sys.argv[1:])\n"
    "r = unittest.TextTestRunner(verbosity=2).run(suite)\n"
    "sys.exit(0 if r.wasSuccessful() else 1)\n"
)


def _clear() -> None:
    for d in pathlib.Path("router").rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def _witness() -> subprocess.CompletedProcess:
    _clear()
    return subprocess.run([sys.executable, "-B", "-c", WITNESS, *TESTS],
                          capture_output=True, text=True)


def _red(r) -> bool:
    out = r.stdout + r.stderr
    return (r.returncode != 0 and "\nFAIL: " in "\n" + out
            and "FAILED (failures=" in out)


def main() -> int:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    clean = _witness()
    if clean.returncode != 0:
        print(f"the witness is not green on unmutated code after {DELAY}s:\n"
              + clean.stderr[-2000:])
        return 1
    print(f"witness, unmutated, after {DELAY}s: GREEN ({len(TESTS)} tests)")
    ok = True
    for label, f, old, new in M:
        path = pathlib.Path(f)
        orig = path.read_text()
        if orig.count(old) != 1:
            print(f"{label}: ANCHOR FOUND {orig.count(old)} TIMES")
            ok = False
            continue
        path.write_text(orig.replace(old, new))
        try:
            r = _witness()
        finally:
            path.write_text(orig)
            _clear()
        red = _red(r)
        ok &= red
        verdict = "RED" if red else ("ERROR only (not RED)" if r.returncode else "GREEN (survived)")
        print(f"{label:40s} after {DELAY}s: {verdict}")
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
