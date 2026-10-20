"""Single-rule mutants for what `docker/entrypoint.sh` hands the CLI
(`router/tests/test_docker.py`, `EntrypointArgvTests`), each run against the
test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_entrypoint.py

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

T = "router.tests.test_docker.EntrypointArgvTests."
EP = "docker/entrypoint.sh"
ONCE = 'exec python3 -m router --config "$ROUTER_CONFIG" once "$@" ;;\n'
PEERS = 'exec python3 -m router --config "$ROUTER_CONFIG" peers "$@" ;;\n'
STATUS = 'exec python3 -m router --config "$ROUTER_CONFIG" status "$@" ;;\n'

M = [
 ('E1 once drops its arguments', EP, ONCE, ONCE.replace(' "$@"', ''),
  [T + 'test_once_passes_its_flags']),
 ('E2 peers drops its arguments', EP, PEERS, PEERS.replace(' "$@"', ''),
  [T + 'test_peers_passes_its_flags',
   T + 'test_an_argument_with_a_space_stays_one_argument']),
 ('E3 status drops its arguments', EP, STATUS, STATUS.replace(' "$@"', ''),
  [T + 'test_status_passes_its_flags']),
 ('E4 peers forwards them unquoted (word splitting)', EP, PEERS, PEERS.replace('"$@"', '$@'),
  [T + 'test_an_argument_with_a_space_stays_one_argument']),
 ('E5 peers forwards them joined into one', EP, PEERS, PEERS.replace('"$@"', '"$*"'),
  [T + 'test_an_argument_with_a_space_stays_one_argument']),
 ('E6 once adds a flag of its own', EP, ONCE, ONCE.replace(' "$@"', ' --json "$@"'),
  [T + 'test_without_flags_each_mode_adds_nothing']),
 ('E7 run takes a different interval', EP, 'run --interval "$INTERVAL" ;;\n',
  'run --interval 5 ;;\n',
  [T + 'test_run_is_the_interval_loop_and_nothing_else']),
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
