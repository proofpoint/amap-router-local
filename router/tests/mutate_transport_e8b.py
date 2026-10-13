"""Single-rule mutants for the optional intake remover's seam at PLUGIN_API
(3, 1): the loader's minor-gated precedence for optional factories and the
capability members (`router/transport.py`), and the `HopFsOps` obligations
the remover relies on (`router/fsops.py`), each run against the tests that
name it.

Run from the repository root:

    python3 -B router/tests/mutate_transport_e8b.py

Same discipline as `mutate_hoplink.py`: one rule per mutant, bytecode caching
OFF and `__pycache__` cleared before each run, the file restored after; every
named test must pass unmutated first, and a mutant is RED only when unittest
reports a FAILURE of the named test (an ERROR is printed and is not red).
Exit 0 only when every mutant turns every named test red. Not a test module
itself (its name keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

TP = "router/transport.py"
FS = "router/fsops.py"
MX = "router.tests.test_transport_e8b.MatrixTests."
SF = "router.tests.test_transport_e8b.SurfaceTests."
LD = "router.tests.test_transport.LoaderTests."
E8 = "router.tests.test_transport_e8.ShapeTests."

M = [
 ('E1 the minor compared with PLUGIN_API', TP,
  '    if got[0] != api[0] or got[1] < required_minor:\n',
  '    if got[0] != api[0] or got[1] < api[1]:\n',
  [LD + "test_an_older_minor_plugin_loads_under_this_3_1_runtime"]),
 ('E2 the capability granted below its minor', TP,
  '        if got < since:\n', '        if False:\n',
  [MX + "test_below_the_minor_the_name_is_ignored_whatever_it_is"]),
 ('E3 a non-callable name refused below its minor', TP,
  '    for name, (since, _port) in sorted(optional_factories.items()):\n        if got < since:\n',
  '    for name, (since, _port) in sorted(optional_factories.items()):\n'
  '        if name in namespace and not callable(namespace[name]):\n'
  '            raise PluginRefused("missing_factory", name)\n        if got < since:\n',
  [MX + "test_below_the_minor_the_name_is_ignored_whatever_it_is"]),
 ('E4 a non-callable name read as absent at its minor', TP,
  '        if not callable(namespace[name]):\n            raise PluginRefused("missing_factory", f"the plugin\'s {name!r} is not callable")\n',
  '        if not callable(namespace[name]):\n            continue\n',
  [MX + "test_at_or_above_the_minor"]),
 ('E5 the remover reachable without the capability', TP,
  '        if "make_intake_remover" not in self.optional_capabilities:\n', '        if False:\n',
  [MX + "test_below_the_minor_the_name_is_ignored_whatever_it_is"]),
 ('E6 the optional factory made required', TP,
  '    "make_sender", "make_intake_reader", "make_upstream_marker_store")\n',
  '    "make_sender", "make_intake_reader", "make_upstream_marker_store", "make_intake_remover")\n',
  [E8 + "test_remove_entry_is_optional_at_3_1"]),
 ('E7 no INFO line for an ignored name', TP,
  '            if name in namespace:\n                _logger.info(', '            if False:\n                _logger.info(',
  [MX + "test_one_info_line_for_an_ignored_present_name"]),
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
        edits = old if isinstance(old, list) else [(old, new)]
        missing = [(a, orig.count(a)) for a, _ in edits if orig.count(a) != 1]
        if missing:
            print(f"{label}: ANCHOR FOUND {missing[0][1]} TIMES")
            ok = False
            continue
        mutated = orig
        for a, b in edits:
            mutated = mutated.replace(a, b)
        path.write_text(mutated)
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
