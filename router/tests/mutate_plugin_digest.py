"""Single-rule mutants for status.json's `transport_plugin` (the loaded
plugin's own digest; `router/tests/test_plugin_digest.py`), each run against
the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_plugin_digest.py

Same discipline as `mutate_classify.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after; every named test must pass unmutated first, and a mutant is RED only
when unittest reports a FAILURE of the named test (an ERROR is printed and
is not red). Exit 0 only when every mutant turns every named test red. Not a
test module itself (its name keeps it out of discovery).

EQUIVALENT, and so not listed: "publish the CONFIG's pin instead of the
loaded object". `load_plugin` refuses unless the bytes hash to the pin and
the path is canonical, and a reload that changes the pin is refused, so the
running config's pin can never differ from the loaded plugin's digest and
path; no row can tell the two apart.
"""
import os
import pathlib
import shutil
import subprocess
import sys

P = "router.tests.test_plugin_digest."
PD, RP, RR = (P + c + "." for c in ("PublishedDigestTests", "RunningProcessTests",
                                     "RefusalIsRecordedTests"))
SV = "router/service.py"
ST = "router/status.py"

M = [
 ('D1 the digest recomputed from the file when published', SV,
  '    return {"path": plugin.path, "sha256": plugin.sha256}\n',
  '    return {"path": plugin.path, "sha256": __import__("hashlib").sha256(\n'
  '        open(plugin.path, "rb").read()).hexdigest()}\n',
  [PD + 'test_it_is_not_recomputed_from_the_file_afterwards']),
 ('D2 a stand-in published as if loaded', SV,
  '    if not isinstance(plugin, transport_mod.LoadedPlugin):\n        return None\n',
  '    if plugin is None:\n        return None\n    if not hasattr(plugin, "sha256"):\n'
  '        return {"path": "", "sha256": ""}\n',
  [PD + 'test_no_loaded_plugin_publishes_nothing']),
 ('D3 run_forever does not record it', SV,
  '    tracker.record_transport_plugin(plugin_status(transport))\n',
  '    pass\n',
  [RP + 'test_the_running_process_publishes_its_loaded_digest']),
 ('D4 the record-once guard dropped', ST,
  '        if self.transport_plugin is not None:\n'
  '            raise ValueError("the loaded transport plugin is recorded once per process")\n',
  '',
  [PD + 'test_the_tracker_records_it_once']),
 ('D5 the document omits it', ST,
  '        if self.transport_plugin is not None:\n'
  '            doc["transport_plugin"] = dict(self.transport_plugin)\n',
  '',
  [RP + 'test_the_running_process_publishes_its_loaded_digest',
   RP + 'test_a_new_process_publishes_its_own']),
 ('D6 the member present without a plugin', ST,
  '        if self.transport_plugin is not None:\n'
  '            doc["transport_plugin"] = dict(self.transport_plugin)\n',
  '        doc["transport_plugin"] = self.transport_plugin\n',
  [PD + 'test_absent_from_the_document_without_a_plugin']),
 ('D7 a changed transport_plugin silently kept on reload', SV,
  '        return _refuse_reload(current, "transport_plugin changed")\n',
  '        return current\n',
  [RR + 'test_a_changed_transport_plugin_is_recorded',
   RP + 'test_a_refused_reload_of_a_changed_plugin_leaves_the_old_digest']),
 ('D8 a changed state_dir silently kept on reload', SV,
  '        return _refuse_reload(current, "state_dir changed")\n',
  '        return current\n',
  [RR + 'test_a_changed_state_dir_is_recorded']),
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
