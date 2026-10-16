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
PD, RP, RR, PS, PV = (P + c + "." for c in ("PublishedDigestTests", "RunningProcessTests",
                                             "RefusalIsRecordedTests", "ProcessStartedTests",
                                             "ProcessStartedValueTests"))
SV = "router/service.py"
ST = "router/status.py"
UT = "router/util.py"
MN = "router/__main__.py"

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
  '        if self._transport_plugin_recorded:\n'
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
 ('S1 process_started_ts without a fraction', UT,
  '    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")\n',
  '    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")\n',
  [PS + 'test_present_with_a_fraction_on_every_write']),
 ('S2 process_started_ts re-read on every write', ST,
  '            doc["process_started_ts"] = self.process_started_ts\n',
  '            doc["process_started_ts"] = __import__("router.util", fromlist=["u"]).format_utc_ts_us(\n'
  '                __import__("router.clock", fromlist=["c"]).now())\n',
  [PS + 'test_unchanged_across_a_reload']),
 ('S3 process_started_ts taken after the plugin is loaded', SV,
  '                            process_started_ts=format_utc_ts_us(process_started))\n',
  '                            process_started_ts=format_utc_ts_us(clock.now()))\n',
  [PS + 'test_taken_before_the_plugin_is_loaded']),
 ('S4 main does not pass its own start', MN,
  '                        process_started=process_started)\n',
  '                        process_started=None)\n',
  [PS + 'test_main_takes_it_first_and_passes_it']),
 ('S5 a new process reuses the first value', ST,
  '        self.process_started_ts = process_started_ts\n',
  '        self.process_started_ts = (StatusTracker.__dict__.get("_first")\n'
  '                                   or setattr(StatusTracker, "_first", process_started_ts)\n'
  '                                   or process_started_ts)\n',
  [PS + 'test_a_new_process_gets_a_new_value']),
 ('S6 process_started_ts omitted', ST,
  '        if self.process_started_ts is not None:\n'
  '            doc["process_started_ts"] = self.process_started_ts\n',
  '',
  [PS + 'test_present_with_a_fraction_on_every_write']),
 ('S7 local time formatted with a Z', UT,
  '    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")\n',
  '    return dt.astimezone().strftime("%Y-%m-%dT%H:%M:%S.%fZ")\n',
  [PV + 'test_the_exact_utc_string_with_its_microseconds']),
 ('S8 the fraction zeroed', UT,
  '    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")\n',
  '    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")\n',
  [PV + 'test_the_exact_utc_string_with_its_microseconds']),
 ('D9 a None record does not latch', ST,
  '        self._transport_plugin_recorded = True\n',
  '        self._transport_plugin_recorded = doc is not None\n',
  [PD + 'test_a_none_record_latches_too']),
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
