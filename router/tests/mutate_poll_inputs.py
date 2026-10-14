"""Single-rule mutants for `service.poll_inputs` and `run_once`'s use of it,
each run against the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_poll_inputs.py

Same discipline as `mutate_peerledger.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after, and a mutant is RED only when unittest reports the named test as a
FAILURE (an ERROR is not red). Not a test module itself.
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_poll_inputs."
SVC = "router/service.py"

M = [
 ("P1 run_once re-inlines the glue", SVC,
  "    cfg, report, gen_keys = poll_inputs(cfg, report=report, gen_keys=gen_keys)\n",
  "    if report is None:\n        report = registry_report(cfg)\n    if gen_keys is None:\n"
  "        report, gen_keys = generations.apply(cfg, report)\n"
  "    cfg = generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys)\n"
  "    cfg = aliases_mod.attach(cfg, report)\n",
  [T + "StructureTests.test_run_once_calls_poll_inputs_and_repeats_none_of_its_steps"]),
 ("P2 the alias view not attached", SVC,
  "    cfg = aliases_mod.attach(cfg, report)\n    return PollInputs(cfg, report, gen_keys)\n",
  "    return PollInputs(cfg, report, gen_keys)\n",
  [T + "PollInputsTests.test_each_of_the_four_steps_is_taken"]),
 ("P3 the generation keying dropped", SVC,
  "    cfg = generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys)\n",
  "    cfg = registry_mod.keyed_config(cfg, report)\n",
  [T + "PollInputsTests.test_each_of_the_four_steps_is_taken"]),
 ("P4 the registry keying dropped", SVC,
  "    cfg = generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys)\n",
  "    cfg = generations.keyed(cfg, gen_keys)\n",
  [T + "PollInputsTests.test_each_of_the_four_steps_is_taken"]),
 ("P5 the generations not applied", SVC,
  "        report, gen_keys = generations.apply(cfg, report)\n    cfg = generations.keyed",
  "        gen_keys = {}\n    cfg = generations.keyed",
  [T + "PollInputsTests.test_each_of_the_four_steps_is_taken"]),
 ("P6 poll_inputs drains", SVC,
  "    cfg = aliases_mod.attach(cfg, report)\n    return PollInputs(cfg, report, gen_keys)\n",
  "    cfg = aliases_mod.attach(cfg, report)\n    if False:\n        outbound.drain_instance(cfg, None)\n"
  "    return PollInputs(cfg, report, gen_keys)\n",
  [T + "StructureTests.test_poll_inputs_takes_the_four_steps_and_nothing_else"]),
 ("P7 a given report recomputed", SVC,
  "    if report is None:\n        report = registry_report(cfg)\n    if gen_keys is None:\n        report, gen_keys = generations.apply(cfg, report)\n    cfg = generations.keyed",
  "    if True:\n        report = registry_report(cfg)\n    if gen_keys is None:\n        report, gen_keys = generations.apply(cfg, report)\n    cfg = generations.keyed",
  [T + "PollInputsTests.test_given_report_and_generation_keys_are_used_not_recomputed"]),
 ("P8 run_once not draining on poll_inputs' cfg", SVC,
  "    cfg, report, gen_keys = poll_inputs(cfg, report=report, gen_keys=gen_keys)\n",
  "    _cfg, report, gen_keys = poll_inputs(cfg, report=report, gen_keys=gen_keys)\n",
  [T + "PollInputsTests.test_run_once_drains_on_exactly_poll_inputs_configuration"]),
 ("P9 the wrapper changes an argument", SVC,
  "    return peercontrol.send_pending(cfg, transport, delegation=delegation, now=now)\n",
  "    return peercontrol.send_pending(cfg, transport, delegation=delegation, now=None)\n",
  [T + "SendControlPendingTests.test_the_wrapper_passes_its_arguments_and_returns_the_result_unchanged"]),
 ("P10 run_once calls send_pending around the wrapper", SVC,
  "            sent = send_control_pending(cfg, transport, delegation=peerlane.current(cfg),\n"
  "                                        now=clock.now())\n",
  "            from . import peercontrol\n"
  "            sent = peercontrol.send_pending(cfg, transport, delegation=peerlane.current(cfg),\n"
  "                                            now=clock.now())\n",
  [T + "StructureTests.test_run_once_reaches_send_pending_only_through_the_wrapper"]),
 ("P11 the report drifts after poll_inputs (Codex)", SVC,
  "    cfg, report, gen_keys = poll_inputs(cfg, report=report, gen_keys=gen_keys)\n",
  "    cfg, report, gen_keys = poll_inputs(cfg, report=report, gen_keys=gen_keys)\n"
  "    import dataclasses as _dc\n    report = _dc.replace(report, state=\"off\") if _dc.is_dataclass(report) else report\n",
  [T + "PollInputsTests.test_run_once_consumes_exactly_the_poll_inputs_it_got"]),
 ("P12 the wrapper calls the pass twice (Codex)", SVC,
  "    return peercontrol.send_pending(cfg, transport, delegation=delegation, now=now)\n",
  "    peercontrol.send_pending(cfg, transport, delegation=delegation, now=now)\n"
  "    return peercontrol.send_pending(cfg, transport, delegation=delegation, now=now)\n",
  [T + "SendControlPendingTests.test_the_wrapper_passes_its_arguments_and_returns_the_result_unchanged",
   T + "SendControlPendingTests.test_its_result_and_record_effects_are_the_direct_calls"]),
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
