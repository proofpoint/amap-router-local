"""Single-rule mutants for req_id reuse (router/tests/test_reuse.py), each
run against the test that names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_reuse.py

Same discipline as `mutate_held_local.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after. Exit 0 only when every mutant turns every named test red. Not a test
module itself (its name keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

R = "router.tests.test_reuse."

M = [
 ('U1 in flight: settle never compares the live entry', 'router/outbound.py',
  '        if _live_differs(cfg, name, req_id, digest):\n',
  '        if False:\n',
  [R + 'InflightReuseTests.test_a_reused_id_never_settles_with_the_old_verdict',
   R + 'InflightReuseTests.test_an_oversized_reuse_is_refused_too',
   'router.tests.test_inflight.LifecycleTests.test_the_staged_copy_is_sent_not_the_agents_later_bytes']),
 ('U2 digest-less anchor: a readable entry resumes', 'router/outbound.py',
  '                        resume_ok = True\n                    else:\n                        resume_ok = False\n',
  '                        resume_ok = True\n                    else:\n                        resume_ok = True\n',
  [R + 'DigestlessAnchorReuseTests.test_a_readable_request_under_a_digestless_anchor_is_refused']),
 ('U3 in flight: a different live entry is not held', 'router/outbound.py',
  '                if record is not None and _live_differs(\n',
  '                if False and _live_differs(\n',
  [R + 'InflightReuseTests.test_a_reused_id_is_held_while_the_record_is_unsettled']),
 ('U4 a transient fault counts as unreadable', 'router/outbound.py',
  '    return isinstance(e, OSError) and e.errno in _KIND_ERRNOS\n',
  '    return isinstance(e, OSError)\n',
  [R + 'InflightReuseTests.test_a_transient_read_fault_at_settle_decides_nothing',
   R + 'DigestlessAnchorReuseTests.test_a_transient_fault_under_a_digestless_anchor_decides_nothing']),
 ('U5 an absent live entry counts as different', 'router/outbound.py',
  '    except FileNotFoundError:\n        return False\n',
  '    except FileNotFoundError:\n        return True\n',
  [R + 'InflightReuseTests.test_an_absent_live_entry_settles_as_before']),
 ('U6 an oversized live entry is the original', 'router/outbound.py',
  '    if isinstance(e, (ReadTooLargeError, UnreadableRequest)):\n',
  '    if isinstance(e, UnreadableRequest):\n',
  [R + 'InflightReuseTests.test_an_oversized_reuse_is_refused_too',
   R + 'DigestlessAnchorReuseTests.test_a_still_oversized_request_resumes']),
 ('U7 private settle publishes anyway', 'router/outbound.py',
  '            _write_anchor(cfg, name, req_id, result, req_digest=digest)\n            return result["outcome"]\n',
  '            return _finish(cfg, name, req_id, result, req_digest=digest)\n',
  [R + 'InflightReuseTests.test_a_reused_id_never_settles_with_the_old_verdict']),
 ('U8 no errno kinds are verdicts', 'router/outbound.py',
  '_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO})\n',
  '_KIND_ERRNOS = frozenset()\n',
  [R + 'InflightReuseTests.test_a_symlink_kind_at_the_open_is_refused']),
 ('U9 a not-regular or hard-link refusal is not a verdict', 'router/outbound.py',
  '    if isinstance(e, (ReadTooLargeError, UnreadableRequest)):\n',
  '    if isinstance(e, ReadTooLargeError):\n',
  [R + 'InflightReuseTests.test_a_hard_linked_reuse_is_refused',
   R + 'InflightReuseTests.test_a_directory_at_the_name_settles_privately',
   R + 'DigestlessAnchorReuseTests.test_a_hard_link_under_a_digestless_anchor_resumes']),
 ('U11 ENXIO is not a verdict', 'router/outbound.py',
  '_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO})\n',
  '_KIND_ERRNOS = frozenset({errno.ELOOP})\n',
  [R + 'InflightReuseTests.test_a_socket_kind_at_the_open_is_refused']),
 ('U12 EACCES is a verdict', 'router/outbound.py',
  '_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO})\n',
  '_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO, errno.EACCES})\n',
  [R + 'InflightReuseTests.test_a_transient_read_fault_at_settle_decides_nothing',
   R + 'DigestlessAnchorReuseTests.test_a_transient_fault_under_a_digestless_anchor_decides_nothing']),
 ('U10 digest anchor: a kind refusal is skipped as transient', 'router/outbound.py',
  '                        if _unreadable_now(e):\n                            # Refused for what it IS (a hard link, not a\n',
  '                        if False:\n                            # Refused for what it IS (a hard link, not a\n',
  [R + 'InflightReuseTests.test_a_hard_linked_reuse_is_refused']),
]

#: A run is RED only when unittest reports the named test as a FAILURE: an
#: assertion in the test itself did not hold. An ERROR (the code under the
#: mutant crashed, the import broke, the test id is wrong) is reported but
#: is not RED: it proves the mutant broke something, not that the test
#: pins the rule.
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
                print(f"{label:52s} {t.split('.')[-1][:58]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
