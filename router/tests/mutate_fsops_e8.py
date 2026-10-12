"""Single-rule mutants for API (3, 0): the runtime-side checks and the
classifier in `router/transport.py` (`test_transport_e8.py`,
`test_transport.py`) and this router's `FsOps.list_pinned`
(`test_fsops_list_pinned.py`), each run against the tests that name it.

Run from the repository root:

    python3 -B router/tests/mutate_fsops_e8.py

Same discipline as `mutate_place_once.py`: one rule per mutant, bytecode
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

E8 = "router.tests.test_transport_e8."
LD = "router.tests.test_transport.LoaderTests."
FL = "router.tests.test_fsops_list_pinned."
TR, FS = "router/transport.py", "router/fsops.py"

M = [
 # -- the classifier and the runtime-side checks (commit 1) ---------------
 ('T1 a plugin .reason classified before the runtime classes', TR,
  [('    for cls in runtime:\n        if isinstance(exc, cls):\n            return "runtime", cls.__name__\n'
    '    reason = getattr(exc, "reason", None)\n'
    '    if type(reason) is str and reason in TRANSPORT_REASONS:\n        return "reason", reason\n',
    '    reason = getattr(exc, "reason", None)\n'
    '    if type(reason) is str and reason in TRANSPORT_REASONS:\n        return "reason", reason\n'
    '    for cls in runtime:\n        if isinstance(exc, cls):\n            return "runtime", cls.__name__\n')],
  None, [E8 + "ClassifyTests.test_the_runtimes_own_classes_win_over_a_colliding_reason"]),
 ('T2 the descendant half of disjointness removed', TR,
  '        if issubclass(cls, base) or issubclass(base, cls):\n',
  '        if issubclass(base, cls):\n',
  [E8 + "DisjointnessTests.test_each_forbidden_shape_is_refused",
   E8 + "DisjointnessTests.test_listing_too_large_is_checked_the_same_way"]),
 ('T3 the ancestor half of disjointness removed', TR,
  '        if issubclass(cls, base) or issubclass(base, cls):\n',
  '        if issubclass(cls, base):\n',
  [E8 + "DisjointnessTests.test_each_forbidden_shape_is_refused",
   E8 + "DisjointnessTests.test_listing_too_large_is_checked_the_same_way"]),
 ('T4 retired_at matched with \\d', TR,
  'RETIRED_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\Z")',
  'RETIRED_AT_RE = re.compile(r"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\\Z")',
  [E8 + "RetiredAtTests.test_the_grammar_is_ascii_only"]),
 ('T5 a limit over the maximum accepted (clamped)', TR,
  '    if type(limit) is not int or not 1 <= limit <= LIST_LIMIT_MAX:\n',
  '    if type(limit) is not int or not 1 <= limit:\n',
  [E8 + "ListArgsTests.test_refused_never_clamped"]),
 ('T6 a bool accepted as the limit', TR,
  '    if type(limit) is not int or not 1 <= limit <= LIST_LIMIT_MAX:\n',
  '    if not isinstance(limit, int) or not 1 <= limit <= LIST_LIMIT_MAX:\n',
  [E8 + "ListArgsTests.test_refused_never_clamped"]),
 ('T7 a verdict class with an unknown reason is a verdict', TR,
  '            if reasons is None or reason in reasons:\n',
  '            if True:\n',
  [E8 + "ClassifyTests.test_a_verdict_with_an_unknown_reason_is_no_verdict"]),
 ('T8 the marker store not required', TR,
  '    "make_sender", "make_intake_reader", "make_upstream_marker_store")\n',
  '    "make_sender", "make_intake_reader")\n',
  [LD + "test_a_plugin_without_the_marker_store_is_refused_naming_it"]),
 ('T9 a /1 notice bundle accepted', TR,
  '    return value == NOTICE_BUNDLE_SCHEMA\n',
  '    return value in (NOTICE_BUNDLE_SCHEMA, "amap-hop-notice-entry/1")\n',
  [E8 + "BundleSchemaTests.test_only_2_is_current"]),
 ('T10 the runtime stays at (2, 0)', TR,
  'PLUGIN_API: Tuple[int, int] = (3, 0)\n', 'PLUGIN_API: Tuple[int, int] = (2, 0)\n',
  [LD + "test_an_older_major_plugin_is_refused_by_this_major_3_runtime"]),
 # -- FsOps.list_pinned (commit 2) ------------------------------------------
 ('F1 the scan reads a dup of the pinned descriptor', FS,
  '        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,\n'
  '                     dir_fd=dir_fd)\n',
  '        fd = os.dup(dir_fd)\n',
  [FL + "FreshDescriptionTests.test_the_scan_opens_dot_relative_to_the_pinned_fd_and_never_dups"]),
 ('F2 the scan cap removed', FS,
  '                    if visited > transport_mod.LIST_SCAN_MAX:\n',
  '                    if False:\n',
  [FL + "ScanCapTests.test_one_more_raises_and_the_scan_stopped",
   FL + "ScanCapTests.test_the_cap_holds_whatever_after_and_limit_are"]),
 ('F3 the cap checked only after a full scan', FS,
  [('                    if visited > transport_mod.LIST_SCAN_MAX:\n'
    '                        raise ListingTooLarge(\n'
    '                            f"more than {transport_mod.LIST_SCAN_MAX} names; the scan stopped")\n',
    ''),
   ('        finally:\n            os.close(fd)\n        names = sorted(h.name for h in heap)\n',
    '        finally:\n            os.close(fd)\n'
    '        if visited > transport_mod.LIST_SCAN_MAX:\n'
    '            raise ListingTooLarge("over the cap")\n'
    '        names = sorted(h.name for h in heap)\n')],
  None, [FL + "ScanCapTests.test_one_more_raises_and_the_scan_stopped"]),
 ('F4 the full listing materialised', FS,
  '            keep = limit + 1\n', '            keep = 10 ** 9\n',
  [FL + "MemoryTests.test_memory_is_bounded_by_limit_not_the_directory"]),
 ('F5 after is not strict', FS,
  '                    if after is not None and name <= after:\n',
  '                    if after is not None and name < after:\n',
  [FL + "PagingTests.test_after_is_strict_and_need_not_exist",
   FL + "PagingTests.test_sorted_bounded_and_truncated"]),
 ('F6 truncated true at exactly limit', FS,
  '        return names[:limit], len(names) > limit\n',
  '        return names[:limit], len(names) >= limit\n',
  [FL + "PagingTests.test_sorted_bounded_and_truncated"]),
 ('F7 the binding check skipped', FS,
  '        b = self.binding(dir_fd)\n        fd = os.open(".",',
  '        st0 = os.fstat(dir_fd)\n        b = Binding("x", (0, 0), (), st0.st_dev, st0.st_ino, st0.st_uid)\n        fd = os.open(".",',
  [FL + "ArgumentAndBindingTests.test_an_unbound_descriptor_is_refused",
   FL + "ArgumentAndBindingTests.test_a_stale_binding_is_refused"]),
 ('F8 ListingTooLarge made an OSError', FS,
  'class ListingTooLarge(Exception):\n', 'class ListingTooLarge(OSError):\n',
  [FL + "ScanCapTests.test_the_class_is_the_runtimes_own_and_disjoint"]),
 ('F9 an undecodable name altered', FS,
  '                    name = entry.name\n',
  '                    name = entry.name.encode("utf-8", "replace").decode("utf-8")\n',
  [FL + "PagingTests.test_an_undecodable_name_is_surfaced_not_dropped"]),
 ('F10 the fresh descriptor leaked', FS,
  '        finally:\n            os.close(fd)\n        names = sorted(h.name for h in heap)\n',
  '        finally:\n            pass\n        names = sorted(h.name for h in heap)\n',
  [FL + "FreshDescriptionTests.test_the_pinned_descriptor_keeps_its_position_and_closes_nothing_extra"]),
 ('F11 a scan error read as an empty listing', FS,
  '            with os.scandir(fd) as it:\n',
  '            try:\n                it = os.scandir(fd)\n            except OSError:\n'
  '                return [], False\n            with it:\n',
  [FL + "ArgumentAndBindingTests.test_an_error_raises_and_is_never_an_empty_listing"]),
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
