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
SV = "router/service.py"
ST = "router.tests.test_transport.StartupTests."
FS = "router/fsops.py"
IG = "router/ingress.py"
HL = "router/hoplink.py"
RM = "router.tests.test_ingress_remover."
MX = "router.tests.test_transport_e8b.MatrixTests."
SF = "router.tests.test_transport_e8b.SurfaceTests."
LD = "router.tests.test_transport.LoaderTests."
E8 = "router.tests.test_transport_e8.ShapeTests."
RR = "router.tests.test_fsops_e8b.RemoveResumableTests."
RB = "router.tests.test_fsops_e8b.RemoveBoundedTests."
SG = "router.tests.test_fsops_e8b.StatGroupTests."

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
 ('E8 no warning for a shared uid', SV,
  '    if cfg.hop.peer_uid == os.geteuid():\n', '    if False:\n',
  [ST + "test_peer_uid_equal_to_this_router_s_uid_is_accepted_with_one_warning"]),
 ('E9 the warning whatever the uids', SV,
  '    if cfg.hop.peer_uid == os.geteuid():\n', '    if True:\n',
  [ST + "test_distinct_uids_give_no_such_warning"]),
 # -- the remover in the ingress pass, and its construction ----------------------
 ('G1 any remover return tombstones', IG,
  '    if got not in transport_mod.REMOVE_RESULTS:\n', '    if False:\n',
  [RM + "RemoverPassTests.test_an_unknown_return_is_a_protocol_hold_and_the_record_waits"]),
 ('G2 a held remover falls to the interim rule', IG,
  '        if st in WAITING_REMOVE and pump.remover_hold is not None:\n            continue                 # an offered remover is held: entries wait\n', '',
  [RM + "RemoverPassTests.test_a_held_remover_leaves_entries_waiting_even_gone_past_the_horizon"]),
 ('G3 a closed remover kept', IG,
  '            hoplink_mod.evict_remover(pump.cfg, pump.logical_id, pump.gen)\n            pump.remover = None\n', '',
  [RM + "RemoverPassTests.test_a_closed_remover_is_evicted"]),
 ('G3b a closed remover lets the pass fall to the interim rule', IG,
  '            pump.remover_hold = HOLD_OBJECT_CLOSED\n', '',
  [RM + "RemoverPassTests.test_after_a_close_the_rest_of_the_pass_waits_never_the_interim_rule"]),
 ('G4 a too-large listing read as unexpected', IG,
  '        if kind == "runtime" and detail == "listing_too_large":\n            why = HOLD_REMOVE_LISTING_TOO_LARGE\n        elif',
  '        if',
  [RM + "RemoverPassTests.test_each_exception_class_has_its_hold_and_the_record_waits"]),
 ('G5 a remover built when not offered', HL,
  '    if not remover_offered(runtime):\n        return None\n', '',
  [RM + "RemoverForTests.test_not_offered_is_none_and_never_calls_the_factory"]),
 ('G6 a refused remover not latched', HL,
  '            _REMOVER_LATCHED[key] = hold\n', '            pass\n',
  [RM + "RemoverForTests.test_refused_settings_latch_the_remover_only"]),
 ('G7 the remover not called when present', IG,
  '        if st in WAITING_REMOVE and pump.remover is not None:\n', '        if False:\n',
  [RM + "RemoverPassTests.test_removed_and_absent_each_make_the_tombstone_at_once"]),
 ('G8 the remover state not shown per generation', IG,
  '            if rs is not None:\n                entry["remover"] = rs\n', '',
  [RM + "RemoverStatusTests.test_status_names_the_remover_state"]),
 # -- HopFsOps: remove_pinned crash-resumable and bounded; stat_group_pinned --
 ('F1 the aside sweep skipped', FS,
  '        for aside in self._asides(dir_fd, name):\n', '        for aside in []:\n',
  [RR + "test_a_crash_after_the_rename_aside_is_finished_by_the_next_call"]),
 ('F2 a prefix-only aside test', FS,
  '                if pattern.fullmatch(n):\n', '                if True:\n',
  [RR + "test_another_name_s_asides_and_junk_are_untouched"]),
 ('F3 the sweep reads one page only', FS,
  '            if not more or not names:\n                return found\n', '            return found\n',
  [RR + "test_the_sweep_pages_past_one_listing_page"]),
 ('F4 the emptying unbounded in count', FS,
  '                if counted > transport_mod.LIST_SCAN_MAX:\n                    raise ListingTooLarge(\n                        f"more than {transport_mod.LIST_SCAN_MAX} names under removal; "',
  '                if False:\n                    raise ListingTooLarge(\n                        f"more than {transport_mod.LIST_SCAN_MAX} names under removal; "',
  [RB + "test_a_directory_over_the_scan_cap_raises_listing_too_large_and_keeps_it"]),
 ('F5 the emptying unbounded in depth', FS,
  '    if depth > REMOVE_TREE_DEPTH_MAX:\n', '    if False:\n',
  [RB + "test_nesting_of_eight_removes_and_nine_raises_eloop"]),
 ('F6 a symlink inside followed', FS,
  '                st = os.stat(entry, dir_fd=fd, follow_symlinks=False)\n                if stat.S_ISDIR(st.st_mode):\n                    _remove_tree(fd, entry, depth + 1)\n',
  '                st = os.stat(entry, dir_fd=fd, follow_symlinks=True)\n                if stat.S_ISDIR(st.st_mode):\n                    _remove_tree(fd, entry, depth + 1)\n',
  [RB + "test_a_symlink_inside_is_unlinked_and_its_target_untouched"]),
 ('F7 a full in-memory listing', FS,
  '            batch: List[str] = []\n            with os.scandir(fd) as it:\n                for entry in it:\n                    batch.append(entry.name)\n                    if len(batch) >= _REMOVE_BATCH:\n                        break\n',
  '            batch: List[str] = list(os.listdir(fd))\n',
  [RB + "test_emptying_holds_a_bounded_batch_not_a_full_listing"]),
 ('F7b only the first batch emptied', FS,
  '                    os.unlink(entry, dir_fd=fd)\n    finally:\n        os.close(fd)\n    os.rmdir(name, dir_fd=parent_fd)',
  '                    os.unlink(entry, dir_fd=fd)\n            break\n    finally:\n        os.close(fd)\n    os.rmdir(name, dir_fd=parent_fd)',
  [RB + "test_a_directory_larger_than_one_batch_is_emptied_whole"]),
 ('F8 stat_group_pinned follows symlinks', FS,
  '        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)\n        kind = "file" if stat.S_ISREG(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) \\\n            else "other"\n        return st.st_uid, st.st_gid,',
  '        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=True)\n        kind = "file" if stat.S_ISREG(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) \\\n            else "other"\n        return st.st_uid, st.st_gid,',
  [SG + "test_it_agrees_with_stat_owner_pinned_and_adds_the_gid"]),
 ('F9 the gid read from the parent', FS,
  '        return st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), kind\n',
  '        return st.st_uid, os.fstat(dir_fd).st_gid, stat.S_IMODE(st.st_mode), kind\n',
  [SG + "test_the_gid_is_the_name_s_not_the_parent_s"]),
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
