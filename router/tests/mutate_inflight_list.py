"""Single-rule mutants for `router inflight list` (router/inflight.py, THE
OPERATOR LISTING; `router/tests/test_inflight_list.py`), each run against the
test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_inflight_list.py

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

P = "router.tests.test_inflight_list."
ST, NS, RO, SC, RG, AT, AR = (P + c + "." for c in
                              ("StateTests", "NeverSkipsTests", "ReadOnlyTests", "ScopeTests",
                               "RegistryTests", "AnchoredTraversalTests",
                               "AnchoredRegistryTests"))
IF = "router/inflight.py"
MN = "router/__main__.py"

M = [
 ('L1 a torn record is skipped', IF,
  '        return _row(instance, generation, current, state=ROW_UNREADABLE,\n'
  '                    reason="record: not JSON", **base)\n',
  '        return None\n',
  [NS + 'test_a_torn_record_is_unreadable_never_skipped']),
 ('L2 a foreign entry is skipped', IF,
  '                row = _row(instance, generation, current, entry=entry, state=ROW_UNREADABLE,\n'
  '                           reason="not a record or a handed marker")\n',
  '                row = None\n',
  [NS + 'test_a_foreign_entry_is_unreadable_never_skipped']),
 ('L3 a linked record is followed', IF,
  'os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)',
  'os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)',
  [NS + 'test_a_linked_record_is_reported_not_followed']),
 ('L4 an orphan marker is skipped', IF,
  '                row = _orphan_row(instance, generation, current, dfd, entry, req_id)\n',
  '                continue\n',
  [NS + 'test_a_marker_with_no_record_is_an_orphan_row']),
 ('L5 a marker beside its record is a second row', IF,
  '                    continue    # read with its record\n',
  '                    pass\n',
  [NS + 'test_a_marker_beside_its_record_is_not_a_second_row']),
 ('L6 the listing takes the drain lock', MN,
  '    ns = config_mod.RUNTIME_NS\n    if args.name is not None and args.name != ns',
  '    ns = config_mod.RUNTIME_NS\n    acquire_lock(cfg.state_dir)\n'
  '    if args.name is not None and args.name != ns',
  [RO + 'test_a_listing_during_a_live_drain_changes_nothing',
   RO + 'test_no_lock_file_is_created']),
 ('L7 the listing takes and releases the lock', MN,
  '    ns = config_mod.RUNTIME_NS\n    if args.name is not None and args.name != ns',
  '    ns = config_mod.RUNTIME_NS\n    acquire_lock(cfg.state_dir).release()\n'
  '    if args.name is not None and args.name != ns',
  [RO + 'test_no_lock_file_is_created']),
 ('L8 the listing sweeps orphan snapshots', IF,
  '            if known is None:\n                rows += _child_rows(',
  '            if known is None:\n                sweep_snapshots(cfg, name)\n'
  '                rows += _child_rows(',
  [RO + 'test_a_listing_during_a_live_drain_changes_nothing']),
 ('L9 the registry read records its seq', MN,
  '            cfg.registry_dir, cfg.state_dir, cfg.instances, persist=False).known or {})\n',
  '            cfg.registry_dir, cfg.state_dir, cfg.instances, persist=True).known or {})\n',
  [RG + 'test_the_registry_is_read_without_recording_its_seq']),
 ('L10 fenced generations are skipped', IF,
  '        for g in doc["gens"]:\n            rows += _child_rows(',
  '        for g in [g for g in doc["gens"] if g["gen"] == doc["current"]]:\n'
  '            rows += _child_rows(',
  [RG + 'test_a_fenced_generation_is_listed_beside_the_current_one']),
 ('L11 a revoked record reads as handed', IF,
  '    if rec.get("revocation_unenforceable") is not None:\n',
  '    if False:\n',
  [ST + 'test_a_revoked_record_is_revoked_not_handed']),
 ('L12 an unresolved instance is silent', IF,
  '        return [_row(name, None, None, state=ROW_UNRESOLVED,\n'
  '                     reason="the registry resolves no logical_id for it")]\n',
  '        return []\n',
  [RG + 'test_an_instance_the_registry_does_not_resolve_is_one_unresolved_row']),
 ('L13 a held generations file is silent', IF,
  '            return [_row(name, None, None, state=ROW_UNRESOLVED, reason=str(e))]\n',
  '            return []\n',
  [AR + 'test_a_generations_file_outside_its_schema_is_one_unresolved_row']),
 ('L14 the runtime namespace is skipped', IF,
  '        if runtime:\n            rows += _list_runtime(anchor, now=now)\n',
  '        if False:\n            rows += _list_runtime(anchor, now=now)\n',
  [SC + 'test_the_runtime_namespace_is_listed_per_generation']),
 ('L15 a marker naming another id counts as handed', IF,
  '    handed = marker == n.encode("ascii")\n',
  '    handed = marker is not None\n',
  [ST + 'test_a_marker_naming_another_transport_id_is_not_handed']),
 ('L16 the ancestor guard disabled (every component followed)', IF,
  'def _open_child(parent_fd: int, name: str) -> Optional[int]:\n',
  'def _open_child(parent_fd, name):\n'
  '    try:\n'
  '        return os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)\n'
  '    except FileNotFoundError:\n'
  '        return None\n\n\n'
  'def _open_child_unused(parent_fd: int, name: str) -> Optional[int]:\n',
  [AT + 'test_a_linked_instance_directory_is_reported_not_followed',
   AT + 'test_a_linked_runtime_root_is_reported_not_followed',
   AR + 'test_a_linked_generation_directory_is_reported_not_followed']),
 ('L17 the per-component identity check dropped', IF,
  '    if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):\n',
  '    if False:\n',
  [AT + 'test_a_component_replaced_while_it_was_opened_is_reported']),
 ('L18 the runtime root opened following links', IF,
  '        rfd = _open_child(anchor, ns)\n',
  '        rfd = os.open(ns, os.O_RDONLY | os.O_DIRECTORY, dir_fd=anchor)\n',
  [AT + 'test_a_linked_runtime_root_is_reported_not_followed']),
 ('L19 the logical-id directory opened following links', IF,
  '        lfd = _open_child(anchor, lid)\n',
  '        lfd = os.open(lid, os.O_RDONLY | os.O_DIRECTORY, dir_fd=anchor)\n',
  [AR + 'test_a_linked_logical_id_directory_is_reported_not_followed']),
 ('L20 instance and generation directories opened following links', IF,
  '        fd = _open_child(parent_fd, name)\n',
  '        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)\n',
  [AT + 'test_a_linked_instance_directory_is_reported_not_followed',
   AT + 'test_a_linked_runtime_generation_is_reported_not_followed',
   AR + 'test_a_linked_generation_directory_is_reported_not_followed']),
 ('L21 the pre-generation layout skipped', IF,
  '            return _list_dir(name, "legacy", None, lfd, runtime=False, now=now)\n',
  '            return []\n',
  [AR + 'test_the_pre_generation_layout_is_listed_as_legacy']),
 ('L22 an unreadable marker beside its record read as absent', IF,
  '        return _row(instance, generation, current, state=ROW_UNREADABLE,\n'
  '                    reason=f"handed marker: {_why(e)}", **facts)\n',
  '        marker = None\n',
  [AT + 'test_an_unreadable_marker_beside_its_record_is_never_not_handed']),
 ('L23 an inflight that is not a directory is silent', IF,
  '        return [_row(instance, generation, current, entry=INFLIGHT_DIR, state=ROW_UNREADABLE,\n'
  '                     reason=f"the inflight directory: {e}")]\n',
  '        return []\n',
  [AT + 'test_an_inflight_that_is_not_a_directory_is_a_row',
   AT + 'test_a_linked_inflight_directory_is_reported_not_followed']),
 ('L24 a generations file that is not JSON is silent', IF,
  '            return [_row(name, None, None, state=ROW_UNRESOLVED,\n'
  '                         reason=f"{gens_mod.GEN_FILE} is not JSON")]\n',
  '            return []\n',
  [RG + 'test_a_held_generations_file_is_one_unresolved_row']),
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
