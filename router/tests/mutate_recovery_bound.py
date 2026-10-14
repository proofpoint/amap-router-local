"""Single-rule mutants for the bounded recovery walk (`router/peerjournal.py`:
the not-done index `peer-open/`, `_recovery_worklist`, `_indexed`,
`_full_walk`, and the index writes in `take`, `write_record` and `reconcile`),
each run against the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_recovery_bound.py

Same discipline as `mutate_repoint.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after, and a mutant is RED only when unittest reports the named test as a
FAILURE (an ERROR is not red). Not a test module itself. It mutates the
checkout in place: run it only in a private worktree.
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_peer_recovery_bound."
W, I, D, F, U, R, S = (T + "IndexWriteTests.", T + "IndexedPassTests.", T + "DamageTests.",
                       T + "FailedWalkTests.", T + "UpgradeTests.",
                       T + "RecoverUsesTheWorklistTests.", T + "ScheduleTests.")
PJ = "router/peerjournal.py"

M = [
 ("B1 the marker is never written", PJ,
  '        _mark_open(state_dir, owner, key, seq)\n        rdir.mkdir(mode=0o700)\n',
  '        rdir.mkdir(mode=0o700)\n',
  [W + "test_take_writes_the_marker_with_its_take_seq"]),
 ("B2 the marker is written after the record directory", PJ,
  '        _mark_open(state_dir, owner, key, seq)\n        rdir.mkdir(mode=0o700)\n        created = True\n',
  '        rdir.mkdir(mode=0o700)\n        created = True\n        _mark_open(state_dir, owner, key, seq)\n',
  [W + "test_the_marker_is_written_before_the_record_directory"]),
 ("B3 done closes a tree record whatever removed says", PJ,
  '    return record.get("state") != "done" or (record.get("intake") not in HOST_INTAKES\n                                             and not record.get("removed"))\n',
  '    return record.get("state") != "done"\n',
  [W + "test_done_but_not_removed_keeps_its_marker"]),
 ("B4 the marker goes before the record write", PJ,
  '    _write_meta(state_dir, meta)\n    atomic_write(path, new, durable_root=state_dir)\n',
  '    _write_meta(state_dir, meta)\n    if not is_open(new_record):\n        _unmark_open(state_dir, owner, key)\n    atomic_write(path, new, durable_root=state_dir)\n',
  [W + "test_the_marker_goes_only_after_the_record_write"]),
 ("B5 the take's cleanup leaves the orphan marker", PJ,
  '            _unmark_open(state_dir, owner, key, durable=True)\n            _mark_vacant(state_dir, seq)\n',
  '            _mark_vacant(state_dir, seq)\n',
  [W + "test_crash_point_2_marker_durable_no_record_is_removed_by_the_takes_cleanup"]),
 ("B6 reconcile leaves a rolled-back take's marker", PJ,
  '            not (record_dir(state_dir, op["owner"], op["key"]) / RECORD).exists():\n        _unmark_open(state_dir, op["owner"], op["key"], durable=True)\n',
  '            not (record_dir(state_dir, op["owner"], op["key"]) / RECORD).exists():\n        pass\n',
  [W + "test_crash_point_2_left_by_a_hard_crash_is_removed_by_reconcile"]),
 ("B7 reconcile rolls back a committed record's marker", PJ,
  '    if op is not None and op["op"] == "take" and \\\n            not (record_dir(state_dir, op["owner"], op["key"]) / RECORD).exists():\n',
  '    if op is not None and op["op"] == "take":\n',
  [W + "test_crash_point_3_record_durable_bookkeeping_not_keeps_the_marker"]),
 ("B8 the first pass is indexed", PJ,
  '    st = _RECOVERY.setdefault(key, {"last_full": None, "required": True})\n',
  '    st = _RECOVERY.setdefault(key, {"last_full": _monotonic(), "required": False})\n',
  [I + "test_the_first_pass_is_a_full_walk"]),
 ("B9 the hourly backstop is never due", PJ,
  '           or now - st["last_full"] >= FULL_WALK_S)\n',
  '           )\n',
  [I + "test_the_bound_an_unmarked_record_waits_for_the_hourly_walk"]),
 ("B10 the scheduler runs on the wall clock", PJ,
  '    from . import hoplink\n    return hoplink._clock()\n', '    from datetime import datetime\n    return datetime.now().timestamp()\n',
  [S + "test_the_default_scheduler_clock_is_monotonic"]),
 ("B11 an indexed pass orders by key", PJ,
  '            return sorted(open_recs, key=lambda r: r["take_seq"])\n',
  '            return sorted(open_recs, key=lambda r: r["key"])\n',
  [I + "test_an_indexed_pass_evaluates_the_open_set_in_take_seq_order"]),
 ("B12 phase 2 leaves a closed record's marker", PJ,
  '            for owner, k in stale:\n                _unmark_open(state_dir, owner, k)\n',
  '            for owner, k in stale:\n                pass\n',
  [I + "test_a_closed_records_marker_is_sound_and_unlinked_in_phase_2"]),
 ("B13 a closed record's marker is damage", PJ,
  '            else:\n                stale.append((owner, name))\n',
  '            else:\n                raise _IndexDamage("closed")\n',
  [I + "test_a_closed_records_marker_is_sound_and_unlinked_in_phase_2"]),
 ("B14 the marker's take_seq is not compared", PJ,
  '                    and rec.get("owner") == owner and rec.get("take_seq") == seq):\n',
  '                    and rec.get("owner") == owner):\n',
  [D + "test_a_marker_with_the_wrong_decimal"]),
 ("B15 a marker naming an absent record is skipped", PJ,
  '            except (OSError, ValueError) as e:\n                raise _IndexDamage(f"{owner}/{name}: the record cannot be read "\n',
  '            except (OSError, ValueError) as e:\n                continue\n                raise _IndexDamage(f"{owner}/{name}: the record cannot be read "\n',
  [D + "test_a_marker_naming_an_absent_record"]),
 ("B16 a missing index beside records reads as empty", PJ,
  '            if has_records:\n                raise _IndexDamage(', '            if False:\n                raise _IndexDamage(',
  [D + "test_a_missing_index_beside_records"]),
 ("B17 index damage evaluates nothing instead of walking fully", PJ,
  '            logger.warning("peer recovery: the not-done index is damaged (%s); walking fully", e)\n',
  '            return []\n',
  [D + "test_damage_found_after_a_sound_entry_evaluates_nothing_early", D + "test_a_marker_with_the_wrong_decimal"]),
 ("B18 a failed walk keeps the index trusted", PJ,
  '    st["required"] = True                   # cleared only by a COMPLETE walk\n',
  '',
  [S + "test_a_failed_walk_after_a_good_one_distrusts_the_index_again"]),
 ("B19 a marker removed on a partial view", PJ,
  '            rec = json.loads((d / RECORD).read_text(encoding="utf-8"))\n            if is_open(rec):\n                open_recs.append(rec)\n                seen_open[owner].add(d.name)\n',
  '            try:\n                rec = json.loads((d / RECORD).read_text(encoding="utf-8"))\n            except ValueError:\n                continue\n            if is_open(rec):\n                open_recs.append(rec)\n                seen_open[owner].add(d.name)\n',
  [F + "test_an_interrupted_full_walk_keeps_the_schedule_and_every_marker"]),
 ("B20 an unremovable stray trusts the index", PJ,
  '    if complete:\n        st["required"] = False\n', '    if True:\n        st["required"] = False\n',
  [F + "test_an_unremovable_stray_keeps_the_next_pass_full"]),
 ("B21 a take in progress loses its marker to a full walk", PJ,
  '            if (owner, k) == in_take:\n                continue\n', '',
  [S + "test_a_take_in_progress_keeps_its_marker_through_a_full_walk"]),
 ("B22 recover walks the journal instead of the worklist", PJ,
  '    pending = _recovery_worklist(state_dir, meta)\n',
  '    pending = _full_walk(state_dir, meta)[0]\n',
  [R + "test_it_visits_the_worklist_and_nothing_else"]),
 ("B23 recover drops the skip set", PJ,
  '    pending = [r for r in pending if r["key"] not in skip]\n', '',
  [R + "test_the_skip_set_is_kept"]),
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
