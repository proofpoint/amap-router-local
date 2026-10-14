"""Single-rule mutants for the runtime-generation guards that read the
journal (`router/peercontrol.py`: `_guard_records` and its callers), each run
against the test that names it. While the peer clock is untrusted the
journal reads as empty, and each guard must refuse rather than pass.

Run from the repository root:

    python3 -B router/tests/mutate_guards_clock.py

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

T = "router.tests.test_peercontrol."
U, C, N, B, K = (T + "UntrustedClockGuardTests.", T + "CorruptClockGuardTests.",
                 T + "NoPeerStoreGuardTests.", T + "UnreadableBookkeepingGuardTests.",
                 T + "UnkeptJournalGuardTests.")
S = T + "StrictJournalGuardTests."
PC = "router/peercontrol.py"
PJ = "router/peerjournal.py"

M = [
 ("G1 an untrusted clock reads as an empty journal", PJ,
  '        raise JournalBlind(f"{JOURNAL_BLIND} ({e})") from None\n',
  '        return []\n',
  [U + "test_new_is_refused_untrusted_where_it_is_refused_trusted",
   C + "test_new_is_refused_untrusted_where_it_is_refused_trusted",
   U + "test_retire_is_refused_untrusted_where_it_is_refused_trusted",
   C + "test_new_is_refused_untrusted_even_with_nothing_frozen"]),
 ("G2 a lost clock file reads as no journal", PJ,
  '        if not journaled and not peerclock.path(state_dir).exists():\n',
  '        if not peerclock.path(state_dir).exists():\n',
  [U + "test_new_is_refused_untrusted_where_it_is_refused_trusted"]),
 ("G3 no journal at all is refused too", PJ,
  '        if not journaled and not peerclock.path(state_dir).exists():\n',
  '        if False:\n',
  [N + "test_new_runs_with_no_clock_and_no_journal"]),
 ("G4 unreadable bookkeeping reads as an empty journal", PJ,
  '        raise JournalBlind(f"{JOURNAL_BLIND} (the bookkeeping is unreadable: "\n                           f"{type(e).__name__}: {e})") from None\n',
  '        return []\n',
  [B + "test_retire_is_refused_with_the_bookkeeping_unreadable"]),
 ("G5 the frozen-in guard reads the lenient journal", PC,
  '    (`JournalBlind` when the journal cannot be read)."""\n    out = []\n    for rec in _guard_records(cfg):\n        c = rec.get("control") or {}\n        if ((c.get("attempt") or {}).get("gen") == gen',
  '    (`JournalBlind` when the journal cannot be read)."""\n    out = []\n    for rec in peerjournal.all_records(Path(cfg.state_dir)):\n        c = rec.get("control") or {}\n        if ((c.get("attempt") or {}).get("gen") == gen',
  [U + "test_retire_is_refused_untrusted_where_it_is_refused_trusted",
   C + "test_retire_is_refused_untrusted_where_it_is_refused_trusted"]),
 ("G6 the frozen-elsewhere guard reads the lenient journal", PC,
  '    read (`_guard_records`)."""\n    out = []\n    for rec in _guard_records(cfg):\n',
  '    read (`_guard_records`)."""\n    out = []\n    for rec in peerjournal.all_records(Path(cfg.state_dir)):\n',
  [U + "test_the_drain_mints_nothing_while_untrusted",
   U + "test_a_planned_mint_stays_pending_while_untrusted"]),
 ("G7 the traffic guard reads the lenient journal", PC,
  '    journal cannot be read)."""\n    out = []\n    for rec in _guard_records(cfg):\n        if rec["key"] != key',
  '    journal cannot be read)."""\n    out = []\n    for rec in peerjournal.all_records(Path(cfg.state_dir)):\n        if rec["key"] != key',
  [U + "test_an_unlisted_generation_is_not_restored_while_untrusted"]),
 ("G8 the drain's mint lets the blindness escape", PC,
  '    except JournalBlind as e:\n        raise Unavailable(UNAVAILABLE, str(e)) from None\n',
  '    except KeyError as e:\n        raise Unavailable(UNAVAILABLE, str(e)) from None\n',
  [U + "test_the_drain_mints_nothing_while_untrusted"]),
 ("G9 a blind restore escapes instead of holding", PC,
  '    except JournalBlind:\n        # No evidence either way is not "no traffic": held, never restored.\n',
  '    except KeyError:\n        # No evidence either way is not "no traffic": held, never restored.\n',
  [U + "test_an_unlisted_generation_is_not_restored_while_untrusted"]),
 ("G10 a clock without bookkeeping reads as an empty journal", PJ,
  '        if not journaled:\n            return []\n        raise JournalBlind(JOURNAL_UNKEPT) from None\n',
  '        return []\n',
  [K + "test_new_is_refused_after_a_bound_rebuilt_the_clock_without_its_bookkeeping",
   K + "test_new_is_refused_with_the_store_member_nulled_in_a_valid_clock",
   K + "test_retire_is_refused_with_the_store_member_nulled_in_a_valid_clock"]),
 ("G11 a clock without bookkeeping and no journal is refused too", PJ,
  '        if not journaled:\n            return []\n        raise JournalBlind(JOURNAL_UNKEPT) from None\n',
  '        if False:\n            return []\n        raise JournalBlind(JOURNAL_UNKEPT) from None\n',
  [N + "test_new_runs_with_a_clock_holding_no_store_and_no_journal"]),
 ("G12 the guard walks the bookkeeping's records, not the disk's", PJ,
  '    records = _strict_walk(state_dir)\n',
  '    records = all_records(state_dir)\n',
  [K + "test_an_unreadable_record_refuses_where_all_records_skips_it",
   K + "test_a_frozen_attempt_under_an_unlisted_owner_still_refuses"]),
 ("G13 an unreadable record is skipped", PJ,
  '            except (OSError, ValueError) as e:\n                raise JournalBlind(f"a journal record cannot be read',
  '            except (OSError, ValueError) as e:\n                continue\n                raise JournalBlind(f"a journal record cannot be read',
  [K + "test_an_unreadable_record_refuses_where_all_records_skips_it"]),
 ("G14 an unlistable state directory escapes as an OSError", PJ,
  '    except FileNotFoundError:\n        return False\n    except OSError as e:\n',
  '    except FileNotFoundError:\n        return False\n    except KeyError as e:\n',
  [K + "test_an_unlistable_state_dir_is_journal_blind_never_a_bare_os_error"]),
 ("G15 a record directory without its record is skipped", PJ,
  '                raise JournalBlind(f"a journal record directory has no regular record "\n',
  '                continue\n                raise JournalBlind(f"a journal record directory has no regular record "\n',
  [S + "test_a_record_directory_without_its_record_refuses"]),
 ("G16 the disk is not compared with the bookkeeping", PJ,
  '    _check_bookkeeping(state_dir, meta)\n', '',
  [S + "test_a_record_deleted_whole_refuses_against_the_bookkeeping",
   S + "test_a_missing_journal_root_refuses"]),
 ("G17 a missing journal root is skipped", PJ,
  '            if not journal_root(state_dir, owner).is_dir():\n                raise JournalBlind(',
  '            if not journal_root(state_dir, owner).is_dir():\n                continue\n                raise JournalBlind(',
  [S + "test_a_missing_journal_root_refuses"]),
 ("G18 any object counts as a record", PJ,
  '            if not (isinstance(rec, dict) and rec.get("key") == d.name and "control" in rec\n',
  '            if not (isinstance(rec, dict)\n',
  [S + "test_a_record_that_is_not_a_record_refuses"]),
 ("G19 an intact journal is refused against its bookkeeping", PJ,
  '            if not ((live, str(total), revs) == want or _rolled(entry, d, live, total, revs)):\n',
  '            if True:\n',
  [S + "test_the_bookkeeping_matching_the_disk_passes"]),
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
