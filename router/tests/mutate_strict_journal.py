"""Single-rule mutants for the strict journal readers outside the
runtime-generation guards: the resend workflow's `answered` and its holds
(`router/peerresend.py`), the trust verb's reseed (`router/peerepochs.py`)
and the bookkeeping's shape (`router/peerjournal.py`), each run against the
test that names it. Each restores a vacuous pass.

Run from the repository root:

    python3 -B router/tests/mutate_strict_journal.py

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

A = "router.tests.test_peerresend.StrictJournalAnsweredTests."
OUT = "router/outbound.py"
E = "router.tests.test_peerepochs.TrustVerbTests."
G = "router.tests.test_peercontrol.StrictJournalGuardTests."
PR, PE, PJ = "router/peerresend.py", "router/peerepochs.py", "router/peerjournal.py"

M = [
 ("S1 answered reads the lenient journal", PR,
  '    for rec in peerjournal.strict_records(Path(cfg.state_dir)):\n        if rec.get("disposed") != "placed":\n',
  '    for rec in peerjournal.all_records(Path(cfg.state_dir)):\n        if rec.get("disposed") != "placed":\n',
  [A + "test_a_store_less_trusted_clock_beside_the_journal_refuses",
   A + "test_an_unreadable_record_refuses", A + "test_a_non_object_record_refuses"]),
 ("S2 answered swallows the blindness into not answered", PR,
  '    for rec in peerjournal.strict_records(Path(cfg.state_dir)):\n        if rec.get("disposed") != "placed":\n',
  '    try:\n        _recs = peerjournal.strict_records(Path(cfg.state_dir))\n    except Exception:\n        _recs = []\n    for rec in _recs:\n        if rec.get("disposed") != "placed":\n',
  [A + "test_an_unlistable_journal_directory_refuses"]),
 ("S3 a placed statement without its snapshot is skipped", PR,
  '        if not isinstance(doc, dict):\n            raise peerjournal.JournalBlind(\n',
  '        if not isinstance(doc, dict):\n            continue\n            raise peerjournal.JournalBlind(\n',
  [A + "test_a_placed_statement_whose_snapshot_is_not_a_statement_refuses"]),
 ("S4 the verb lets the blindness escape unrefused", PR,
  '    except peerjournal.JournalBlind as e:\n        raise Refused("journal_unreadable"',
  '    except KeyError as e:\n        raise Refused("journal_unreadable"',
  [A + "test_an_unreadable_record_refuses"]),
 ("S5 the drain hands a retransmit while the journal cannot be read", OUT,
  '                and (not peerresend.clock_trusted(cfg)\n                     or peerresend.journal_blind(cfg) is not None)):\n',
  '                and (not peerresend.clock_trusted(cfg))):\n',
  [A + "test_a_claim_is_held_never_handed_while_the_journal_is_unreadable"]),
 ("S6 a claim never begun is not held", PR,
  '        if settled is None and live is None and (not clock_trusted(cfg) or journal_blind(cfg)):\n',
  '        if settled is None and live is None and not clock_trusted(cfg):\n',
  [A + "test_a_claim_never_begun_is_held_while_the_journal_is_unreadable"]),
 ("S7 show says not answered when it cannot tell", PR,
  '        except peerjournal.JournalBlind as e:\n            out["answered"] = f"unknown (journal unreadable: {e})"\n',
  '        except peerjournal.JournalBlind as e:\n            out["answered"] = None\n',
  [A + "test_show_never_says_not_answered_when_it_cannot_tell"]),
 ("S8 the reseed reads the lenient journal", PE,
  '    for rec in pj.strict_records(Path(state_dir)):\n',
  '    for rec in pj.all_records(Path(state_dir)):\n',
  [E + "test_an_unreadable_record_reseeds_nothing_and_keeps_the_flag",
   E + "test_a_record_directory_without_its_record_reseeds_nothing"]),
 ("S9 the trust verb lets the blindness escape", PE,
  '        except pj.JournalBlind as e:\n            # Nothing reseeded from a partial view; the flag stays.\n',
  '        except KeyError as e:\n            # Nothing reseeded from a partial view; the flag stays.\n',
  [E + "test_a_record_that_is_not_a_record_reseeds_nothing"]),
 ("S10 a malformed bookkeeping entry escapes as a bare error", PJ,
  '    except (KeyError, TypeError, AttributeError, ValueError) as e:\n        if isinstance(e, JournalBlind):\n',
  '    except (ValueError,) as e:\n        if isinstance(e, JournalBlind):\n',
  [G + "test_a_malformed_root_entry_refuses_never_a_bare_error",
   G + "test_a_malformed_pending_op_refuses_never_a_bare_error"]),
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
