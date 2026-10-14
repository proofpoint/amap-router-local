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
INF = "router/inflight.py"

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
 ("S10a a roots that is not a mapping is converted", PJ,
  '    if type(roots) is not dict:\n        raise bad("roots is not a mapping")\n', '',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S10b a root entry's shape is not checked", PJ,
  '            raise bad(f"the root entry for {owner!r}")\n', '            pass\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S10c a pending_op that is not an operation is accepted", PJ,
  '        raise bad("pending_op is neither null nor an operation")\n', '        return\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion",
   A + "test_a_falsy_wrong_pending_op_refuses"]),
 ("S10d a delta's shape is not checked", PJ,
  '            raise bad(f"an entry of pending_op {name}\'s delta")\n', '            pass\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S10e the trust verb reseeds over malformed roots", PJ,
  '    if type(roots) is not dict:\n        raise bad("roots is not a mapping")\n', '    if type(roots) is not dict:\n        return\n',
  [E + "test_a_malformed_roots_reseeds_nothing_and_keeps_the_flag"]),
 ("S11 a router state at the gate cancels the retransmit", OUT,
  '        if cancel is not None and cancel[0] in peerresend.HOLD_CODES:\n',
  '        if False:\n',
  [A + "test_a_journal_blind_only_at_the_gate_holds_never_cancels",
   A + "test_each_router_state_at_the_gate_is_a_hold_not_a_verdict"]),
 ("S12 an untrusted clock at the gate cancels", PR,
  'HOLD_CODES = frozenset({"clock_untrusted", "journal_unreadable"})',
  'HOLD_CODES = frozenset({"journal_unreadable"})',
  [A + "test_each_router_state_at_the_gate_is_a_hold_not_a_verdict"]),
 ("S13 the in-flight table settles a hold", INF,
  '        if rc.hold:\n            logger.warning("instance %r req %r: held, not published: %s", name, req_id, rc.why)\n            return BLOCKED\n',
  '',
  [A + "test_a_journal_blind_only_at_the_gate_holds_never_cancels"]),
 ("S14 the op name's type is not checked first", PJ,
  '    if not isinstance(name, str) or name not in PENDING_OP_FORMS:\n',
  '    if name not in PENDING_OP_FORMS:\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S15 an operation's member set is not checked", PJ,
  '    if set(op) != want:\n', '    if False:\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S16 an operation's member values are not checked", PJ,
  '        if not check(op[member]):\n', '        if False:\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S17 an operation's owner form is not checked", PJ,
  '    if not (owner is None if owner_form == "none" else _is_str(owner)):\n',
  '    if False:\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S18 the delta's length is not checked", PJ,
  '    if type(delta) is not list or len(delta) != len(stores):\n',
  '    if type(delta) is not list:\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S19 the delta's store is not checked", PJ,
  '        if not (type(d) is dict and set(d) == _DELTA_MEMBERS and d["store"] == store\n',
  '        if not (type(d) is dict and set(d) == _DELTA_MEMBERS\n',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S20 the delta's owner is not checked", PJ,
  '                and d["owner"] == (owner if store == "root" else None)\n', '',
  [G + "test_each_wrong_bookkeeping_shape_refuses_before_any_conversion"]),
 ("S21 a real writer's form refused", PJ,
  '    "epoch_recount": ({"targets": lambda v: type(v) is list and all(_is_str(t) for t in v)},\n',
  '    "epoch_recount": ({"targets": lambda v: False},\n',
  [E + "test_every_pending_op_the_real_writers_emit_passes_the_shape_check"]),
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
