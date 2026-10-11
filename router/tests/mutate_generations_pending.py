"""Single-rule mutants for pending snapshots and fenced generations
(`router/tests/test_generations_pending.py`), each run against the test that
names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_generations_pending.py

Same discipline as `mutate_reuse.py`: one rule per mutant, bytecode caching
OFF and `__pycache__` cleared before each run, the file restored after;
every named test must pass unmutated first, and a mutant is RED only when
unittest reports a FAILURE of the named test (an ERROR is printed and is
not red). Exit 0 only when every mutant turns every named test red. Not a
test module itself (its name keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

P = "router.tests.test_generations_pending."
H = "router.tests.test_held_local."
OB = "router/outbound.py"
GN = "router/generations.py"

M = [
 # -- the snapshot -----------------------------------------------------------
 ('S1 the record is written before its snapshot', OB,
  '    snapshot = _write_snapshot(cfg, name, req_id, raw, list(attachments or []))\n',
  '    snapshot = {"nonce": secrets.token_hex(16), "attachments": []}\n',
  [P + 'SnapshotTests.test_the_snapshot_is_written_before_the_record']),
 ('S2 the snapshot digest is not verified', OB,
  '    if hashlib.sha256(raw).hexdigest() != rec["request_sha256"]:\n        raise SnapshotDamaged("request digest")\n',
  '',
  [P + 'SnapshotTests.test_a_damaged_snapshot_holds_and_places_nothing']),
 ('S3 a version-2 record is drained like version 1', OB,
  '    if rec["v"] == 1:\n        if fenced:\n',
  '    if True:\n        if fenced:\n',
  [P + 'SnapshotTests.test_a_vanished_live_entry_continues_from_the_snapshot',
   H + 'RequestIdentityTests.test_a_changed_request_does_not_change_the_held_work']),
 ('S4 a changed live entry does not make the settle private', OB,
  '    private = live or (fenced and not _same_root(cfg, name))\n',
  '    private = fenced and not _same_root(cfg, name)\n',
  [H + 'RequestIdentityTests.test_a_changed_request_does_not_change_the_held_work']),
 ('S5 the snapshot goes before the record', OB,
  '    _remove_pending(path)\n    _remove_snapshot(cfg, name, rec)\n    return outcome\n',
  '    _remove_snapshot(cfg, name, rec)\n    _remove_pending(path)\n    return outcome\n',
  [P + 'SnapshotTests.test_completion_removes_record_then_snapshot']),
 ('S6 the sweep leaves orphan snapshots', OB,
  '        if _private_result_path(cfg, name, req_id).is_file():\n            shutil.rmtree(p, ignore_errors=True)\n',
  '        if False:\n            shutil.rmtree(p, ignore_errors=True)\n',
  [P + 'SnapshotTests.test_the_snapshot_is_written_before_the_record']),
 ('S7 a pending request with no live file is never drained', OB,
  '        for req_id in sorted(set(_pending_ids(cfg, name)) - listed):\n',
  '        for req_id in []:\n',
  [P + 'SnapshotTests.test_a_vanished_live_entry_continues_from_the_snapshot']),
 ('S8 a held reused id is not audited', OB,
  '    if live and not fenced:\n        generations_mod.note_reuse_pending(cfg, name, req_id)\n', '',
  [P + 'SnapshotTests.test_a_changed_live_entry_is_audited_held_then_refused']),
 # -- fenced generations ------------------------------------------------------------
 ('F1 fenced work is not stepped', OB,
  '    for view in _fenced_views(cfg, name):\n', '    for view in []:\n',
  [P + 'FencedTests.test_a_fenced_pending_request_completes_and_is_answered_at_the_same_root',
   P + 'FencedTests.test_a_fenced_in_flight_record_settles_under_its_own_id']),
 ('F2 a fenced generation publishes into a replaced root', OB,
  '    private = live or (fenced and not _same_root(cfg, name))\n',
  '    private = live\n',
  [P + 'FencedTests.test_a_fenced_generation_with_a_replaced_root_settles_privately']),
 ('F3 a fenced version-1 record is drained from the live file', OB,
  '        if fenced:\n            return _block(cfg, name, req_id, rec, BLOCK_LEGACY_SNAPSHOT_MISSING)\n', '',
  [P + 'FencedTests.test_a_fenced_version_1_record_holds']),
 ('F4 first sight takes fenced work\'s files (C1)', 'router/firstsight.py',
  '                    if e.get("filename") not in excluded]\n', '                    if True]\n',
  [P + 'FencedTests.test_a_fenced_in_flight_record_settles_under_its_own_id']),
 ('F5 the current generation drains fenced work\'s files', OB,
  '        if filename in fenced_owned:\n            continue', '        if False:\n            continue',
  [P + 'FencedTests.test_a_fenced_in_flight_record_settles_under_its_own_id']),
 # -- pinned listing --------------------------------------------------------------
 ('L1 the listing follows a symlinked outbound', OB,
  '        out_fd = attachments_mod._descend_pinned(root_fd, inst.outbox_root.relative_to(inst.root))\n',
  '        out_fd = os.open(str(inst.outbox_root), os.O_RDONLY | os.O_DIRECTORY)\n',
  [P + 'PinnedListingTests.test_a_symlinked_outbound_lists_nothing']),
 ('L2 first sight is taken through a symlinked outbound', 'router/firstsight.py',
  '            if kind != "dir":\n                raise FirstSightError(\n',
  '            if kind != "dir":\n                return None\n                raise FirstSightError(\n',
  [P + 'PinnedListingTests.test_first_sight_is_never_taken_through_a_symlinked_outbound']),
 ('L3 no /proc check', OB,
  '    if not os.path.isdir(generations_mod.PINNED_PREFIX):\n', '    if False:\n',
  [P + 'PinnedListingTests.test_registry_mode_without_proc_holds']),
 # -- review round ------------------------------------------------------------------
 ('W1 replay re-derives the sender address', OB,
  '                                  from_address=rec.get("from_address"))\n',
  '                                  from_address=None)\n',
  [P + 'ReviewRoundTests.test_replay_sends_from_the_pinned_address_after_a_domain_flip',
   P + 'ReviewRoundTests.test_replay_sends_from_the_pinned_address_after_a_name_override']),
 ('W2 a damaged fenced record releases its file', OB,
  '        if digest is None:\n            out.add(live.name)\n            continue\n',
  '        if digest is None:\n            continue\n',
  [P + 'ReviewRoundTests.test_a_damaged_fenced_record_keeps_its_file']),
 ('W3 ownership is taken only after the fenced work', OB,
  '        if same_root:\n            owned |= _fenced_claims(cfg, view, name)\n',
  '',
  [P + 'ReviewRoundTests.test_a_fenced_replay_error_never_releases_its_file',
   P + 'ReviewRoundTests.test_a_fenced_replay_error_keeps_the_file_out_of_first_sight']),
 ('W4 a settled fenced verdict is never completed', OB,
  '            for req_id in sorted(_settled_unarchived(cfg, view, name)):\n',
  '            for req_id in []:\n',
  [P + 'ReviewRoundTests.test_a_fenced_in_flight_record_settled_but_not_archived_is_completed_once']),
 ('W5 a transient fault on the live read is a reuse', OB,
  '    except OSError:\n        return HELD                        # a transient fault decides nothing\n',
  '    except OSError:\n        live = True\n',
  [P + 'ReviewRoundTests.test_a_transient_fault_on_the_live_read_decides_nothing']),
 ('W6 a well-formed digest-less anchor always claims', OB,
  '        if digest is _DAMAGED_ANCHOR:\n            out.add(live.name)\n',
  '        if digest is _DAMAGED_ANCHOR or digest is None:\n            out.add(live.name)\n',
  [P + 'DigestlessAnchorTests.test_a_readable_reuse_under_a_fenced_digestless_anchor_is_answered']),
 ('W7 a damaged anchor releases its file', OB,
  '        if digest is _DAMAGED_ANCHOR:\n            out.add(live.name)\n            continue\n',
  '        if digest is _DAMAGED_ANCHOR:\n            continue\n',
  [P + 'DigestlessAnchorTests.test_a_damaged_fenced_anchor_keeps_its_file']),
 ('W8 a digest-less fenced verdict is never completed', OB,
  '        if digest is _DAMAGED_ANCHOR or inflight_mod.record_path(view, name, req_id).exists() \\\n',
  '        if digest is _DAMAGED_ANCHOR or digest is None or inflight_mod.record_path(view, name, req_id).exists() \\\n',
  [P + 'DigestlessAnchorTests.test_a_still_oversized_file_is_completed_by_the_fenced_verdict']),
 ('W9 a damaged fenced anchor is not shown', GN,
  '            if anchor_digest(d / fn) is not DAMAGED_ANCHOR:\n                continue\n',
  '            continue\n',
  [P + 'DigestlessAnchorTests.test_a_damaged_fenced_anchor_is_shown_in_status_with_its_age']),
 ('W10 every fenced anchor is shown as damaged', GN,
  '            if anchor_digest(d / fn) is not DAMAGED_ANCHOR:\n                continue\n',
  '            if False:\n                continue\n',
  [P + 'DigestlessAnchorTests.test_a_readable_fenced_anchor_is_not_shown_as_damaged']),
 ('W11 an unreadable fenced enumeration reads as none', OB,
  '    doc = generations_mod.read_doc(cfg.state_dir, lid)\n    if doc is None:\n',
  '    try:\n        doc = generations_mod.read_doc(cfg.state_dir, lid)\n'
  '    except generations_mod.GenerationHeld:\n        return []\n    if doc is None:\n',
  [P + 'ReviewRoundTests.test_an_unreadable_generations_file_on_the_second_read_holds_the_drain']),
 ('W12 a transient fault on a fenced anchor releases its claim', OB,
  '        except (OSError, ReadTooLargeError):\n            out.add(live.name)\n    return out\n',
  '        except (OSError, ReadTooLargeError):\n            pass\n    return out\n',
  [P + 'DigestlessAnchorTests.test_a_transient_fault_checking_a_fenced_anchor_keeps_its_claim']),
 ('W13 a transient fault under a digest-less anchor is the original', OB,
  '        if _unreadable_now(e):\n            return True\n        raise\n    return False\n',
  '        if _unreadable_now(e):\n            return True\n        return True\n    return False\n',
  [P + 'DigestlessAnchorTests.test_a_transient_fault_under_a_digestless_anchor_publishes_nothing']),
 ('W14 a vanished generations file reads as no fenced generations', OB,
  '    if doc is None:\n        raise generations_mod.GenerationHeld(\n',
  '    if doc is None:\n        return []\n        raise generations_mod.GenerationHeld(\n',
  [P + 'DigestlessAnchorTests.test_a_vanished_generations_file_on_the_second_read_holds_the_drain']),
 # -- the recipient ------------------------------------------------------------------
 ('R1 delivering records no recipient generation', OB,
  '        t.update(state="delivering", notice_id=mint_notice_id(), ts=utc_ts(),\n                 recipient_gen=_recipient_gen(cfg, t["recipient"]))\n',
  '        t.update(state="delivering", notice_id=mint_notice_id(), ts=utc_ts())\n',
  [P + 'RecipientGenerationTests.test_a_begun_placement_holds_when_the_recipient_generation_changes']),
 ('R2 a changed recipient generation is not held', OB,
  '            and _recipient_gen(cfg, r) != target["recipient_gen"]:\n',
  '            and False:\n',
  [P + 'RecipientGenerationTests.test_a_begun_placement_holds_when_the_recipient_generation_changes']),
 ('R3 a mid-pass hold fails the recipient', OB,
  '            held_now.append(r)    # nothing placed for it: it goes pending, below\n',
  '            failed.append(r)\n',
  [P + 'RecipientGenerationTests.test_a_root_swapped_mid_pass_goes_pending_not_failed']),
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
                print(f"{label:52s} {t.split('.')[-1][:58]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
