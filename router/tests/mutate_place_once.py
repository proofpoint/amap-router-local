"""Single-rule mutants for placing once through the intent record
(`test_place_once.py`), the refusal's `attachments[]` (`test_attachments_
outbound.py`, `TestRefusalDiagnosticIsConformant`), the `.control/` listing
(`test_quarantine_cli.py`), the launcher umask (`test_docker.py`,
`EntrypointUmaskTests`) and the agent-visible write barriers
(`test_agent_visible_durability.py`), each run against the tests that name
it.

Run from the repository root:

    python3 -B router/tests/mutate_place_once.py

Same discipline as `mutate_classify.py`: one rule per mutant (a rule
enforced by two redundant guards is mutated as both, and says so), bytecode
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

P = "router.tests.test_place_once."
NR, UR = P + "WithoutARegistry.", P + "UnderARegistry."
A = "router.tests.test_attachments_outbound.TestRefusalDiagnosticIsConformant."
Q = "router.tests.test_quarantine_cli."
GP = "router.tests.test_generations_pending.DigestlessAnchorTests."
U = "router.tests.test_docker.EntrypointUmaskTests."
D = "router.tests.test_agent_visible_durability."
OB, QU, EP = "router/outbound.py", "router/quarantine.py", "docker/entrypoint.sh"


def both(test):
    return [NR + test, UR + test]


M = [
 ('P1 cold mail uses the record only when a target is held', OB,
  '            _any_held(cfg, recipients) or _placement_origin(deliver_backend) is not None):\n',
  '            _any_held(cfg, recipients)):\n',
  both('test_cold_mail_to_two_recipients_places_each_once')),
 ('P2 a bound reply uses the record only when held', OB,
  '    if req_digest is not None and (held or _placement_origin(deliver_backend) is not None):\n',
  '    if req_digest is not None and held:\n',
  both('test_a_bound_reply_places_once')),
 ('P3 a peer route uses the record only when held', OB,
  '    if req_digest is not None:\n        # Held or not, through the record',
  '    if req_digest is not None and _any_held(cfg, [recipient]):\n        # Held or not, through the record',
  both('test_a_peer_route_places_once')),
 ('P4 a direct failure is not terminal', OB,
  '        if rec.get("origin") == ORIGIN_DIRECT and not isinstance(',
  '        if False and not isinstance(',
  both('test_a_failing_recipient_on_a_direct_path_is_answered_failed')),
 ('P5 a replay mints a fresh identity', OB,
  '    if t["state"] in ("held", "ready"):\n        if t["recipient"] in cfg.instances and t["lid"] is None:',
  '    if t["state"] in ("held", "ready", "delivering"):\n        if t["recipient"] in cfg.instances and t["lid"] is None:',
  both('test_a_crash_before_the_delivered_mark_replays_the_same_identity')),
 # Two guards, one rule: the sweep removes an answered record, and the loop
 # skips one the sweep could not; either alone keeps the test green.
 ('P6 a fenced view replays an answered record', OB,
  [('            _sweep_answered_pending(view, name)\n', '            pass\n'),
   ('            if _private_result_path(view, name, req_id).is_file():\n                continue\n',
    '')],
  None,
  [GP + 'test_a_fenced_answered_record_is_swept_never_replayed']),
 ('P7 the legacy address form is damage', OB,
  '                    and (a == address_for(t["recipient"])\n                         or ',
  '                    and (',
  [P + 'WithoutAFleetDomain.test_cold_mail_to_two_recipients_places_each_once',
   P + 'WithoutAFleetDomain.test_a_bound_reply_places_once']),
 ('P8 a direct hold mid-write keeps its identity', OB,
  '            t.update(state="held", reason=e.reason, notice_id=None, ts=None,\n                     recipient_gen=None)\n',
  '            t["reason"] = e.reason\n',
  ['router.tests.test_generations_pending.RecipientGenerationTests.'
   'test_a_root_swapped_mid_pass_goes_pending_not_failed']),
 ('D1 the array written whatever was examined', OB,
  '    if submitted == 1 and e.index == 0:\n',
  '    if True:\n',
  [A + 'test_a_size_cap_on_the_last_attachment_omits_the_array',
   A + 'test_a_cap_on_the_first_of_two_omits_the_array']),
 ('D2 the omitted array leaves no index in detail', OB,
  '    return None, f"{e.detail} (attachment {e.index}: {e.attachment_outcome})"\n',
  '    return None, e.detail\n',
  [A + 'test_a_size_cap_on_the_last_attachment_omits_the_array',
   A + 'test_a_cap_on_the_first_of_two_omits_the_array']),
 ('D3 a malformed refusal leaves no index in detail', OB,
  '        return None, f"{e.detail} (attachment {e.index}: malformed)"\n',
  '        return None, e.detail\n',
  [A + 'test_a_mismatch_after_the_first_attachment_omits_the_array',
   A + 'test_a_failure_at_index_zero_of_two_omits_the_array',
   A + 'test_the_only_attachment_malformed_has_no_array']),
 ('C1 a malformed attachment is called rejected_type', 'router/attachments.py',
  "            f\"{declared_sha}, computed {digest} over the sidecar bytes)\",\n                index=index, attachment_outcome=None,\n",
  "            f\"{declared_sha}, computed {digest} over the sidecar bytes)\",\n                index=index, attachment_outcome=\"rejected_type\",\n",
  [A + 'test_the_only_attachment_malformed_has_no_array',
   'router.tests.test_attachments_outbound.TestIntegrityMismatch.test_sha_mismatch_whole_request_rejected']),
 ('B1 no file fsync before the rename', 'router/attachments.py',
  '            f.flush()\n            os.fsync(f.fileno())\n',
  '            f.flush()\n',
  [D + 'BlobBarrierTests.test_file_fsync_then_rename_then_directory_fsync',
   D + 'BlobBarrierTests.test_a_failed_file_fsync_never_publishes',
   D + 'PlacementIsDurableTests.test_the_notice_is_synced_before_and_after_its_rename']),
 ('B2 no directory fsync after the rename', 'router/attachments.py',
  '    try:\n        os.fsync(dir_fd)\n    except OSError as e:\n',
  '    try:\n        pass\n    except OSError as e:\n',
  [D + 'BlobBarrierTests.test_file_fsync_then_rename_then_directory_fsync',
   D + 'BlobBarrierTests.test_a_failed_directory_fsync_raises_published_not_durable',
   D + 'PlacementIsDurableTests.test_a_failed_barrier_on_the_notice_directory_leaves_the_request_unanswered']),
 ('B3 a directory not made durable in its parent', 'router/attachments.py',
  '        pass\n    os.fsync(parent_fd)\n',
  '        pass\n',
  [D + 'BlobBarrierTests.test_a_directory_is_made_durable_in_its_parent_created_or_not']),
 ('B4 published-not-durable treated as nothing placed', OB,
  '        if rec.get("origin") == ORIGIN_DIRECT and not isinstance(\n                e, attachments_mod.PublishedNotDurable):\n',
  '        if rec.get("origin") == ORIGIN_DIRECT:\n',
  [D + 'PlacementIsDurableTests.test_a_failed_barrier_on_the_notice_directory_leaves_the_request_unanswered']),
 ('Q1 the writer stage is listed', QU,
  '            if entry == STAGE_NAME:\n                continue',
  '            if False:\n                continue',
  [Q + 'ControlTests.test_the_writers_stage_is_not_listed']),
 ('Q2 a missing sentinel is damage', QU,
  '    except Missing:\n',
  '    except NotImplementedError:\n',
  [Q + 'ControlTests.test_a_directory_without_its_candidate_is_not_yet_an_item']),
 ('Q3 a symlink gets the generic open text', QU,
  '        if e.errno == errno.ELOOP:\n',
  '        if False:\n',
  [Q + 'ControlTests.test_damaged_entries',
   Q + 'FormatTests.test_links_and_non_regular_entries']),
 ('Q4 every open error says "without following a link"', QU,
  '        raise Damaged(f"cannot be opened ({os.strerror(e.errno)})") from None\n',
  '        raise Damaged(f"cannot be opened without following a link ({os.strerror(e.errno)})") from None\n',
  [Q + 'ControlTests.test_an_unreadable_candidate_names_its_own_error']),
 ('U1 the launcher leaves the umask alone', EP,
  'umask 0027\n',
  '\n',
  [U + 'test_every_router_mode_runs_under_0027']),
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
