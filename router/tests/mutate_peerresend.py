"""Single-rule mutants for the no-resign resend workflow
(`router/peerresend.py`, its hooks in `router/inflight.py` and
`router/outbound.py`, its config default), each run against the test that
names it.

Run from the repository root:

    python3 -B router/tests/mutate_peerresend.py

Same discipline as `mutate_peerledger.py`: one rule per mutant, bytecode
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

T = "router.tests.test_peerresend."
PR, INF, OUT, CF = ("router/peerresend.py", "router/inflight.py", "router/outbound.py",
                    "router/config.py")

M = [
 ("preserved after the handed marker", INF,
  '    if preserve is not None:\n        # The original is preserved, committed, BEFORE the handed marker',
  '    _effect("handed", atomic_write, handed, n.encode("ascii"), durable_root=cfg.state_dir)\n'
  '    if preserve is not None:\n        # The original is preserved, committed, BEFORE the handed marker',
  [T + "PreservationTests.test_the_copy_is_committed_before_the_marker_and_before_the_transport"]),
 ("preserved after write_request", INF,
  '    if preserve is not None:\n        # The original is preserved, committed, BEFORE the handed marker',
  '    writer.write_request(n, data)\n'
  '    if preserve is not None:\n        # The original is preserved, committed, BEFORE the handed marker',
  [T + "PreservationTests.test_the_copy_is_committed_before_the_marker_and_before_the_transport"]),
 ("a preservation failure proceeds to the transport", INF,
  '                         type(e).__name__, e)\n            return BLOCKED\n    _effect("handed"',
  '                         type(e).__name__, e)\n    _effect("handed"',
  [T + "PreservationTests.test_a_staging_failure_holds_named_and_nothing_is_handed",
   T + "PreservationTests.test_a_crash_before_commit_is_never_read_and_is_rewritten"]),
 ("an uncommitted copy is read", PR,
  '        d = copy_dir(cfg.state_dir, lid, peer_id)\n        if committed(d):\n            out.append((name, lid, d))\n',
  '        d = copy_dir(cfg.state_dir, lid, peer_id)\n        if d.is_dir():\n            out.append((name, lid, d))\n',
  [T + "PreservationTests.test_a_crash_before_commit_is_never_read_and_is_rewritten"]),
 ("the preserved time compared", PR,
  '    want = {k: v for k, v in origin.items() if k != "preserved_ts"}\n',
  '    want = dict(origin)\n',
  [T + "PreservationTests.test_a_crash_after_commit_keeps_the_first_preserved_time"]),
 ("a different committed copy silently replaced", PR,
  '    if committed(d):\n        _compare_committed(d, record, origin, blobs)\n        return d\n',
  '    if committed(d):\n        shutil.rmtree(d)\n',
  [T + "PreservationTests.test_a_different_committed_copy_holds_and_nothing_is_handed"]),
 ("evidence not required", PR,
  '    if not (isinstance(evidence, str) and evidence.strip()):\n',
  '    if not isinstance(evidence, str):\n',
  [T + "RefusalTests.test_evidence_is_required"]),
 ("a second claim not refused", PR,
  '    if copy["claim"] is not None:\n        raise Refused("retransmit_pending"',
  '    if False:\n        raise Refused("retransmit_pending"',
  [T + "RefusalTests.test_a_second_retransmit_while_one_is_claimed_is_pending"]),
 ("a rotated key not refused", PR,
  '    if pin["key_id"] != key_id:\n', '    if False:\n',
  [T + "RefusalTests.test_a_rotated_signing_key_refuses",
   T + "CancellationTests.test_a_key_rotated_before_the_first_hand_over_cancels_it"]),
 ("the window's end inclusive", PR,
  '    if end is None or now > end:\n', '    if end is None or now >= end:\n',
  [T + "RefusalTests.test_one_second_past_the_window_refuses_and_inside_it_does_not"]),
 ("the window not checked", PR,
  '    if end is None or now > end:\n', '    if end is None:\n',
  [T + "RefusalTests.test_one_second_past_the_window_refuses_and_inside_it_does_not",
   T + "CancellationTests.test_the_window_closing_before_the_first_hand_over_cancels_it"]),
 ("a received control notice does not answer it", PR,
  '    if peerledger.notified_path(cfg.state_dir, lid, peer_id).exists():\n',
  '    if False:\n',
  [T + "RefusalTests.test_a_received_control_notice_answers_it",
   T + "CancellationTests.test_an_answer_arriving_before_the_first_hand_over_cancels_it"]),
 ("a rejected original eligible", PR,
  '    elif settled is not None and settled.get("outcome") != "accepted":\n',
  '    elif False:\n',
  [T + "RefusalTests.test_a_rejected_original_is_not_eligible"]),
 ("staleness not required", PR,
  '        if (now - handed).total_seconds() < inflight.STALE_AFTER_S:\n',
  '        if False:\n',
  [T + "RefusalTests.test_an_accepted_original_needs_allow_pending_and_staleness"]),
 ("trigger 2 without --allow-pending", PR,
  '        if not allow_pending:\n', '        if False:\n',
  [T + "RefusalTests.test_an_accepted_original_needs_allow_pending_and_staleness"]),
 ("a changed sender policy not refused", PR,
  '    if rc is not None:\n        raise Refused("policy_changed", rc)\n', '',
  [T + "RefusalTests.test_a_changed_sender_policy_refuses"]),
 ("the gate only in the verb", OUT,
  '        cancel = peerresend.gate(cfg, name, record, clock.now())\n',
  '        cancel = None\n',
  [T + "CancellationTests.test_the_window_closing_before_the_first_hand_over_cancels_it",
   T + "CancellationTests.test_an_answer_arriving_before_the_first_hand_over_cancels_it"]),
 ("the gate on the wall clock", OUT,
  '        cancel = peerresend.gate(cfg, name, record, clock.now())\n',
  '        import datetime as _dt\n        cancel = peerresend.gate(cfg, name, record, _dt.datetime.now(_dt.timezone.utc))\n',
  [T + "CancellationTests.test_the_window_closing_before_the_first_hand_over_cancels_it"]),
 ("the gate skipped in recovery", PR,
  '                check_dynamic(cfg, name, lid, copy, allow_pending=True, now=now)\n                begin_record(',
  '                begin_record(',
  [T + "CancellationTests.test_recovery_after_a_crash_before_the_record_runs_the_gate"]),
 ("the claim removed before the settled line", PR,
  '            _audit(cfg, SETTLED_ACT, now, id=d.name, generation=gen, n=n, by=claim["by"],\n'
  '                   outcome=settled.get("outcome"), reason_code=settled.get("reason_code"))\n'
  '            os.unlink(d / CLAIM)\n',
  '            os.unlink(d / CLAIM)\n'
  '            _audit(cfg, SETTLED_ACT, now, id=d.name, generation=gen, n=n, by=claim["by"],\n'
  '                   outcome=settled.get("outcome"), reason_code=settled.get("reason_code"))\n',
  [T + "RecoveryTests.test_a_crash_after_the_settlement_before_the_settled_line"]),
 ("only a hash of the evidence kept", PR,
  '               generation=gen, n=n, by=claim["by"], evidence=claim["evidence"])\n',
  '               generation=gen, n=n, by=claim["by"],\n'
  '               evidence=hashlib.sha256(claim["evidence"].encode()).hexdigest())\n',
  [T + "RecoveryTests.test_a_crash_after_the_claim_before_the_requested_line"]),
 ("a new reservation on recovery", PR,
  '                begin_record(cfg, name, copy, claim)\n            except Refused as e:',
  '                from . import inflight as _inf\n'
  '                begin_record(cfg, name, copy, dict(claim, n=_inf.reserve_transport_id(cfg, name)))\n'
  '            except Refused as e:',
  [T + "RecoveryTests.test_a_crash_after_the_requested_line_before_the_record"]),
 ("the retransmit settled through the agent path", OUT,
  '    if "retransmit" in record:\n        if (not inflight_mod._was_handed(',
  '    if False:\n        if (not inflight_mod._was_handed(',
  [T + "OneResultWriterTests.test_the_original_settling_after_a_retransmit_writes_its_own_result_once",
   T + "RetransmitFlowTests.test_trigger_1_hands_the_original_bytes_under_a_new_n_and_settles_apart"]),
 ("the peer block recomputed", PR,
  '        attachments=atts or None, peer=dict(rec["peer"]),\n',
  '        attachments=atts or None, peer=dict(rec["peer"], message_id=__import__("router.peerlane", fromlist=["x"]).message_id(rec["peer"]["id"], "other.example")),\n',
  [T + "NeverResignTests.test_a_full_retransmit_with_the_six_raising_hands_the_preserved_header",
   T + "RetransmitFlowTests.test_trigger_1_hands_the_original_bytes_under_a_new_n_and_settles_apart"]),
 ("the sweep off by default", CF,
  '    peer_sent_prune = top.get("peer_sent_prune", True)\n',
  '    peer_sent_prune = top.get("peer_sent_prune", False)\n',
  [T + "PruneTests.test_the_sweep_is_on_by_default"]),
 ("the sweep ignores its switch", PR,
  '    if not getattr(cfg, "peer_sent_prune", True):\n', '    if False:\n',
  [T + "PruneTests.test_with_the_sweep_off_nothing_is_pruned"]),
 ("trigger 2 measured from the preservation", PR,
  '        handed = parse_utc_ts((copy.get("handed") or {}).get("handed_ts"))\n',
  '        handed = parse_utc_ts((copy.get("origin") or {}).get("preserved_ts"))\n',
  [T + "StaleFromHandedTests.test_trigger_2_is_measured_from_handed_never_from_preserved"]),
 ("a fenced generation's claims never finished", OUT,
  '                peerresend.finish(view, name, clock.now(), fenced=True)\n',
  '                pass\n',
  [T + "FencedGenerationTests.test_a_handed_retransmit_settles_as_itself_in_its_fenced_generation",
   T + "FencedGenerationTests.test_a_claim_never_begun_in_a_fenced_generation_is_cancelled"]),
 ("a claim begun in a fenced generation", PR,
  '                if fenced:\n                    raise Refused("generation_unavailable", "its generation is fenced")\n',
  '',
  [T + "FencedGenerationTests.test_a_claim_never_begun_in_a_fenced_generation_is_cancelled"]),
 ("a record handed before preservation never preserved", OUT,
  '            preserve(rec)\n        peerresend.note_handed(cfg, name, rec)\n',
  '            pass\n        peerresend.note_handed(cfg, name, rec)\n',
  [T + "UpgradeTests.test_a_record_handed_before_preservation_is_preserved_on_its_next_pass"]),
 ("the preserved copies not reported", OUT,
  '                inflight_summary["peer_sent"] = peerresend.status(cfg, name)\n',
  '                pass\n',
  [T + "StatusTests.test_the_drain_summary_reports_the_copies"]),
 ("the verb ignores an untrusted clock", PR,
  '    if not clock_trusted(cfg):\n        raise Refused("clock_untrusted"',
  '    if False:\n        raise Refused("clock_untrusted"',
  [T + "UntrustedClockTests.test_the_verb_refuses_and_writes_nothing"]),
 ("an unhanded retransmit not held under an untrusted clock", OUT,
  '                and not peerresend.clock_trusted(cfg)):\n',
  '                and False):\n',
  [T + "UntrustedClockTests.test_a_claimed_retransmit_is_held_then_handed_once_the_clock_recovers"]),
 ("recovery cancels under an untrusted clock", PR,
  '        if settled is None and live is None and not clock_trusted(cfg):\n            continue',
  '        if False:\n            continue',
  [T + "UntrustedClockTests.test_a_claim_never_begun_is_held_then_recovered"]),
 ("a received signed Result ignored", PR,
  '        if isinstance(doc, dict) and doc.get("in_reply_to") == peer_id:\n',
  '        if False:\n',
  [T + "SignedResultAnswersTests.test_a_placed_statement_replying_to_it_answers_it"]),
 ("a retransmit keyed by n alone", PR,
  '    _link_once(d / RETRANSMITS / f"{gen}-{record[\'transport_req_id\']}.json", _canonical({\n',
  '    _link_once(d / RETRANSMITS / f"{record[\'transport_req_id\']}.json", _canonical({\n',
  [T + "GenerationKeyingTests.test_a_rotation_reusing_n_keeps_two_distinct_settlements"]),
 ("an attachment omitted from the retransmit", PR,
  '                              rec.get("attachments") or [], copy["blobs"])]\n',
  '                              rec.get("attachments") or [], copy["blobs"][:-1])]\n',
  [T + "CompleteAloneTests.test_the_retransmit_from_the_copy_alone_carries_every_attachment"]),
 ("the draft omitted from the retransmit", PR,
  '    request = dict(rec["request"], req_id=rid)\n',
  '    request = dict(rec["request"], req_id=rid)\n    request["draft"] = dict(request["draft"], body_text="")\n',
  [T + "CompleteAloneTests.test_the_retransmit_from_the_copy_alone_carries_every_attachment",
   T + "RetransmitFlowTests.test_trigger_1_hands_the_original_bytes_under_a_new_n_and_settles_apart"]),
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
