"""Single-rule mutants for the peer ledger, the one resolution and the
decide-hook builder (`router/peerledger.py`, `router/peerpolicy.py`, the
profile-factory seam in `router/peerjournal.py`), each run against the test
that names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_peerledger.py

Same discipline as `mutate_reuse.py`: one rule per mutant, bytecode caching
OFF and `__pycache__` cleared before each run, the file restored after, and a
mutant is RED only when unittest reports the named test as a FAILURE (an
ERROR is not red). Exit 0 only when the named tests are green unmutated and
every mutant turns every named test red. Not a test module itself (its name
keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_peerledger."
LED, POL, PJ, SVC = ("router/peerledger.py", "router/peerpolicy.py", "router/peerjournal.py",
                     "router/service.py")
OUT, CLS = "router/outbound.py", "router/classify.py"

M = [
 ("L1 placed keyed by id alone", LED,
  '    return ledger_root(state_dir, logical_id) / PLACED_DIR / remote_key(remote) / f"{record_id}.json"\n',
  '    return ledger_root(state_dir, logical_id) / PLACED_DIR / f"{record_id}.json"\n',
  [T + "PlacedRecordTests.test_two_remotes_with_the_same_id_get_their_own_records"]),
 ("L2 different bytes on a retry accepted", LED,
  "    except peerbind.LinkConflict:\n        raise LedgerConflict(str(path)) from None\n",
  "    except peerbind.LinkConflict:\n        return \"exists_same\"\n",
  [T + "PlacedRecordTests.test_a_retry_with_identical_bytes_is_accepted_and_different_bytes_conflict"]),
 ("L3 an open placed record accepted", LED,
  '    if set(record) != set(peerlane.LEDGER_MEMBERS) or record.get("direction") != direction:\n',
  '    if record.get("direction") != direction:\n',
  [T + "PlacedRecordTests.test_the_record_is_closed_and_the_id_is_the_statement_grammar"]),
 ("L4 the remote keyed raw", LED,
  '    return hashlib.sha256(canonical(remote).encode("utf-8")).hexdigest()[:32]\n',
  '    return hashlib.sha256(remote.encode("utf-8")).hexdigest()[:32]\n',
  [T + "PlacedRecordTests.test_the_remote_is_keyed_canonically"]),
 ("L5 the remote not compared", LED,
  '            if want is not None and canonical(rec["remote"]) != want:\n                continue\n',
  '',
  [T + "ResolveTests.test_each_participant_mismatch_is_unresolved"]),
 ("L6 the local address not compared", LED,
  '            if canonical(rec["local_address"]) != local:\n                continue\n',
  '',
  [T + "ResolveTests.test_each_participant_mismatch_is_unresolved"]),
 ("L7 the reply window not applied", LED,
  "    return Resolved(rec) if now < expires else Expired(rec)\n",
  "    return Resolved(rec)\n",
  [T + "ResolveTests.test_an_expired_record_is_expired_not_resolved"]),
 ("L8 an id in both namespaces resolves to the first", LED,
  "    if len(matches) != 1:\n        return None\n",
  "    if not matches:\n        return None\n",
  [T + "ResolveTests.test_an_id_in_both_namespaces_is_unresolved"]),
 ("L9 at submit, the first placed match picked", LED,
  "            out.append(doc)\n    return out\n",
  "            out.append(doc)\n    return out[:1]\n",
  [T + "ResolveTests.test_at_submit_two_placed_matches_are_unresolved_and_one_resolves"]),
 ("L10 the deny after the resolution", POL,
  "        if classify.task_denied(ctx.cfg, hosted, sender):\n"
  "            return peerjournal.Refuse(\"policy\", \"denied\")\n"
  "        in_reply_to = payload.get(\"in_reply_to\")\n"
  "        if in_reply_to is None:\n"
  "            return peerjournal.Resolved(None)\n"
  "        if not isinstance(_resolution(ctx, payload, hosted), peerledger.Resolved):\n"
  "            return peerjournal.Refuse(\"unresolved_reply\")\n",
  "        in_reply_to = payload.get(\"in_reply_to\")\n"
  "        if in_reply_to is not None and not isinstance(_resolution(ctx, payload, hosted),\n"
  "                                                      peerledger.Resolved):\n"
  "            return peerjournal.Refuse(\"unresolved_reply\")\n"
  "        if classify.task_denied(ctx.cfg, hosted, sender):\n"
  "            return peerjournal.Refuse(\"policy\", \"denied\")\n"
  "        if in_reply_to is None:\n"
  "            return peerjournal.Resolved(None)\n",
  [T + "DenyReplyEdgeTests.test_a_deny_refuses_policy_denied_on_every_path"]),
 ("L11 the receive side's own exact deny match", POL,
  "        if classify.task_denied(ctx.cfg, hosted, sender):\n",
  "        if sender.canonical() in ctx.cfg.instances[hosted].task_deny:\n",
  [T + "DenyReplyEdgeTests.test_the_deny_uses_the_submit_sides_skeleton_match"]),
 ("L12 a reverse result made to need an edge", POL,
  '            if isinstance(got, peerledger.Resolved) and got.direction == "issued":\n',
  '            if False:\n',
  [T + "DenyReplyEdgeTests.test_a_reverse_result_needs_no_edge_and_anything_else_does"]),
 ("L13 production_hooks assembling a member itself", POL,
  "    return decide_hooks(production_profile(ctx))\n",
  "    hooks = decide_hooks(production_profile(ctx))\n"
  "    from . import peerjournal\n"
  "    return peerjournal.DecideHooks(check8=hooks.check8, reply=lambda p, h: peerjournal.Resolved(None),\n"
  "                                   edge=hooks.edge, policy=hooks.policy,\n"
  "                                   control_receive=hooks.control_receive, context=ctx)\n",
  [T + "BuilderTests.test_production_hooks_is_decide_hooks_of_the_production_profile"]),
 ("L14 a member built from the wrong part", POL,
  "        policy=_policy(profile), control_receive=_control_receive(profile), context=ctx)\n",
  "        policy=_check8(profile), control_receive=_control_receive(profile), context=ctx)\n",
  [T + "BuilderTests.test_production_holds_every_statement_at_check8_and_policy"]),
 ("L15 conformance with production's policy part", POL,
  "    return Profile(context=ctx, edges=conformance_edges(pairs), policy=PERMISSIVE)\n",
  "    return Profile(context=ctx, edges=conformance_edges(pairs), policy=HOLD)\n",
  [T + "BuilderTests.test_conformance_differs_only_in_the_policy_and_edge_members"]),
 ("L16 a hook bound to the first context it saw", POL,
  "    return peerledger.resolve(ctx.cfg, in_reply_to=payload[\"in_reply_to\"],\n",
  "    return peerledger.resolve(globals().setdefault(\"_FIRST_CFG\", ctx.cfg),\n"
  "                              in_reply_to=payload[\"in_reply_to\"],\n",
  [T + "BuilderTests.test_two_contexts_resolve_only_in_their_own_ledger"]),
 ("L17 Ctx's binding check removed", PJ,
  "            raise TypeError(\"hooks: built over another pass's context\")\n",
  "            pass\n",
  [T + "ContextBindingTests.test_hooks_bound_to_this_pass_are_accepted_and_any_other_refused"]),
 ("L18 the factory's context not checked", PJ,
  "    if getattr(profile, \"context\", None) is not hctx:\n"
  "        raise TypeError(\"profile_factory: the profile must hold the context it was given\")\n",
  "",
  [T + "PassFactoryTests.test_the_factory_gets_this_pass_context_and_must_return_it"]),
 ("L19 poll stops forwarding the factory to poll_host", PJ,
  "                                    touched=touched, profile_factory=profile_factory)\n",
  "                                    touched=touched)\n",
  [T + "ForwardingTests.test_poll_forwards_the_identical_factory_and_its_clock"]),
 ("L20 poll stops forwarding the factory to recover", PJ,
  "                                   now=now, first_pass=first, skip=touched,\n"
  "                                   profile_factory=profile_factory)\n",
  "                                   now=now, first_pass=first, skip=touched)\n",
  [T + "ForwardingTests.test_poll_forwards_the_identical_factory_and_its_clock"]),
 ("L21 poll stops forwarding the factory to poll_generation", PJ,
  "                    current=gen == doc[\"current\"], touched=touched,\n"
  "                    profile_factory=profile_factory)\n",
  "                    current=gen == doc[\"current\"], touched=touched)\n",
  [T + "ForwardingTests.test_poll_forwards_the_identical_factory_and_its_clock"]),
 ("L22 the service passes a factory", SVC,
  "                                      delegation=peerlane.current(cfg),\n"
  "                                      now=clock.now())\n",
  "                                      delegation=peerlane.current(cfg),\n"
  "                                      now=clock.now(), profile_factory=None)\n",
  [T + "SeamRulesTests.test_no_module_outside_peerjournal_passes_a_profile_factory"]),
 ("L23 a callable edge part accepted", POL,
  "        raise TypeError(\"decide_hooks: the edge part is TRUSTED_HOST_DEFAULT or a frozenset \"\n",
  "        _ = (\"decide_hooks: the edge part is TRUSTED_HOST_DEFAULT or a frozenset \"\n",
  [T + "BuilderTests.test_every_part_must_be_data"]),
 ("L24 the placed record written after the notice", PJ,
  "    try:\n        _write_placed(ctx, auth)\n",
  "    try:\n        pass\n",
  [T + "PlacedBeforeNoticeTests.test_the_placed_record_exists_when_the_notice_is_written",
   T + "PlacedBeforeNoticeTests.test_a_crash_between_placed_and_the_notice_places_once"]),
 ("L25 production with the permissive policy", POL,
  "    return Profile(context=ctx, edges=TRUSTED_HOST_DEFAULT, policy=HOLD)\n",
  "    return Profile(context=ctx, edges=TRUSTED_HOST_DEFAULT, policy=PERMISSIVE)\n",
  [T + "BuilderTests.test_production_holds_every_statement_at_check8_and_policy",
   T + "FactoryThroughAPassTests.test_the_production_default_holds_at_check8"]),
 ("L26 a pass ignores its factory", PJ,
  "    factory = peerpolicy.production_profile if profile_factory is None else profile_factory\n",
  "    factory = peerpolicy.production_profile\n",
  [T + "FactoryThroughAPassTests.test_an_absent_pair_is_no_edge_and_a_present_one_places"]),
 ("L27 a hook module keeps a cache", POL,
  "_EDGE_MARKERS = (TRUSTED_HOST_DEFAULT,)\n",
  "_EDGE_MARKERS = (TRUSTED_HOST_DEFAULT,)\n_CACHE = {}\n",
  [T + "SeamRulesTests.test_the_hook_modules_hold_no_mutable_state_and_read_no_clock"]),
 ("L29 step 4a skipped", OUT,
  '    if record is None or (record.get("tree") == deliver_mod.TREE_PEER\n',
  '    if False and (record.get("tree") == deliver_mod.TREE_PEER\n',
  [T + "ResultSubmitTests.test_a_reply_to_a_placed_task_is_a_signed_result_to_its_remote"]),
 ("L30 the result sent to the draft's recipient", OUT,
  "    classified = classify_mod._trusted(cfg, name, draft, [classify_mod.parse_address(remote)],\n",
  "    remote = ((doc.get(\"draft\") or {}).get(\"to\") or [remote])[0]\n"
  "    classified = classify_mod._trusted(cfg, name, draft, [classify_mod.parse_address(remote)],\n",
  [T + "ResultSubmitTests.test_a_reply_to_a_placed_task_is_a_signed_result_to_its_remote"]),
 ("L31 the statement without its in_reply_to", CLS,
  "        sender_since=sender_since(cfg, sender), in_reply_to=in_reply_to)\n",
  "        sender_since=sender_since(cfg, sender))\n",
  [T + "ResultSubmitTests.test_a_reply_to_a_placed_task_is_a_signed_result_to_its_remote"]),
 ("L32 the sender's age not checked for a result", CLS,
  "    age = sender_age_refusal(cfg, sender, now)\n",
  "    age = sender_age_refusal(cfg, sender, now) if in_reply_to is None else None\n",
  [T + "ResultSubmitTests.test_an_agent_under_24_hours_old_is_refused_and_nothing_is_signed"]),
 ("L33 the exposure not checked for a result", CLS,
  "    if stamp is None:\n",
  "    if stamp is None and in_reply_to is None:\n",
  [T + "ResultSubmitTests.test_an_unavailable_exposure_is_refused_and_nothing_is_signed"]),
 ("L34 a closed window not refused before hand-over", OUT,
  "        if isinstance(got, peerledger.Expired):\n            return inflight_mod.Recheck(False, verdict={\n",
  "        if False:\n            return inflight_mod.Recheck(False, verdict={\n",
  [T + "ResultRecheckTests.test_a_window_closed_before_hand_over_is_refused_not_sent"]),
 ("L28 a router module builds a conformance profile", SVC,
  "def poll_once(",
  "def _conf(h):\n    from . import peerpolicy\n    return peerpolicy.conformance_profile(h, None, [])\n\n\n"
  "def poll_once(",
  [T + "SeamRulesTests.test_no_router_module_builds_a_conformance_profile"]),
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
