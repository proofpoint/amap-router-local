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
PC, INF = "router/peercontrol.py", "router/inflight.py"
C = "router.tests.test_peercontrol."

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
  '    if record is None or _signed_placement(record):\n',
  '    if False:\n',
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
 ("L35 the runtime gate ignores the declaration", PC,
  "    if not transport_mod.runtime_capability_declared(plugin):\n        return None\n",
  "",
  [C + "GateTests.test_no_capability_attempts_nothing_and_calls_no_factory"]),
 ("L36 the statement signed at the intent's time", PC,
  "        ts = format_utc_ts(clock_mod.now())        # signed now, never at the intent time\n",
  "        ts = attempt[\"at\"]\n",
  [C + "AttemptTests.test_the_statement_is_signed_at_the_attempt_not_the_intent"]),
 ("L37 re-signed on a re-drive", PC,
  '    if "n" not in attempt:\n',
  '    if True:\n',
  [C + "AttemptTests.test_a_crash_after_the_bytes_are_frozen_re_begins_them_unsigned"]),
 ("L38 a changed destination redirected, not suppressed", PC,
  '    if owner is None or owner.runtime != control["to"]:\n',
  '    if owner is None:\n',
  [C + "SuppressionTests.test_a_destination_no_longer_configured_is_suppressed_not_redirected"]),
 ("L39 no coalescing owner", PC,
  '    return (d / name).read_text(encoding="ascii").strip()\n',
  '    return key\n',
  [C + "SuppressionTests.test_the_coalescing_owner_is_link_once_for_the_whole_triple"]),
 ("L40 the bucket refilled on wall time", PC,
  "    elapsed = max(0.0, (h - last).total_seconds())     # H only rises\n",
  "    elapsed = 3600.0\n",
  [C + "RateTests.test_the_bucket_is_measured_on_h_never_raw_time"]),
 ("L41 an untrusted clock attempts anyway", PC,
  '        return {"held_clock_untrusted": len(pending(state_dir))}\n',
  '        clock = type("Trusted", (), {"H": now, "admission": "open"})()\n',
  [C + "SuppressionTests.test_nothing_is_attempted_while_the_clock_is_untrusted"]),
 ("L42 an unreadable generation does not block the mint", PC,
  '    others = [(g, s) for g, s in listed if s in ("live", "unreadable") and g != recorded]\n',
  '    others = [(g, s) for g, s in listed if s == "live" and g != recorded]\n',
  [C + "ListerTests.test_an_unreadable_generation_blocks_the_mint"]),
 ("L43 an unknown generation state taken as definite", PC,
  '                state = "unreadable"     # never read as definite\n',
  '                pass\n',
  [C + "ListerTests.test_an_unknown_state_is_never_read_as_definite"]),
 ("L44 status guesses a runtime tree", PC,
  '        doc["runtime_tree"] = "unavailable"\n',
  '        doc["runtime_tree"] = {"generation": None}\n',
  [C + "GateTests.test_no_plugin_at_all_is_unavailable"]),
 ("L45 the pending control without its destination", PJ,
  '    c = {"outcome": outcome, "cause": cause, "about": about, "sent": False, "to": to}\n',
  '    c = {"outcome": outcome, "cause": cause, "about": about, "sent": False, "to": None}\n',
  [C + "PendingNoticeTests.test_the_pending_notice_records_its_destination"]),
 ("L46 a control pin accepted in any namespace", INF,
  '        if (doc["peer"]["kind"] in RUNTIME_ONLY_KINDS) != runtime:\n',
  '        if False:\n',
  ["router.tests.test_peerlane.RecordSchemaTests.test_a_control_pin_is_damage_outside_the_runtime_namespace"]),
 ("L47 an unallocated id begun", INF,
  "    if int(n) >= _next_transport_id(cfg, name):\n",
  "    if False:\n",
  [C + "ReservedIdTests.test_an_unallocated_id_and_a_second_id_are_refused"]),
 ("L48 a second id for a request in flight", INF,
  '    if existing is not None and existing["transport_req_id"] != n:\n',
  '    if False:\n',
  [C + "ReservedIdTests.test_an_unallocated_id_and_a_second_id_are_refused"]),
 ("L49 the runtime request carries an instance's agent id", INF,
  '    doc["agent_id"] = ("runtime" if name == config_mod.RUNTIME_NS\n',
  '    doc["agent_id"] = (config_mod.state_key(cfg, name) if name == config_mod.RUNTIME_NS\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L50 a control header re-parsed as a statement field", INF,
  '    field, want_kind = ((peerlane.CONTROL_FIELD, "control") if pin["kind"] == "control"\n',
  '    field, want_kind = ((peerlane.STATEMENT_FIELD, "control") if pin["kind"] == "control"\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L51 the runtime directory bound as an agent's", "router/fsops.py",
  "        if parts == (RUNTIME_DIR,):\n            return RUNTIME, idents[0], parts\n",
  "",
  [C + "RuntimeBindingTests.test_the_runtime_directory_is_its_own_kind"]),
 ("L52 the runtime directory walked to bound as an agent's", "router/fsops.py",
  "            if parts == (RUNTIME_DIR,):\n                return self._register(fd, RUNTIME, parent.tree, parts)\n",
  "",
  [C + "RuntimeBindingTests.test_the_runtime_directory_is_its_own_kind"]),
 ("L53 control candidates no longer held", POL,
  '        return peerjournal.Hold("hook_absent", "control_receive")\n',
  '        return None\n',
  [T + "BuilderTests.test_control_candidates_still_hold_hook_absent_under_every_profile"]),
 ("L54 a signed placement resolved by its notice id", OUT,
  '        peer_id = str(record["message_id"]) if record is not None else str(in_reply_to)\n',
  '        peer_id = str(in_reply_to)\n',
  [T + "ResultSubmitTests.test_a_reply_by_the_signed_placements_notice_id_resolves_its_statement"]),
 ("L28 a router module builds a conformance profile", SVC,
  "def poll_once(",
  "def _conf(h):\n    from . import peerpolicy\n    return peerpolicy.conformance_profile(h, None, [])\n\n\n"
  "def poll_once(",
  [T + "SeamRulesTests.test_no_router_module_builds_a_conformance_profile"]),
 # The control request's shape, one mutant per member group.
 ("L61 the control request from another address", PC,
  "            from_address=runtime_address(cfg), peer=pin(cfg, attempt))\n",
  "            from_address=f\"agent@{cfg.fleet_domain}\", peer=pin(cfg, attempt))\n",
  [C + "AttemptTests.test_the_request_shape"]),
 ("L62 a second recipient", PC,
  '            request_doc=request_doc(cfg, record, attempt), recipients=[record["control"]["to"]],\n',
  '            request_doc=request_doc(cfg, record, attempt), recipients=[record["control"]["to"], f"x@{cfg.fleet_domain}"],\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L63 an extra draft recipient", PC,
  '            "draft": {"to": [record["control"]["to"]], "subject": "", "body_text": ""}}\n',
  '            "draft": {"to": [record["control"]["to"], "x@y.example"], "subject": "", "body_text": ""}}\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L64 body octets in the control request", PC,
  '            "draft": {"to": [record["control"]["to"]], "subject": "", "body_text": ""}}\n',
  '            "draft": {"to": [record["control"]["to"]], "subject": "", "body_text": "x"}}\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L65 RL sets a charset", PC,
  '            "draft": {"to": [record["control"]["to"]], "subject": "", "body_text": ""}}\n',
  '            "draft": {"to": [record["control"]["to"]], "subject": "", "body_text": "",\n'
  '                      "content_type": "text/plain; charset=us-ascii"}}\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L66 the control envelope names a reply", PC,
  '            "statement_header": attempt["header"], "in_reply_to": None, "references": []}\n',
  '            "statement_header": attempt["header"], "in_reply_to": "<x@y.example>", "references": []}\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L67 the message id in another domain", PC,
  '            "message_id": peerlane.message_id(attempt["id"], cfg.fleet_domain),\n',
  '            "message_id": peerlane.message_id(attempt["id"], "other.example"),\n',
  [C + "AttemptTests.test_the_request_shape"]),
 ("L68 the result envelope carries the peer id", OUT,
  '           "statement_header": signed.header, "in_reply_to": None, "references": []}\n',
  '           "statement_header": signed.header, "in_reply_to": in_reply_to, "references": []}\n',
  [T + "ResultSubmitTests.test_a_reply_to_a_placed_task_is_a_signed_result_to_its_remote"]),
 ("L69 a result gets no issued record", OUT,
  "        before_record=lambda: peerlane.write_issued(cfg, issued))\n",
  "        before_record=(lambda: None) if in_reply_to else (lambda: peerlane.write_issued(cfg, issued)))\n",
  [T + "ResultSubmitTests.test_a_reply_to_a_placed_task_is_a_signed_result_to_its_remote"]),
 # Admission, status and the stuck states.
 ("L70 controls attempted while admission is closed", PC,
  '    if clock.admission != "open":\n',
  '    if False:\n',
  [C + "AdmissionClosedTests.test_nothing_is_attempted_minted_or_refilled_while_admission_is_closed"]),
 ("L71 the controls section not in production status", SVC,
  '                    peer_doc["controls"] = peercontrol.status_doc(\n'
  '                        cfg, None if transport is _LOAD else transport, now=clock.now())\n',
  '                    pass\n',
  [C + "ControlStatusTests.test_poll_once_records_the_controls_section",
   C + "ControlStatusTests.test_without_the_capability_the_runtime_tree_is_unavailable"]),
 ("L72 no capability not shown unavailable", PC,
  '    if cap is None:\n        doc["runtime_tree"] = "unavailable"\n        return doc\n',
  '    if cap is None:\n        return doc\n',
  [C + "ControlStatusTests.test_without_the_capability_the_runtime_tree_is_unavailable"]),
 ("L73 a lost record lists no generations", PC,
  '        tree["generations"] = [[g, s] for g, s in cap.generations()]\n',
  '        tree["generations"] = []\n',
  [C + "ControlStatusTests.test_a_lost_record_lists_the_generations_to_adopt_or_retire"]),
 ("L74 handed without record not recorded", PC,
  '                _update(sd, record, stuck={"reason": STUCK_HANDED, "since": format_utc_ts(now)})\n',
  '                pass\n',
  [C + "AttemptTests.test_a_handed_marker_without_its_record_is_stuck_never_resent"]),
 ("L75 an aged attempt not recorded stuck", PC,
  "        if (signed is not None and (now - signed).total_seconds() >= SETTLE_HORIZON_S\n",
  "        if (signed is None and (now - signed).total_seconds() >= SETTLE_HORIZON_S\n",
  [C + "AttemptTests.test_an_attempt_unsettled_past_the_horizon_is_recorded_stuck_never_resent"]),
 ("L76 a settled failure counted as sent", PC,
  "            if outcome in SENT_OUTCOMES:\n",
  "            if outcome:\n",
  [C + "ControlStatusTests.test_a_settled_failure_is_counted_as_failed_never_as_sent"]),
 # The generation, classified every time.
 ("L77 a recorded retired generation reused", PC,
  '        if state in ("live", None):\n',
  '        if state in ("live", None, "retired"):\n',
  [C + "GenerationClassifiedTests.test_a_recorded_generation_retired_before_its_record_was_removed_is_never_reused"]),
 ("L78 a recorded generation ignores the others", PC,
  "            if others:\n                raise Unavailable(UNAVAILABLE, f\"the recorded generation {recorded} beside \"\n",
  "            if False:\n                raise Unavailable(UNAVAILABLE, f\"the recorded generation {recorded} beside \"\n",
  [C + "GenerationClassifiedTests.test_a_recorded_generation_beside_another_live_one_holds",
   C + "GenerationClassifiedTests.test_a_recorded_generation_beside_an_unreadable_one_holds"]),
 ("L79 an unreadable recorded generation passed", PC,
  '        if state == "unreadable":\n',
  '        if False:\n',
  [C + "GenerationClassifiedTests.test_an_unreadable_recorded_generation_holds"]),
 ("L80 an attempt handed into a retired generation", PC,
  '    if state in ("retired", "unreadable"):\n',
  '    if False:\n',
  [C + "GenerationClassifiedTests.test_an_attempt_whose_generation_was_retired_is_not_handed_over"]),
 ("L81 a token taken before the deferral horizon", PC,
  "    if since is not None and (h - since).total_seconds() >= DEFER_LIMIT_S:\n",
  "    if since is not None and not take_token(cfg, control[\"to\"], h) and (h - since).total_seconds() >= DEFER_LIMIT_S:\n",
  [C + "DeferralHorizonTests.test_a_notice_deferred_24_hours_is_suppressed_though_the_bucket_refilled"]),
 ("L82 an unlisted generation retired", PC,
  "    if gen not in listed:\n",
  "    if False:\n",
  [C + "RetireListedOnlyTests.test_retire_refuses_a_generation_the_lister_does_not_show"]),
 ("L83 the record removal not made durable", PC,
  "        fsync_dir(runtime_dir(cfg))\n",
  "",
  [C + "RetireListedOnlyTests.test_retire_makes_the_record_removal_durable"]),
 ("L84 a missing destination labelled unconfigured", PC,
  '    if control.get("about") is None or control.get("to") is None:\n',
  '    if False:\n',
  [C + "DestinationUnknownTests.test_a_notice_without_about_or_to_is_held_never_unconfigured"]),
 ("L85 no delegation errors per record", PC,
  "    if delegation is None:\n        # No signing key",
  "    if False:\n        # No signing key",
  [C + "DelegationInactiveTests.test_no_delegation_is_one_count_and_nothing_is_tried"]),
 ("L86 a production module reaches RUNTIME_DIR", PC,
  '_STAGE = ".coalesce-stage-"\n',
  '_STAGE = ".coalesce-stage-"\n_RT = __import__("router.fsops", fromlist=["x"]).RUNTIME_DIR\n',
  [C + "GateTests.test_no_production_module_reaches_the_runtime_tree_but_through_the_port"]),
 ("L87 stage_tree refuses the runtime directory", "router/fsops.py",
  "        if parent.kind not in (HOP_ROOT, RUNTIME) or len(parent.rel) != 1 \\\n",
  "        if parent.kind not in (HOP_ROOT,) or len(parent.rel) != 1 \\\n",
  [C + "StageUnderRuntimeTests.test_a_tree_staged_under_the_runtime_directory_binds_as_a_generation"]),
 ("L112 a frozen attempt's generation selected after a mint", PC,
  '    if "gen" in attempt:\n        # The attempt is frozen in ITS generation',
  '    if False:\n        # The attempt is frozen in ITS generation',
  [C + "AttemptTests.test_a_never_admitted_generation_is_restored_and_no_other_is_minted"]),
 ("L113 a restore beside another live generation", PC,
  '    if (listed.get(gen) == "live" or unlisted_ok) and not others:\n',
  '    if (listed.get(gen) == "live" or unlisted_ok):\n',
  [C + "AttemptTests.test_a_lost_record_beside_another_live_generation_holds_and_restores_nothing"]),
 ("L114 a retired generation restored", PC,
  '    if (listed.get(gen) == "live" or unlisted_ok) and not others:\n',
  '    if (listed.get(gen) in ("live", "retired") or unlisted_ok) and not others:\n',
  [C + "AttemptTests.test_no_generation_is_minted_while_an_attempt_is_held_unrecorded"]),
 ("L115 a restore not audited", PC,
  '        peerjournal._audit(cfg.state_dir, RESTORE_VERB, now, key=key, generation=gen,\n'
  '                           listed=listed.get(gen) or "not listed")\n',
  '',
  [C + "AttemptTests.test_a_never_admitted_generation_is_restored_and_no_other_is_minted"]),
 ("L116 a generation minted while an attempt is frozen elsewhere", PC,
  '    if frozen:\n        # A frozen attempt still names',
  '    if False:\n        # A frozen attempt still names',
  [C + "AttemptTests.test_no_generation_is_minted_while_an_attempt_is_held_unrecorded",
   C + "AttemptTests.test_no_mint_while_any_attempt_is_frozen_elsewhere_whatever_the_order"]),
 ("L121 an unlisted generation with traffic in flight restored", PC,
  '    unlisted_ok = listed.get(gen) is None and not _inflight_entries(cfg, gen)\n',
  '    unlisted_ok = listed.get(gen) is None\n',
  [C + "AttemptTests.test_an_unlisted_generation_with_traffic_in_flight_is_held_not_restored"]),
 ("L120 the no-mint guard keyed on the held flag, not the journal's state", PC,
  '        if gen is not None and gen != recorded and not c.get("sent") and not c.get("suppressed"):\n',
  '        if c.get("held") == HELD_GENERATION_UNRECORDED and not c.get("sent") and not c.get("suppressed"):\n',
  [C + "AttemptTests.test_no_mint_while_any_attempt_is_frozen_elsewhere_whatever_the_order"]),
 ("L117 abandon beside an unreadable generation", PC,
  '    if state in ("live", "unreadable"):\n        raise ValueError(f"the attempt\'s generation',
  '    if state == "live":\n        raise ValueError(f"the attempt\'s generation',
  [C + "AttemptTests.test_abandon_refuses_a_live_or_unreadable_generation_and_an_attempt_in_flight"]),
 ("L118 abandon of an attempt in flight", PC,
  '        if name in _inflight_entries(cfg, gen):\n',
  '        if False:\n',
  [C + "AttemptTests.test_abandon_refuses_a_live_or_unreadable_generation_and_an_attempt_in_flight"]),
 ("L119 abandon without the suppression", PC,
  '    _update(sd, record, suppressed=SUPPRESS_ABANDONED, held=None)\n',
  '    _update(sd, record, held=None)\n',
  [C + "AttemptTests.test_abandon_ends_a_held_attempt_never_resent"]),
 ("L88 a de-trusted remote's result signed", OUT,
  "    if klass != classify_mod.CLASS_TRUSTED:\n        result = _result_doc(\n"
  "            req_id, \"rejected\", reason_code=classify_mod.REASON_NO_ROUTE, recipients=[],\n",
  "    if False:\n        result = _result_doc(\n"
  "            req_id, \"rejected\", reason_code=classify_mod.REASON_NO_ROUTE, recipients=[],\n",
  [T + "ResultSubmitTests.test_a_remote_no_longer_trusted_gets_nothing_signed_and_no_issued_record"]),
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
