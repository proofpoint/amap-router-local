"""Single-rule mutants for generations (`router/generations.py` and its
touch-points; `router/tests/test_generations.py`), each run against the test
that names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_generations.py

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

G = "router.tests.test_generations."
R = "router.tests.test_state_rekey."
GEN = "router/generations.py"

M = [
 # -- when a generation begins ---------------------------------------------
 ('B1 a rebind is not compared', GEN,
  '    if cur["binding"] != binding:\n', '    if False:\n',
  [G + 'BeginTests.test_a_rebind_begins_one_and_fences_the_old']),
 ('B2 the root is not compared', GEN,
  '    if not same_root(cur["root"], observed):\n', '    if False:\n',
  [G + 'BeginTests.test_a_replaced_root_begins_one']),
 ('B3 name_seq is part of the binding', GEN,
  '            "binding_seq": entry.binding_seq}\n',
  '            "binding_seq": entry.binding_seq, "name_seq": entry.name_seq}\n',
  [G + 'BeginTests.test_a_name_seq_or_epoch_change_does_not']),
 ('B4 the root identity follows a symlink', GEN,
  '        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n',
  '        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)\n',
  [G + 'BeginTests.test_the_root_identity_comes_from_the_opened_descriptor']),
 ('B5 the fenced generation keeps no fenced_ts', GEN,
  '        if g.get("fenced_ts") is None:\n            g["fenced_ts"] = now\n',
  '        if False:\n            g["fenced_ts"] = now\n',
  [G + 'BeginTests.test_a_rebind_begins_one_and_fences_the_old']),
 # -- holds ----------------------------------------------------------------
 ('H1 the pre-generation layout is not held', GEN,
  '        if legacy:\n            raise GenerationHeld(HELD_LEGACY_UNADOPTED,\n',
  '        if False:\n            raise GenerationHeld(HELD_LEGACY_UNADOPTED,\n',
  [G + 'HoldTests.test_the_pre_generation_layout_holds_and_nothing_is_written']),
 ('H2 an unfinished migration is ignored', GEN,
  '    if _present(lid_dir(state_dir, lid) / MIGRATION_FILE):\n        raise GenerationHeld(',
  '    if False:\n        raise GenerationHeld(',
  [G + 'HoldTests.test_an_unfinished_migration_holds']),
 ('H3 a lost marker is not held', GEN,
  '    if not _is_fresh(d) and not _marker_readable(d):\n', '    if False:\n',
  [G + 'HoldTests.test_a_lost_marker_in_a_generation_with_state_holds_never_resnapshots',
   G + 'HoldTests.test_a_corrupt_marker_holds_too']),
 ('H4 first sight writes no sentinel', 'router/firstsight.py',
  '    if cfg.registry_dir is not None:\n        # Under a registry, first sight is recorded TWICE',
  '    if False:\n        # Under a registry, first sight is recorded TWICE',
  [G + 'HoldTests.test_first_sight_in_a_fresh_generation_survives_losing_its_marker']),
 ('H5 a missing current generation is not held', GEN,
  '    if not (d.is_dir() and not d.is_symlink()):\n        raise GenerationHeld(HELD_LAYOUT_CONFLICT',
  '    if False:\n        raise GenerationHeld(HELD_LAYOUT_CONFLICT',
  [G + 'HoldTests.test_a_missing_current_generation_holds']),
 ('H6 holds are not folded into the report', GEN,
  '    if not prep.held:\n        return report, dict(prep.keys)\n',
  '    if True:\n        return report, dict(prep.keys)\n',
  [G + 'HoldTests.test_the_pre_generation_layout_holds_and_nothing_is_written']),
 # -- the counter ------------------------------------------------------------
 ('C1 the successor starts at "last used"', GEN,
  '    return max(int(text), 1)\n', '    return max(int(text) - 1, 1)\n',
  [G + 'CounterTests.test_the_successor_starts_at_the_next_unused_id']),
 ('C2 a missing counter with ids handed out gives 1', GEN,
  '        if _handed_out(pred_dir):\n', '        if False:\n',
  [G + 'CounterTests.test_a_missing_counter_with_ids_handed_out_holds']),
 ('C3 a corrupt counter is accepted as 1', GEN,
  '    if not _COUNTER_RE.fullmatch(text):\n        raise GenerationHeld(HELD_COUNTER_UNVERIFIED, "the predecessor\'s counter is corrupt")\n',
  '    if not _COUNTER_RE.fullmatch(text):\n        return 1\n',
  [G + 'CounterTests.test_a_corrupt_counter_holds']),
 ('C4 the generations file is written before the counter', GEN,
  '    atomic_write(_counter_path(d), str(start).encode("ascii"), durable_root=state_dir)\n    now = utc_ts()\n',
  '    now = utc_ts()\n',
  [G + 'CounterTests.test_the_generations_file_names_it_only_after_its_counter_is_durable']),
 # -- placement --------------------------------------------------------------
 ('P1 the hold check ignores the root', 'router/config.py',
  '    if (seen["st_dev"], seen["st_ino"]) != expected:\n        return generations_mod.HELD_RECIPIENT_ROOT\n', '',
  [G + 'RecipientRootTests.test_a_root_replaced_after_the_pre_pass_receives_nothing']),
 ('P2 the write does not verify its root', 'router/attachments.py',
  '    if expect_root is None:\n        return\n    st = os.fstat(root_fd)\n',
  '    if True:\n        return\n    st = os.fstat(root_fd)\n',
  [G + 'RecipientRootTests.test_the_write_itself_verifies_the_root']),
 ('P3 a recipient without a generation is not held', 'router/config.py',
  '    except (LookupError, generations_mod.GenerationHeld):\n        return generations_mod.HELD_RECIPIENT_UNRESOLVED\n',
  '    except (LookupError, generations_mod.GenerationHeld):\n        return None\n',
  [G + 'RecipientRootTests.test_a_recipient_without_a_generation_holds']),
 # -- the stranded guard -------------------------------------------------------
 ('S1 a generation chain is not registry state', 'router/registry.py',
  '        if any(_present(Path(e.path) / f) for f in _REGISTRY_FILES):\n',
  '        if False:\n',
  [G + 'StrandedTests.test_a_generation_chain_without_its_registry_is_stranded']),
 ('S2 generations are not scanned', 'router/registry.py',
  '                     if g.name.startswith("gen-") for sub in _GEN_IN_FLIGHT_DIRS]\n',
  '                     if False for sub in _GEN_IN_FLIGHT_DIRS]\n',
  [G + 'StrandedTests.test_in_flight_work_inside_a_generation_is_seen']),
 # -- reset ------------------------------------------------------------------------
 ('R1 reset deletes generations', 'router/reset.py',
  '    return (entry_name.startswith(generations_mod.GEN_PREFIX)\n',
  '    return (False\n',
  [R + 'KeyedResetTests.test_reset_fences_the_generation_and_begins_the_next']),
 ('R2 reset begins no generation', 'router/reset.py',
  '        generation = generations_mod.begin(\n            cfg.state_dir, name, entry.logical_id, generations_mod.binding_of(entry),\n            gen_inputs["root"], generations_mod.REASON_RESET)\n',
  '        generation = None\n',
  [R + 'KeyedResetTests.test_reset_fences_the_generation_and_begins_the_next']),
 ('R3 reset accepts the pre-generation layout', 'router/reset.py',
  '        if doc is None and generations_mod.legacy_entries(cfg.state_dir, lid):\n',
  '        if False:\n',
  [R + 'KeyedResetTests.test_reset_refuses_the_pre_generation_layout']),
 # -- the operator verb ------------------------------------------------------------
 ('V1 the verb takes no lock', GEN,
  '    if not dry_run:\n        try:\n            lk = lock_mod.acquire(cfg.state_dir)\n',
  '    if False:\n        try:\n            lk = lock_mod.acquire(cfg.state_dir)\n',
  [G + 'OperatorNewTests.test_a_running_router_refuses_it']),
 ('V2 a dry run persists the seq floor', GEN,
  '                                         persist=not dry_run)\n',
  '                                         persist=True)\n',
  [G + 'OperatorNewTests.test_a_dry_run_writes_nothing']),
 ('V3 a registry-held instance is not refused', GEN,
  '        if name not in (report.resolved or {}):\n            raise OperatorRefused(\n',
  '        if False:\n            raise OperatorRefused(\n',
  [G + 'OperatorNewTests.test_a_registry_held_instance_is_refused']),
 ('V4 the verb ignores an unfinished migration', GEN,
  '        if _present(lid_dir(cfg.state_dir, lid) / MIGRATION_FILE):\n            raise OperatorRefused(',
  '        if False:\n            raise OperatorRefused(',
  [G + 'OperatorNewTests.test_an_unfinished_migration_is_refused']),
 ('V5 the verb records no reason', GEN,
  '                                       REASON_OPERATOR, note=reason.strip(),\n',
  '                                       REASON_OPERATOR,\n',
  [G + 'OperatorNewTests.test_it_fences_carries_and_audits']),
 # -- review round ------------------------------------------------------------------
 ('L1 a lost generations file restarts at gen 1', GEN,
  '        check_unlisted(state_dir, lid)\n        return begin(state_dir, name, lid, binding, observed, REASON_FIRST)\n',
  '        return begin(state_dir, name, lid, binding, observed, REASON_FIRST)\n',
  [G + 'HoldTests.test_a_lost_generations_file_holds_rather_than_restart']),
 ('L2 an empty leftover counts as a loss', GEN,
  '              if not _empty_leftover(d)]\n', '              if True]\n',
  [G + 'HoldTests.test_an_empty_leftover_of_an_interrupted_first_start_is_not_a_loss']),
 ('L3 reset restarts over a lost generations file', 'router/reset.py',
  '        if doc is None:\n            generations_mod.check_unlisted(cfg.state_dir, lid)\n', '',
  [G + 'HoldTests.test_a_lost_generations_file_holds_rather_than_restart']),
 ('A1 an anomaly-settled hand-off is not counted', GEN,
  '        if not isinstance(envelope, dict) or envelope.get("transport_req_id") is not None:\n',
  '        if not isinstance(envelope, dict):\n',
  [G + 'CounterTests.test_a_hand_off_settled_as_an_anomaly_still_counts']),
 ('A2 the anchor records no transport id', 'router/outbound.py',
  '    if transport_req_id is not None:\n        envelope["transport_req_id"] = transport_req_id\n', '',
  [G + 'CounterTests.test_a_hand_off_settled_as_an_anomaly_still_counts']),
 ('O1 the drain does not verify its own root', 'router/outbound.py',
  '    _verify_own_root(cfg, name)\n    marker_doc, first_sight', '    marker_doc, first_sight',
  [G + 'RecipientRootTests.test_a_sender_root_replaced_after_the_pre_pass_is_not_drained']),
 ('O2 the publish does not verify its root', 'router/outbound.py',
  '        attachments_mod._check_root(root_fd, generations_mod.expected_root(cfg, name))\n', '',
  [G + 'RecipientRootTests.test_a_result_is_never_published_into_a_replaced_root']),
 ('K1 anchors are per identity, not per generation', 'router/outbound.py',
  '    return gen_state_dir(cfg, name) / "results" / f"{req_id}.json"\n',
  '    return cfg.state_dir / state_key(cfg, name) / "results" / f"{req_id}.json"\n',
  [G + 'GenerationScopedAnchorsTests.test_a_reused_id_is_refused_within_a_generation_and_accepted_after_new']),
 ('X1 exposure reads first sight per identity', 'router/exposure.py',
  '    doc = firstsight_mod.read_marker(cfg.state_dir, sender, state_key=gen_key(cfg, sender))\n',
  '    doc = firstsight_mod.read_marker(cfg.state_dir, sender, state_key=state_key(cfg, sender))\n',
  [G + 'ExposureClampTests.test_the_window_is_clamped_to_first_sight_in_the_generation']),
 ('Z1 reset ignores an unfinished migration', 'router/reset.py',
  '    if (cfg.state_dir / lid / generations_mod.MIGRATION_FILE).exists():\n', '    if False:\n',
  [G + 'ResetGenerationTests.test_an_unfinished_migration_refuses_reset']),
 ('Z2 reset checks each instance only when it acts on it', 'router/reset.py',
  '        inputs = {name: _generation_inputs(cfg, name) for name in names}\n'
  '        return [_reset_one(cfg, name, inputs[name]) for name in names]\n',
  '        return [_reset_one(cfg, name, _generation_inputs(cfg, name)) for name in names]\n',
  [G + 'ResetGenerationTests.test_one_instance_that_cannot_begin_refuses_the_whole_batch']),
 ('Z3 reset wipes before it begins the generation', 'router/reset.py',
  '    generation = None\n    if gen_inputs is not None:\n',
  '    generation = None\n    _clear_state(cfg, name)\n    if gen_inputs is not None:\n',
  [G + 'ResetGenerationTests.test_the_generation_is_begun_before_anything_is_wiped']),
 ('Q1 settled reuse is not counted', 'router/outbound.py',
  '                    generations_mod.record_reuse(cfg, name)\n', '',
  [G + 'ReuseCountTests.test_status_counts_settled_reuse_per_generation']),
 ('Q2 a failed audit line still commits the verb', GEN,
  '        if audit_required:\n            if prior is None:\n',
  '        if False:\n            if prior is None:\n',
  [G + 'OperatorNewTests.test_a_failed_audit_line_commits_nothing']),
 # -- status -------------------------------------------------------------------------
 ('T1 status shows no held reused id', GEN,
  '        if held:\n            entry["req_id_reused_pending"] = held\n',
  '        if False:\n            entry["req_id_reused_pending"] = held\n',
  [G + 'ReusePendingExitTests.test_status_shows_it_and_generation_new_lets_the_agent_resubmit']),
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
