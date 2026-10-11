"""Single-rule mutants for the alias table (`router/tests/test_aliases.py`),
each run against the test that names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_aliases.py

Same discipline as `mutate_generations_migration.py`: one rule per mutant,
bytecode caching OFF and `__pycache__` cleared before each run, the file
restored after; every named test must pass unmutated first, and a mutant is
RED only when unittest reports a FAILURE of the named test (an ERROR is
printed and is not red). Exit 0 only when every mutant turns every named
test red. Not a test module itself (its name keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_aliases."
AL = "router/aliases.py"
OB = "router/outbound.py"
CF = "router/config.py"

M = [
 # -- load time -----------------------------------------------------------------
 ('L1 the local part need not be a name', CF,
  '    if not _NAME_RE.fullmatch(local):\n', '    if False:\n',
  [T + 'LoadTests.test_rules']),
 ('L2 new may be outside the fleet', CF,
  '        if new_domain != fleet_domain:\n', '        if False:\n',
  [T + 'LoadTests.test_rules']),
 ('L3 a reserved old is accepted', CF,
  '        if skeleton(old_local) in reserved:\n', '        if False:\n',
  [T + 'LoadTests.test_rules']),
 ('L4 a same-domain variant of its target is accepted', CF,
  '        if old_domain == new_domain and skeleton(old_local) == skeleton(new_local):\n',
  '        if False:\n',
  [T + 'LoadTests.test_rules']),
 ('L5 a cross-domain rename is refused', CF,
  '        if old_domain == new_domain and skeleton(old_local) == skeleton(new_local):\n',
  '        if skeleton(old_local) == skeleton(new_local):\n',
  [T + 'LoadTests.test_the_cross_domain_rename_is_valid']),
 ('L6 chains are accepted', CF,
  '    if chained:\n', '    if False:\n',
  [T + 'LoadTests.test_rules']),
 ('L7 aliases need no registry', CF,
  '    if registry_dir is None or not fleet_domain:\n', '    if False:\n',
  [T + 'LoadTests.test_rules']),
 ('L8 aliases is not a reserved state name', CF,
  'RESERVED_STATE_NAMES = frozenset({"registry", "status.json", "aliases"})',
  'RESERVED_STATE_NAMES = frozenset({"registry", "status.json"})',
  [T + 'LoadTests.test_an_instance_named_aliases_is_a_load_error']),
 # -- normalisation -------------------------------------------------------------
 ('N1 an inactive alias reaches the policy', OB,
  '    if isinstance(norm, aliases_mod.Refuse):\n', '    if False:\n',
  [T + 'NormaliseTests.test_an_inactive_alias_is_refused_before_any_policy']),
 ('N2 an undecidable alias is consumed', OB,
  '    if isinstance(norm, aliases_mod.Hold):\n', '    if False:\n',
  [T + 'NormaliseTests.test_a_malformed_history_holds_unconsumed']),
 ('N3 a refusal wins over a hold', AL,
  '    if holds:\n        return Hold(', '    if holds and not refused:\n        return Hold(',
  [T + 'NormaliseTests.test_a_hold_wins_over_a_refusal']),
 ('N4 a case variant matches', AL,
  '    return f"{local}@{domain.lower()}"\n', '    return f"{local.lower()}@{domain.lower()}"\n',
  [T + 'NormaliseTests.test_a_case_variant_fails_closed']),
 ('N5 aliases are not applied', AL,
  '                applied[a.old] = a.new\n                mapped.append(a.new)\n',
  '                mapped.append(addr)\n',
  [T + 'NormaliseTests.test_an_active_alias_delivers_to_its_target_and_warns']),
 ('N6 an alias use is not logged', OB,
  '        logger.warning("instance %r req %r: alias used: %s -> %s", name, req_id, old, new)\n',
  '        pass\n',
  [T + 'NormaliseTests.test_an_active_alias_delivers_to_its_target_and_warns']),
 # -- decisions -------------------------------------------------------------------
 ('D1 an unknown target is active', AL,
  '        elif target not in known or target not in entries:\n            out[a.old] = Decision(INACTIVE, TARGET_UNKNOWN)\n',
  '        elif target not in known or target not in entries:\n            out[a.old] = Decision(ACTIVE, target=target)\n',
  [T + 'NormaliseTests.test_inactive_reasons']),
 ('D2 the name history is not consulted', AL,
  '            elif old_local not in names:\n', '            elif False:\n',
  [T + 'NormaliseTests.test_inactive_reasons']),
 ('D3 no history counts as history', AL,
  '            if names is None:\n                out[a.old] = Decision(INACTIVE, NO_HISTORY)\n',
  '            if names is None:\n                out[a.old] = Decision(ACTIVE, target=target)\n',
  [T + 'NormaliseTests.test_inactive_reasons']),
 ('D4 a collision is not checked', AL,
  '            elif skeleton(old_local) in others:\n', '            elif False:\n',
  [T + 'NormaliseTests.test_inactive_reasons']),
 ('D5 the history need not end in the current name', AL,
  '    if (hist[-1]["name"], hist[-1]["seq"]) != (entry.name, entry.name_seq):\n',
  '    if False:\n',
  [T + 'NormaliseTests.test_the_last_history_element_must_be_the_current_name']),
 ('D6 a malformed history is inactive, not a hold', AL,
  '                out[a.old] = Decision(UNVERIFIABLE, HELD_HISTORY)\n',
  '                out[a.old] = Decision(INACTIVE, HELD_HISTORY)\n',
  [T + 'NormaliseTests.test_a_malformed_history_holds_unconsumed']),
 ('D7 an unavailable registry makes aliases inactive', AL,
  '        elif not registry_ok:\n            out[a.old] = Decision(UNVERIFIABLE,',
  '        elif not registry_ok:\n            out[a.old] = Decision(INACTIVE,',
  [T + 'NormaliseTests.test_an_unavailable_registry_holds']),
 ('D8 a held target is unknown', AL,
  '    known = dict(getattr(report, "known", None) or {})\n',
  '    known = {n: e.logical_id for n, e in (getattr(report, "resolved", None) or {}).items()}\n',
  [T + 'NormaliseTests.test_a_held_target_goes_pending_then_delivers']),
 ('D9 an expired alias is active', AL,
  '        elif now >= parse_utc_ts(a.expires):\n', '        elif False:\n',
  [T + 'TombstoneTests.test_a_failed_tombstone_write_leaves_it_inactive_and_retries']),
 ('D10 a tombstone does not deactivate', AL,
  '        elif a.old in store.tombstones:\n', '        elif False:\n',
  [T + 'TombstoneTests.test_a_relisted_tombstoned_alias_stays_inactive']),
 # -- the external leg (R7) -------------------------------------------------------
 ('X1 an aliased draft may take the external leg', OB,
  '    if isinstance(decided, ExternalRoute) and applied:\n',
  '    if isinstance(decided, ExternalRoute) and False:\n',
  [T + 'ExternalTests.test_an_aliased_draft_never_reaches_the_external_leg']),
 # -- tombstones ------------------------------------------------------------------
 ('T1 expired aliases are never tombstoned', AL,
  '                    store = write_tombstone(cfg.state_dir, store, a.old, a.expires)\n',
  '                    pass\n',
  [T + 'TombstoneTests.test_an_expired_alias_is_unknown_and_tombstoned']),
 ('T2 a failed tombstone write stops the poll', AL,
  '                except Exception as e:  # noqa: BLE001 -- never stops a poll\n',
  '                except ZeroDivisionError as e:  # noqa: BLE001 -- never stops a poll\n',
  [T + 'TombstoneTests.test_a_failed_tombstone_write_leaves_it_inactive_and_retries']),
 # -- the store -------------------------------------------------------------------
 ('S1 a non-empty first store is recovered', AL,
  '    if s.kind == "ok" and s.seq == 1 and not s.tombstones:\n',
  '    if s.kind == "ok" and s.seq == 1:\n',
  [T + 'StoreTests.test_holding_rows']),
 ('S2 a floor one behind is not raised', AL,
  '        if s.seq == f + 1:\n            return ROW_RAISE_FLOOR, s, f, w\n', '',
  [T + 'StoreTests.test_a_floor_eio_on_an_update_is_raised_next_pass']),
 ('S3 the witness before the audit line', AL,
  '            _audit(state_dir, action="init", seq=1)\n            _write_witness(state_dir)\n',
  '            _write_witness(state_dir)\n            _audit(state_dir, action="init", seq=1)\n',
  [T + 'StoreTests.test_first_initialisation_in_order',
   T + 'StoreTests.test_a_failed_audit_append_leaves_no_witness_and_holds']),
 ('S4 a store below its floor is trusted', AL,
  '        if s.seq == f:\n            return ROW_OK, s, f, w\n',
  '        if s.seq <= f:\n            return ROW_OK, s, f, w\n',
  [T + 'StoreTests.test_holding_rows']),
 ('S5 a foreign entry is ignored', AL,
  '    if any(n != STORE_FILE and not n.startswith(STORE_FILE + ".") for n in names):\n',
  '    if False:\n',
  [T + 'StoreTests.test_holding_rows']),
 ('S6 status writes', AL,
  '    view = prepare(cfg, report, write=False)\n    store = read_store(cfg.state_dir)\n',
  '    view = prepare(cfg, report, write=True)\n    store = read_store(cfg.state_dir)\n',
  [T + 'StoreTests.test_status_never_writes']),
 ('S7 the witness may be anything', AL,
  '    return "ok" if raw == WITNESS_BYTES else "corrupt"\n', '    return "ok"\n',
  [T + 'StoreTests.test_holding_rows']),
 # -- reinit ----------------------------------------------------------------------
 ('R1 reinit keeps configured aliases', AL,
  '        tombs = sorted(set(expires) | _audit_tombstoned(cfg.state_dir))\n',
  '        tombs = sorted(_audit_tombstoned(cfg.state_dir))\n',
  [T + 'ReinitTests.test_reinit_tombstones_every_configured_alias',
   T + 'ReinitTests.test_a_lost_store_holds_then_reinit_decides']),
 ('R2 reinit ignores the audit log', AL,
  '        tombs = sorted(set(expires) | _audit_tombstoned(cfg.state_dir))\n',
  '        tombs = sorted(set(expires))\n',
  [T + 'ReinitTests.test_reinit_adds_what_the_audit_log_records_as_tombstoned']),
 ('R3 a dry run writes', AL,
  '        if dry_run:\n            return dict(plan, dry_run=True)\n', '',
  [T + 'ReinitTests.test_a_dry_run_writes_nothing']),
 ('R4 reinit takes no lock', AL,
  '    if not dry_run:\n        try:\n            lk = lock_mod.acquire(cfg.state_dir)\n',
  '    if False:\n        try:\n            lk = lock_mod.acquire(cfg.state_dir)\n',
  [T + 'ReinitTests.test_reinit_needs_a_reason_and_a_stopped_router']),
 ('R5 reinit is not audited', AL,
  '        _audit(cfg.state_dir, action="reinit", reason=reason.strip(), seq=seq,\n',
  '        (lambda *a, **k: None)(cfg.state_dir, action="reinit", reason=reason.strip(), seq=seq,\n',
  [T + 'ReinitTests.test_reinit_is_audited_durably']),
 # -- pending pins ----------------------------------------------------------------
 ('P1 pending work reads the live table', OB,
  '        decided = policy(cfg, name, aliases_mod.apply_pinned(doc["draft"],\n                                                             rec.get("aliases") or {}))\n',
  '        decided = policy(cfg, name, doc["draft"])\n',
  [T + 'PinTests.test_an_alias_that_expires_while_pending_still_delivers',
   T + 'PinTests.test_a_table_edit_while_pending_does_not_retarget']),
 ('P2 an aliased record stays version 2', OB,
  '        rec["v"] = PENDING_VERSION_ALIASED\n', '        pass\n',
  [T + 'PinTests.test_an_alias_that_expires_while_pending_still_delivers']),
 ('P3 unknown members are accepted', OB,
  '    if not set(doc) <= allowed:\n', '    if False:\n',
  [T + 'PinTests.test_the_schema_is_closed']),
 ('P4 unknown target members are accepted', OB,
  '    if not set(t) <= _TARGET_KEYS:\n', '    if False:\n',
  [T + 'PinTests.test_the_schema_is_closed']),
 ('P5 the map and addresses need not come together', OB,
  '    if any(("address" in t) != has_map for t in targets):\n', '    if False:\n',
  [T + 'PinTests.test_the_schema_is_closed']),
 ('P6 an alias may map to no target', OB,
  '        if not set(amap.values()) <= addrs:\n', '        if False:\n',
  [T + 'PinTests.test_the_schema_is_closed']),
 ('P7 version and map need not agree', OB,
  '    if (doc["v"] == PENDING_VERSION_ALIASED) != bool(doc.get("aliases")):\n',
  '    if False:\n',
  [T + 'PinTests.test_the_schema_is_closed']),
 # -- hold markers (N4) ----------------------------------------------------------
 ('H1 a consumed request keeps its marker', OB,
  '    aliases_mod.clear_held(cfg, name, req_id)\n    if private:\n', '    if private:\n',
  [T + 'HoldMarkerTests.test_the_marker_binds_the_request_and_clears_on_consume']),
 ('H2 a malformed marker gets a made-up age', AL,
  '        except Exception:  # noqa: BLE001\n            age, reason = None, None\n',
  '        except Exception:  # noqa: BLE001\n            age, reason = 0, None\n',
  [T + 'HoldMarkerTests.test_a_malformed_marker_has_an_unknown_age_and_decides_nothing']),
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
