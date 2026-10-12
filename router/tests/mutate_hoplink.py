"""Single-rule mutants for the external leg's activation and handover
(`router/hoplink.py` and its callers in `config.py`, `inflight.py`,
`outbound.py`, `service.py` and `status.py`), each run against the tests
that name it.

Run from the repository root:

    python3 -B router/tests/mutate_hoplink.py

Same discipline as `mutate_place_once.py`: one rule per mutant, bytecode
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

HC = "router.tests.test_hop_config.HopConfigTests."
EN = "router.tests.test_hoplink_encoding."
HO = "router.tests.test_hoplink_handover."
SE = "router.tests.test_hoplink_senders."
WT = "router.tests.test_hoplink_write_table."
ST = "router.tests.test_hoplink_status."
SU = "router.tests.test_transport.StartupTests."
CF, HL, IF, OB, SV, SS = ("router/config.py", "router/hoplink.py", "router/inflight.py",
                          "router/outbound.py", "router/service.py", "router/status.py")

M = [
 # -- config ---------------------------------------------------------------
 ('C1 version_write unbounded above', CF,
  '"config.hop.version_write",\n                                  maximum=HOP_CONTRACT_MAX)',
  '"config.hop.version_write")',
  [HC + "test_version_write_is_at_most_the_envelopes_maximum"]),
 ('C2 a root not in normal form accepted', CF,
  '    if os.path.normpath(root) != root:\n', '    if False:\n',
  [HC + "test_the_root_is_absolute_and_in_normal_form"]),
 ('C3 overlap checked one way only', CF,
  '        if _is_within(rp, other) or _is_within(other, rp):\n',
  '        if _is_within(rp, other):\n',
  [HC + "test_the_root_never_overlaps_state_registry_or_an_agent_root"]),
 ('C4 the document floor off by one', CF,
  '    if hop.cap("document") < floor:\n', '    if hop.cap("document") < floor - 1:\n',
  [EN + "ConfigFloorTests.test_exactly_the_floor_loads_and_one_less_is_refused"]),
 ('C5 hop without a registry', CF,
  '    if registry_dir is None:\n        raise ConfigError(\n            "config.hop: requires',
  '    if False:\n        raise ConfigError(\n            "config.hop: requires',
  [HC + "test_a_registry_is_required"]),
 # -- encoding and the begin-time checks -----------------------------------
 ('H1 recipients counted without duplicates', HL,
  '    if len(raw) > MAX_RECIPIENTS:\n', '    if len(set(map(str, raw))) > MAX_RECIPIENTS:\n',
  [EN + "BeginCheckTests.test_recipient_count_counts_every_raw_entry"]),
 ('H2 bcc not counted', HL,
  '    for key in ("to", "cc", "bcc"):\n', '    for key in ("to", "cc"):\n',
  [EN + "BeginCheckTests.test_recipient_count_counts_every_raw_entry"]),
 ('H3 the request file newline not counted', HL,
  '    return len(canonical(request)) + 1\n', '    return len(canonical(request))\n',
  [EN + "BeginCheckTests.test_the_request_cap_counts_the_newline"]),
 ('H4 a 65-octet local part accepted', HL,
  '    if len(local) > LOCAL_MAX:\n', '    if len(local) > LOCAL_MAX + 1:\n',
  [EN + "AddressTests.test_octet_boundaries"]),
 ('H5 the floor counts the newline twice', HL,
  '    return (request_cap - 1) + attach_array_max', '    return request_cap + attach_array_max',
  [EN + "FloorTests.test_the_floor_is_exact"]),
 ('H6 the attachment array one comma long', HL,
  '    return 4 * quanta + 3 * count_cap - 1\n', '    return 4 * quanta + 3 * count_cap\n',
  [EN + "AttachArrayTests.test_exact_against_brute_force"]),
 # -- the sender: pin, cache, construction ---------------------------------
 ('H7 a changed binding not compared', HL,
  '    if have != want:\n        raise HopHold(HOLD_BINDING_CHANGED,',
  '    if False:\n        raise HopHold(HOLD_BINDING_CHANGED,',
  [SE + "PinTests.test_a_changed_binding_holds_and_constructs_nothing"]),
 ('H8 admitted_at from the clock', HL,
  '    want = pin_doc(cfg.hop, minted_ts(cfg, name))\n', '    want = pin_doc(cfg.hop, utc_ts())\n',
  [SE + "SenderTests.test_admitted_at_comes_from_the_record_never_the_clock"]),
 ('H9 a successor admitted with its predecessor unretired', HL,
  '    if fenced:\n', '    if False:\n',
  [SE + "PredecessorTests.test_no_successor_sender_while_an_admitted_predecessor_is_unretired"]),
 ('H10 no sender cache', HL,
  '    if port is not None:\n        return port\n', '    if False:\n        return port\n',
  [SE + "SenderTests.test_the_pin_then_the_sender_then_admitted_once_per_process"]),
 ('H11 settings_invalid retried', HL,
  '    if kind == "reason" and detail == "settings_invalid":\n',
  '    if kind == "reason" and detail == "never":\n',
  [SE + "ConstructionTests.test_the_latched_construction_reasons"]),
 ('H12 a bare ValueError read as a settings refusal', HL,
  '    if kind == "reason" and detail == "settings_invalid":\n',
  '    if isinstance(e, ValueError):\n',
  [SE + "ConstructionTests.test_a_bare_value_error_is_never_the_settings_hold"]),
 # -- the write_request row ------------------------------------------------
 ('W1 below_frontier retried', HL,
  '    "below_frontier": "hop_frontier_undecidable",\n', '',
  [WT + "LatchTests.test_each_latched_reason_holds_this_generation"]),
 ('W2 a latched hold not consulted', IF,
  '    held = hoplink.write_hold(cfg, name)\n    if held is not None:\n',
  '    held = None\n    if held is not None:\n',
  [WT + "LatchTests.test_each_latched_reason_holds_this_generation"]),
 ('W3 the runtime classes not seen before .reason', HL,
  '    kind, detail = transport_mod.classify(exc, runtime=tuple(_RUNTIME_CLASSES))\n'
  '    if kind == "reason":\n        return LATCHED',
  '    kind, detail = transport_mod.classify(exc)\n'
  '    if kind == "reason":\n        return LATCHED',
  [WT + "RetryTests.test_a_runtime_unsafe_read_with_a_colliding_reason_never_latches"]),
 ('W4 a routine retry loud at once', IF,
  '        quiet = status in hoplink.QUIET_RETRIES and age < STALE_AFTER_S\n',
  '        quiet = False\n',
  [ST + "RetryStatusTests.test_a_routine_retry_is_named_quiet_then_loud_once_stale"]),
 ('W5 a routine retry never loud', IF,
  '        quiet = status in hoplink.QUIET_RETRIES and age < STALE_AFTER_S\n',
  '        quiet = status in hoplink.QUIET_RETRIES\n',
  [ST + "RetryStatusTests.test_a_routine_retry_is_named_quiet_then_loud_once_stale"]),
 ('W6 an anomaly quiet', HL,
  'QUIET_RETRIES = ("hop_version_unavailable", "hop_peer_not_ready", "hop_io_error")',
  'QUIET_RETRIES = ("hop_version_unavailable", "hop_peer_not_ready", "hop_io_error", '
  '"hop_owner_mismatch")',
  [ST + "RetryStatusTests.test_an_anomaly_is_loud_on_the_first_poll"]),
 ('W7 a retry first sighting reset every poll', HL,
  '    if prior is None or (prior["status"], prior["transport_req_id"]) != (status, n):\n',
  '    if True:\n',
  [ST + "RetryStatusTests.test_a_routine_retry_is_named_quiet_then_loud_once_stale"]),
 ('W8 a retry never cleared', IF,
  '        hoplink.clear_retry(cfg, name)\n', '        pass\n',
  [ST + "RetryStatusTests.test_a_routine_retry_is_named_quiet_then_loud_once_stale"]),
 ('W9 layout mislabelled', HL,
  '    "layout": "hop_peer_not_ready",\n', '    "layout": "hop_anomaly:layout",\n',
  [ST + "RetryStatusTests.test_every_named_retry_status"]),
 ('W10 closed not evicted', IF,
  '            hoplink.evict_sender(cfg, name)\n        if _is_hop',
  '            pass\n        if _is_hop',
  [ST + "RetryStatusTests.test_closed_evicts_and_the_next_poll_reconstructs"]),
 ('W11 an OSError unexpected', HL,
  '        return "hop_io_error"\n', '        return RETRY_UNEXPECTED\n',
  [ST + "RetryStatusTests.test_an_io_error_is_hop_io_error"]),
 # -- the frontier and the handover document --------------------------------
 ('I1 an unreadable record skipped', IF,
  '        except (RecordDamaged, OSError) as e:\n            raise FrontierUndecidable(f"{p}: {e}") from e\n',
  '        except (RecordDamaged, OSError) as e:\n            continue\n',
  [HO + "FrontierTests.test_any_unreadable_entry_makes_it_undecidable"]),
 ('I2 the frontier is the lowest live id', IF,
  '    return min(live) - 1\n', '    return min(live)\n',
  [HO + "FrontierTests.test_lowest_live_minus_one"]),
 ('I3 the frontier not asserted below the id', IF,
  '    if not frontier < int(record["transport_req_id"]):\n', '    if False:\n',
  [HO + "HandoverTests.test_the_frontier_must_be_below_the_id"]),
 ('I4 a missing from_address not refused', IF,
  '    if not isinstance(record.get("from_address"), str):\n        raise HandoverUnavailable',
  '    if False:\n        raise HandoverUnavailable',
  [HO + "HandoverTests.test_the_from_address_is_the_pinned_one_never_filled_in"]),
 ('I5 agent_id the instance name', IF,
  '    doc["agent_id"] = config_mod.state_key(cfg, name)\n', '    doc["agent_id"] = name\n',
  [SE + "SenderTests.test_the_pin_then_the_sender_then_admitted_once_per_process"]),
 # -- begin ------------------------------------------------------------------
 ('O1 no begin-time check', OB,
  '        hoplink.check_begin(probe, request_cap=', '        (lambda *a, **k: None)(probe, request_cap=',
  [HO + "BeginRefusalTests.test_101_recipients"]),
 ('O2 the probe at an 8-digit id', OB,
  '    probe["req_id"] = "9" * hoplink.TRANSPORT_ID_MAX_DIGITS\n', '    probe["req_id"] = "9" * 8\n',
  [HO + "BeginRefusalTests.test_the_cap_is_checked_at_the_longest_transport_id"]),
 ('O3 the from_address not checked', OB,
  '    why = hoplink.from_address_problem(from_address)\n', '    why = None\n',
  [HO + "BeginRefusalTests.test_an_address_that_cannot_be_a_from_address"]),
 ('O4 a held sender consumes the request', OB,
  '                       name, req_id, transport.hold.reason)\n        return HELD\n',
  '                       name, req_id, transport.hold.reason)\n        transport = None\n',
  [SE + "ConstructionTests.test_a_failure_caches_nothing_and_the_next_poll_recovers"]),
 # -- service and status -----------------------------------------------------
 ('S1 a reload that moves hop accepted', SV,
  '    if fresh.hop != current.hop:\n', '    if False:\n',
  [SU + "test_a_reload_that_changes_hop_is_refused"]),
 ('S2 the sender hold first sighting reset', HL,
  '            e.since, e.since_ts = prior.since, prior.since_ts', '            pass',
  [ST + "HoldStatusTests.test_a_sender_hold_with_its_first_sighting"]),
 ('S3 no hop section in status.json', SS,
  '            doc["hop"] = self.hop\n', '            pass\n',
  [ST + "PollTests.test_status_json_carries_it_and_the_summary_does_not"]),
 ('S4 the hop section never recorded', SV,
  'tracker.record_hop(hoplink.status_doc(keyed_cfg, keyed_cfg.instances))', 'None',
  [ST + "PollTests.test_status_json_carries_it_and_the_summary_does_not"]),
 ('S5 a latched hold not shown', HL,
  '                    entry["write_hold"] = held\n', '                    pass\n',
  [ST + "HoldStatusTests.test_a_latched_write_hold"]),
 ('S6 open senders not counted', HL,
  '"senders_open": sum(1 for k in _SENDERS if k[1] == state)', '"senders_open": 0',
  [ST + "HoldStatusTests.test_a_quiet_instance_has_no_entry_and_the_senders_are_counted"]),
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
