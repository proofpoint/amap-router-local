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
FP = "router.tests.test_hoplink_failure_paths."
RD = "router.tests.test_hoplink_readers."
CF, HL, IF, OB, SV, SS = ("router/config.py", "router/hoplink.py", "router/inflight.py",
                          "router/outbound.py", "router/service.py", "router/status.py")
IG = "router/ingress.py"
FV = "router.tests.test_ingress_facts_version.FactsVersionTests."
BT = "router.tests.test_ingress_bundle.BundleTests."
SN = "router.tests.test_ingress_snapshot."
QW = "router.tests.test_ingress_quarantine_writer.WriterTests."
DF = "router.tests.test_ingress_documents.FixtureTests.test_invalid_fixtures_are_refused"
PL = "router.tests.test_ingress_place."
KC = "router.tests.test_ingress_classify.ClassifyTests."

M = [
 # -- the facts version guard (driven directly at the guard unit) -------------
 ('G1 facts_version unchecked (presence selects version 2)', IG,
  '    if type(v) is int and v == 2:\n', '    if True:\n',
  [FV + "test_every_other_present_value_is_refused"]),
 ('G2 the type check removed', IG,
  '    if type(v) is int and v == 2:\n', '    if v == 2:\n',
  [FV + "test_every_other_present_value_is_refused"]),
 ('G3 version-1 facts may carry attachments', IG,
  '        if "attachments" in facts:\n            raise FactsInvalid("version-1 facts carry no attachments member")\n', '',
  [FV + "test_version_1_carrying_attachments_is_refused"]),
 ('G4 version 2 without attachments accepted', IG,
  '        if "attachments" not in facts:\n            raise FactsInvalid("version-2 facts require an attachments member")\n', '',
  [FV + "test_version_2_without_attachments_is_refused"]),
 # -- the notice bundle, parsed as hostile input --------------------------------
 ('B1 an older bundle schema accepted', IG,
  '    if not transport_mod.is_current_bundle_schema(bundle.get("schema")):\n', '    if False:\n',
  [BT + "test_an_older_bundle_schema"]),
 ('B2 members not closed', IG,
  '    if tuple(sorted(bundle)) != BUNDLE_MEMBERS:\n', '    if not set(BUNDLE_MEMBERS) <= set(bundle):\n',
  [BT + "test_members_are_exactly_five"]),
 ('B3 non-canonical base64 accepted', IG,
  '    if _base64.b64encode(raw).decode("ascii") != text:\n', '    if False:\n',
  [BT + "test_non_canonical_base64_is_refused"]),
 ('B4 the decoded cap unchecked', IG,
  '    if len(raw) > cap:\n', '    if False:\n',
  [BT + "test_base64_is_standard_canonical_and_capped",
   BT + "test_the_document_cap_is_exact"]),
 # (No mutant for the encoded-length precheck alone: it only bounds the work
 # done before the exact decoded-length check, which refuses the same inputs.)
 ('B5 the facts capped at the document cap', IG,
  '_b64(bundle["hop"], "hop", transport_mod.HOP_FACTS_MAX)', '_b64(bundle["hop"], "hop", DOC_CAP)',
  [BT + "test_the_facts_cap"]),
 ('B6 notice_id not compared with the entry', IG,
  'if notice.get("notice_id") != entry_id or spool', 'if spool',
  [BT + "test_the_notice_id_must_be_the_listed_entry"]),
 ('B8 an absent member not read as zero attachments', IG,
  '    descs = notice["message"].get("attachments", [])', '    descs = notice["message"].get("attachments")',
  [BT + "test_zero_attachments_with_the_member_absent"]),
 ('B9 attachments not positional', IG,
  '    if not isinstance(atts, list) or len(atts) != len(descs):\n', '    if not isinstance(atts, list):\n',
  [BT + "test_attachments_are_positional"]),
 ('B10 bytes accepted without a content_ref', IG,
  '            if a is not None:\n                raise _invalid(f"attachment {k} present without a content_ref")\n', '',
  [BT + "test_bytes_without_a_ref_and_a_ref_without_bytes"]),
 # (B7, B11, B12 and B16 are gone: `check_notice_doc` now enforces the
 # message and descriptor shapes and the content_ref rules before this point,
 # and its M-mutants carry them.)
 # (No mutant for "a ref without bytes" alone: `_b64` refuses a non-string,
 # None included, so removing the explicit check changes only the message.)
 ('B14 size unchecked', IG,
  '        if (d.get("size_bytes") != len(blob)\n                or ', '        if (',
  [BT + "test_size_and_digest_must_match_the_descriptor"]),
 ('B15 sha256 unchecked', IG,
  '\n                or d.get("sha256") != hashlib.sha256(blob).hexdigest()):', '):',
  [BT + "test_size_and_digest_must_match_the_descriptor"]),
 # -- the AMAP document checks, each pinned by an invalid golden fixture --------
 ('M1 the notice kind unchecked', IG,
  '    if doc.get("kind") != "deliver":\n', '    if False:\n', [DF]),
 ('M2 the notice id grammar unchecked', IG,
  '    if not (_str(nid) and _NOTICE_ID_RE.fullmatch(nid)):\n', '    if not _str(nid):\n', [DF]),
 ('M3 content_ref position unchecked', IG,
  '            if ref != f"{notice_id}.attachments/{k}":\n', '            if False:\n', [DF]),
 ('M4 a grant on a non-clean descriptor', IG,
  '        if ("content_ref" in d or "sha256" in d) and d["disposition"] != "clean":\n',
  '        if False:\n', [DF]),
 ('M5 any disposition accepted', IG,
  '        if d.get("disposition") not in DISPOSITIONS:\n', '        if False:\n', [DF]),
 ('M6 preview not required', IG,
  '    for member in ("subject", "preview"):\n', '    for member in ("subject",):\n', [DF]),
 ('M7 the spool body not required', IG,
  '    if not _str(doc.get("body_text")):\n', '    if False:\n', [DF]),
 ('M8 the notice version unchecked', IG,
  '        raise _invalid("the notice\'s contract_version is not \\"2\\"")\n', '        pass\n', [DF]),
 # (No mutant for the content_ref grammar alone: the positional post-check
 # requires equality with "<notice_id>.attachments/<k>", whose notice_id has
 # passed the grammar, so it refuses everything the grammar does.)
 ('M10 the spool notice id not compared', IG,
  ' or spool.get("notice_id") != entry_id:\n', ':\n',
  [BT + "test_the_spool_notice_id_must_be_the_listed_entry_too"]),
 # -- snapshots: kept durably, verified fail-closed ------------------------------
 ('N1 the snapshot directory left at the umask', IG,
  '    os.mkdir(path, 0o700)\n    os.chmod(path, 0o700)\n', '    os.mkdir(path)\n',
  [SN + "TakeTests.test_round_trip_and_modes"]),
 ('N2 snapshot files group-readable', IG,
  '        os.fchmod(fd, 0o600)\n        view = memoryview(data)\n',
  '        os.fchmod(fd, 0o640)\n        view = memoryview(data)\n',
  [SN + "TakeTests.test_round_trip_and_modes"]),
 ('N3 snapshot files not fsynced', IG,
  '            view = view[os.write(fd, view):]\n        os.fsync(fd)\n',
  '            view = view[os.write(fd, view):]\n',
  [SN + "TakeTests.test_every_file_then_the_directory_then_its_parent_is_fsynced"]),
 ('N4 the snapshot directory not fsynced', IG,
  '            _write_new(dfd, name, data)\n        os.fsync(dfd)\n',
  '            _write_new(dfd, name, data)\n',
  [SN + "TakeTests.test_every_file_then_the_directory_then_its_parent_is_fsynced"]),
 ('N5 its parent not fsynced after it', IG,
  '    fsync_dir(path.parent)\n    digests', '    digests',
  [SN + "TakeTests.test_every_file_then_the_directory_then_its_parent_is_fsynced"]),
 ('N6 an uncommitted leftover kept', IG,
  '    _discard_uncommitted(path)\n    os.mkdir', '    os.mkdir',
  [SN + "TakeTests.test_an_uncommitted_leftover_is_replaced"]),
 ('N7 a non-directory leftover not refused', IG,
  '    if not stat.S_ISDIR(st.st_mode):\n        raise SnapshotInvalid("not_a_directory", f"{path} exists and is not a directory")\n', '',
  [SN + "TakeTests.test_a_leftover_that_is_not_a_directory_is_refused"]),
 ('N8 malformed digests trusted', IG,
  '        raise SnapshotInvalid("digests", "the record carries no well-formed snapshot digests")\n',
  '        pass\n',
  [SN + "VerifyTests.test_malformed_digests"]),
 ('N9 a symlinked snapshot directory not named', IG,
  '    if stat.S_ISLNK(st.st_mode):\n        raise SnapshotInvalid("symlink", f"{path} is a symlink")\n', '',
  [SN + "VerifyTests.test_the_directory_a_symlink"]),
 ('N10 the directory mode unchecked', IG,
  '    if stat.S_IMODE(st.st_mode) != 0o700:\n', '    if False:\n',
  [SN + "VerifyTests.test_the_directory_mode"]),
 ('N11 unexpected members allowed', IG,
  '        if extra:\n            raise SnapshotInvalid("unexpected"', '        if False:\n            raise SnapshotInvalid("unexpected"',
  [SN + "VerifyTests.test_an_unexpected_member"]),
 ('N12 a missing member not named', IG,
  '            except FileNotFoundError:\n                raise SnapshotInvalid("missing", f"{path}: no member {name}") from None\n', '',
  [SN + "VerifyTests.test_a_member_absent"]),
 ('N13 a symlinked member not named', IG,
  '                if stat.S_ISLNK(os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mode):\n', '                if False:\n',
  [SN + "VerifyTests.test_a_member_a_symlink"]),
 ('N14 a non-regular member read', IG,
  '                if not stat.S_ISREG(fst.st_mode):\n                    raise SnapshotInvalid("not_regular"', '                if False:\n                    raise SnapshotInvalid("not_regular"',
  [SN + "VerifyTests.test_a_member_not_regular"]),
 ('N15 a second link allowed', IG,
  '                if fst.st_nlink != 1:\n', '                if False:\n',
  [SN + "VerifyTests.test_a_member_with_a_second_link"]),
 ('N16 a member mode unchecked', IG,
  '                if stat.S_IMODE(fst.st_mode) != 0o600:\n', '                if False:\n',
  [SN + "VerifyTests.test_a_member_mode"]),
 ('N17 a member over its cap read whole', IG,
  '            if len(data) > cap:\n                raise SnapshotInvalid("over_cap"', '            if False:\n                raise SnapshotInvalid("over_cap"',
  [SN + "VerifyTests.test_a_member_over_its_cap"]),
 ('N18 the id member unchecked', IG,
  '    if got["id"] != _id_bytes(kind, link, gen, entry_id):\n', '    if False:\n',
  [SN + "VerifyTests.test_the_identity_of_another_entry"]),
 ('N19 digests not compared', IG,
  '        if want is not None and hashlib.sha256(got[name]).hexdigest() != want:\n', '        if False:\n',
  [SN + "VerifyTests.test_a_hash_mismatch"]),
 ('N20 an enumerated directory not matched to its name', IG,
  '                  and key_for(kind, ident.get("link"), gen, ident.get("entry_id")) == key)\n',
  '                  )\n',
  [SN + "EnumerationTests.test_a_directory_that_does_not_match_its_name_raises"]),
 # (No mutant for O_NONBLOCK on member opens: without it a FIFO member blocks
 # the open forever, and this runner has no timeout to turn a hang into a
 # FAILURE. The FIFO witness above runs with it in place.)
 # -- the quarantine writer: create-if-absent ----------------------------------
 ('Q1 an existing item overwritten', IG,
  '        except FileExistsError:\n            created = False\n',
  '        except FileExistsError:\n            os.unlink(qdir / name)\n            os.link(tmp, qdir / name)\n            created = True\n',
  [QW + "test_a_different_item_is_a_conflict_and_is_kept"]),
 ('Q2 an existing item adopted unread', IG,
  '    if raw != _item_bytes(build(ts)):\n', '    if False:\n',
  [QW + "test_a_different_item_is_a_conflict_and_is_kept"]),
 ('Q3 adoption compared at the new arrival time', IG,
  '    return _adopt(qdir, name, item_id, gen, build)\n',
  '    return _adopt(qdir, name, item_id, gen, lambda _ts: build(now or utc_ts()))\n',
  [QW + "test_five_presentations_give_one_item"]),
 ('Q4 a damaged existing entry adopted', IG,
  '            raise QuarantineConflict(f"{qdir / name}: an existing entry is damaged ({e})") from None\n',
  '            return "adopted"\n',
  [QW + "test_a_damaged_item_is_a_conflict_and_is_kept"]),
 ('Q5 the item group-readable', IG,
  '            os.fchmod(fd, 0o600)\n            view = memoryview(fresh)\n',
  '            os.fchmod(fd, 0o644)\n            view = memoryview(fresh)\n',
  [QW + "test_the_written_item_is_in_the_frozen_format_and_private"]),
 ('Q6 notice_invalid dropped from the cause vocabulary', "router/quarantine.py",
  'CAUSES = (CAUSE_COLD_FLEET_MAIL, CAUSE_LATE_INBOUND, CAUSE_NOTICE_INVALID)',
  'CAUSES = (CAUSE_COLD_FLEET_MAIL, CAUSE_LATE_INBOUND)',
  [QW + "test_a_first_sight_notice_invalid_item_is_in_the_frozen_format",
   "router.tests.test_quarantine_cli.FormatTests.test_the_vocabulary_is_closed"]),
 # (No mutant for the explicit cause check: `check_item` refuses the same
 # value before anything is written, so removing it changes only the message.
 # None for the temporary file's directory either: it matters only after a
 # process death between create and unlink, which no in-process test makes.)
 # -- placement: recorded bytes, the generation check, the recovery table --------
 ('P1 no generation check before placing', IG,
  '    if not current:\n        return _quarantine_late(state_dir, logical_id, gen, link, entry_id, rec)\n    write(state_dir, logical_id, gen, "notice", link, entry_id, PLACING)\n',
  '    write(state_dir, logical_id, gen, "notice", link, entry_id, PLACING)\n',
  [PL + "PlaceTests.test_a_mint_between_prepared_and_placing_quarantines_to_the_old_generation"]),
 ('P2 row 2 without the generation check', IG,
  '    if not current:\n        return _quarantine_late(state_dir, logical_id, gen, link, entry_id, rec)\n    if any(',
  '    if any(',
  [PL + "RecoveryTests.test_row_2_after_a_mint_quarantines_late"]),
 ('P3 an unverified survivor published', IG,
  '        if notice_state and ledger_got == parts["ledger"] and all(\n                present(p, b) for p, b in expected[1:]):\n',
  '        if True:\n',
  [PL + "RecoveryTests.test_row_1_a_corrupt_survivor_holds"]),
 ('P4 survivors-only checking', IG,
  '                present(p, b) for p, b in expected[1:]):\n',
  '                present(p, b) is not False for p, b in expected[1:]):\n',
  [PL + "RecoveryTests.test_row_1_every_expected_part_is_required"]),
 ('P5 placing_ambiguous re-placed', IG,
  '    if ledger_got is not None:\n        # Row 3.\n        return hold(HELD_PLACING_AMBIGUOUS)\n', '',
  [PL + "RecoveryTests.test_row_3_the_ledger_without_the_notice_is_ambiguous_and_terminal",
   PL + "RecoveryTests.test_row_1_a_consumed_notice_is_row_3"]),
 ('P6 a live rebuild instead of the recorded bytes', IG,
  '    write(state_dir, logical_id, gen, "notice", link, entry_id, PLACING)\n    _commit_recorded',
  '    write(state_dir, logical_id, gen, "notice", link, entry_id, PLACING)\n    parts["notice"]["ts"] = utc_ts() + "x"\n    _commit_recorded',
  [PL + "PlaceTests.test_the_recorded_bytes_are_placed_once"]),
 ('P7 a held recipient placed', IG,
  '    if config_mod.target_hold(cfg, rec["recipient"]) is not None:\n        return None\n', '',
  [PL + "PlaceTests.test_a_held_recipient_gets_nothing_and_the_record_waits"]),
 ('P8 a different survivor overwritten in row 2', IG,
  '    if any(present(p, b) is False for p, b in expected[1:]):\n        return hold(HELD_EXISTS_DIFFERENT)\n', '',
  [PL + "RecoveryTests.test_row_2_a_different_survivor_holds"]),
 ('P9 the survivor notice not fsynced', IG,
  '            _fsync_agent(icfg.root, notice_path)\n', '',
  [PL + "RecoveryTests.test_row_1_the_notice_present_publishes_without_placing_again"]),
 ('P10 a snapshot not re-verified before placing', IG,
  '    parts, why = _rebuild(state_dir, logical_id, gen, link, entry_id, rec, attachment_cap)\n    if parts is None:\n        write(state_dir, logical_id, gen, "notice", link, entry_id, HELD, reason=why)\n        return HELD\n',
  '    parts, why = _rebuild(state_dir, logical_id, gen, link, entry_id, rec, attachment_cap)\n',
  [PL + "PlaceTests.test_a_tampered_snapshot_holds_and_places_nothing"]),
 ('P11 a positional gap written as a blob', "router/attachments.py",
  '                    if att is not None:\n                        _write_blob_pinned(side_fd, i, att.data)\n',
  '                    _write_blob_pinned(side_fd, i, att.data)\n',
  [PL + "PlaceTests.test_a_gap_keeps_every_later_index"]),
 # -- the §7.2 order and A5 admission (first match wins) --------------------------
 ('K1 rows 5 and 6 swapped', IG,
  '    if facts["admission_link"] != link:\n        return HOLD, HELD_LINK_MISMATCH\n    if origin in trusted_fleet_hosts:\n        return QUARANTINE, quarantine_mod.CAUSE_COLD_FLEET_MAIL\n',
  '    if origin in trusted_fleet_hosts:\n        return QUARANTINE, quarantine_mod.CAUSE_COLD_FLEET_MAIL\n    if facts["admission_link"] != link:\n        return HOLD, HELD_LINK_MISMATCH\n',
  [KC + "test_trusted_with_the_wrong_link_is_row_5_not_cold"]),
 ('K2 a failure notice not held', IG,
  '    if nc != "mail":\n        return HOLD, HELD_FAILURE_NOTICE\n', '',
  [KC + "test_row_1_a_failure_notice_is_held"]),
 ('K3 a bound reply not held', IG,
  '    if "in_reply_to" in facts:\n        return HOLD, HELD_BOUND_REPLY\n', '',
  [KC + "test_a_bound_reply_from_a_trusted_host_is_row_2"]),
 ('K4 open admission not held', IG,
  '    if admission in ("inbound_allowlist", "open"):\n        return HOLD, HELD_NOT_PLACEABLE\n', '',
  [KC + "test_row_3_open_admission_is_not_placeable"]),
 ('K5 an unknown host placed', IG,
  '    if origin not in fleet_hosts:\n        return HOLD, HELD_UNKNOWN_HOST\n', '',
  [KC + "test_row_7_an_unknown_host_is_held"]),
 ('K6 origin_host case not canonical', IG,
  '        if canonical != origin:\n', '        if False:\n',
  [KC + "test_values_outside_the_enums_are_invalid"]),
 ('K7 any admission value read', IG,
  '    if admission not in ADMISSIONS:\n', '    if False:\n',
  [KC + "test_values_outside_the_enums_are_invalid"]),
 ('K8 any ingress value read', IG,
  '    if ingress_v not in INGRESSES:\n', '    if False:\n',
  [KC + "test_non_hub_ingress_is_invalid_while_the_enum_is_hub_only"]),
 # (No mutant for row 4 alone: it is unreachable while the ingress enum is
 # {"hub"}, so removing it is equivalent; K8 is what pins the enum.)
 # -- the intake-reader seam ----------------------------------------------------
 ('D1 no reader cache', HL,
  '    reader = _READERS.get(key)\n    if reader is not None:\n        return reader\n',
  '    reader = None\n',
  [RD + "ConstructionTests.test_settings_are_exactly_the_core_and_the_reader_is_cached"]),
 # (No mutant for "the class looked up afresh at construction": at that moment
 # it is the same value capture_verdict_class returns, so the mutant is
 # equivalent. Capture matters at dispatch, which uses Reader.notice_refused.)
 ('D3 a refused reader not closed', HL,
  '    except transport_mod.SeamRefused as e:\n        _close_quietly(port)\n',
  '    except transport_mod.SeamRefused as e:\n',
  [RD + "ConstructionTests.test_a_class_that_is_not_disjoint_latches_the_vocabulary_hold_and_closes_it"]),
 ('D4 a latched reader hold re-attempted', HL,
  '    if key in _READER_LATCHED:\n        raise _READER_LATCHED[key]\n', '',
  [RD + "ConstructionTests.test_settings_invalid_latches"]),
 ('D5 eviction leaves the reader open', HL,
  '        _close_quietly(_READERS.pop(k).port)\n', '        _READERS.pop(k)\n',
  [RD + "EvictionTests.test_eviction_closes_and_the_next_call_rebuilds"]),
 # -- canonical's refusal reasons (shared with the plugin's encoder) ---------
 ('E1 NaN and the infinities read as a float', HL,
  "        if value != value or value in (float(\"inf\"), float(\"-inf\")):\n",
  "        if False:\n",
  [EN + "RefusalReasonTests.test_each_input_has_its_reason"]),
 ('E2 a lone surrogate in a key left to the encoder', HL,
  "            if _has_surrogate(k):\n                raise CanonicalRefused(REFUSE_SURROGATE, f\"{where}: an unpaired surrogate in a key\")\n",
  "",
  [EN + "RefusalReasonTests.test_each_input_has_its_reason"]),
 # -- failure paths: holds, cleanup, the pin guard, mail only ----------------
 ('F1 an undecidable frontier or missing field not latched', IF,
  '    except (FrontierUndecidable, HandoverUnavailable) as e:\n        # Decided BEFORE',
  '    except () as e:\n        # Decided BEFORE',
  [FP + "FrontierAndFieldHoldTests.test_an_undecidable_frontier_latches_before_anything_is_handed",
   FP + "FrontierAndFieldHoldTests.test_a_record_without_its_pinned_from_address_latches_handover_invalid"]),
 ('F2 the sender not closed after a failed admission write', HL,
  '        try:\n            port.close()\n        except Exception:  # noqa: BLE001 -- close is cleanup\n'
  '            logger.exception("closing a hop sender after',
  '        try:\n            pass\n        except Exception:  # noqa: BLE001 -- close is cleanup\n'
  '            logger.exception("closing a hop sender after',
  [FP + "ConstructionFailureTests.test_a_failed_admission_write_closes_the_sender_and_the_poll_goes_on"]),
 ('F3 a non-hold failure escapes sender_for', HL,
  '    except Exception as e:  # noqa: BLE001 -- classified as a retried hold, never escaped\n',
  '    except ZeroDivisionError as e:  # noqa: BLE001 -- classified as a retried hold, never escaped\n',
  [FP + "ConstructionFailureTests.test_a_damaged_pin_is_a_construction_hold_not_an_aborted_drain"]),
 ('F4 the predecessor guard keyed on admitted.json', HL,
  '                                    / TRANSPORT_DIR / PIN_FILE).is_file():\n',
  '                                    / TRANSPORT_DIR / ADMITTED_FILE).is_file():\n',
  [FP + "PinnedPredecessorTests.test_a_pinned_but_unconfirmed_predecessor_blocks_the_successor"]),
 ('F5 a latched construction hold re-attempted', HL,
  '    if key in _LATCHED:\n        raise _LATCHED[key]\n', '',
  [FP + "ConstructionFailureTests.test_a_latched_construction_hold_is_not_reattempted"]),
 ('F6 construction classified without the runtime classes', HL,
  '    kind, detail = transport_mod.classify(e, runtime=tuple(_RUNTIME_CLASSES))\n'
  '    if kind == "reason" and detail == "settings_invalid":\n'
  '        return HopHold(HOLD_SETTINGS_REFUSED,',
  '    kind, detail = transport_mod.classify(e)\n'
  '    if kind == "reason" and detail == "settings_invalid":\n'
  '        return HopHold(HOLD_SETTINGS_REFUSED,',
  [FP + "ConstructionFailureTests.test_a_runtime_class_with_a_colliding_reason_is_never_latched"]),
 ('F7 a latched hand-over hold consumes new requests', OB,
  '    if transport is not None and hoplink.write_hold(cfg, name) is not None:\n',
  '    if False:\n',
  [FP + "WriteHoldUnconsumedTests.test_a_latched_handover_hold_leaves_new_requests_unconsumed"]),
 ('F8 a non-mail class handed over as mail', OB,
  '    if klass not in (classify_mod.CLASS_FLEET, classify_mod.CLASS_INTERNET):\n',
  '    if False:\n',
  [FP + "MailOnlyTests.test_a_request_outside_the_cold_mail_classes_is_no_route"]),
 ('F9 the envelope version taken from the current config', IF,
  '        version_write = pin["version_write"]\n', '        version_write = cfg.hop.version_write\n',
  [HO + "PinnedVersionTests.test_the_version_is_the_pins"]),
 ('F10 a missing pin filled in', IF,
  '        if pin is None or type(pin.get("version_write")) is not int:\n'
  '            raise HandoverUnavailable("this generation has no pinned version_write")\n'
  '        version_write = pin["version_write"]\n',
  '        version_write = (pin or {}).get("version_write", 1)\n',
  [HO + "PinnedVersionTests.test_no_pin_is_no_handover"]),
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
 ('C6 no from_address check at load', CF,
  "    if hop is not None:\n        # Every handover's envelope",
  "    if False:\n        # Every handover's envelope",
  [HC + "test_every_address_can_be_a_from_address_at_254_octets_and_not_255",
   HC + "test_the_local_part_at_64_octets_and_not_65"]),
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
  '    if kind == "reason" and detail == "settings_invalid":\n        return HopHold(HOLD_SETTINGS_REFUSED,',
  '    if kind == "reason" and detail == "never":\n        return HopHold(HOLD_SETTINGS_REFUSED,',
  [SE + "ConstructionTests.test_the_latched_construction_reasons"]),
 ('H12 a bare ValueError read as a settings refusal', HL,
  '    if kind == "reason" and detail == "settings_invalid":\n        return HopHold(HOLD_SETTINGS_REFUSED,',
  '    if isinstance(e, ValueError):\n        return HopHold(HOLD_SETTINGS_REFUSED,',
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
  'QUIET_RETRIES = ("hop_version_unavailable", "hop_layout", "hop_io_error")',
  'QUIET_RETRIES = ("hop_version_unavailable", "hop_layout", "hop_io_error", '
  '"hop_anomaly:protocol_violation")',
  [ST + "RetryStatusTests.test_an_anomaly_is_loud_on_the_first_poll"]),
 ('W7 a retry first sighting reset every poll', HL,
  '    if prior is None or (prior["status"], prior["transport_req_id"]) != (status, n):\n',
  '    if True:\n',
  [ST + "RetryStatusTests.test_a_routine_retry_is_named_quiet_then_loud_once_stale"]),
 ('W8 a retry never cleared', IF,
  '        hoplink.clear_retry(cfg, name)\n', '        pass\n',
  [ST + "RetryStatusTests.test_a_routine_retry_is_named_quiet_then_loud_once_stale"]),
 ('W9 layout mislabelled', HL,
  '    "layout": "hop_layout",\n', '    "layout": "hop_anomaly:layout",\n',
  [ST + "RetryStatusTests.test_every_named_retry_status",
   ST + "RetryStatusTests.test_layout_names_both_causes"]),
 ('W12 owner a write_request row again', HL,
  '    "layout": "hop_layout",\n', '    "layout": "hop_layout",\n    "owner": "hop_owner_mismatch",\n',
  [ST + "RetryStatusTests.test_owner_from_a_sender_is_unexpected"]),
 ('W13 the layout hint dropped', HL,
  '                    entry["retry"]["hint"] = RETRY_HINTS[retry["status"]]', '                    pass',
  [ST + "RetryStatusTests.test_layout_names_both_causes"]),
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
