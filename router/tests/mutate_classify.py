"""Single-rule mutants for cold-send classification, the policy digest, the
re-check at publication, revocation, the failing-reload gate and the
quarantine inspection, each run against the test that names it.

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_classify.py

Same discipline as `mutate_aliases.py`: one rule per mutant, bytecode
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

C = "router.tests.test_classify."
D = "router.tests.test_policy_digest."
R = "router.tests.test_revocation."
Q = "router.tests.test_quarantine_cli."
S = "router.tests.test_cold_policy_seam."
I = "router.tests.test_inflight."
CL = "router/classify.py"
CF = "router/config.py"
OB = "router/outbound.py"
IF = "router/inflight.py"
SV = "router/service.py"
QU = "router/quarantine.py"
MN = "router/__main__.py"

M = [
 # -- item 2: the address grammar -------------------------------------------------
 ('GR1 a non-string address is parsed', CL,
  '        raise Malformed("an address must be a string")\n', '        pass\n',
  [C + 'GrammarTests.test_non_strings_are_malformed']),
 ('GR2 no address length bound', CL,
  '    if len(raw) > ADDRESS_MAX:\n', '    if False:\n',
  [C + 'GrammarTests.test_the_shared_vectors']),
 ('GR3 no local-part length bound', CL,
  '    if len(local) > LOCAL_MAX:\n', '    if False:\n',
  [C + 'GrammarTests.test_the_shared_vectors']),
 ('GR4 the local part is not a dot-atom', CL,
  '    if not _DOT_ATOM_RE.fullmatch(local):\n', '    if not local:\n',
  [C + 'GrammarTests.test_the_shared_vectors']),
 ('GR5 a non-string domain is parsed', CL,
  '        raise Malformed("a domain must be a string")\n', '        pass\n',
  [C + 'GrammarTests.test_non_strings_are_malformed']),
 ('GR6 no domain length bound', CL,
  '    if len(raw) > DOMAIN_MAX:\n', '    if False:\n',
  [C + 'GrammarTests.test_a_domain_over_253_characters']),
 ('GR7 labels are not LDH', CL,
  '    if not all(_LABEL_RE.fullmatch(label) for label in labels):\n',
  '    if not all(label for label in labels):\n',
  [C + 'GrammarTests.test_the_shared_vectors',
   C + 'FleetLocalPartTests.test_a_homoglyph_domain_is_malformed_not_a_fleet_host']),
 ('GR8 a dotted numeric is a domain', CL,
  '    if labels[-1].isdigit():\n', '    if False:\n',
  [C + 'GrammarTests.test_the_shared_vectors']),
 ('GR9 the domain is not folded', CL,
  '    return raw.lower()\n', '    return raw\n',
  [C + 'FleetLocalPartTests.test_upper_case_is_matched_lowercased_not_refused',
   D + 'KnownAnswerTests.test_every_vector']),
 ('GR10 a fleet local part need not be a name', CL,
  '    if not _FLEET_LOCAL_RE.fullmatch(addr.local):\n', '    if False:\n',
  [C + 'FleetLocalPartTests.test_a_fleet_local_part_outside_the_name_grammar_is_malformed']),
 # -- classes -----------------------------------------------------------------
 ('CS1 an unknown own-domain name is local', CL,
  '        return (CLASS_LOCAL if name is not None else CLASS_UNKNOWN), addr\n',
  '        return CLASS_LOCAL, addr\n',
  [C + 'OrderTests.test_this_domain_unknown_wins_over_mixed']),
 ('CS2 the trusted list is ignored', CL,
  '    if addr.domain in cfg.trusted_fleet_hosts:\n', '    if False:\n',
  [C + 'TrustedHostTests.test_peer_denied_by_address_and_by_domain']),
 ('CS3 fleet hosts are the internet', CL,
  '    if addr.domain in cfg.fleet_hosts:\n', '    if False:\n',
  [C + 'FleetAndInternetTests.test_item_6_remote_fleet']),
 # -- item 1: the order ---------------------------------------------------------
 ('OR2 malformed is not refused first', CL,
  '    if malformed:\n', '    if False:\n',
  [C + 'OrderTests.test_malformed_wins_over_this_domain_unknown']),
 ('OR3 this-domain-unknown is not refused', CL,
  '    if any(k == CLASS_UNKNOWN for k, _ in classes):\n', '    if False:\n',
  [C + 'OrderTests.test_this_domain_unknown_wins_over_mixed']),
 ('OR4 no plugin does not short-circuit', CL,
  '    if not plugin and any(k != CLASS_LOCAL for k, _ in classes):\n', '    if False:\n',
  [C + 'OrderTests.test_no_plugin_wins_over_mixed_and_over_every_class_rule']),
 ('OR5 mixed classes are not refused', CL,
  '    if len(kinds) > 1:\n', '    if False:\n',
  [C + 'OrderTests.test_mixed_classes']),
 ('OR6 the drain always says a plugin is present', OB,
  '    classified = classify_mod.classify(cfg, name, draft, plugin=transport is not None,\n',
  '    classified = classify_mod.classify(cfg, name, draft, plugin=True,\n',
  [I + 'LifecycleTests.test_without_a_transport_a_cross_host_recipient_is_unknown']),
 # -- item 5 (trusted host), in order ---------------------------------------------
 ('TH2 two recipients can be a peer task', CL,
  '    if len(addrs) != 1:\n        return Refuse("rejected", REASON_FLEET_MAIL_DISABLED,\n',
  '    if False:\n        return Refuse("rejected", REASON_FLEET_MAIL_DISABLED,\n',
  [C + 'TrustedHostTests.test_shape_first_more_than_one_recipient_or_any_cc']),
 ('TH3 task_deny is ignored', CL,
  '    if _denied(cfg.instances[sender].task_deny, addr):\n', '    if False:\n',
  [C + 'TrustedHostTests.test_peer_denied_by_address_and_by_domain']),
 ('TH4 a domain deny is ignored', CL,
  '        if domain == addr.domain and (not local or registry_mod.skeleton(local) == key):\n',
  '        if domain == addr.domain and registry_mod.skeleton(local) == key:\n',
  [C + 'TrustedHostTests.test_peer_denied_by_address_and_by_domain']),
 ('TH4b a deny matches its target exactly', CL,
  '        if domain == addr.domain and (not local or registry_mod.skeleton(local) == key):\n',
  '        if domain == addr.domain and (not local or local == addr.local):\n',
  [C + 'TrustedHostTests.test_a_deny_catches_every_spelling_of_its_target']),
 ('TH4c a deny ignores the host', CL,
  '        if domain == addr.domain and (not local or registry_mod.skeleton(local) == key):\n',
  '        if (not local or registry_mod.skeleton(local) == key):\n',
  [C + 'TrustedHostTests.test_a_deny_is_still_per_address_and_per_host']),
 ('TH5 the quarantine is ignored', CL,
  '    if age is not None:\n', '    if False:\n',
  [C + 'TrustedHostTests.test_the_24_hour_quarantine_edges']),
 ('TH6 exactly 24 h is still quarantined', CL,
  '    if age < QUARANTINE_S:\n', '    if age <= QUARANTINE_S:\n',
  [C + 'TrustedHostTests.test_the_24_hour_quarantine_edges']),
 ('TH7 the quarantine is 23 h', CL,
  'QUARANTINE_S = 24 * 3600\n', 'QUARANTINE_S = 23 * 3600\n',
  [C + 'TrustedHostTests.test_the_24_hour_quarantine_edges']),
 ('TH8 a future registration is just young', CL,
  '    if age < 0:\n', '    if False:\n',
  [C + 'TrustedHostTests.test_the_24_hour_quarantine_edges']),
 ('TH9 no registration value is not refused', CL,
  '    if first is None:\n        return "sender age unknown"\n',
  '    if first is None:\n        return None\n',
  [C + 'TrustedHostTests.test_sender_age_unknown']),
 ('TH10 no stamp is not refused', CL,
  '    if stamp is None:\n', '    if False:\n',
  [C + 'TrustedHostTests.test_exposure_unavailable_on_none_or_on_any_exception']),
 ('TH11 an assessment that raises is not caught', CL,
  '    except Exception:  # noqa: BLE001 -- any failure is "unavailable", never a send\n',
  '    except ZeroDivisionError:\n',
  [C + 'TrustedHostTests.test_exposure_unavailable_on_none_or_on_any_exception']),
 ('TH12 no peer lane reaches the size seam', CL,
  '    if not peer_lane_available(cfg):\n', '    if False:\n',
  [C + 'TrustedHostTests.test_no_peer_lane_is_recipient_unknown_and_the_size_seam_is_never_reached']),
 ('TH13 the peer lane is available', CL,
  '    its signing step exists, so never, today. A seam, not a setting."""\n    return False\n',
  '    its signing step exists, so never, today. A seam, not a setting."""\n    return True\n',
  [C + 'TrustedHostTests.test_no_peer_lane_is_recipient_unknown_and_the_size_seam_is_never_reached']),
 ('TH14 8192 bytes is too large', CL,
  '    if statement_size(cfg, sender, draft, stamp) > STATEMENT_MAX_BYTES:\n',
  '    if statement_size(cfg, sender, draft, stamp) >= STATEMENT_MAX_BYTES:\n',
  [C + 'TrustedHostTests.test_statement_too_large_through_the_seam']),
 ('TH15 the size bound is 8193', CL,
  'STATEMENT_MAX_BYTES = 8192\n', 'STATEMENT_MAX_BYTES = 8193\n',
  [C + 'TrustedHostTests.test_statement_too_large_through_the_seam']),
 # -- items 6 and 7 -------------------------------------------------------------
 ('RM1 remote_fleet is not consulted', CL,
  '        if all(entry_domain(c) in hosts for c in remote.canonical):\n', '        if True:\n',
  [C + 'FleetAndInternetTests.test_item_6_remote_fleet']),
 ('RM2 no egress is not refused', CL,
  '    if not cfg.egress:\n', '    if False:\n',
  [C + 'FleetAndInternetTests.test_item_7_no_egress_is_no_route_first']),
 ('RM3 send_to before egress', CL,
  '    if not cfg.egress:\n        return Refuse("rejected", REASON_NO_ROUTE,\n'
  '                      detail="this host has no egress to the internet")\n'
  '    allowed = set(canonical_entries(inst.send_to))\n'
  '    if all(c in allowed or "@" + entry_domain(c) in allowed for c in remote.canonical):\n'
  '        return remote\n',
  '    allowed = set(canonical_entries(inst.send_to))\n'
  '    if all(c in allowed or "@" + entry_domain(c) in allowed for c in remote.canonical):\n'
  '        return remote if cfg.egress else Refuse("rejected", REASON_NO_ROUTE)\n',
  [C + 'FleetAndInternetTests.test_item_7_no_egress_wins_over_a_send_to_miss']),
 ('RM4 send_to by exact address is ignored', CL,
  '    if all(c in allowed or "@" + entry_domain(c) in allowed for c in remote.canonical):\n',
  '    if all("@" + entry_domain(c) in allowed for c in remote.canonical):\n',
  [C + 'FleetAndInternetTests.test_item_7_send_to_by_address_and_by_domain']),
 ('RM5 send_to by domain is ignored', CL,
  '    if all(c in allowed or "@" + entry_domain(c) in allowed for c in remote.canonical):\n',
  '    if all(c in allowed for c in remote.canonical):\n',
  [C + 'FleetAndInternetTests.test_item_7_send_to_by_address_and_by_domain']),
 # -- item 12: the seam --------------------------------------------------------
 ('SE1 a policy may route outside the class', OB,
  '            _canonical_or_none(r) in remote.canonical for r in decided.recipients):\n',
  '            True for r in decided.recipients):\n',
  [S + 'ColdPolicySeamTest.test_a_policy_cannot_route_outside_the_class']),
 ('SE2 any policy answer is taken', OB,
  '    policy = cold_policy if cold_policy is not None else default_remote_policy\n'
  '    decided = policy(cfg, sender, draft)\n',
  '    policy = cold_policy if cold_policy is not None else default_remote_policy\n'
  '    return policy(cfg, sender, draft)\n',
  [S + 'ColdPolicySeamTest.test_a_policy_cannot_route_outside_the_class']),
 # -- item 5: the digest ---------------------------------------------------------
 ('DG1 unsorted keys', CL,
  '    text = json.dumps(obj, sort_keys=True, separators=(",", ":"),\n',
  '    text = json.dumps(obj, sort_keys=False, separators=(",", ":"),\n',
  [D + 'KnownAnswerTests.test_every_vector']),
 ('DG2 default separators', CL,
  '    text = json.dumps(obj, sort_keys=True, separators=(",", ":"),\n',
  '    text = json.dumps(obj, sort_keys=True, separators=(", ", ": "),\n',
  [D + 'KnownAnswerTests.test_every_vector']),
 ('DG3 ASCII-escaped', CL,
  '                      ensure_ascii=False, allow_nan=False)\n',
  '                      ensure_ascii=True, allow_nan=False)\n',
  [D + 'KnownAnswerTests.test_every_vector']),
 ('DG4 NaN allowed', CL,
  '                      ensure_ascii=False, allow_nan=False)\n',
  '                      ensure_ascii=False, allow_nan=True)\n',
  [D + 'PinnedFormTests.test_non_finite_numbers_are_refused']),
 ('DG5 the prefix', CL,
  'DIGEST_PREFIX = "sha256:"\n', 'DIGEST_PREFIX = "sha-256:"\n',
  [D + 'KnownAnswerTests.test_every_vector']),
 ('DG6 host lists not de-duplicated', CL,
  '    return sorted({canonical_host(v) for v in values})\n',
  '    return sorted([canonical_host(v) for v in values])\n',
  [D + 'KnownAnswerTests.test_every_vector']),
 ('DG7 entries not de-duplicated', CL,
  '    return sorted({canonical_entry(v) for v in values})\n',
  '    return sorted([canonical_entry(v) for v in values])\n',
  [D + 'KnownAnswerTests.test_every_vector']),
 ('DG8 egress not in the object', CL,
  '        "egress": egress,\n', '',
  [D + 'KnownAnswerTests.test_every_vector', D + 'ConfigDigestTests.test_the_digest_covers_exactly_the_policy_inputs']),
 ('DG9 task_deny not in the object', CL,
  '        "task_deny": canonical_entries(task_deny),\n', '        "task_deny": [],\n',
  [D + 'ConfigDigestTests.test_the_digest_covers_exactly_the_policy_inputs']),
 ('DG10 the record carries no digest or route', OB,
  '        policy_digest=classify_mod.policy_digest(cfg, name), route=klass,\n',
  '        policy_digest=None, route=None,\n',
  [C + 'FleetAndInternetTests.test_the_route_and_digest_are_recorded_before_anything_is_handed']),
 # -- item 3: load-time refusals ----------------------------------------------
 ('LD1 the own domain may be a fleet host', CF,
  '        if own in values:\n', '        if False:\n',
  [C + 'ConfigTests.test_own_domain_in_either_list']),
 ('LD2 a trusted host need not be a fleet host', CF,
  '    if missing:\n', '    if False:\n',
  [C + 'ConfigTests.test_trusted_must_be_fleet_hosts']),
 ('LD3 duplicates accepted', CF,
  '    if dups:\n', '    if False:\n',
  [C + 'ConfigTests.test_duplicates_after_canonicalisation']),
 ('LD4 egress need not be a boolean', CF,
  '    if not isinstance(egress, bool):\n', '    if False:\n',
  [C + 'ConfigTests.test_malformed_entries_and_shapes']),
 ('LD5 task_deny may name any host', CF,
  '            if outside:\n', '            if False:\n',
  [C + 'ConfigTests.test_task_deny_outside_the_trusted_hosts']),
 ('LD6 send_to may name a trusted host', CF,
  '            named = [e for e in send_to if classify_mod.entry_domain(e) in trusted]\n',
  '            named = []\n',
  [C + 'ConfigTests.test_send_to_naming_a_trusted_host']),
 ('LD7 remote_fleet may name a trusted host', CF,
  '            named = [h for h in remote if h in trusted]\n', '            named = []\n',
  [C + 'ConfigTests.test_remote_fleet_naming_a_trusted_host_or_a_stranger']),
 ('LD8 remote_fleet may name a stranger', CF,
  '            unknown = [h for h in remote if h not in fleet]\n', '            unknown = []\n',
  [C + 'ConfigTests.test_remote_fleet_naming_a_trusted_host_or_a_stranger']),
 ('LD9 retention unbounded', CF,
  '            1 <= v <= INGRESS_QUARANTINE_DAYS_MAX):\n', '            1 <= v):\n',
  [C + 'ConfigTests.test_ingress_quarantine_days_bounds']),
 ('LD10 a malformed host entry accepted', CF,
  '    except classify_mod.Malformed as e:\n        raise ConfigError(f"{where}: {e}") from None\n',
  '    except classify_mod.Malformed as e:\n        return ()\n',
  [C + 'ConfigTests.test_malformed_entries_and_shapes']),
 # -- item 4: the re-check at publication -------------------------------------------
 ('PB3 no re-check at publication', IF,
  '    if recheck is not None:\n        rc = recheck(record)\n',
  '    if False:\n        rc = recheck(record)\n',
  [R + 'PublicationRecheckTests.test_a_policy_change_that_no_longer_permits_is_refused_unpublished',
   R + 'PublicationRecheckTests.test_a_handed_but_unwritten_record_is_rechecked_too']),
 ('PB3b a route-less record is not backfilled', IF,
  '    if record.get("route") is None and rc.route is not None:\n', '    if False:\n',
  [R + 'PublicationRecheckTests.test_a_route_less_record_is_pinned_before_its_first_publication',
   R + 'PublicationRecheckTests.test_a_route_less_handed_record_is_pinned_on_its_pending_recheck']),
 ('PB3c the re-check reports no route', OB,
  '                                route=decided.klass)\n', '                                route=None)\n',
  [R + 'PublicationRecheckTests.test_a_route_less_record_is_pinned_before_its_first_publication']),
 ('PB3d a pending route-less record is not pinned', IF,
  '        if record.get("route") is None and _repin(name, req_id, record, rc):\n',
  '        if False:\n',
  [R + 'PublicationRecheckTests.test_a_route_less_handed_record_is_pinned_on_its_pending_recheck']),
 ('PB4 the new digest is not written before publication', IF,
  '        if _repin(name, req_id, record, rc):\n            _write_record(cfg, name, req_id, record, "repin")\n',
  '        if _repin(name, req_id, record, rc):\n            pass\n',
  [R + 'PublicationRecheckTests.test_a_policy_change_that_still_permits_publishes_the_NEW_digest']),
 ('PB5 a route change is not detected', OB,
  '    if old is not None and len(kinds) == 1 and None not in kinds and kinds != {old}:\n',
  '    if False:\n',
  [R + 'PublicationRecheckTests.test_a_route_change_is_refused_not_rebuilt',
   R + 'PublicationRecheckTests.test_an_unchanged_digest_does_not_skip_the_recheck']),
 ('PB6 a changed recipient set is permitted', OB,
  '    if None in then or then != now_set:\n', '    if False:\n',
  [R + 'PublicationRecheckTests.test_a_narrowed_recipient_set_is_refused']),
 ('PB7 an alias at re-check is ignored', OB,
  '    if not isinstance(norm, aliases_mod.Normalised) or norm.applied:\n', '    if False:\n',
  [R + 'PublicationRecheckTests.test_an_alias_now_naming_a_recipient_is_refused']),
 ('PB8 a refusal at re-check is permitted', OB,
  '    if isinstance(decided, classify_mod.Refuse):\n        return refused(f"now {decided.reason_code}")\n',
  '    if isinstance(decided, classify_mod.Refuse):\n        return inflight_mod.Recheck(True)\n',
  [R + 'PublicationRecheckTests.test_a_record_from_before_the_digest_is_refused_by_the_order']),
 # -- item 8: the failing reload ---------------------------------------------------
 ('BR1 publication not blocked', IF,
  '    if publish_blocked:\n        logger.error(\n',
  '    if False:\n        logger.error(\n',
  [R + 'BadReloadTests.test_nothing_new_is_published_while_it_fails',
   R + 'BadReloadTests.test_the_handed_but_unwritten_rewrite_is_blocked_too']),
 ('BR2 the drain never passes the flag', OB,
  '        publish_blocked=cfg.reload_failed,\n', '        publish_blocked=False,\n',
  [R + 'BadReloadTests.test_nothing_new_is_published_while_it_fails']),
 ('BR3 a broken config keeps no flag', SV,
  '            "may now be stale: %s", e)\n        return replace(current, reload_failed=True)\n',
  '            "may now be stale: %s", e)\n        return current\n',
  [R + 'BadReloadTests.test_failed_and_refused_reloads_set_the_flag_and_a_good_one_clears_it']),
 ('BR4 a refused state_dir change keeps no flag', SV,
  '            current.state_dir, fresh.state_dir)\n        return replace(current, reload_failed=True)\n',
  '            current.state_dir, fresh.state_dir)\n        return current\n',
  [R + 'BadReloadTests.test_failed_and_refused_reloads_set_the_flag_and_a_good_one_clears_it']),
 ('BR5 revocation enacted during a failing reload', IF,
  '    if not enact:\n', '    if False:\n',
  [R + 'RevocationTests.test_not_enacted_while_the_reload_fails']),
 # -- revocation after hand-over ---------------------------------------------
 ('RV1 no re-check while pending', IF,
  '        if recheck is not None:\n            _check_revocation(',
  '        if False:\n            _check_revocation(',
  [R + 'RevocationTests.test_a_revoked_pending_request_is_marked_and_logged_every_poll']),
 ('RV2 the mark is not persisted', IF,
  '    _write_record(cfg, name, req_id, record, "revoked")\n', '',
  [R + 'RevocationTests.test_the_mark_survives_a_restart']),
 ('RV3 a marked record is re-decided', IF,
  '    if since is not None:\n', '    if False:\n',
  [R + 'RevocationTests.test_a_revoked_pending_request_is_marked_and_logged_every_poll']),
 # -- the closed record schema -----------------------------------------------------
 ('SC1 an unknown member accepted', IF,
  '    if extra:\n        raise RecordDamaged(f"unknown member(s) {extra}")\n', '',
  [R + 'RecordSchemaTests.test_an_unknown_member_is_damaged_and_never_handed']),
 ('SC2 records are not checked on read', IF,
  '    return check_record(doc)\n', '    return doc\n',
  [R + 'RecordSchemaTests.test_an_unknown_member_is_damaged_and_never_handed']),
 ('SC3 local parts fold in the mismatch check', IF,
  '        return {classify_mod.parse_address(a).canonical() for a in addrs}\n',
  '        return {a.casefold() for a in addrs}\n',
  [I + 'RecipientIntegrityTests.test_the_mismatch_check_compares_local_parts_exactly']),
 # -- item 11: the quarantine ---------------------------------------------------
 ('QU1 duplicate causes accepted', QU,
  '    if len(set(causes)) != len(causes):\n', '    if False:\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU2 a cause outside the vocabulary', QU,
  '    if any(c not in CAUSES for c in causes):\n', '    if False:\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU3 a JSON boolean is an integer', QU,
  '    return isinstance(v, int) and not isinstance(v, bool) and abs(v) < EVIDENCE_INT_LIMIT\n',
  '    return isinstance(v, int) and abs(v) < EVIDENCE_INT_LIMIT\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU4 integers unbounded', QU,
  '    return isinstance(v, int) and not isinstance(v, bool) and abs(v) < EVIDENCE_INT_LIMIT\n',
  '    return isinstance(v, int) and not isinstance(v, bool)\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU5 any evidence key', QU,
  '        if not _EVIDENCE_KEY.fullmatch(k):\n', '        if False:\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU6 no skew bound', QU,
  '    if (arrived - now).total_seconds() > SKEW_S:\n', '    if False:\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU7 the skew edge is exclusive', QU,
  '    if (arrived - now).total_seconds() > SKEW_S:\n',
  '    if (arrived - now).total_seconds() >= SKEW_S:\n',
  [Q + 'FormatTests.test_the_skew_edge']),
 ('QU8 id need not match the filename', QU,
  '    if doc["id"] != item_id:\n', '    if False:\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU9 generation need not match the directory', QU,
  '    if doc["generation"] != generation:\n', '    if False:\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU10 extra members accepted', QU,
  '    if set(doc) != _KEYS:\n', '    if not _KEYS <= set(doc):\n',
  [Q + 'FormatTests.test_every_rule_fails_visibly']),
 ('QU11 hard links followed', QU,
  '        if st.st_nlink != 1:\n', '        if False:\n',
  [Q + 'FormatTests.test_links_and_non_regular_entries']),
 ('QU12 non-regular files read', QU,
  '        if not stat.S_ISREG(st.st_mode):\n', '        if False:\n',
  [Q + 'FormatTests.test_links_and_non_regular_entries']),
 ('QU13 item symlinks followed', QU,
  '        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),\n',
  '        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0),\n',
  [Q + 'FormatTests.test_links_and_non_regular_entries']),
 ('QU14 directory symlinks followed', QU,
  '    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)\n',
  '    return os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd)\n',
  [Q + 'FormatTests.test_a_linked_quarantine_directory_is_damaged']),
 ('QU15 reads unbounded', QU,
  '        if got > cap:\n', '        if False:\n',
  [Q + 'FormatTests.test_oversize_files']),
 ('QU16 evidence printed raw', QU,
  '    return json.dumps(doc, ensure_ascii=True, sort_keys=True, indent=2)\n',
  '    return json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2)\n',
  [Q + 'CliTests.test_list_and_show']),
 ('QU17 names printed raw', QU,
  '    return json.dumps(text, ensure_ascii=True)[1:-1]\n', '    return text\n',
  [Q + 'FormatTests.test_an_unexpected_name_is_listed_escaped']),
 ('QU18 any control entry name', QU,
  '    if not _HEX32.fullmatch(entry):\n', '    if False:\n',
  [Q + 'ControlTests.test_damaged_entries']),
 ('QU18b a commit in progress is damaged', QU,
  '        if e.nlink == 2:\n', '        if False:\n',
  [Q + 'ControlTests.test_a_commit_caught_in_progress_is_in_flight_not_damaged']),
 ('QU18c any link count is in flight', QU,
  '        if e.nlink == 2:\n', '        if e.nlink >= 2:\n',
  [Q + 'ControlTests.test_a_commit_caught_in_progress_is_in_flight_not_damaged']),
 ('QU19 status has no count', SV,
  '        doc["ingress_quarantine"] = {\n', '        doc["_"] = {\n',
  [Q + 'CliTests.test_status_counts_per_agent']),
 ('QU20 the CLI records the registry seq', MN,
  '        report = registry_mod.report_for(cfg.registry_dir, cfg.state_dir, cfg.instances,\n'
  '                                         persist=False)\n',
  '        report = registry_mod.report_for(cfg.registry_dir, cfg.state_dir, cfg.instances,\n'
  '                                         persist=True)\n',
  [Q + 'CliTests.test_the_registry_seq_is_not_recorded']),
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
