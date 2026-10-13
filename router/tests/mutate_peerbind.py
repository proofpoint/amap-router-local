"""Single-rule mutants for signed peer binding and placement
(`router/peerbind.py`, `deliver.deliver_signed_peer`, and the activation and
reset sites that touch them), each run against the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_peerbind.py

Same discipline as `mutate_hoplink.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after; every named test must pass unmutated first, and a mutant is RED only
when unittest reports a FAILURE of the named test (an ERROR is printed and is
not red). Exit 0 only when every mutant turns every named test red. Not a
test module itself (its name keeps it out of discovery).

EQUIVALENT under one rule, recorded and NOT run:
  * placement's own entry seal check removed: `peerbind.consistency` and
    `peerbind.published` each re-check the seal before anything is written,
    so the forgery witness stays green; `published()`'s check alone is S4.

NOT EXPRESSIBLE as a single-rule mutant, recorded here:
  * "the declared media_type consulted for a disposition":
    `deliver.signed_dispositions` takes only the sizes, so no one-line edit
    can introduce the media type; the identical-bytes witness pins the
    behaviour.
  * "a lone stage temp read as the decided record": no code path reads a
    stage name; the crash-before-link witness pins the behaviour.
"""
import os
import pathlib
import shutil
import subprocess
import sys

PB, DL, SV, RS = ("router/peerbind.py", "router/deliver.py", "router/service.py",
                  "router/reset.py")
T = "router.tests.test_peerbind."

M = [
 ('B1 check 6 skipped', PB,
  '    cause = check6(payload, delegation.config)\n    if cause:\n        return Demoted(cause)\n',
  '',
  [T + 'CheckSixTests.test_from_in_another_runtimes_domain_is_key_domain']),
 ('B2 a domain compared case-sensitively', PB,
  '    return domain.lower() if domain and domain.isascii() else None',
  '    return domain if domain and domain.isascii() else None',
  [T + 'CheckSixTests.test_the_domain_compares_case_insensitively_and_each_domain_passes']),
 ('B3 check 9 skipped', PB,
  '    if isinstance(text, Demoted):\n        return text\n',
  '    if False:\n        return text\n',
  [T + 'CheckNineTests.test_an_appended_footer_is_body_digest']),
 ('B4 check 10 skipped', PB,
  '    if isinstance(leaves, Demoted):\n        return leaves\n',
  '    if False:\n        return leaves\n',
  [T + 'CheckTenTests.test_count_then_each_index']),
 ('B5 check 11 skipped', PB,
  '    cause = check11(payload, candidate)\n    if cause:\n        return Demoted(cause)\n',
  '',
  [T + 'CheckElevenTests.test_failures']),
 ('B6 body_charset reported as body_digest', PB,
  '        return Demoted(BODY_CHARSET)',
  '        return Demoted(BODY_DIGEST)',
  [T + 'CheckNineTests.test_charset_failures']),
 ('B7 attachment_count reported as attachment_digest', PB,
  '        return Demoted(ATTACHMENT_COUNT)',
  '        return Demoted(ATTACHMENT_DIGEST)',
  [T + 'CheckTenTests.test_count_then_each_index']),
 ('B8 key_domain reported as message_id', PB,
  '    cause = check6(payload, delegation.config)\n    if cause:\n        return Demoted(cause)\n',
  '    cause = check6(payload, delegation.config)\n    if cause:\n        return Demoted(MESSAGE_ID)\n',
  [T + 'CheckSixTests.test_from_in_another_runtimes_domain_is_key_domain']),
 ('B9 check 11 run before check 9', PB,
  '    text = check9(payload, candidate)\n',
  '    cause = check11(payload, candidate)\n    if cause:\n        return Demoted(cause)\n    text = check9(payload, candidate)\n',
  [T + 'OrderTests.test_the_first_failure_decides']),
 ('B10 checks 7 and 8 run after check 9', PB,
  '    for supplied in (check7, check8):\n        cause = supplied(payload, key_id)\n        if cause:\n            return Demoted(cause)\n    text = check9(payload, candidate)\n    if isinstance(text, Demoted):\n        return text\n',
  '    text = check9(payload, candidate)\n    if isinstance(text, Demoted):\n        return text\n    for supplied in (check7, check8):\n        cause = supplied(payload, key_id)\n        if cause:\n            return Demoted(cause)\n',
  [T + 'OrderTests.test_the_first_failure_decides']),
 ('B11 CRLF not normalised', PB,
  '        return octets.decode(codec).replace("\\r\\n", "\\n")',
  '        return octets.decode(codec)',
  [T + 'CheckNineTests.test_only_crlf_pairs_are_normalised']),
 ('B12 every CR stripped', PB,
  '        return octets.decode(codec).replace("\\r\\n", "\\n")',
  '        return octets.decode(codec).replace("\\r\\n", "\\n").replace("\\r", "")',
  [T + 'CheckNineTests.test_only_crlf_pairs_are_normalised']),
 ('B13 the charset label compared case-sensitively', PB,
  '    codec = {"utf-8": "utf-8", "us-ascii": "ascii"}.get(label.lower())',
  '    codec = {"utf-8": "utf-8", "us-ascii": "ascii"}.get(label)',
  [T + 'CheckNineTests.test_accepted_labels']),
 ('B14 an absent label read as utf-8', PB,
  '    label = "us-ascii" if label is None else label',
  '    label = "utf-8" if label is None else label',
  [T + 'CheckNineTests.test_charset_failures']),
 ('B15 decoding with errors replaced', PB,
  '        return octets.decode(codec).replace(',
  '        return octets.decode(codec, "replace").replace(',
  [T + 'CheckNineTests.test_charset_failures']),
 ('B16 the size check dropped', PB,
  '        if (len(octets) != desc.get("size_bytes")\n                or hashlib.sha256(octets).hexdigest() != desc.get("sha256")):',
  '        if hashlib.sha256(octets).hexdigest() != desc.get("sha256"):',
  [T + 'CheckTenTests.test_a_wrong_signed_size_with_a_matching_digest']),
 ('B17 the count check dropped (zip truncates)', PB,
  '    if len(leaves) != len(signed):\n        return Demoted(ATTACHMENT_COUNT)\n',
  '',
  [T + 'CheckTenTests.test_count_then_each_index']),
 ('B18 the Message-ID id compared case-insensitively', PB,
  '    if ident != payload.get("id") or',
  '    if ident.lower() != str(payload.get("id")).lower() or',
  [T + 'CheckElevenTests.test_failures']),
 ('B19 the Message-ID domain compared case-sensitively', PB,
  'domain.lower() != from_domain:',
  'domain != from_domain:',
  [T + 'CheckElevenTests.test_passes']),
 ('B20 the first of two Message-ID fields taken', PB,
  '    if len(values) != 1 or not isinstance(values[0], str):',
  '    if not values or not isinstance(values[0], str):',
  [T + 'CheckElevenTests.test_failures']),
 ('B21 Message-ID not unfolded', PB,
  '    value = _FOLD_RE.sub("", values[0]).strip(" \\t")',
  '    value = values[0].strip(" \\t")',
  [T + 'CheckElevenTests.test_passes']),
 ('B22 unfolding drops the whitespace', PB,
  '_FOLD_RE = re.compile(r"\\r?\\n(?=[ \\t])")',
  '_FOLD_RE = re.compile(r"\\r?\\n[ \\t]+")',
  [T + 'CheckElevenTests.test_failures']),
 ('B23 a control kind bound', PB,
  '    if getattr(verified, "kind", None) != "statement":',
  '    if False:',
  [T + 'OrderTests.test_only_a_statement_is_bound']),
 ('H1 the local part compared case-insensitively', PB,
  '            and local in cfg.instances\n',
  '            and local.lower() in {n.lower() for n in cfg.instances}\n',
  [T + 'HostingTests.test_by_name']),
 ('H2 a held recipient misrouted', PB,
  '        return Undecided("registry_held")',
  '        return NotHosted()',
  [T + 'HostingTests.test_a_held_recipient_is_undecided']),
 ('H3 an unverifiable alias misrouted', PB,
  '        return Undecided("alias_unverifiable")',
  '        return NotHosted()',
  [T + 'HostingTests.test_aliases']),
 ('H4 an inactive alias hosted', PB,
  '    if decision.status == aliases_mod.ACTIVE and decision.target in cfg.instances:',
  '    if decision.target in cfg.instances:',
  [T + 'HostingTests.test_aliases']),
 ('H5 an alias with no decision misrouted', PB,
  '        return Undecided("alias_undecided")',
  '        return NotHosted()',
  [T + 'HostingTests.test_aliases']),
 ('S1 the construction seal check removed', PB,
  '        _require_seal(self)\n        object.__setattr__(self, "payload"',
  '        object.__setattr__(self, "payload"',
  [T + 'SealTests.test_only_the_issuers_build_an_authorised']),
 ('S2 statement_sha256 left out of the seal', PB,
  '"statement_sha256": _sha(statement), ',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S2 key_id left out of the seal', PB,
  '"key_id": key_id, ',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S2 runtime left out of the seal', PB,
  '"runtime": runtime,\n',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S2 body_sha256 left out of the seal', PB,
  '"body_sha256": _sha(body_text.encode("utf-8")),\n',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S2 attachment_sha256s left out of the seal', PB,
  '"attachment_sha256s": [_sha(a) for a in attachments], ',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S2 hosted left out of the seal', PB,
  '"hosted": hosted,\n',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S2 origin left out of the seal', PB,
  '"origin": origin, ',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S2 confirmed left out of the seal', PB,
  '"confirmed": confirmed, ',
  '',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('S3 an Authorised picklable', PB,
  '    def __reduce_ex__(self, protocol):\n        raise TypeError("an Authorised is not persisted")\n',
  '',
  [T + 'SealTests.test_not_picklable_and_copies_are_identical']),
 ('S4 published() skipping the seal', PB,
  '    _require_seal(auth)\n    p = auth.payload',
  '    p = auth.payload',
  [T + 'SealTests.test_a_forged_or_stale_seal_is_refused_at_every_entry']),
 ('S6 payload a plain field', PB,
  '    payload: Any = field(init=False, repr=False, compare=False)',
  '    payload: Any = field(default=None, repr=False, compare=False)',
  [T + 'SealTests.test_replace_with_any_bound_part_changed_fails']),
 ('C1 confirm skipping hosting', PB,
  '    if hosting(cfg, auth.payload.get("to")) != Hosted(auth.hosted):\n        raise AuthorisationMismatch("stale", "hosting")\n',
  '',
  [T + 'ConfirmAndRecordTests.test_confirm_refuses_a_moved_world']),
 ('C2 an unconfirmed value recorded', PB,
  '    if auth.origin != ORIGIN_FRESH or not auth.confirmed:',
  '    if auth.origin != ORIGIN_FRESH:',
  [T + 'ConfirmAndRecordTests.test_decision_record_takes_only_a_confirmed_fresh_value']),
 ('C3 decision_record not re-confirming', PB,
  '    auth = confirm(auth, cfg=cfg)\n    notice_id, ts = preset',
  '    notice_id, ts = preset',
  [T + 'ConfirmAndRecordTests.test_decision_record_re_confirms']),
 ('R1 the record MAC skipped', PB,
  '    if not (isinstance(doc["mac"], str) and hmac.compare_digest(want, doc["mac"])):\n        raise RecoveryCorrupt("mac")\n',
  '',
  [T + 'PersistenceTests.test_a_fabricated_self_consistent_record_gets_no_seal']),
 ('R2 hosted_instance left out of the record MAC', PB,
  '    return hmac.new(key, _LABEL_DECISION + hoplink.canonical(dict(members)),',
  "    return hmac.new(key, _LABEL_DECISION + hoplink.canonical({k: v for k, v in dict(members).items() if k != 'hosted_instance'}),",
  [T + 'PersistenceTests.test_each_member_edited_on_disk_fails_the_mac']),
 ('R2 runtime left out of the record MAC', PB,
  '    return hmac.new(key, _LABEL_DECISION + hoplink.canonical(dict(members)),',
  "    return hmac.new(key, _LABEL_DECISION + hoplink.canonical({k: v for k, v in dict(members).items() if k != 'runtime'}),",
  [T + 'PersistenceTests.test_each_member_edited_on_disk_fails_the_mac']),
 ('R2 key_id left out of the record MAC', PB,
  '    return hmac.new(key, _LABEL_DECISION + hoplink.canonical(dict(members)),',
  "    return hmac.new(key, _LABEL_DECISION + hoplink.canonical({k: v for k, v in dict(members).items() if k != 'key_id'}),",
  [T + 'PersistenceTests.test_each_member_edited_on_disk_fails_the_mac']),
 ('R2 notice_id left out of the record MAC', PB,
  '    return hmac.new(key, _LABEL_DECISION + hoplink.canonical(dict(members)),',
  "    return hmac.new(key, _LABEL_DECISION + hoplink.canonical({k: v for k, v in dict(members).items() if k != 'notice_id'}),",
  [T + 'PersistenceTests.test_each_member_edited_on_disk_fails_the_mac']),
 ('R2 ts left out of the record MAC', PB,
  '    return hmac.new(key, _LABEL_DECISION + hoplink.canonical(dict(members)),',
  "    return hmac.new(key, _LABEL_DECISION + hoplink.canonical({k: v for k, v in dict(members).items() if k != 'ts'}),",
  [T + 'PersistenceTests.test_each_member_edited_on_disk_fails_the_mac']),
 ('R2 record_id left out of the record MAC', PB,
  '    return hmac.new(key, _LABEL_DECISION + hoplink.canonical(dict(members)),',
  "    return hmac.new(key, _LABEL_DECISION + hoplink.canonical({k: v for k, v in dict(members).items() if k != 'record_id'}),",
  [T + 'PersistenceTests.test_each_member_edited_on_disk_fails_the_mac']),
 ('R3 the record_id unchecked', PB,
  '    if members["record_id"] != record_id:\n        raise RecoveryCorrupt("record_id")\n',
  '',
  [T + 'PersistenceTests.test_a_record_resumed_under_another_record_id_is_refused']),
 ('R4 resume not checking the inode', PB,
  '    if (dev, ino) != (receipt.dev, receipt.ino) or _sha(data) != receipt.record_sha256:',
  '    if _sha(data) != receipt.record_sha256:',
  [T + 'PersistenceTests.test_replacement_after_the_receipt_is_detected']),
 ('R5 link replaced by an overwriting rename', PB,
  [('        os.link(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)', '        os.rename(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)'), ('    os.unlink(tmp, dir_fd=dirfd)\n    os.fsync(dirfd)\n    return "created"', '    os.fsync(dirfd)\n    return "created"')],
  None,
  [T + 'PersistenceTests.test_recommit_is_idempotent_and_a_different_record_conflicts']),
 ('R6 no read-back before the receipt', PB,
  '        if data != rec:\n            raise RecoveryCorrupt("readback")\n',
  '',
  [T + 'PersistenceTests.test_a_read_back_mismatch_gives_no_receipt']),
 ('R7 the created path skipping the directory fsync', PB,
  '    os.unlink(tmp, dir_fd=dirfd)\n    os.fsync(dirfd)\n    return "created"',
  '    os.unlink(tmp, dir_fd=dirfd)\n    return "created"',
  [T + 'PersistenceTests.test_no_receipt_without_durability']),
 ('R8 reopen without the fsync barrier', PB,
  '        try:\n            os.fsync(fd)\n        finally:\n            os.close(fd)\n        os.fsync(dirfd)\n        _parse_record(data, key, record_id)',
  '        os.close(fd)\n        _parse_record(data, key, record_id)',
  [T + 'PersistenceTests.test_no_receipt_without_durability']),
 ('R9 the exists_same retry skipping the directory fsync', PB,
  '            os.close(efd)\n        os.fsync(dirfd)\n        return "exists_same"',
  '            os.close(efd)\n        return "exists_same"',
  [T + 'PersistenceTests.test_a_retry_after_a_failed_fsync_re_establishes_durability']),
 ('R10 reopen not cleaning the stage', PB,
  '        _clean_stage(dirfd, DECISION_STAGE_PREFIX)\n        try:\n            data, fd, dev, ino = _read_checked(dirfd, DECISION_FILE)\n        except FileNotFoundError:\n            raise NoDecision',
  '        try:\n            data, fd, dev, ino = _read_checked(dirfd, DECISION_FILE)\n        except FileNotFoundError:\n            raise NoDecision',
  [T + 'PersistenceTests.test_a_crash_between_link_and_unlink_resumes_once']),
 ('R11 the journal containment dropped', PB,
  '    if (len(parts) != 3 or parts[1] != JOURNAL_DIR or',
  '    if (len(parts) != 3 or',
  [T + 'PersistenceTests.test_a_record_dir_outside_the_journal_is_refused']),
 ('K1 the present-key barrier removed', PB,
  '    try:\n        os.fsync(fd)\n    finally:\n        os.close(fd)\n    os.fsync(dirfd)\n    return data',
  '    os.close(fd)\n    return data',
  [T + 'DecisionKeyTests.test_the_present_key_path_makes_the_key_durable_first']),
 ('K2 fchmod dropped', PB,
  '        os.fchmod(fd, 0o600)\n',
  '',
  [T + 'DecisionKeyTests.test_created_once_0600_even_under_a_restrictive_umask']),
 ('K3 a conflicting creator fatal', PB,
  '            except LinkConflict:\n                pass',
  '            except LinkConflict:\n                raise',
  [T + 'DecisionKeyTests.test_a_conflicting_creator_is_validated_not_fatal']),
 ('K4 key stage temps left in place', PB,
  '    _clean_stage(dirfd, DECISION_KEY_STAGE_PREFIX)\n',
  '',
  [T + 'DecisionKeyTests.test_leftover_temps_are_cleaned_and_never_read']),
 ('K5 activation not creating the key', SV,
  '        peerbind.ensure_decision_key(cfg.state_dir)\n',
  '        pass\n',
  [T + 'CallerPinTests.test_the_activation_call_sites']),
 ('P1 placement accepting a fresh value', DL,
  '    if auth.origin != peerbind.ORIGIN_DECIDED:\n        raise TypeError("placement needs a persisted decision")\n',
  '',
  [T + 'PlacementTests.test_a_fresh_value_writes_nothing']),
 ('P2 placement re-deciding hosting', DL,
  '    peerbind.consistency(auth)\n',
  '    peerbind.consistency(auth)\n    if peerbind.hosting(cfg, auth.payload.get("to")) != peerbind.Hosted(auth.hosted):\n        raise peerbind.RecoveryCorrupt("hosting")\n',
  [T + 'PlacementTests.test_a_decision_survives_a_changed_world']),
 ('P3 a gone recipient not held', DL,
  '    if recipient not in cfg.instances:\n        raise peerbind.RecipientGone(recipient)\n',
  '',
  [T + 'PlacementTests.test_a_recipient_no_longer_configured_holds']),
 ('P4 a leading-dash id published', DL,
  '    if not _NOTICE_MESSAGE_ID_RE.fullmatch(str(payload.get("id", ""))):\n        raise peerbind.Unpublishable("id", "not in the notice id grammar")\n',
  '',
  [T + 'PlacementTests.test_a_leading_dash_id_is_unpublishable']),
 ('P5 message.id from the notice id', DL,
  '        notice_id=notice_id, message_id=pub["id"], ts=ts, kind=KIND_PEER, mailbox="peer",',
  '        notice_id=notice_id, message_id=notice_id, ts=ts, kind=KIND_PEER, mailbox="peer",',
  [T + 'PlacementTests.test_the_published_fields_come_from_the_statement']),
 ('P6 sender_exposure omitted', DL,
  '    extra = {"sender_exposure": pub["sender_exposure"]} if "sender_exposure" in pub else None',
  '    extra = None',
  [T + 'PlacementTests.test_the_published_fields_come_from_the_statement']),
 ('P7 subject omitted', DL,
  '        from_address=pub["from"], to_address=pub["to"], subject=pub["subject"],',
  '        from_address=pub["from"], to_address=pub["to"], subject="",',
  [T + 'PlacementTests.test_the_published_fields_come_from_the_statement']),
 ('P8 in_reply_to published unresolved', PB,
  '    if signed_reply is not None and in_reply_to_resolved is None:\n        raise ValueError("in_reply_to is unresolved: a reply is placed only once resolved")\n',
  '',
  [T + 'PlacementTests.test_in_reply_to_only_when_resolved']),
 ('P9 the ledger transport defaulted', DL,
  '        transport=LEDGER_TRANSPORT, tree=TREE_PEER)',
  '        transport="local", tree=TREE_PEER)',
  [T + 'PlacementTests.test_the_ledger_and_the_audit_line']),
 ('A1 no basis asserting clean', DL,
  '        elif basis == config_mod.ATTACHMENT_BASIS_CLOSED_FLEET:',
  '        elif True:',
  [T + 'AttachmentTests.test_no_basis_means_unscanned_and_no_bytes']),
 ('A2 unscanned bytes published', DL,
  '        attachments=[a if a.disposition == DISPOSITION_CLEAN else None for a in signed],',
  '        attachments=list(signed),',
  [T + 'AttachmentTests.test_no_basis_means_unscanned_and_no_bytes']),
 ('A3 sha256 on a non-clean descriptor', DL,
  '    if att.disposition == DISPOSITION_CLEAN:\n        doc["sha256"] = att.sha256\n',
  '    doc["sha256"] = att.sha256\n    if att.disposition == DISPOSITION_CLEAN:\n',
  [T + 'AttachmentTests.test_no_basis_means_unscanned_and_no_bytes']),
 ('A4 content_ref on a non-clean descriptor', DL,
  '        doc["sha256"] = att.sha256\n        doc["content_ref"] = attachments_mod.content_ref_for(notice_id, index)\n    return doc',
  '        doc["sha256"] = att.sha256\n    doc["content_ref"] = attachments_mod.content_ref_for(notice_id, index)\n    return doc',
  [T + 'AttachmentTests.test_no_basis_means_unscanned_and_no_bytes']),
 ('A5 sha256 on a stripped descriptor', DL,
  '    if att.disposition == DISPOSITION_CLEAN:\n        doc["sha256"] = att.sha256\n',
  '    if att.disposition != DISPOSITION_UNSCANNED:\n        doc["sha256"] = att.sha256\n',
  [T + 'AttachmentTests.test_caps_strip_by_index_and_count_only_published_bytes']),
 ('A6 the count cap removed', DL,
  '        if (i >= cfg.attachment_max_count or size > cfg.attachment_max_bytes',
  '        if (size > cfg.attachment_max_bytes',
  [T + 'AttachmentTests.test_the_count_cap']),
 ('A7 the per-file cap removed', DL,
  '        if (i >= cfg.attachment_max_count or size > cfg.attachment_max_bytes\n                or published_total',
  '        if (i >= cfg.attachment_max_count\n                or published_total',
  [T + 'AttachmentTests.test_the_per_file_cap']),
 ('A8 the total cap removed', DL,
  '\n                or published_total + size > cfg.attachment_max_total_bytes):',
  '):',
  [T + 'AttachmentTests.test_caps_strip_by_index_and_count_only_published_bytes']),
 ('A9 a stripped attachment counted in the total', DL,
  '            out.append(DISPOSITION_STRIPPED)\n',
  '            out.append(DISPOSITION_STRIPPED)\n            published_total += size\n',
  [T + 'AttachmentTests.test_caps_strip_by_index_and_count_only_published_bytes']),
 ('A10 the signed filename sanitized', DL,
  '        filename=d["filename"], media_type=d["media_type"],',
  '        filename=attachments_mod._sanitize_display(d["filename"], 255, "attachment"), media_type=d["media_type"],',
  [T + 'AttachmentTests.test_the_signed_names_are_published_exactly']),
 ('X1 reset removing the candidate journal', RS,
  '_STATE_KEEP = (audit_mod.AUDIT_DIR, inflight_mod.TRANSPORT_STATE_DIR, PEER_LEDGER_DIR,\n               PEER_JOURNAL_DIR)',
  '_STATE_KEEP = (audit_mod.AUDIT_DIR, inflight_mod.TRANSPORT_STATE_DIR, PEER_LEDGER_DIR)',
  [T + 'ResetKeepsTests.test_reset_keeps_the_candidate_journal']),
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
