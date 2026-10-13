"""Binding checks 6, 9, 10 and 11, the hosting test, and the authority chain
from a verified signed peer statement to its placement (`router/peerbind.py`,
`deliver.deliver_signed_peer`).

The checks are pure functions of the verified statement and the candidate
view, so these witnesses build both directly; no crypto is involved past
check 5, which `peerverify` owns."""
import ast
import base64
import copy
import dataclasses
import hashlib
import inspect
import json
import os
import pickle
import types
import unittest
from pathlib import Path
from unittest import mock

from router import config as config_mod
from router import deliver, peerbind, peerverify
from router.tests import helpers
from router.tests.peer_helpers import load_amp_validate, make_peer_config, peer_schema_present

FD = "example.invalid"
T1, T2 = "t1.fleet.example", "t2.fleet.example"
KEY_ID = "peer-key-1"
STATEMENT_ID = "pA1b2C3d4E5f6G7h8I9j0kL"
PRESET = ("0123456789abcdef0123456789abcdef", "2026-10-13T12:00:00Z")
RECORD_ID = "cand-0001"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def statement(**over):
    """A decoded statement and its exact bytes."""
    body = over.pop("body_text", "Please run the suite.\n")
    atts = over.pop("atts", [])
    doc = {"v": 1, "key_id": KEY_ID, "kind": "peer", "id": STATEMENT_ID,
           "from": f"planner@{T1}", "to": f"bob@{FD}", "ts": "2026-10-13T11:59:00Z",
           "subject": "Run it", "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
           "attachments": [{"sha256": hashlib.sha256(d).hexdigest(), "size_bytes": len(d),
                            "filename": name, "media_type": mt} for name, mt, d in atts]}
    doc.update(over)
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return doc, raw


def view(doc, *, body=b"Please run the suite.\n", charset="utf-8", atts=None, fields=None):
    if fields is None:
        fields = [["Message-ID", f"<{doc['id']}@{doc['from'].rsplit('@', 1)[1]}>"]]
    return {"fields": fields,
            "body": None if body is None else {"charset": charset, "octets_b64": b64(body)},
            "attachments": [{"octets_b64": b64(d)} for d in (atts or [])]}


def verified(doc, raw, kind="statement"):
    return peerverify.Verified(kind, doc, None, doc["key_id"], raw)


def passes(_payload, _key_id):
    return None


class _Base(helpers.RouterTestCase):
    """bob, hosted here with a peer tree; one peer runtime, host-a, owning
    KEY_ID for T1."""

    def setUp(self):
        super().setUp()
        cfg = make_peer_config(self, {"bob": {}}, fleet_domain=FD)
        self.dc = config_mod.DelegationConfig(
            partition_verified="evidence", signing_key_path="/k/seed", signing_key_id="rl-key",
            signing_public_key="ab" * 32,
            runtimes=(config_mod.DelegationRuntime(
                name="host-a", runtime=f"amap.router@{T1}", domains=(T1, T2),
                keys=(types.MappingProxyType({"key_id": KEY_ID, "public_key": "cd" * 32}),)),),
            crypto_backend="pyca")
        self.cfg = dataclasses.replace(cfg, delegation=self.dc)
        self.delegation = types.SimpleNamespace(config=self.dc)

    def bind(self, doc, raw, cand, check7=passes, check8=passes):
        return peerbind.bind(verified(doc, raw), cand, delegation=self.delegation,
                             check7=check7, check8=check8)

    def cause(self, doc, raw, cand, **kw):
        got = self.bind(doc, raw, cand, **kw)
        return got.cause if isinstance(got, peerbind.Demoted) else None


class CheckSixTests(_Base):

    def test_from_in_another_runtimes_domain_is_key_domain(self):
        doc, raw = statement(**{"from": "planner@elsewhere.example"})
        self.assertEqual(self.cause(doc, raw, view(doc)), peerbind.KEY_DOMAIN)

    def test_the_domain_compares_case_insensitively_and_each_domain_passes(self):
        for frm in (f"planner@{T1.upper()}", f"planner@{T2}"):
            with self.subTest(frm=frm):
                doc, raw = statement(**{"from": frm})
                self.assertIsInstance(self.bind(doc, raw, view(doc)), peerbind.Bound)


class CheckNineTests(_Base):

    def run9(self, body, charset, text=None):
        doc, raw = statement(body_text=text if text is not None else "Please run the suite.\n")
        return self.cause(doc, raw, view(doc, body=body, charset=charset))

    def test_no_body_leaf_is_the_empty_us_ascii_body(self):
        doc, raw = statement(body_text="")
        got = self.bind(doc, raw, view(doc, body=None))
        self.assertEqual(got.body_text, "")

    def test_accepted_labels(self):
        for charset in ("UTF-8", "Us-Ascii", None):
            with self.subTest(charset=charset):
                self.assertIsNone(self.run9(b"Please run the suite.\n", charset))

    def test_charset_failures(self):
        cases = {"an absent label with a high octet": (b"caf\xc3\xa9\n", None, "café\n"),
                 "utf-8 with invalid octets": (b"caf\xe9\n", "utf-8", "café\n"),
                 "another charset": (b"plain\n", "iso-8859-1", "plain\n"),
                 "a non-ASCII label": (b"plain\n", "utf‑8", "plain\n")}
        for why, (body, charset, text) in cases.items():
            with self.subTest(why=why):
                self.assertEqual(self.run9(body, charset, text), peerbind.BODY_CHARSET)

    def test_only_crlf_pairs_are_normalised(self):
        body = b"a\r\nb\rc  \n.d\n"
        self.assertIsNone(self.run9(body, "utf-8", "a\nb\rc  \n.d\n"))
        self.assertEqual(self.run9(body, "utf-8", "a\nb\nc\n.d\n"), peerbind.BODY_DIGEST)

    def test_an_appended_footer_is_body_digest(self):
        self.assertEqual(self.run9(b"Please run the suite.\n-- footer\n", "utf-8"),
                         peerbind.BODY_DIGEST)

    def test_the_text_bound_is_the_text_published(self):
        doc, raw = statement(body_text="x\ny\n")
        self.assertEqual(self.bind(doc, raw, view(doc, body=b"x\r\ny\r\n")).body_text, "x\ny\n")


class CheckTenTests(_Base):

    def doc(self):
        return statement(atts=[("a.txt", "text/plain", b"AAAA")])

    def test_count_then_each_index(self):
        doc, raw = self.doc()
        self.assertEqual(self.cause(doc, raw, view(doc, atts=[])), peerbind.ATTACHMENT_COUNT)
        for why, octets in (("same size, other bytes", b"AAAB"), ("other size", b"AAA"),
                            ("changed", b"BBBBBB")):
            with self.subTest(why=why):
                self.assertEqual(self.cause(doc, raw, view(doc, atts=[octets])),
                                 peerbind.ATTACHMENT_DIGEST)
        self.assertEqual(self.bind(doc, raw, view(doc, atts=[b"AAAA"])).attachments, (b"AAAA",))

    def test_a_wrong_signed_size_with_a_matching_digest(self):
        doc, _raw = self.doc()
        doc["attachments"][0]["size_bytes"] = 5
        raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(self.cause(doc, raw, view(doc, atts=[b"AAAA"])),
                         peerbind.ATTACHMENT_DIGEST)


class CheckElevenTests(_Base):

    def mid(self, fields):
        doc, raw = statement()
        return self.cause(doc, raw, view(doc, fields=fields))

    def test_failures(self):
        good = f"<{STATEMENT_ID}@{T1}>"
        cases = {"two fields": [["Message-ID", good], ["message-id", good]],
                 "no field": [],
                 "the id differs only in case": [["Message-ID", f"<{STATEMENT_ID.lower()}@{T1}>"]],
                 "another domain": [["Message-ID", f"<{STATEMENT_ID}@{T2}>"]],
                 "another id": [["Message-ID", f"<other@{T1}>"]],
                 "interior whitespace": [["Message-ID", f"<{STATEMENT_ID}@ {T1}>"]],
                 "a fold inside the brackets": [["Message-ID", f"<{STATEMENT_ID}@\r\n {T1}>"]],
                 "a marker": [["Message-ID", {"oversize": True}]]}
        for why, fields in cases.items():
            with self.subTest(why=why):
                self.assertEqual(self.mid(fields), peerbind.MESSAGE_ID)

    def test_passes(self):
        for why, value in (("exact", f"<{STATEMENT_ID}@{T1}>"),
                           ("the domain in upper case", f"<{STATEMENT_ID}@{T1.upper()}>"),
                           ("folded before, then trimmed", f"\r\n <{STATEMENT_ID}@{T1}> ")):
            with self.subTest(why=why):
                self.assertIsNone(self.mid([["Message-ID", value]]))


class OrderTests(_Base):

    def test_the_first_failure_decides(self):
        doc, raw = statement(atts=[("a", "text/plain", b"AA")])
        bad_all = view(doc, body=b"wrong\n", atts=[], fields=[])
        self.assertEqual(self.cause(doc, raw, bad_all), peerbind.BODY_DIGEST)
        bad_10_11 = view(doc, atts=[], fields=[])
        self.assertEqual(self.cause(doc, raw, bad_10_11), peerbind.ATTACHMENT_COUNT)
        self.assertEqual(self.cause(doc, raw, bad_all, check7=lambda p, k: "ts_window"),
                         "ts_window")
        self.assertEqual(self.cause(doc, raw, bad_all, check8=lambda p, k: "exposure_signer"),
                         "exposure_signer")

    def test_check_six_runs_before_seven_and_eight(self):
        doc, raw = statement(**{"from": "planner@elsewhere.example"})
        called = []
        got = self.cause(doc, raw, view(doc), check7=lambda p, k: called.append(7),
                         check8=lambda p, k: called.append(8))
        self.assertEqual((got, called), (peerbind.KEY_DOMAIN, []))
        self.assertEqual(peerbind.ORDER, (6, 7, 8, 9, 10, 11))

    def test_checks_seven_and_eight_are_required(self):
        params = inspect.signature(peerbind.bind).parameters
        for name in ("check7", "check8"):
            self.assertIs(params[name].default, inspect.Parameter.empty, name)
        doc, raw = statement()
        with self.assertRaises(TypeError):
            peerbind.bind(verified(doc, raw), view(doc), delegation=self.delegation,
                          check8=passes)

    def test_only_a_statement_is_bound(self):
        doc, raw = statement()
        with self.assertRaises(ValueError):
            peerbind.bind(verified(doc, raw, kind="control"), view(doc),
                          delegation=self.delegation, check7=passes, check8=passes)

    def test_a_malformed_view_is_not_a_verdict(self):
        doc, raw = statement()
        for bad in ({"fields": [], "body": {"charset": None, "octets_b64": "%%"},
                     "attachments": []},
                    {"fields": "x", "body": None, "attachments": []}):
            with self.subTest(bad=bad):
                with self.assertRaises(peerbind.CandidateMalformed):
                    self.bind(doc, raw, bad)


class HostingTests(_Base):

    def alias(self, status, target="bob"):
        entry = config_mod.AliasEntry(old=f"Old.Bob@{FD}", new=f"bob@{FD}",
                                      expires="2099-01-01T00:00:00Z")
        decisions = {} if status is None else {
            entry.old: types.SimpleNamespace(status=status, target=target)}
        return dataclasses.replace(self.cfg, aliases=(entry,),
                                   alias_view=types.SimpleNamespace(decisions=decisions))

    def test_by_name(self):
        h = peerbind.hosting
        self.assertEqual(h(self.cfg, f"bob@{FD}"), peerbind.Hosted("bob"))
        self.assertEqual(h(self.cfg, f"bob@{FD.upper()}"), peerbind.Hosted("bob"))
        for to in (f"Bob@{FD}", f"carol@{FD}", f"bob@{T1}", f"amap.router@{FD}", "bob", None):
            with self.subTest(to=to):
                self.assertEqual(h(self.cfg, to), peerbind.NotHosted())

    def test_a_held_recipient_is_undecided(self):
        with mock.patch.object(config_mod, "target_hold", return_value="held"):
            self.assertEqual(peerbind.hosting(self.cfg, f"bob@{FD}"),
                             peerbind.Undecided("registry_held"))

    def test_aliases(self):
        from router import aliases as al
        old = f"Old.Bob@{FD}"
        self.assertEqual(peerbind.hosting(self.alias(al.ACTIVE), old), peerbind.Hosted("bob"))
        self.assertEqual(peerbind.hosting(self.alias(al.INACTIVE), old), peerbind.NotHosted())
        self.assertEqual(peerbind.hosting(self.alias(al.UNVERIFIABLE), old),
                         peerbind.Undecided("alias_unverifiable"))
        self.assertEqual(peerbind.hosting(self.alias(None), old),
                         peerbind.Undecided("alias_undecided"))
        self.assertEqual(peerbind.hosting(self.alias(al.ACTIVE), f"old.bob@{FD}"),
                         peerbind.NotHosted(), "the alias matches the local part exactly")


class _Chain(_Base):
    """The authority chain over a real state_dir: the decision key, a record
    directory, and bob's peer tree."""

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        peerbind.ensure_decision_key(self.state_dir)
        self.record_dir = f"bob/{peerbind.JOURNAL_DIR}/{RECORD_ID}"
        (self.state_dir / self.record_dir).mkdir(parents=True)
        self.baseline = self.tree()

    def fresh(self, **over):
        atts_raw = over.pop("atts_raw", [])
        doc, raw = statement(**over)
        cand = view(doc, body=over.get("body_text", "Please run the suite.\n").encode("utf-8"),
                    atts=[d for _n, _m, d in atts_raw])
        auth = peerbind.authorise(verified(doc, raw), cand, delegation=self.delegation,
                                  cfg=self.cfg, check7=passes, check8=passes)
        self.assertIsInstance(auth, peerbind.Authorised, auth)
        return auth, peerbind.Snapshot(raw, cand)

    def decide(self, auth, record_id=RECORD_ID, record_dir=None):
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=record_id,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        return rec, peerbind.commit_decision(self.state_dir, record_dir or self.record_dir, rec,
                                             record_id=record_id)

    def tree(self):
        root = self.cfg.instances["bob"].peer_root
        return sorted((str(p.relative_to(root)), p.read_bytes() if p.is_file() else None)
                      for p in root.rglob("*"))


class SealTests(_Chain):

    def test_only_the_issuers_build_an_authorised(self):
        auth, _snap = self.fresh()
        parts = {f.name: getattr(auth, f.name) for f in dataclasses.fields(auth) if f.init}
        for seal in (b"", b"\x00" * 32):
            with self.subTest(seal=seal):
                with self.assertRaises(TypeError):
                    peerbind.Authorised(**dict(parts, seal=seal))

    def test_replace_with_any_bound_part_changed_fails(self):
        auth, _snap = self.fresh()
        other, _ = self.fresh(subject="Other", body_text="Another body.\n")
        for part in ("statement", "body_text", "attachments", "key_id", "runtime", "hosted",
                     "origin", "confirmed"):
            with self.subTest(part=part):
                value = {"statement": other.statement, "body_text": other.body_text,
                         "attachments": (b"Z",), "key_id": "x", "runtime": "amap.router@x",
                         "hosted": "carol", "origin": peerbind.ORIGIN_DECIDED,
                         "confirmed": True}[part]
                self.assertNotEqual(value, getattr(auth, part), "the swap must change the part")
                with self.assertRaises(TypeError):
                    dataclasses.replace(auth, **{part: value})
        # TypeError on 3.10+, ValueError on 3.9: either way, refused.
        with self.assertRaises((TypeError, ValueError)):
            dataclasses.replace(auth, payload={})

    def test_not_picklable_and_copies_are_identical(self):
        auth, _snap = self.fresh()
        with self.assertRaisesRegex(TypeError, "not persisted"):
            pickle.dumps(auth)
        self.assertIs(copy.copy(auth), auth)
        self.assertIs(copy.deepcopy(auth), auth)

    def test_a_forged_or_stale_seal_is_refused_at_every_entry(self):
        fresh, snap = self.fresh()
        _rec, rcp = self.decide(fresh)
        auth = peerbind.resume(rcp, snap, state_dir=self.state_dir)
        forged = object.__new__(peerbind.Authorised)
        for f in dataclasses.fields(auth):
            object.__setattr__(forged, f.name, getattr(auth, f.name))
        object.__setattr__(forged, "seal", b"\x00" * 32)
        with mock.patch.object(peerbind, "_SEAL_KEY", b"\x01" * 32):
            stale = auth          # sealed under the key it was issued with
            for value in (forged, stale):
                with self.subTest(value=value is forged and "forged" or "old key"):
                    with self.assertRaises(TypeError):
                        peerbind.published(value)
                    before = self.tree()
                    with self.assertRaises(TypeError):
                        deliver.deliver_signed_peer(self.cfg, self.state_dir, value)
                    self.assertEqual(self.tree(), before)


class ConfirmAndRecordTests(_Chain):

    def test_confirm_refuses_a_moved_world(self):
        auth, _snap = self.fresh()
        with mock.patch.object(config_mod, "target_hold", return_value="held"):
            with self.assertRaises(peerbind.AuthorisationMismatch) as cm:
                peerbind.confirm(auth, cfg=self.cfg)
        self.assertEqual(cm.exception.kind, "stale")
        self.assertTrue(peerbind.confirm(auth, cfg=self.cfg).confirmed)

    def test_decision_record_takes_only_a_confirmed_fresh_value(self):
        auth, snap = self.fresh()
        with self.assertRaises(TypeError):
            peerbind.decision_record(auth, record_id=RECORD_ID, preset=PRESET, cfg=self.cfg,
                                     state_dir=self.state_dir)
        _rec, rcp = self.decide(auth)
        decided = peerbind.resume(rcp, snap, state_dir=self.state_dir)
        with self.assertRaises(TypeError):
            peerbind.decision_record(decided, record_id=RECORD_ID, preset=PRESET, cfg=self.cfg,
                                     state_dir=self.state_dir)

    def test_decision_record_re_confirms(self):
        auth, _snap = self.fresh()
        confirmed = peerbind.confirm(auth, cfg=self.cfg)
        with mock.patch.object(config_mod, "target_hold", return_value="held"):
            with self.assertRaises(peerbind.AuthorisationMismatch):
                peerbind.decision_record(confirmed, record_id=RECORD_ID, preset=PRESET,
                                         cfg=self.cfg, state_dir=self.state_dir)


class PersistenceTests(_Chain):

    def test_raw_record_bytes_cannot_be_resumed(self):
        auth, snap = self.fresh()
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=RECORD_ID,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        with self.assertRaises(TypeError):
            peerbind.resume(rec, snap, state_dir=self.state_dir)

    def test_a_fabricated_self_consistent_record_gets_no_seal(self):
        doc, raw = statement(**{"from": "planner@elsewhere.example"})    # demoted at check 6
        cand = view(doc)
        text = "Please run the suite.\n"
        members = {"v": 1, "state": "decided", "disposition": "place", "record_id": RECORD_ID,
                   "statement_sha256": hashlib.sha256(raw).hexdigest(), "key_id": KEY_ID,
                   "runtime": f"amap.router@{T1}", "hosted_instance": "bob",
                   "notice_id": PRESET[0], "ts": PRESET[1],
                   "body_sha256": hashlib.sha256(text.encode()).hexdigest(),
                   "attachment_sha256s": []}
        forged = json.dumps(dict(members, mac="0" * 64), sort_keys=True).encode()
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.commit_decision(self.state_dir, self.record_dir, forged, record_id=RECORD_ID)
        self.assertEqual(cm.exception.reason, "mac")
        (self.state_dir / self.record_dir / peerbind.DECISION_FILE).write_bytes(forged)
        os.chmod(self.state_dir / self.record_dir / peerbind.DECISION_FILE, 0o600)
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.reopen_decision(self.state_dir, self.record_dir, record_id=RECORD_ID)
        self.assertEqual(cm.exception.reason, "mac")

    def test_each_member_edited_on_disk_fails_the_mac(self):
        auth, snap = self.fresh()
        rec, _rcp = self.decide(auth)
        path = self.state_dir / self.record_dir / peerbind.DECISION_FILE
        for member, value in (("hosted_instance", "carol"), ("runtime", "amap.router@x"),
                              ("key_id", "x"), ("notice_id", "f" * 32),
                              ("ts", "2026-10-14T00:00:00Z"), ("record_id", "cand-0002")):
            with self.subTest(member=member):
                doc = json.loads(rec)
                doc[member] = value
                os.chmod(path, 0o600)
                path.unlink()
                path.write_bytes(json.dumps(doc, sort_keys=True).encode())
                os.chmod(path, 0o600)
                with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
                    peerbind.reopen_decision(self.state_dir, self.record_dir,
                                             record_id=doc["record_id"])
                self.assertEqual(cm.exception.reason, "mac")

    def test_a_record_resumed_under_another_record_id_is_refused(self):
        auth, _snap = self.fresh()
        self.decide(auth)
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.reopen_decision(self.state_dir, self.record_dir, record_id="cand-0002")
        self.assertEqual(cm.exception.reason, "record_id")

    def test_replacement_after_the_receipt_is_detected(self):
        auth, snap = self.fresh()
        rec, rcp = self.decide(auth)
        path = self.state_dir / self.record_dir / peerbind.DECISION_FILE
        # Hold the original open, so the filesystem cannot hand its inode
        # number straight back to the replacement (ext4 reuses a freed one).
        held = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, held)
        path.unlink()
        path.write_bytes(rec)                     # same bytes, a new inode
        os.chmod(path, 0o600)
        self.assertNotEqual(os.stat(path).st_ino, os.fstat(held).st_ino)
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.resume(rcp, snap, state_dir=self.state_dir)
        self.assertEqual(cm.exception.reason, "replaced")

    def test_recommit_is_idempotent_and_a_different_record_conflicts(self):
        auth, _snap = self.fresh()
        rec, rcp = self.decide(auth)
        again = peerbind.commit_decision(self.state_dir, self.record_dir, rec,
                                         record_id=RECORD_ID)
        self.assertEqual(again.record_sha256, rcp.record_sha256)
        other, _ = self.fresh(subject="Other")
        rec2 = peerbind.decision_record(peerbind.confirm(other, cfg=self.cfg),
                                        record_id=RECORD_ID, preset=PRESET, cfg=self.cfg,
                                        state_dir=self.state_dir)
        with self.assertRaises(peerbind.DecisionConflict):
            peerbind.commit_decision(self.state_dir, self.record_dir, rec2, record_id=RECORD_ID)
        self.assertEqual((self.state_dir / self.record_dir / peerbind.DECISION_FILE).read_bytes(),
                         rec)

    def test_a_crash_between_link_and_unlink_resumes_once(self):
        auth, snap = self.fresh()
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=RECORD_ID,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        real_unlink = os.unlink

        def crash(path, *a, **kw):
            if str(path).startswith(peerbind.DECISION_STAGE_PREFIX):
                raise SystemExit("crash")
            return real_unlink(path, *a, **kw)
        with mock.patch.object(peerbind.os, "unlink", crash):
            with self.assertRaises(SystemExit):
                peerbind.commit_decision(self.state_dir, self.record_dir, rec,
                                         record_id=RECORD_ID)
        try:
            rcp = peerbind.reopen_decision(self.state_dir, self.record_dir, record_id=RECORD_ID)
        except peerbind.RecoveryCorrupt as e:
            self.fail(f"a crash between link and unlink became a permanent hold: {e}")
        d = peerbind.resume(rcp, snap, state_dir=self.state_dir)
        self.assertTrue(deliver.deliver_signed_peer(self.cfg, self.state_dir, d)["placed"])
        self.assertFalse(deliver.deliver_signed_peer(self.cfg, self.state_dir, d)["placed"])

    def test_a_crash_before_the_link_leaves_no_decision(self):
        auth, _snap = self.fresh()
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=RECORD_ID,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        with mock.patch.object(peerbind.os, "link", side_effect=SystemExit("crash")):
            with self.assertRaises(SystemExit):
                peerbind.commit_decision(self.state_dir, self.record_dir, rec,
                                         record_id=RECORD_ID)
        with self.assertRaises(peerbind.NoDecision):
            peerbind.reopen_decision(self.state_dir, self.record_dir, record_id=RECORD_ID)
        self.assertEqual(os.listdir(self.state_dir / self.record_dir), [])

    def test_no_receipt_without_durability(self):
        auth, snap = self.fresh()
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=RECORD_ID,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        real_fsync = os.fsync
        dirs = []

        def failing_dir_fsync(fd):
            import stat as st
            if st.S_ISDIR(os.fstat(fd).st_mode):
                dirs.append(fd)
                raise OSError(5, "EIO")
            return real_fsync(fd)
        with mock.patch.object(peerbind.os, "fsync", failing_dir_fsync):
            with self.assertRaises(OSError):
                peerbind.commit_decision(self.state_dir, self.record_dir, rec,
                                         record_id=RECORD_ID)
            with self.assertRaises(OSError):
                peerbind.reopen_decision(self.state_dir, self.record_dir, record_id=RECORD_ID)
        self.assertGreaterEqual(len(dirs), 2)
        self.assertEqual(self.tree(), self.baseline)
        rcp = peerbind.commit_decision(self.state_dir, self.record_dir, rec, record_id=RECORD_ID)
        d = peerbind.resume(rcp, snap, state_dir=self.state_dir)
        self.assertTrue(deliver.deliver_signed_peer(self.cfg, self.state_dir, d)["placed"])

    def test_a_read_back_mismatch_gives_no_receipt(self):
        auth, _snap = self.fresh()
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=RECORD_ID,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        real = peerbind._link_once

        def then_altered(dirfd, name, data, *, stage_prefix):
            got = real(dirfd, name, data, stage_prefix=stage_prefix)
            fd = os.open(name, os.O_WRONLY, dir_fd=dirfd)
            os.write(fd, b"X")
            os.close(fd)
            return got
        with mock.patch.object(peerbind, "_link_once", then_altered):
            with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
                peerbind.commit_decision(self.state_dir, self.record_dir, rec,
                                         record_id=RECORD_ID)
        self.assertEqual(cm.exception.reason, "readback")

    def test_a_retry_after_a_failed_fsync_re_establishes_durability(self):
        auth, _snap = self.fresh()
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=RECORD_ID,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        real_fsync = os.fsync
        import stat as st
        fail = [True]
        dir_syncs = []

        def spy(fd):
            if st.S_ISDIR(os.fstat(fd).st_mode):
                if fail[0]:
                    raise OSError(5, "EIO")
                dir_syncs.append(fd)
            return real_fsync(fd)
        with mock.patch.object(peerbind.os, "fsync", spy):
            with self.assertRaises(OSError):
                peerbind.commit_decision(self.state_dir, self.record_dir, rec,
                                         record_id=RECORD_ID)
            fail[0] = False
            peerbind.commit_decision(self.state_dir, self.record_dir, rec, record_id=RECORD_ID)
        self.assertTrue(dir_syncs, "the exists_same retry fsyncs the directory again")

    def test_a_record_dir_outside_the_journal_is_refused(self):
        auth, _snap = self.fresh()
        rec = peerbind.decision_record(peerbind.confirm(auth, cfg=self.cfg), record_id=RECORD_ID,
                                       preset=PRESET, cfg=self.cfg, state_dir=self.state_dir)
        (self.state_dir / "bob" / "elsewhere" / "x").mkdir(parents=True)
        os.symlink(self.state_dir / self.record_dir, self.state_dir / "bob" / "link")
        for bad in ("bob/elsewhere/x", "../bob/peer-candidates/x", f"bob/{peerbind.JOURNAL_DIR}"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    peerbind.commit_decision(self.state_dir, bad, rec, record_id=RECORD_ID)


class DecisionKeyTests(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.key = self.state_dir / peerbind.DECISION_KEY_FILE

    def test_created_once_0600_even_under_a_restrictive_umask(self):
        old = os.umask(0o277)
        try:
            first = peerbind.ensure_decision_key(self.state_dir)
        except peerbind.RecoveryCorrupt as e:
            self.fail(f"the umask wedged the key: {e}")
        finally:
            os.umask(old)
        self.assertEqual(os.stat(self.key).st_mode & 0o777, 0o600)
        self.assertEqual(peerbind.ensure_decision_key(self.state_dir), first)
        self.assertEqual(len(first), peerbind.DECISION_KEY_BYTES)

    def test_a_wrong_key_file_is_refused(self):
        peerbind.ensure_decision_key(self.state_dir)
        os.chmod(self.key, 0o644)
        with self.assertRaises(peerbind.RecoveryCorrupt):
            peerbind.ensure_decision_key(self.state_dir)
        os.chmod(self.key, 0o600)
        os.link(self.key, self.state_dir / "second")
        with self.assertRaises(peerbind.RecoveryCorrupt):
            peerbind.ensure_decision_key(self.state_dir)
        os.unlink(self.state_dir / "second")
        real = self.state_dir / "real"
        os.rename(self.key, real)
        os.symlink(real, self.key)
        with self.assertRaises(OSError):
            peerbind.ensure_decision_key(self.state_dir)

    def test_the_present_key_path_makes_the_key_durable_first(self):
        real_fsync = os.fsync

        def dir_fsync_fails(fd):
            import stat as st
            if st.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, "EIO")
            return real_fsync(fd)
        with mock.patch.object(peerbind.os, "fsync", dir_fsync_fails):
            with self.assertRaises(OSError):
                peerbind.ensure_decision_key(self.state_dir)
            self.assertTrue(self.key.exists(), "the key was linked before the fsync failed")
            with self.assertRaises(OSError):
                peerbind.ensure_decision_key(self.state_dir)       # present path: no key
        linked = self.key.read_bytes()
        self.assertEqual(peerbind.ensure_decision_key(self.state_dir), linked)

    def test_leftover_temps_are_cleaned_and_never_read(self):
        (self.state_dir / (peerbind.DECISION_KEY_STAGE_PREFIX + "x")).write_bytes(b"short")
        key = peerbind.ensure_decision_key(self.state_dir)
        self.assertEqual(len(key), 32)
        # a crash after a later stage write leaves a temp beside a PRESENT key
        (self.state_dir / (peerbind.DECISION_KEY_STAGE_PREFIX + "y")).write_bytes(b"short")
        self.assertEqual(peerbind.ensure_decision_key(self.state_dir), key)
        self.assertEqual([n for n in os.listdir(self.state_dir)
                          if n.startswith(peerbind.DECISION_KEY_STAGE_PREFIX)], [])

    def test_a_conflicting_creator_is_validated_not_fatal(self):
        winner = os.urandom(32)

        def race(dirfd, name, data, *, stage_prefix):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dirfd)
            os.write(fd, winner)
            os.close(fd)
            raise peerbind.LinkConflict(name)
        with mock.patch.object(peerbind, "_link_once", race):
            try:
                got = peerbind.ensure_decision_key(self.state_dir)
            except peerbind.LinkConflict:
                self.fail("a conflicting creator was fatal")
        self.assertEqual(got, winner)


class PlacementTests(_Chain):

    def place(self, cfg=None, in_reply_to_resolved=None, **over):
        auth, snap = self.fresh(**over)
        _rec, rcp = self.decide(auth)
        d = peerbind.resume(rcp, snap, state_dir=self.state_dir)
        return deliver.deliver_signed_peer(cfg or self.cfg, self.state_dir, d,
                                           in_reply_to_resolved=in_reply_to_resolved)

    def docs(self):
        root = self.cfg.instances["bob"].peer_root
        nid = PRESET[0]
        return (json.loads((root / "notices" / f"notice-{nid}.json").read_text()),
                json.loads((root / "messages" / f"notice-{nid}.json").read_text()))

    def test_a_fresh_value_writes_nothing(self):
        auth, _snap = self.fresh()
        for value in (auth, peerbind.confirm(auth, cfg=self.cfg)):
            try:
                deliver.deliver_signed_peer(self.cfg, self.state_dir, value)
            except Exception as e:  # noqa: BLE001
                self.assertIsInstance(e, TypeError)
                self.assertIn("persisted decision", str(e))
            else:
                self.fail("a fresh value was placed")
        self.assertEqual(self.tree(), self.baseline)

    def test_the_published_fields_come_from_the_statement(self):
        exposure = {"asserted_by": f"amap.router@{T1}", "external_mail_delivered": False,
                    "window_start": "2026-10-13T00:00:00Z", "window_end": "2026-10-13T11:00:00Z"}
        self.place(sender_exposure=exposure)
        notice, spool = self.docs()
        m = notice["message"]
        self.assertEqual((m["id"], m["from"], m["subject"], m["mailbox"]),
                         (STATEMENT_ID, f"planner@{T1}", "Run it", "peer"))
        self.assertEqual(m.get("sender_exposure"), exposure)
        self.assertNotIn("in_reply_to", m)
        self.assertNotIn("references", m)
        self.assertEqual((spool["id"], spool["to"], spool["body_text"]),
                         (STATEMENT_ID, f"bob@{FD}", "Please run the suite.\n"))
        self.assertNotIn("sender_exposure", spool)
        self.assertEqual(notice["notice_id"], PRESET[0])
        self.assertNotEqual(m["id"], notice["notice_id"])

    def test_the_ledger_and_the_audit_line(self):
        from router import audit, binding
        self.place()
        rec = json.loads(binding.ledger_path(self.state_dir, "bob", PRESET[0]).read_text())
        self.assertEqual((rec["tree"], rec["transport"], rec["from_instance"], rec["message_id"]),
                         ("peer", "hop", None, STATEMENT_ID))
        [line] = [e for e in audit.read_events(self.state_dir, "bob")
                  if e["event"] == audit.EVENT_PEER_NOTICE_PLACED]
        self.assertEqual((line["origin"], line["signature_verdict"], line["key_id"],
                          line["runtime"], line["demotion_cause"]),
                         ("fleet", "verified", KEY_ID, f"amap.router@{T1}", None))

    def test_in_reply_to_only_when_resolved(self):
        with self.assertRaises(ValueError):
            self.place(in_reply_to="orig0123456789abcdefghij")
        self.assertEqual(self.tree(), self.baseline)
        self.place(in_reply_to="orig0123456789abcdefghij",
                   in_reply_to_resolved="orig0123456789abcdefghij")
        notice, _spool = self.docs()
        self.assertEqual(notice["message"]["in_reply_to"], "orig0123456789abcdefghij")

    def test_a_leading_dash_id_is_unpublishable(self):
        with self.assertRaises(peerbind.Unpublishable) as cm:
            self.place(id="-" + STATEMENT_ID[1:])
        self.assertEqual(cm.exception.member, "id")
        self.assertEqual(self.tree(), self.baseline)

    def test_a_recipient_no_longer_configured_holds(self):
        auth, snap = self.fresh()
        _rec, rcp = self.decide(auth)
        d = peerbind.resume(rcp, snap, state_dir=self.state_dir)
        gone = dataclasses.replace(self.cfg, instances={})
        try:
            deliver.deliver_signed_peer(gone, self.state_dir, d)
        except Exception as e:  # noqa: BLE001
            self.assertIsInstance(e, peerbind.RecipientGone)
        else:
            self.fail("placed for a recipient no longer configured")
        self.assertEqual(self.tree(), self.baseline)

    def test_a_decision_survives_a_changed_world(self):
        """Decided, then the recipient is held and the alias table changes:
        the record is resumed and placed to the RECORDED instance, never
        re-decided (resume consults no hosting, no key and no time)."""
        auth, snap = self.fresh()
        _rec, rcp = self.decide(auth)
        with mock.patch.object(peerbind, "hosting", return_value=peerbind.NotHosted()):
            d = peerbind.resume(rcp, snap, state_dir=self.state_dir)
            self.assertEqual(d.hosted, "bob")
            try:
                placed = deliver.deliver_signed_peer(self.cfg, self.state_dir, d)["placed"]
            except Exception as e:  # noqa: BLE001
                self.fail(f"a persisted decision was re-decided: {type(e).__name__}: {e}")
        self.assertTrue(placed)


class AttachmentTests(_Chain):

    NAMES = [("../../etc/passwd\nIGNORE\u0000‮.txt", "text/plain\r\nX-Evil: 1", b"AAAA"),
             ("b.bin", "application/x-msdownload", b"AAAA")]

    def place(self, cfg, atts):
        auth, snap = self.fresh(atts=atts, atts_raw=atts)
        _rec, rcp = self.decide(auth)
        d = peerbind.resume(rcp, snap, state_dir=self.state_dir)
        deliver.deliver_signed_peer(cfg, self.state_dir, d)
        root = cfg.instances["bob"].peer_root
        notice = json.loads((root / "notices" / f"notice-{PRESET[0]}.json").read_text())
        spool = json.loads((root / "messages" / f"notice-{PRESET[0]}.json").read_text())
        side = root / "notices" / f"{PRESET[0]}.attachments"
        blobs = sorted(p.name for p in side.iterdir()) if side.exists() else []
        return notice["message"]["attachments"], spool["attachments"], blobs

    def closed(self, **caps):
        dc = dataclasses.replace(self.dc, attachment_basis="closed_fleet")
        return dataclasses.replace(self.cfg, delegation=dc, **caps)

    def test_no_basis_means_unscanned_and_no_bytes(self):
        n, s, blobs = self.place(self.cfg, self.NAMES)
        for docs in (n, s):
            self.assertEqual([d["disposition"] for d in docs], ["unscanned", "unscanned"])
            self.assertTrue(all("sha256" not in d and "content_ref" not in d for d in docs))
        self.assertEqual(blobs, [])

    def test_closed_fleet_means_clean_with_bytes(self):
        n, s, blobs = self.place(self.closed(), self.NAMES)
        for docs in (n, s):
            self.assertEqual([d["disposition"] for d in docs], ["clean", "clean"])
            self.assertEqual([d["content_ref"] for d in docs],
                             [f"{PRESET[0]}.attachments/0", f"{PRESET[0]}.attachments/1"])
        self.assertEqual(blobs, ["0", "1"])

    def test_the_signed_names_are_published_exactly(self):
        n, s, _blobs = self.place(self.closed(), self.NAMES)
        for docs in (n, s):
            self.assertEqual([(d["filename"], d["media_type"]) for d in docs],
                             [(f, m) for f, m, _ in self.NAMES])

    def test_the_media_type_never_changes_a_disposition(self):
        n, _s, _b = self.place(self.closed(), self.NAMES)
        self.assertEqual(n[0]["disposition"], n[1]["disposition"])

    def test_caps_strip_by_index_and_count_only_published_bytes(self):
        atts = [("big", "a/b", b"X" * 10), ("small", "a/b", b"Y" * 3), ("more", "a/b", b"Z" * 4)]
        n, _s, blobs = self.place(self.closed(attachment_max_bytes=5,
                                              attachment_max_total_bytes=6,
                                              attachment_max_count=10), atts)
        self.assertEqual([d["disposition"] for d in n], ["stripped", "clean", "stripped"])
        self.assertTrue(all("sha256" not in d for d in n if d["disposition"] != "clean"))
        self.assertEqual(blobs, ["1"])

    def test_the_per_file_cap(self):
        atts = [("big", "a/b", b"X" * 10), ("small", "a/b", b"Y" * 3)]
        n, _s, _b = self.place(self.closed(attachment_max_bytes=5,
                                           attachment_max_total_bytes=100), atts)
        self.assertEqual([d["disposition"] for d in n], ["stripped", "clean"])

    def test_the_count_cap(self):
        atts = [("a", "a/b", b"1"), ("b", "a/b", b"2"), ("c", "a/b", b"3")]
        n, _s, _b = self.place(self.closed(attachment_max_count=2), atts)
        self.assertEqual([d["disposition"] for d in n], ["clean", "clean", "stripped"])

    def test_a_capped_attachment_under_no_basis_is_stripped(self):
        atts = [("big", "a/b", b"X" * 10), ("small", "a/b", b"Y")]
        n, _s, _b = self.place(dataclasses.replace(self.cfg, attachment_max_bytes=5), atts)
        self.assertEqual([d["disposition"] for d in n], ["stripped", "unscanned"])


@unittest.skipUnless(peer_schema_present(), "no spec checkout")
class SpecConformanceTests(AttachmentTests):
    """The notice a signed placement writes validates as a peer notice under
    the spec's own engine (AMAP_SPEC_REPO), control-bearing names included."""

    def test_the_notice_validates(self):
        self.place(self.closed(), self.NAMES)
        root = self.cfg.instances["bob"].peer_root
        notice = json.loads((root / "notices" / f"notice-{PRESET[0]}.json").read_text())
        self.assertEqual(load_amp_validate().check_document("peer-produced.json", notice), [])


class ResetKeepsTests(_Base):

    def test_reset_keeps_the_candidate_journal(self):
        from router import reset as reset_mod
        self.assertTrue(reset_mod._kept(self.cfg, peerbind.JOURNAL_DIR))


class CallerPinTests(unittest.TestCase):
    """Delegation is activated, and the decision key created, only under the
    drain lock: `activate_delegation` from `run_forever`'s startup and from
    `reload_config`; `peerlane.activate` and `ensure_decision_key` only from
    `activate_delegation`. A new caller fails here and must be reviewed."""

    def calls(self, name):
        found = []
        for path in sorted(Path(peerbind.__file__).parent.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for node in ast.walk(fn):
                        if (isinstance(node, ast.Call) and (
                                (isinstance(node.func, ast.Attribute) and node.func.attr == name)
                                or (isinstance(node.func, ast.Name) and node.func.id == name))):
                            found.append((path.name, fn.name))
        return sorted(set(found))

    def test_the_activation_call_sites(self):
        self.assertEqual(self.calls("activate_delegation"),
                         [("service.py", "reload_config"), ("service.py", "run_forever")])
        self.assertEqual(self.calls("activate"), [("service.py", "activate_delegation")])
        self.assertEqual(self.calls("ensure_decision_key"),
                         [("service.py", "activate_delegation")])


if __name__ == "__main__":
    unittest.main()
