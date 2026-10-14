"""The reserved path in `router/peerbind.py`: checks 6-11 once
(`bind_for_reservation`), the MAC'd reservation and its receipt
(`reservation_record`, `commit_reservation`, `reopen_reservation`), the
reserved value (`resume_reserved`) and hosting alone (`authorise_checked`),
ending in the decision chain (`confirm`, `decision_record`)."""
import copy
import dataclasses
import hashlib
import json
import os
import pickle
import types
import unittest

from router import config as config_mod
from router import peerbind
from router.tests.test_peerbind import (KEY_ID, T1, _Base, passes, statement, verified, view)

RID = "a" * 64
OTHER = "b" * 64


def refuses(_payload, _key_id):
    return "ts_window"


class _Reserved(_Base):

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        peerbind.ensure_decision_key(self.state_dir)
        self.record_dir = f"bob/{peerbind.JOURNAL_DIR}/{RID}"
        (self.state_dir / self.record_dir).mkdir(parents=True)
        self.seq = 0

    def pre(self, **over):
        doc, raw = statement(**over)
        cand = view(doc)
        chk = peerbind.bind_for_reservation(verified(doc, raw), cand, delegation=self.delegation,
                                            check7=passes, check8=passes)
        self.assertIsInstance(chk, peerbind.Checked, chk)
        return chk, peerbind.Snapshot(raw, cand)

    def reserve(self, chk, record_id=RID):
        self.seq += 1
        rec = peerbind.reservation_record(chk, record_id=record_id, reserve_seq=self.seq,
                                          state_dir=self.state_dir)
        doc = json.loads(rec)
        rcp = peerbind.commit_reservation(self.state_dir, doc["rt"], doc["idk"], rec,
                                          record_id=record_id)
        return rec, rcp

    def path(self, rcp):
        return (self.state_dir / peerbind.REPLAY_DIR / rcp.rt / (rcp.idk + ".json"))

    def rewrite(self, path, data):
        path.unlink()
        path.write_bytes(data)
        os.chmod(path, 0o600)


class OnePathTests(_Reserved):

    def test_the_fresh_path_carries_the_reservations_notice_id(self):
        chk, snap = self.pre()
        rec, rcp = self.reserve(chk)
        reserved = peerbind.resume_reserved(rcp, snap, state_dir=self.state_dir)
        auth = peerbind.authorise_checked(reserved, cfg=self.cfg)
        self.assertIsInstance(auth, peerbind.Authorised)
        self.assertEqual(auth.notice_id, json.loads(rec)["notice_id"])
        self.assertEqual(auth.record_id, RID)
        confirmed = peerbind.confirm(auth, cfg=self.cfg)
        drec = peerbind.decision_record(confirmed, record_id=RID,
                                        preset=(auth.notice_id, auth.ts), cfg=self.cfg,
                                        state_dir=self.state_dir)
        drcp = peerbind.commit_decision(self.state_dir, self.record_dir, drec, record_id=RID)
        decided = peerbind.resume(drcp, snap, state_dir=self.state_dir)
        self.assertEqual((decided.notice_id, decided.ts),
                         (json.loads(rec)["notice_id"], json.loads(rec)["ts"]))

    def test_a_pre_value_is_refused_by_authorise_checked(self):
        chk, _snap = self.pre()
        with self.assertRaises(TypeError):
            peerbind.authorise_checked(chk, cfg=self.cfg)
        self.assertFalse((self.state_dir / peerbind.REPLAY_DIR).exists(), "nothing reserved")

    def test_a_reserved_value_is_refused_by_reservation_record(self):
        chk, snap = self.pre()
        _rec, rcp = self.reserve(chk)
        reserved = peerbind.resume_reserved(rcp, snap, state_dir=self.state_dir)
        with self.assertRaises(TypeError):
            peerbind.reservation_record(reserved, record_id=RID, reserve_seq=9,
                                        state_dir=self.state_dir)

    def test_decision_record_refuses_a_preset_that_is_not_the_reservations(self):
        chk, snap = self.pre()
        _rec, rcp = self.reserve(chk)
        auth = peerbind.authorise_checked(
            peerbind.resume_reserved(rcp, snap, state_dir=self.state_dir), cfg=self.cfg)
        confirmed = peerbind.confirm(auth, cfg=self.cfg)
        for preset, rid in (((("f" * 32), auth.ts), RID), ((auth.notice_id, "2026-10-14T00:00:00Z"),
                                                           RID),
                            ((auth.notice_id, auth.ts), OTHER)):
            with self.subTest(preset=preset, rid=rid):
                with self.assertRaises(ValueError):
                    peerbind.decision_record(confirmed, record_id=rid, preset=preset,
                                             cfg=self.cfg, state_dir=self.state_dir)

    def test_the_reserved_value_reruns_no_check(self):
        """Checks 7 and 8 are behind the reservation: what refuses them now
        cannot reach a reserved value."""
        chk, snap = self.pre()
        _rec, rcp = self.reserve(chk)
        doc, raw = statement()
        self.assertIsInstance(
            peerbind.bind_for_reservation(verified(doc, raw), view(doc), delegation=self.delegation,
                                          check7=refuses, check8=passes), peerbind.Demoted)
        reserved = peerbind.resume_reserved(rcp, snap, state_dir=self.state_dir)
        self.assertIsInstance(peerbind.authorise_checked(reserved, cfg=self.cfg),
                              peerbind.Authorised)

    def test_a_runtime_changed_since_the_reservation_is_stale(self):
        chk, snap = self.pre()
        _rec, rcp = self.reserve(chk)
        auth = peerbind.authorise_checked(
            peerbind.resume_reserved(rcp, snap, state_dir=self.state_dir), cfg=self.cfg)
        rt = self.dc.runtimes[0]
        renamed = dataclasses.replace(self.dc, runtimes=(dataclasses.replace(
            rt, runtime=f"amap.router@{rt.domains[1]}"),))
        cfg = dataclasses.replace(self.cfg, delegation=renamed)
        with self.assertRaises(peerbind.AuthorisationMismatch) as cm:
            peerbind.confirm(auth, cfg=cfg)
        self.assertEqual((cm.exception.kind, cm.exception.detail), ("stale", "runtime"))


class CommitTests(_Reserved):

    def test_a_retried_step_is_ours(self):
        chk, _snap = self.pre()
        first, rcp1 = self.reserve(chk)
        _second, rcp2 = self.reserve(chk)
        self.assertEqual(rcp2.notice_id, json.loads(first)["notice_id"])
        self.assertEqual(self.path(rcp1).read_bytes(), first)

    def test_another_candidate_is_a_collision_and_the_prior_is_untouched(self):
        chk, _snap = self.pre()
        first, rcp = self.reserve(chk)
        with self.assertRaises(peerbind.ReservationCollision) as cm:
            self.reserve(chk, record_id=OTHER)
        self.assertEqual(cm.exception.candidate_ref, RID)
        self.assertEqual(self.path(rcp).read_bytes(), first)

    def test_reopen_gives_the_same_receipt_fields(self):
        chk, _snap = self.pre()
        _rec, rcp = self.reserve(chk)
        again = peerbind.reopen_reservation(self.state_dir, rcp.rt, rcp.idk, record_id=RID)
        self.assertEqual(dataclasses.astuple(again)[:-1], dataclasses.astuple(rcp)[:-1])

    def test_reopen_of_another_candidates_reservation_collides(self):
        chk, _snap = self.pre()
        _rec, rcp = self.reserve(chk)
        with self.assertRaises(peerbind.ReservationCollision):
            peerbind.reopen_reservation(self.state_dir, rcp.rt, rcp.idk, record_id=OTHER)

    def test_the_receipt_is_sealed_and_not_persisted(self):
        chk, _snap = self.pre()
        _rec, rcp = self.reserve(chk)
        self.assertIs(copy.copy(rcp), rcp)
        self.assertIs(copy.deepcopy(rcp), rcp)
        with self.assertRaises(TypeError):
            pickle.dumps(rcp)
        with self.assertRaises((TypeError, ValueError)):
            dataclasses.replace(rcp, notice_id="f" * 32)


class ForgeryTests(_Reserved):

    def members(self, raw, record_id=RID):
        text = "Please run the suite.\n"
        doc = json.loads(raw)
        rt, idk = peerbind.replay_keys(f"amap.router@{T1}", doc["id"])
        return {"v": 1, "state": "reserved", "rt": rt, "idk": idk,
                "runtime": f"amap.router@{T1}", "id": doc["id"], "ts": doc["ts"],
                "statement_sha256": hashlib.sha256(raw).hexdigest(),
                "body_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "attachment_sha256s": [], "key_id": KEY_ID, "notice_id": "e" * 32,
                "candidate_ref": record_id, "reserve_seq": 1}

    def test_a_fabricated_reservation_for_a_demoted_statement_gets_no_receipt(self):
        doc, raw = statement(**{"from": "planner@elsewhere.example"})
        m = self.members(raw)
        forged = json.dumps(dict(m, mac="0" * 64), sort_keys=True).encode()
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.commit_reservation(self.state_dir, m["rt"], m["idk"], forged, record_id=RID)
        self.assertEqual(cm.exception.reason, "mac")

    def test_a_decision_mac_never_verifies_a_reservation(self):
        _doc, raw = statement()
        m = self.members(raw)
        key = peerbind._decision_key(self.state_dir)
        crossed = json.dumps(dict(m, mac=peerbind._record_mac(m, key)), sort_keys=True).encode()
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.parse_reservation(crossed, key)
        self.assertEqual(cm.exception.reason, "mac")
        honest = json.dumps(dict(m, mac=peerbind._reservation_mac(m, key)),
                            sort_keys=True).encode()
        self.assertEqual(peerbind.parse_reservation(honest, key)["notice_id"], "e" * 32)

    def test_each_member_edited_on_disk_fails_the_mac(self):
        chk, _snap = self.pre()
        rec, rcp = self.reserve(chk)
        for member, value in (("runtime", "amap.router@x"), ("notice_id", "f" * 32),
                              ("candidate_ref", OTHER), ("ts", "2026-10-14T00:00:00Z"),
                              ("statement_sha256", "0" * 64), ("reserve_seq", 7)):
            with self.subTest(member=member):
                doc = json.loads(rec)
                doc[member] = value
                self.rewrite(self.path(rcp), json.dumps(doc, sort_keys=True).encode())
                with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
                    peerbind.reopen_reservation(self.state_dir, rcp.rt, rcp.idk, record_id=RID)
                self.assertEqual(cm.exception.reason, "mac")

    def test_a_snapshot_mismatch_is_refused(self):
        chk, snap = self.pre()
        _rec, rcp = self.reserve(chk)
        doc, raw = statement()
        cases = {
            "statement": peerbind.Snapshot(raw + b" ", snap.candidate),
            "body": peerbind.Snapshot(raw, view(doc, body=b"Something else.\n")),
            "attachments": peerbind.Snapshot(raw, view(doc, atts=[b"extra"])),
        }
        for why, bad in cases.items():
            with self.subTest(why=why):
                with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
                    peerbind.resume_reserved(rcp, bad, state_dir=self.state_dir)
                self.assertEqual(cm.exception.detail, why)

    def test_the_inode_replaced_after_the_receipt_is_refused(self):
        chk, snap = self.pre()
        rec, rcp = self.reserve(chk)
        # Hold the old file open while it is replaced: a filesystem may hand a
        # freed inode number straight back (ext4 does), and identical bytes on
        # the SAME number would be no replacement at all.
        held = os.open(self.path(rcp), os.O_RDONLY)
        self.addCleanup(os.close, held)
        self.rewrite(self.path(rcp), rec)            # identical bytes, a new inode
        self.assertNotEqual(os.stat(self.path(rcp)).st_ino, rcp.ino, "the inode did change")
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.resume_reserved(rcp, snap, state_dir=self.state_dir)
        self.assertEqual(cm.exception.reason, "replaced")

    def test_under_key_loss_the_reservation_reads_as_data_only(self):
        chk, _snap = self.pre()
        rec, _rcp = self.reserve(chk)
        doc = json.loads(rec)
        self.assertEqual(peerbind.parse_reservation(rec, None)["notice_id"], doc["notice_id"])
        doc["notice_id"] = "../x"
        with self.assertRaises(peerbind.RecoveryCorrupt) as cm:
            peerbind.parse_reservation(json.dumps(doc).encode(), None)
        self.assertEqual(cm.exception.reason, "grammar")


if __name__ == "__main__":
    unittest.main()
