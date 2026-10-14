"""The candidate journal's store bookkeeping (`router/peerjournal.py`): init,
take, the take sequence and its vacant markers, record revisions, and the
startup reconciliation that detects a store it cannot show complete."""
import dataclasses
import errno
import hashlib
import json
import os
import shutil
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from router import peerbind, peerclock, peerjournal
from router.tests import helpers
from router.tests.test_peerbind import _Base, passes, statement, verified, view

NOW = datetime(2026, 10, 9, 15, 0, 0, tzinfo=timezone.utc)
OWNER = "lid-a"


class _Store(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=())

    def take(self, entry, raw=b'{"x": 1}'):
        return peerjournal.take(self.state_dir, OWNER, intake="candidates", gen="g1",
                                entry_id=entry, raw=raw, now=NOW)

    def meta(self):
        return peerjournal.read_meta(self.state_dir)


class InitTests(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def test_init_opens_admission_with_no_floor(self):
        clock = peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=())
        self.assertEqual((clock.admission, clock.floor), ("open", None))
        self.assertEqual(peerclock.read(self.state_dir).store_token, clock.store_token)

    def test_init_refuses_over_an_existing_store(self):
        peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=())
        with self.assertRaises(peerjournal.StoreRefused):
            peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=())

    def test_init_refuses_over_a_surviving_tombstone(self):
        hop = self.tmp / "hop"
        (hop / ".disposed" / ".control").mkdir(parents=True)
        (hop / ".disposed" / ".control" / "t1").write_text("{}")
        with self.assertRaises(peerjournal.StoreRefused):
            peerjournal.init_store(self.state_dir, NOW, hop_root=hop, peer_roots=())
        self.assertFalse((self.state_dir / peerclock.CLOCK_FILE).exists())
        peerjournal.init_store(self.state_dir, NOW, hop_root=hop, peer_roots=(),
                               acknowledge_surviving="wiped deliberately, ticket 12")

    def test_init_refuses_over_a_signed_peer_notice(self):
        root = self.tmp / "peer"
        (root / "notices").mkdir(parents=True)
        signed = {"kind": "peer", "message": {"id": "A" * 23}}
        local = {"kind": "peer", "message": {"id": "0" * 32}}
        (root / "notices" / "notice-local.json").write_text(json.dumps(local))
        other = self.tmp / "other-state"
        other.mkdir()
        peerjournal.init_store(other, NOW, hop_root=None, peer_roots=[root])   # local only: fine
        (root / "notices" / "notice-signed.json").write_text(json.dumps(signed))
        with self.assertRaises(peerjournal.StoreRefused):
            peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=[root])


class TakeTests(_Store):

    def test_take_writes_a_pending_record_and_counts_it(self):
        key, seq = self.take("e1")
        self.assertEqual(seq, 1)
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        self.assertEqual((rec["state"], rec["rev"], rec["take_seq"]), ("pending", 1, 1))
        snap = peerjournal.record_dir(self.state_dir, OWNER, key) / "snapshot" / "candidate.json"
        self.assertEqual(snap.read_bytes(), b'{"x": 1}')
        entry = self.meta()["roots"][OWNER]
        self.assertEqual((entry["live"], entry["high_seq"], entry["rev_total"]), (2, 1, 1))
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_the_same_delivery_is_one_record(self):
        first = self.take("e1")
        self.assertEqual(self.take("e1"), first)
        self.assertEqual(self.meta()["take_seq"], 1)

    def test_seqs_strictly_increase(self):
        self.assertEqual([self.take(f"e{i}")[1] for i in range(3)], [1, 2, 3])

    def test_write_record_raises_the_revision(self):
        key, _ = self.take("e1")
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        out = peerjournal.write_record(self.state_dir, dict(rec, state="done"))
        self.assertEqual(out["rev"], 2)
        self.assertEqual(peerjournal.read_record(self.state_dir, OWNER, key)["rev"], 2)
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])


class ContributionTests(unittest.TestCase):
    """End to end, a rolled-back record is caught twice over (its bytes carry
    `rev`, and `rev_total` is compared separately), so only the function
    itself can show that the revision is part of a contribution."""

    def test_the_revision_is_part_of_the_contribution(self):
        self.assertNotEqual(peerjournal.contribution("k/record.json", 1, b"x"),
                            peerjournal.contribution("k/record.json", 2, b"x"))

    def test_the_encoding_is_length_prefixed(self):
        self.assertNotEqual(peerjournal.contribution("ab", 1, b""),
                            peerjournal.contribution("a", 11, b""))


class SynchronousTakeFailureTests(_Store):
    """A take that fails after its seq is allocated: the directory goes, the
    seq is VACANT, and the frontier passes it."""

    def test_a_failed_snapshot_write_leaves_a_vacant_seq(self):
        real = peerjournal._write_once

        def fail_snapshot(d, name, data):
            if name == peerjournal.SNAPSHOT_CANDIDATE:
                raise OSError(errno.ENOSPC, "no space")
            return real(d, name, data)

        with mock.patch.object(peerjournal, "_write_once", fail_snapshot):
            with self.assertRaises(OSError):
                self.take("e1")
        key = peerjournal.record_key(intake="candidates", gen="g1", owner=OWNER, entry_id="e1")
        self.assertFalse(peerjournal.record_dir(self.state_dir, OWNER, key).exists())
        self.assertIsNone(self.meta()["pending_op"])
        key2, seq2 = self.take("e2")
        self.assertEqual(seq2, 2)
        rec = peerjournal.read_record(self.state_dir, OWNER, key2)
        peerjournal.write_record(self.state_dir, dict(rec, state="done"))
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), 2)
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_a_failed_cleanup_blocks_every_later_mutation(self):
        real = peerjournal._write_once

        def fail_snapshot(d, name, data):
            if name == peerjournal.SNAPSHOT_CANDIDATE:
                raise OSError(errno.EIO, "io")
            return real(d, name, data)

        with mock.patch.object(peerjournal, "_write_once", fail_snapshot), \
                mock.patch.object(peerjournal, "_mark_vacant", side_effect=OSError(errno.EIO, "io")):
            with self.assertRaises(peerjournal.StoreBlocked):
                self.take("e1")
        self.assertIsNotNone(self.meta()["pending_op"])
        with self.assertRaises(peerjournal.StoreBlocked):
            self.take("e2")
        self.assertEqual(self.meta()["take_seq"], 1, "no N+1 is taken while blocked")
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])
        self.assertIn(1, peerjournal._vacant(self.state_dir))
        self.assertEqual(self.take("e2")[1], 2)


class CrashRepairTests(_Store):
    """Only the top seq can lack a record after a crash: it is marked
    VACANT at startup, and the frontier passes it."""

    def _crash_after(self, stage):
        """Simulate a crash at `stage` of a take of e9 (seq 2)."""
        meta = self.meta()
        key = peerjournal.record_key(intake="candidates", gen="g1", owner=OWNER, entry_id="e9")
        meta["take_seq"] += 1
        meta["pending_op"] = {"op": "take", "owner": OWNER, "key": key, "seq": meta["take_seq"]}
        peerjournal._write_meta(self.state_dir, meta)
        rdir = peerjournal.record_dir(self.state_dir, OWNER, key)
        if stage in ("dir", "snapshot"):
            (rdir / "snapshot").mkdir(parents=True)
        if stage == "snapshot":
            (rdir / "snapshot" / "candidate.json").write_bytes(b"{}")
        return rdir

    def _repairs(self, stage):
        key1, _ = self.take("base")
        rec = peerjournal.read_record(self.state_dir, OWNER, key1)
        peerjournal.write_record(self.state_dir, dict(rec, state="done"))
        rdir = self._crash_after(stage)
        top = self.meta()["take_seq"]
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])
        self.assertFalse(rdir.exists(), "an incomplete directory is removed")
        self.assertIn(top, peerjournal._vacant(self.state_dir))
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), top)
        self.assertEqual(self.take("e9")[1], top + 1, "re-taken under a fresh seq")
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_seq_written_but_no_directory(self):
        self._repairs("seq")

    def test_directory_created_but_no_record(self):
        self._repairs("dir")

    def test_snapshot_written_but_no_record(self):
        self._repairs("snapshot")


class CompletenessTests(_Store):
    """A store that cannot be shown complete is reported; an untouched one
    verifies clean."""

    def setUp(self):
        super().setUp()
        self.k1, _ = self.take("e1")
        self.k2, _ = self.take("e2")
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def path(self, key):
        return peerjournal.record_dir(self.state_dir, OWNER, key) / "record.json"

    def test_an_untouched_store_is_complete(self):
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_a_record_rolled_back_in_place_is_detected(self):
        earlier = self.path(self.k1).read_bytes()
        rec = peerjournal.read_record(self.state_dir, OWNER, self.k1)
        peerjournal.write_record(self.state_dir, dict(rec, state="done"))
        self.path(self.k1).write_bytes(earlier)
        self.assertTrue(peerjournal.reconcile(self.state_dir))

    def test_a_record_rolled_back_with_a_sibling_is_detected(self):
        e1, e2 = self.path(self.k1).read_bytes(), self.path(self.k2).read_bytes()
        for k in (self.k1, self.k2):
            rec = peerjournal.read_record(self.state_dir, OWNER, k)
            peerjournal.write_record(self.state_dir, dict(rec, state="done"))
        self.path(self.k1).write_bytes(e1)
        self.path(self.k2).write_bytes(e2)
        self.assertTrue(peerjournal.reconcile(self.state_dir))

    def test_a_deleted_record_is_detected(self):
        shutil.rmtree(self.path(self.k1).parent)
        problems = peerjournal.reconcile(self.state_dir)
        self.assertTrue(any("does not match" in p for p in problems), problems)

    def test_a_deleted_root_is_detected(self):
        shutil.rmtree(peerjournal.journal_root(self.state_dir, OWNER))
        self.assertIn(f"loss: journal root {OWNER} is missing", peerjournal.reconcile(self.state_dir))

    def test_an_unrecorded_root_is_detected(self):
        (self.state_dir / "lid-b" / peerjournal.JOURNAL_DIR).mkdir(parents=True)
        self.assertIn("behind: journal root lid-b is not recorded",
                      peerjournal.reconcile(self.state_dir))

    def test_a_missing_seq_below_the_top_is_loss(self):
        self.take("e3")
        shutil.rmtree(self.path(self.k2).parent)
        problems = peerjournal.reconcile(self.state_dir)
        self.assertIn("loss: take_seq 2 has no record and is not vacant", problems)


class _Replay(_Base):
    """A store plus a decision key and a real pre-reservation value."""

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=())
        peerbind.ensure_decision_key(self.state_dir)

    def candidate(self, entry, **over):
        doc, raw = statement(**over)
        key, _ = peerjournal.take(self.state_dir, OWNER, intake="candidates", gen="g1",
                                  entry_id=entry, raw=raw, now=NOW)
        chk = peerbind.bind_for_reservation(verified(doc, raw), view(doc),
                                            delegation=self.delegation, check7=passes,
                                            check8=passes)
        return key, chk, hashlib.sha256(raw).hexdigest()

    def record(self, key):
        return peerjournal.read_record(self.state_dir, OWNER, key)

    def reserve(self, key, chk):
        return peerjournal.reserve(self.state_dir, chk, record=self.record(key))


class ReplayTests(_Replay):

    def test_reserve_files_the_reservation_its_digest_and_the_record(self):
        key, chk, sha = self.candidate("e1")
        rcp, rec = self.reserve(key, chk)
        self.assertEqual((rec["state"], rec["replay_ref"]), ("reserved", f"{rcp.rt}/{rcp.idk}"))
        self.assertEqual(peerjournal.known(self.state_dir, sha), (rcp.rt, rcp.idk))
        meta = peerjournal.read_meta(self.state_dir)
        self.assertEqual((meta["replay"]["live"], meta["replay"]["high_reserve_seq"]), (1, 1))
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_a_collision_leaves_every_file_as_it_was(self):
        key1, chk1, _ = self.candidate("e1")
        rcp, _ = self.reserve(key1, chk1)
        path = self.state_dir / "peer-replay" / rcp.rt / (rcp.idk + ".json")
        before = path.read_bytes()
        key2, chk2, _ = self.candidate("e2")
        with self.assertRaises(peerbind.ReservationCollision):
            self.reserve(key2, chk2)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.record(key2)["state"], "pending")
        self.assertIsNone(peerjournal.read_meta(self.state_dir)["pending_op"])
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_done_is_a_marker_and_idempotent(self):
        key, chk, _ = self.candidate("e1")
        rcp, _ = self.reserve(key, chk)
        res = self.state_dir / "peer-replay" / rcp.rt / (rcp.idk + ".json")
        before = res.read_bytes()
        peerjournal.mark_done(self.state_dir, rcp.rt, rcp.idk, disposition="placed", now=NOW)
        peerjournal.mark_done(self.state_dir, rcp.rt, rcp.idk, disposition="placed", now=NOW)
        with self.assertRaises(peerbind.LinkConflict):
            peerjournal.mark_done(self.state_dir, rcp.rt, rcp.idk, disposition="refused", now=NOW)
        self.assertEqual(res.read_bytes(), before, "the reservation is never rewritten")
        self.assertEqual(peerjournal.done_marker(self.state_dir, rcp.rt, rcp.idk)["disposition"],
                         "placed")
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])


class DiscoveryTests(_Replay):

    def test_found_through_the_digest_index(self):
        key, chk, sha = self.candidate("e1")
        rcp, _ = self.reserve(key, chk)
        self.assertEqual(peerjournal.discover(self.state_dir, key, sha), (rcp.rt, rcp.idk))

    def test_found_by_the_scan_when_the_digest_entry_is_missing(self):
        key, chk, sha = self.candidate("e1")
        rcp, _ = self.reserve(key, chk)
        (self.state_dir / "peer-replay" / "digests" / sha).unlink()
        self.assertEqual(peerjournal.discover(self.state_dir, key, sha), (rcp.rt, rcp.idk))
        self.assertEqual(peerjournal.repair_digests(self.state_dir), 1)
        self.assertEqual(peerjournal.known(self.state_dir, sha), (rcp.rt, rcp.idk))
        self.assertEqual(peerjournal.repair_digests(self.state_dir), 0)

    def test_another_records_reservation_is_not_discovered(self):
        key, chk, sha = self.candidate("e1")
        self.reserve(key, chk)
        self.assertIsNone(peerjournal.discover(self.state_dir, "c" * 64, sha))


class ReplayCompletenessTests(_Replay):

    def setUp(self):
        super().setUp()
        key, chk, _ = self.candidate("e1")
        self.rcp, _ = self.reserve(key, chk)
        peerjournal.mark_done(self.state_dir, self.rcp.rt, self.rcp.idk, disposition="placed",
                              now=NOW)
        self.dir = self.state_dir / "peer-replay" / self.rcp.rt
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_a_removed_done_marker_is_detected(self):
        (self.dir / (self.rcp.idk + ".done")).unlink()
        self.assertIn("loss: replay store: content does not match its bookkeeping",
                      peerjournal.reconcile(self.state_dir))

    def test_a_deleted_reservation_is_detected(self):
        (self.dir / (self.rcp.idk + ".json")).unlink()
        self.assertIn("loss: replay store: content does not match its bookkeeping",
                      peerjournal.reconcile(self.state_dir))

    def test_a_crash_before_the_bookkeeping_rolls_forward(self):
        meta = peerjournal.read_meta(self.state_dir)
        meta["replay"].update(live=0, content_sum="0", high_reserve_seq=0)
        meta["pending_op"] = {"op": "reserve", "owner": None, "rt": self.rcp.rt,
                              "idk": self.rcp.idk, "seq": 1}
        peerjournal._write_meta(self.state_dir, meta)
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])


class InboundConfigTests(helpers.RouterTestCase):
    """`delegation.inbound`, `windows` and `retention` at load."""

    def doc(self, **over):
        from router.tests import test_peerlane as tp
        return tp.DelegationConfigTests.doc(self, **over)

    def load(self, **over):
        from router import config as config_mod
        return config_mod.load_obj(self.doc(**over)).delegation

    def refused(self, phrase, **over):
        from router import config as config_mod
        with self.assertRaises(config_mod.ConfigError) as cm:
            self.load(**over)
        self.assertIn(phrase, str(cm.exception))

    def test_absent_means_off_and_the_fleet_window(self):
        d = self.load()
        self.assertEqual((d.inbound, d.window_p, d.window_f, d.retention_sweep),
                         (False, 3600, 300, False))

    def test_inbound_true_is_refused_in_this_build(self):
        self.assertFalse(self.load(inbound=False).inbound)
        self.refused("inbound peer intake is not available in this build", inbound=True)
        from router import config as config_mod
        with mock.patch.object(config_mod, "INBOUND_AVAILABLE", True):
            self.assertTrue(self.load(inbound=True).inbound)

    def test_inbound_must_be_a_boolean(self):
        for bad in (1, "true", None, {}):
            with self.subTest(bad=bad):
                self.refused("delegation.inbound", inbound=bad)

    def test_windows_within_the_profiles_bounds(self):
        d = self.load(windows={"p": 300, "f": 900})
        self.assertEqual((d.window_p, d.window_f), (300, 900))
        for bad in ({"p": 299, "f": 300}, {"p": 86401, "f": 300}, {"p": 3600, "f": 901},
                    {"p": 3600}, {"p": 3600, "f": 300, "x": 1}, {"p": 3600.0, "f": 300},
                    {"p": True, "f": 300}):
            with self.subTest(bad=bad):
                self.refused("delegation.windows", windows=bad)

    def test_a_peer_store_name_is_never_an_instance(self):
        """A reset of an instance named after a peer store would clear it."""
        from router import config as config_mod
        for name in ("peer-replay", "Peer-Clock.json", "peer-vacant",
                     "peer-decision.key"):
            with self.subTest(name=name):
                doc = self.doc()
                doc["instances"] = {name: doc["instances"]["alice"]}
                with self.assertRaises(config_mod.ConfigError) as cm:
                    config_mod.load_obj(doc)
                self.assertIn("state_dir", str(cm.exception))
                self.assertIn(repr(name), str(cm.exception))

    def test_the_sweep_is_refused_without_a_frontier(self):
        self.assertFalse(self.load(retention={"sweep": False}).retention_sweep)
        self.refused("settled-through frontier", retention={"sweep": True})
        self.state_dir.mkdir(parents=True, exist_ok=True)
        peerjournal.init_store(self.state_dir, NOW, hop_root=None, peer_roots=())
        self.assertTrue(self.load(retention={"sweep": True}).retention_sweep)


class StartupTests(_Replay):
    """`startup`: never opens admission; closes it when the clock file is
    older than the stores; raises the floor when the stores lost something
    with H intact."""

    def clock_bytes(self):
        return (self.state_dir / peerclock.CLOCK_FILE).read_bytes()

    def test_a_clean_store_stays_open_and_advances_h(self):
        later = NOW.replace(hour=16)
        rep = peerjournal.startup(self.state_dir, later)
        self.assertEqual((rep["admission"], rep["why"], rep["problems"]), ("open", None, []))
        self.assertEqual(peerclock.read(self.state_dir).H, later)

    def test_a_wiped_state_dir_stays_closed_and_writes_nothing(self):
        empty = self.tmp / "wiped"
        empty.mkdir()
        rep = peerjournal.startup(empty, NOW)
        self.assertEqual((rep["admission"], rep["why"]), ("closed", "uninitialised"))
        self.assertEqual(list(empty.iterdir()), [])

    def test_a_clock_restored_alone_closes_admission(self):
        """An older peer-clock.json restored over untouched stores."""
        older = self.clock_bytes()
        key, chk, _ = self.candidate("e1")
        self.reserve(key, chk)
        (self.state_dir / peerclock.CLOCK_FILE).write_bytes(older)
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((rep["admission"], rep["why"]), ("closed", "clock_behind_stores"))
        self.assertEqual(peerclock.read(self.state_dir).admission, "closed", "persisted")

    def test_a_clock_older_than_one_record_rewrite_closes(self):
        """The root was already recorded: only that root is ahead."""
        key, _chk, _ = self.candidate("e1")
        older = self.clock_bytes()
        peerjournal.write_record(self.state_dir, dict(self.record(key), state="done"))
        (self.state_dir / peerclock.CLOCK_FILE).write_bytes(older)
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((rep["admission"], rep["why"]), ("closed", "clock_behind_stores"))
        self.assertEqual([p.split(":")[0] for p in rep["problems"]], ["behind"])

    def test_a_clock_older_than_one_done_marker_closes(self):
        """Only the replay store is ahead."""
        key, chk, _ = self.candidate("e1")
        rcp, _rec = self.reserve(key, chk)
        older = self.clock_bytes()
        peerjournal.mark_done(self.state_dir, rcp.rt, rcp.idk, disposition="placed", now=NOW)
        (self.state_dir / peerclock.CLOCK_FILE).write_bytes(older)
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((rep["admission"], rep["why"]), ("closed", "clock_behind_stores"))
        self.assertEqual(rep["problems"],
                         ["behind: replay store: content does not match its bookkeeping"])

    def test_a_lost_record_with_h_intact_raises_the_floor(self):
        key, chk, _ = self.candidate("e1")
        self.candidate("e2")
        shutil.rmtree(peerjournal.record_dir(self.state_dir, OWNER, key))
        rep = peerjournal.startup(self.state_dir, NOW)
        clock = peerclock.read(self.state_dir)
        self.assertEqual((rep["admission"], rep["why"]), ("open", "store_loss"))
        self.assertEqual(clock.floor, NOW + timedelta(seconds=clock.fmax + 1))

    def test_a_missing_clock_over_a_store_is_untrusted(self):
        (self.state_dir / peerclock.CLOCK_FILE).unlink()
        rep = peerjournal.startup(self.state_dir, NOW)
        self.assertEqual((rep["admission"], rep["why"]), ("closed", "clock_untrusted"))

    def test_digests_are_repaired_at_startup(self):
        key, chk, sha = self.candidate("e1")
        self.reserve(key, chk)
        (self.state_dir / "peer-replay" / "digests" / sha).unlink()
        self.assertEqual(peerjournal.startup(self.state_dir, NOW)["digests_repaired"], 1)
        self.assertIsNotNone(peerjournal.known(self.state_dir, sha))

    def test_a_bound_b_and_a_rebuild_reopen_after_a_clock_rollback(self):
        older = self.clock_bytes()
        key, chk, _ = self.candidate("e1")
        self.reserve(key, chk)
        (self.state_dir / peerclock.CLOCK_FILE).write_bytes(older)
        peerjournal.startup(self.state_dir, NOW)
        with self.assertRaises(peerjournal.StoreRefused):
            peerjournal.rebuild_meta(self.state_dir)
        b = NOW + timedelta(minutes=5)
        peerclock.record_bound(self.state_dir, NOW + timedelta(hours=1), at=b,
                               evidence="hub log line 4411", not_from_wall_clock=False,
                               observed=[(NOW, "first_seen_ts")])
        peerjournal.rebuild_meta(self.state_dir)
        rep = peerjournal.startup(self.state_dir, NOW + timedelta(hours=1))
        self.assertEqual((rep["admission"], rep["why"], rep["problems"]), ("open", None, []))


class StatusTests(_Replay):

    def test_holds_and_the_frontier_are_shown_with_their_age(self):
        key, _chk, _ = self.candidate("e1")
        peerjournal.set_hold(self.state_dir, self.record(key), "hook_absent", "check8", NOW)
        doc = peerjournal.status_doc(self.state_dir, NOW + timedelta(seconds=90))
        self.assertEqual(doc["holds"], [{"key": key, "take_seq": 1, "state": "pending",
                                         "reason": "hook_absent", "detail": "check8",
                                         "age_s": 90}])
        self.assertEqual((doc["admission"], doc["take_seq"], doc["settled_through"],
                          doc["warnings"]), ("open", 1, 0, []))

    def test_a_clock_behind_h_is_a_warning_never_a_hold(self):
        peerclock.advance(self.state_dir, NOW + timedelta(hours=1))
        doc = peerjournal.status_doc(self.state_dir, NOW)
        self.assertEqual((doc["admission"], doc["warnings"]), ("open", ["clock_behind_h"]))

    def test_bound_b_is_shown_with_its_evidence_cut(self):
        peerclock.record_bound(self.state_dir, NOW + timedelta(hours=2), at=NOW + timedelta(hours=1),
                               evidence="x" * 200, not_from_wall_clock=False, observed=())
        doc = peerjournal.status_doc(self.state_dir, NOW + timedelta(hours=2))
        self.assertEqual(doc["bound_b"]["evidence"], "x" * 80)
        self.assertTrue(doc["bound_b"]["by"].startswith("uid="))

    def test_an_uninitialised_store_is_shown_closed(self):
        empty = self.tmp / "wiped"
        empty.mkdir()
        self.assertEqual(peerjournal.status_doc(empty, NOW),
                         {"admission": "closed", "why": "uninitialised"})

    def test_the_tracker_emits_the_section_only_when_recorded(self):
        from router.status import StatusTracker
        t = StatusTracker(interval_s=5.0)
        self.assertNotIn("peer_store", t.to_doc())
        t.record_peer_store({"admission": "open"})
        doc = t.to_doc()
        self.assertEqual(doc["peer_store"], {"admission": "open"})


class ServiceStartupTests(_Replay):

    def test_no_delegation_runs_nothing(self):
        from router import service
        cfg = dataclasses.replace(self.cfg, delegation=None)
        self.assertIsNone(service.peer_startup(cfg))
        self.assertNotIn(str(self.state_dir), service.PEER_STARTUP)

    def test_the_report_is_recorded_for_status(self):
        from router import service
        self.addCleanup(service.PEER_STARTUP.clear)
        cfg = dataclasses.replace(self.cfg, state_dir=self.state_dir)
        rep = service.peer_startup(cfg)
        self.assertEqual(service.PEER_STARTUP[str(self.state_dir)], rep)
        self.assertEqual(rep["admission"], "open")


if __name__ == "__main__":
    unittest.main()
