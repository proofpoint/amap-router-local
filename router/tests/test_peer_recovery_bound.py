"""The bounded recovery walk: the not-done index (`peer-open/`) and when
recovery trusts it.

Per pass with a healthy index, recovery evaluates exactly the OPEN records
(not `done`, or `done` but its tree entry never removed), in `take_seq`
order, read through the index. Any damage the index validation can see
makes that pass a full walk BEFORE anything is evaluated. Damage it cannot
see (an open record with no marker) is caught by the full walk at start and
on the monotonic hourly backstop. `peerjournal._recovery_worklist` is the
one producer of the records a pass evaluates, so it is the surface pinned
here."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from unittest import mock

from router import peerjournal
from router.tests import test_peerevaluate as tpe

OWNER = tpe.OWNER


class _Bound(tpe._Eval):

    def setUp(self):
        super().setUp()
        peerjournal._RECOVERY.clear()
        self.addCleanup(peerjournal._RECOVERY.clear)
        self.clock = [1000.0]
        self._real_monotonic = peerjournal._monotonic
        p = mock.patch.object(peerjournal, "_monotonic", lambda: self.clock[0])
        p.start()
        self.addCleanup(p.stop)

    def meta(self):
        return peerjournal.read_meta(self.state_dir)

    def worklist(self):
        return [r["key"] for r in peerjournal._recovery_worklist(self.state_dir, self.meta())]

    def marker(self, key):
        return peerjournal.open_dir(self.state_dir, OWNER) / key

    def full_walk_done(self):
        """A first pass: the full walk the start requires."""
        return self.worklist()

    def close(self, key):
        """Mark a record closed (done, removed) through the one writer."""
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        return peerjournal.write_record(self.state_dir, dict(rec, state="done", removed=True,
                                                             done_ts="2026-10-13T12:00:00Z"))


class IndexWriteTests(_Bound):
    """W1/W2/W3: the marker is written in take's intent, before the record,
    and removed only once the record is durably closed."""

    def test_take_writes_the_marker_with_its_take_seq(self):
        key = self.take(self.raw())
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        self.assertTrue(self.marker(key).is_file(), "take wrote the marker")
        self.assertEqual(self.marker(key).read_text(), str(rec["take_seq"]))

    def test_the_marker_is_written_before_the_record_directory(self):
        seen = []
        real = peerjournal._mark_open

        def mark(state_dir, owner, key, seq):
            seen.append(peerjournal.record_dir(state_dir, owner, key).exists())
            return real(state_dir, owner, key, seq)
        with mock.patch.object(peerjournal, "_mark_open", mark):
            self.take(self.raw())
        self.assertEqual(seen, [False], "the record directory did not exist yet")

    def test_crash_point_1_before_the_marker_leaves_nothing(self):
        with mock.patch.object(peerjournal, "_mark_open", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.take(self.raw())
        d = peerjournal.open_dir(self.state_dir, OWNER)
        self.assertEqual(sorted(p.name for p in d.iterdir()) if d.is_dir() else [], [])
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_crash_point_2_marker_durable_no_record_is_removed_by_the_takes_cleanup(self):
        key = peerjournal.record_key(intake="candidates", gen="g1", owner=OWNER, entry_id="e1")
        real_mkdir = Path.mkdir
        seen = []

        def mkdir(p, *a, **k):
            if p.name == key:                     # only the record directory fails
                seen.append(self.marker(key).is_file())
                raise OSError(28, "no space")
            return real_mkdir(p, *a, **k)
        with mock.patch.object(Path, "mkdir", mkdir):
            with self.assertRaises(OSError):
                self.take(self.raw(), entry="e1")
        self.assertEqual(seen, [True], "the marker was durable when the record failed")
        self.assertFalse(self.marker(key).exists(), "the caught cleanup removed it")

    def test_crash_point_2_left_by_a_hard_crash_is_removed_by_reconcile(self):
        # A hard crash leaves the intent and the marker, and no record.
        key = peerjournal.record_key(intake="candidates", gen="g1", owner=OWNER, entry_id="e1")
        real_mkdir = Path.mkdir

        class Hard(BaseException):
            pass

        def mkdir(p, *a, **k):
            if p.name == key:
                raise Hard()
            return real_mkdir(p, *a, **k)
        with mock.patch.object(Path, "mkdir", mkdir):
            with self.assertRaises(Hard):
                self.take(self.raw(), entry="e1")
        self.assertTrue(self.marker(key).exists(), "the hard crash left the marker")
        self.assertEqual(self.meta()["pending_op"]["op"], "take")
        peerjournal.reconcile(self.state_dir)
        self.assertFalse(self.marker(key).exists(), "reconcile is its one owner")

    def test_crash_point_3_record_durable_bookkeeping_not_keeps_the_marker(self):
        class Hard(BaseException):
            pass
        real = peerjournal._apply
        with mock.patch.object(peerjournal, "_apply", side_effect=Hard()):
            with self.assertRaises(Hard):
                self.take(self.raw(), entry="e1")
        key = peerjournal.record_key(intake="candidates", gen="g1", owner=OWNER, entry_id="e1")
        self.assertTrue((peerjournal.record_dir(self.state_dir, OWNER, key)
                         / peerjournal.RECORD).is_file(), "the record is committed")
        peerjournal.reconcile(self.state_dir)
        self.assertTrue(self.marker(key).exists(), "a committed record keeps its marker")
        self.assertIn(key, self.worklist())
        del real

    def test_done_but_not_removed_keeps_its_marker(self):
        key = self.take(self.raw())
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        peerjournal.write_record(self.state_dir, dict(rec, state="done", removed=False))
        self.assertTrue(self.marker(key).exists())
        self.close(key)
        self.assertFalse(self.marker(key).exists(), "removed: closed, so it goes")

    def test_the_marker_goes_only_after_the_record_write(self):
        key = self.take(self.raw())
        rec = peerjournal.read_record(self.state_dir, OWNER, key)
        with mock.patch.object(peerjournal, "atomic_write", side_effect=OSError(5, "io")):
            with self.assertRaises(OSError):
                peerjournal.write_record(self.state_dir, dict(rec, state="done", removed=True))
        self.assertTrue(self.marker(key).exists(), "a failed close keeps the record indexed")

    def test_take_is_the_only_creator_of_a_record(self):
        src = Path(peerjournal.__file__).read_text(encoding="utf-8")
        self.assertEqual(src.count("_write_once(rdir, RECORD, data)"), 1)
        self.assertEqual(src.count(", RECORD, "), 1, "no other create of a record file")


class IndexedPassTests(_Bound):
    """W8/W9 and the two phases."""

    def test_the_first_pass_is_a_full_walk(self):
        a = self.take(self.raw(), entry="a")
        os.unlink(self.marker(a))
        self.assertEqual(self.worklist(), [a], "the start's full walk finds it")
        self.assertTrue(self.marker(a).exists(), "and rebuilds its marker")

    def test_the_bound_an_unmarked_record_waits_for_the_hourly_walk(self):
        a = self.take(self.raw(), entry="a")
        b = self.take(self.raw(), entry="b")
        self.full_walk_done()
        os.unlink(self.marker(b))                  # damage validation cannot see
        self.clock[0] += 60
        self.assertEqual(self.worklist(), [a], "an indexed pass reads only the index")
        self.clock[0] += peerjournal.FULL_WALK_S
        self.assertEqual(self.worklist(), [a, b], "the hourly full walk finds it")
        self.assertTrue(self.marker(b).exists(), "and repairs the index")

    def test_the_backstop_is_monotonic_whatever_wall_time_does(self):
        a = self.take(self.raw(), entry="a")
        b = self.take(self.raw(), entry="b")
        self.full_walk_done()
        os.unlink(self.marker(b))
        self.clock[0] += peerjournal.FULL_WALK_S
        with mock.patch("time.time", return_value=0.0):   # wall time stepped far back
            self.assertEqual(self.worklist(), [a, b])

    def test_an_indexed_pass_evaluates_the_open_set_in_take_seq_order(self):
        keys = [self.take(self.raw(), entry=e) for e in ("c", "a", "b")]
        self.close(keys[1])
        self.full_walk_done()
        self.clock[0] += 60
        want = sorted((peerjournal.read_record(self.state_dir, OWNER, k)["take_seq"], k)
                      for k in (keys[0], keys[2]))
        self.assertEqual(self.worklist(), [k for _s, k in want])

    def test_a_closed_records_marker_is_sound_and_unlinked_in_phase_2(self):
        a = self.take(self.raw(), entry="a")
        self.full_walk_done()
        # A close whose unlink did not happen (the close path's crash window).
        with mock.patch.object(peerjournal, "_unmark_open"):
            self.close(a)
        self.assertTrue(self.marker(a).exists())
        self.clock[0] += 60
        calls = []
        real = peerjournal._full_walk
        with mock.patch.object(peerjournal, "_full_walk",
                               lambda *a_, **k: calls.append(1) or real(*a_, **k)):
            self.assertEqual(self.worklist(), [])
        self.assertEqual(calls, [], "no fallback to a full walk")
        self.assertFalse(self.marker(a).exists(), "phase 2 unlinked it")


class DamageTests(_Bound):
    """Damage the validation sees: a full walk THIS pass, before any effect."""

    def setUp(self):
        super().setUp()
        self.a = self.take(self.raw(), entry="a")
        self.b = self.take(self.raw(), entry="b")
        self.full_walk_done()
        self.clock[0] += 60

    def assert_full_walk(self):
        calls = []
        real = peerjournal._full_walk
        with mock.patch.object(peerjournal, "_full_walk",
                               lambda *a_, **k: calls.append(1) or real(*a_, **k)):
            got = self.worklist()
        self.assertEqual(calls, [1], "a full walk this pass")
        self.assertEqual(sorted(got), sorted([self.a, self.b]), "every open record, once")
        self.assertEqual(len(got), len(set(got)))
        return got

    def test_a_marker_with_the_wrong_decimal(self):
        self.marker(self.a).write_text("999")
        self.assert_full_walk()
        rec = peerjournal.read_record(self.state_dir, OWNER, self.a)
        self.assertEqual(self.marker(self.a).read_text(), str(rec["take_seq"]), "rebuilt")

    def test_a_garbage_marker(self):
        self.marker(self.a).write_text("not a number")
        self.assert_full_walk()

    def test_a_marker_naming_an_absent_record(self):
        ghost = "f" * 64
        self.marker(ghost).write_text("7")
        self.assert_full_walk()
        self.assertFalse(self.marker(ghost).exists(), "the full walk removed it")

    def test_damage_found_after_a_sound_entry_evaluates_nothing_early(self):
        # Sorted listing: a sound marker first, then a damaged one.
        first, second = sorted([self.a, self.b])
        self.marker(second).write_text("x")
        seen = []
        real = peerjournal._full_walk

        def full(*a_, **k):
            seen.append("full")
            return real(*a_, **k)
        with mock.patch.object(peerjournal, "_full_walk", full):
            got = peerjournal._recovery_worklist(self.state_dir, self.meta())
        self.assertEqual(seen, ["full"])
        self.assertEqual([r["key"] for r in got],
                         [k for _s, k in sorted(
                             (peerjournal.read_record(self.state_dir, OWNER, k)["take_seq"], k)
                             for k in (self.a, self.b))], "take_seq order, each once")

    def test_a_missing_index_beside_records(self):
        shutil.rmtree(peerjournal.open_dir(self.state_dir, OWNER))
        self.assert_full_walk()
        self.assertTrue(self.marker(self.a).exists() and self.marker(self.b).exists())

    def test_an_unlistable_index(self):
        real = Path.iterdir
        od = peerjournal.open_dir(self.state_dir, OWNER)

        def iterdir(p):
            if Path(p) == od:
                raise PermissionError(13, "denied")
            return real(p)
        calls = []
        realf = peerjournal._full_walk
        with mock.patch.object(Path, "iterdir", iterdir), \
                mock.patch.object(peerjournal, "_full_walk",
                                  lambda *a_, **k: calls.append(1) or realf(*a_, **k)):
            with self.assertRaises(PermissionError):
                self.worklist()            # the full walk's rebuild cannot list it either
        self.assertEqual(calls, [1])
        self.assertTrue(peerjournal._RECOVERY[os.path.realpath(str(self.state_dir))]["required"],
                        "a failed walk establishes nothing: the next pass walks fully")


class FailedWalkTests(_Bound):
    """A failed full walk establishes nothing (Codex A3), each with a
    healthy companion."""

    def state(self):
        return peerjournal._RECOVERY[os.path.realpath(str(self.state_dir))]

    def test_an_interrupted_full_walk_keeps_the_schedule_and_every_marker(self):
        a = self.take(self.raw(), entry="a")
        b = self.take(self.raw(), entry="b")
        (peerjournal.record_dir(self.state_dir, OWNER, b) / peerjournal.RECORD).write_text("{")
        with self.assertRaises(ValueError):
            self.worklist()
        self.assertTrue(self.state()["required"])
        self.assertIsNone(self.state()["last_full"])
        self.assertTrue(self.marker(a).exists() and self.marker(b).exists(),
                        "no marker removed on a partial view")

    def test_the_healthy_companion_completes_and_trusts_the_index(self):
        self.take(self.raw(), entry="a")
        self.worklist()
        self.assertFalse(self.state()["required"])
        self.assertEqual(self.state()["last_full"], self.clock[0])

    def test_an_unremovable_stray_keeps_the_next_pass_full(self):
        a = self.take(self.raw(), entry="a")
        (peerjournal.open_dir(self.state_dir, OWNER) / ("e" * 64)).mkdir()
        self.assertEqual(self.worklist(), [a], "recovery still runs")
        self.assertTrue(self.state()["required"], "but the index is not trusted")


class UpgradeTests(_Bound):

    def test_a_journal_from_before_the_index_is_fully_marked_by_its_first_pass(self):
        a = self.take(self.raw(), entry="a")
        b = self.take(self.raw(), entry="b")
        shutil.rmtree(peerjournal.open_dir(self.state_dir, OWNER))   # a pre-change journal
        self.assertEqual(sorted(self.worklist()), sorted([a, b]))
        self.assertTrue(self.marker(a).exists() and self.marker(b).exists())
        self.clock[0] += 60
        calls = []
        real = peerjournal._full_walk
        with mock.patch.object(peerjournal, "_full_walk",
                               lambda *a_, **k: calls.append(1) or real(*a_, **k)):
            self.assertEqual(sorted(self.worklist()), sorted([a, b]))
        self.assertEqual(calls, [], "the next pass is indexed")


class RecoverUsesTheWorklistTests(_Bound):
    """`recover` evaluates exactly the worklist, minus the pass's `skip`."""

    def recover(self, skip=()):
        from router import peerclock
        clock = peerclock.advance(self.state_dir, tpe.NOW)
        return peerjournal.recover(self.cfg, None, delegation=self.lane, clock=clock,
                                   now=tpe.NOW, skip=skip, profile_factory=tpe.permissive)

    def test_it_visits_the_worklist_and_nothing_else(self):
        a = self.take(self.raw(), entry="a")
        self.take(self.raw(), entry="b")
        rec = peerjournal.read_record(self.state_dir, OWNER, a)
        with mock.patch.object(peerjournal, "_recovery_worklist", return_value=[rec]):
            got = self.recover()
        self.assertEqual(sum(got.values()), 1, got)

    def test_the_skip_set_is_kept(self):
        a = self.take(self.raw(), entry="a")
        rec = peerjournal.read_record(self.state_dir, OWNER, a)
        with mock.patch.object(peerjournal, "_recovery_worklist", return_value=[rec]):
            self.assertEqual(self.recover(skip={a}), {})


class ScheduleTests(_Bound):

    def state(self):
        return peerjournal._RECOVERY[os.path.realpath(str(self.state_dir))]

    def test_the_default_scheduler_clock_is_monotonic(self):
        # Unpatched, the scheduler reads the package's one monotonic source.
        import time
        from router import hoplink
        self.assertIs(hoplink._clock, time.monotonic)
        with mock.patch.object(hoplink, "_clock", return_value=12345.0):
            self.assertEqual(self._real_monotonic(), 12345.0)

    def test_a_failed_walk_after_a_good_one_distrusts_the_index_again(self):
        a = self.take(self.raw(), entry="a")
        b = self.take(self.raw(), entry="b")
        self.worklist()
        self.assertFalse(self.state()["required"])
        good = self.state()["last_full"]
        (peerjournal.record_dir(self.state_dir, OWNER, b) / peerjournal.RECORD).write_text("{")
        self.clock[0] += peerjournal.FULL_WALK_S
        with self.assertRaises(ValueError):
            self.worklist()
        self.assertTrue(self.state()["required"], "the next pass walks fully")
        self.assertEqual(self.state()["last_full"], good, "the schedule did not advance")
        del a

    def test_a_take_in_progress_keeps_its_marker_through_a_full_walk(self):
        key = peerjournal.record_key(intake="candidates", gen="g1", owner=OWNER, entry_id="e1")
        real_mkdir = Path.mkdir

        class Hard(BaseException):
            pass

        def mkdir(p, *a, **k):
            if p.name == key:
                raise Hard()
            return real_mkdir(p, *a, **k)
        with mock.patch.object(Path, "mkdir", mkdir):
            with self.assertRaises(Hard):
                self.take(self.raw(), entry="e1")
        self.assertEqual(self.meta()["pending_op"]["key"], key)
        self.worklist()                               # a full walk, the take still pending
        self.assertTrue(self.marker(key).exists(), "the take's own marker is left alone")
