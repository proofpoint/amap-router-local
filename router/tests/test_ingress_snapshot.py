"""Ingress snapshots: kept durably (0700 directory, 0600 files, every file and
the directory fsynced before the digests are returned), and verified against
the journalled digests with every defect failing closed under its own name."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import ingress
from router.tests.test_ingress_bundle import CAP, NID, enc, make

LID = "lid-a"
GEN = "0" * 32
LINK = "link-a"
KIND = "notice"


class SnapshotCase(unittest.TestCase):

    def setUp(self):
        # A permissive umask, so the modes are the writer's and never the
        # environment's.
        self.addCleanup(os.umask, os.umask(0o022))
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name)
        self.parsed = ingress.parse_bundle(enc(make(blobs=(b"hello", b"world"))), NID,
                                           attachment_cap=CAP)

    def tearDown(self):
        self._tmp.cleanup()

    def take(self, entry_id=NID, parsed=None):
        """A snapshot meant to be kept that raises is a FAILURE, not an error."""
        try:
            return ingress.take_snapshot(self.state, LID, GEN, KIND, LINK, entry_id,
                                         parsed or self.parsed)
        except Exception as e:  # noqa: BLE001
            self.fail(f"take_snapshot raised {e!r}")

    def verify(self, digests, entry_id=NID, cap=CAP):
        return ingress.verify_snapshot(self.state, LID, GEN, KIND, LINK, entry_id, digests,
                                       attachment_cap=cap)

    def kept(self, digests):
        """A snapshot meant to verify that is refused is a FAILURE."""
        try:
            return self.verify(digests)
        except ingress.SnapshotInvalid as e:
            self.fail(f"refused: {e}")

    @property
    def dir(self) -> Path:
        return ingress.snapshot_dir(self.state, LID, GEN, KIND,
                                    ingress.key_for(KIND, LINK, GEN, NID))

    def invalid(self, digests, what, **kw):
        with self.assertRaises(Exception) as cm:
            self.verify(digests, **kw)
        self.assertIsInstance(cm.exception, ingress.SnapshotInvalid)
        self.assertEqual(cm.exception.what, what, str(cm.exception))
        self.assertEqual(cm.exception.reason, f"snapshot_invalid:{what}")


class TakeTests(SnapshotCase):

    def test_round_trip_and_modes(self):
        d = self.take()
        self.assertEqual(stat.S_IMODE(os.lstat(self.dir).st_mode), 0o700)
        for name in os.listdir(self.dir):
            self.assertEqual(stat.S_IMODE(os.lstat(self.dir / name).st_mode), 0o600, name)
        got = self.kept(d)
        self.assertEqual(got["attachments"], [b"hello", b"world"])
        self.assertEqual(got["notice"], self.parsed["raw"]["notice"])
        self.assertEqual(got["hop"], self.parsed["raw"]["facts"])
        self.assertEqual(sorted(os.listdir(self.dir)),
                         ["att-0", "att-1", "hop", "id", "notice", "spool"])

    def test_a_part_without_bytes_keeps_no_file(self):
        parsed = ingress.parse_bundle(enc(make(clean=False)), NID, attachment_cap=CAP)
        d = self.take(parsed=parsed)
        self.assertEqual(d["attachments"], [None])
        self.assertNotIn("att-0", os.listdir(self.dir))
        self.assertEqual(self.kept(d)["attachments"], [None])

    def test_every_file_then_the_directory_then_its_parent_is_fsynced(self):
        synced = []
        real = os.fsync

        def spy(fd):
            st = os.fstat(fd)
            synced.append((st.st_dev, st.st_ino))
            return real(fd)

        with mock.patch("os.fsync", spy):
            self.take()
        ino = lambda p: (os.lstat(p).st_dev, os.lstat(p).st_ino)  # noqa: E731
        files = [ino(self.dir / n) for n in os.listdir(self.dir)]
        for f in files:
            self.assertIn(f, synced)
        last_file = max(synced.index(f) for f in files)
        self.assertIn(ino(self.dir), synced, "the snapshot directory is never fsynced")
        d_at = synced.index(ino(self.dir))
        self.assertGreater(d_at, last_file, "the directory fsync precedes a file's")
        parent_after = [i for i, x in enumerate(synced) if x == ino(self.dir.parent)]
        self.assertTrue(parent_after and parent_after[-1] > d_at,
                        "the parent is not fsynced after the snapshot directory")

    def test_an_uncommitted_leftover_is_replaced(self):
        self.dir.parent.mkdir(parents=True)
        self.dir.mkdir()
        (self.dir / "stray").write_bytes(b"x")
        d = self.take()
        self.assertNotIn("stray", os.listdir(self.dir))
        self.kept(d)

    def test_a_leftover_that_is_not_a_directory_is_refused(self):
        self.dir.parent.mkdir(parents=True)
        target = self.state / "elsewhere"
        target.mkdir()
        os.symlink(target, self.dir)
        with self.assertRaises(Exception) as cm:
            ingress.take_snapshot(self.state, LID, GEN, KIND, LINK, NID, self.parsed)
        self.assertIsInstance(cm.exception, ingress.SnapshotInvalid)
        self.assertEqual(cm.exception.what, "not_a_directory")
        self.assertTrue(target.is_dir(), "the symlink's target was removed")


class VerifyTests(SnapshotCase):

    def setUp(self):
        super().setUp()
        self.d = self.take()

    def test_malformed_digests(self):
        for bad in (None, {}, dict(self.d, extra=1), dict(self.d, notice="x"),
                    dict(self.d, attachments="x"), dict(self.d, attachments=[1])):
            with self.subTest(bad=bad):
                self.invalid(bad, "digests")

    def test_the_directory_absent(self):
        for name in os.listdir(self.dir):
            os.unlink(self.dir / name)
        os.rmdir(self.dir)
        self.invalid(self.d, "missing")

    def test_the_directory_a_symlink(self):
        moved = self.state / "moved"
        os.rename(self.dir, moved)
        os.symlink(moved, self.dir)
        self.invalid(self.d, "symlink")

    def test_the_directory_not_a_directory(self):
        for name in os.listdir(self.dir):
            os.unlink(self.dir / name)
        os.rmdir(self.dir)
        self.dir.write_bytes(b"")
        self.invalid(self.d, "not_a_directory")

    def test_the_directory_mode(self):
        os.chmod(self.dir, 0o750)
        self.invalid(self.d, "mode")

    def test_an_unexpected_member(self):
        (self.dir / "att-9").write_bytes(b"")
        self.invalid(self.d, "unexpected")

    def test_a_member_absent(self):
        os.unlink(self.dir / "att-1")
        self.invalid(self.d, "missing")

    def test_a_member_a_symlink(self):
        os.rename(self.dir / "spool", self.state / "spool")
        os.symlink(self.state / "spool", self.dir / "spool")
        self.invalid(self.d, "symlink")

    def test_a_member_not_regular(self):
        os.unlink(self.dir / "spool")
        os.mkfifo(self.dir / "spool", 0o600)
        self.invalid(self.d, "not_regular")

    def test_a_member_with_a_second_link(self):
        os.link(self.dir / "spool", self.state / "spool-link")
        self.invalid(self.d, "links")

    def test_a_member_mode(self):
        os.chmod(self.dir / "spool", 0o644)
        self.invalid(self.d, "mode")

    def test_a_member_over_its_cap(self):
        self.invalid(self.d, "over_cap", cap=4)

    def test_the_identity_of_another_entry(self):
        other = "1700000000-43"
        self.take(entry_id=other)
        odir = ingress.snapshot_dir(self.state, LID, GEN, KIND,
                                    ingress.key_for(KIND, LINK, GEN, other))
        os.unlink(self.dir / "id")
        os.rename(odir / "id", self.dir / "id")
        self.invalid(self.d, "identity")

    def test_a_hash_mismatch(self):
        p = self.dir / "att-0"
        p.write_bytes(b"hellO")
        self.invalid(self.d, "hash")


class EnumerationTests(SnapshotCase):

    def test_lists_entry_ids_from_each_directory_id(self):
        self.assertEqual(ingress.snapshots(self.state, LID, GEN, KIND), [])
        self.take()
        self.take(entry_id="1700000000-43")
        self.assertEqual(sorted(ingress.snapshots(self.state, LID, GEN, KIND)),
                         sorted([NID, "1700000000-43"]))

    def test_a_directory_that_does_not_match_its_name_raises(self):
        self.take()
        os.rename(self.dir, self.dir.parent / (("a" * 64) + ingress.SNAP_SUFFIX))
        with self.assertRaises(Exception) as cm:
            ingress.snapshots(self.state, LID, GEN, KIND)
        self.assertIsInstance(cm.exception, ingress.SnapshotInvalid)
        self.assertEqual(cm.exception.what, "identity")

    def test_a_directory_without_its_id_raises(self):
        self.take()
        os.unlink(self.dir / "id")
        with self.assertRaises(Exception) as cm:
            ingress.snapshots(self.state, LID, GEN, KIND)
        self.assertIsInstance(cm.exception, ingress.SnapshotInvalid)
        self.assertEqual(cm.exception.what, "missing")


if __name__ == "__main__":
    unittest.main()
