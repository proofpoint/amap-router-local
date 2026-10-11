"""`util.atomic_write` and `util.fsync_dir`: the barriers themselves.

Asserted at the real `os.fsync`/`os.replace` boundary, with the descriptor's
target named through `/proc/self/fd`, because the defect these pin was
invisible above it: every write "succeeded" and no fsync ever happened.
"""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import util


def _target(fd):
    kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
    return kind, os.readlink(f"/proc/self/fd/{fd}")


@unittest.skipUnless(os.path.isdir("/proc/self/fd"), "needs /proc/self/fd")
class AtomicWriteBarrierTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(os.path.realpath(self._tmp.name))
        self.dest = self.root / "d" / "f.json"
        self.dest.parent.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, fail=None, fail_replace=False):
        events = []
        real_fsync, real_replace = os.fsync, os.replace

        def fsync(fd):
            t = _target(fd)
            if fail is not None and fail(t):
                raise OSError(5, "injected fsync failure")
            events.append(("fsync",) + t)
            return real_fsync(fd)

        def replace(src, dst, *a, **k):
            if fail_replace:
                raise OSError(18, "injected rename failure")
            events.append(("replace", str(dst)))
            return real_replace(src, dst, *a, **k)

        with mock.patch("router.util.os.fsync", fsync), \
                mock.patch("router.util.os.replace", replace):
            util.atomic_write(self.dest, b"new")
        return events

    def _leftovers(self):
        return sorted(p.name for p in self.dest.parent.iterdir() if p.name != "f.json")

    def test_file_fsync_then_rename_then_directory_fsync(self):
        """On the commit before this test there was no fsync at all."""
        events = self._run()
        kinds = [(e[0], e[1] if e[0] == "fsync" else None) for e in events]
        # The leading dir fsync is the existing parent's (`_mkdir_durable`).
        self.assertEqual(kinds, [("fsync", "dir"), ("fsync", "file"),
                                 ("replace", None), ("fsync", "dir")])
        self.assertEqual(events[0][2], str(self.root))
        self.assertTrue(os.path.basename(events[1][2]).startswith("f.json."))
        self.assertEqual(events[3][2], str(self.dest.parent))
        self.assertEqual(self.dest.read_bytes(), b"new")

    def test_a_failed_file_fsync_leaves_the_destination_untouched(self):
        self.dest.write_bytes(b"old")
        with self.assertRaises(OSError):
            self._run(fail=lambda t: t[0] == "file")
        self.assertEqual(self.dest.read_bytes(), b"old")
        self.assertEqual(self._leftovers(), [], "the temp file was left behind")

    def test_a_failed_rename_leaves_the_destination_untouched(self):
        self.dest.write_bytes(b"old")
        with self.assertRaises(OSError):
            self._run(fail_replace=True)
        self.assertEqual(self.dest.read_bytes(), b"old")
        self.assertEqual(self._leftovers(), [])

    def test_a_failed_directory_fsync_raises_although_the_rename_happened(self):
        """Success is never reported for a write that is not yet durable."""
        self.dest.write_bytes(b"old")
        with self.assertRaises(OSError):
            self._run(fail=lambda t: t == ("dir", str(self.dest.parent)))
        self.assertEqual(self.dest.read_bytes(), b"new")
        self.assertEqual(self._leftovers(), [])

    def test_directories_it_creates_are_made_durable_in_their_parents(self):
        self.dest = self.root / "a" / "b" / "f.json"
        events = self._run()
        dirs = [e[2] for e in events if e[0] == "fsync" and e[1] == "dir"]
        self.assertIn(str(self.root), dirs)            # for a/
        self.assertIn(str(self.root / "a"), dirs)      # for a/b/
        self.assertIn(str(self.root / "a" / "b"), dirs)  # for the rename
        self.assertEqual(self.dest.read_bytes(), b"new")

    def test_the_parent_is_fsynced_even_when_the_directory_exists(self):
        """An earlier creator whose fsync failed leaves a directory that
        exists but may not be durable."""
        events = self._run()
        dirs = [e[2] for e in events if e[0] == "fsync" and e[1] == "dir"]
        self.assertIn(str(self.root), dirs)  # d/ existed before the write
        self.assertIn(str(self.dest.parent), dirs)

    def test_with_a_durable_root_a_failed_ancestor_barrier_is_repaired(self):
        """Creating root/a/b fails at the FIRST parent fsync and leaves both
        directories. The retry re-establishes the whole chain from the root,
        though it creates nothing."""
        self.dest = self.root / "a" / "b" / "f.json"
        state = {"failed": False}

        def fail(t):
            if t == ("dir", str(self.root)) and not state["failed"]:
                state["failed"] = True
                return True
            return False

        events = []
        real_fsync = os.fsync

        def fsync(fd):
            t = _target(fd)
            if fail(t):
                raise OSError(5, "injected")
            events.append(t)
            return real_fsync(fd)

        with mock.patch("router.util.os.fsync", fsync):
            with self.assertRaises(OSError):
                util.atomic_write(self.dest, b"new", durable_root=self.root)
            self.assertTrue((self.root / "a" / "b").is_dir())
            events.clear()
            util.atomic_write(self.dest, b"new", durable_root=self.root)
        dirs = [p for k, p in events if k == "dir"]
        for d in (self.root, self.root / "a", self.root / "a" / "b"):
            self.assertIn(str(d), dirs)
        self.assertEqual(self.dest.read_bytes(), b"new")

    def test_a_durable_root_must_contain_the_destination(self):
        with self.assertRaises(ValueError):
            util.atomic_write(self.dest, b"x", durable_root=self.root / "elsewhere")

    def test_fsync_dir_propagates_errors(self):
        with mock.patch("router.util.os.fsync", side_effect=OSError(5, "x")):
            with self.assertRaises(OSError):
                util.fsync_dir(self.root)


if __name__ == "__main__":
    unittest.main()
