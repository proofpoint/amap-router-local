"""`FsOps.list_pinned` (API (3, 0), `router/fsops.py`): this router's
implementation of the paged, bounded directory listing a plugin makes
through `HopFsOps`. Each rule of `transport.HopFsOps`'s LISTING paragraph
has a witness here, and `router/tests/mutate_fsops_e8.py` breaks each one.
"""
from __future__ import annotations

import errno
import os
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

from router import fsops as fsops_mod
from router import transport
from router.fsops import BindingError, FsOps


class _Dir(unittest.TestCase):
    """A hop root with one generation tree whose `inbound/notices/` the
    tests fill; listed through a descriptor the FsOps bound."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name)) / "hop"
        self.dir = self.root / ("a" * 32) / ("b" * 32) / "inbound" / "notices"
        self.dir.mkdir(parents=True)
        self.fs = FsOps(hop_root=str(self.root))
        root_fd = self.fs.open_root_nofollow(str(self.root))
        self.addCleanup(os.close, root_fd)
        self.fd = self.fs.descend_pinned(root_fd, os.path.relpath(self.dir, self.root))
        self.assertIsNotNone(self.fd)
        self.addCleanup(os.close, self.fd)

    def touch(self, *names):
        for n in names:
            (self.dir / n).write_bytes(b"")

    def touch_many(self, count, prefix="n-"):
        for i in range(count):
            fd = os.open(self.dir / f"{prefix}{i:06d}", os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)

    def ls(self, limit, after=None):
        return self.fs.list_pinned(self.fd, limit=limit, after=after)


class PagingTests(_Dir):

    def test_sorted_bounded_and_truncated(self):
        self.touch("d", "b", "a", "c", "e")
        self.assertEqual(self.ls(2), (["a", "b"], True))
        self.assertEqual(self.ls(2, after="b"), (["c", "d"], True))
        self.assertEqual(self.ls(2, after="d"), (["e"], False))
        self.assertEqual(self.ls(5), (["a", "b", "c", "d", "e"], False))
        self.assertEqual(self.ls(1024, after="e"), ([], False))

    def test_after_is_strict_and_need_not_exist(self):
        self.touch("a", "b", "c")
        self.assertEqual(self.ls(10, after="a"), (["b", "c"], False))
        self.assertEqual(self.ls(10, after="aa"), (["b", "c"], False))

    def test_names_are_code_point_ordered(self):
        names = ["notice-a.json", "notice-a.b.json", "notice-a-x.json", "notice-ab.json"]
        self.touch(*names)
        self.assertEqual(self.ls(10)[0], sorted(names))
        self.assertEqual(self.ls(10)[0][:2], ["notice-a-x.json", "notice-a.b.json"])

    def test_an_undecodable_name_is_surfaced_not_dropped(self):
        raw = b"notice-\xff.json"
        fd = os.open(os.fsencode(str(self.dir)) + b"/" + raw, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        # Some filesystems (macOS-backed virtiofs, for one) store a different
        # name for a non-UTF-8 byte. There the rule cannot be shown, and a
        # failure would be the filesystem's, not this code's: skip, by name.
        if raw not in os.listdir(os.fsencode(str(self.dir))):
            self.skipTest("this filesystem does not preserve non-UTF-8 name bytes")
        self.touch("notice-ok.json")
        names, _ = self.ls(10)
        self.assertEqual(len(names), 2)
        self.assertIn(os.fsdecode(raw), names)
        self.assertEqual(os.fsencode(next(n for n in names if n != "notice-ok.json")), raw)

    def test_dot_entries_never_appear(self):
        self.assertEqual(self.ls(10), ([], False))
        self.touch(".hidden")
        self.assertEqual(self.ls(10), ([".hidden"], False))


class ArgumentAndBindingTests(_Dir):

    def test_bad_arguments_are_refused_before_anything_is_opened(self):
        with mock.patch.object(fsops_mod.os, "open", side_effect=AssertionError("opened")):
            for limit, after in ((0, None), (-1, None), (True, None), (1025, None),
                                 (1, 3), (1, b"x")):
                with self.subTest(limit=limit, after=after):
                    with self.assertRaises(ValueError):
                        self.ls(limit, after)

    def test_an_unbound_descriptor_is_refused(self):
        other = os.open(str(self.dir), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, other)
        with self.assertRaises(BindingError):
            self.fs.list_pinned(other, limit=1)

    def test_a_stale_binding_is_refused(self):
        """The pinned number now names another directory."""
        moved = self.dir.parent / "elsewhere"
        moved.mkdir()
        root_fd = self.fs.open_root_nofollow(str(self.root))
        self.addCleanup(os.close, root_fd)
        fd = self.fs.descend_pinned(root_fd, os.path.relpath(moved, self.root))
        os.close(fd)
        replacement = os.open(str(self.dir.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            if replacement != fd:
                os.dup2(replacement, fd)
            with self.assertRaises(BindingError):
                self.fs.list_pinned(fd, limit=1)
        finally:
            os.close(replacement)
            try:
                os.close(fd)
            except OSError:
                pass

    def test_an_error_raises_and_is_never_an_empty_listing(self):
        self.touch("a")
        with mock.patch.object(fsops_mod.os, "scandir",
                               side_effect=OSError(errno.EIO, "injected")):
            with self.assertRaises(OSError):
                self.ls(10)


class FreshDescriptionTests(_Dir):
    """The scan reads a FRESH open description, never the pinned one or a
    dup of it (a dup shares its offset)."""

    def test_the_scan_opens_dot_relative_to_the_pinned_fd_and_never_dups(self):
        self.touch("a", "b")
        opened, real_open = [], os.open
        def recording_open(path, flags, *a, **kw):
            opened.append((path, kw.get("dir_fd")))
            return real_open(path, flags, *a, **kw)
        with mock.patch.object(fsops_mod.os, "open", side_effect=recording_open), \
                mock.patch.object(fsops_mod.os, "dup", side_effect=AssertionError("dup")):
            self.assertEqual(self.ls(10), (["a", "b"], False))
        self.assertEqual(opened, [(".", self.fd)])

    def test_the_pinned_descriptor_keeps_its_position_and_closes_nothing_extra(self):
        self.touch_many(40)
        before = os.lseek(self.fd, 0, os.SEEK_CUR)
        fds_before = set(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
        for _ in range(2):
            self.assertEqual(len(self.ls(5)[0]), 5)
        self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), before)
        if fds_before is not None:
            self.assertEqual(set(os.listdir("/proc/self/fd")), fds_before,
                             "the fresh descriptor leaked")
        os.fstat(self.fd)   # still open, still ours


class ScanCapTests(_Dir):
    """`LIST_SCAN_MAX` is shrunk here so the cap can be shown without 65,537
    files; the constant's value is pinned in `test_transport_e8`."""

    CAP = 50

    def visits(self):
        """Count the names the scan actually visited."""
        counter = {"n": 0}
        real = os.scandir
        def counting(fd):
            it = real(fd)
            class Wrapped:
                def __enter__(s):
                    it.__enter__()
                    return s
                def __exit__(s, *exc):
                    return it.__exit__(*exc)
                def __iter__(s):
                    for e in it:
                        counter["n"] += 1
                        yield e
            return Wrapped()
        return counter, mock.patch.object(fsops_mod.os, "scandir", side_effect=counting)

    def test_exactly_the_cap_lists(self):
        self.touch_many(self.CAP)
        with mock.patch.object(transport, "LIST_SCAN_MAX", self.CAP):
            names, truncated = self.ls(1024)
        self.assertEqual((len(names), truncated), (self.CAP, False))

    def test_one_more_raises_and_the_scan_stopped(self):
        self.touch_many(self.CAP * 4)
        counter, patch = self.visits()
        with mock.patch.object(transport, "LIST_SCAN_MAX", self.CAP), patch:
            with self.assertRaises(FsOps.ListingTooLarge):
                self.ls(1)
        self.assertLessEqual(counter["n"], self.CAP + 1,
                             "the scan visited past the cap before refusing")

    def test_the_cap_holds_whatever_after_and_limit_are(self):
        self.touch_many(self.CAP + 1)
        with mock.patch.object(transport, "LIST_SCAN_MAX", self.CAP):
            for after in (None, "n-000000", "zzz"):
                with self.subTest(after=after):
                    with self.assertRaises(FsOps.ListingTooLarge):
                        self.ls(1, after)

    def test_the_class_is_the_runtimes_own_and_disjoint(self):
        self.assertIs(FsOps.ListingTooLarge, fsops_mod.ListingTooLarge)
        for base in (OSError, FsOps.UnsafeRead):
            self.assertFalse(issubclass(FsOps.ListingTooLarge, base))
            self.assertFalse(issubclass(base, FsOps.ListingTooLarge))
        self.assertEqual(transport.check_fsops_classes(self.fs),
                         ((FsOps.UnsafeRead, "unsafe_read"),
                          (FsOps.ListingTooLarge, "listing_too_large")))
        self.assertIsInstance(self.fs, transport.HopFsOps)


class MemoryTests(_Dir):

    COUNT = 10000

    def test_memory_is_bounded_by_limit_not_the_directory(self):
        """A full listing of 10,000 names costs far more than five; the
        bounded heap keeps the peak near the cost of `limit` names."""
        self.touch_many(self.COUNT)
        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            base = tracemalloc.get_traced_memory()[0]
            names, truncated = self.ls(5)
            peak = tracemalloc.get_traced_memory()[1] - base
        finally:
            tracemalloc.stop()
        self.assertEqual((len(names), truncated), (5, True))
        full = sum(len(f"n-{i:06d}") + 49 for i in range(self.COUNT))   # str objects alone
        self.assertLess(peak, full // 4,
                        f"peak {peak} bytes is not bounded by limit (a full listing is ~{full})")


if __name__ == "__main__":
    unittest.main()
