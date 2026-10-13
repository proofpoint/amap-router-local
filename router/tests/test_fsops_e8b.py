"""This router's `HopFsOps` obligations for the optional `(3, 1)` remover
(`router/fsops.py`): `remove_pinned` is crash-resumable (it sweeps the
asides of the name it removes, and only those), its emptying is bounded,
and `stat_group_pinned` is `stat_owner_pinned` plus the same stat's gid.
`router/tests/mutate_transport_e8b.py` breaks each rule."""
from __future__ import annotations

import errno
import os
import stat
from unittest import mock

from router import fsops as fsops_mod
from router import transport
from router.fsops import BindingError
from router.tests.test_fsops_list_pinned import _Dir

ASIDE = ".x.old.tmp.123.0123456789abcdef"


class RemoveResumableTests(_Dir):

    def remove(self, name):
        try:
            self.fs.remove_pinned(self.fd, name)
        except OSError as e:
            self.fail(f"remove_pinned raised {e!r}")

    def test_a_crash_after_the_rename_aside_is_finished_by_the_next_call(self):
        # As a crash leaves it: the name already renamed aside, populated.
        (self.dir / ASIDE).mkdir()
        (self.dir / ASIDE / "0").write_bytes(b"blob")
        (self.dir / ASIDE / "1").write_bytes(b"blob")
        self.remove("x")
        self.assertEqual(sorted(os.listdir(self.dir)), [])

    def test_the_name_and_its_aside_both_go(self):
        (self.dir / "x").mkdir()
        (self.dir / "x" / "0").write_bytes(b"blob")
        (self.dir / ASIDE).mkdir()
        self.remove("x")
        self.assertEqual(sorted(os.listdir(self.dir)), [])

    def test_a_file_aside_is_unlinked(self):
        (self.dir / ASIDE).write_bytes(b"")
        self.remove("x")
        self.assertEqual(os.listdir(self.dir), [])

    def test_another_name_s_asides_and_junk_are_untouched(self):
        keep = [".x.old.tmp.x", ".x.old.tmp.1.0123456789ABCDEF", ".xy.old.tmp.1.0123456789abcdef",
                ".x.b.old.tmp.1.0123456789abcdef", "x.old.tmp.1.0123456789abcdef"]
        for n in keep:
            (self.dir / n).mkdir()
        (self.dir / ASIDE).mkdir()
        self.remove("x")
        self.assertEqual(sorted(os.listdir(self.dir)), sorted(keep))

    def test_the_sweep_pages_past_one_listing_page(self):
        with mock.patch.object(transport, "LIST_LIMIT_MAX", 2):
            asides = [f".x.old.tmp.{i}.0123456789abcdef" for i in range(5)]
            for n in asides:
                (self.dir / n).mkdir()
            self.remove("x")
        self.assertEqual(os.listdir(self.dir), [])


class RemoveBoundedTests(_Dir):

    def test_a_directory_over_the_scan_cap_raises_listing_too_large_and_keeps_it(self):
        (self.dir / "x").mkdir()
        for i in range(9):
            (self.dir / "x" / f"f{i}").write_bytes(b"")
        with mock.patch.object(transport, "LIST_SCAN_MAX", 8):
            with self.assertRaises(Exception) as cm:
                self.fs.remove_pinned(self.fd, "x")
        self.assertIsInstance(cm.exception, fsops_mod.ListingTooLarge)
        (aside,) = [n for n in os.listdir(self.dir) if n.startswith(".x.old.tmp.")]
        self.assertEqual(len(os.listdir(self.dir / aside)), 9, "something was removed")

    def test_nesting_of_eight_removes_and_nine_raises_eloop(self):
        d = self.dir / "x"
        for _ in range(8):
            d = d / "n"
        d.mkdir(parents=True)              # x plus 8 nested: depth 9 under x's aside
        (self.dir / "y").mkdir()
        e = self.dir / "y"
        for _ in range(7):
            e = e / "n"
        e.mkdir(parents=True)              # y plus 7: depth 8
        try:
            self.fs.remove_pinned(self.fd, "y")
        except OSError as err:
            self.fail(f"depth 8 was refused: {err!r}")
        self.assertFalse((self.dir / "y").exists())
        with self.assertRaises(OSError) as cm:
            self.fs.remove_pinned(self.fd, "x")
        self.assertEqual(cm.exception.errno, errno.ELOOP)

    def test_a_symlink_inside_is_unlinked_and_its_target_untouched(self):
        target = self.root / "target"
        target.mkdir()
        (target / "keep").write_bytes(b"k")
        (self.dir / "x").mkdir()
        os.symlink(target, self.dir / "x" / "link")
        os.symlink(target / "keep", self.dir / "x" / "flink")
        try:
            self.fs.remove_pinned(self.fd, "x")
        except OSError as e:
            self.fail(f"remove_pinned raised {e!r}")
        self.assertEqual(os.listdir(self.dir), [])
        self.assertEqual((target / "keep").read_bytes(), b"k")

    def test_emptying_holds_a_bounded_batch_not_a_full_listing(self):
        (self.dir / "x").mkdir()
        for i in range(10):
            (self.dir / "x" / f"f{i}").write_bytes(b"")
        with mock.patch.object(fsops_mod, "_REMOVE_BATCH", 3), \
                mock.patch.object(fsops_mod.os, "listdir",
                                  side_effect=AssertionError("a full listing")):
            self.fs.remove_pinned(self.fd, "x")
        self.assertEqual(os.listdir(self.dir), [])


class StatGroupTests(_Dir):

    def test_it_agrees_with_stat_owner_pinned_and_adds_the_gid(self):
        (self.dir / "f").write_bytes(b"")
        (self.dir / "d").mkdir()
        os.symlink(self.dir / "d", self.dir / "l")
        os.mkfifo(self.dir / "p")
        for name in ("f", "d", "l", "p"):
            with self.subTest(name=name):
                uid, gid, mode, kind = self.fs.stat_group_pinned(self.fd, name)
                self.assertEqual((uid, mode, kind), self.fs.stat_owner_pinned(self.fd, name))
                st = os.stat(self.dir / name, follow_symlinks=False)
                self.assertEqual(gid, st.st_gid)
                self.assertEqual(mode, stat.S_IMODE(st.st_mode))
        self.assertEqual(self.fs.stat_group_pinned(self.fd, "l")[3], "other",
                         "a symlink was followed")

    def test_the_gid_is_the_name_s_not_the_parent_s(self):
        (self.dir / "f").write_bytes(b"")
        real = os.stat

        def fake(path, *a, **kw):
            st = real(path, *a, **kw)
            if path == "f":
                return os.stat_result(st[:5] + (4242,) + st[6:])
            return st

        with mock.patch.object(fsops_mod.os, "stat", fake):
            self.assertEqual(self.fs.stat_group_pinned(self.fd, "f")[1], 4242)

    def test_a_missing_name_and_an_unbound_descriptor(self):
        with self.assertRaises(FileNotFoundError):
            self.fs.stat_group_pinned(self.fd, "missing")
        loose = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, loose)
        with self.assertRaises(BindingError):
            self.fs.stat_group_pinned(loose, "f")
