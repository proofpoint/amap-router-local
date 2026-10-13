"""The at-most-once guarantee under a crash that DROPS every write not yet
made durable. A rename is durable only once its directory is fsynced after
it; a crash undoes every rename that was not. At every rename and every
directory fsync of a placement, crash there, let a consumer read and DELETE
any notice it finds, restart (the recovery table), and let it read again:
at most one notice is ever observed. The guarantee rests on the ledger row
being durable before the notice is committed (`deliver._commit`)."""
from __future__ import annotations

import os
import stat
from unittest import mock

from router import ingress
from router.tests.test_ingress_place import _Placement

_real_replace, _real_rename, _real_fsync = os.replace, os.rename, os.fsync


class _Crash(Exception):
    pass


class DroppedWrites:
    """Renames are pending until their directory is fsynced; `crash()`
    undoes every pending one. `crash_at` raises after that many crash points
    (each rename and each directory fsync is one)."""

    def __init__(self, crash_at=None):
        self.pending = []
        self.points = 0
        self.crash_at = crash_at

    def _point(self):
        self.points += 1
        if self.crash_at is not None and self.points == self.crash_at:
            raise _Crash(self.points)

    def replace(self, src, dst, *a, **kw):
        _real_replace(src, dst, *a, **kw)
        parent = os.path.dirname(os.fspath(dst))
        st = os.stat(parent)
        self.pending.append(((st.st_dev, st.st_ino), lambda d=os.fspath(dst): os.unlink(d)))
        self._point()

    def rename(self, src, dst, *a, src_dir_fd=None, dst_dir_fd=None, **kw):
        _real_rename(src, dst, *a, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, **kw)
        if dst_dir_fd is not None:
            st = os.fstat(dst_dir_fd)
            fd = os.dup(dst_dir_fd)
            self.pending.append(((st.st_dev, st.st_ino),
                                 lambda n=dst, fd=fd: os.unlink(n, dir_fd=fd)))
        else:
            parent = os.path.dirname(os.fspath(dst))
            st = os.stat(parent)
            self.pending.append(((st.st_dev, st.st_ino), lambda d=os.fspath(dst): os.unlink(d)))
        self._point()

    def fsync(self, fd):
        _real_fsync(fd)
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            key = (st.st_dev, st.st_ino)
            self.pending = [p for p in self.pending if p[0] != key]
            self._point()

    def crash(self):
        for _key, undo in reversed(self.pending):
            try:
                undo()
            except FileNotFoundError:
                pass
        self.pending = []

    def patches(self):
        return (mock.patch("os.replace", self.replace), mock.patch("os.rename", self.rename),
                mock.patch("os.fsync", self.fsync))


class CrashModelTests(_Placement):

    def run_with_crash(self, at):
        """Place with a crash at point `at`; drop what was not durable; a
        consumer deletes what it sees; restart; it looks again. Returns how
        many notices it ever observed."""
        self.prepared()
        model = DroppedWrites(crash_at=at)
        p1, p2, p3 = model.patches()
        with p1, p2, p3:
            try:
                self.place()
            except _Crash:
                model.crash()
        observed = 0
        for name in self.notices():
            observed += 1
            (self.tree() / "notices" / name).unlink()
        st = self.state()
        if st and st[0] == ingress.PLACING:
            self.recover()
        elif st and st[0] == ingress.PREPARED:
            self.place()
        observed += len(self.notices())
        return observed

    def test_at_most_one_notice_at_every_crash_point(self):
        self.prepared()
        dry = DroppedWrites()
        p1, p2, p3 = dry.patches()
        with p1, p2, p3:
            self.place()
        self.assertGreater(dry.points, 6, "control: the placement's crash points were seen")
        for at in range(1, dry.points + 1):
            with self.subTest(crash_at=at):
                self.tearDown()
                self.setUp()
                self.assertLessEqual(self.run_with_crash(at), 1)
