"""`router/fsops.py` against contract amendment E5 (`transport.HopFsOps`):
the private stage, the disjoint-roots refusal, the refusal vocabulary of
`open_regular_pinned`, `commit_durable`'s dependencies, and the
`mkdir_and_pin` predicate.

Each test pins one rule, and `router/tests/mutate_fsops_e5.py` breaks each
rule in the source and names the test that must go red. Cases that need a
second group or a device node are PENDING (skipped, saying so) where the
runner cannot provide them, never reported as a pass.
"""
from __future__ import annotations

import errno
import hashlib
import os
import socket
import stat
import unittest
from unittest import mock

from router import fsops, transport
from router.tests.test_fsops import DATA, GEN, LID, _Crash, _HopCase


def _dep(fd, name, data):
    return (fd, name, len(data), hashlib.sha256(data).hexdigest())


class _Strict:
    """A wrong outcome is a FAILURE of the claim, never an error: an
    unexpected exception, or the wrong one, is reported through `fail`."""

    def expect(self, exc, fn, *a, **kw):
        try:
            fn(*a, **kw)
        except exc as e:
            return e
        except Exception as e:  # noqa: BLE001 -- the wrong outcome, as a failure
            self.fail(f"expected {exc.__name__}, got {type(e).__name__}: {e}")
        self.fail(f"{exc.__name__} was not raised")

    def succeeds(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except Exception as e:  # noqa: BLE001 -- the wrong outcome, as a failure
            self.fail(f"expected success, got {type(e).__name__}: {e}")


class _PrivateCase(_Strict, _HopCase):

    def setUp(self):
        super().setUp()
        self.proot = self.ops.open_root_nofollow(str(self.priv))
        self.pstage = self.ops.open_private_stage_dir(self.proot)


# ---------------------------------------------------------------------------
# The private stage
# ---------------------------------------------------------------------------

class PrivateStageTests(_PrivateCase):

    def test_commit_into_the_private_root_and_a_per_item_directory(self):
        self.assertEqual(self.succeeds(self.ops.commit_durable, self.pstage, self.proot,
                                       "ledger", DATA, 0o600), "created")
        results = self.ops.mkdir_and_pin(self.proot, "results", 0o700)
        item = self.ops.mkdir_and_pin(results, "req-00000001", 0o700)
        self.assertEqual(self.succeeds(self.ops.commit_durable, self.pstage, item,
                                       "result.json", DATA, 0o600), "created")
        self.assertEqual(os.stat(self.priv / "ledger").st_nlink, 1)
        self.assertEqual(os.listdir(self.priv / ".stage"), [])
        self.assertEqual((self.priv / "results" / "req-00000001" / "result.json").read_bytes(),
                         DATA)

    def test_the_stage_is_0700_and_pinned_once(self):
        st = os.stat(self.priv / ".stage")
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
        again = self.ops.open_private_stage_dir(self.proot)
        self.assertEqual(os.fstat(again).st_ino, os.fstat(self.pstage).st_ino)

    def test_an_interrupted_private_commit_raises_on_read_and_recovers(self):
        """P4: link count 2 on a private binding RAISES (never NOT_YET), and
        a fresh writer's replay recovers it."""
        with self.crash_at("linked"), self.assertRaises(_Crash):
            self.ops.commit_durable(self.pstage, self.proot, "ledger", DATA, 0o600)
        with self.assertRaises(fsops.UnsafeRead) as cm:
            self.ops.open_regular_pinned(self.proot, "ledger", max_bytes=1024)
        self.assertEqual(cm.exception.reason, "link_count")
        ops = self.new_ops()
        root = ops.open_root_nofollow(str(self.priv))
        stage = ops.open_private_stage_dir(root)
        self.assertEqual(ops.commit_durable(stage, root, "ledger", DATA, 0o600), "exists_same")
        self.assertEqual(ops.open_regular_pinned(root, "ledger", max_bytes=1024), DATA)

    def test_a_fresh_instance_derives_the_same_stage_name(self):
        with self.crash_at("staged"), self.assertRaises(_Crash):
            self.ops.commit_durable(self.pstage, self.proot, "ledger", DATA, 0o600)
        self.assertEqual(os.listdir(self.priv / ".stage"), [f"{fsops.dest_tag(())}.ledger"])

    def test_the_stage_is_never_a_destination(self):
        with self.assertRaises(fsops.BindingError):
            self.ops.commit_durable(self.pstage, self.pstage, "x", DATA, 0o600)


class PrivateRefusalTests(_PrivateCase):
    """P7: every refusal raises with the watched listings unchanged."""

    def listing(self):
        return {str(p.relative_to(self.priv.parent)) for p in self.priv.parent.rglob("*")}

    def refused(self, exc, fn, *a):
        before = self.listing()
        with self.assertRaises(exc):
            fn(*a)
        self.assertEqual(self.listing(), before)

    def test_roots_that_are_not_disjoint_are_refused_at_construction(self):
        hop, priv = str(self.hop), str(self.priv)
        for hop_root, privs in ((hop, [hop + "/inner"]), (hop, [hop]),
                                (priv + "/hop", [priv]), (hop, [priv, priv + "/x"]),
                                (hop, [priv, priv])):
            with self.subTest(hop=hop_root, private=privs):
                self.refused(fsops.FsOpsError, lambda h=hop_root, p=privs:
                             fsops.FsOps(hop_root=h, private_roots=p))

    def test_disjoint_siblings_with_a_shared_prefix_are_accepted(self):
        fsops.FsOps(hop_root=str(self.hop), private_roots=[str(self.hop) + "-state"])

    def test_only_the_private_root_itself(self):
        hop_root = self.ops.open_root_nofollow(str(self.hop))
        intake = self.ops.open_root_nofollow(str(self.hop / ".unresolved"))
        (self.priv / "sub").mkdir()
        inside = self.ops.descend_pinned(self.proot, "sub")
        for fd in (self.tree, intake, hop_root, inside):
            with self.subTest(fd=fd):
                self.refused(ValueError, self.ops.open_private_stage_dir, fd)

    def test_open_stage_dir_never_reaches_a_private_root(self):
        for side in typing_args(transport.StageSide):
            with self.subTest(side=side):
                self.refused(ValueError, self.ops.open_stage_dir, self.proot, side)

    def test_a_wrong_mode_stage_is_refused_never_repaired(self):
        ops = self.new_ops()
        os.chmod(self.priv / ".stage", 0o750)
        root = ops.open_root_nofollow(str(self.priv))
        self.refused(fsops.BindingError, ops.open_private_stage_dir, root)
        self.assertEqual(stat.S_IMODE(os.stat(self.priv / ".stage").st_mode), 0o750)

    def test_a_stage_of_another_owner_is_refused(self):
        """The owner half of the check: the same 0700 directory, seen by a
        writer of another uid, is refused."""
        ops = self.new_ops()
        root = ops.open_root_nofollow(str(self.priv))
        other = os.geteuid() + 1
        with mock.patch.object(fsops.os, "geteuid", lambda: other):
            self.refused(fsops.BindingError, ops.open_private_stage_dir, root)

    def test_a_stage_reached_by_descend_is_refused_at_commit(self):
        ops = self.new_ops()
        root = ops.open_root_nofollow(str(self.priv))
        walked = ops.descend_pinned(root, ".stage")
        self.refused(fsops.BindingError, ops.commit_durable, walked, root, "x", DATA, 0o600)

    def test_no_crossing_between_private_and_hop_trees(self):
        self.refused(fsops.BindingError, self.ops.commit_durable,
                     self.pstage, self.outbound, "x", DATA, 0o600)
        self.refused(fsops.BindingError, self.ops.commit_durable,
                     self.up_stage, self.proot, "x", DATA, 0o600)
        intake = self.ops.open_root_nofollow(str(self.hop / ".control"))
        self.refused(fsops.BindingError, self.ops.commit_durable,
                     self.pstage, intake, "x", DATA, 0o600)


def typing_args(t):
    import typing
    return typing.get_args(t)


class PrivateRootBarrierTests(_Strict, _HopCase):
    """P9: the private root is fsynced when `.stage/` is created AND when it
    is found, and a failed barrier at creation is repaired by a fresh call."""

    def fsyncs(self):
        seen = []
        real = os.fsync

        def fsync(fd):
            seen.append(os.fstat(fd).st_ino)
            return real(fd)
        return seen, mock.patch.object(fsops.os, "fsync", fsync)

    def test_fsynced_on_creation_and_when_found(self):
        root_ino = os.stat(self.priv).st_ino
        for label in ("created", "found"):
            with self.subTest(label):
                ops = self.new_ops()
                root = ops.open_root_nofollow(str(self.priv))
                seen, patch = self.fsyncs()
                with patch:
                    ops.open_private_stage_dir(root)
                self.assertIn(root_ino, seen)
        self.assertTrue((self.priv / ".stage").is_dir())

    def test_a_failed_barrier_at_creation_raises_and_a_fresh_call_repairs_it(self):
        root_ino = os.stat(self.priv).st_ino
        ops = self.new_ops()
        root = ops.open_root_nofollow(str(self.priv))
        real = os.fsync

        def eio(fd):
            if os.fstat(fd).st_ino == root_ino:
                raise OSError(errno.EIO, "injected")
            return real(fd)
        with mock.patch.object(fsops.os, "fsync", eio), self.assertRaises(OSError):
            ops.open_private_stage_dir(root)
        self.assertTrue((self.priv / ".stage").is_dir(), "precondition: .stage/ was created")
        fresh = self.new_ops()
        froot = fresh.open_root_nofollow(str(self.priv))
        seen, patch = self.fsyncs()
        with patch:
            fresh.open_private_stage_dir(froot)
        self.assertIn(root_ino, seen)


# ---------------------------------------------------------------------------
# The refusal vocabulary (V4)
# ---------------------------------------------------------------------------

class RefusalVocabularyTests(_PrivateCase):

    def read(self, name, fd=None, cap=1024):
        return self.ops.open_regular_pinned(self.outbound if fd is None else fd, name,
                                            max_bytes=cap)

    def reason(self, name, fd=None, cap=1024):
        """The refusal, dispatched as a caller must: on the port's own
        `UnsafeRead` attribute and `.reason`."""
        cls = getattr(self.ops, "UnsafeRead", None)
        self.assertIsNotNone(cls, "the port has no UnsafeRead attribute")
        e = self.expect(cls, self.read, name, fd, cap)
        self.assertIn(e.reason, transport.UNSAFE_READ_REASONS)
        return e

    @property
    def out(self):
        return self.final().parent

    def test_the_attribute_is_the_class(self):
        self.assertIs(getattr(self.ops, "UnsafeRead", None), fsops.UnsafeRead)
        self.assertIs(getattr(fsops.FsOps, "UnsafeRead", None), fsops.UnsafeRead)

    def test_a_symlink_is_not_regular_with_eloop_as_the_cause(self):
        os.symlink("/etc/hostname", self.out / "s")
        e = self.reason("s")
        self.assertEqual(e.reason, "not_regular")
        self.assertEqual(e.__cause__.errno, errno.ELOOP)

    def test_a_socket_is_not_regular_with_enxio_as_the_cause(self):
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.bind(str(self.out / "k"))
        except OSError as exc:  # an over-long socket path
            self.skipTest(f"PENDING: cannot bind a socket here ({exc})")
        try:
            e = self.reason("k")
        finally:
            sock.close()
        self.assertEqual(e.reason, "not_regular")
        self.assertEqual(e.__cause__.errno, errno.ENXIO)

    def test_a_fifo_and_a_directory_open_and_are_not_regular(self):
        os.mkfifo(self.out / "f")
        os.mkdir(self.out / "d")
        for name in ("f", "d"):
            with self.subTest(name=name):
                self.assertEqual(self.reason(name).reason, "not_regular")

    def test_a_device_is_not_regular(self):
        try:
            os.mknod(self.out / "dev", 0o600 | stat.S_IFCHR, os.makedev(1, 3))
        except PermissionError:
            self.skipTest("PENDING: creating a device node needs privileges")
        self.assertEqual(self.reason("dev").reason, "not_regular")

    def test_the_kind_changed_between_the_stat_and_the_open(self):
        (self.out / "r").write_bytes(b"x")
        self.assertEqual(self.ops.stat_owner_pinned(self.outbound, "r")[2], "file")
        (self.out / "r").unlink()
        os.symlink("/etc/hostname", self.out / "r")
        e = self.reason("r")
        self.assertEqual((e.reason, e.__cause__.errno), ("not_regular", errno.ELOOP))

    def test_link_counts(self):
        (self.out / "x").write_bytes(b"x")
        os.link(self.out / "x", self.out / "y")
        os.link(self.out / "x", self.out / "z")
        self.assertEqual(self.reason("x").reason, "link_count")
        (self.priv / "a").write_bytes(b"x")
        os.link(self.priv / "a", self.priv / "b")
        self.assertEqual(self.reason("a", fd=self.proot).reason, "link_count")

    def test_link_count_zero_on_a_generation_tree(self):
        (self.out / "gone").write_bytes(b"x")
        real = os.open

        def open_then_unlink(path, flags, *a, **kw):
            fd = real(path, flags, *a, **kw)
            if path == "gone":
                os.unlink("gone", dir_fd=kw["dir_fd"])
            return fd
        with mock.patch.object(fsops.os, "open", open_then_unlink):
            self.assertEqual(self.reason("gone").reason, "link_count")

    def test_too_large(self):
        (self.out / "big").write_bytes(b"x" * 11)
        self.assertEqual(self.reason("big", cap=10).reason, "too_large")

    def test_a_missing_name_is_a_raw_file_not_found(self):
        e = self.expect(FileNotFoundError, self.read, "absent")
        self.assertNotIsInstance(e, fsops.UnsafeRead)

    def test_any_other_error_propagates_as_itself(self):
        (self.out / "t").write_bytes(b"x")
        real = os.open
        for code in (errno.EACCES, errno.EIO, errno.EMFILE):
            with self.subTest(errno=errno.errorcode[code]):
                def fail(path, flags, *a, _code=code, **kw):
                    if path == "t":
                        raise OSError(_code, os.strerror(_code))
                    return real(path, flags, *a, **kw)
                with mock.patch.object(fsops.os, "open", fail):
                    e = self.expect(OSError, self.read, "t")
                self.assertNotIsInstance(e, fsops.UnsafeRead)
                self.assertEqual(e.errno, code)

    def test_an_unknown_reason_cannot_be_constructed(self):
        with self.assertRaises(ValueError):
            fsops.UnsafeRead("hardlink", "x")


# ---------------------------------------------------------------------------
# Dependencies (HFP1)
# ---------------------------------------------------------------------------

ATT = b"attachment bytes"


class DependencyTests(_Strict, _HopCase):
    """A request publication: its attachment directory and one attachment
    committed first, then the sentinel with that attachment as its dep."""

    def setUp(self):
        super().setUp()
        self.att = self.ops.mkdir_and_pin(self.outbound, "req-00000001.attachments", 0o750)
        self.assertEqual(self.ops.commit_durable(self.up_stage, self.att, "0", ATT, 0o640),
                         "created")
        self.deps = [_dep(self.att, "0", ATT)]

    @property
    def att_path(self):
        return self.final().parent / "req-00000001.attachments"

    def sentinel(self, ops=None, deps=None, stage=None, dest=None, data=DATA):
        ops = ops or self.ops
        return ops.commit_durable(stage if stage is not None else self.up_stage,
                                  dest if dest is not None else self.outbound,
                                  "req-00000001.json", data, 0o640,
                                  deps=self.deps if deps is None else deps)

    def anomaly(self, cause, **kw):
        e = self.expect(fsops.DependencyAnomaly, self.sentinel, **kw)
        self.assertEqual(e.cause, cause, str(e))
        return e

    def swap_dir(self):
        """FS2: the pinned directory moved aside, a compliant one at the name."""
        os.rename(self.att_path, self.att_path.with_name("aside"))
        os.mkdir(self.att_path, 0o750)

    def test_intact_deps_commit(self):
        self.assertEqual(self.sentinel(), "created")
        self.assertEqual(self.sentinel(), "exists_same")

    def test_the_dir_swapped_before_the_sentinel_is_refused_before_the_link(self):
        self.swap_dir()
        (self.att_path / "0").write_bytes(ATT)
        self.anomaly("binding_moved")
        self.assertFalse(self.final().exists())
        self.assertFalse(self.stage_path().exists())

    def test_wrong_digest_size_missing(self):
        for cause, deps in (("digest", [(self.att, "0", len(ATT), "0" * 64)]),
                            ("size", [(self.att, "0", len(ATT) - 1,
                                       hashlib.sha256(ATT).hexdigest())]),
                            ("missing", [_dep(self.att, "1", ATT)])):
            with self.subTest(cause=cause):
                self.anomaly(cause, deps=deps)
                self.assertFalse(self.final().exists())

    def test_link_count_two_or_a_hardlink_is_an_anomaly_never_a_skip(self):
        os.link(self.att_path / "0", self.final().parent / "elsewhere")
        self.anomaly("link_count")

    def test_a_symlink_dep_is_not_regular(self):
        (self.att_path / "0").unlink()
        os.symlink("/etc/hostname", self.att_path / "0")
        self.anomaly("not_regular")

    def test_an_oversized_planted_dep_is_read_bounded(self):
        (self.att_path / "0").unlink()
        (self.att_path / "0").write_bytes(b"y" * (len(ATT) * 1000))
        reads = []
        real = fsops.FsOps._read_all

        def spy(fd, expect):
            out = real(fd, expect)
            reads.append(len(out))
            return out
        with mock.patch.object(fsops.FsOps, "_read_all", staticmethod(spy)):
            self.anomaly("size")
        self.assertTrue(reads and max(reads) <= len(ATT) + 1, reads)

    def test_a_swap_between_the_entry_check_and_the_link_is_caught_after_it(self):
        def step(label, **kw):
            if label == "staged":
                self.swap_dir()
                (self.att_path / "0").write_bytes(ATT)
        with mock.patch.object(self.ops, "_step", step):
            self.anomaly("binding_moved")
        self.assertEqual(os.stat(self.final()).st_nlink, 2, "never committed")
        self.assertTrue(self.stage_path().exists(), "the stage is kept")

    def test_the_post_compare_check_on_exists_same(self):
        self.assertEqual(self.sentinel(), "created")
        self.assert_second_check_fires()

    def test_the_post_compare_check_on_f1_recovery(self):
        with self.crash_at("linked"), self.assertRaises(_Crash):
            self.sentinel()
        self.assert_second_check_fires()
        self.assertTrue(self.stage_path().exists(), "the stage is kept")

    def assert_second_check_fires(self):
        """The entry check passes; the dep is broken before the second."""
        real = fsops.FsOps._check_deps
        calls = []

        def check(ops, deps):
            calls.append(1)
            if len(calls) == 2:
                (self.att_path / "0").unlink()
            return real(ops, deps)
        with mock.patch.object(fsops.FsOps, "_check_deps", check):
            self.anomaly("missing")
        self.assertEqual(len(calls), 2)

    def test_the_post_check_on_an_exists_different_fast_path(self):
        """A symlink final is `exists_different` without any compare; the
        dependency, intact at entry and removed before the second check, is
        still reported as the anomaly, never as `exists_different`."""
        os.symlink("/etc/hostname", self.final())
        self.assert_second_check_fires()

    def test_dependency_scope_is_the_destinations_tree(self):
        """The same publication: a dependency in another tree, or inside a
        stage directory, is refused before anything is staged."""
        intake = self.ops.open_root_nofollow(str(self.hop / ".control"))
        istage = self.ops.open_stage_dir(intake, "intake")
        self.assertEqual(self.ops.commit_durable(istage, intake, "x", ATT, 0o640), "created")
        (self.hop / LID / GEN / "up" / "stage" / "planted").write_bytes(ATT)
        for label, deps in (("another tree", [_dep(intake, "x", ATT)]),
                            ("a stage directory", [_dep(self.up_stage, "planted", ATT)])):
            with self.subTest(label):
                e = self.expect(fsops.BindingError, self.sentinel, deps=deps)
                self.assertNotIsInstance(e, fsops.DependencyAnomaly)
                self.assertFalse(self.final().exists())
                self.assertFalse(self.stage_path().exists())

    def walk_fault(self, part, code):
        """Make the canonical walk's open of `part` fail with `code`."""
        real = os.open

        def fail(path, flags, *a, **kw):
            if path == part and flags & os.O_DIRECTORY:
                raise OSError(code, os.strerror(code))
            return real(path, flags, *a, **kw)
        return mock.patch.object(fsops.os, "open", fail)

    def test_walk_errors_that_say_moved_and_those_that_say_nothing(self):
        """Gone, a symlink or not a directory, on the way up ('..') or down
        (a recorded name), is `binding_moved`; any other fault propagates
        as itself and is never read as a move."""
        for part in ("..", "req-00000001.attachments"):
            for code in (errno.ENOENT, errno.ELOOP, errno.ENOTDIR):
                with self.subTest(part=part, errno=errno.errorcode[code]):
                    with self.walk_fault(part, code):
                        self.anomaly("binding_moved")
            for code in (errno.EIO, errno.EACCES):
                with self.subTest(part=part, errno=errno.errorcode[code]):
                    with self.walk_fault(part, code):
                        e = self.expect(OSError, self.sentinel)
                    self.assertNotIsInstance(e, fsops.DependencyAnomaly)
                    self.assertEqual(e.errno, code)
        self.assertFalse(self.final().exists())

    def test_the_entry_check_comes_before_any_recovery_compare(self):
        """F1: an interrupted sentinel whose dependency broke meanwhile is
        refused at ENTRY, before recovery starts comparing anything."""
        with self.crash_at("linked"), self.assertRaises(_Crash):
            self.sentinel()
        (self.att_path / "0").unlink()
        steps = []
        with mock.patch.object(self.ops, "_step", lambda label, **kw: steps.append(label)):
            self.anomaly("missing")
        self.assertNotIn("recover_before_compare", steps)

    def test_a_broken_dep_is_reported_before_exists_different(self):
        self.assertEqual(self.sentinel(), "created")
        (self.att_path / "0").unlink()
        self.anomaly("missing", data=b"other bytes")

    def test_a_dep_in_another_directory_whose_directory_moved(self):
        """The sentinel is in outbound/; its dep's directory is swapped."""
        self.swap_dir()
        self.anomaly("binding_moved")

    def test_a_dep_directory_moved_into_another_tree_at_the_same_path(self):
        """The walk back up must reach the dependency's OWN tree root: a
        directory moved into another tree at the same relative path is
        found again by name from that other root, so only the tree check
        refuses it."""
        other = self.priv.parent / "state2"
        other.mkdir()
        ops = fsops.FsOps(hop_root=self.hop, private_roots=[self.priv, other])
        roots = {}
        for p in (self.priv, other):
            root = ops.open_root_nofollow(str(p))
            out = ops.mkdir_and_pin(root, "outbound", 0o750)
            roots[p] = (root, ops.open_private_stage_dir(root), out)
        root_a, stage_a, out_a = roots[self.priv]
        item = ops.mkdir_and_pin(out_a, "req-1.attachments", 0o750)
        self.assertEqual(ops.commit_durable(stage_a, item, "0", ATT, 0o640), "created")
        os.rename(self.priv / "outbound" / "req-1.attachments",
                  other / "outbound" / "req-1.attachments")
        e = self.expect(fsops.DependencyAnomaly, ops.commit_durable, stage_a, out_a,
                        "req-1.json", DATA, 0o640, deps=[_dep(item, "0", ATT)])
        self.assertEqual(e.cause, "binding_moved")
        self.assertFalse((self.priv / "outbound" / "req-1.json").exists())

    def test_a_restart_over_a_swapped_directory_is_caught_by_content(self):
        with self.crash_at("linked"), self.assertRaises(_Crash):
            self.sentinel()
        self.swap_dir()
        ops, stage, out = self.fresh()
        att = ops.descend_pinned(out, "req-00000001.attachments")
        self.anomaly("missing", ops=ops, stage=stage, dest=out, deps=[_dep(att, "0", ATT)])
        self.assertEqual(ops.commit_durable(stage, att, "0", ATT, 0o640), "created")
        self.assertEqual(self.sentinel(ops=ops, stage=stage, dest=out,
                                       deps=[_dep(att, "0", ATT)]), "exists_same")

    def test_malformed_deps_are_refused_before_anything(self):
        for bad in ([(self.att, "0", len(ATT))], [(self.att, "0", -1, "0" * 64)],
                    [(self.att, "../0", len(ATT), "0" * 64)],
                    [(self.att, "0", len(ATT), "A" * 64)]):
            with self.subTest(bad=bad):
                e = self.expect(fsops.FsOpsError, self.sentinel, deps=bad)
                self.assertNotIsInstance(e, fsops.DependencyAnomaly)
                self.assertFalse(self.final().exists())


# ---------------------------------------------------------------------------
# mkdir_and_pin's predicate (HFP2)
# ---------------------------------------------------------------------------

class MkdirPredicateTests(_Strict, unittest.TestCase):
    """On a private tree of its own, so nothing in the fixture goes through
    `mkdir_and_pin` before the case under test does."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(os.path.realpath(self._tmp.name)) / "state"
        self.base = root / "base"
        self.base.mkdir(parents=True)
        self.ops = fsops.FsOps(private_roots=[root])
        self.outbound = self.ops.open_root_nofollow(str(self.base))

    def umask(self, value):
        old = os.umask(value)
        self.addCleanup(os.umask, old)

    def mode(self, name):
        return os.stat(self.base / name).st_mode

    def test_a_non_setgid_parent_ordinary_umask(self):
        os.chmod(self.base, 0o770)
        self.umask(0o022)
        self.succeeds(self.ops.mkdir_and_pin, self.outbound, "a", 0o750)
        self.assertEqual(stat.S_IMODE(self.mode("a")), 0o750)

    def test_an_own_group_setgid_parent_strict_umask_keeps_setgid(self):
        os.chmod(self.base, 0o2770)
        self.umask(0o077)
        self.succeeds(self.ops.mkdir_and_pin, self.outbound, "a", 0o750)
        self.assertEqual(stat.S_IMODE(self.mode("a")), 0o2750)

    def test_a_requested_setgid_bit_means_nothing(self):
        os.chmod(self.base, 0o770)
        self.umask(0o022)
        self.succeeds(self.ops.mkdir_and_pin, self.outbound, "a", 0o2750)
        self.assertEqual(stat.S_IMODE(self.mode("a")), 0o750)

    def test_a_new_directory_is_checked_too(self):
        """The predicate applies to a directory this call created: with the
        repairing fchmod made a no-op, the umask-narrowed one is refused."""
        os.chmod(self.base, 0o770)
        self.umask(0o077)
        with mock.patch.object(fsops.os, "fchmod", lambda fd, mode: None):
            self.expect(fsops.MkdirRefused, self.ops.mkdir_and_pin, self.outbound, "n", 0o750)

    def test_no_fchmod_when_the_umask_removed_nothing(self):
        os.chmod(self.base, 0o2770)
        self.umask(0o022)
        calls = []
        real = os.fchmod
        with mock.patch.object(fsops.os, "fchmod",
                               lambda fd, mode: (calls.append(mode), real(fd, mode))):
            self.succeeds(self.ops.mkdir_and_pin, self.outbound, "q", 0o750)
        self.assertEqual(calls, [])
        self.assertEqual(stat.S_IMODE(self.mode("q")), 0o2750)

    def test_a_pre_existing_mismatch_is_refused_never_repaired(self):
        os.chmod(self.base, 0o770)
        for name, mode in (("m", 0o700), ("s", 0o1750), ("g", 0o2750)):
            with self.subTest(name=name):
                os.mkdir(self.base / name)
                os.chmod(self.base / name, mode)
                with self.assertRaises(fsops.MkdirRefused):
                    self.ops.mkdir_and_pin(self.outbound, name, 0o750)
                self.assertEqual(stat.S_IMODE(self.mode(name)), mode)

    def test_a_directory_of_another_owner_is_refused(self):
        """The owner clause: a compliant directory, seen by a writer of
        another uid, is refused."""
        os.chmod(self.base, 0o770)
        os.mkdir(self.base / "o")
        os.chmod(self.base / "o", 0o750)
        other = os.geteuid() + 1
        with mock.patch.object(fsops.os, "geteuid", lambda: other):
            self.expect(fsops.MkdirRefused, self.ops.mkdir_and_pin, self.outbound, "o", 0o750)

    def test_the_check_is_on_the_pinned_descriptor(self):
        """A compliant directory put at the name after the open does not
        make the pinned one pass: the predicate reads `fstat(fd)`."""
        os.chmod(self.base, 0o770)
        os.mkdir(self.base / "p")
        os.chmod(self.base / "p", 0o700)
        real = os.open

        def open_then_swap(path, flags, *a, **kw):
            fd = real(path, flags, *a, **kw)
            if path == "p":
                os.rename(self.base / "p", self.base / "p-aside")
                os.mkdir(self.base / "p", 0o750)
                os.chmod(self.base / "p", 0o750)
            return fd
        with mock.patch.object(fsops.os, "open", open_then_swap), \
                self.assertRaises(fsops.MkdirRefused):
            self.ops.mkdir_and_pin(self.outbound, "p", 0o750)

    def _as_a_foreign_group_member(self, umask, fn):
        """Run `fn(parent_fd)` with effective uid `nobody` under a setgid
        parent whose group that uid is not in: the case where Linux clears
        setgid on `chmod`. Root prepares it and drops to `nobody` for the
        call (root itself keeps setgid on chmod, so it cannot show the
        case). Unprivileged runners cannot build it: PENDING."""
        if os.geteuid() != 0:
            self.skipTest("PENDING: a foreign-group parent needs a privileged runner")
        nobody = 65534
        mine = set(os.getgroups()) | {os.getegid()}
        gid = next(g for g in range(1000, 65534) if g not in mine)
        fg = self.base / "fg"
        os.mkdir(fg)
        os.chown(fg, nobody, gid)
        os.chmod(fg, 0o2770)
        parent = self.ops.descend_pinned(self.outbound, "fg")
        self.umask(umask)
        os.seteuid(nobody)
        try:
            return fn(parent)
        finally:
            os.seteuid(0)

    def test_a_foreign_group_setgid_parent_ordinary_umask_passes(self):
        self._as_a_foreign_group_member(
            0o022, lambda parent: self.ops.mkdir_and_pin(parent, "a", 0o750))
        self.assertTrue(os.stat(self.base / "fg" / "a").st_mode & stat.S_ISGID)

    def test_a_foreign_group_setgid_parent_strict_umask_is_refused(self):
        def call(parent):
            with self.assertRaises(fsops.MkdirRefused):
                self.ops.mkdir_and_pin(parent, "a", 0o750)
        self._as_a_foreign_group_member(0o077, call)


if __name__ == "__main__":
    unittest.main()
