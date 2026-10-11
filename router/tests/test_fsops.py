"""`router/fsops.py`: this router's `HopFsOps`, against contract §4.3 /
B §e.2 and the destination-tag adjudication.

Same-uid tests cannot show a second uid being kept out of a private stage
directory; that is the deployment probe's job. They do show what the code
owes: the commit sequence, F1/H1 recovery at every boundary, refusals,
bindings and tags, and the barriers.
"""
from __future__ import annotations

import errno
import logging
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import fsops, transport

LID = "0123456789abcdef0123456789abcdef"
GEN = "fedcba9876543210fedcba9876543210"
DATA = b'{"req_id": "00000001"}\n'


class _Crash(Exception):
    pass


class _HopCase(unittest.TestCase):
    """A hop root with one published generation tree (identity marker in
    `up/`), its `down/` and `outbound/`, and both host intakes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(os.path.realpath(self._tmp.name))
        self.hop = base / "hop"
        self.priv = base / "state"
        for d in (self.hop, self.hop / ".unresolved", self.hop / ".control",
                  self.hop / LID, self.priv):
            d.mkdir()
        self.ops = self.new_ops()
        self.publish_generation(self.ops)
        self.tree = self.ops.descend_pinned(self.ops.open_root_nofollow(str(self.hop)),
                                            f"{LID}/{GEN}")
        self.up_stage = self.ops.open_stage_dir(self.tree, "up")
        self.outbound = self.ops.mkdir_and_pin(self.tree, "outbound", 0o770)

    def tearDown(self):
        self._tmp.cleanup()

    def new_ops(self):
        return fsops.FsOps(hop_root=self.hop, private_roots=[self.priv])

    def publish_generation(self, ops):
        lid = ops.descend_pinned(ops.open_root_nofollow(str(self.hop)), LID)
        staging = f".adm-{GEN}-x"
        root = ops.stage_tree(lid, staging)
        up = ops.descend_pinned(root, "up")
        stage = ops.open_stage_dir(root, "up")
        self.assertEqual(ops.commit_durable(stage, up, "identity", b"{}", 0o640), "created")
        self.assertEqual(ops.rename_noreplace(lid, staging, lid, GEN), "moved")
        os.mkdir(self.hop / LID / GEN / "down", 0o750)

    def final(self, name="req-00000001.json"):
        return self.hop / LID / GEN / "outbound" / name

    def stage_path(self, name="req-00000001.json"):
        tag = fsops.dest_tag(("outbound",))
        return self.hop / LID / GEN / "up" / "stage" / f"{tag}.{name}"

    def commit(self, ops=None, data=DATA, name="req-00000001.json", mode=0o640,
               stage=None, dest=None):
        ops = ops or self.ops
        return ops.commit_durable(stage if stage is not None else self.up_stage,
                                  dest if dest is not None else self.outbound,
                                  name, data, mode)

    def crash_at(self, label):
        def step(lbl, **kw):
            if lbl == label:
                raise _Crash(lbl)
        return mock.patch.object(self.ops, "_step", step)

    def fresh(self):
        """A new FsOps (a restart) with the same tree reopened."""
        ops = self.new_ops()
        tree = ops.descend_pinned(ops.open_root_nofollow(str(self.hop)), f"{LID}/{GEN}")
        return ops, ops.open_stage_dir(tree, "up"), ops.descend_pinned(tree, "outbound")


class ConformanceTests(_HopCase):

    def test_it_is_a_hopfsops(self):
        self.assertIsInstance(self.ops, transport.HopFsOps)
        self.assertNotIsInstance(fsops.NOT_YET, bytes)
        self.assertIs(self.ops.NOT_YET, fsops.NOT_YET)


class CommitTests(_HopCase):

    def test_created_then_committed_at_link_count_one(self):
        self.assertEqual(self.commit(), "created")
        st = os.stat(self.final())
        self.assertEqual(st.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o640)
        self.assertEqual(self.final().read_bytes(), DATA)
        self.assertFalse(self.stage_path().exists())

    def test_identical_retry_is_exists_same_and_different_bytes_never_replace(self):
        self.commit()
        self.assertEqual(self.commit(), "exists_same")
        with self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(data=b"other"), "exists_different")
        self.assertEqual(self.final().read_bytes(), DATA)

    def test_wrong_mode_or_symlink_final_is_exists_different(self):
        self.commit()
        os.chmod(self.final(), 0o600)
        with self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(), "exists_different")
        os.chmod(self.final(), 0o640)
        (self.final().parent / "link.json").symlink_to(self.final())
        with self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(name="link.json"), "exists_different")

    def test_a_refused_existing_file_is_made_durable_before_the_answer(self):
        self.commit()
        os.chmod(self.final(), 0o600)
        synced = []
        real = os.fsync

        def fsync(fd):
            st = os.fstat(fd)
            synced.append("dir" if stat.S_ISDIR(st.st_mode) else "file")
            return real(fd)

        with mock.patch("router.fsops.os.fsync", fsync), \
                self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(), "exists_different")
        self.assertEqual(synced, ["file", "dir"])

    def test_a_stale_own_stage_with_no_final_is_cleaned_and_the_commit_retried(self):
        self.stage_path().write_bytes(b"stale")
        self.assertEqual(self.commit(), "created")
        self.assertEqual(self.final().read_bytes(), DATA)
        self.assertFalse(self.stage_path().exists())


class BarrierOrderTests(_HopCase):
    """The order of every fsync, link and unlink, at the real os calls."""

    def spy(self):
        events = []
        real_fsync, real_link, real_unlink = os.fsync, os.link, os.unlink
        stage_ino = os.fstat(self.up_stage).st_ino
        dest_ino = os.fstat(self.outbound).st_ino

        def name(fd):
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                return "file"
            return {stage_ino: "stage_dir", dest_ino: "dest_dir"}.get(st.st_ino, "dir")

        def fsync(fd):
            events.append(("fsync", name(fd)))
            return real_fsync(fd)

        def link(*a, **k):
            events.append(("link",))
            return real_link(*a, **k)

        def unlink(*a, **k):
            events.append(("unlink",))
            return real_unlink(*a, **k)

        return events, (mock.patch("router.fsops.os.fsync", fsync),
                        mock.patch("router.fsops.os.link", link),
                        mock.patch("router.fsops.os.unlink", unlink))

    def test_the_commit_sequence(self):
        events, (a, b, c) = self.spy()
        with a, b, c:
            self.assertEqual(self.commit(), "created")
        self.assertEqual(events, [("fsync", "file"), ("fsync", "stage_dir"), ("link",),
                                  ("fsync", "dest_dir"), ("unlink",), ("fsync", "stage_dir")])

    def test_stage_tree_is_durable_bottom_up_before_it_returns(self):
        lid = self.ops.descend_pinned(self.ops.open_root_nofollow(str(self.hop)), LID)
        lid_ino = os.fstat(lid).st_ino
        synced = []
        real = os.fsync

        def fsync(fd):
            st = os.fstat(fd)
            synced.append("lid" if st.st_ino == lid_ino else "sub")
            return real(fd)

        with mock.patch("router.fsops.os.fsync", fsync):
            self.ops.stage_tree(lid, ".adm-order")
        # stage/ (its mode), up/ (stage's entry), the root (up's entry), then
        # the <logical_id>/ parent (the root's entry).
        self.assertEqual(synced, ["sub", "sub", "sub", "lid"])


class ExistsBranchTests(_HopCase):
    """Establish and make durable BEFORE any cleanup; repair the stage-dir
    barrier on every exists_same."""

    def _spy(self):
        events = []
        real = os.fsync
        stage_ino = os.fstat(self.up_stage).st_ino
        dest_ino = os.fstat(self.outbound).st_ino

        def fsync(fd):
            st = os.fstat(fd)
            events.append("file" if not stat.S_ISDIR(st.st_mode) else
                          {stage_ino: "stage_dir", dest_ino: "dest_dir"}.get(st.st_ino, "dir"))
            return real(fd)

        return events, mock.patch("router.fsops.os.fsync", fsync)

    def test_exists_same_fsyncs_the_file_the_destination_and_the_stage_dir(self):
        self.commit()
        events, patch = self._spy()
        with patch:
            self.assertEqual(self.commit(), "exists_same")
        self.assertEqual(events, ["file", "dest_dir", "stage_dir"])

    def test_a_failed_final_stage_dir_fsync_is_repaired_by_a_fresh_retry(self):
        """Codex F1: the last barrier (the stage-dir fsync after the unlink)
        fails. A fresh instance's retry must attempt it again, and must not
        answer exists_same while it still fails."""
        stage_ino = os.fstat(self.up_stage).st_ino
        real = os.fsync
        state = {"armed": False}

        def fsync(fd):
            if state["armed"] and os.fstat(fd).st_ino == stage_ino:
                raise OSError(errno.EIO, "injected")
            return real(fd)

        def step(lbl, **kw):
            if lbl == "unlinked":
                state["armed"] = True

        with mock.patch.object(self.ops, "_step", step), \
                mock.patch("router.fsops.os.fsync", fsync):
            with self.assertRaises(OSError):
                self.commit()
            ops, stage, out = self.fresh()
            with self.assertRaises(OSError):
                self.commit(ops, stage=stage, dest=out)
        ops, stage, out = self.fresh()
        events, patch = self._spy()
        with patch:
            self.assertEqual(self.commit(ops, stage=stage, dest=out), "exists_same")
        self.assertIn("stage_dir", events)

    def test_a_mismatched_final_keeps_our_stage_as_evidence(self):
        """Codex F2: an nlink-1 final with different bytes, and our own stage
        present. exists_different, with the stage kept."""
        self.final().write_bytes(b"someone else's")
        os.chmod(self.final(), 0o640)
        self.stage_path().write_bytes(DATA)
        with self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(), "exists_different")
        self.assertTrue(self.stage_path().exists(), "evidence removed before the compare")
        self.assertEqual(self.final().read_bytes(), b"someone else's")

    def test_a_matching_final_drops_our_stale_stage_only_after_the_barriers(self):
        self.final().write_bytes(DATA)
        os.chmod(self.final(), 0o640)
        self.stage_path().write_bytes(b"old attempt")
        seen = []

        def step(lbl, **kw):
            if lbl == "same_synced":
                seen.append(self.stage_path().exists())

        with mock.patch.object(self.ops, "_step", step):
            self.assertEqual(self.commit(), "exists_same")
        self.assertEqual(seen, [True])
        self.assertFalse(self.stage_path().exists())


class CrashPointTests(_HopCase):
    """Interrupt at each boundary; a restarted writer (a fresh FsOps)
    resumes to exists_same, the file at link count 1, the stage gone."""

    def test_each_boundary_resumes(self):
        for label in ("staged", "linked", "dest_synced", "unlinked"):
            with self.subTest(after=label):
                for p in (self.final(), self.stage_path()):
                    if p.exists():
                        p.unlink()
                with self.crash_at(label), self.assertRaises(_Crash):
                    self.commit()
                ops, stage, out = self.fresh()
                want = "created" if label == "staged" else "exists_same"
                self.assertEqual(self.commit(ops, stage=stage, dest=out), want)
                self.assertEqual(os.stat(self.final()).st_nlink, 1)
                self.assertEqual(self.final().read_bytes(), DATA)
                self.assertFalse(self.stage_path().exists())


class RecoveryTests(_HopCase):
    """H1: with the stage present the file stays NOT_YET; only after the
    compare and the barrier is the stage unlinked."""

    def interrupted(self):
        with self.crash_at("dest_synced"), self.assertRaises(_Crash):
            self.commit()
        self.assertEqual(os.stat(self.final()).st_nlink, 2)
        return self.fresh()

    def test_a_reader_sees_not_yet_at_every_boundary_then_the_bytes(self):
        ops, stage, out = self.interrupted()
        reader = self.new_ops()
        rtree = reader.descend_pinned(reader.open_root_nofollow(str(self.hop)), f"{LID}/{GEN}")
        rout = reader.descend_pinned(rtree, "outbound")
        seen = []

        def step(lbl, **kw):
            seen.append((lbl, reader.open_regular_pinned(rout, "req-00000001.json",
                                                         max_bytes=1024)))

        self.assertIs(reader.open_regular_pinned(rout, "req-00000001.json", max_bytes=1024),
                      fsops.NOT_YET)
        with mock.patch.object(ops, "_step", step):
            self.assertEqual(self.commit(ops, stage=stage, dest=out), "exists_same")
        self.assertEqual([l for l, _ in seen],
                         ["recover_before_compare", "recover_after_compare",
                          "recover_after_barrier"])
        self.assertTrue(all(r is fsops.NOT_YET for _, r in seen))
        self.assertEqual(reader.open_regular_pinned(rout, "req-00000001.json", max_bytes=1024),
                         DATA)

    def test_a_comparison_failure_leaves_the_stage_and_not_yet(self):
        ops, stage, out = self.interrupted()
        with self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(ops, data=b"different", stage=stage, dest=out),
                             "exists_different")
        self.assertTrue(self.stage_path().exists())
        self.assertIs(ops.open_regular_pinned(out, "req-00000001.json", max_bytes=1024),
                      fsops.NOT_YET)

    def test_an_fsync_failure_during_recovery_leaves_the_stage_and_not_yet(self):
        ops, stage, out = self.interrupted()
        real = os.fsync
        armed = []

        def step(lbl, **kw):
            if lbl == "recover_after_compare":
                armed.append(True)

        def fsync(fd):
            if armed:
                raise OSError(errno.EIO, "injected")
            return real(fd)

        with mock.patch.object(ops, "_step", step), mock.patch("router.fsops.os.fsync", fsync):
            with self.assertRaises(OSError):
                self.commit(ops, stage=stage, dest=out)
        self.assertTrue(armed, "the injection never armed")
        self.assertTrue(self.stage_path().exists())
        self.assertIs(ops.open_regular_pinned(out, "req-00000001.json", max_bytes=1024),
                      fsops.NOT_YET)


class AnomalyTests(_HopCase):

    def test_a_planted_foreign_hardlink_is_exists_different(self):
        other = self.final().parent / "other.json"
        other.write_bytes(DATA)
        os.chmod(other, 0o640)
        os.link(other, self.final())
        with self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(), "exists_different")

    def test_a_stage_on_a_different_inode_is_exists_different(self):
        other = self.final().parent / "other.json"
        other.write_bytes(DATA)
        os.chmod(other, 0o640)
        os.link(other, self.final())
        self.stage_path().write_bytes(DATA)
        with self.assertLogs("amap_router_local.fsops", logging.ERROR):
            self.assertEqual(self.commit(), "exists_different")

    def test_a_substituted_stage_is_never_published(self):
        """G1, as far as one uid can show it: whatever replaces the stage
        pathname after it was frozen, the published bytes are the frozen
        bytes or nothing."""
        def step(lbl, stage_fd=None, stage_name=None, **kw):
            if lbl == "staged":
                fake = os.open("fake", os.O_WRONLY | os.O_CREAT, 0o640, dir_fd=stage_fd)
                os.write(fake, b"SUBSTITUTE")
                os.close(fake)
                os.rename("fake", stage_name, src_dir_fd=stage_fd, dst_dir_fd=stage_fd)

        with mock.patch.object(self.ops, "_step", step):
            with self.assertRaises(fsops.FsOpsError):
                self.commit()
        self.assertFalse(self.final().exists(), "the substitute was published")


class ReaderTests(_HopCase):

    def test_link_count_two_is_skipped_then_read_once_committed(self):
        with self.crash_at("dest_synced"), self.assertRaises(_Crash):
            self.commit()
        self.assertIs(self.ops.open_regular_pinned(self.outbound, "req-00000001.json",
                                                   max_bytes=1024), fsops.NOT_YET)
        ops, stage, out = self.fresh()
        self.commit(ops, stage=stage, dest=out)
        self.assertEqual(self.ops.open_regular_pinned(self.outbound, "req-00000001.json",
                                                      max_bytes=1024), DATA)

    def test_outside_a_hop_tree_link_count_two_raises(self):
        ops = self.ops
        root = ops.open_root_nofollow(str(self.priv))
        (self.priv / "a").write_bytes(b"x")
        os.link(self.priv / "a", self.priv / "b")
        with self.assertRaises(fsops.UnsafeRead):
            ops.open_regular_pinned(root, "a", max_bytes=10)

    def test_host_intake_link_count_two_is_not_yet(self):
        intake = self.ops.open_root_nofollow(str(self.hop / ".unresolved"))
        (self.hop / ".unresolved" / "a").write_bytes(b"x")
        os.link(self.hop / ".unresolved" / "a", self.hop / ".unresolved" / "b")
        self.assertIs(self.ops.open_regular_pinned(intake, "a", max_bytes=10), fsops.NOT_YET)

    def test_three_links_and_oversize_and_non_regular_raise(self):
        (self.final().parent / "x").write_bytes(b"x")
        os.link(self.final().parent / "x", self.final().parent / "y")
        os.link(self.final().parent / "x", self.final().parent / "z")
        with self.assertRaises(fsops.UnsafeRead):
            self.ops.open_regular_pinned(self.outbound, "x", max_bytes=10)
        self.commit()
        with self.assertRaises(fsops.UnsafeRead):
            self.ops.open_regular_pinned(self.outbound, "req-00000001.json", max_bytes=3)
        os.mkdir(self.final().parent / "d")
        with self.assertRaises(fsops.UnsafeRead):
            self.ops.open_regular_pinned(self.outbound, "d", max_bytes=10)


class BindingAndTagTests(_HopCase):

    def test_tags_are_length_prefixed_and_unambiguous(self):
        self.assertEqual(fsops.dest_tag(("outbound",)), "8-outbound")
        self.assertEqual(fsops.dest_tag(()), "0-")
        self.assertNotEqual(fsops.dest_tag(("a.b",)), fsops.dest_tag(("a", "b")))

    def test_per_item_directories_get_distinct_tags(self):
        a = self.ops.mkdir_and_pin(self.outbound, "req-00000001.attachments", 0o770)
        b = self.ops.mkdir_and_pin(self.outbound, "req-00000002.attachments", 0o770)
        self.assertNotEqual(self.ops.binding(a).tag, self.ops.binding(b).tag)
        self.assertEqual(self.commit(dest=a, name="0", data=b"one"), "created")
        self.assertEqual(self.commit(dest=b, name="0", data=b"two"), "created")
        self.assertEqual((self.final().parent / "req-00000002.attachments" / "0").read_bytes(),
                         b"two")

    def test_restart_and_equivalent_openings_give_the_same_tag(self):
        tag = self.ops.binding(self.outbound).tag
        ops, _, out = self.fresh()
        self.assertEqual(ops.binding(out).tag, tag)
        direct = ops.open_root_nofollow(str(self.hop / LID / GEN / "outbound"))
        self.assertEqual(ops.binding(direct).tag, tag)
        self.assertEqual(ops.binding(direct).tree, ops.binding(out).tree)

    def test_tag_components_outside_the_charset_are_refused(self):
        with self.assertRaises(fsops.BindingError):
            fsops.dest_tag(("outbound", "a b"))
        with self.assertRaises(fsops.BindingError):
            self.ops.mkdir_and_pin(self.tree, "we irdé", 0o750)
        self.assertEqual(fsops.dest_tag(("a-b_c.d",)), "7-a-b_c.d")

    def test_a_prior_binding_no_descriptor_holds_is_replaced_not_ambiguous(self):
        """RE's B2: once nothing holds the prior directory, its inode may be
        freed and reused, so the old binding proves nothing."""
        d = self.ops.mkdir_and_pin(self.outbound, "req-00000001.attachments", 0o770)
        os.close(d)
        os.rename(self.final().parent / "req-00000001.attachments",
                  self.final().parent / "req-00000002.attachments")
        fd = self.ops.descend_pinned(self.outbound, "req-00000002.attachments")
        self.assertEqual(self.ops.binding(fd).rel, ("outbound", "req-00000002.attachments"))

    def test_an_injected_inode_reuse_after_removal_is_not_ambiguous(self):
        """The ext4/xfs case, simulated: a per-item directory removed BY
        SOMEONE ELSE (so remove_pinned's pruning never ran) has its
        (dev, ino) reappear for the next item's directory."""
        a = self.ops.mkdir_and_pin(self.outbound, "req-00000001.attachments", 0o770)
        old = os.fstat(a)
        os.close(a)
        os.rmdir(self.final().parent / "req-00000001.attachments")
        real = os.fstat
        target = str(self.final().parent / "req-00000002.attachments")

        def fstat(fd):
            st = real(fd)
            if stat.S_ISDIR(st.st_mode) and os.readlink(f"/proc/self/fd/{fd}") == target:
                fields = list(st)
                fields[stat.ST_INO], fields[stat.ST_DEV] = old.st_ino, old.st_dev
                return os.stat_result(fields)
            return st

        if not os.path.isdir("/proc/self/fd"):
            self.skipTest("needs /proc/self/fd")
        with mock.patch("router.fsops.os.fstat", fstat):
            b = self.ops.mkdir_and_pin(self.outbound, "req-00000002.attachments", 0o770)
            self.assertEqual(self.ops.binding(b).rel[-1], "req-00000002.attachments")

    def test_remove_pinned_forgets_the_bindings_under_it(self):
        d = self.ops.mkdir_and_pin(self.outbound, "req-00000003.attachments", 0o770)
        key = (os.fstat(d).st_dev, os.fstat(d).st_ino)
        os.close(d)
        self.ops.remove_pinned(self.outbound, "req-00000003.attachments")
        self.assertNotIn(key, self.ops._by_dir)

    def test_one_directory_under_two_paths_is_ambiguous(self):
        os.rename(self.hop / LID / GEN / "outbound", self.hop / LID / GEN / "moved")
        with self.assertRaises(fsops.BindingError):
            self.ops.descend_pinned(self.tree, "moved")

    def test_an_unknown_or_stale_descriptor_is_refused(self):
        raw = os.open(self.hop / LID / GEN / "outbound", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, raw)
        with self.assertRaises(fsops.BindingError):
            self.commit(dest=raw)
        other = os.open(self.hop / ".control", os.O_RDONLY | os.O_DIRECTORY)
        os.dup2(other, self.outbound)  # the bound number now names another directory
        os.close(other)
        with self.assertRaises(fsops.BindingError):
            self.commit()

    def test_a_path_under_no_configured_root_is_refused(self):
        with self.assertRaises(fsops.BindingError):
            self.ops.open_root_nofollow(self._tmp.name)

    def test_only_a_stage_opened_by_open_stage_dir_is_accepted(self):
        """Reached by descend_pinned, `up/stage` skipped the owner and 0700
        check, so it is refused as a stage even when it would pass it."""
        lid = self.ops.descend_pinned(self.ops.open_root_nofollow(str(self.hop)), LID)
        root = self.ops.stage_tree(lid, ".adm-v")
        sneaky = self.ops.descend_pinned(root, "up/stage")
        up = self.ops.descend_pinned(root, "up")
        with self.assertRaises(fsops.BindingError):
            self.ops.commit_durable(sneaky, up, "identity", b"{}", 0o640)
        good = self.ops.open_stage_dir(root, "up")
        self.assertEqual(self.ops.commit_durable(good, up, "identity", b"{}", 0o640), "created")

    def test_the_stage_and_destination_must_share_a_tree_and_a_stage_is_never_a_dest(self):
        intake = self.ops.open_root_nofollow(str(self.hop / ".unresolved"))
        istage = self.ops.open_stage_dir(intake, "intake")
        with self.assertRaises(fsops.BindingError):
            self.commit(stage=istage)
        with self.assertRaises(fsops.BindingError):
            self.commit(dest=self.up_stage)
        with self.assertRaises(fsops.BindingError):
            self.commit(stage=self.outbound)

    def test_an_admitted_trees_tags_do_not_change_at_publication(self):
        lid = self.ops.descend_pinned(self.ops.open_root_nofollow(str(self.hop)), LID)
        root = self.ops.stage_tree(lid, ".adm-next-y")
        before = self.ops.binding(self.ops.mkdir_and_pin(root, "outbound", 0o770)).tag
        self.assertEqual(self.ops.rename_noreplace(lid, ".adm-next-y", lid, "next"), "moved")
        after_ops = self.new_ops()
        tree = after_ops.descend_pinned(after_ops.open_root_nofollow(str(self.hop)), f"{LID}/next")
        self.assertEqual(after_ops.binding(after_ops.descend_pinned(tree, "outbound")).tag, before)


class StageDirTests(_HopCase):

    def test_unknown_and_mismatched_sides_raise_before_anything_is_opened(self):
        intake = self.ops.open_root_nofollow(str(self.hop / ".control"))
        for fd in (self.tree, intake):
            with self.assertRaises(ValueError):
                self.ops.open_stage_dir(fd, "sideways")
        self.assertFalse((self.hop / ".control" / ".stage").exists(),
                         "an unknown side opened the intake stage")
        with self.assertRaises(ValueError):
            self.ops.open_stage_dir(self.tree, "intake")
        with self.assertRaises(ValueError):
            self.ops.open_stage_dir(intake, "up")
        self.assertFalse((self.hop / LID / GEN / ".stage").exists())
        self.assertFalse((self.hop / ".control" / "up").exists())

    def test_an_existing_stage_with_the_wrong_mode_is_refused_not_repaired(self):
        os.chmod(self.hop / LID / GEN / "down", 0o750)
        os.mkdir(self.hop / LID / GEN / "down" / "stage", 0o700)
        os.chmod(self.hop / LID / GEN / "down" / "stage", 0o750)
        with self.assertRaises(fsops.FsOpsError):
            self.ops.open_stage_dir(self.tree, "down")
        self.assertEqual(stat.S_IMODE(os.stat(self.hop / LID / GEN / "down" / "stage").st_mode),
                         0o750)

    def test_the_marker_directory_is_never_created(self):
        os.rmdir(self.hop / LID / GEN / "down")
        with self.assertRaises(FileNotFoundError):
            self.ops.open_stage_dir(self.tree, "down")

    def test_pinned_once_and_the_intake_stage(self):
        a = self.ops.open_stage_dir(self.tree, "up")
        b = self.ops.open_stage_dir(self.tree, "up")
        self.assertEqual(os.fstat(a).st_ino, os.fstat(b).st_ino)
        intake = self.ops.open_root_nofollow(str(self.hop / ".unresolved"))
        s = self.ops.open_stage_dir(intake, "intake")
        self.assertTrue((self.hop / ".unresolved" / ".stage").is_dir())
        cand = self.ops.mkdir_and_pin(intake, "cand1", 0o750)
        self.assertEqual(self.ops.commit_durable(s, cand, "c.json", b"{}", 0o640), "created")


class StageTreeTests(_HopCase):

    def test_stage_tree_never_publishes(self):
        lid = self.ops.descend_pinned(self.ops.open_root_nofollow(str(self.hop)), LID)
        root = self.ops.stage_tree(lid, ".adm-z")
        self.assertTrue((self.hop / LID / ".adm-z" / "up" / "stage").is_dir())
        self.assertEqual(stat.S_IMODE(os.stat(self.hop / LID / ".adm-z" / "up").st_mode), 0o750)
        self.assertFalse((self.hop / LID / "z").exists())
        self.assertEqual(sorted(os.listdir(self.hop / LID)), sorted([GEN, ".adm-z"]))
        self.assertIsNotNone(root)

    def test_stage_tree_needs_a_logical_id_directory(self):
        with self.assertRaises(fsops.FsOpsError):
            self.ops.stage_tree(self.tree, ".adm-q")


class RenameTests(_HopCase):

    def test_moved_dst_exists_src_gone_and_both_dirs_synced(self):
        a = self.ops.mkdir_and_pin(self.tree, "claimed", 0o750)
        (self.final().parent / "x").write_bytes(b"1")
        synced = []
        real = os.fsync

        def fsync(fd):
            synced.append(os.fstat(fd).st_ino)
            return real(fd)

        with mock.patch("router.fsops.os.fsync", fsync):
            self.assertEqual(self.ops.rename_noreplace(self.outbound, "x", a, "x"), "moved")
        self.assertEqual(synced, [os.fstat(a).st_ino, os.fstat(self.outbound).st_ino])
        (self.final().parent / "y").write_bytes(b"2")
        (self.hop / LID / GEN / "claimed" / "y").write_bytes(b"3")
        self.assertEqual(self.ops.rename_noreplace(self.outbound, "y", a, "y"), "dst_exists")
        self.assertEqual((self.final().parent / "y").read_bytes(), b"2")
        self.assertEqual(self.ops.rename_noreplace(self.outbound, "nope", a, "nope"), "src_gone")

    def test_einval_is_unsupported_with_no_fallback(self):
        def refuse(*a):
            raise OSError(errno.EINVAL, "no")

        (self.final().parent / "x").write_bytes(b"1")
        with mock.patch("router.fsops._sys_renameat2", refuse):
            with self.assertRaises(fsops.NoReplaceUnsupported):
                self.ops.rename_noreplace(self.outbound, "x", self.outbound, "z")
        self.assertFalse((self.final().parent / "z").exists())
        self.assertTrue((self.final().parent / "x").exists())


class OtherPrimitiveTests(_HopCase):

    def test_mkdir_and_pin_fsyncs_the_parent_even_when_it_exists(self):
        synced = []
        real = os.fsync

        def fsync(fd):
            synced.append(os.fstat(fd).st_ino)
            return real(fd)

        with mock.patch("router.fsops.os.fsync", fsync):
            self.ops.mkdir_and_pin(self.tree, "outbound", 0o770)
        self.assertEqual(synced, [os.fstat(self.tree).st_ino])

    def test_replace_durable_and_remove_pinned(self):
        up = self.ops.descend_pinned(self.tree, "up")
        self.ops.replace_durable(up, "versions", b"[1]", 0o640)
        self.ops.replace_durable(up, "versions", b"[1,2]", 0o640)
        self.assertEqual((self.hop / LID / GEN / "up" / "versions").read_bytes(), b"[1,2]")
        self.assertEqual([n for n in os.listdir(self.hop / LID / GEN / "up")
                          if ".tmp." in n], [])
        synced = []
        real = os.fsync

        def fsync(fd):
            synced.append(os.fstat(fd).st_ino)
            return real(fd)

        with mock.patch("router.fsops.os.fsync", fsync):
            self.ops.remove_pinned(up, "never-existed")
        self.assertEqual(synced, [os.fstat(up).st_ino], "no fsync when the name was missing")
        sub = self.ops.mkdir_and_pin(self.tree, "withdrawn", 0o750)
        (self.hop / LID / GEN / "withdrawn" / "f").write_bytes(b"x")
        self.ops.remove_pinned(self.tree, "withdrawn")
        self.assertFalse((self.hop / LID / GEN / "withdrawn").exists())
        self.assertIsNotNone(sub)

    def test_stat_owner_pinned(self):
        self.commit()
        uid, mode, kind = self.ops.stat_owner_pinned(self.outbound, "req-00000001.json")
        self.assertEqual((uid, mode, kind), (os.geteuid(), 0o640, "file"))
        self.assertEqual(self.ops.stat_owner_pinned(self.tree, "outbound")[2], "dir")
        (self.final().parent / "l").symlink_to("req-00000001.json")
        self.assertEqual(self.ops.stat_owner_pinned(self.outbound, "l")[2], "other")
        with self.assertRaises(FileNotFoundError):
            self.ops.stat_owner_pinned(self.outbound, "missing")


class ProbeTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_real_filesystem_passes_and_leaves_nothing(self):
        self.assertIn("protected_hardlinks", fsops.probe(self.dir))
        self.assertEqual(os.listdir(self.dir), [])

    def test_each_refusal(self):
        def replaces(src_fd, src, dst_fd, dst, flags):
            os.rename(src, dst, src_dir_fd=src_fd, dst_dir_fd=dst_fd)

        def einval(*a):
            raise OSError(errno.EINVAL, "no")

        def bad_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "no")

        for label, patch in (("replaces", mock.patch("router.fsops._sys_renameat2", replaces)),
                             ("einval", mock.patch("router.fsops._sys_renameat2", einval)),
                             ("dir fsync", mock.patch("router.fsops.os.fsync", bad_fsync))):
            with self.subTest(label), patch:
                with self.assertRaises(fsops.CapabilityError):
                    fsops.probe(self.dir)
                self.assertEqual(os.listdir(self.dir), [])


if __name__ == "__main__":
    unittest.main()
