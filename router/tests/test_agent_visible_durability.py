"""The agent-visible writes are durable: `attachments._write_blob_pinned`
and `_mkdir_and_pin`, which every placement writes through (sidecars, the
message spool, the notice LAST) and which publish an outbox Result.

Asserted at the real `os.fsync`/`os.rename` boundary, with each descriptor
named through `/proc/self/fd`, as `test_util_durability.py` does for
`util.atomic_write`: a write that "succeeds" with no barrier is invisible
above it. Without these, a power loss could keep the private record that
says a notice was delivered and lose the notice."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import attachments, outbound
from router.tests.helpers import RouterTestCase, list_notices, write_request


def _target(fd):
    kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
    return kind, os.readlink(f"/proc/self/fd/{fd}")


class _Recorder:
    """Records every fsync (kind, path) and rename (final name) in order;
    `fail(target)` true raises EIO instead of syncing."""

    def __init__(self, fail=None):
        self.events = []
        self.fail = fail
        self.real_fsync, self.real_rename = os.fsync, os.rename

    def fsync(self, fd):
        t = _target(fd)
        if self.fail is not None and self.fail(t):
            raise OSError(5, "injected fsync failure")
        self.events.append(("fsync",) + t)
        return self.real_fsync(fd)

    def rename(self, src, dst, *a, **k):
        where = _target(k["dst_dir_fd"])[1] if "dst_dir_fd" in k else ""
        self.events.append(("rename", os.path.join(where, str(dst))))
        return self.real_rename(src, dst, *a, **k)

    def patched(self):
        return [mock.patch("router.attachments.os.fsync", self.fsync),
                mock.patch("router.attachments.os.rename", self.rename)]


@unittest.skipUnless(os.path.isdir("/proc/self/fd"), "needs /proc/self/fd")
class BlobBarrierTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))

    def _write(self, rec):
        fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with rec.patched()[0], rec.patched()[1]:
                attachments._write_blob_pinned(fd, "f.json", b"new")
        finally:
            os.close(fd)

    def test_file_fsync_then_rename_then_directory_fsync(self):
        rec = _Recorder()
        self._write(rec)
        kinds = [(e[0], e[1]) for e in rec.events]
        self.assertEqual(kinds, [("fsync", "file"), ("rename", str(self.root / "f.json")),
                                 ("fsync", "dir")])
        self.assertEqual(rec.events[2][2], str(self.root))
        self.assertEqual((self.root / "f.json").read_bytes(), b"new")

    def test_a_failed_file_fsync_never_publishes(self):
        rec = _Recorder(fail=lambda t: t[0] == "file")
        with self.assertRaises(OSError):
            self._write(rec)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [],
                         "a name was published, or the temp was left behind")

    def test_a_failed_directory_fsync_raises_published_not_durable(self):
        rec = _Recorder(fail=lambda t: t[0] == "dir")
        with self.assertRaises(attachments.PublishedNotDurable):
            self._write(rec)
        self.assertEqual((self.root / "f.json").read_bytes(), b"new",
                         "control: the name was published before the barrier failed")

    def test_a_directory_is_made_durable_in_its_parent_created_or_not(self):
        for exists in (False, True):
            with self.subTest(exists=exists):
                if exists:
                    (self.root / "d").mkdir(exist_ok=True)
                rec = _Recorder()
                fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with rec.patched()[0], rec.patched()[1]:
                        os.close(attachments._mkdir_and_pin(fd, "d"))
                finally:
                    os.close(fd)
                self.assertIn(("fsync", "dir", str(self.root)), rec.events)


@unittest.skipUnless(os.path.isdir("/proc/self/fd"), "needs /proc/self/fd")
class PlacementIsDurableTests(RouterTestCase):
    """A real delivery: the notice file is fsynced before it is renamed into
    place and its directory after, and a failed barrier on the notice leaves
    the request unanswered (it is replayed), never answered over a notice
    that might not survive."""

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"])

    def test_the_notice_is_synced_before_and_after_its_rename(self):
        rec = _Recorder()
        with rec.patched()[0], rec.patched()[1]:
            outbound.drain_instance(self.cfg, "alice")
        (notice,) = list_notices(self.cfg, "bob")
        notices = os.path.realpath(str(self.cfg.instances["bob"].inbox_root / "notices"))
        at = rec.events.index(("rename", os.path.join(notices, notice)))
        self.assertEqual(rec.events[at - 1][:2], ("fsync", "file"))
        self.assertEqual(rec.events[at + 1], ("fsync", "dir", notices))

    def test_a_failed_barrier_on_the_notice_directory_leaves_the_request_unanswered(self):
        notices = os.path.realpath(str(self.cfg.instances["bob"].inbox_root / "notices"))
        rec = _Recorder(fail=lambda t: t == ("dir", notices))
        with rec.patched()[0], rec.patched()[1]:
            outbound.drain_instance(self.cfg, "alice")
        self.assertFalse((self.cfg.instances["alice"].outbox_root / "results"
                          / "00000001.json").exists(),
                         "answered over a notice whose directory entry was not made durable")
        outbound.drain_instance(self.cfg, "alice")
        self.assertEqual(len(list_notices(self.cfg, "bob")), 1)


if __name__ == "__main__":
    unittest.main()


class _FailOnce:
    """A `_Recorder.fail` predicate: true for the FIRST fsync of `target` only."""

    def __init__(self, target):
        self.target, self.fired = target, 0

    def __call__(self, t):
        if t == self.target and not self.fired:
            self.fired += 1
            return True
        return False


@unittest.skipUnless(os.path.isdir("/proc/self/fd"), "needs /proc/self/fd")
class ResultPublicationIsDurableTests(RouterTestCase):
    """The outbox Result (`_publish_result_and_archive`). A Result whose
    directory barrier failed is visible but may not survive, so the request
    is NOT archived: the next poll re-publishes it from the private result
    (nothing is delivered or handed over again) and only then archives it.
    The archive rename is followed by a barrier on `processed/` and then on
    the outbox."""

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"])
        self.outbox = Path(os.path.realpath(str(self.cfg.instances["alice"].outbox_root)))

    def drain(self, rec):
        with rec.patched()[0], rec.patched()[1]:
            return outbound.drain_instance(self.cfg, "alice")

    def test_a_result_not_made_durable_is_left_unarchived_then_resumed(self):
        fail = _FailOnce(("dir", str(self.outbox / "results")))
        self.drain(_Recorder(fail=fail))
        self.assertEqual(fail.fired, 1, "control: the results/ barrier was injected")
        result = self.outbox / "results" / "00000001.json"
        self.assertTrue(result.exists(), "control: the Result was published before the barrier")
        self.assertTrue((self.outbox / "req-00000001.json").exists(),
                        "archived over a Result that might not survive")
        self.assertFalse((self.outbox / "processed" / "req-00000001.json").exists())
        published = result.read_bytes()
        rec = _Recorder()
        self.drain(rec)
        self.assertIn(("fsync", "dir", str(self.outbox / "results")), rec.events,
                      "the resume did not re-establish the Result's durability")
        self.assertTrue((self.outbox / "processed" / "req-00000001.json").exists())
        self.assertFalse((self.outbox / "req-00000001.json").exists())
        self.assertEqual(result.read_bytes(), published, "the resume changed the Result")
        self.assertEqual(len(list_notices(self.cfg, "bob")), 1, "delivered again on the resume")

    def test_the_archive_rename_is_followed_by_both_directory_barriers(self):
        rec = _Recorder()
        self.drain(rec)
        at = rec.events.index(("rename", str(self.outbox / "processed" / "req-00000001.json")))
        self.assertEqual(rec.events[at + 1:at + 3],
                         [("fsync", "dir", str(self.outbox / "processed")),
                          ("fsync", "dir", str(self.outbox))])

    def test_a_failed_archive_barrier_is_logged_and_the_request_stays_answered(self):
        fail = _FailOnce(("dir", str(self.outbox / "processed")))
        with self.assertLogs("amap_router_local", level="WARNING") as cm:
            self.drain(_Recorder(fail=fail))
        self.assertEqual(fail.fired, 1, "control: the processed/ barrier was injected")
        self.assertTrue(any("was not made durable" in r.getMessage() for r in cm.records))
        self.assertTrue((self.outbox / "processed" / "req-00000001.json").exists())
        self.assertTrue((self.outbox / "results" / "00000001.json").exists())


@unittest.skipUnless(os.path.isdir("/proc/self/fd"), "needs /proc/self/fd")
class ExternalLegResultIsDurableTests(RouterTestCase):
    """The same rule on the external leg: a Result settled from the
    downstream runtime whose barrier failed is re-published from the private
    result, and the request is never handed over again."""

    def setUp(self):
        super().setUp()
        from router.tests.test_inflight import EXT, FakeTransport, _external
        self.ext, self.policy = EXT, _external
        self.cfg = self.make_config({"alice": []})
        self.port = FakeTransport()
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.outbox = Path(os.path.realpath(str(self.cfg.instances["alice"].outbox_root)))

    def drain(self, rec):
        with rec.patched()[0], rec.patched()[1]:
            return outbound.drain_instance(self.cfg, "alice", transport=self.port,
                                           cold_policy=self.policy)

    def test_a_settled_result_not_made_durable_is_made_durable_before_it_is_archived(self):
        """The settle step leaves the request unarchived; the same poll's
        listing then finds the anchor and resumes it: the Result's barrier
        succeeds BEFORE the archive rename, and nothing is handed over again."""
        self.drain(_Recorder())
        self.assertEqual(self.port.writes, ["00000001"])
        self.port.send_all(recipients=[self.ext])
        fail = _FailOnce(("dir", str(self.outbox / "results")))
        rec = _Recorder(fail=fail)
        self.drain(rec)
        self.assertEqual(fail.fired, 1, "control: the results/ barrier was injected")
        archive = ("rename", str(self.outbox / "processed" / "req-00000001.json"))
        self.assertIn(archive, rec.events, "control: the request was archived")
        synced = ("fsync", "dir", str(self.outbox / "results"))
        self.assertIn(synced, rec.events[:rec.events.index(archive)],
                      "archived before the Result was made durable")
        self.drain(_Recorder())
        self.assertEqual(self.port.writes, ["00000001"], "handed over again")
        doc = json.loads((self.outbox / "results" / "00000001.json").read_text())
        self.assertEqual(doc["outcome"], "accepted")
