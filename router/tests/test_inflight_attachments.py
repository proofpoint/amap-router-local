"""Attachments carried over the external leg (`router/inflight.py`, THE
ATTACHMENT SNAPSHOT; `router/outbound.py`, `_begin_external`).

At begin, the bytes ingest verified are copied ONCE into this router's
private state, `<gen>/inflight-snapshots/<req_id>/<i>`, before the record;
every hand-over re-proves them against the record; settlement removes the
record durably, then the snapshot; an orphan goes only on proof of its
record's absence. Damage never handed over settles as an anomaly; damage
after a hand-over holds the generation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import attachments, config as config_mod, generations, hoplink, inflight, outbound
from router.tests import helpers
from router.tests.helpers import write_request
from router.tests.test_inflight import EXT, FakeTransport, _InflightCase


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class _Att(_InflightCase):

    def submit(self, blobs, req_id="00000001"):
        descs = [helpers.attachment_descriptor(b, filename=f"a{i}.txt") for i, b in enumerate(blobs)]
        helpers.stage_outbound_sidecars(self.cfg, "alice", req_id, blobs)
        write_request(self.cfg, "alice", req_id, to=[EXT], attachments=descs)
        return descs

    def gen(self) -> Path:
        return config_mod.gen_state_dir(self.cfg, "alice")

    def snap(self, req_id="00000001") -> Path:
        return self.gen() / inflight.SNAPSHOT_DIR / req_id

    def sidecar(self, req_id="00000001") -> Path:
        return self.cfg.instances["alice"].outbox_root / f"req-{req_id}.attachments"


class _FailOnce(FakeTransport):
    """The first write raises a transient OSError (retried next poll), AFTER
    the handed marker: so the request is handed over and not yet written."""

    def __init__(self):
        super().__init__()
        self.fail = 1

    def write_request(self, n, data):
        if self.fail:
            self.fail -= 1
            raise OSError(5, "injected transient failure")
        return super().write_request(n, data)


class CarriageTests(_Att):

    def test_retry_hands_over_the_original_bytes_after_the_agent_rewrites_and_deletes(self):
        self.port = _FailOnce()
        self.submit([b"original"])
        self.drain()
        self.assertEqual(self.port.pending, {}, "control: the first write failed")
        self.assertTrue(inflight.handed_path(self.cfg, "alice", "00000001").exists())
        (self.sidecar() / "0").write_bytes(b"REWRITTEN")
        self.drain()          # (the retry may also see the rewrite; it must not matter)
        os.unlink(self.sidecar() / "0")
        self.drain()
        (n, data), = self.port.pending.items()
        self.assertEqual(json.loads(data)["attachments"],
                         [base64.b64encode(b"original").decode("ascii")])

    def test_inflight_holds_only_records_and_markers(self):
        self.submit([b"a", b"b"])
        self.drain()
        names = sorted(os.listdir(self.gen() / inflight.INFLIGHT_DIR))
        self.assertEqual(names, ["00000001.handed", "00000001.json"])
        self.assertEqual(sorted(os.listdir(self.snap())), ["0", "1"])
        for p in (self.gen() / inflight.SNAPSHOT_DIR, self.snap()):
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o700)
        for b in ("0", "1"):
            self.assertEqual(stat.S_IMODE(os.stat(self.snap() / b).st_mode), 0o600)

    def test_snapshots_change_no_frontier_list_or_status_nonregression(self):
        """Pins that snapshots stay invisible to the frontier, the record list
        and the in-flight status. NOT the placement witness: none of these
        could redden under a snapshot inside inflight/ (see
        PlacementTests)."""
        self.submit([b"a"])
        self.drain()
        before = (inflight.settled_through(self.cfg, "alice"), inflight.list_records(self.cfg, "alice"),
                  inflight.summarize(self.cfg, "alice", now="2026-10-13T00:00:00Z"))
        orphan = self.gen() / inflight.SNAPSHOT_DIR / "zz-orphan"
        orphan.mkdir(mode=0o700)
        (orphan / "0").write_bytes(b"x")
        after = (inflight.settled_through(self.cfg, "alice"), inflight.list_records(self.cfg, "alice"),
                 inflight.summarize(self.cfg, "alice", now="2026-10-13T00:00:00Z"))
        self.assertEqual(before, after)

    def test_settlement_removes_the_record_marker_and_snapshot(self):
        self.submit([b"a"])
        self.drain()
        self.assertTrue(self.snap().exists(), "control: the snapshot is there while in flight")
        self.port.send_all(recipients=[EXT])
        self.drain()
        self.assertEqual(self.result()["outcome"], "accepted")
        self.assertFalse(self.snap().exists())
        self.assertEqual(os.listdir(self.gen() / inflight.INFLIGHT_DIR), [])


class RecordShapeTests(unittest.TestCase):

    def record(self, rec_atts, draft_atts):
        return {"transport_req_id": "00000001", "recipients": [EXT], "written_ts": "t",
                "request": {"draft": {"to": [EXT], "attachments": draft_atts}},
                "attachments": rec_atts}

    def test_the_record_s_attachments_must_match_its_draft(self):
        good = {"size_bytes": 1, "sha256": _sha(b"x")}
        desc = dict(good, filename="a", media_type="t")
        inflight.check_record(self.record([good], [desc]))
        for label, rec_atts, draft_atts in (
                ("size", [dict(good, size_bytes=2)], [desc]),
                ("digest", [dict(good, sha256=_sha(b"y"))], [desc]),
                ("count", [good, good], [desc]),
                ("extra member", [dict(good, filename="a")], [desc])):
            with self.subTest(label):
                with self.assertRaises(inflight.RecordDamaged):
                    inflight.check_record(self.record(rec_atts, draft_atts))


class EffectiveCapTests(unittest.TestCase):

    def att(self, n):
        return attachments.VerifiedAttachment("f", "t", n, _sha(b"x" * n), b"x" * n)

    def test_the_per_file_cap_at_f_and_f_plus_one(self):
        attachments.check_effective_caps([self.att(5)], file_cap=5, total_cap=100)
        with self.assertRaises(attachments.AttachmentIngestError) as cm:
            attachments.check_effective_caps([self.att(6)], file_cap=5, total_cap=100)
        e = cm.exception
        self.assertEqual((e.outcome, e.reason_code, e.index, e.attachment_outcome),
                         ("queued_for_human", "attachment_too_large", 0, "too_large"))

    def test_the_total_cap_at_t_and_t_plus_one(self):
        attachments.check_effective_caps([self.att(5), self.att(5)], file_cap=5, total_cap=10)
        with self.assertRaises(attachments.AttachmentIngestError) as cm:
            attachments.check_effective_caps([self.att(5), self.att(6)], file_cap=6, total_cap=10)
        e = cm.exception
        self.assertEqual((e.outcome, e.reason_code, e.index), ("queued_for_human",
                                                                "attachment_too_large", None))


class HopCapTests(_Att):
    """At begin, the EFFECTIVE caps: here hop's is the smaller, so a file
    within RL's cap and over hop's is refused before any id is allocated.
    (Where RL's cap is the smaller, ingest has already refused the file, so
    a begin that used hop's cap alone is an EQUIVALENT mutant there.)"""

    def setUp(self):
        super().setUp()
        hop = config_mod.HopConfig(root=self.tmp / "hop", peer_uid=os.geteuid(), version_write=1,
                                   caps=dict(helpers.TEST_HOP_CAPS, attachment=4, total=6))
        self.cfg = self.cfg.__class__(**dict(self.cfg.__dict__, hop=hop))

    def test_a_file_over_the_hop_cap_is_refused_before_allocation(self):
        self.submit([b"12345"])
        counter = inflight.counter_path(self.cfg, "alice")
        before = counter.read_bytes() if counter.exists() else None
        self.drain()
        self.assertTrue(self.has_result(), "not refused at begin")
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]), ("queued_for_human", "attachment_too_large"))
        self.assertEqual(r["attachments"][0]["outcome"], "too_large")
        self.assertEqual(self.port.writes, [])
        self.assertEqual(counter.read_bytes() if counter.exists() else None, before)

    def test_files_within_the_hop_caps_are_not_refused_at_begin(self):
        """(No generation pin here, so the hand-over itself holds; what this
        pins is that begin accepted them and put them in flight.)"""
        self.submit([b"1234", b"12"])
        self.drain()
        self.assertFalse(self.has_result(), "refused at begin")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])

    def test_a_total_over_the_hop_cap_is_refused(self):
        self.submit([b"1234", b"123"])
        self.drain()
        self.assertTrue(self.has_result(), "not refused at begin")
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]), ("queued_for_human", "attachment_too_large"))
        self.assertNotIn("attachments", r)


class DamageRowTests(_Att):

    def test_damage_never_handed_over_settles_as_an_anomaly(self):
        real = inflight._effect

        def corrupt_after_snapshot(label, fn, *a, **k):
            out = real(label, fn, *a, **k)
            if label == "snapshot":
                (self.snap() / "0").write_bytes(b"tampered")
            return out
        self.submit([b"good"])
        with mock.patch.object(inflight, "_effect", corrupt_after_snapshot):
            self.drain()
        self.assertTrue(self.has_result(), "not settled: damage never handed over was held")
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"], r["detail"]),
                         ("queued_for_human", "transport_anomaly", inflight.DETAIL_SNAPSHOT_DAMAGED))
        self.assertEqual(self.port.writes, [])
        self.assertFalse(inflight.handed_path(self.cfg, "alice", "00000001").exists())
        self.assertFalse(self.snap().exists(), "the settled request's snapshot was left")

    def test_damage_after_a_hand_over_holds_the_generation(self):
        self.port = _FailOnce()
        self.submit([b"good"])
        self.drain()
        self.assertTrue(inflight.handed_path(self.cfg, "alice", "00000001").exists(), "control")
        (self.snap() / "0").write_bytes(b"tampered")
        self.drain()
        hold = hoplink.write_hold(self.cfg, "alice")
        self.assertIsNotNone(hold, "no hold: the damage after a hand-over was not held")
        self.assertEqual(hold["reason"], hoplink.HOLD_SNAPSHOT_DAMAGED)
        self.assertEqual(self.port.pending, {}, "different bytes were handed over")
        self.assertFalse(self.has_result(), "settled after a hand-over")
        self.assertTrue(inflight.record_path(self.cfg, "alice", "00000001").exists())

    def test_the_hold_reason_is_never_a_write_table_row(self):
        self.assertNotIn(hoplink.HOLD_SNAPSHOT_DAMAGED, hoplink.LATCHED_WRITE_REASONS)
        self.assertNotIn(hoplink.HOLD_SNAPSHOT_DAMAGED, hoplink.LATCHED_WRITE_REASONS.values())


class ReadBackTests(_Att):
    """`read_snapshot`, every kind of damage, against the record's own
    `attachments`. No config cap is consulted: the bound is the record's."""

    def setUp(self):
        super().setUp()
        self.data = b"0123456789"
        self.expected = [{"size_bytes": len(self.data), "sha256": _sha(self.data)}]
        self.rid = "r1"
        self.dir = self.fresh("r1")

    def fresh(self, rid):
        self.rid = rid
        inflight.write_snapshot(self.cfg, "alice", rid,
                                [attachments.VerifiedAttachment("f", "t", len(self.data),
                                                                _sha(self.data), self.data)])
        return self.gen() / inflight.SNAPSHOT_DIR / rid

    def reason(self):
        with self.assertRaises(inflight.SnapshotDamaged) as cm:
            inflight.read_snapshot(self.cfg, "alice", self.rid, self.expected)
        return cm.exception.reason

    def test_control_it_reads(self):
        self.assertEqual(inflight.read_snapshot(self.cfg, "alice", "r1", self.expected), [self.data])

    def test_a_config_cap_below_the_size_changes_nothing(self):
        import dataclasses
        low = dataclasses.replace(self.cfg, attachment_max_bytes=1, attachment_max_total_bytes=1)
        self.assertEqual(inflight.read_snapshot(low, "alice", "r1", self.expected), [self.data])

    def test_each_kind_of_damage(self):
        cases = {
            "sha256": lambda b: b.write_bytes(b"9123456789"),
            "size": lambda b: b.write_bytes(self.data + b"!"),
            "missing": lambda b: b.unlink(),
            "linked": lambda b: os.link(b, self.tmp / f"hard-{self.rid}"),
        }
        for i, (want, damage) in enumerate(cases.items()):
            with self.subTest(damage=want):
                damage(self.fresh(f"k{i}") / "0")
                self.assertEqual(self.reason(), want)

    def test_a_truncated_blob_is_size(self):
        (self.dir / "0").write_bytes(self.data[:-1])
        self.assertEqual(self.reason(), "size")

    def test_a_symlinked_blob_is_never_followed(self):
        (self.tmp / "elsewhere").write_bytes(self.data)
        (self.dir / "0").unlink()
        os.symlink(self.tmp / "elsewhere", self.dir / "0")
        self.assertEqual(self.reason(), "linked")

    def test_a_symlinked_or_plain_req_id_dir_is_never_followed(self):
        os.rename(self.dir, self.tmp / "real")
        os.symlink(self.tmp / "real", self.dir)
        self.assertEqual(self.reason(), "not_a_directory")
        self.dir.unlink()
        self.dir.write_bytes(b"not a directory")
        self.assertEqual(self.reason(), "not_a_directory")

    def test_a_symlinked_snapshot_root_is_never_followed(self):
        root = self.gen() / inflight.SNAPSHOT_DIR
        os.rename(root, self.tmp / "real-root")
        os.symlink(self.tmp / "real-root", root)
        self.assertEqual(self.reason(), "not_a_directory")


class SweepTests(_Att):

    def plant(self, name, gen=None):
        d = (gen or self.gen()) / inflight.SNAPSHOT_DIR / name
        d.mkdir(parents=True, mode=0o700)
        (d / "0").write_bytes(b"x")
        return d

    def test_an_orphan_goes_and_a_live_one_stays(self):
        self.submit([b"live"])
        self.drain()
        orphan = self.plant("00000099")
        tmp = self.plant(".tmp-r98-0123456789abcdef")
        self.assertEqual(inflight.sweep_snapshots(self.cfg, "alice"), 0)
        self.assertFalse(orphan.exists())
        self.assertFalse(tmp.exists())
        self.assertTrue(self.snap().exists(), "a live snapshot was swept")

    def test_an_uncertain_lookup_retains_and_counts(self):
        orphan = self.plant("00000099")
        inflight_dir = self.gen() / inflight.INFLIGHT_DIR
        inflight_dir.mkdir(exist_ok=True)
        os.rename(inflight_dir, self.tmp / "moved")
        os.symlink(self.tmp / "moved", inflight_dir)
        with self.assertLogs("amap_router_local", level="ERROR"):
            self.assertEqual(inflight.sweep_snapshots(self.cfg, "alice"), 1)
        self.assertTrue(orphan.exists(), "removed without proof")

    def test_a_name_of_neither_form_is_retained(self):
        odd = self.plant("-not-a-req-id")
        with self.assertLogs("amap_router_local", level="ERROR"):
            self.assertEqual(inflight.sweep_snapshots(self.cfg, "alice"), 1)
        self.assertTrue(odd.exists())

    def test_a_fenced_generation_is_swept_records_or_not(self):
        keys = dict(self.cfg.gen_keys)
        keys["alice"] = keys.get("alice", "alice") + "-fenced"
        view = generations.keyed(self.cfg, keys)
        fgen = config_mod.gen_state_dir(view, "alice")
        orphan = self.plant("00000077", gen=fgen)
        with mock.patch.object(outbound, "_fenced_views", lambda c, n: [view]):
            outbound._drain_fenced(self.cfg, "alice", None)
        self.assertFalse(orphan.exists(), "a fenced generation's orphan was not swept")


class PlacementTests(unittest.TestCase):
    """THE placement witness: the one state where a snapshot under inflight/
    would differ from one beside it. A predecessor holding ONLY an orphan
    snapshot, with no record, marker or anchor, and its counter removed: its
    successor's counter is derived as 1 (intended: an orphan, like a burned
    id, is not a handed-out id), never held."""

    def test_an_orphan_snapshot_never_counts_as_a_handed_out_id(self):
        with tempfile.TemporaryDirectory() as t:
            pred = Path(t) / "gen-a"
            snap = pred / inflight.SNAPSHOT_DIR / "00000001"
            snap.mkdir(parents=True)
            (snap / "0").write_bytes(b"x")
            self.assertFalse(generations._counter_path(pred).exists())
            try:
                got = generations._ordinary_counter(pred)
            except generations.GenerationHeld as e:
                self.fail(f"an orphan snapshot counted as a handed-out id: {e}")
            self.assertEqual(got, 1)


class ModeTests(unittest.TestCase):
    """`_mkdir_and_pin(mode=0o700)`: exactly 0700 even under a umask that
    clears OWNER bits (where only the fchmod can restore them)."""

    def test_0700_under_owner_clearing_umasks(self):
        for umask in (0o277, 0o200):
            with self.subTest(umask=oct(umask)), tempfile.TemporaryDirectory() as t:
                parent = os.open(t, os.O_RDONLY | os.O_DIRECTORY)
                old = os.umask(umask)
                try:
                    fd = attachments._mkdir_and_pin(parent, "d", mode=0o700)
                    os.close(fd)
                finally:
                    os.umask(old)
                    os.close(parent)
                self.assertEqual(stat.S_IMODE(os.stat(Path(t) / "d").st_mode), 0o700)

    def test_an_interrupted_narrower_dir_is_completed_and_a_wider_one_refused(self):
        with tempfile.TemporaryDirectory() as t:
            parent = os.open(t, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.mkdir(Path(t) / "narrow", 0o500)
                os.chmod(Path(t) / "narrow", 0o500)
                os.close(attachments._mkdir_and_pin(parent, "narrow", mode=0o700))
                self.assertEqual(stat.S_IMODE(os.stat(Path(t) / "narrow").st_mode), 0o700)
                os.mkdir(Path(t) / "wide")
                os.chmod(Path(t) / "wide", 0o755)
                with self.assertRaises(attachments.NamespaceEscapeError):
                    attachments._mkdir_and_pin(parent, "wide", mode=0o700)
            finally:
                os.close(parent)

    def test_without_mode_behaviour_is_unchanged(self):
        with tempfile.TemporaryDirectory() as t:
            parent = os.open(t, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.mkdir(Path(t) / "wide")
                os.chmod(Path(t) / "wide", 0o755)
                os.close(attachments._mkdir_and_pin(parent, "wide"))
                self.assertEqual(stat.S_IMODE(os.stat(Path(t) / "wide").st_mode), 0o755)
            finally:
                os.close(parent)


# ---------------------------------------------------------------------------
# POWER LOSS. A process crash keeps everything the kernel did; a power loss
# can also lose a namespace change whose DIRECTORY was never fsynced. The
# model (`PowerLog`): every unlink, rmdir, rename, replace and mkdir (the
# dir_fd forms included) is a change of an entry in its parent directory,
# durable once that directory is fsynced (`os.fsync` on a directory fd,
# whichever helper issued it). At a power loss after event k, an entry's
# state is the last one made durable by event k. An entry is present only if
# every directory above it is present (a non-durable mkdir, or a durable
# rmdir, takes the subtree with it; a non-durable rmdir restores the
# directory with every child whose unlink is not itself durable). File
# content: every file on these paths is fsynced before its rename, so the
# content of a present entry is the content written.
# ---------------------------------------------------------------------------

def _fd_path(fd):
    return os.readlink(f"/proc/self/fd/{fd}")


class PowerLog:

    def __init__(self):
        self.events = []      # ("ns", dir, name, present) | ("sync", dir)

    def _where(self, path, dir_fd):
        path = os.fsdecode(path)
        if dir_fd is not None:
            return _fd_path(dir_fd), path
        a = os.path.abspath(path)
        return os.path.dirname(a), os.path.basename(a)

    def patches(self):
        real = {n: getattr(os, n) for n in ("unlink", "rmdir", "rename", "replace", "mkdir", "fsync")}
        log = self

        def unlink(path, *, dir_fd=None):
            real["unlink"](path, dir_fd=dir_fd)
            log.events.append(("ns",) + log._where(path, dir_fd) + (False,))

        def rmdir(path, *, dir_fd=None):
            real["rmdir"](path, dir_fd=dir_fd)
            log.events.append(("ns",) + log._where(path, dir_fd) + (False,))

        def mkdir(path, mode=0o777, *, dir_fd=None):
            real["mkdir"](path, mode, dir_fd=dir_fd)
            log.events.append(("ns",) + log._where(path, dir_fd) + (True,))

        def _mv(kind):
            def mv(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                real[kind](src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
                log.events.append(("ns",) + log._where(src, src_dir_fd) + (False,))
                log.events.append(("ns",) + log._where(dst, dst_dir_fd) + (True,))
            return mv

        def fsync(fd):
            real["fsync"](fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                log.events.append(("sync", _fd_path(fd)))

        return [mock.patch.object(os, "unlink", unlink), mock.patch.object(os, "rmdir", rmdir),
                mock.patch.object(os, "mkdir", mkdir), mock.patch.object(os, "rename", _mv("rename")),
                mock.patch.object(os, "replace", _mv("replace")),
                mock.patch.object(os, "fsync", fsync)]

    def present_after(self, k, initial, path):
        """Whether `path` exists after a power loss following event k (0 =
        before any event), `initial` being the paths present at the start."""
        p = os.path.abspath(path)
        parts = [p]
        while os.path.dirname(parts[-1]) != parts[-1]:
            parts.append(os.path.dirname(parts[-1]))
        for q in parts[:-1]:
            if not self._entry_durable(k, initial, os.path.dirname(q), os.path.basename(q)):
                return False
        return True

    def _entry_durable(self, k, initial, d, name):
        durable = os.path.join(d, name) in initial or not any(
            e[0] == "ns" and e[1] == d and e[2] == name for e in self.events)
        pending = durable
        for e in self.events[:k]:
            if e[0] == "ns" and e[1] == d and e[2] == name:
                pending = e[3]
            elif e[0] == "sync" and e[1] == d:
                durable = pending
        return durable


def _tree(root):
    out = set()
    for base, dirs, files in os.walk(root):
        for n in dirs + files:
            out.add(os.path.abspath(os.path.join(base, n)))
    return out


class PowerLossTests(_Att):

    def run_logged(self, fn):
        log = PowerLog()
        initial = _tree(self.cfg.state_dir) | {os.path.abspath(self.cfg.state_dir)}
        ps = log.patches()
        for p in ps:
            p.start()
        try:
            fn()
        finally:
            for p in reversed(ps):
                p.stop()
        return log, initial

    def assert_never_a_record_without_its_snapshot(self, log, initial, record, snap):
        points = range(len(log.events) + 1)
        self.assertGreater(len(log.events), 4, "control: the sequence was logged")
        seen_record = False
        for k in points:
            rec = log.present_after(k, initial, record)
            seen_record |= rec
            if rec:
                self.assertTrue(log.present_after(k, initial, snap),
                                f"power loss after event {k} ({log.events[k - 1] if k else '-'}): "
                                f"a durable record without its snapshot")
        return seen_record

    def test_cleanup_power_loss_at_every_point_never_leaves_a_record_without_its_snapshot(self):
        self.submit([b"a", b"b"])
        self.drain()
        record = inflight.record_path(self.cfg, "alice", "00000001")
        handed = inflight.handed_path(self.cfg, "alice", "00000001")
        self.assertTrue(record.exists() and self.snap().exists(), "control")
        log, initial = self.run_logged(lambda: inflight._cleanup(record, handed))
        self.assertTrue(self.assert_never_a_record_without_its_snapshot(
            log, initial, record, self.snap()), "control: the record was durable at some point")
        self.assertFalse(log.present_after(len(log.events), initial, record))
        self.assertFalse(log.present_after(len(log.events), initial, self.snap()))

    def test_begin_power_loss_at_every_point_keeps_record_and_snapshot_together_nonregression(self):
        """From no inflight-snapshots/ at all. A NON-REGRESSION guard: the
        record's own durable write fsyncs the generation dir, so no current
        mutant reaches it; it reddens if the record writer ever drops that."""
        self.assertFalse((self.gen() / inflight.SNAPSHOT_DIR).exists())
        self.submit([b"a"])
        log, initial = self.run_logged(self.drain)
        record = inflight.record_path(self.cfg, "alice", "00000001")
        self.assertTrue(self.assert_never_a_record_without_its_snapshot(
            log, initial, record, self.snap()), "control: the record became durable")


if __name__ == "__main__":
    unittest.main()
