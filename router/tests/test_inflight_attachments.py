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
import errno
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

    def _blob_open_fails(self, err):
        real = os.open

        def failing(path, flags, *a, **k):
            if (k.get("dir_fd") is not None and path == "0" and not flags & os.O_DIRECTORY
                    and inflight.SNAPSHOT_DIR in _fd_path(k["dir_fd"])):
                raise OSError(err, os.strerror(err))
            return real(path, flags, *a, **k)
        return mock.patch.object(os, "open", failing)

    def test_a_transient_error_never_handed_over_neither_settles_nor_holds(self):
        """EMFILE or EIO on the blob open is not damage: nothing is settled,
        nothing is held, and the next poll hands over."""
        for err in (errno.EMFILE, errno.EIO):
            with self.subTest(errno=errno.errorcode[err]):
                self.tearDown()
                self.setUp()
                self.submit([b"good"])
                with self._blob_open_fails(err):
                    self.drain()
                self.assertFalse(self.has_result(), "a transient error settled the request")
                self.assertIsNone(hoplink.write_hold(self.cfg, "alice"), "a transient error held")
                self.assertEqual(self.port.writes, [])
                self.drain()
                self.assertEqual(self.port.writes, ["00000001"], "the retry did not hand over")

    def test_a_transient_error_after_a_hand_over_neither_settles_nor_holds(self):
        for err in (errno.EMFILE, errno.EIO):
            with self.subTest(errno=errno.errorcode[err]):
                self.tearDown()
                self.setUp()
                self.port = _FailOnce()
                self.submit([b"good"])
                self.drain()
                self.assertTrue(inflight.handed_path(self.cfg, "alice", "00000001").exists())
                with self._blob_open_fails(err):
                    self.drain()
                self.assertFalse(self.has_result(), "a transient error settled the request")
                self.assertIsNone(hoplink.write_hold(self.cfg, "alice"), "a transient error held")
                self.drain()
                self.assertIn("00000001", self.port.pending, "the retry did not hand over")

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

    def fenced_view(self):
        """A generation directory of its own (another state root), so the
        current generation's sweep can never be what reaches it."""
        import dataclasses
        other = self.tmp / "fenced-state"
        other.mkdir()
        view = dataclasses.replace(self.cfg, state_dir=other)
        self.assertNotEqual(config_mod.gen_state_dir(view, "alice"), self.gen())
        return view

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

    def test_a_fenced_generation_s_uncertain_count_reaches_the_summary(self):
        view = self.fenced_view()
        self.plant("-odd-name", gen=config_mod.gen_state_dir(view, "alice"))
        with mock.patch.object(outbound, "_fenced_views", lambda c, n: [view]), \
                self.assertLogs("amap_router_local", level="ERROR"):
            summary = self.drain()
        self.assertEqual(summary.get("snapshot_sweep_uncertain"), 1,
                         "the fenced generation's uncertain count did not reach the summary")

    def test_a_fenced_generation_is_swept_records_or_not(self):
        view = self.fenced_view()
        fgen = config_mod.gen_state_dir(view, "alice")
        orphan = self.plant("00000077", gen=fgen)
        with mock.patch.object(outbound, "_fenced_views", lambda c, n: [view]):
            outbound._drain_fenced(self.cfg, "alice", None)
        self.assertFalse(orphan.exists(), "a fenced generation's orphan was not swept")


def _not_owned(target_name):
    """`inflight._own_dir` as it answers for a directory another uid owns,
    for the one directory named `target_name` (no root in CI)."""
    real = inflight._own_dir

    def own(fd):
        return False if os.path.basename(_fd_path(fd)) == target_name else real(fd)
    return mock.patch.object(inflight, "_own_dir", own)


class ForeignOwnerTests(_Att):
    """No destructive path lists or deletes a directory this uid does not
    own: the begin leftover rule raises (retried next poll), the sweep
    retains and counts, cleanup leaves it for the sweep."""

    def plant(self, name):
        d = self.gen() / inflight.SNAPSHOT_DIR / name
        d.mkdir(parents=True, mode=0o700)
        (d / "0").write_bytes(b"x")
        return d

    def test_the_sweep_keeps_a_foreign_req_dir_and_counts_it(self):
        orphan = self.plant("00000099")
        with _not_owned("00000099"), self.assertLogs("amap_router_local", level="ERROR"):
            self.assertEqual(inflight.sweep_snapshots(self.cfg, "alice"), 1)
        self.assertTrue((orphan / "0").exists(), "a foreign directory was emptied")

    def test_the_sweep_keeps_a_foreign_temp_dir(self):
        tmp = self.plant(".tmp-r98-0123456789abcdef")
        with _not_owned(".tmp-r98-0123456789abcdef"), \
                self.assertLogs("amap_router_local", level="ERROR"):
            self.assertEqual(inflight.sweep_snapshots(self.cfg, "alice"), 1)
        self.assertTrue((tmp / "0").exists())

    def test_cleanup_leaves_a_foreign_snapshot_root(self):
        self.submit([b"a"])
        self.drain()
        record = inflight.record_path(self.cfg, "alice", "00000001")
        with _not_owned(inflight.SNAPSHOT_DIR), self.assertLogs("amap_router_local", level="ERROR"):
            inflight._cleanup(record, inflight.handed_path(self.cfg, "alice", "00000001"))
        self.assertFalse(record.exists(), "control: the record went")
        self.assertTrue((self.snap() / "0").exists(), "a foreign snapshot root was descended")

    def test_cleanup_leaves_a_foreign_req_dir(self):
        self.submit([b"a"])
        self.drain()
        record = inflight.record_path(self.cfg, "alice", "00000001")
        with _not_owned("00000001"), self.assertLogs("amap_router_local", level="ERROR"):
            inflight._cleanup(record, inflight.handed_path(self.cfg, "alice", "00000001"))
        self.assertTrue((self.snap() / "0").exists())

    def test_begin_refuses_a_foreign_leftover(self):
        leftover = self.plant("00000001")
        self.submit([b"a"])
        with _not_owned("00000001"):
            self.drain()
        self.assertFalse(self.has_result(), "settled instead of retried")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [], "a record was begun")
        self.assertTrue((leftover / "0").exists(), "a foreign leftover was emptied")


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
# can also lose a namespace change whose DIRECTORY was never fsynced. A
# directory's entries become durable exactly when that directory is fsynced,
# so the model (`PowerLog`) records, at every `os.fsync` of a directory fd
# (whichever helper issued it), that directory's ACTUAL listing. After a
# power loss at any point, a directory holds its LAST FSYNCED listing (its
# listing at the start, if it existed then and was never fsynced since; none
# at all, if it is new and never fsynced). An entry survives only if every
# directory above it survives: a non-durable mkdir, or a durable rmdir, takes
# the subtree with it, and a non-durable rmdir restores the directory with
# its children as last fsynced. Points between two fsyncs share one durable
# state, so enumerating the point after EVERY directory fsync is exhaustive.
#
# Reading listings at the barrier, rather than intercepting unlink, rename
# and mkdir, sees a change however it was made: Python 3.9's pathlib calls
# `os.unlink` through an accessor captured at import (`_NormalAccessor`), so
# a patched `os.unlink` never sees `Path.unlink` there, and a model built on
# interception would miss the record's own unlink on 3.9 alone.
# File content: every file on these paths is fsynced before its rename.
# ---------------------------------------------------------------------------

def _fd_path(fd):
    return os.readlink(f"/proc/self/fd/{fd}")


class PowerLog:

    def __init__(self, root):
        self.syncs = []            # [(dir, frozenset(names))], in order
        self.initial = {}          # dir -> frozenset(names), at the start
        for base, dirs, files in os.walk(root):
            self.initial[os.path.abspath(base)] = frozenset(dirs + files)

    def patches(self):
        real = os.fsync
        log = self

        def fsync(fd):
            real(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                log.syncs.append((_fd_path(fd), frozenset(os.listdir(fd))))
        return [mock.patch.object(os, "fsync", fsync)]

    def listing(self, k, d):
        """`d`'s durable listing after a power loss following the k-th
        directory fsync (0: before any)."""
        last = None
        for sd, names in self.syncs[:k]:
            if sd == d:
                last = names
        if last is not None:
            return last
        return self.initial.get(d, frozenset())

    def present_after(self, k, path):
        p = os.path.realpath(path)
        chain = []
        while os.path.dirname(p) != p:
            chain.append((os.path.dirname(p), os.path.basename(p)))
            p = os.path.dirname(p)
        for d, name in chain:
            if d not in self.initial and not any(sd == d for sd, _ in self.syncs) \
                    and os.path.realpath(d) == d and self._outside(d):
                continue          # above the logged tree: durable by assumption
            if name not in self.listing(k, d):
                return False
        return True

    def _outside(self, d):
        return not any(d == r or d.startswith(r + os.sep) for r in self.initial)


class PowerLossTests(_Att):

    def run_logged(self, fn):
        log = PowerLog(os.path.realpath(self.cfg.state_dir))
        ps = log.patches()
        for p in ps:
            p.start()
        try:
            fn()
        finally:
            for p in reversed(ps):
                p.stop()
        return log

    def assert_never_a_record_without_its_snapshot(self, log, record, snap):
        self.assertGreaterEqual(len(log.syncs), 2, "control: the barriers were logged")
        seen_record = False
        for k in range(len(log.syncs) + 1):
            rec = log.present_after(k, record)
            seen_record |= rec
            if rec:
                self.assertTrue(log.present_after(k, snap),
                                f"power loss after directory fsync {k} "
                                f"({log.syncs[k - 1][0] if k else '-'}): "
                                f"a durable record without its snapshot")
        return seen_record

    def test_cleanup_power_loss_at_every_point_never_leaves_a_record_without_its_snapshot(self):
        self.submit([b"a", b"b"])
        self.drain()
        record = inflight.record_path(self.cfg, "alice", "00000001")
        handed = inflight.handed_path(self.cfg, "alice", "00000001")
        self.assertTrue(record.exists() and self.snap().exists(), "control")
        log = self.run_logged(lambda: inflight._cleanup(record, handed))
        self.assertTrue(log.present_after(0, record) and log.present_after(0, self.snap()),
                        "control: both durable before cleanup")
        self.assert_never_a_record_without_its_snapshot(log, record, self.snap())
        last = len(log.syncs)
        self.assertFalse(log.present_after(last, record), "control: the record durably gone")
        self.assertFalse(log.present_after(last, self.snap()), "control: the snapshot durably gone")

    def test_begin_power_loss_at_every_point_keeps_record_and_snapshot_together_nonregression(self):
        """From no inflight-snapshots/ at all. A NON-REGRESSION guard: the
        record's own durable write fsyncs the generation dir, so no current
        mutant reaches it; it reddens if the record writer ever drops that."""
        self.assertFalse((self.gen() / inflight.SNAPSHOT_DIR).exists())
        self.submit([b"a"])
        log = self.run_logged(self.drain)
        record = inflight.record_path(self.cfg, "alice", "00000001")
        self.assertTrue(self.assert_never_a_record_without_its_snapshot(log, record, self.snap()),
                        "control: the record became durable")

    def test_the_model_sees_a_change_however_it_was_made(self):
        """The model reads listings at the barrier, so a change made through
        ANY entry point is seen: here an unlink made through a reference to
        `os.unlink` captured BEFORE the model's patches, exactly as Python
        3.9's pathlib accessor holds one (the 3.9-only CI failure this
        replaced). Not durable until its directory is fsynced; durable
        after."""
        d = Path(os.path.realpath(self.tmp)) / "pl"
        d.mkdir()
        f = d / "x"
        f.write_bytes(b"1")
        captured_unlink = os.unlink
        log = PowerLog(str(d.parent))
        ps = log.patches()
        for p in ps:
            p.start()
        try:
            captured_unlink(str(f))
            pfd = os.open(str(d.parent), os.O_RDONLY | os.O_DIRECTORY)   # another dir
            try:
                os.fsync(pfd)
            finally:
                os.close(pfd)
            fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            for p in reversed(ps):
                p.stop()
        self.assertTrue(log.present_after(1, f), "an unsynced unlink counted as durable")
        self.assertFalse(log.present_after(2, f), "a synced unlink not seen")


if __name__ == "__main__":
    unittest.main()
