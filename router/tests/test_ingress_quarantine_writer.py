"""The ingress quarantine WRITER: `quarantine`'s frozen item format, one item
per journal key, create-if-absent (an identical item is adopted, a different
or damaged one is a conflict, never overwritten)."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from router import ingress, quarantine

LID = "lid-a"
GEN = "1" * 32
LINK = "link-a"
NID = "1700000000-42"
DIGESTS = {"notice": "a" * 64, "spool": "b" * 64, "hop": "c" * 64,
           "attachments": ["d" * 64, None]}
TS = "2026-10-13T00:00:00Z"


class WriterTests(unittest.TestCase):

    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name)
        self.key = ingress.key_for("notice", LINK, GEN, NID)
        self.qdir = self.state / LID / f"gen-{GEN}" / quarantine.DIR_NAME
        self.path = self.qdir / f"{ingress.quarantine_item_id(self.key)}.json"

    def write(self, cause=quarantine.CAUSE_LATE_INBOUND, now=TS, **kw):
        try:
            return ingress.write_quarantine_item(self.state, LID, GEN, "notice", LINK, NID,
                                                 cause, digests=kw.pop("digests", DIGESTS),
                                                 now=now, **kw)
        except (ingress.QuarantineConflict, ValueError) as e:
            self.fail(f"refused: {e!r}")

    def conflict(self, **kw):
        with self.assertRaises(Exception) as cm:
            ingress.write_quarantine_item(self.state, LID, GEN, "notice", LINK, NID,
                                          quarantine.CAUSE_LATE_INBOUND,
                                          digests=kw.pop("digests", DIGESTS),
                                          now=kw.pop("now", TS), **kw)
        self.assertIsInstance(cm.exception, ingress.QuarantineConflict)
        self.assertEqual(cm.exception.reason, "quarantine_item_conflict")

    def items(self):
        return ingress.quarantine_items(self.state, LID, "a", GEN, days=14)

    def test_the_item_id_is_derived_from_the_key(self):
        self.assertEqual(ingress.quarantine_item_id(self.key),
                         __import__("hashlib").sha256(self.key.encode()).hexdigest()[:32])

    def test_the_written_item_is_in_the_frozen_format_and_private(self):
        self.assertEqual(self.write(), "created")
        doc = json.loads(self.path.read_bytes())
        quarantine.check_item(doc, item_id=self.path.stem, generation=GEN,
                              now=quarantine._now(None))
        self.assertEqual(doc["causes"], ["late_inbound"])
        self.assertEqual(doc["arrival_ts"], TS)
        self.assertEqual(stat.S_IMODE(os.lstat(self.path).st_mode), 0o600)
        self.assertEqual(os.lstat(self.path).st_nlink, 1)
        self.assertEqual(os.listdir(self.qdir), [self.path.name])

    def test_the_probe_returns_what_was_written(self):
        self.write()
        (got,) = self.items()
        self.assertIsNone(got["damaged"])
        self.assertEqual(got["entry_id"], NID)
        self.assertEqual(got["cause"], "late_inbound")
        self.assertEqual(got["arrived_at"], TS)
        self.assertEqual(got["digests"], DIGESTS)

    def test_five_presentations_give_one_item(self):
        self.assertEqual(self.write(), "created")
        for k in range(4):
            # A later observation must not move the arrival time.
            self.assertEqual(self.write(now=f"2026-10-13T00:0{k + 1}:00Z"), "adopted")
        self.assertEqual(len(self.items()), 1)
        self.assertEqual(self.items()[0]["arrived_at"], TS)

    def test_a_different_item_is_a_conflict_and_is_kept(self):
        self.write()
        before = self.path.read_bytes()
        self.conflict(digests=dict(DIGESTS, notice="e" * 64))
        self.assertEqual(self.path.read_bytes(), before)

    def test_a_damaged_item_is_a_conflict_and_is_kept(self):
        self.qdir.mkdir(parents=True)
        self.path.write_bytes(b"{not json")
        self.conflict()
        self.assertEqual(self.path.read_bytes(), b"{not json")

    def test_no_stray_name_is_left_in_the_quarantine(self):
        self.write()
        self.write(now="2026-10-13T00:05:00Z")
        self.assertEqual(os.listdir(self.qdir), [self.path.name])
        self.assertEqual([i for i in self.items() if i["damaged"]], [])

    def test_a_cause_outside_the_vocabulary_is_refused_before_writing(self):
        with self.assertRaises(ValueError):
            ingress.write_quarantine_item(self.state, LID, GEN, "notice", LINK, NID,
                                          "policy", digests=DIGESTS, now=TS)
        self.assertFalse(self.qdir.exists() and os.listdir(self.qdir))

    def test_a_long_attachment_list_keeps_count_and_aggregate(self):
        many = dict(DIGESTS, attachments=["f" * 64] * 20)
        self.write(digests=many)
        (got,) = self.items()
        self.assertIsNone(got["digests"]["attachments"])
        self.assertEqual(got["evidence"]["snapshot_attachments_count"], 20)
        self.assertEqual(len(got["evidence"]["snapshot_attachments_sha256"]), 64)

    def test_no_snapshot_means_no_digests(self):
        self.write(digests=None, extra_evidence={"refusal": "notice_invalid"})
        (got,) = self.items()
        self.assertIsNone(got["digests"])
        self.assertEqual(got["evidence"]["refusal"], "notice_invalid")


if __name__ == "__main__":
    unittest.main()
