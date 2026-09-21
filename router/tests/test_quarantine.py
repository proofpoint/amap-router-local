"""router/tests/test_quarantine.py — the staged-request quarantine itself.

A request whose FILENAME was already sitting in `outbox_root` at the moment
this router FIRST SAW the instance is never delivered, whatever its content,
whatever its mtime, however it's disguised — see `router/firstsight.py`'s
module docstring for the exact guarantee and its explicit limit.

`approve` is retired, so the snapshot is no longer taken by an operator
command: `drain_instance` takes it itself, before draining anything, on the
first poll that sees the root. Tests here that only need "already staged when
the router arrived" therefore just drain. Tests that need to act in the window
BETWEEN the snapshot and the drain — a rewrite, a symlink swap, a chmod —
call `firstsight.record_first_sight` explicitly first; the drain then finds
the marker already written and does not re-snapshot, which is the same
idempotence `approve` had.

That the drain takes the snapshot AT ALL is pinned in `test_first_sight.py`,
not here."""

import json
import os
import stat
import unittest

from router import firstsight, outbound
from router.outbound import REASON_QUARANTINED
from router.tests.helpers import (
    RouterTestCase, list_notices, processed_path, read_json, result_path, write_request,
)


class TestQuarantine(RouterTestCase):
    def test_pre_staged_request_is_quarantined_never_delivered(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        # Staged BEFORE this router ever saw the root — exactly the
        # passive-tier scenario: the host's per-workspace config (even one
        # committed to a repo) can create the handoff pair and pre-stage this
        # with no prompt ever shown.
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="pre-staged")

        # No operator step: the drain itself snapshots first, then refuses
        # what the snapshot named.
        summary = outbound.drain_instance(cfg, "alice")

        self.assertEqual(summary["first_sight"], 1)
        self.assertEqual(summary["quarantined"], 1)
        self.assertEqual(summary["rejected"], 1)
        self.assertEqual(summary["drained"], 1)

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], REASON_QUARANTINED)

        # Archived like any other governed outcome — never left un-answered.
        self.assertTrue(processed_path(cfg, "alice", "00000001").is_file())
        # Never delivered anywhere.
        self.assertEqual(list_notices(cfg, "bob"), [])

        # A router-private preserved copy exists for the operator.
        q_dir = cfg.state_dir / "alice" / "quarantine"
        preserved = q_dir / "req-00000001.json"
        self.assertTrue(preserved.is_file())
        preserved_doc = json.loads(preserved.read_text(encoding="utf-8"))
        self.assertEqual(preserved_doc["draft"]["body_text"], "pre-staged")
        sidecar = json.loads((q_dir / "req-00000001.json.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(sidecar["req_id"], "00000001")
        self.assertIsNotNone(sidecar["snapshot_digest"])
        self.assertEqual(sidecar["snapshot_digest"], sidecar["current_digest"])

    def test_request_written_after_first_sight_delivers_normally(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        first = outbound.drain_instance(cfg, "alice")  # nothing staged: empty snapshot
        self.assertEqual(first["first_sight"], 1)

        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        summary = outbound.drain_instance(cfg, "alice")

        self.assertEqual(summary["first_sight"], 0, "the snapshot was retaken")
        self.assertEqual(summary["quarantined"], 0)
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

    def test_redrop_same_quarantined_filename_same_bytes_replays_rejection(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        req_path = write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        raw = req_path.read_bytes()

        outbound.drain_instance(cfg, "alice")  # first sight: snapshots, then quarantines
        first = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(first["reason_code"], REASON_QUARANTINED)

        # Re-drop the identical bytes under the same filename (e.g. a naive resync).
        outbox_root = cfg.instances["alice"].outbox_root
        (outbox_root / "req-00000001.json").write_bytes(raw)
        summary2 = outbound.drain_instance(cfg, "alice")

        self.assertEqual(summary2["outbound_resumed"], 1)
        second = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(second, first)
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_redrop_same_filename_different_bytes_is_req_id_reused_not_delivered(self):
        """A quarantined filename never even reaches `_drain_one`, so once
        the ORIGINAL bytes have been processed once (establishing the
        private anchor), a resubmission under the SAME filename with
        DIFFERENT content goes through the ordinary req_id-reuse path
        (`outbound.py`'s existing machinery) — not a second quarantine
        decision. Either way, it is never delivered."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="first")
        outbound.drain_instance(cfg, "alice")

        write_request(
            cfg, "alice", "00000001", to=["agent.bob@local"], body_text="different bytes",
        )
        summary2 = outbound.drain_instance(cfg, "alice")

        self.assertEqual(summary2["outbound_req_id_reused"], 1)
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["reason_code"], "req_id_reused")
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_snapshot_named_file_rewritten_before_first_drain_still_quarantined(self):
        """Content rewritten AFTER the snapshot but BEFORE the first drain,
        under the SAME snapshot-named filename, is still quarantined — the
        check is filename membership, never a content/digest match against
        the snapshot. The digest carried in the snapshot is for operator
        forensics (the sidecar), not for deciding whether to quarantine.

        The snapshot is taken explicitly here to open that window: in
        production it and the drain are one call, and an agent that rewrites
        between them wins nothing either way."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="original")
        firstsight.record_first_sight(cfg, "alice")

        # Rewrite the SAME filename's bytes before the router ever drains it.
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="rewritten")

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["quarantined"], 1)
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["reason_code"], REASON_QUARANTINED)
        self.assertEqual(list_notices(cfg, "bob"), [])

        sidecar = json.loads(
            (cfg.state_dir / "alice" / "quarantine" / "req-00000001.json.meta.json")
            .read_text(encoding="utf-8")
        )
        # The digest of what was actually quarantined differs from the
        # snapshot's original digest — recorded for the operator, but it
        # never changes the outcome: filename membership alone decided.
        self.assertNotEqual(sidecar["snapshot_digest"], sidecar["current_digest"])

    def test_new_filename_after_first_sight_is_not_quarantined(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        firstsight.record_first_sight(cfg, "alice")
        write_request(cfg, "alice", "00000002", to=["agent.bob@local"])

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["quarantined"], 1)  # 00000001
        self.assertEqual(summary["accepted"], 1)  # 00000002
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

    def test_staged_symlink_later_swapped_for_a_regular_file_is_quarantined(self):
        """A symlink named `req-*.json` sitting in the outbox at first
        sight must still block that NAME from delivery even after it's
        later replaced by an ordinary regular file — `_snapshot_outbox`
        must never skip an entry just because it's a symlink at the
        instant the snapshot is taken."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        outbox_root = cfg.instances["alice"].outbox_root
        outbox_root.mkdir(parents=True, exist_ok=True)
        target = self.tmp / "symlink-target.json"
        target.write_bytes(b'{"not": "a real request"}')
        staged = outbox_root / "req-00000001.json"
        os.symlink(target, staged)

        doc, _ = firstsight.record_first_sight(cfg, "alice")
        self.assertEqual([e["filename"] for e in doc["outbox_snapshot"]], ["req-00000001.json"])

        # Swap the symlink out for a genuine regular file under the SAME name.
        staged.unlink()
        write_request(
            cfg, "alice", "00000001", to=["agent.bob@local"],
            body_text="STAGED BY A REPO BEFORE FIRST SIGHT (via symlink swap)",
        )

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["quarantined"], 1)
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["reason_code"], REASON_QUARANTINED)
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_staged_directory_later_replaced_by_a_file_is_quarantined(self):
        """Same guarantee for a directory staged under a `req-*.json`-
        shaped name: `outbound.list_outbound` would never have opened a
        directory, but the NAME still must be treated as pre-staged once
        it's replaced by a real request file."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        outbox_root = cfg.instances["alice"].outbox_root
        staged_dir = outbox_root / "req-00000001.json"
        staged_dir.mkdir(parents=True, exist_ok=True)

        doc, _ = firstsight.record_first_sight(cfg, "alice")
        self.assertEqual([e["filename"] for e in doc["outbox_snapshot"]], ["req-00000001.json"])

        staged_dir.rmdir()
        write_request(
            cfg, "alice", "00000001", to=["agent.bob@local"],
            body_text="STAGED BY A REPO BEFORE FIRST SIGHT (via directory swap)",
        )

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["quarantined"], 1)
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["reason_code"], REASON_QUARANTINED)
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_staged_unreadable_file_restored_afterward_is_quarantined(self):
        """A regular file that is unreadable (e.g. `chmod 000`) at the
        exact moment the snapshot is taken must still be quarantined once
        permissions are restored — mtime/permissions are agent-
        controllable under posture A (the agent owns `outbox_root`), so
        "unreadable right now" must never mean "not in the outbox."."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        req_path = write_request(
            cfg, "alice", "00000001", to=["agent.bob@local"],
            body_text="STAGED BY A REPO BEFORE FIRST SIGHT (chmod 000)",
        )
        original_mode = req_path.stat().st_mode
        req_path.chmod(0)
        try:
            doc, _ = firstsight.record_first_sight(cfg, "alice")
        finally:
            req_path.chmod(stat.S_IMODE(original_mode))

        self.assertEqual([e["filename"] for e in doc["outbox_snapshot"]], ["req-00000001.json"])
        self.assertIsNone(doc["outbox_snapshot"][0]["sha256"])

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["quarantined"], 1)
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["reason_code"], REASON_QUARANTINED)
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_the_snapshot_includes_symlinks_directories_and_unreadable_entries(self):
        """The marker's `outbox_snapshot` — and the entry count first sight
        logs with it — must include every `req-*.json`-shaped name regardless
        of type/readability. An operator reading that line after the fact must
        not be told fewer entries were staged than actually were."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        outbox_root = cfg.instances["alice"].outbox_root
        outbox_root.mkdir(parents=True, exist_ok=True)

        target = self.tmp / "symlink-target-2.json"
        target.write_bytes(b"{}")
        os.symlink(target, outbox_root / "req-00000001.json")
        (outbox_root / "req-00000002.json").mkdir()
        unreadable = write_request(cfg, "alice", "00000003", to=["agent.bob@local"])
        original_mode = unreadable.stat().st_mode
        unreadable.chmod(0)
        try:
            doc, _ = firstsight.record_first_sight(cfg, "alice")
        finally:
            unreadable.chmod(stat.S_IMODE(original_mode))

        self.assertEqual(
            sorted(e["filename"] for e in doc["outbox_snapshot"]),
            ["req-00000001.json", "req-00000002.json", "req-00000003.json"],
        )

    def test_quarantine_in_handoff_mode(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff", seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["quarantined"], 1)
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["reason_code"], REASON_QUARANTINED)
        self.assertEqual(list_notices(cfg, "bob"), [])
        preserved = cfg.state_dir / "alice" / "quarantine" / "req-00000001.json"
        self.assertTrue(preserved.is_file())


if __name__ == "__main__":
    unittest.main()
