"""router/tests/test_reset.py — `router.reset`: wiping an instance's
mailbox CONTENTS and its router-private state together, to a clean slate.

The two hazards a mailbox-only wipe would create (and this module exists
to close) are pinned end-to-end here, not just unit-by-unit: `req_id`
reuse against a stale private digest (`router/outbound.py`'s
`REASON_REQ_ID_REUSED`, `test_req_id_reuse.py`) and a stale first-sight
snapshot quarantining a genuinely-new post-reset file
(`router/firstsight.py`, `test_quarantine.py`). Also covered: the mailbox
ROOTS and skeleton leaves are never deleted (only emptied — they are
the host's live bind-mount sources in `handoff_dir` mode), the containment
abort is truly all-or-nothing (a batch of many names, or a single one),
and a crash between the state-clear and mailbox-empty halves leaves a
fail-closed (never a poisoned) intermediate that a second `reset` run
completes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router import firstsight, outbound, reset
from router.__main__ import main
from router.provision import provision
from router.tests.helpers import (
    RouterTestCase, attachment_descriptor, inbound_sidecar_dir, list_notices, messages_dir,
    notices_dir, outbound_sidecar_dir, read_json, result_path, stage_outbound_sidecars,
    write_request,
)
from router.util import NamespaceEscapeError


class TestResetCleanSlate(RouterTestCase):
    """Claim 3 from the ask, end to end: mailbox and router-private state
    must be cleared TOGETHER, or the clean slate is poisoned."""

    def test_no_req_id_reuse_after_reset_even_with_the_same_id(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"], body_text="first")
        outbound.drain_instance(cfg, "alice")
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

        reset.reset_instance(cfg, "alice")
        # Reset puts the instance back to never-seen; this drain is the new
        # first sight and snapshots an outbox that reset left empty.
        self.assertFalse(firstsight.has_been_seen(cfg.state_dir, "alice"))
        self.assertEqual(outbound.drain_instance(cfg, "alice")["first_sight"], 1)

        # Same id the connector's own restarted-at-0 counter would reuse,
        # genuinely DIFFERENT content — must be accepted, never
        # `req_id_reused` (that trap is exactly what a mailbox-only wipe
        # would spring: see `outbound.py`'s private results anchor).
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"], body_text="second, different")
        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["outbound_req_id_reused"], 0)
        self.assertEqual(summary["accepted"], 1)
        result = read_json(result_path(cfg, "alice", "00000000"))
        self.assertEqual(result["outcome"], "accepted")

    def test_stale_snapshot_cleared_new_file_under_old_name_is_not_quarantined(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"], body_text="pre-staged")
        outbound.drain_instance(cfg, "alice")  # first sight: {req-00000000.json}
        snapshot = firstsight.read_marker(cfg.state_dir, "alice")["outbox_snapshot"]
        self.assertEqual(len(snapshot), 1)

        reset.reset_instance(cfg, "alice")
        # Reset is the documented remedy for a stale snapshot: the marker is
        # gone, so this drain is a fresh first sight over the now-empty outbox.
        outbound.drain_instance(cfg, "alice")

        write_request(cfg, "alice", "00000000", to=["agent.bob@local"], body_text="genuinely new")
        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["quarantined"], 0)
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(len(list_notices(cfg, "bob")), 1)


class TestResetWhatMovesWhatStays(RouterTestCase):
    def test_populated_instance_swept_but_roots_and_leaves_survive(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff", seen=False)
        # alice only ever SENDS in this scenario — provision first so her
        # own inbox skeleton (notices/, messages/) exists too, exactly as
        # a real bring-up would (`router provision alice`), rather than
        # this test's mailbox-side assertions accidentally depending on
        # alice having received mail.
        provision(cfg, "alice", create=True)
        inst = cfg.instances["alice"]
        inbox_root, outbox_root = inst.inbox_root, inst.outbox_root

        # First sight with an empty outbox, so the request below is an
        # ordinary send rather than a quarantined pre-staged one.
        outbound.drain_instance(cfg, "alice")
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        # Strays reset must sweep without being told their names in advance.
        sidecar_dir = outbox_root / "req-00000000.attachments"
        sidecar_dir.mkdir()
        (sidecar_dir / "a.txt").write_text("x")
        stray_inbox_file = inbox_root / "stray.txt"
        stray_inbox_file.write_text("y")

        # Inode snapshot of everything that must survive, as a mount-
        # preservation proxy (a real bind mount would be a different
        # device/inode pair on the host; a temp-dir test can only assert
        # "same inode, never recreated").
        survivors = {
            "inbox_root": inbox_root, "outbox_root": outbox_root,
            "notices": inbox_root / "notices", "messages": inbox_root / "messages",
            "results": outbox_root / "results", "processed": outbox_root / "processed",
        }
        inodes_before = {k: p.stat().st_ino for k, p in survivors.items()}

        summary = reset.reset_instance(cfg, "alice")

        self.assertTrue(summary["was_seen"])
        self.assertTrue(summary["mailbox_available"])
        self.assertGreater(summary["state_removed"], 0)
        self.assertGreater(summary["mailbox_removed"], 0)

        # Router-private state gone.
        self.assertFalse(firstsight.marker_path(cfg.state_dir, "alice").is_file())
        self.assertFalse((cfg.state_dir / "alice" / "results").exists())
        self.assertFalse(firstsight.has_been_seen(cfg.state_dir, "alice"))

        # Agent-visible artifacts gone.
        self.assertFalse(stray_inbox_file.exists())
        self.assertFalse(sidecar_dir.exists())
        self.assertEqual(list(notices_dir(cfg, "alice").iterdir()), [])
        self.assertEqual(list(messages_dir(cfg, "alice").iterdir()), [])
        self.assertEqual(list((outbox_root / "results").iterdir()), [])
        self.assertEqual(list((outbox_root / "processed").iterdir()), [])

        # Roots + the four skeleton leaves: same directories, never
        # recreated — the inode proves it, not just "a dir happens to
        # exist there again."
        for k, p in survivors.items():
            self.assertEqual(p.stat().st_ino, inodes_before[k], f"{k} was recreated, not preserved")

        # v2.2.0: this optional leaf is never manufactured by reset either.
        self.assertFalse((inbox_root / "notices" / "processed").exists())


class TestResetAttachmentSidecarDirs(RouterTestCase):
    """Requirement 8: `reset` must clear the new attachment artifacts on
    BOTH sides. Structurally already covered by the generic mailbox sweep
    (no new code in `reset.py` — see `attachments.py`'s module docstring
    and `router/README.md`'s "Attachment transport" section): an outbound
    `req-<id>.attachments/` dir is an ordinary non-keep direct entry of
    `outbox_root`, and an inbound `<notice-id>.attachments/` dir lives
    INSIDE the `notices` skeleton leaf, whose contents are purged
    recursively either way. This test proves it end-to-end with a REAL
    delivered attachment, not just a synthetic stray directory."""

    def test_inbound_sidecar_dir_and_blob_are_cleared_messages_leaf_survives(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        data = b"attachment bytes that must be gone after reset"
        desc = attachment_descriptor(data)
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"], attachments=[desc])
        stage_outbound_sidecars(cfg, "alice", "00000000", [data])
        outbound.drain_instance(cfg, "alice")

        notice_name = list_notices(cfg, "bob")[0]
        notice_id = notice_name[len("notice-"):-len(".json")]
        side_dir = inbound_sidecar_dir(cfg, "bob", notice_id)
        self.assertTrue((side_dir / "0").is_file())
        self.assertEqual((side_dir / "0").read_bytes(), data)

        messages_leaf = messages_dir(cfg, "bob")
        messages_ino_before = messages_leaf.stat().st_ino

        summary = reset.reset_instance(cfg, "bob")
        self.assertGreater(summary["mailbox_removed"], 0)

        self.assertFalse(side_dir.exists())
        self.assertEqual(list(messages_leaf.iterdir()), [])
        # the leaf itself survives (same inode) — only its contents go.
        self.assertEqual(messages_leaf.stat().st_ino, messages_ino_before)

    def test_outbound_sidecar_dir_from_a_held_attachment_request_is_cleared(self):
        """A request held for a policy cap (count/size) never gets its
        sidecar dir opened, but the dir may still exist on disk (the agent
        wrote it before the router ever looked) — `reset` must sweep it
        like any other stray outbox entry."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        oversized = attachment_descriptor(b"x")
        oversized["size_bytes"] = cfg.attachment_max_bytes + 1
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"], attachments=[oversized])
        side_dir = outbound_sidecar_dir(cfg, "alice", "00000000")
        side_dir.mkdir(parents=True)
        (side_dir / "0").write_bytes(b"never opened by the router")

        outbound.drain_instance(cfg, "alice")
        result = read_json(result_path(cfg, "alice", "00000000"))
        self.assertEqual(result["reason_code"], "attachment_too_large")

        # the cleanup call in `_publish_result_and_archive` already swept
        # it post-drain — confirm reset ALSO would if it hadn't (recreate
        # a stray one to prove reset's own sweep independently).
        stray = outbound_sidecar_dir(cfg, "alice", "99999999")
        stray.mkdir(parents=True)
        (stray / "0").write_bytes(b"stray debris")

        reset.reset_instance(cfg, "alice")
        self.assertFalse(side_dir.exists())
        self.assertFalse(stray.exists())


class TestResetContainmentAbort(RouterTestCase):
    """A namespace escape must abort the WHOLE call, deleting nothing —
    neither state nor mailbox, for the offending instance OR any other
    instance named in the same batch."""

    def test_symlinked_inbox_root_namespace_mode_deletes_nothing(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        provision(cfg, "alice", create=True)
        first_seen_marker = firstsight.marker_path(cfg.state_dir, "alice")
        self.assertTrue(first_seen_marker.is_file())
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])

        inbox_root = cfg.instances["alice"].inbox_root
        outside = self.tmp / "outside-alice-inbox"
        outside.mkdir()
        shutil.rmtree(inbox_root)
        os.symlink(outside, inbox_root)

        with self.assertRaises(NamespaceEscapeError):
            reset.reset_instance(cfg, "alice")

        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(first_seen_marker.is_file())
        self.assertTrue((cfg.instances["alice"].outbox_root / "req-00000000.json").exists())

    def test_symlinked_outbox_results_leaf_handoff_mode_deletes_nothing(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        first_seen_marker = firstsight.marker_path(cfg.state_dir, "alice")
        self.assertTrue(first_seen_marker.is_file())
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])

        outbox_root = cfg.instances["alice"].outbox_root
        (outbox_root / "results").mkdir(exist_ok=True)
        outside = self.tmp / "outside-alice-results"
        outside.mkdir()
        shutil.rmtree(outbox_root / "results")
        os.symlink(outside, outbox_root / "results")

        with self.assertRaises(NamespaceEscapeError):
            reset.reset_instance(cfg, "alice")

        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(first_seen_marker.is_file())
        self.assertTrue((outbox_root / "req-00000000.json").exists())

    def test_batch_abort_protects_every_named_instance_not_just_the_escaping_one(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        write_request(cfg, "bob", "00000000", to=["agent.alice@local"])
        bob_marker = firstsight.marker_path(cfg.state_dir, "bob")
        self.assertTrue(bob_marker.is_file())

        alice_inbox = cfg.instances["alice"].inbox_root
        outside = self.tmp / "outside-alice-inbox-batch"
        outside.mkdir()
        shutil.rmtree(alice_inbox)
        os.symlink(outside, alice_inbox)

        # alice (escaping) listed BEFORE bob (clean) — with the escaping
        # instance listed first, this alone would pass even WITHOUT a
        # batch-wide pre-probe (a per-instance-only check would already
        # stop before ever reaching bob). See
        # `test_batch_abort_protects_the_earlier_instance_when_a_LATER_one_escapes`
        # below for the case that actually pins the stronger guarantee —
        # every instance probed before any of them is touched, regardless
        # of list order.
        with self.assertRaises(NamespaceEscapeError):
            reset.reset_instances(cfg, ["alice", "bob"])

        self.assertTrue(bob_marker.is_file())
        self.assertTrue((cfg.instances["bob"].outbox_root / "req-00000000.json").exists())

    def test_batch_abort_protects_the_earlier_instance_when_a_later_one_escapes(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])
        alice_marker = firstsight.marker_path(cfg.state_dir, "alice")
        self.assertTrue(alice_marker.is_file())

        bob_inbox = cfg.instances["bob"].inbox_root
        outside = self.tmp / "outside-bob-inbox-batch"
        outside.mkdir()
        shutil.rmtree(bob_inbox)
        os.symlink(outside, bob_inbox)

        # bob (escaping) listed AFTER alice (clean) — this is the case
        # that actually distinguishes a batch-wide pre-probe from a
        # per-instance-only check: without the pre-probe,
        # `reset_instances` would reset alice successfully FIRST (she's
        # clean) and only discover bob's escape afterward, leaving
        # alice's first-sight marker and outbox already gone despite the
        # batch as a whole having "failed."
        with self.assertRaises(NamespaceEscapeError):
            reset.reset_instances(cfg, ["alice", "bob"])

        self.assertTrue(alice_marker.is_file())
        self.assertTrue((cfg.instances["alice"].outbox_root / "req-00000000.json").exists())


class TestResetOrderingAndCrashSafety(RouterTestCase):
    def test_state_cleared_before_mailbox_and_mid_crash_is_fail_closed(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        # Provision first so alice's mailbox skeleton exists on BOTH sides
        # even though she only sends here — otherwise her never-created
        # inbox side would make `mailbox_available` False and this test
        # would exercise only the state half of reset.
        provision(cfg, "alice", create=True)
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        call_order = []
        real_clear_state = reset._clear_state

        def tracking_clear_state(cfg_, name):
            call_order.append("state")
            return real_clear_state(cfg_, name)

        def raising_empty_mailboxes(cfg_, name):
            call_order.append("mailbox")
            raise RuntimeError("simulated crash mid-reset")

        with mock.patch.object(reset, "_clear_state", tracking_clear_state), \
             mock.patch.object(reset, "_empty_mailboxes", raising_empty_mailboxes):
            with self.assertRaises(RuntimeError):
                reset.reset_instance(cfg, "alice")

        self.assertEqual(call_order, ["state", "mailbox"])

        # Fail-closed midpoint: the marker is already gone, so the instance
        # is back to never-seen. The next drain re-snapshots rather than
        # draining against half-cleared private state — and anything sitting
        # in the outbox when it arrives is quarantined, not delivered.
        self.assertFalse(firstsight.has_been_seen(cfg.state_dir, "alice"))
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        resumed = outbound.drain_instance(cfg, "alice")
        self.assertEqual(resumed["first_sight"], 1)
        self.assertEqual(resumed["quarantined"], 1)
        self.assertEqual(resumed["accepted"], 0)

        # Mailbox side was never reached.
        self.assertTrue(
            (cfg.instances["alice"].outbox_root / "results" / "00000000.json").exists()
        )

        # Re-running (unpatched) completes the job.
        reset.reset_instance(cfg, "alice")
        self.assertFalse(
            (cfg.instances["alice"].outbox_root / "results" / "00000000.json").exists()
        )

    def test_concurrent_drain_between_first_state_clear_and_mailbox_empty_is_caught_by_resweep(self):
        """Defect: 'state, then mailbox' alone is fail-closed against a
        CRASH (pinned above) but not against a concurrent `run`/`once`
        poll — one that read the (still-valid) first-sight marker a moment
        before this reset's first `_clear_state` call removes it can go
        on to write a brand-new private result anchor for some OTHER
        req_id WHILE `_empty_mailboxes` is running. Simulated here by
        hooking `_empty_mailboxes` itself to perform exactly that write,
        mid-reset, before delegating to the real implementation."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        real_empty_mailboxes = reset._empty_mailboxes
        stale_id = "00000099"

        def racing_empty_mailboxes(cfg_, name_):
            private_path = cfg_.state_dir / name_ / "results" / f"{stale_id}.json"
            private_path.parent.mkdir(parents=True, exist_ok=True)
            private_path.write_text('{"digest": "deadbeef", "result": {"outcome": "accepted"}}')
            return real_empty_mailboxes(cfg_, name_)

        with mock.patch.object(reset, "_empty_mailboxes", racing_empty_mailboxes):
            reset.reset_instance(cfg, "alice")

        # The re-sweep caught it — nothing left in state_dir at all.
        self.assertFalse((cfg.state_dir / "alice" / "results").exists())

        # End-to-end: without the re-sweep, this stale anchor would have
        # survived and poisoned the first post-reset send that reuses its
        # id, exactly like the trap `reset` exists to prevent (see
        # `TestResetCleanSlate`).
        outbound.drain_instance(cfg, "alice")  # post-reset first sight, empty outbox
        write_request(cfg, "alice", stale_id, to=["agent.bob@local"], body_text="genuinely new")
        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["outbound_req_id_reused"], 0)
        self.assertEqual(summary["accepted"], 1)


class TestResetMailboxTOCTOU(RouterTestCase):
    def test_leaf_swapped_to_escaping_symlink_mid_removal_never_touches_the_swap_target(self):
        """Defect: check-then-act on PATHS is not atomic. This models the
        proven attack: an already-pinned skeleton leaf (`outbox/results`)
        is renamed to a symlink pointing OUTSIDE the instance root in the
        gap between reset pinning it (via an `O_NOFOLLOW`-opened `dir_fd`)
        and enumerating/removing its contents. A vulnerable, path-based
        implementation re-resolves `leaf / entry_name` at removal time and
        would delete through the new symlink; the `dir_fd`-pinned engine
        must keep operating on the ORIGINAL directory's inode regardless.

        The swap is injected by patching `os.scandir`, triggered
        specifically on the call whose fd's (device, inode) identifies it
        as the pinned `outbox/results` directory — checked by `os.fstat`,
        not by filename, since `state_dir/<name>/results/` (the
        router-private idempotency anchor, cleared earlier in the SAME
        `reset_instance` call via `shutil.rmtree`, which on this platform
        also walks by fd) happens to use the identical `<req_id>.json`
        naming and would otherwise be indistinguishable by content alone.
        """
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        result_file = result_path(cfg, "alice", "00000000")
        self.assertTrue(result_file.is_file())

        outbox_root = cfg.instances["alice"].outbox_root
        victim_dir = self.tmp / "victim-outside-root"
        victim_dir.mkdir()
        (victim_dir / "victim.txt").write_text("must survive")

        # An independent observer fd, pinned to the REAL `results/`
        # directory BEFORE the race — used both to identify the correct
        # `os.scandir` call (by device/inode, via `os.fstat`) and, after
        # reset runs, to verify the original inode's content was actually
        # removed (checking via the live `results` PATH after the swap
        # would just follow the new symlink and prove nothing).
        parent_fd = os.open(str(outbox_root), os.O_RDONLY | os.O_DIRECTORY)
        observer_fd = os.open("results", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        target_stat = os.fstat(observer_fd)
        target_key = (target_stat.st_dev, target_stat.st_ino)

        real_scandir = os.scandir
        swapped = {"done": False}

        def racing_scandir(fd):
            if not swapped["done"] and isinstance(fd, int):
                try:
                    same = (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == target_key
                except OSError:
                    same = False
                if same:
                    swapped["done"] = True
                    # The attacker's move: swap the LIVE PATH out from
                    # under the fd reset already pinned. A real attack
                    # does this via `rename()` from a separate process;
                    # doing it in-process, after the pin but before
                    # enumeration, is the deterministic equivalent.
                    shutil.rmtree(outbox_root / "results", ignore_errors=True)
                    os.symlink(victim_dir, outbox_root / "results")
            return real_scandir(fd)

        try:
            with mock.patch("os.scandir", racing_scandir):
                summary = reset.reset_instance(cfg, "alice")
        finally:
            pass

        self.assertTrue(swapped["done"], "the race never triggered — test isn't exercising the gap")

        # The swap target was never touched.
        self.assertEqual([p.name for p in victim_dir.iterdir()], ["victim.txt"])

        # The ORIGINAL (pinned) directory's real content was actually
        # removed, via our independent observer fd on the same inode —
        # not merely unreachable because the path now points elsewhere.
        remaining = sorted(e.name for e in os.scandir(observer_fd))
        os.close(observer_fd)
        os.close(parent_fd)
        self.assertEqual(remaining, [])

        self.assertGreater(summary["mailbox_removed"], 0)


class TestResetHalfPresentMailbox(RouterTestCase):
    def test_agent_deleted_outbox_root_still_empties_the_surviving_inbox_side(self):
        """Defect: the two mailbox roots must be probed and emptied
        INDEPENDENTLY. Under `namespace` mode the agent owns both roots
        and can delete or replace just one of them (here: its own
        `outbox_root`) — the other, still-present side must still be
        emptied and reported as such, never silently skipped because the
        pair isn't BOTH present."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="namespace")
        write_request(cfg, "bob", "00000000", to=["agent.alice@local"])
        outbound.drain_instance(cfg, "bob")
        self.assertEqual(len(list_notices(cfg, "alice")), 1)

        # alice's outbox_root exists (she's never sent, but `namespace`
        # mode is agent-owned end to end, so she can create/delete it at
        # will) — create it, then delete it, to model "was present, now
        # gone" rather than "never existed."
        cfg.instances["alice"].outbox_root.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(cfg.instances["alice"].outbox_root)

        summary = reset.reset_instance(cfg, "alice")
        self.assertTrue(summary["inbox_available"])
        self.assertFalse(summary["outbox_available"])
        self.assertFalse(summary["mailbox_available"])
        self.assertEqual(list_notices(cfg, "alice"), [])


class TestResetStateDirSymlinkGuard(RouterTestCase):
    def test_symlinked_instance_state_dir_is_left_alone(self):
        """Defect (hardening — `state_dir` is never agent-reachable in a
        real deployment, `config.py` enforces that at load): if
        `state_dir/<name>` has itself become a symlink, `reset` must
        refuse to descend through it rather than trusting `is_dir()`,
        which follows symlinks transparently."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        firstsight.record_first_sight(cfg, "alice")
        real_state_dir = cfg.state_dir / "alice"
        self.assertTrue(real_state_dir.is_dir())

        decoy = self.tmp / "decoy-state"
        decoy.mkdir()
        (decoy / "first-seen.json").write_text("not a real first-sight marker")
        moved = self.tmp / "real-alice-state-moved"
        shutil.move(str(real_state_dir), str(moved))
        os.symlink(decoy, real_state_dir)

        reset.reset_instance(cfg, "alice")

        self.assertTrue(real_state_dir.is_symlink())
        self.assertTrue((decoy / "first-seen.json").is_file())


class TestResetNonFileFirstSightMarker(RouterTestCase):
    def test_directory_shaped_first_sight_marker_is_still_swept(self):
        """Defect: excluding the 'rest of state_dir' listing by identity
        with the marker path (rather than by membership in what was
        actually already collected/removed) let a non-regular-file
        `first-seen.json` — here, a directory sitting where the marker
        should be — survive a reset entirely."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        first_seen_marker = firstsight.marker_path(cfg.state_dir, "alice")
        first_seen_marker.parent.mkdir(parents=True, exist_ok=True)
        first_seen_marker.mkdir()
        (first_seen_marker / "junk").write_text("x")

        reset.reset_instance(cfg, "alice")

        self.assertFalse(first_seen_marker.exists())


class TestResetPlanAndDryRun(RouterTestCase):
    def _tree_snapshot(self, cfg):
        """Sorted (relative path, is_dir, size) triples over `state_dir`
        and every instance's declared root — a byte-identical-before/after
        proxy for `--dry-run` touching nothing at all."""
        snap = []
        bases = [cfg.state_dir] + [inst.root for inst in cfg.instances.values()]
        for base in bases:
            if not base.exists():
                continue
            for p in sorted(base.rglob("*")):
                try:
                    size = p.stat().st_size if p.is_file() else None
                except OSError:
                    size = None
                snap.append((str(p.relative_to(self.tmp)), p.is_dir(), size))
        return snap

    def test_dry_run_plan_matches_reality_and_touches_nothing(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        before = self._tree_snapshot(cfg)
        plan = reset.plan_reset(cfg, "alice")
        after = self._tree_snapshot(cfg)

        self.assertEqual(before, after)
        self.assertTrue(plan.was_seen)
        self.assertTrue(plan.mailbox_available)
        self.assertTrue(any(p.name == "first-seen.json" for p in plan.state_paths))
        self.assertEqual(plan.state_paths[0].name, "first-seen.json")  # unlinked FIRST
        self.assertTrue(plan.mailbox_paths)  # at least the notice/message/results/processed entries

    def test_unknown_instance_refused_by_plan_and_execute(self):
        cfg = self.make_config({"alice": []})
        with self.assertRaises(reset.ResetError):
            reset.plan_reset(cfg, "mallory")
        with self.assertRaises(reset.ResetError):
            reset.reset_instance(cfg, "mallory")

    def test_plan_resets_names_every_unknown_instance_at_once(self):
        cfg = self.make_config({"alice": []})
        with self.assertRaises(reset.ResetError) as ctx:
            reset.plan_resets(cfg, ["alice", "mallory", "carol"])
        msg = str(ctx.exception)
        self.assertIn("mallory", msg)
        self.assertIn("carol", msg)


class TestResetHandoffRootsNeverLaunched(RouterTestCase):
    def test_missing_handoff_pair_clears_state_creates_no_dirs(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff", seen=False)
        firstsight.record_first_sight(cfg, "alice")
        inst = cfg.instances["alice"]
        # Stand in for "the host has never created this sandbox" — undo the
        # fixture's own pre-creation of the pair.
        shutil.rmtree(inst.inbox_root)
        shutil.rmtree(inst.outbox_root)

        summary = reset.reset_instance(cfg, "alice")

        self.assertTrue(summary["was_seen"])
        self.assertFalse(summary["mailbox_available"])
        self.assertGreater(summary["state_removed"], 0)
        self.assertEqual(summary["mailbox_removed"], 0)
        self.assertFalse(firstsight.has_been_seen(cfg.state_dir, "alice"))
        self.assertFalse(inst.inbox_root.exists())
        self.assertFalse(inst.outbox_root.exists())  # reset never creates the host's dirs


class TestResetIdempotence(RouterTestCase):
    def test_second_reset_on_an_already_clean_instance_is_a_noop(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000000", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        summary1 = reset.reset_instance(cfg, "alice")
        self.assertGreater(summary1["state_removed"] + summary1["mailbox_removed"], 0)

        summary2 = reset.reset_instance(cfg, "alice")
        self.assertEqual(summary2["state_removed"], 0)
        self.assertEqual(summary2["mailbox_removed"], 0)
        self.assertFalse(summary2["was_seen"])


class TestResetCLI(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.state_dir = self.tmp / "state"
        self.alice_ns = self.tmp / "instances" / "alice"
        self.bob_ns = self.tmp / "instances" / "bob"
        for ns in (self.alice_ns, self.bob_ns):
            ns.mkdir(parents=True, exist_ok=True)
        self.config_path = self.tmp / "config.json"
        self.config_path.write_text(json.dumps({
            "state_dir": str(self.state_dir),
            "instances": {
                "alice": {"namespace": str(self.alice_ns), "peers": ["bob"]},
                "bob": {"namespace": str(self.bob_ns), "peers": ["alice"]},
            },
        }))

    def tearDown(self) -> None:
        self._tmp_ctx.cleanup()

    def _run(self, *args: str):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--config", str(self.config_path), *args])
        return code, out.getvalue(), err.getvalue()

    def _mark_seen(self) -> None:
        """One `once` is all it takes now — the poll itself records first
        sight for every instance, which is what leaves a marker for `reset`
        to find. There is no operator command in this path any more."""
        code, _, _ = self._run("once")
        self.assertEqual(code, 0)

    def _marker(self, name: str) -> Path:
        return self.state_dir / name / "first-seen.json"

    def test_missing_yes_refuses_and_deletes_nothing(self):
        self._mark_seen()
        self.assertTrue(self._marker("alice").is_file())

        code, _, err = self._run("reset", "alice")
        self.assertEqual(code, 1)
        self.assertIn("--yes", err)
        self.assertTrue(self._marker("alice").is_file())

    def test_yes_executes_and_says_the_marker_is_gone(self):
        self._mark_seen()
        code, out, _ = self._run("reset", "alice", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("no first-sight marker now", out)
        self.assertIn("alice", out)
        self.assertFalse(self._marker("alice").exists())

    def test_unknown_name_alongside_valid_one_rejects_batch_valid_untouched(self):
        self._mark_seen()

        code, _, err = self._run("reset", "alice", "mallory", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("mallory", err)
        self.assertTrue(self._marker("alice").is_file())

    def test_all_resets_every_configured_instance(self):
        self._mark_seen()
        code, out, _ = self._run("reset", "--all", "--yes")
        self.assertEqual(code, 0)
        self.assertFalse(self._marker("alice").exists())
        self.assertFalse(self._marker("bob").exists())

    def test_all_and_explicit_names_together_rejected(self):
        code, _, err = self._run("reset", "--all", "alice", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("--all", err)

    def test_no_names_and_no_all_rejected(self):
        code, _, err = self._run("reset")
        self.assertEqual(code, 1)

    def test_dry_run_lists_and_deletes_nothing(self):
        self._mark_seen()
        code, out, _ = self._run("reset", "alice", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("dry-run", out)
        self.assertIn("first-seen.json", out)
        self.assertTrue(self._marker("alice").is_file())


if __name__ == "__main__":
    unittest.main()
