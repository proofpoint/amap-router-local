"""Concurrent-swap tests for the v3.0.0 write-side path discipline fix
(contract sec 2, lines 89-162; ROUTER-SECURITY.md Findings 1 and 2).

Every write this router makes into an agent-owned namespace now resolves
its full parent chain exactly once, via a pinned (`O_NOFOLLOW`-opened)
`dir_fd` chain from the instance's declared `root`, and acts (`renameat`)
off that SAME descriptor — never by re-resolving a path string for the
act. The tests below prove that directly, two ways:

  - DETERMINISTIC: a monkeypatched hook fires the instant
    `attachments._mkdir_and_pin` pins the directory in question — the
    exact moment `verify_namespace_containment` + a path-based write used
    to leave a window between "checked" and "acted on" (ROUTER-SECURITY.md
    Finding 1/2's shape). The hook renames that just-pinned directory
    aside and puts a symlink to a VICTIM instance's own mailbox in its
    place, then lets the real write proceed. If the write is truly pinned
    by descriptor rather than by name, the bytes land in the renamed-aside
    original directory — never through the new symlink, and never in the
    victim's mailbox — on every single run, not merely on average.
  - STRESS: a background thread continuously flips `outbox_root/processed`
    between a real directory and a symlink to a victim's outbox while the
    main thread drains a fresh request every iteration, for N iterations —
    real concurrent pressure, not an interposed hook. Because correctness
    here no longer depends on winning a timing race (the fix removes the
    race rather than narrowing it), the invariant must hold on EVERY
    iteration, not just most of them.
"""

from __future__ import annotations

import os
import shutil
import threading
import unittest
from unittest import mock

from router import attachments as attachments_mod
from router import deliver, outbound
from router.tests.helpers import RouterTestCase, write_request


def _interpose_mkdir_and_pin(target_name, on_pin):
    """Return `(hook, state)`. `hook` is a drop-in replacement for
    `attachments._mkdir_and_pin` that calls the REAL implementation first
    (so the directory is genuinely created/pinned exactly as production
    code would), then — the FIRST time it is called for `target_name` —
    invokes `on_pin()` before returning the already-obtained fd. `on_pin`
    is exactly where a swap happens: AFTER the pin, before whatever the
    caller does with the returned descriptor next, which is the precise
    window the contract's leg (a)+(b) exist to close."""
    real = attachments_mod._mkdir_and_pin
    state = {"done": False}

    def hook(parent_fd, name):
        fd = real(parent_fd, name)
        if name == target_name and not state["done"]:
            state["done"] = True
            on_pin()
        return fd

    return hook, state


class TestConcurrentSwapDeterministic(RouterTestCase):
    def test_processed_archive_swap_between_pin_and_rename_never_touches_victim(self):
        """Finding 1 (identity forgery via `outbound/processed`), closed:
        swap `processed` for a symlink into a VICTIM's own outbox in the
        exact window between the pin and the archive `renameat`. The
        archived request must land in the pinned original directory,
        never through the symlink into mallory's outbox — no forged
        `from:` is possible if the bytes never arrive there at all."""
        cfg = self.make_config({
            "alice": ["bob"], "bob": ["alice"], "mallory": ["alice"],
        })
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        alice_outbox = cfg.instances["alice"].outbox_root
        mallory_outbox = cfg.instances["mallory"].outbox_root
        mallory_outbox.mkdir(parents=True, exist_ok=True)

        def swap():
            os.rename(alice_outbox / "processed", alice_outbox / "processed.orig")
            os.symlink(mallory_outbox, alice_outbox / "processed")

        hook, state = _interpose_mkdir_and_pin("processed", swap)
        with mock.patch.object(attachments_mod, "_mkdir_and_pin", side_effect=hook):
            summary = outbound.drain_instance(cfg, "alice")

        self.assertTrue(state["done"], "swap hook never fired — test didn't exercise the race window")
        self.assertEqual(summary["accepted"], 1)

        # mallory's outbox — the swap TARGET — received nothing at all.
        self.assertEqual(list(mallory_outbox.iterdir()), [])
        # The archive landed in the pinned ORIGINAL directory (now named
        # "processed.orig" on disk, since the swap renamed it aside), not
        # through the symlink that now sits at the name "processed".
        self.assertTrue((alice_outbox / "processed.orig" / "req-00000001.json").is_file())
        self.assertTrue((alice_outbox / "processed").is_symlink())

    def test_results_write_swap_between_pin_and_write_never_touches_victim(self):
        """W4 — Finding 1's posture-independent twin: the SAME
        check-then-act shape on `outbound/results`, closed the same way."""
        cfg = self.make_config({
            "alice": ["bob"], "bob": ["alice"], "mallory": ["alice"],
        })
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        alice_outbox = cfg.instances["alice"].outbox_root
        mallory_outbox = cfg.instances["mallory"].outbox_root
        mallory_outbox.mkdir(parents=True, exist_ok=True)

        def swap():
            os.rename(alice_outbox / "results", alice_outbox / "results.orig")
            os.symlink(mallory_outbox, alice_outbox / "results")

        hook, state = _interpose_mkdir_and_pin("results", swap)
        with mock.patch.object(attachments_mod, "_mkdir_and_pin", side_effect=hook):
            summary = outbound.drain_instance(cfg, "alice")

        self.assertTrue(state["done"], "swap hook never fired — test didn't exercise the race window")
        self.assertEqual(summary["accepted"], 1)

        self.assertEqual(list(mallory_outbox.iterdir()), [])
        self.assertTrue((alice_outbox / "results.orig" / "00000001.json").is_file())
        self.assertTrue((alice_outbox / "results").is_symlink())
        # The archive step (which runs after the results write, same
        # call) still completes normally against its OWN pinned chain —
        # this swap didn't touch `processed` at all.
        self.assertTrue((alice_outbox / "processed" / "req-00000001.json").is_file())

    def test_recipient_notices_swap_during_deliver_never_touches_escape_dir(self):
        """Finding 2 (runtime writes outside the namespace) — `deliver.py`'s
        notice write (W1). Swap the recipient's `inbound/notices` for a
        symlink to an arbitrary host directory OUTSIDE every namespace, in
        the window between the pin and the notice write."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        bob_inbox_root = cfg.instances["bob"].inbox_root
        escape_dir = self.tmp / "escape-notices"
        escape_dir.mkdir()

        def swap():
            notices_path = bob_inbox_root / "notices"
            os.rename(notices_path, bob_inbox_root / "notices.orig")
            os.symlink(escape_dir, notices_path)

        hook, state = _interpose_mkdir_and_pin("notices", swap)
        with mock.patch.object(attachments_mod, "_mkdir_and_pin", side_effect=hook):
            result = deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob",
                {"req_id": "00000001",
                 "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"}},
            )

        self.assertTrue(state["done"], "swap hook never fired — test didn't exercise the race window")
        self.assertEqual(list(escape_dir.iterdir()), [])
        notice_id = result["notice_id"]
        self.assertTrue(
            (bob_inbox_root / "notices.orig" / f"notice-{notice_id}.json").is_file()
        )

    def test_recipient_messages_swap_during_deliver_never_touches_escape_dir(self):
        """Finding 2, the message-spool twin (W2) — same window, one
        directory over (`inbound/messages`, written before `notices`)."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        bob_inbox_root = cfg.instances["bob"].inbox_root
        escape_dir = self.tmp / "escape-messages"
        escape_dir.mkdir()

        def swap():
            messages_path = bob_inbox_root / "messages"
            os.rename(messages_path, bob_inbox_root / "messages.orig")
            os.symlink(escape_dir, messages_path)

        hook, state = _interpose_mkdir_and_pin("messages", swap)
        with mock.patch.object(attachments_mod, "_mkdir_and_pin", side_effect=hook):
            result = deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob",
                {"req_id": "00000001",
                 "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"}},
            )

        self.assertTrue(state["done"], "swap hook never fired — test didn't exercise the race window")
        self.assertEqual(list(escape_dir.iterdir()), [])
        notice_id = result["notice_id"]
        self.assertTrue(
            (bob_inbox_root / "messages.orig" / f"notice-{notice_id}.json").is_file()
        )


class TestConcurrentSwapStress(RouterTestCase):
    def test_processed_swap_race_never_leaks_into_victim_outbox(self):
        """Real concurrent pressure, not an interposed hook: a background
        thread continuously toggles `outbox_root/processed` between a real
        directory and a symlink into a victim's own outbox while the main
        thread drains a fresh request every iteration. The pinned-fd fix
        makes correctness independent of who wins any given race, so the
        invariant (mallory's outbox stays empty) must hold after EVERY
        iteration, not just on average."""
        cfg = self.make_config({
            "alice": ["bob"], "bob": ["alice"], "mallory": ["alice"],
        })
        alice_outbox = cfg.instances["alice"].outbox_root
        mallory_outbox = cfg.instances["mallory"].outbox_root
        mallory_outbox.mkdir(parents=True, exist_ok=True)

        stop = threading.Event()

        def toggler():
            target = alice_outbox / "processed"
            while not stop.is_set():
                try:
                    if target.is_symlink():
                        target.unlink()
                        target.mkdir()
                    elif target.is_dir():
                        shutil.rmtree(target)
                        os.symlink(mallory_outbox, target)
                    else:
                        os.symlink(mallory_outbox, target)
                except OSError:
                    pass  # racing the router's own mkdir/pin — expected, harmless

        t = threading.Thread(target=toggler, daemon=True)
        t.start()
        try:
            n_iterations = 150
            for i in range(n_iterations):
                req_id = f"{i:08d}"
                write_request(cfg, "alice", req_id, to=["agent.bob@local"], body_text=f"msg {i}")
                outbound.drain_instance(cfg, "alice")
                # The invariant must hold AFTER EVERY SINGLE iteration —
                # not just at the end — so a leak on iteration 37 that
                # gets cleaned up by iteration 150 is still caught.
                leaked = [p.name for p in mallory_outbox.iterdir()]
                self.assertEqual(
                    leaked, [],
                    f"iteration {i}: request(s) leaked into mallory's outbox: {leaked}",
                )
        finally:
            stop.set()
            t.join(timeout=5)

        self.assertEqual(list(mallory_outbox.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
