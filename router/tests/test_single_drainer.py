"""Single writer, single drainer (contract v3.0.0 sec 2, lines 74-85;
ROUTER-RELIABILITY.md RR-F1, reproduced 15/15 with no attacker needed).

Before `router/lock.py` existed, nothing enforced single-instance
operation over a `state_dir`: two `once`/`run` processes, or a `reset`
overlapping a live drain, could duplicate every message in flight and
publish a false verdict for a request the OTHER process had already
answered. These tests pin the fix at three levels: the lock primitive
itself, the `once`/`run` CLI entry points, and `reset.reset_instances`."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from router import lock as lock_mod
from router import reset as reset_mod
from router.__main__ import main
from router.reset import ResetError
from router.tests.helpers import RouterTestCase, list_notices, write_request


class TestLockPrimitive(RouterTestCase):
    def test_second_acquire_fails_while_first_is_held(self):
        held = lock_mod.acquire(self.state_dir)
        try:
            with self.assertRaises(lock_mod.LockHeldError):
                lock_mod.acquire(self.state_dir)
        finally:
            held.release()

    def test_release_then_reacquire_succeeds(self):
        held = lock_mod.acquire(self.state_dir)
        held.release()
        held2 = lock_mod.acquire(self.state_dir)
        held2.release()  # no LockHeldError — proves release genuinely dropped it

    def test_context_manager_releases_on_exit(self):
        with lock_mod.acquire(self.state_dir):
            pass
        # Held again cleanly — the `with` block released it.
        held = lock_mod.acquire(self.state_dir)
        held.release()

    def test_error_names_the_holder_pid_diagnostically(self):
        import os

        held = lock_mod.acquire(self.state_dir)
        try:
            with self.assertRaises(lock_mod.LockHeldError) as ctx:
                lock_mod.acquire(self.state_dir)
            self.assertEqual(ctx.exception.holder_pid, str(os.getpid()))
            self.assertIn(str(os.getpid()), str(ctx.exception))
        finally:
            held.release()

    def test_lock_survives_a_crashed_holder_closing_its_fd(self):
        """The whole reason this is `flock`, not a pidfile (module
        docstring): the kernel drops the lock the instant the holder's fd
        is closed, crash or clean exit alike — no stale-lock state, no
        liveness probe needed. Simulate the crash as an abrupt `release()`
        (the OS-level effect of a process dying is exactly this: its file
        table is torn down) and confirm a fresh `acquire` just succeeds."""
        held = lock_mod.acquire(self.state_dir)
        held.release()  # stands in for the OS closing a crashed process's fds
        held2 = lock_mod.acquire(self.state_dir)  # no reaping, no liveness check needed
        held2.release()

    def test_lock_file_lives_directly_under_state_dir_not_per_instance(self):
        held = lock_mod.acquire(self.state_dir)
        held.release()
        lock_path = self.state_dir / lock_mod.LOCK_NAME
        self.assertTrue(lock_path.is_file())
        # Never inside a per-instance state_dir/<name> subtree — reset's
        # per-instance `_clear_state` only ever lists state_dir/<name>,
        # so a lock file living there would risk being swept as if it
        # were instance state.
        self.assertEqual(lock_path.parent, self.state_dir)


class TestCLISingleDrainer(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

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

    def test_once_refuses_and_drains_nothing_while_another_drainer_holds_the_lock(self):
        # Get first sight out of the way (empty outbox), THEN stage a
        # fresh, perfectly deliverable request — staged before the snapshot
        # it would be quarantined, and this test is about the lock.
        code, _, _ = self._run("once")
        self.assertEqual(code, 0)
        (self.alice_ns / "outbound").mkdir(parents=True, exist_ok=True)
        (self.alice_ns / "outbound" / "req-00000001.json").write_bytes(
            b'{"contract_version":"2","req_id":"00000001",'
            b'"draft":{"to":["agent.bob@local"],"subject":"s","body_text":"b"}}'
        )

        # Simulate a `once`/`run` already in flight against this state_dir.
        held = lock_mod.acquire(self.state_dir)
        try:
            code, out, err = self._run("once")
        finally:
            held.release()

        self.assertEqual(code, 1)
        self.assertIn("refusing", err)
        # Zero duplicate (or even single) delivery — the drain never ran
        # at all, the RR-F1 shape now refused up front rather than
        # racing.
        self.assertFalse(
            (self.bob_ns / "inbound" / "notices").is_dir()
            and any((self.bob_ns / "inbound" / "notices").glob("notice-*.json"))
        )
        # The request is exactly as it was — never opened, never archived.
        self.assertTrue((self.alice_ns / "outbound" / "req-00000001.json").is_file())

        # Lock released — the SAME `once` now succeeds and drains normally.
        code2, _, _ = self._run("once")
        self.assertEqual(code2, 0)
        self.assertTrue(
            any((self.bob_ns / "inbound" / "notices").glob("notice-*.json"))
        )
        # And it delivered exactly once — not duplicated by the earlier,
        # refused attempt.
        self.assertEqual(
            len(list((self.bob_ns / "inbound" / "notices").glob("notice-*.json"))), 1
        )

    def test_two_sequential_once_invocations_each_take_and_release_the_lock(self):
        # Sanity: the lock must not be held ACROSS separate `once`
        # invocations (it's process-lifetime per invocation, not
        # permanent) — two back-to-back `once` calls must both succeed.
        code1, _, _ = self._run("once")
        self.assertEqual(code1, 0)
        code2, _, _ = self._run("once")
        self.assertEqual(code2, 0)


class TestResetSingleDrainer(RouterTestCase):
    def test_reset_refuses_and_removes_nothing_while_a_drainer_holds_the_lock(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        first_seen_marker = self.state_dir / "alice" / "first-seen.json"
        self.assertTrue(first_seen_marker.exists())

        held = lock_mod.acquire(cfg.state_dir)
        try:
            with self.assertRaises(ResetError):
                reset_mod.reset_instances(cfg, ["alice"])
        finally:
            held.release()

        # Nothing was removed — reset never got past the lock acquire.
        self.assertTrue(first_seen_marker.exists())
        self.assertTrue(
            (cfg.instances["alice"].outbox_root / "req-00000001.json").is_file()
        )

        # Lock released — the same reset now succeeds normally.
        reset_mod.reset_instances(cfg, ["alice"])
        self.assertFalse(first_seen_marker.exists())


if __name__ == "__main__":
    unittest.main()
