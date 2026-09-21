"""`router.__main__.main` drives the subcommand CLI in-process (no
subprocess) over a real config file on disk — `peers`/`matrix` alias,
`status` before any poll, `provision`, and a bad config, per the L2 plan's
CLI verification list."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from router.__main__ import main


class TestCLI(unittest.TestCase):
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

    def test_peers_and_matrix_alias(self):
        code, out, _ = self._run("peers")
        self.assertEqual(code, 0)
        self.assertIn("alice", out)
        self.assertIn("bob", out)
        self.assertIn("FULL MESH", out)  # alice<->bob is mutual, only two instances

        code2, out2, _ = self._run("matrix")
        self.assertEqual(code2, 0)
        self.assertEqual(out2, out)

    def test_status_before_any_poll_exits_1(self):
        code, out, err = self._run("status")
        self.assertEqual(code, 1)
        self.assertIn("has not written status yet", err)

    def test_status_after_once_reports_and_json(self):
        code, _, _ = self._run("once")
        self.assertEqual(code, 0)
        # `once` (unlike `run`) does not itself write status.json — only
        # run_forever's poll loop does. Confirm the plain-text path still
        # reports cleanly absent, then exercise --json on a hand-seeded
        # status.json to prove the CLI's --json branch works end to end.
        from router.status import StatusTracker
        tracker = StatusTracker()
        tracker.record_poll({"alice": {"drained": 1, "accepted": 1, "rejected": 0,
                                        "queued_for_human": 0, "outbound_errored": 0,
                                        "outbound_skipped_bad_name": 0,
                                        "outbound_resumed": 0, "outbound_req_id_reused": 0}})
        tracker.write(self.state_dir)

        code, out, _ = self._run("status")
        self.assertEqual(code, 0)
        self.assertIn("alice", out)

        code_json, out_json, _ = self._run("status", "--json")
        self.assertEqual(code_json, 0)
        doc = json.loads(out_json)
        self.assertEqual(doc["schema"], 1)

    def test_provision_prints_four_lines_and_creates_skeleton(self):
        code, out, _ = self._run("provision", "alice")
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 4)
        # All four literal env var names, in the fixed documented order —
        # not just the first and last.
        self.assertTrue(lines[0].startswith("INBOX_NOTICE_DIR="))
        self.assertTrue(lines[1].startswith("INBOX_MESSAGE_DIR="))
        self.assertTrue(lines[2].startswith("OUTBOX_DIR="))
        self.assertTrue(lines[3].startswith("MAILBOX_AGENT_ID=alice"))
        self.assertTrue((self.alice_ns / "outbound" / "results").is_dir())

    def test_provision_no_create_and_json_format(self):
        code, out, _ = self._run(
            "provision", "bob", "--no-create", "--format", "json"
        )
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["MAILBOX_AGENT_ID"], "bob")
        self.assertFalse((self.bob_ns / "outbound").exists())

    def test_provision_unknown_instance_exits_1(self):
        code, _, err = self._run("provision", "mallory")
        self.assertEqual(code, 1)
        self.assertIn("mallory", err)

    def test_first_poll_snapshots_then_a_later_send_delivers(self):
        """`approve` is retired: nothing gates the first drain but the
        snapshot it takes. A request written AFTER that first poll is an
        ordinary send and must deliver — the quarantine case itself is
        test_first_sight.py's."""
        code, _, _ = self._run("once")           # first sight, empty outbox
        self.assertEqual(code, 0)
        self.assertTrue((self.state_dir / "alice" / "first-seen.json").is_file(),
                        "the first poll must record first sight for itself")

        (self.alice_ns / "outbound").mkdir(parents=True, exist_ok=True)
        (self.alice_ns / "outbound" / "req-00000001.json").write_bytes(
            b'{"contract_version":"2","req_id":"00000001",'
            b'"draft":{"to":["agent.bob@local"],"subject":"s","body_text":"b"}}'
        )

        code2, _, _ = self._run("once")
        self.assertEqual(code2, 0)
        self.assertTrue(
            (self.bob_ns / "inbound" / "notices").is_dir()
            and any((self.bob_ns / "inbound" / "notices").glob("notice-*.json")),
            "a send written after first sight should have delivered",
        )

    def _run_expecting_exit(self, *args: str):
        """argparse exits the process for an unknown subcommand and for
        `--help`; neither returns through `main`."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                main(["--config", str(self.config_path), *args])
        return ctx.exception.code, out.getvalue(), err.getvalue()

    def test_the_approve_subcommand_is_gone(self):
        """Retired, not deprecated. Anything still calling it — an adapter's
        provisioning script, an operator's shell history — must fail loudly
        rather than appear to work: argparse rejects the unknown subcommand
        and exits non-zero before `main` can return anything."""
        code, _, err = self._run_expecting_exit("approve", "alice")
        self.assertNotEqual(code, 0)
        self.assertIn("approve", err, "argparse should name the bad command")

        help_code, help_out, _ = self._run_expecting_exit("--help")
        self.assertEqual(help_code, 0)
        self.assertNotIn("approve", help_out,
                         "the retired subcommand is still advertised in --help")

    def test_bad_config_exits_2(self):
        bad_config = self.tmp / "bad.json"
        bad_config.write_text("not json at all")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--config", str(bad_config), "peers"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
