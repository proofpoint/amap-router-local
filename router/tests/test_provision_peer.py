"""Step 2 of the peer-lane build, the filesystem half: `provision` grows
`<handoff_dir>/peer/{notices,messages}` — creating `peer/` ITSELF, since it is
router-owned and not a sandy mount source — and `<intake_dir>/<instance>/`,
reports both in `--format json`, and leaves the four env vars exactly as
they were. `reset` empties the peer tree and preserves `audit/`."""

import contextlib
import io
import json
import os
import unittest

from router import audit, deliver, outbound, reset
from router.__main__ import main
from router.provision import ENV_KEYS, format_report, provision, report
from router.tests.helpers import RouterTestCase, read_json, write_request
from router.tests.peer_helpers import (
    FLEET_DOMAIN, addr, events, list_peer_notices, make_peer_config, peer_messages_dir,
    peer_notices_dir,
)
from router.util import NamespaceEscapeError


class ProvisionPeerTreeTests(RouterTestCase):
    def test_creates_peer_tree_including_peer_itself_and_not_processed(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}}, provision=False)
        root = cfg.instances["b"].root
        self.assertFalse((root / "peer").exists())
        env = provision(cfg, "b", create=True)
        self.assertTrue((root / "peer" / "notices").is_dir())
        self.assertTrue((root / "peer" / "messages").is_dir())
        self.assertFalse((root / "peer" / "notices" / "processed").exists())
        # The env dict is untouched by the peer lane: the daemon never reads these.
        self.assertEqual(sorted(env), sorted(ENV_KEYS))

    def test_idempotent(self):
        cfg = make_peer_config(self, {"a": {}}, provision=False)
        self.assertEqual(provision(cfg, "a"), provision(cfg, "a"))
        self.assertTrue((cfg.instances["a"].root / "peer" / "notices").is_dir())

    def test_no_peer_tree_without_a_domain_or_in_namespace_mode(self):
        cfg = make_peer_config(self, {"a": {}}, fleet_domain=None, provision=False)
        provision(cfg, "a")
        self.assertFalse((cfg.instances["a"].root / "peer").exists())
        cfg2 = make_peer_config(self, {"n": {"mode": "namespace"}}, provision=False)
        provision(cfg2, "n")
        self.assertFalse((cfg2.instances["n"].root / "peer").exists())

    def test_no_create_creates_no_peer_tree(self):
        cfg = make_peer_config(self, {"a": {}}, provision=False)
        provision(cfg, "a", create=False)
        self.assertFalse((cfg.instances["a"].root / "peer").exists())

    def test_symlinked_peer_dir_refused_nothing_created_at_target(self):
        cfg = make_peer_config(self, {"a": {}}, provision=False)
        outside = self.tmp / "outside"
        outside.mkdir()
        os.symlink(outside, cfg.instances["a"].root / "peer")
        with self.assertRaises(NamespaceEscapeError):
            provision(cfg, "a", create=True)
        self.assertEqual(list(outside.iterdir()), [])

    def test_intake_dir_per_instance_created(self):
        intake = self.tmp / "router-intake"
        cfg = make_peer_config(self, {"a": {}}, intake_dir=intake, provision=False)
        self.assertFalse(intake.exists())
        provision(cfg, "a")
        self.assertTrue((intake / "a").is_dir())


class ProvisionReportTests(RouterTestCase):
    def test_report_shape_exact(self):
        """THE shape the adapter consumes. Literal keys, not constants."""
        intake = self.tmp / "router-intake"
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}},
                               intake_dir=intake, provision=False)
        inst = cfg.instances["b"]
        env = provision(cfg, "b")
        doc = report(cfg, "b", env)
        self.assertEqual(doc, {
            "INBOX_NOTICE_DIR": str(inst.inbox_root / "notices"),
            "INBOX_MESSAGE_DIR": str(inst.inbox_root / "messages"),
            "OUTBOX_DIR": str(inst.outbox_root),
            "MAILBOX_AGENT_ID": "b",
            "address": "b@example.invalid",
            "router_address": "amap.router@example.invalid",
            "peer": {
                "root": str(inst.root / "peer"),
                "notices": str(inst.root / "peer" / "notices"),
                "messages": str(inst.root / "peer" / "messages"),
            },
            "intake": str(intake / "b"),
        })
        # Key order is part of the shape: env vars first, so the head of the
        # output is what it always was.
        self.assertEqual(list(doc)[:4], list(ENV_KEYS))
        self.assertEqual(json.loads(format_report(doc)), doc)

    def test_report_nulls_outside_the_peer_lane(self):
        cfg = make_peer_config(self, {"a": {}}, fleet_domain=None, provision=False)
        doc = report(cfg, "a", provision(cfg, "a"))
        self.assertEqual(doc["address"], "agent.a@local")
        self.assertIsNone(doc["router_address"])
        self.assertIsNone(doc["peer"])
        self.assertIsNone(doc["intake"])
        cfg2 = make_peer_config(self, {"n": {"mode": "namespace"}}, provision=False)
        doc2 = report(cfg2, "n", provision(cfg2, "n"))
        self.assertEqual(doc2["address"], "n@example.invalid")
        self.assertIsNone(doc2["peer"])

    def test_cli_format_json_prints_the_report_and_env_stays_four_lines(self):
        cfg_path = self.tmp / "router.json"
        root = self.tmp / "sb" / "a" / "handoff"
        (root / "inbox").mkdir(parents=True)
        (root / "outbox").mkdir()
        cfg_path.write_text(json.dumps({
            "state_dir": str(self.state_dir), "fleet_domain": FLEET_DOMAIN,
            "intake_dir": str(self.tmp / "intake"),
            "instances": {"a": {"handoff_dir": str(root)}},
        }))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--config", str(cfg_path), "provision", "a", "--format", "json"])
        self.assertEqual(code, 0, err.getvalue())
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["MAILBOX_AGENT_ID"], "a")
        self.assertEqual(doc["peer"]["root"], str(root / "peer"))
        self.assertEqual(doc["intake"], str(self.tmp / "intake" / "a"))
        self.assertTrue((root / "peer" / "messages").is_dir())
        self.assertTrue((self.tmp / "intake" / "a").is_dir())

        out2 = io.StringIO()
        with contextlib.redirect_stdout(out2), contextlib.redirect_stderr(io.StringIO()):
            main(["--config", str(cfg_path), "provision", "a"])
        self.assertEqual(len(out2.getvalue().strip().splitlines()), 4)


class ResetPeerTreeAndAuditTests(RouterTestCase):
    def _deliver_peer(self, cfg):
        write_request(cfg, "a", "00000001", to=[addr("b")], body_text="task")
        outbound.drain_instance(cfg, "a")
        self.assertEqual(len(list_peer_notices(cfg, "b")), 1)

    def test_reset_empties_peer_contents_keeps_leaves_and_preserves_audit(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        self._deliver_peer(cfg)
        # Something to sweep in every peer location, plus a stray at the root.
        (cfg.instances["b"].peer_root / "stray.txt").write_text("x")
        self.assertTrue(audit.log_path(cfg.state_dir, "b").is_file())
        before_events = events(cfg, "b")
        self.assertEqual(len(before_events), 1)
        survivors = {
            "peer": cfg.instances["b"].peer_root,
            "notices": peer_notices_dir(cfg, "b"),
            "messages": peer_messages_dir(cfg, "b"),
        }
        inodes = {k: p.stat().st_ino for k, p in survivors.items()}

        summary = reset.reset_instance(cfg, "b")

        self.assertTrue(summary["peer_available"])
        self.assertTrue(summary["audit_preserved"])
        self.assertEqual(list(peer_notices_dir(cfg, "b").iterdir()), [])
        self.assertEqual(list(peer_messages_dir(cfg, "b").iterdir()), [])
        self.assertFalse((cfg.instances["b"].peer_root / "stray.txt").exists())
        for k, p in survivors.items():
            self.assertEqual(p.stat().st_ino, inodes[k], f"{k} was recreated, not preserved")
        # Router-private state gone — except the audit log, which grew a `reset` line.
        self.assertFalse((cfg.state_dir / "b" / "delivered").exists())
        after = events(cfg, "b")
        self.assertEqual([e["event"] for e in after], ["peer_notice_placed", "reset"])
        line = after[-1]
        self.assertEqual(line["instance"], "b")
        self.assertEqual(line["was_seen"], True)
        self.assertGreater(line["state_removed"], 0)
        self.assertGreater(line["mailbox_removed"], 0)
        self.assertTrue(line["peer_available"])
        self.assertIn("ts", line)

    def test_plan_lists_peer_paths_and_never_the_audit_log(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        self._deliver_peer(cfg)
        plan = reset.plan_reset(cfg, "b")
        self.assertTrue(plan.has_peer_tree and plan.peer_available)
        self.assertTrue(any("peer" in p.parts for p in plan.mailbox_paths))
        self.assertFalse(any(p.name == audit.AUDIT_DIR for p in plan.state_paths))
        # plan is pure: no reset line was appended.
        self.assertEqual([e["event"] for e in events(cfg, "b")], ["peer_notice_placed"])

    def test_second_reset_is_a_noop_despite_the_surviving_audit_dir(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        self._deliver_peer(cfg)
        reset.reset_instance(cfg, "b")
        summary = reset.reset_instance(cfg, "b")
        self.assertEqual((summary["state_removed"], summary["mailbox_removed"]), (0, 0))
        self.assertEqual([e["event"] for e in events(cfg, "b")][-2:], ["reset", "reset"])

    def test_symlinked_peer_leaf_aborts_touching_nothing(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        self._deliver_peer(cfg)
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "victim").write_text("v")
        import shutil
        shutil.rmtree(peer_messages_dir(cfg, "b"))
        os.symlink(outside, peer_messages_dir(cfg, "b"))
        with self.assertRaises(NamespaceEscapeError):
            reset.reset_instance(cfg, "b")
        self.assertTrue((outside / "victim").is_file())
        self.assertEqual(len(list_peer_notices(cfg, "b")), 1)

    def test_no_peer_lane_summary_reports_peer_unavailable_and_plan_has_no_tree(self):
        cfg = self.make_config({"a": ["b"], "b": ["a"]}, mode="handoff")
        summary = reset.reset_instance(cfg, "a")
        self.assertFalse(summary["peer_available"])
        self.assertFalse(reset.plan_reset(cfg, "a").has_peer_tree)


if __name__ == "__main__":
    unittest.main()
