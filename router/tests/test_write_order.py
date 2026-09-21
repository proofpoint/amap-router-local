"""`deliver.py`'s commit-sentinel discipline: message spool -> router-
private ledger record -> notice LAST, and a failure on the LAST write must
never leave a notice behind (no partial commit).

v3.0.0 write-side path discipline (contract sec 2): the message doc and
the notice doc are now written via `attachments.write_agent_visible` (a
pinned `dir_fd` descent + `O_EXCL`-tmp + `renameat`, replacing the old
`verify_namespace_containment` + `util.atomic_write` pairing —
ROUTER-SECURITY.md Finding 2). Only the router-private ledger record
(under `state_dir`, never agent-reachable) still goes through plain
`util.atomic_write`. These tests patch both call sites so the recorded
order still reconstructs the true write sequence."""

import unittest
from unittest import mock

from router import deliver
from router.attachments import write_agent_visible as real_write_agent_visible
from router.tests.helpers import RouterTestCase, list_notices, messages_dir
from router.util import atomic_write as real_atomic_write


class TestWriteOrder(RouterTestCase):
    def _request(self):
        return {
            "req_id": "00000001",
            "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"},
        }

    def test_ledger_before_notice_ordering(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        calls = []

        def recording_write_agent_visible(root, target_path, data):
            calls.append(str(target_path))
            return real_write_agent_visible(root, target_path, data)

        def recording_atomic_write(path, data):
            calls.append(str(path))
            return real_atomic_write(path, data)

        with mock.patch.object(
            deliver.attachments_mod, "write_agent_visible",
            side_effect=recording_write_agent_visible,
        ), mock.patch.object(deliver, "atomic_write", side_effect=recording_atomic_write):
            deliver.deliver(cfg, cfg.state_dir, "alice", "bob", self._request())

        self.assertEqual(len(calls), 3)
        self.assertIn("inbound/messages/notice-", calls[0])
        self.assertIn(str(cfg.state_dir), calls[1])
        self.assertIn("delivered/notice-", calls[1])
        self.assertIn("inbound/notices/notice-", calls[2])

    def test_failure_on_notice_write_leaves_no_notice(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

        def failing_write_agent_visible(root, target_path, data):
            if "inbound/notices/" in str(target_path):
                raise OSError("simulated failure writing the notice")
            return real_write_agent_visible(root, target_path, data)

        with mock.patch.object(
            deliver.attachments_mod, "write_agent_visible",
            side_effect=failing_write_agent_visible,
        ):
            with self.assertRaises(OSError):
                deliver.deliver(cfg, cfg.state_dir, "alice", "bob", self._request())

        # No partial commit: no notice was left behind for bob.
        self.assertEqual(list_notices(cfg, "bob"), [])
        # The message spool DID get written (it's write #1, before the
        # simulated failure) — its presence alone is not the publish
        # signal; only the notice is.
        self.assertEqual(len(list(messages_dir(cfg, "bob").glob("notice-*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
