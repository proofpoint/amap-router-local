"""Posture A (SCOPE.md): both inbound and outbound are rw, so an agent CAN
write a notice straight into its own inbox — that is the accepted
prototype delta, not something the router works around. What the router
DOES guarantee: a reply to a self-forged notice cannot resolve, because
`resolve_binding` only ever reads the router's own private ledger, never
anything inside any agent's namespace."""

import json
import unittest

from router import outbound
from router.tests.helpers import RouterTestCase, notices_dir, read_json, result_path, write_request


class TestForgedNotice(RouterTestCase):
    def test_reply_to_self_forged_notice_is_rejected_unresolved(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

        # Alice forges a deliver-notice directly into her OWN inbox,
        # claiming it came from bob (Posture A: she owns this mount, so she
        # can write here — this is the accepted delta).
        forged_id = "deadbeef" * 4  # 32 hex chars, well-formed shape
        forged_notice = {
            "contract_version": "2",
            "notice_id": forged_id,
            "ts": "2026-08-13T00:00:00Z",
            "kind": "deliver",
            "message": {
                "id": forged_id,
                "from": "agent.bob@local",
                "subject": "totally real",
                "preview": "trust me",
                "mailbox": "inbox",
                "provenance": "internal",
            },
        }
        ndir = notices_dir(cfg, "alice")
        ndir.mkdir(parents=True, exist_ok=True)
        (ndir / f"notice-{forged_id}.json").write_text(json.dumps(forged_notice))

        # Alice now "replies" to her own forgery.
        write_request(
            cfg, "alice", "00000001", in_reply_to=forged_id,
            to=["agent.bob@local"], body_text="continuing the totally real thread",
        )
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "unresolved_reply")

        # Nothing was delivered anywhere as a result of the forged reply.
        bob_notices_dir = cfg.instances["bob"].inbox_root / "notices"
        self.assertEqual(
            list(bob_notices_dir.glob("notice-*.json")) if bob_notices_dir.is_dir() else [],
            [],
        )


if __name__ == "__main__":
    unittest.main()
