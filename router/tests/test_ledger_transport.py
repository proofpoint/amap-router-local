"""The ledger's `transport` field: the delivery leg a notice went out
over, recorded in router-private state so a reply can be routed back the
same way without asking the agent.

Three properties, and the last two matter more than the first:

  - it round-trips, and defaults to `"local"` (this repo's only leg);
  - a record written BEFORE the field existed still resolves. Absent is
    not invalid, and absent is not `"local"` either — no reader may
    backfill it, because under a runtime with a second leg that default
    would be an active lie about how the original arrived;
  - it never appears in an agent's namespace. The field exists to be a
    thing the agent cannot see or forge; leaking it into the notice or
    the message spool would hand the agent the routing input.
"""

import json
import unittest

from router import binding, deliver, outbound
from router.tests.helpers import (
    RouterTestCase, list_notices, messages_dir, notices_dir, read_json,
    result_path, write_request,
)


def _request(req_id="00000001", to="agent.bob@local"):
    return {
        "contract_version": "2",
        "req_id": req_id,
        "draft": {"to": [to], "subject": "s", "body_text": "b"},
    }


def _legacy_record(notice_id, *, from_instance="alice", to_instance="bob"):
    """A ledger record in the shape written BEFORE `transport` existed —
    every key of the old record, and no `transport`."""
    return {
        "notice_id": notice_id,
        "from_instance": from_instance,
        "from_address": f"agent.{from_instance}@local",
        "to_instance": to_instance,
        "ts": "2026-01-01T00:00:00Z",
        "req_id": "seed",
        "message_id": notice_id,
    }


class TestLedgerTransportWritten(RouterTestCase):
    def test_delivered_record_carries_transport_local(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        result = deliver.deliver(cfg, cfg.state_dir, "alice", "bob", _request())

        doc = read_json(binding.ledger_path(cfg.state_dir, "bob", result["notice_id"]))
        self.assertEqual(doc["transport"], "local")

    def test_record_delivery_refuses_to_default_the_leg(self):
        """There is NO default. A default of "local" would invent, on the
        writer's side, exactly the answer `binding`'s docstring forbids readers
        to backfill: silently correct in this transport-free router, an active
        lie in a runtime with a second leg — and the reply path routes on this
        field, so the symptom would be a reply leaving over the wrong
        transport with nothing raised anywhere.

        The only in-repo writer already passes it explicitly (`deliver.py`), so
        requiring it costs nothing today and converts a future backend's
        omission into a TypeError at the call site."""
        with self.assertRaises(TypeError):
            binding.record_delivery(
                self.state_dir,
                notice_id="n1",
                from_instance="alice",
                from_address="agent.alice@local",
                to_instance="bob",
                ts="2026-01-01T00:00:00Z",
                req_id="00000001",
                message_id="n1",
            )

    def _write_legacy(self, cfg, notice_id):
        path = binding.ledger_path(cfg.state_dir, "bob", notice_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(_legacy_record(notice_id)).encode("utf-8"))

    def test_legacy_record_without_transport_still_resolves(self):
        cfg = self.make_config({"alice": [], "bob": []})
        self._write_legacy(cfg, "legacy0001")

        self.assertEqual(binding.resolve_binding(cfg.state_dir, "bob", "legacy0001"), "alice")
        # And it is handed back AS IT IS: absent stays absent.
        doc = binding.read_ledger_record(cfg.state_dir, "bob", "legacy0001")
        self.assertNotIn("transport", doc)

    def test_legacy_record_reply_drains_end_to_end(self):
        # The whole reply path, not `binding` in isolation: `outbound.
        # _drain_reply` reads the same record.
        cfg = self.make_config({"alice": [], "bob": []})
        self._write_legacy(cfg, "legacy0002")

        write_request(
            cfg, "bob", "00000001", in_reply_to="legacy0002",
            to=["agent.someone-else@local"], body_text="replying",
        )
        outbound.drain_instance(cfg, "bob")

        result = read_json(result_path(cfg, "bob", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["recipients"], ["agent.alice@local"])
        self.assertEqual(len(list_notices(cfg, "alice")), 1)


class TestTransportNeverEntersAgentNamespace(RouterTestCase):
    def test_transport_never_enters_agent_namespace(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        result = deliver.deliver(cfg, cfg.state_dir, "alice", "bob", _request())
        notice_id = result["notice_id"]

        message_doc = read_json(messages_dir(cfg, "bob") / f"notice-{notice_id}.json")
        self.assertNotIn("transport", message_doc)

        notice_doc = read_json(notices_dir(cfg, "bob") / f"notice-{notice_id}.json")
        self.assertNotIn("transport", notice_doc)
        self.assertNotIn("transport", notice_doc["message"])

        # Premise check: it IS on disk — router-side, where only the
        # router can reach it.
        self.assertEqual(
            read_json(binding.ledger_path(cfg.state_dir, "bob", notice_id))["transport"],
            "local",
        )


if __name__ == "__main__":
    unittest.main()
