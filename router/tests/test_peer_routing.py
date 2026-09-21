"""Step 3 of the peer-lane build: the peer cold policy and delivery backend.

A declared edge routes an ordinary submit-request to the recipient's `peer/`
tree as a `kind: "peer"` notice — single recipient, no `cc`, `peer_routed`,
the exposure stamp asserted `false`, no `provenance`, ledger `tree: "peer"`,
an audit line — and NO edge gets exactly the mail-lane decision the operator
declared for that pair, which the loader has already made disjoint from the
edge. Every produced document is checked against the AMAP fixture engine."""

import json
import re
import unittest
from unittest import mock

from router import binding, deliver, outbound
from router.tests.helpers import (
    RouterTestCase, attachment_descriptor, list_notices, notices_dir, read_json,
    result_path, stage_outbound_sidecars, write_request,
)
from router.tests.peer_helpers import (
    addr, events, list_peer_notices, load_amp_validate, make_peer_config, notice_id_of,
    peer_messages_dir, peer_notices_dir, peer_schema_present,
)

_HEX32 = re.compile(r"^[0-9a-f]{32}$")


class PeerColdSendTests(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.amp = load_amp_validate()

    def _fleet(self):
        # a may task b; nobody else may task anybody; no mail pairs at all
        # (the first fleet: `peers` rendered empty).
        return make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}, "c": {}})

    def test_declared_edge_places_a_peer_notice(self):
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("b")], subject="Draft the notes",
                      body_text="Use the changelog.")
        summary = outbound.drain_instance(cfg, "a")
        self.assertEqual((summary["drained"], summary["accepted"]), (1, 1))

        result = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]), ("accepted", "peer_routed"))
        self.assertEqual(result["recipients"], ["b@example.invalid"])
        self.assertRegex(result["message_id"], _HEX32)
        self.assertEqual(self.amp.check_document("result-produced.json", result), [])

        # Peer tree, not inbox.
        self.assertEqual(list_notices(cfg, "b"), [])
        names = list_peer_notices(cfg, "b")
        self.assertEqual(len(names), 1)
        nid = notice_id_of(names[0])
        self.assertEqual(nid, result["message_id"], "the peer message id IS the notice id")

        notice = read_json(peer_notices_dir(cfg, "b") / names[0])
        self.assertEqual(notice["kind"], "peer")
        self.assertEqual(notice["notice_id"], nid)
        msg = notice["message"]
        self.assertEqual(msg["id"], nid)
        self.assertEqual(msg["mailbox"], "peer")
        self.assertEqual(msg["from"], "a@example.invalid")
        self.assertEqual(msg["subject"], "Draft the notes")
        self.assertNotIn("provenance", msg)
        self.assertNotIn("in_reply_to", msg, "a fresh task carries no in_reply_to")
        exposure = msg["sender_exposure"]
        self.assertEqual(exposure["asserted_by"], "amap.router@example.invalid")
        self.assertIs(exposure["external_mail_delivered"], False)
        self.assertEqual(exposure["window_end"], notice["ts"])
        self.assertNotIn("last_external_delivery_ts", exposure)
        self.assertNotIn("derived_from", exposure)

        # Message spool doc: reused unchanged, no exposure on it.
        message_doc = read_json(peer_messages_dir(cfg, "b") / names[0])
        self.assertEqual(message_doc["body_text"], "Use the changelog.")
        self.assertEqual(message_doc["from"], "a@example.invalid")
        self.assertEqual(message_doc["to"], "b@example.invalid")
        self.assertNotIn("sender_exposure", message_doc)
        self.assertEqual(self.amp.check_document("message-produced.json", message_doc), [])

        # Ledger: under the recipient, tree peer.
        record = read_json(binding.ledger_path(cfg.state_dir, "b", nid))
        self.assertEqual(record["tree"], "peer")
        self.assertEqual(record["from_instance"], "a")
        self.assertEqual(record["message_id"], nid)
        self.assertEqual(record["transport"], "local")

    def test_peer_notice_conforms_to_the_peer_schema_and_fails_the_deliver_schema(self):
        if not peer_schema_present():
            self.skipTest("peer-notice.schema.json has not landed in the AMAP checkout")
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("b")])
        outbound.drain_instance(cfg, "a")
        name = list_peer_notices(cfg, "b")[0]
        notice = read_json(peer_notices_dir(cfg, "b") / name)
        self.assertEqual(self.amp.check_document("peer-produced.json", notice), [])
        # The second lock: this document in inbox/notices/ would be dropped.
        self.assertNotEqual(self.amp.check_document("notice-produced.json", notice), [])

    def test_audit_line_for_a_placed_peer_notice(self):
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("b")])
        outbound.drain_instance(cfg, "a")
        nid = notice_id_of(list_peer_notices(cfg, "b")[0])
        lines = events(cfg, "b", "peer_notice_placed")
        self.assertEqual(len(lines), 1)
        line = lines[0]
        self.assertEqual(line["instance"], "b")
        self.assertEqual(line["notice_id"], nid)
        self.assertEqual(line["message_id"], nid)
        self.assertEqual(line["tree"], "peer")
        self.assertEqual((line["from"], line["to"]), ("a@example.invalid", "b@example.invalid"))
        self.assertEqual((line["from_instance"], line["to_instance"]), ("a", "b"))
        self.assertEqual(line["req_id"], "00000001")
        self.assertIsNone(line["in_reply_to"])
        self.assertIsNone(line["reply_basis"])
        self.assertIs(line["sender_exposure"]["external_mail_delivered"], False)
        self.assertEqual(line["origin"], "local")
        self.assertIsNone(line["signature_verdict"])
        self.assertIsNone(line["demotion_cause"])
        self.assertIn("ts", line)
        # Nothing in the sender's log: the recipient's tree was written.
        self.assertEqual(events(cfg, "a"), [])

    def test_no_edge_gets_the_mail_lane_decision(self):
        cfg = self._fleet()
        # a -> c: no edge, no mail pair -> held, exactly as before the peer lane.
        write_request(cfg, "a", "00000001", to=[addr("c")])
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]),
                         ("queued_for_human", "recipient_not_allowlisted"))
        self.assertTrue((cfg.state_dir / "a" / "held" / "req-00000001.json").is_file())
        self.assertEqual(list_peer_notices(cfg, "c"), [])
        self.assertEqual(list_notices(cfg, "c"), [])
        # And the reverse of a declared edge is no edge: b -> a is held too.
        write_request(cfg, "b", "00000001", to=[addr("a")])
        outbound.drain_instance(cfg, "b")
        r2 = read_json(result_path(cfg, "b", "00000001"))
        self.assertEqual(r2["reason_code"], "recipient_not_allowlisted")
        self.assertEqual(list_peer_notices(cfg, "a"), [])

    def test_no_edge_with_a_mail_pair_goes_to_inbox_as_deliver(self):
        cfg = make_peer_config(self, {
            "a": {"peers": ["c"]}, "b": {"peer_senders": ["a"]}, "c": {"peers": ["a"]},
        })
        write_request(cfg, "a", "00000001", to=[addr("c")])
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]), ("accepted", "allowlisted"))
        self.assertEqual(len(list_notices(cfg, "c")), 1)
        self.assertEqual(list_peer_notices(cfg, "c"), [])
        notice = read_json(notices_dir(cfg, "c") / list_notices(cfg, "c")[0])
        self.assertEqual(notice["kind"], "deliver")
        self.assertNotIn("sender_exposure", notice["message"])

    def test_cc_on_a_peer_send_is_refused_whole_and_audited(self):
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("b")], cc=[addr("c")])
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]),
                         ("rejected", "peer_single_recipient"))
        self.assertEqual(list_peer_notices(cfg, "b"), [])
        self.assertEqual(list_notices(cfg, "c"), [])
        refusals = events(cfg, "a", "peer_refused")
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["reason_code"], "peer_single_recipient")
        self.assertEqual(refusals[0]["req_id"], "00000001")
        self.assertEqual(sorted(refusals[0]["recipients"]), ["b", "c"])

    def test_two_recipients_one_on_an_edge_refused_whole(self):
        cfg = make_peer_config(self, {
            "a": {"peers": ["c"]}, "b": {"peer_senders": ["a"]}, "c": {"peers": ["a"]},
        })
        write_request(cfg, "a", "00000001", to=[addr("b"), addr("c")])
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual(result["reason_code"], "peer_single_recipient")
        # Neither lane received anything: refused whole, never half-sent.
        self.assertEqual(list_peer_notices(cfg, "b"), [])
        self.assertEqual(list_notices(cfg, "c"), [])

    def test_self_send_and_unknown_still_refused_before_the_edge_check(self):
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("a")])
        write_request(cfg, "a", "00000002", to=["nobody@example.invalid"])
        outbound.drain_instance(cfg, "a")
        self.assertEqual(read_json(result_path(cfg, "a", "00000001"))["reason_code"], "self_send")
        self.assertEqual(read_json(result_path(cfg, "a", "00000002"))["reason_code"],
                         "recipient_unknown")

    def test_attachments_are_published_under_the_peer_tree(self):
        cfg = self._fleet()
        data = b"peer bytes"
        write_request(cfg, "a", "00000001", to=[addr("b")],
                      attachments=[attachment_descriptor(data, filename="f.bin")])
        stage_outbound_sidecars(cfg, "a", "00000001", [data])
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual(result["reason_code"], "peer_routed")
        self.assertEqual(result["attachments"], [{"index": 0, "outcome": "accepted", "detail": None}])
        name = list_peer_notices(cfg, "b")[0]
        nid = notice_id_of(name)
        blob = peer_notices_dir(cfg, "b") / f"{nid}.attachments" / "0"
        self.assertEqual(blob.read_bytes(), data)
        message_doc = read_json(peer_messages_dir(cfg, "b") / name)
        # Bare `notice_id`, under the PEER tree's own `notices/`. This is not
        # inherited from the mail lane — `peer-origin.md` 1d makes the confinement
        # per tree: "Bytes resolve only within the `notices/` directory of the tree
        # the enclosing document was read from ... A peer notice cannot point into
        # the mail sidecar directory or vice versa." An earlier version of this
        # comment said the peer lane "inherits the mail lane's answer", which was
        # true by accident rather than by construction; cite the rule, not the
        # coincidence.
        self.assertEqual(message_doc["attachments"][0]["content_ref"], f"{nid}.attachments/0")
        notice = read_json(peer_notices_dir(cfg, "b") / name)
        self.assertEqual(notice["message"]["attachments"][0]["disposition"], "clean")
        if peer_schema_present():
            self.assertEqual(self.amp.check_document("peer-produced.json", notice), [])

    def test_peer_delivery_failure_is_answered_once_not_retried(self):
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("b")])
        with mock.patch.object(deliver, "deliver_peer", side_effect=OSError("disk")):
            outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]),
                         ("queued_for_human", "delivery_failed"))
        self.assertNotIn("disk", json.dumps(result), "exception text never reaches the agent")
        self.assertFalse((cfg.instances["a"].outbox_root / "req-00000001.json").exists())
        # A second drain resumes the recorded verdict rather than redelivering.
        summary = outbound.drain_instance(cfg, "a")
        self.assertEqual(summary["drained"], 0)
        self.assertEqual(list_peer_notices(cfg, "b"), [])

    def test_injected_cold_policy_seam_still_wins(self):
        """A caller's policy replaces the whole decision, peer lane included."""
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("b")])
        outbound.drain_instance(
            cfg, "a",
            cold_policy=lambda c, s, d: outbound.ColdRefusal("rejected", "custom"),
        )
        self.assertEqual(read_json(result_path(cfg, "a", "00000001"))["reason_code"], "custom")
        self.assertEqual(list_peer_notices(cfg, "b"), [])

    def test_ids_unique_across_both_trees_for_one_writer(self):
        cfg = make_peer_config(self, {
            "a": {"peers": ["c"]}, "b": {"peer_senders": ["a"]}, "c": {"peers": ["a"]},
        })
        write_request(cfg, "a", "00000001", to=[addr("b")])
        write_request(cfg, "a", "00000002", to=[addr("c")])
        outbound.drain_instance(cfg, "a")
        peer_id = notice_id_of(list_peer_notices(cfg, "b")[0])
        mail_id = notice_id_of(list_notices(cfg, "c")[0])
        self.assertNotEqual(peer_id, mail_id)
        for i in (peer_id, mail_id):
            self.assertRegex(i, _HEX32)


if __name__ == "__main__":
    unittest.main()
