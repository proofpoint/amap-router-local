"""Step 4 of the peer-lane build: the reverse edge on the reply path, and the
invariant the receiving daemon's `allowed_repliers` rests on —

    a peer notice carries `in_reply_to` IFF this router resolved it from
    its own ledger.

`InReplyToIffResolvedTests` is the fixture the connector asked for: every
way a sender can try to put an `in_reply_to` on a peer notice that the ledger
did not resolve ends in `rejected`, never in a notice, and every peer notice
that does carry one names a ledger record under the sender."""

import json
import unittest
from datetime import timedelta

from router import binding, outbound
from router.tests.helpers import (
    RouterTestCase, list_notices, notices_dir, read_json, result_path, write_request,
)
from router.tests.peer_helpers import (
    addr, events, list_peer_notices, make_peer_config, notice_id_of, peer_notices_dir,
)
from router.util import format_utc_ts, parse_utc_ts


def _age_record(cfg, recipient, notice_id, seconds):
    """Rewrite the ledger record's `ts` to `seconds` ago — the only way to
    make the reply window expire without sleeping a week."""
    path = binding.ledger_path(cfg.state_dir, recipient, notice_id)
    doc = json.loads(path.read_text())
    then = parse_utc_ts(doc["ts"]) - timedelta(seconds=seconds)
    doc["ts"] = format_utc_ts(then)
    path.write_text(json.dumps(doc, sort_keys=True))


class ReverseEdgeTests(RouterTestCase):
    def _task(self, cfg, sender="a", recipient="b", req_id="00000001"):
        write_request(cfg, sender, req_id, to=[addr(recipient)], body_text="do the thing")
        outbound.drain_instance(cfg, sender)
        result = read_json(result_path(cfg, sender, req_id))
        self.assertEqual(result["reason_code"], "peer_routed")
        self.assertIn(f"notice-{result['message_id']}.json", list_peer_notices(cfg, recipient))
        return result["message_id"]

    def test_reply_travels_the_reverse_edge_within_the_window(self):
        # Only a -> b is declared. b answers a without an edge of its own.
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        task_id = self._task(cfg)

        write_request(cfg, "b", "00000001", in_reply_to=task_id,
                      to=["forged@example.invalid"], body_text="done")
        outbound.drain_instance(cfg, "b")

        result = read_json(result_path(cfg, "b", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]), ("accepted", "peer_routed"))
        self.assertEqual(result["recipients"], ["a@example.invalid"])

        names = list_peer_notices(cfg, "a")
        self.assertEqual(len(names), 1)
        notice = read_json(peer_notices_dir(cfg, "a") / names[0])
        self.assertEqual(notice["kind"], "peer")
        self.assertEqual(notice["message"]["in_reply_to"], task_id)
        self.assertEqual(notice["message"]["from"], "b@example.invalid")
        self.assertNotEqual(notice["notice_id"], task_id, "a reply is a new notice with its own id")
        self.assertEqual(result["message_id"], notice["notice_id"])
        # Nothing on the mail lane.
        self.assertEqual(list_notices(cfg, "a"), [])

        line = events(cfg, "a", "peer_notice_placed")[0]
        self.assertEqual(line["in_reply_to"], task_id)
        self.assertEqual(line["reply_basis"], "reply_window")

    def test_reply_along_a_declared_edge_is_always_permitted(self):
        cfg = make_peer_config(self, {"a": {"peer_senders": ["b"]}, "b": {"peer_senders": ["a"]}})
        task_id = self._task(cfg)
        _age_record(cfg, "b", task_id, seconds=cfg.peer_reply_window_seconds * 10)
        write_request(cfg, "b", "00000001", in_reply_to=task_id, to=["x@example.invalid"])
        outbound.drain_instance(cfg, "b")
        self.assertEqual(read_json(result_path(cfg, "b", "00000001"))["reason_code"], "peer_routed")
        line = events(cfg, "a", "peer_notice_placed")[0]
        self.assertEqual(line["reply_basis"], "edge")

    def test_expired_window_without_an_edge_is_rejected_and_audited(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}},
                               top={"peer_reply_window_seconds": 3600})
        task_id = self._task(cfg)
        _age_record(cfg, "b", task_id, seconds=3601)
        write_request(cfg, "b", "00000001", in_reply_to=task_id, to=["x@example.invalid"])
        outbound.drain_instance(cfg, "b")
        result = read_json(result_path(cfg, "b", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]),
                         ("rejected", "peer_reply_window_expired"))
        self.assertEqual(list_peer_notices(cfg, "a"), [])
        self.assertEqual(list_notices(cfg, "a"), [])
        refusal = events(cfg, "b", "peer_refused")[0]
        self.assertEqual(refusal["reason_code"], "peer_reply_window_expired")
        self.assertEqual(refusal["in_reply_to"], task_id)
        self.assertEqual(refusal["recipients"], ["a"])

    def test_window_boundary_inclusive_and_unparseable_ts_fails_closed(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}},
                               top={"peer_reply_window_seconds": 3600})
        task_id = self._task(cfg)
        _age_record(cfg, "b", task_id, seconds=3500)
        write_request(cfg, "b", "00000001", in_reply_to=task_id, to=["x@example.invalid"])
        outbound.drain_instance(cfg, "b")
        self.assertEqual(read_json(result_path(cfg, "b", "00000001"))["reason_code"], "peer_routed")

        task2 = self._task(cfg, req_id="00000002")
        path = binding.ledger_path(cfg.state_dir, "b", task2)
        doc = json.loads(path.read_text())
        doc["ts"] = "yesterday"
        path.write_text(json.dumps(doc))
        write_request(cfg, "b", "00000002", in_reply_to=task2, to=["x@example.invalid"])
        outbound.drain_instance(cfg, "b")
        self.assertEqual(read_json(result_path(cfg, "b", "00000002"))["reason_code"],
                         "peer_reply_window_expired")

    def test_several_replies_and_a_thread_alternate_without_both_edges(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        task_id = self._task(cfg)
        # b: progress, then result — two replies to one id.
        write_request(cfg, "b", "00000001", in_reply_to=task_id, to=["x@example.invalid"],
                      body_text="progress")
        write_request(cfg, "b", "00000002", in_reply_to=task_id, to=["x@example.invalid"],
                      body_text="result")
        outbound.drain_instance(cfg, "b")
        a_notices = list_peer_notices(cfg, "a")
        self.assertEqual(len(a_notices), 2)
        result_id = read_json(result_path(cfg, "b", "00000002"))["message_id"]
        # a replies to b's result: a -> b has an edge anyway, but the reply
        # binds from the ledger, so draft.to is discarded.
        write_request(cfg, "a", "00000002", in_reply_to=result_id, to=["x@example.invalid"],
                      body_text="thanks")
        outbound.drain_instance(cfg, "a")
        self.assertEqual(read_json(result_path(cfg, "a", "00000002"))["reason_code"], "peer_routed")
        b_notices = list_peer_notices(cfg, "b")
        self.assertEqual(len(b_notices), 2)
        replies = [read_json(peer_notices_dir(cfg, "b") / n)["message"].get("in_reply_to")
                   for n in b_notices]
        self.assertIn(result_id, replies)

    def test_reply_to_a_mail_notice_stays_mail_even_with_a_domain(self):
        cfg = make_peer_config(self, {
            "a": {"peers": ["c"]}, "b": {"peer_senders": ["a"]}, "c": {"peers": ["a"]},
        })
        write_request(cfg, "a", "00000001", to=[addr("c")])
        outbound.drain_instance(cfg, "a")
        mail_id = notice_id_of(list_notices(cfg, "c")[0])
        write_request(cfg, "c", "00000001", in_reply_to=mail_id, to=["x@example.invalid"])
        outbound.drain_instance(cfg, "c")
        result = read_json(result_path(cfg, "c", "00000001"))
        self.assertEqual(result["reason_code"], "recipient_bound")
        self.assertEqual(len(list_notices(cfg, "a")), 1)
        self.assertEqual(list_peer_notices(cfg, "a"), [])
        notice = read_json(notices_dir(cfg, "a") / list_notices(cfg, "a")[0])
        self.assertEqual(notice["kind"], "deliver")
        self.assertEqual(notice["message"]["in_reply_to"], mail_id)


class InReplyToIffResolvedTests(RouterTestCase):
    """THE FIXTURE: a peer notice never carries an `in_reply_to` the ledger
    did not resolve. Every attempt below to smuggle one in ends in
    `rejected` with NO notice on either tree; and the one notice that does
    carry `in_reply_to` names a record in the sender's ledger."""

    def _fleet(self):
        return make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})

    def _no_notices_anywhere(self, cfg):
        for n in cfg.instances:
            self.assertEqual(list_peer_notices(cfg, n), [], f"peer notice leaked into {n}")
            self.assertEqual(list_notices(cfg, n), [], f"mail notice leaked into {n}")

    def test_unresolved_key_is_rejected_never_stripped_into_a_fresh_task(self):
        cfg = self._fleet()
        # a has a declared edge to b, so a STRIPPING router would forward this
        # as a fresh task. This one refuses.
        for req_id, key in (("00000001", "0" * 32), ("00000002", "not-a-notice-id")):
            write_request(cfg, "a", req_id, in_reply_to=key, to=[addr("b")], body_text="result?")
        outbound.drain_instance(cfg, "a")
        for req_id in ("00000001", "00000002"):
            result = read_json(result_path(cfg, "a", req_id))
            self.assertEqual((result["outcome"], result["reason_code"]),
                             ("rejected", "unresolved_reply"), req_id)
        self._no_notices_anywhere(cfg)

    def test_draft_reply_to_message_id_is_bound_by_the_same_rule(self):
        cfg = self._fleet()
        outbox = cfg.instances["a"].outbox_root
        outbox.mkdir(parents=True, exist_ok=True)
        (outbox / "req-00000001.json").write_bytes(json.dumps({
            "contract_version": "2", "req_id": "00000001",
            "draft": {"to": [addr("b")], "subject": "s", "body_text": "b",
                      "reply_to_message_id": "f" * 32},
        }).encode())
        outbound.drain_instance(cfg, "a")
        self.assertEqual(read_json(result_path(cfg, "a", "00000001"))["reason_code"],
                         "unresolved_reply")
        self._no_notices_anywhere(cfg)

    def test_a_forged_notice_in_the_agents_own_peer_tree_resolves_nothing(self):
        """Namespace-mode agents cannot be on the lane, and in handoff mode
        `peer/` is read-only to the agent — but binding must not depend on
        either: it reads ONLY the router's ledger."""
        cfg = self._fleet()
        forged_id = "ab" * 16
        forged = {"contract_version": "2", "notice_id": forged_id, "ts": "t", "kind": "peer",
                  "message": {"id": forged_id, "from": addr("a"), "subject": "s",
                              "preview": "p", "mailbox": "peer"}}
        (peer_notices_dir(cfg, "b") / f"notice-{forged_id}.json").write_text(json.dumps(forged))
        write_request(cfg, "b", "00000001", in_reply_to=forged_id, to=["x@example.invalid"])
        outbound.drain_instance(cfg, "b")
        self.assertEqual(read_json(result_path(cfg, "b", "00000001"))["reason_code"],
                         "unresolved_reply")
        self.assertEqual(list_peer_notices(cfg, "a"), [])

    def test_a_reply_to_a_dsn_cannot_bind(self):
        """A DSN is ledgered with `from_instance: null`; binding fails closed."""
        cfg = self._fleet()
        from router import deliver
        dsn = deliver.deliver_router_notice(
            cfg, cfg.state_dir, "a", subject="Not delivered: denied", body_text="x",
            in_reply_to="0" * 32,
        )
        write_request(cfg, "a", "00000001", in_reply_to=dsn["notice_id"], to=[addr("b")])
        outbound.drain_instance(cfg, "a")
        self.assertEqual(read_json(result_path(cfg, "a", "00000001"))["reason_code"],
                         "unresolved_reply")
        self.assertEqual(list_peer_notices(cfg, "b"), [])

    def test_every_in_reply_to_on_a_peer_notice_names_a_ledger_record_under_the_sender(self):
        """The positive half, swept over every peer notice the fleet wrote."""
        cfg = self._fleet()
        write_request(cfg, "a", "00000001", to=[addr("b")])
        outbound.drain_instance(cfg, "a")
        task_id = notice_id_of(list_peer_notices(cfg, "b")[0])
        write_request(cfg, "b", "00000001", in_reply_to=task_id, to=["x@example.invalid"])
        outbound.drain_instance(cfg, "b")
        write_request(cfg, "a", "00000002", to=[addr("b")])  # a second fresh task
        outbound.drain_instance(cfg, "a")

        seen = 0
        for recipient in cfg.instances:
            for name in list_peer_notices(cfg, recipient):
                notice = read_json(peer_notices_dir(cfg, recipient) / name)
                sender = notice["message"]["from"].split("@")[0]
                irt = notice["message"].get("in_reply_to")
                if irt is None:
                    continue
                seen += 1
                record = binding.read_ledger_record(cfg.state_dir, sender, irt)
                self.assertIsNotNone(record, "in_reply_to must resolve in the SENDER's ledger")
                self.assertEqual(record["message_id"], irt)
                self.assertEqual(record["from_instance"], recipient)
                self.assertEqual(record["tree"], "peer")
        self.assertEqual(seen, 1, "exactly one reply was placed")


if __name__ == "__main__":
    unittest.main()
