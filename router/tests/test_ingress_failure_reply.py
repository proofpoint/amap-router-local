"""§7.2 rows 1 and 2 through the real pump: a failure report, or a reply,
that the downstream runtime correlated to one of THIS router's own outbound
transactions is believed only when this router's own record of that
transaction agrees (`ingress.own_transaction`).

A failure report places ONE router-authored notice listing only the
(transaction, recipient, action) pairs not announced before, reserved
durably first; one with nothing new is suppressed; one that does not match is
held `failure_unmatched` and re-checked from its snapshot. A matched reply is
placed threaded to the router's send; an unmatched one is classified exactly
as mail without the correlation."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest import mock

from router import binding, generations, ingress
from router.tests.peer_helpers import addr
from router.tests.test_ingress_bundle import enc, make
from router.tests.test_ingress_pump import E1, E2, E3, LINK, _Pump

CANARY = "CANARY-FROM-THE-DSN"
SENT_TO = "Rcpt.One@Fleet-A.Example"       # as recorded: canonical "Rcpt.One@fleet-a.example"
OTHER = "two@fleet-a.example"
CANON = "Rcpt.One@fleet-a.example"
MSG_ID = "<sent-1@fleet.example>"


class _Own(_Pump):

    def setUp(self):
        super().setUp()
        self.pin()

    def pin(self):
        """This generation's link pin, as the pass over every generation
        writes it on first inbound use (`ingress.pinned_link`)."""
        link, why = ingress.pinned_link(self.state_dir, self.lid, self.gen, LINK)
        self.assertEqual((link, why), (LINK, None))

    def anchor(self, n="00000001", req_id="00000007", recipients=(SENT_TO, OTHER),
               message_id=MSG_ID, gen=None):
        d = generations.gen_dir(self.state_dir, self.lid, gen or self.gen) / "results"
        d.mkdir(parents=True, exist_ok=True)
        result = {"contract_version": "2", "req_id": req_id, "outcome": "accepted",
                  "reason_code": "allowlisted", "recipients": list(recipients),
                  "message_id": message_id}
        (d / f"{req_id}.json").write_text(json.dumps(
            {"digest": "0" * 64, "result": result, "transport_req_id": n}))

    def txn(self, n="00000001", **kw):
        return dict({"link": LINK, "logical_id": self.lid, "generation": self.gen, "n": n}, **kw)

    def failure_entry(self, eid, reports, txn=None, **kw):
        def facts(f):
            return dict(f, notice_class="failure_notice",
                        failure={"transaction": txn or self.txn(), "correlated_by": "envid",
                                 "reports": reports})
        return enc(make(nid=eid, facts_extra=facts, to=addr("bravo"), blobs=(),
                        drop_message_attachments=True,
                        notice_extra={"message": {"id": "42", "from": "MAILER-DAEMON@fleet-b.example",
                                                  "subject": CANARY, "preview": CANARY,
                                                  "mailbox": "inbox",
                                                  "provenance": "fleet-remote"}}, **kw))

    def reply_entry(self, eid, from_value, message_id=MSG_ID, txn=None, **facts_kw):
        def facts(f):
            f = dict(f, in_reply_to={"message_id": message_id,
                                     "transaction": txn or self.txn()}, **facts_kw)
            if f.get("admission") == "open":
                f.pop("origin_host", None)
            return f
        return enc(make(nid=eid, facts_extra=facts, to=addr("bravo"), blobs=(),
                        drop_message_attachments=True,
                        notice_extra={"message": {"id": "43", "from": from_value,
                                                  "subject": "re", "preview": "p",
                                                  "mailbox": "inbox",
                                                  "provenance": "unverified"
                                                  if facts_kw.get("admission") == "open"
                                                  else "fleet-remote"}}))

    def placed(self):
        out = []
        inbox = self.keyed.instances["bravo"].inbox_root
        for name in self.notices():
            notice = json.loads((inbox / "notices" / name).read_text())
            spool = json.loads((inbox / "messages" / name).read_text())
            out.append((notice, spool))
        return out


def failed(recipient, status="5.1.1", action="failed"):
    return {"recipient": recipient, "action": action, "status": status}


class FailureNoticeTests(_Own):

    def test_a_matched_report_places_one_runtime_authored_notice(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(CANON)])
        self.pump()
        [(notice, spool)] = self.placed()
        self.assertEqual(notice["message"]["in_reply_to"], MSG_ID, "threaded to the send")
        self.assertTrue(notice["message"]["from"].startswith("amap.router@"))
        body = spool["body_text"]
        self.assertIn(SENT_TO, body, "the RECORDED recipient string")
        self.assertIn("00000007", body)
        self.assertIn("status 5.1.1", body)
        self.assertNotIn(CANARY, json.dumps([notice, spool]), "text from the report forwarded")
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))
        rec = binding.read_ledger_record(self.state_dir, "bravo", notice["notice_id"],
                                         state_key=self.lid)
        self.assertEqual(rec.get("authored_by"), "router", "a reply to it must fail closed")
        self.assertFalse(set(binding.MAIL_ORIGIN_MEMBERS) & set(rec))

    def test_a_repeated_report_is_suppressed_and_places_nothing(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        self.pump()
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(len(self.placed()), 1)
        self.assertEqual(self.state(E2), (ingress.SUPPRESSED_WAITING_REMOVE, None))

    def test_a_mixed_report_lists_only_the_new_pair(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        self.pump()
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO), failed(OTHER)])
        self.pump()
        notices = self.placed()
        self.assertEqual(len(notices), 2)
        second = [s["body_text"] for _n, s in notices if OTHER in s["body_text"]]
        self.assertEqual(len(second), 1)
        self.assertNotIn(SENT_TO, second[0], "an announced pair listed again")

    def test_delayed_and_failed_are_different_pairs(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO, "4.4.1", "delayed")])
        self.pump()
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(len(self.placed()), 2)

    def test_unmatched_is_held_from_its_snapshot_then_placed_once_the_anchor_lands(self):
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, ingress.HELD_FAILURE_UNMATCHED))
        self.assertEqual(self.placed(), [])
        self.anchor()
        self.pump()
        self.assertEqual(len(self.placed()), 1)

    def test_each_mismatch_holds(self):
        cases = {
            "a recipient not sent to": dict(reports=[failed("stranger@fleet-a.example")]),
            "another identity": dict(reports=[failed(SENT_TO)],
                                     txn={"logical_id": "f" * 32}),
            "another link": dict(reports=[failed(SENT_TO)], txn={"link": "link-b"}),
            "an unknown transaction": dict(reports=[failed(SENT_TO)],
                                           txn={"n": "00000099"}),
        }
        for why, case in cases.items():
            with self.subTest(why=why):
                self.tearDown()
                self.setUp()
                self.anchor()
                txn = self.txn(**case.get("txn", {}))
                self.port.entries[E1] = self.failure_entry(E1, case["reports"], txn=txn)
                self.pump()
                self.assertEqual(self.state(E1), (ingress.HELD, ingress.HELD_FAILURE_UNMATCHED))
                self.assertEqual(self.placed(), [])

    def test_a_record_never_handed_over_matches_nothing(self):
        d = generations.gen_dir(self.state_dir, self.lid, self.gen) / "inflight"
        d.mkdir(parents=True, exist_ok=True)
        (d / "00000007.json").write_text(json.dumps({
            "transport_req_id": "00000001", "recipients": [SENT_TO], "request": {},
            "written_ts": "2026-10-13T00:00:00Z"}))
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, ingress.HELD_FAILURE_UNMATCHED))
        (d / "00000007.handed").write_bytes(b"00000001")
        self.pump()
        self.assertEqual(len(self.placed()), 1, "control: once handed, it matches")

    def test_a_report_read_through_a_fenced_generation_is_late(self):
        self.anchor()
        old = self.mint()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)],
                                                   txn=self.txn(generation=old))
        self.pump(gen=old)
        (item,) = self.items(gen=old)
        self.assertEqual(item["cause"], "late_inbound")
        self.assertEqual(self.placed(), [])
        # Decided at dispatch (the late check), before the failure-report
        # path: nothing reserved, no identity minted.
        st = ingress.journal_state(self.state_dir, self.lid, old, "notice", LINK, E1)
        self.assertIsNone(st["notice_id"], "the failure path ran before the late check")
        self.assertFalse((self.state_dir / self.lid / ingress.FAILURE_SEEN_DIR).exists())


class SuppressedRemovalTests(_Own):

    def test_a_suppressed_entry_is_removed_upstream_and_tombstoned(self):
        from router.tests.test_ingress_remover import RecordingRemover
        from router.tests.ingress_double import DoubleReader, ListingTooLarge
        from router.tests.test_ingress_pump import CAP, HORIZON
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        self.pump()
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(self.state(E2), (ingress.SUPPRESSED_WAITING_REMOVE, None))
        remover = RecordingRemover()
        p = ingress.Pump(self.keyed, DoubleReader(self.port), self.lid, self.gen, LINK,
                         report=self.report, recipient="bravo", unresolved=None,
                         attachment_cap=CAP, remover=remover)
        ingress.pump_generation(p, listing_too_large=ListingTooLarge, horizon_s=HORIZON)
        self.assertIn(("notice", E2), remover.calls)
        self.assertEqual(self.state(E2), (ingress.SUPPRESSED_COMPLETE, None))


class ReservationTests(_Own):

    def reservations(self):
        d = self.state_dir / self.lid / ingress.FAILURE_SEEN_DIR
        return sorted(os.listdir(d)) if d.is_dir() else []

    def test_an_owner_that_goes_late_releases_its_pairs(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        real = ingress.generation_is_current
        calls = []

        def late_at_placing(state_dir, lid, gen):
            calls.append(gen)
            return False if len(calls) > 1 else real(state_dir, lid, gen)
        with mock.patch.object(ingress, "generation_is_current", late_at_placing):
            self.pump()
        self.assertIn(self.state(E1)[0], ingress.RELEASED_STATES,
                      "control: the owner went late after reserving")
        self.assertEqual(len(self.reservations()), 1)
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(len(self.placed()), 1, "a released pair was not announced")

    def test_a_placing_ambiguous_owner_keeps_its_pairs(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        self.pump()
        key = ingress.key_for("notice", LINK, self.gen, E1)
        path = ingress.record_path(self.state_dir, self.lid, self.gen, "notice", key)
        doc = json.loads(path.read_text())
        doc.update(state=ingress.HELD, reason=ingress.HELD_PLACING_AMBIGUOUS)
        path.write_text(json.dumps(doc))
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(self.state(E2), (ingress.SUPPRESSED_WAITING_REMOVE, None))

    def test_a_placed_owner_reaching_duplicate_different_held_stays_seen(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        self.pump()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO), failed(OTHER)])
        self.pump()
        self.assertEqual(self.state(E1)[0], ingress.DUPLICATE_DIFFERENT_HELD,
                         "control: the owner moved on after placing")
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO)])
        self.pump()
        self.assertEqual(self.state(E2), (ingress.SUPPRESSED_WAITING_REMOVE, None))
        self.assertEqual(len(self.placed()), 1)

    def test_an_unreadable_owner_is_undecided_and_nothing_is_released(self):
        """The owner lives in ANOTHER generation (a report read after a
        fence) and its record is damaged: the asking entry decides nothing,
        the reservation is untouched, and nothing is released."""
        self.anchor()
        other = "d" * 32
        owner_key = "e" * 64
        owner = ingress.record_path(self.state_dir, self.lid, other, "notice", owner_key)
        owner.parent.mkdir(parents=True)
        owner.write_bytes(b"{damaged")
        res_path = ingress.reservation_path(
            self.state_dir, self.lid, ingress.pair_key(self.txn(), CANON, "failed"))
        res_path.parent.mkdir(parents=True)
        res_path.write_text(json.dumps({"txn": self.txn(), "recipient": CANON,
                                        "action": "failed", "owner_gen": other,
                                        "owner_key": owner_key,
                                        "reserved_at": "2026-10-13T00:00:00Z"}))
        before = res_path.read_bytes()
        self.port.entries[E2] = self.failure_entry(E2, [failed(SENT_TO)])
        counts = self.pump()
        self.assertIsNone(self.state(E2), "a decision made over an unreadable owner")
        self.assertEqual(counts.get("failure_reservations_undecided"), 1)
        self.assertEqual(self.placed(), [])
        self.assertEqual(res_path.read_bytes(), before, "the reservation was touched")
        owner.unlink()                            # cleanly absent: released
        self.pump()
        self.assertEqual(len(self.placed()), 1)

    def test_an_absent_owner_is_released_at_and_beyond_the_horizon(self):
        horizon = self.keyed.ingress_dedup_horizon_days * 86400
        now = datetime.now(timezone.utc)
        for label, age in (("inside", 60), ("exactly at", horizon), ("beyond", horizon + 1)):
            with self.subTest(age=label):
                reserved = (now - timedelta(seconds=age)).strftime("%Y-%m-%dT%H:%M:%SZ")
                res = {"txn": {}, "recipient": "x", "action": "failed",
                       "owner_gen": self.gen, "owner_key": "e" * 64, "reserved_at": reserved}
                self.assertEqual(ingress.owner_verdict(self.state_dir, self.lid, res, "d" * 64),
                                 ingress.RELEASED)
                self.assertEqual(ingress.owner_verdict(self.state_dir, self.lid, res, "e" * 64),
                                 ingress.REUSED, "its own entry reuses it")

    def test_every_state_is_classified_and_an_unlisted_one_is_seen(self):
        named = set(ingress.SEEN_STATES) | set(ingress.RELEASED_STATES) | {ingress.HELD}
        self.assertEqual(named, set(ingress.STATES), "a journal state left unclassified")
        self.assertFalse(set(ingress.SEEN_STATES) & set(ingress.RELEASED_STATES))
        res = {"owner_gen": self.gen, "owner_key": "e" * 64}
        with mock.patch.object(ingress, "read", lambda *a: {"state": "a_future_state"}):
            self.assertEqual(ingress.owner_verdict(self.state_dir, self.lid, res, "d" * 64),
                             ingress.SEEN)

    def test_the_sweep_keeps_a_young_reservation_and_reads_the_one_horizon(self):
        self.anchor()
        self.port.entries[E1] = self.failure_entry(E1, [failed(SENT_TO)])
        real = ingress.generation_is_current
        calls = []

        def late_at_placing(state_dir, lid, gen):
            calls.append(gen)
            return False if len(calls) > 1 else real(state_dir, lid, gen)
        with mock.patch.object(ingress, "generation_is_current", late_at_placing):
            self.pump()                           # the owner is released (late)
        horizon = self.keyed.ingress_dedup_horizon_days * 86400
        now = datetime.now(timezone.utc)
        self.assertEqual(ingress.sweep_reservations(self.state_dir, self.lid, horizon, now), 0,
                         "a young reservation was swept")
        later = now + timedelta(seconds=horizon + 120)
        self.assertEqual(ingress.sweep_reservations(self.state_dir, self.lid, horizon, later), 1)


class ReplyTests(_Own):

    def test_a_matched_reply_is_placed_threaded_even_from_a_trusted_host(self):
        self.anchor()
        self.port.entries[E1] = self.reply_entry(E1, f"R <{CANON}>", origin_host="fleet-a.example")
        self.pump()
        [(notice, _spool)] = self.placed()
        self.assertEqual(notice["message"]["in_reply_to"], MSG_ID)

    def test_a_matched_reply_from_open_admission_is_placed(self):
        self.anchor()
        self.port.entries[E1] = self.reply_entry(E1, CANON, admission="open")
        self.pump()
        self.assertEqual(len(self.placed()), 1)

    def test_an_unmatched_reply_falls_through_never_widened(self):
        cases = {
            "the From was not sent to": dict(from_value="stranger@fleet-a.example"),
            "another identity": dict(from_value=CANON, txn={"logical_id": "f" * 32}),
            "another Message-ID": dict(from_value=CANON, message_id="<other@x>"),
        }
        for why, case in cases.items():
            with self.subTest(why=why):
                self.tearDown()
                self.setUp()
                self.anchor()
                txn = self.txn(**case.get("txn", {}))
                self.port.entries[E1] = self.reply_entry(
                    E1, case["from_value"], message_id=case.get("message_id", MSG_ID),
                    txn=txn, origin_host="fleet-a.example")
                self.pump()
                self.assertEqual(self.placed(), [], "an unmatched reply widened")
                items = self.items()
                self.assertEqual([i["cause"] for i in items], ["cold_fleet_mail"])

    def test_a_reply_to_a_fenced_generations_send_read_through_the_current_tree(self):
        old_gen = self.gen
        self.anchor(gen=old_gen)
        self.mint()
        self.gen = generations.read_doc(self.state_dir, self.lid)["current"]
        self.pin()
        self.port.entries[E1] = self.reply_entry(E1, CANON, txn=self.txn(generation=old_gen),
                                                 origin_host="fleet-a.example")
        self.pump()
        self.assertEqual(len(self.placed()), 1, "authorisation did not survive the fence")

    def test_a_matched_reply_with_another_admission_link_holds(self):
        self.anchor()
        self.port.entries[E1] = self.reply_entry(E1, CANON, admission_link="link-b",
                                                 origin_host="fleet-a.example")
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, ingress.HELD_LINK_MISMATCH))


class SharedHorizonTests(_Own):
    """Reservations and tombstones share ONE horizon: the pump's
    `horizon_s`, which the pass over every generation computes from
    `config.ingress_dedup_horizon_days` alone."""

    def test_the_sweep_runs_with_the_pumps_horizon(self):
        seen = []
        real = ingress.sweep_reservations

        def spy(state_dir, lid, horizon_s, now):
            seen.append(horizon_s)
            return real(state_dir, lid, horizon_s, now)
        with mock.patch.object(ingress, "sweep_reservations", spy):
            self.pump(horizon_s=12345)
        self.assertEqual(seen, [12345])

    def test_the_pass_takes_that_horizon_from_the_one_config_value(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(ingress.pump_all))
        values = [ast.unparse(k.value) for node in ast.walk(tree) if isinstance(node, ast.Call)
                  for k in node.keywords if k.arg == "horizon_s"]
        self.assertEqual(values, ["cfg.ingress_dedup_horizon_days * 86400"])
