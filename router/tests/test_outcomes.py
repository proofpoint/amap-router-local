"""Step 5 of the peer-lane build: the outcome reader, the outcome record,
DSNs, and the `status` banners — driven through `service.run_once`, the unit
the deployment loop runs, with the daemon's writes stood in for by
`peer_helpers.write_outcome` in the agreed shape."""

import json
import os
import unittest

from router import binding, firstsight, outbound, outcomes, service
from router.status import StatusTracker, render
from router.tests.helpers import (
    RouterTestCase, list_notices, messages_dir, notices_dir, read_json, result_path,
    write_request,
)
from router.tests.peer_helpers import (
    addr, events, list_peer_notices, load_amp_validate, make_peer_config, notice_id_of,
    outcomes_dir, write_outcome,
)


class OutcomeFlowTests(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.amp = load_amp_validate()

    def _fleet(self):
        return make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})

    def _task(self, cfg, req_id="00000001"):
        """a -> b; returns the peer id the SENDER learned from its result
        (notice names sort by random hex, so a listing cannot say which is
        newest)."""
        write_request(cfg, "a", req_id, to=[addr("b")], body_text="task")
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", req_id))
        self.assertEqual(result["reason_code"], "peer_routed")
        return result["message_id"]

    def _record(self, cfg, nid, outcome):
        return outcomes.record_path(cfg.state_dir, "b", "peer", nid, outcome)

    def test_delivered_is_recorded_once_audited_and_unlinked(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        path = write_outcome(cfg, "b", nid, "delivered", detail="injected into pane 0")
        summary = service.run_once(cfg)
        b = summary["b"]
        self.assertEqual((b["peer_outcomes_seen"], b["peer_delivered"]), (1, 1))
        self.assertFalse(path.exists(), "consumed outcomes are unlinked")
        rec = read_json(self._record(cfg, nid, "delivered"))
        self.assertEqual(rec["outcome"], "delivered")
        self.assertEqual(rec["notice_id"], nid)
        self.assertEqual(rec["outcome_ts"], "2026-09-03T12:00:00Z")
        self.assertEqual(rec["detail"], "injected into pane 0")
        self.assertEqual((rec["from_instance"], rec["to_instance"]), ("a", "b"))
        line = events(cfg, "b", "outcome_consumed")[0]
        self.assertEqual(line["instance"], "b")
        self.assertEqual((line["tree"], line["notice_id"], line["outcome"]), ("peer", nid, "delivered"))
        self.assertEqual(line["outcome_ts"], "2026-09-03T12:00:00Z")
        self.assertEqual(line["detail"], "injected into pane 0")
        self.assertEqual((line["from_instance"], line["to_instance"]), ("a", "b"))
        # Nothing to the sender; the ledger record is untouched.
        self.assertEqual(list_notices(cfg, "a"), [])
        self.assertNotIn("outcome", read_json(binding.ledger_path(cfg.state_dir, "b", nid)))

    def test_same_transition_twice_is_a_duplicate_no_second_dsn(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        write_outcome(cfg, "b", nid, "denied")
        service.run_once(cfg)
        self.assertEqual(len(list_notices(cfg, "a")), 1)
        path = write_outcome(cfg, "b", nid, "denied")
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_outcome_discarded"], 1)
        self.assertEqual(summary["b"]["peer_dsn_sent"], 0)
        self.assertFalse(path.exists())
        self.assertEqual(len(list_notices(cfg, "a")), 1, "a sender is never DSN'd twice")
        discard = events(cfg, "b", "outcome_discarded")[0]
        self.assertEqual(discard["cause"], "duplicate")

    def test_held_then_delivered_are_two_transitions_both_recorded(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        write_outcome(cfg, "b", nid, "held")
        s1 = service.run_once(cfg)
        self.assertEqual(s1["b"]["peer_held"], 1)
        self.assertEqual(s1["b"]["peer_alerts"], [{
            "kind": "held", "notice_id": nid, "sender": "a", "recipient": "b",
            "ts": "2026-09-03T12:00:00Z",
        }])
        self.assertEqual(list_notices(cfg, "a"), [], "held tells the sender nothing")
        write_outcome(cfg, "b", nid, "delivered", ts="2026-09-03T12:05:00Z")
        s2 = service.run_once(cfg)
        self.assertEqual(s2["b"]["peer_delivered"], 1)
        self.assertTrue(self._record(cfg, nid, "held").is_file())
        self.assertTrue(self._record(cfg, nid, "delivered").is_file())

    def test_denied_sends_the_dsn_fixture(self):
        """THE DSN FIXTURE: the notice as it appears in the sender's inbox/."""
        cfg = self._fleet()
        nid = self._task(cfg)
        write_outcome(cfg, "b", nid, "denied", ts="2026-09-03T12:34:56Z",
                      detail="user clicked Deny — SECRET reason text")
        summary = service.run_once(cfg)
        self.assertEqual((summary["b"]["peer_denied"], summary["b"]["peer_dsn_sent"]), (1, 1))

        names = list_notices(cfg, "a")
        self.assertEqual(len(names), 1)
        notice = read_json(notices_dir(cfg, "a") / names[0])
        dsn_id = notice_id_of(names[0])
        self.assertEqual(notice, {
            "contract_version": "2",
            "notice_id": dsn_id,
            "ts": notice["ts"],
            "kind": "deliver",
            "message": {
                "id": dsn_id,
                "from": "amap.router@example.invalid",
                "subject": "Not delivered: denied",
                "preview": notice["message"]["preview"],
                "mailbox": "inbox",
                "provenance": "internal",
                "in_reply_to": nid,
            },
        })
        self.assertEqual(self.amp.check_document("notice-produced.json", notice), [])
        message = read_json(messages_dir(cfg, "a") / names[0])
        self.assertEqual(message["from"], "amap.router@example.invalid")
        self.assertEqual(message["to"], "a@example.invalid")
        body = message["body_text"]
        for must in ("reported outcome: denied", f"peer message id: {nid}",
                     "recipient: b@example.invalid", "reported at: 2026-09-03T12:34:56Z",
                     "The recipient's sandbox reported that a human reviewed this message "
                     "and declined it."):
            self.assertIn(must, body)
        # A claim, never a fact: every sentence attributes the outcome to the
        # receiving sandbox's report (round 3, item 1).
        self.assertTrue(body.startswith("The sandbox at b@example.invalid reported that it "
                                        "did not deliver your peer message."), body)
        for never in ("A human at the recipient reviewed", "was not delivered.\n"):
            self.assertNotIn(never, body)
        for ln in (ln for ln in body.splitlines() if ln):
            self.assertTrue(
                "reported" in ln or ln.startswith(("peer message id:", "recipient:")),
                f"unattributed line: {ln!r}")
        self.assertNotIn("SECRET", body, "detail is logged, never forwarded")
        self.assertNotIn("SECRET", json.dumps(notice))
        self.assertEqual(self.amp.check_document("message-produced.json", message), [])
        # Ledgered under the sender as router-authored: a reply cannot bind.
        rec = read_json(binding.ledger_path(cfg.state_dir, "a", dsn_id))
        self.assertIsNone(rec["from_instance"])
        self.assertEqual(rec["authored_by"], "router")
        self.assertEqual(rec["tree"], "inbox")
        self.assertIsNone(binding.resolve_binding(cfg.state_dir, "a", dsn_id))
        # Audit: the DSN in a's log, the consumed outcome in b's, detail only in b's.
        dsn_line = events(cfg, "a", "dsn_sent")[0]
        self.assertEqual(dsn_line["instance"], "a")
        self.assertEqual(dsn_line["notice_id"], dsn_id)
        self.assertEqual(dsn_line["in_reply_to"], nid)
        self.assertEqual(dsn_line["peer_notice_id"], nid)
        self.assertEqual(dsn_line["outcome"], "denied")
        self.assertEqual(dsn_line["peer_recipient"], "b")
        self.assertEqual((dsn_line["from"], dsn_line["to"]),
                         ("amap.router@example.invalid", "a@example.invalid"))
        self.assertEqual(dsn_line["subject"], "Not delivered: denied")
        self.assertIn("SECRET", json.dumps(events(cfg, "b", "outcome_consumed")))
        self.assertNotIn("SECRET", json.dumps(events(cfg, "a")))

    def test_refused_sends_a_dsn_and_alerts_naming_both_ends(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        write_outcome(cfg, "b", nid, "refused")
        summary = service.run_once(cfg)
        self.assertEqual((summary["b"]["peer_refused"], summary["b"]["peer_dsn_sent"]), (1, 1))
        self.assertEqual(summary["b"]["peer_alerts"][0]["kind"], "refused")
        self.assertEqual((summary["b"]["peer_alerts"][0]["sender"],
                          summary["b"]["peer_alerts"][0]["recipient"]), ("a", "b"))
        notice = read_json(notices_dir(cfg, "a") / list_notices(cfg, "a")[0])
        self.assertEqual(notice["message"]["subject"], "Not delivered: refused")
        body = read_json(messages_dir(cfg, "a") / list_notices(cfg, "a")[0])["body_text"]
        self.assertIn("The recipient's sandbox reported that its delivery daemon refused "
                      "this message", body)
        self.assertNotIn("The recipient's delivery daemon refused it", body)
        self.assertIn("reported outcome: refused", body)
        # AND IT NAMES NO CAUSE. `detail` is never forwarded, so the router
        # does not know one; the previous text asserted an allowlist miss,
        # which was a guess before ruling 16 and false after it. An operator
        # chasing that sentence looks for a list no daemon keeps, while the
        # real reason sits in the recipient's log.
        for invented in ("allowed-senders", "allowlist", "allowed_senders"):
            self.assertNotIn(invented, body,
                             "the DSN must not name a cause this router cannot know")
        self.assertIn("does not forward", body)

    def test_ambiguous_target_and_inject_failed_tell_the_sender_nothing(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        write_outcome(cfg, "b", nid, "ambiguous_target")
        s1 = service.run_once(cfg)
        write_outcome(cfg, "b", nid, "inject_failed")
        s2 = service.run_once(cfg)
        self.assertEqual(s1["b"]["peer_ambiguous_target"], 1)
        self.assertEqual(s2["b"]["peer_inject_failed"], 1)
        self.assertEqual(s2["b"]["peer_alerts"], [])
        self.assertEqual(list_notices(cfg, "a"), [])
        # The notice stays in the spool: nothing is ever re-written or removed.
        self.assertEqual(len(list_peer_notices(cfg, "b")), 1)

    def test_unknown_notice_id_is_discarded_and_unlinked(self):
        cfg = self._fleet()
        self._task(cfg)
        path = write_outcome(cfg, "b", "0" * 32, "delivered")
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_outcome_discarded"], 1)
        self.assertFalse(path.exists())
        self.assertEqual(events(cfg, "b", "outcome_discarded")[0]["cause"], "unknown_notice_id")

    def test_an_id_issued_to_another_recipient_is_unknown_here(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}, "c": {"peer_senders": ["a"]}})
        write_request(cfg, "a", "00000001", to=[addr("c")])
        outbound.drain_instance(cfg, "a")
        c_id = notice_id_of(list_peer_notices(cfg, "c")[0])
        write_outcome(cfg, "b", c_id, "denied")  # b claims an outcome for c's notice
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_outcome_discarded"], 1)
        self.assertEqual(list_notices(cfg, "a"), [], "no DSN on a forged cross-recipient outcome")

    def test_malformed_shapes_are_discarded(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        good = {"outcome": "delivered", "ts": "2026-09-03T12:00:00Z", "tree": "peer", "notice_id": nid}
        cases = {
            "extra_key": {**good, "extra": 1},
            "missing_ts": {k: v for k, v in good.items() if k != "ts"},
            "bad_outcome": {**good, "outcome": "delivered!"},
            "wrong_tree": {**good, "tree": "inbox"},
            "id_mismatch": {**good, "notice_id": "1" * 32},
            "detail_not_string": {**good, "detail": 7},
            "not_object": ["x"],
        }
        for label, doc in cases.items():
            with self.subTest(case=label):
                path = write_outcome(cfg, "b", nid, "delivered", doc_override=doc)
                summary = service.run_once(cfg)
                self.assertEqual(summary["b"]["peer_outcome_discarded"], 1, label)
                self.assertEqual(summary["b"]["peer_delivered"], 0, label)
                self.assertFalse(path.exists(), label)
        path = write_outcome(cfg, "b", nid, "delivered", raw_override=b"\xff not json")
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_outcome_discarded"], 1)
        self.assertFalse(path.exists())
        self.assertFalse(self._record(cfg, nid, "delivered").exists())

    def test_staging_and_hostile_names_are_never_opened_or_removed(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        d = outcomes_dir(cfg, "b")
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".peer-{nid}.json.tmp"
        tmp.write_text("partial")
        upper = d / f"peer-{nid.upper()}.json"
        upper.write_text("{}")
        mail = d / f"mail-{nid}.json"
        mail.write_text("{}")
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_outcomes_seen"], 0)
        for p in (tmp, upper, mail):
            self.assertTrue(p.exists(), f"{p.name} must be left alone")

    def test_hard_link_and_symlink_are_refused_and_left_in_place(self):
        cfg = self._fleet()
        nid = self._task(cfg)
        d = outcomes_dir(cfg, "b")
        d.mkdir(parents=True, exist_ok=True)
        outside = self.tmp / "outside.json"
        outside.write_text(json.dumps({"outcome": "delivered", "ts": "t", "tree": "peer", "notice_id": nid}))
        os.link(outside, d / f"peer-{nid}.json")
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_outcome_errored"], 1)
        self.assertEqual(summary["b"]["peer_delivered"], 0)
        self.assertTrue((d / f"peer-{nid}.json").exists())
        os.unlink(d / f"peer-{nid}.json")
        os.symlink(outside, d / f"peer-{nid}.json")
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_delivered"], 0)
        self.assertTrue((d / f"peer-{nid}.json").is_symlink())

    def test_no_outcomes_dir_yet_is_the_empty_summary(self):
        cfg = self._fleet()
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["peer_outcomes_seen"], 0)
        self.assertEqual(summary["b"]["peer_alerts"], [])
        self.assertNotIn("peer_outcomes_seen", summary["a"]
                         if cfg.instances["a"].peer_root is None else {})

    def test_a_never_seen_recipient_still_has_its_outcomes_consumed(self):
        """First sight governs what an instance may SEND. The outcome leg is
        inbound-driven and must run regardless — otherwise a DSN owed to the
        SENDER would be withheld because the RECIPIENT happened to be new to
        this router. Removing the marker puts `b` back to never-seen, which
        is the strongest form of that state."""
        cfg = self._fleet()
        nid = self._task(cfg)
        os.unlink(firstsight.marker_path(cfg.state_dir, "b"))
        write_outcome(cfg, "b", nid, "denied")
        summary = service.run_once(cfg)
        self.assertEqual(summary["b"]["first_sight"], 1,
                         "b should have been snapshotted afresh this poll")
        self.assertEqual(summary["b"]["peer_dsn_sent"], 1)
        self.assertEqual(len(list_notices(cfg, "a")), 1)


class StatusBannerTests(RouterTestCase):
    def _fleet(self):
        return make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})

    def _task(self, cfg, req_id="00000001"):
        """a -> b; returns the peer id the SENDER learned from its result
        (notice names sort by random hex, so a listing cannot say which is
        newest)."""
        write_request(cfg, "a", req_id, to=[addr("b")], body_text="task")
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", req_id))
        self.assertEqual(result["reason_code"], "peer_routed")
        return result["message_id"]

    def test_held_and_refused_banner_ambiguous_only_when_recurring(self):
        cfg = self._fleet()
        n1, n2, n3 = self._task(cfg), self._task(cfg, "00000002"), self._task(cfg, "00000003")
        tracker = StatusTracker()
        write_outcome(cfg, "b", n1, "held")
        write_outcome(cfg, "b", n2, "refused")
        write_outcome(cfg, "b", n3, "ambiguous_target")
        service.poll_once(cfg, tracker)
        doc = tracker.to_doc()
        totals = doc["instances"]["b"]["totals"]
        self.assertEqual((totals["peer_held"], totals["peer_refused"], totals["peer_ambiguous_target"]),
                         (1, 1, 1))
        self.assertEqual(len(doc["instances"]["b"]["peer_alerts"]), 3)
        out = render(doc)
        self.assertIn("PEER HELD (1)", out)
        # NAMES NO CAUSE. `held` has at least two, which this router cannot
        # tell apart: a human reviewed and parked it, or the receiving
        # sandbox has `crossSessionInbound` not set to accept — a config
        # state and nobody's decision. An earlier version asserted the human
        # one in the banner text, which is the same mistake `outcomes.py`
        # records against the `refused` DSN ("named a cause anyway... cost an
        # operator a real debugging session"). Recovery differs too: the
        # config case fixes itself when the setting changes.
        # THE TWO "HELD"s ARE DISTINGUISHABLE. The status line's outbound
        # counter and the peer-lane banner count OPPOSITE DIRECTIONS —
        # what this instance tried to SEND and a human must release, versus
        # what someone sent TO it and its own daemon declined. Same word on
        # adjacent lines invited an operator to relate two disjoint numbers,
        # so the line's label is `for_human=` and the spec's word `held` is
        # left to the spec's concept.
        instance_line = next(ln for ln in out.splitlines() if ln.startswith("b "))
        self.assertIn("for_human=", instance_line)
        self.assertNotIn("held=", instance_line,
                         "the outbound counter must not share the word "
                         "`held` with the peer-lane outcome one line below")

        held_line = next(ln for ln in out.splitlines() if "PEER HELD" in ln)
        for guess in ("human approval", "human reviewed", "crossSessionInbound"):
            self.assertNotIn(guess, held_line,
                             f"the PEER HELD banner states a cause ({guess!r}) "
                             f"that this router cannot know")
        self.assertIn("outcomes/", held_line,
                      "having declined to guess, it must say where the "
                      "daemon's own `detail` can be read")
        self.assertIn("PEER REFUSED", out)
        self.assertIn(f"(notice {n2})", out)
        self.assertNotIn("AMBIGUOUS TARGET", out, "once is not recurring")
        # Claims, not facts: each banner attributes its outcome to b's report.
        banners = [ln for ln in out.splitlines() if ln.startswith("    ** PEER")]
        self.assertEqual(len(banners), 2)
        for ln in banners:
            self.assertIn("b's sandbox reported", ln)
        self.assertNotIn("a receiving session parked", out)
        self.assertNotIn("b's daemon refused", out)

        # A second ambiguous_target for the same recipient recurs -> banner.
        n4 = self._task(cfg, "00000004")
        write_outcome(cfg, "b", n4, "ambiguous_target")
        service.poll_once(cfg, tracker)
        out2 = render(tracker.to_doc())
        self.assertIn("AMBIGUOUS TARGET recurring (2): b's sandbox reported", out2)
        self.assertNotIn("more than one live session in b;", out2)
        # Of the three, only n2 (refused) is placed-but-denied.
        self.assertEqual([d["notice_id"] for d in doc["instances"]["b"]["placed_but_denied"]],
                         [n2])
        # status.json parses and carries the alerts.
        raw = json.loads((cfg.state_dir / "status.json").read_text())
        self.assertEqual(raw["instances"]["b"]["totals"]["peer_ambiguous_target"], 2)
        # Files are consumed in name order (random hex), so assert the set.
        self.assertEqual(sorted(a["kind"] for a in raw["instances"]["b"]["peer_alerts"]),
                         ["ambiguous_target", "ambiguous_target", "held", "refused"])

    def test_no_peer_lane_renders_no_peer_banner_and_no_peer_keys_in_summary(self):
        cfg = self.make_config({"a": ["b"], "b": ["a"]})
        tracker = StatusTracker()
        summary = service.poll_once(cfg, tracker)
        self.assertNotIn("peer_outcomes_seen", summary["a"])
        self.assertNotIn("peer_placed_denied", summary["a"])
        self.assertNotIn("placed_but_denied", tracker.to_doc()["instances"]["a"])
        out = render(tracker.to_doc())
        self.assertNotIn("PEER", out)
        self.assertNotIn("PLACED BUT DENIED", out)


class PlacedButDeniedTests(RouterTestCase):
    """Round 3, item 2: the one shape a receiver's deniability takes — per
    receiver, the notices THIS router's ledger says it placed whose latest
    recorded outcome is `denied` or `refused` — as a `status` banner and a
    JSON key, recomputed from router-private state on every poll."""

    def _fleet(self):
        return make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})

    def _task(self, cfg, req_id):
        write_request(cfg, "a", req_id, to=[addr("b")], body_text="task")
        outbound.drain_instance(cfg, "a")
        result = read_json(result_path(cfg, "a", req_id))
        self.assertEqual(result["reason_code"], "peer_routed")
        return result["message_id"]

    def test_latest_outcome_decides_and_both_renderings_carry_it(self):
        cfg = self._fleet()
        n_denied = self._task(cfg, "00000001")
        n_refused = self._task(cfg, "00000002")
        n_recovered = self._task(cfg, "00000003")   # denied, then delivered
        n_held = self._task(cfg, "00000004")        # held only
        n_late = self._task(cfg, "00000005")        # held, then denied
        tracker = StatusTracker()

        write_outcome(cfg, "b", n_denied, "denied", ts="2026-09-03T10:00:01Z")
        write_outcome(cfg, "b", n_refused, "refused", ts="2026-09-03T10:00:02Z")
        write_outcome(cfg, "b", n_recovered, "denied")
        write_outcome(cfg, "b", n_held, "held")
        write_outcome(cfg, "b", n_late, "held")
        service.poll_once(cfg, tracker)
        write_outcome(cfg, "b", n_recovered, "delivered")
        write_outcome(cfg, "b", n_late, "denied", ts="2026-09-03T10:00:05Z")
        summary = service.poll_once(cfg, tracker)

        listed = summary["b"]["peer_placed_denied"]
        self.assertEqual(sorted(d["notice_id"] for d in listed),
                         sorted([n_denied, n_refused, n_late]))
        by_id = {d["notice_id"]: d for d in listed}
        self.assertEqual(by_id[n_denied], {
            "notice_id": n_denied, "sender": "a", "recipient": "b", "outcome": "denied",
            "outcome_ts": "2026-09-03T10:00:01Z",
            "recorded_ts": by_id[n_denied]["recorded_ts"], "req_id": "00000001",
        })
        self.assertEqual(by_id[n_refused]["outcome"], "refused")
        self.assertEqual(by_id[n_late]["outcome"], "denied", "held then denied: latest wins")
        # The sender's side has no such key: only the receiver's ledger can answer.
        self.assertEqual(summary["a"]["peer_placed_denied"], [])

        # JSON status carries the same list, replaced (not accumulated) per poll.
        raw = json.loads((cfg.state_dir / "status.json").read_text())
        self.assertEqual(sorted(d["notice_id"] for d in raw["instances"]["b"]["placed_but_denied"]),
                         sorted([n_denied, n_refused, n_late]))
        self.assertEqual(raw["instances"]["a"]["placed_but_denied"], [])

        # Text status: one banner counting three, one line per notice, claims only.
        out = render(raw)
        self.assertIn("** PLACED BUT DENIED (3): this router placed 3 peer notice(s) in b's "
                      "tree whose latest reported outcome is denied/refused — b's sandbox "
                      "says it did not deliver them **", out)
        for nid, outcome in ((n_denied, "denied"), (n_refused, "refused"), (n_late, "denied")):
            self.assertIn(f"notice {nid} from 'a': reported {outcome} at", out)
        self.assertNotIn(n_recovered, out)
        self.assertNotIn(n_held, out)

    def test_recomputed_from_disk_so_a_restart_and_an_empty_daemon_dir_still_show_it(self):
        cfg = self._fleet()
        nid = self._task(cfg, "00000001")
        write_outcome(cfg, "b", nid, "denied")
        service.poll_once(cfg, StatusTracker())
        # The daemon's file is consumed; a fresh process polls with nothing to read.
        self.assertEqual(os.listdir(outcomes_dir(cfg, "b")), [])
        fresh = StatusTracker()
        summary = service.poll_once(cfg, fresh)
        self.assertEqual(summary["b"]["peer_outcomes_seen"], 0)
        self.assertEqual([d["notice_id"] for d in summary["b"]["peer_placed_denied"]], [nid])
        self.assertIn("PLACED BUT DENIED (1)", render(fresh.to_doc()))
        # Direct: the function itself, and its answer for a notice the ledger
        # does not attribute to the peer tree (the record is deleted).
        self.assertEqual([d["notice_id"] for d in outcomes.placed_but_denied(cfg, "b")], [nid])
        binding.ledger_path(cfg.state_dir, "b", nid).unlink()
        self.assertEqual(outcomes.placed_but_denied(cfg, "b"), [])

    def test_an_errored_poll_keeps_the_last_known_list_absent_is_not_empty(self):
        tracker = StatusTracker()
        tracker.record_poll({"b": {"peer_placed_denied": [{"notice_id": "x" * 32,
                                                           "sender": "a", "outcome": "denied"}]}})
        tracker.record_poll({"b": {"instance_errored": 1}})
        self.assertEqual(len(tracker.to_doc()["instances"]["b"]["placed_but_denied"]), 1)
        tracker.record_poll({"b": {"peer_placed_denied": []}})
        self.assertEqual(tracker.to_doc()["instances"]["b"]["placed_but_denied"], [])

    def test_render_caps_the_listing_and_counts_the_rest(self):
        from router.status import MAX_PLACED_DENIED_LINES
        many = [{"notice_id": f"{i:032x}", "sender": "a", "recipient": "b",
                 "outcome": "denied", "outcome_ts": "t"} for i in range(MAX_PLACED_DENIED_LINES + 3)]
        doc = {"instances": {"b": {"totals": {}, "placed_but_denied": many}}}
        out = render(doc)
        self.assertIn(f"PLACED BUT DENIED ({MAX_PLACED_DENIED_LINES + 3})", out)
        self.assertEqual(out.count("       notice "), MAX_PLACED_DENIED_LINES)
        self.assertIn("... and 3 more (status --json)", out)


if __name__ == "__main__":
    unittest.main()
