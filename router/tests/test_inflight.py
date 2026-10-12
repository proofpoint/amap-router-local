"""The in-flight state (`router/inflight.py`): a request handed to a second
runtime stays unsettled across polls and settles exactly once, from that
runtime's result.

No transport tree exists yet. `FakeTransport` stands in for the transport
and for the downstream runtime, with the downstream ordering the design
adopted: the result is written BEFORE the request is archived. No policy in
this repo returns `ExternalRoute` yet either, so each test injects one.

CRASH POINTS. Every side effect in `inflight` passes through `inflight._effect`;
`CrashPointTests` crashes the lifecycle before and after each one in turn and
proves the later polls still end with one transport request and one agent
result. A raised exception stands in for a process crash because everything
the sequence depends on is on disk; the drain's per-request isolation
catches it the way a restart would discard the process.
"""
from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from unittest import mock

from router import inflight, outbound, reset, validate as validate_mod
from router.tests import helpers
from router.tests.helpers import processed_path, read_json, result_path, write_request

EXT = "you@example.com"


def _external(cfg, sender, draft):
    return outbound.ExternalRoute(tuple(draft["to"]) + tuple(draft.get("cc") or ()))


class FakeTransport:
    """The transport and the downstream runtime. `write_request` refuses to
    overwrite anything already handed over: a rewrite is the failure the
    design forbids, so it fails the test where it happens."""

    def __init__(self):
        self.pending = {}
        self.results = {}
        self.archived = {}
        self.writes = []

    def has_result(self, n):
        return n in self.results

    def has_pending(self, n):
        return n in self.pending

    def has_archived(self, n):
        return n in self.archived

    def read_result(self, n):
        return self.results[n]

    def write_request(self, n, data):
        # Recorded BEFORE the refusal: the drain isolates exceptions, so a
        # refusal alone would be swallowed and the rewrite never seen.
        self.writes.append(n)
        assert n not in self.pending and n not in self.archived and n not in self.results, \
            f"transport request {n} rewritten"
        self.pending[n] = data

    def withdraw_request(self, n):
        """API (3, 0): the in-flight table never calls it yet; a test that
        does gets the Protocol's vocabulary."""
        if n in self.results or n in self.archived:
            return "too_late"
        if n not in self.pending:
            raise FileNotFoundError(n)
        self.archived[n] = self.pending.pop(n)
        return "withdrawn"

    def close(self):
        self.closed = True

    # -- the downstream runtime ------------------------------------------

    def send(self, n, *, outcome="accepted", reason_code="allowlisted",
             detail=None, recipients=None, raw=None):
        doc = {"contract_version": "2", "req_id": n, "outcome": outcome,
               "reason_code": reason_code, "detail": detail, "message_id": "up-1"}
        if recipients is not None:
            doc["recipients"] = recipients
        self.results[n] = raw if raw is not None else json.dumps(doc).encode()
        self.archived[n] = self.pending.pop(n)

    def send_all(self, **kw):
        for n in list(self.pending):
            self.send(n, **kw)


class _InflightCase(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": []})
        self.port = FakeTransport()

    def drain(self, **kw):
        kw.setdefault("cold_policy", _external)
        kw.setdefault("transport", self.port)
        return outbound.drain_instance(self.cfg, "alice", **kw)

    def result(self, req_id="00000001"):
        return read_json(result_path(self.cfg, "alice", req_id))

    def has_result(self, req_id="00000001"):
        return result_path(self.cfg, "alice", req_id).exists()


class LifecycleTests(_InflightCase):

    def test_pending_until_the_downstream_result_then_settled_once(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])

        s1 = self.drain()
        self.assertEqual(self.port.writes, ["00000001"])
        self.assertFalse(self.has_result(), "answered before the downstream runtime accepted")
        self.assertEqual(s1["outbound_inflight_begun"], 1)
        self.assertEqual(s1["inflight"], 1)

        s2 = self.drain()
        self.assertEqual(self.port.writes, ["00000001"], "rewritten while pending")
        self.assertFalse(self.has_result())
        self.assertEqual(s2["outbound_inflight_waiting"], 1)

        self.port.send_all(recipients=[EXT])
        s3 = self.drain()
        r = self.result()
        self.assertEqual(r["outcome"], "accepted")
        self.assertEqual(r["reason_code"], "allowlisted")
        self.assertEqual(r["recipients"], [EXT])
        self.assertEqual(s3["accepted"], 1)
        self.assertEqual(s3["inflight_settled"], 1)
        self.assertEqual(s3["inflight"], 0)
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.assertTrue(processed_path(self.cfg, "alice", "00000001").exists())

        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])

    def test_the_request_is_handed_once_and_rechecked_every_poll(self):
        """Consumed and handed over ONCE; the policy is consulted again by the
        re-check at publication and on every poll while it is pending,
        because what decides a permit can change after it was staged."""
        calls = []

        def spy(cfg, sender, draft):
            calls.append(sender)
            return _external(cfg, sender, draft)

        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain(cold_policy=spy)
        self.assertEqual(calls, ["alice", "alice"], "classified, then re-checked to publish")
        self.drain(cold_policy=spy)
        self.assertEqual(calls, ["alice"] * 3, "re-checked while pending")
        self.assertEqual(self.port.writes, ["00000001"])

    def test_the_verdict_passes_through_verbatim_with_the_detail_prefixed(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.send_all(outcome="queued_for_human",
                           reason_code="recipient_not_allowlisted", detail="held")
        self.drain()
        r = self.result()
        self.assertEqual(r["outcome"], "queued_for_human")
        self.assertEqual(r["reason_code"], "recipient_not_allowlisted")
        self.assertEqual(r["detail"], "transport: held")

    def test_accepted_without_a_recipient_list_reports_the_evaluated_set(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT], cc=["b@example.org"])
        self.drain()
        self.port.send_all()
        self.drain()
        self.assertEqual(self.result()["recipients"], [EXT, "b@example.org"])

    def test_archived_without_a_result_is_an_anomaly_and_never_resubmitted(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.archived["00000001"] = self.port.pending.pop("00000001")
        self.drain()
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "transport_anomaly"))
        self.assertEqual(self.port.writes, ["00000001"])

    def test_a_result_landing_between_the_probes_is_not_read_as_an_anomaly(self):
        """THE RE-CHECK IS THE TEST. The downstream runtime writes its result
        and archives the request after this step's first `has_result` and
        before `has_archived`. Without the second `has_result` that reads as
        "archived without a result", and a SENT message settles
        `transport_anomaly`."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        port = self.port
        real = port.has_result
        fired = []

        def has_result(n):
            seen = real(n)
            if not fired:
                fired.append(n)
                port.send(n)
            return seen

        with mock.patch.object(port, "has_result", has_result):
            self.drain()
        self.assertEqual(fired, ["00000001"])
        self.assertEqual(self.result()["outcome"], "accepted")

    def test_the_staged_copy_is_sent_not_the_agents_later_bytes(self):
        """Ingest by copy: rewriting the outbox file after the hand-off
        changes nothing that reaches the transport. The rewritten file is a
        different request under a used id, and nothing here can tell a
        rewrite from a reset connector's reuse, so it is answered as one:
        the staged copy's verdict stays private (the anchor) and the file
        now in the outbox is refused as `req_id_reused`, never reported as
        sent (test_reuse.py)."""
        write_request(self.cfg, "alice", "00000001", to=[EXT], subject="original")
        self.drain()
        write_request(self.cfg, "alice", "00000001", to=["other@example.net"],
                      subject="rewritten")
        self.port.send_all()
        self.drain()
        sent = json.loads(self.port.archived["00000001"])
        self.assertEqual(sent["draft"]["subject"], "original")
        self.assertEqual(sent["draft"]["to"], [EXT])
        self.assertEqual(self.port.writes, ["00000001"])
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        anchor = read_json(outbound._private_result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(anchor["result"]["outcome"], "accepted")

    def test_without_a_transport_a_cross_host_recipient_is_unknown(self):
        """No transport plugin: every cross-host address is `recipient_unknown`
        before any policy is asked, and nothing is put in flight."""
        called = []
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain(transport=None, cold_policy=lambda c, s, d: called.append(s))
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "recipient_unknown"))
        self.assertEqual(called, [])
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])

    def test_records_without_a_transport_are_left_alone(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        s = self.drain(transport=None)
        self.assertFalse(self.has_result())
        self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])
        self.assertEqual(s["outbound_inflight_waiting"], 1)

    def test_attachments_settle_as_an_anomaly_until_staging_exists(self):
        sidecar = helpers.stage_outbound_sidecars(self.cfg, "alice", "00000001", [b"x"])
        write_request(self.cfg, "alice", "00000001", to=[EXT],
                      attachments=[helpers.attachment_descriptor(b"x", filename="a.txt")])
        self.drain()
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "transport_anomaly"))
        self.assertEqual(self.port.writes, [])
        self.assertIsNotNone(sidecar)

    def test_a_router_without_the_external_leg_reports_no_inflight_keys(self):
        write_request(self.cfg, "alice", "00000001", to=["agent.nobody@local"])
        s = outbound.drain_instance(self.cfg, "alice")
        self.assertFalse([k for k in s if "inflight" in k])


class TransportRequestTests(_InflightCase):

    def _record(self, **doc_overrides):
        doc = {"contract_version": "2", "req_id": "00000009",
               "draft": {"to": [EXT], "subject": "s", "body_text": "b"}}
        doc.update(doc_overrides)
        return {"transport_req_id": "00000003", "request": doc, "recipients": [EXT]}

    def test_it_is_a_valid_submit_request_under_the_transport_id(self):
        doc = json.loads(inflight.transport_request_bytes(self.cfg, "alice", self._record()))
        ok, reason, detail = validate_mod.validate_request(doc)
        self.assertTrue(ok, (reason, detail))
        self.assertEqual(doc["req_id"], "00000003")
        self.assertEqual(doc["agent_id"], "alice")
        self.assertEqual(doc["draft"]["to"], [EXT])

    def test_an_unmapped_threading_key_is_dropped_not_carried_across(self):
        rec = self._record(in_reply_to="n-agent")
        rec["request"]["draft"]["reply_to_message_id"] = "n-agent"
        doc = json.loads(inflight.transport_request_bytes(self.cfg, "alice", rec))
        self.assertNotIn("in_reply_to", doc)
        self.assertNotIn("reply_to_message_id", doc["draft"])

    def test_building_it_leaves_the_staged_copy_untouched(self):
        rec = self._record(in_reply_to="n-agent")
        inflight.transport_request_bytes(self.cfg, "alice", rec)
        self.assertEqual(rec["request"]["req_id"], "00000009")
        self.assertEqual(rec["request"]["in_reply_to"], "n-agent")


class HostileResultTests(_InflightCase):
    """Anything that is not a Result for this transport id with a known
    outcome settles `transport_anomaly`. Each case is checked against a
    valid twin, so the anomaly is the shape's doing and not the fixture's."""

    REC = {"recipients": [EXT]}

    def verdict(self, doc=None, raw=None):
        if raw is None:
            raw = json.dumps(doc).encode()
        return inflight.verdict_from_result(raw, "00000001", self.REC)

    def good(self, **kw):
        doc = {"contract_version": "2", "req_id": "00000001", "outcome": "accepted",
               "reason_code": "allowlisted", "detail": None}
        doc.update(kw)
        return doc

    def test_the_valid_twin_passes(self):
        v = self.verdict(self.good())
        self.assertEqual((v["outcome"], v["reason_code"]), ("accepted", "allowlisted"))

    def test_each_bad_shape_is_an_anomaly(self):
        cases = {
            "not json": dict(raw=b"{nope"),
            "not utf-8": dict(raw=b"\xff\xfe"),
            "not an object": dict(doc=["accepted"]),
            "wrong version": dict(doc=self.good(contract_version="1")),
            "other req_id": dict(doc=self.good(req_id="00000002")),
            "unknown outcome": dict(doc=self.good(outcome="sent")),
            "reason not a string": dict(doc=self.good(reason_code=7)),
            "reason with a newline": dict(doc=self.good(reason_code="a\nb")),
            "detail not a string": dict(doc=self.good(detail={"x": 1})),
            "recipients not strings": dict(doc=self.good(recipients=[1])),
        }
        for label, kw in cases.items():
            with self.subTest(label):
                v = self.verdict(**kw)
                self.assertEqual((v["outcome"], v["reason_code"]),
                                 ("queued_for_human", "transport_anomaly"))

    def test_an_oversized_detail_is_capped(self):
        v = self.verdict(self.good(detail="x" * 10000))
        self.assertEqual(len(v["detail"]), 2000)
        self.assertTrue(v["detail"].startswith("transport: "))

    def test_extra_downstream_recipients_are_reported_as_given_and_logged(self):
        with self.assertLogs("amap_router_local.inflight", logging.ERROR):
            v = self.verdict(self.good(recipients=[EXT, "bcc@evil.example"]))
        self.assertEqual(v["recipients"], [EXT, "bcc@evil.example"])


class CounterTests(_InflightCase):

    def test_ids_are_monotonic_and_the_successor_is_persisted_first(self):
        self.assertEqual(inflight.allocate_transport_req_id(self.cfg, "alice"), "00000001")
        self.assertEqual(inflight.counter_path(self.cfg, "alice").read_text(), "2")
        self.assertEqual(inflight.allocate_transport_req_id(self.cfg, "alice"), "00000002")

    def test_a_corrupt_counter_is_refused_never_restarted(self):
        p = inflight.counter_path(self.cfg, "alice")
        p.parent.mkdir(parents=True)
        for bad in ("", "0", "-3", "abc", "07", "1\n2"):
            with self.subTest(bad=bad):
                p.write_text(bad)
                with self.assertRaises(inflight.CounterCorrupt):
                    inflight.allocate_transport_req_id(self.cfg, "alice")
                self.assertEqual(p.read_text(), bad)

    def test_reset_preserves_the_counter_and_removes_the_records(self):
        """A restarted counter would reuse ids already handed to the
        downstream runtime. Paired with the record check so the test fails if
        reset did nothing at all."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])

        reset.reset_instance(self.cfg, "alice")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        helpers._mark_seen(self.cfg)

        write_request(self.cfg, "alice", "00000002", to=[EXT])
        self.drain()
        self.assertEqual(self.port.writes, ["00000001", "00000002"])

    def test_a_burned_id_is_skipped_not_reused(self):
        """Crash after the counter write, before the record: the retry
        allocates the next id."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        real = inflight._effect

        def crash_on_record(label, fn, *a, **k):
            if label == "record":
                raise RuntimeError("crash")
            return real(label, fn, *a, **k)

        with mock.patch.object(inflight, "_effect", crash_on_record):
            self.drain()
        self.assertEqual(self.port.writes, [])
        self.drain()
        self.assertEqual(self.port.writes, ["00000002"])


class StaleTests(_InflightCase):

    def _age(self, req_id="00000001"):
        p = inflight.record_path(self.cfg, "alice", req_id)
        rec = json.loads(p.read_text())
        rec["written_ts"] = "2020-01-01T00:00:00Z"
        p.write_text(json.dumps(rec))

    def test_a_stale_request_is_reported_and_warned_once_and_never_settled(self):
        outbound._STALE_WARNED.clear()
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        s = self.drain()
        self.assertEqual(s["inflight_stale"], 0)
        self._age()

        with self.assertLogs("amap_router_local.outbound", logging.WARNING) as logs:
            s = self.drain()
            self.drain()
        stale_lines = [m for m in logs.output if "in flight past" in m]
        self.assertEqual(len(stale_lines), 1)
        self.assertEqual(s["inflight_stale"], 1)
        self.assertGreater(s["inflight_oldest_age_s"], inflight.STALE_AFTER_S)
        self.assertFalse(self.has_result())
        self.assertEqual(self.port.writes, ["00000001"])

    def test_an_unreadable_timestamp_counts_as_stale(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        p = inflight.record_path(self.cfg, "alice", "00000001")
        rec = json.loads(p.read_text())
        rec["written_ts"] = "yesterday"
        p.write_text(json.dumps(rec))
        summary, stale = inflight.summarize(self.cfg, "alice")
        self.assertEqual(stale, ["00000001"])
        self.assertEqual(summary["inflight_stale"], 1)


class CrashPointTests(_InflightCase):
    """Crash before, then after, each side effect of the lifecycle; keep
    polling (the downstream runtime sending whatever is pending) until it
    settles. Every run must end with ONE transport request ever written, ONE
    agent result, no record, and the agent's request archived.

    "One agent result" is counted as settle steps actually TAKEN, not read
    off the published file: a second settle rewrites that file with the same
    verdict, so the file alone cannot tell one result from two."""

    EXPECTED_EFFECTS = ["counter", "record", "handed", "transport", "settle", "unlink"]

    def lifecycle(self, injector):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        with mock.patch.object(inflight, "_effect", injector):
            for _ in range(8):
                self.drain()
                self.port.send_all(recipients=[EXT])

    def assert_settled_once(self, taken):
        self.assertEqual(taken.count("settle"), 1, taken)
        self.assertEqual(len(self.port.writes), 1, self.port.writes)
        self.assertEqual(self.result()["outcome"], "accepted")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.assertTrue(processed_path(self.cfg, "alice", "00000001").exists())

    def test_the_clean_run_takes_every_expected_effect_once(self):
        """The positive control: without it, a lifecycle that took no
        effects at all would make every crash case below vacuous."""
        seen = []
        real = inflight._effect

        def record(label, fn, *a, **k):
            seen.append(label)
            return real(label, fn, *a, **k)

        self.lifecycle(record)
        self.assertEqual(seen, self.EXPECTED_EFFECTS)
        self.assert_settled_once(seen)

    def test_a_crash_before_or_after_any_effect_still_settles_once(self):
        real = inflight._effect
        for k, label in enumerate(self.EXPECTED_EFFECTS):
            for when in ("before", "after"):
                with self.subTest(effect=label, when=when):
                    self.tearDown()
                    self.setUp()
                    fired, taken = [], []

                    def crash(lbl, fn, *a, _k=k, _when=when, **kw):
                        index = crash.calls
                        crash.calls += 1
                        if index == _k and not fired:
                            fired.append(lbl)
                            if _when == "after":
                                real(lbl, fn, *a, **kw)
                                taken.append(lbl)
                            raise RuntimeError(f"crash {_when} {lbl}")
                        out = real(lbl, fn, *a, **kw)
                        taken.append(lbl)
                        return out

                    crash.calls = 0
                    self.lifecycle(crash)
                    self.assertEqual(fired, [label], "the crash never fired")
                    self.assert_settled_once(taken)


ALLOWED = "allowed@example.org"
DENIED = "denied@example.org"
DENIED_CC = "denied-cc@example.org"


class RecipientIntegrityTests(_InflightCase):
    """The transport request carries the draft, and the downstream runtime
    sends to everything in it. So the draft's `to` ∪ `cc` must be EXACTLY
    the evaluated set, or nothing goes out (cold sends are all-or-nothing).
    Each refusal is checked against `self.port.writes`, the one surface only
    a transport write can produce."""

    def _only(self, *allowed):
        return lambda cfg, sender, draft: outbound.ExternalRoute(tuple(allowed))

    def test_a_policy_allowing_part_of_the_draft_sends_to_nobody(self):
        """THE WITNESS: on the commit before this test, the policy allowed
        only ALLOWED and the transport request still carried DENIED and
        DENIED_CC."""
        write_request(self.cfg, "alice", "00000001", to=[ALLOWED, DENIED], cc=[DENIED_CC])
        self.drain(cold_policy=self._only(ALLOWED))
        self.assertEqual(self.port.writes, [])
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "transport_anomaly"))
        self.assertEqual(r["recipients"], [])
        self.assertIn("nothing was sent", r["detail"])
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.drain(cold_policy=self._only(ALLOWED))
        self.assertEqual(self.port.writes, [])

    def test_an_authorised_address_missing_from_the_draft_also_fails_closed(self):
        write_request(self.cfg, "alice", "00000001", to=[ALLOWED])
        self.drain(cold_policy=self._only(ALLOWED, DENIED))
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result()["reason_code"], "transport_anomaly")

    def test_the_exact_set_goes_out_with_the_domain_folded(self):
        """The positive twin: without it, a check refusing everything would
        pass both tests above. The domain is compared case-insensitively."""
        write_request(self.cfg, "alice", "00000001", to=["Allowed@Example.ORG"], cc=[DENIED])
        self.drain(cold_policy=self._only("Allowed@example.org", DENIED))
        self.assertEqual(self.port.writes, ["00000001"])
        sent = json.loads(self.port.pending["00000001"])
        self.assertEqual(sent["draft"]["to"], ["Allowed@Example.ORG"])
        self.assertEqual(sent["draft"]["cc"], [DENIED])

    def test_a_local_part_differing_in_case_is_a_different_recipient(self):
        """A remote local part is matched exactly, never case-folded: a
        policy naming DENIED@ for a draft naming denied@ routed someone the
        agent did not name, and nothing goes out."""
        write_request(self.cfg, "alice", "00000001", to=[ALLOWED], cc=[DENIED])
        self.drain(cold_policy=self._only(ALLOWED, "DENIED@example.org"))
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result()["reason_code"], "transport_anomaly")

    def test_the_mismatch_check_compares_local_parts_exactly(self):
        """The in-flight check alone, past the policy's own class check."""
        rec = {"recipients": ["denied@example.org"],
               "request": {"draft": {"to": ["DENIED@example.org"]}}}
        self.assertIsNotNone(inflight.recipient_mismatch(rec))
        rec["request"]["draft"]["to"] = ["denied@EXAMPLE.org"]
        self.assertIsNone(inflight.recipient_mismatch(rec))

    def test_the_request_bytes_cannot_be_built_for_a_mismatched_record(self):
        """Defence in depth: the builder itself refuses, so no caller can
        produce a transport request that skips the check."""
        rec = {"transport_req_id": "00000003", "recipients": [ALLOWED],
               "request": {"contract_version": "2", "req_id": "00000009",
                           "draft": {"to": [ALLOWED, DENIED], "subject": "s",
                                     "body_text": "b"}}}
        with self.assertRaises(inflight.RecipientSetMismatch):
            inflight.transport_request_bytes(self.cfg, "alice", rec)
        rec["request"]["draft"]["to"] = [ALLOWED]
        inflight.transport_request_bytes(self.cfg, "alice", rec)


class TransportIdInUseTests(_InflightCase):
    """A record not recorded as handed over finds a trace under its `n`, and
    cannot tell whose request it carries. Both guesses are unsafe, and each
    has a witness here: settling from the trace (a rolled-back counter,
    where the trace is ANOTHER request's) and handing over again (a restored
    state, where it is THIS request's own). It fails closed."""

    def test_a_rolled_back_counter_never_settles_a_request_from_another_ones_result(self):
        """The power-loss witness, as a model: the counter's successor was
        lost after a request had used the id and finished, so a DIFFERENT
        request got the same id and, before the fix, settled from the first
        one's result with nothing sent. The fsyncs in `atomic_write` are one
        barrier (`DurabilityBarrierTests`); this rolls the file back by hand,
        so it holds whatever made the counter go backwards."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.send_all(recipients=[EXT])
        self.drain()
        self.assertEqual(self.result("00000001")["outcome"], "accepted")
        self.assertEqual(inflight.counter_path(self.cfg, "alice").read_text(), "2")

        inflight.counter_path(self.cfg, "alice").write_text("1")  # the rollback

        write_request(self.cfg, "alice", "00000002", to=[EXT], subject="different")
        with self.assertLogs("amap_router_local.inflight", logging.ERROR) as logs:
            self.drain()
        self.assertTrue(any("already exists on the transport" in m for m in logs.output))
        r = self.result("00000002")
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "transport_anomaly"),
                         "settled from another request's downstream result")
        self.assertIn("cannot tell whose request it carries", r["detail"])
        self.assertEqual(self.port.writes, ["00000001"])
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])

    def test_a_restored_state_never_hands_the_same_request_over_twice(self):
        """THE WITNESS for the remedy the first fix used. The state is
        restored to after the record and before its marker, so the trace
        under `n` is this request's OWN hand-off. Re-handing under a new id
        (the previous fix) put it on the transport twice."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])
        inflight.handed_path(self.cfg, "alice", "00000001").unlink()  # the restore
        with self.assertLogs("amap_router_local.inflight", logging.ERROR):
            self.drain()
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"], "handed over twice")
        r = self.result()
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "transport_anomaly"))
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])

    def test_the_marker_names_its_id_and_an_orphan_does_not_vouch(self):
        """An orphan marker (a crash between the two unlinks in `_cleanup`)
        for a reused agent req_id names an OLD id, so the new record is
        still checked, and a mismatched draft is still refused."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.assertEqual(inflight.handed_path(self.cfg, "alice", "00000001").read_bytes(),
                         b"00000001")
        self.port.send_all(recipients=[EXT])
        self.drain()
        handed = inflight.handed_path(self.cfg, "alice", "00000001")
        self.assertFalse(handed.exists())
        handed.write_bytes(b"00000001")  # the orphan

        rec = inflight.begin(self.cfg, "alice", "00000001", digest=None,
                             request_doc={"contract_version": "2", "req_id": "00000001",
                                          "draft": {"to": [ALLOWED, DENIED],
                                                    "subject": "s", "body_text": "b"}},
                             recipients=[ALLOWED])
        self.assertEqual(rec["transport_req_id"], "00000002")
        settled = []
        state = inflight.advance(self.cfg, "alice", "00000001", rec, self.port,
                                 settle=lambda v, d: settled.append(v),
                                 already_settled=False)
        self.assertEqual(state, inflight.SETTLED)
        self.assertEqual(settled[0]["reason_code"], "transport_anomaly")
        self.assertEqual(self.port.writes, ["00000001"])


def _fd_target(fd):
    """What an fsync'd descriptor names: ('dir'|'file', path)."""
    kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
    return kind, os.readlink(f"/proc/self/fd/{fd}")


class _FsyncSpyCase(_InflightCase):
    """Records each real `os.fsync` (with its target) and each transport
    write, in order, optionally failing chosen fsyncs."""

    def setUp(self):
        super().setUp()
        if not os.path.isdir("/proc/self/fd"):
            self.skipTest("needs /proc/self/fd to name fsync targets")

    def _spy(self, events, fail=None):
        real_fsync = os.fsync
        real_write = FakeTransport.write_request

        def fsync(fd):
            target = _fd_target(fd)
            if fail is not None and fail(target):
                raise OSError(5, "injected fsync failure")
            events.append(("fsync",) + target)
            return real_fsync(fd)

        def write_request(port, n, data):
            events.append(("transport", n))
            return real_write(port, n, data)

        return (mock.patch("router.util.os.fsync", fsync),
                mock.patch.object(FakeTransport, "write_request", write_request))


class DurabilityBarrierTests(_FsyncSpyCase):
    """Barriers at the real `os.fsync` boundary, not at `_effect`: the bug
    was that `_effect` ran and NO fsync happened inside it."""

    def test_counter_and_record_are_durable_before_the_transport_write(self):
        """On the commit before this test there were ZERO fsyncs before the
        transport write."""
        events = []
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        a, b = self._spy(events)
        with a, b:
            self.drain()
        cut = events.index(("transport", "00000001"))
        before = events[:cut]
        counter = str(inflight.counter_path(self.cfg, "alice"))
        record = str(inflight.record_path(self.cfg, "alice", "00000001"))
        inflight_dir = os.path.dirname(record)
        file_syncs = [p for e, k, p in before if k == "file"]
        dir_syncs = [p for e, k, p in before if k == "dir"]
        # The file fsync happens on the temp, before the rename: match the prefix.
        self.assertTrue(any(os.path.basename(p).startswith("next_req_id.") for p in file_syncs))
        self.assertTrue(any(os.path.basename(p).startswith("00000001.json.") for p in file_syncs))
        self.assertIn(os.path.dirname(counter), dir_syncs)
        self.assertIn(inflight_dir, dir_syncs)

    def test_the_settlement_is_durable_before_the_record_is_removed(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.send_all(recipients=[EXT])
        events = []
        real_unlink = Path.unlink
        record = str(inflight.record_path(self.cfg, "alice", "00000001"))

        def unlink(path, *a, **k):
            if str(path) == record:
                events.append(("unlink-record",))
            return real_unlink(path, *a, **k)

        a, b = self._spy(events)
        with a, b, mock.patch.object(Path, "unlink", unlink):
            self.drain()
        self.assertEqual(self.result()["outcome"], "accepted")
        cut = events.index(("unlink-record",))
        private = outbound._private_result_path(self.cfg, "alice", "00000001")
        synced = [e[1:] for e in events[:cut] if e[0] == "fsync"]
        self.assertTrue(any(k == "file" and os.path.basename(p).startswith(private.name + ".")
                            for k, p in synced), synced)
        self.assertIn(("dir", str(private.parent)), synced)

    def test_a_failed_fsync_of_the_record_means_no_transport_write(self):
        """Injected at the real boundary. The poll fails; the next one
        recovers with one transport request and one result."""
        events = []
        write_request(self.cfg, "alice", "00000001", to=[EXT])

        def fail(target):
            kind, path = target
            return kind == "file" and os.path.basename(path).startswith("00000001.json.")

        a, b = self._spy(events, fail=fail)
        with a, b:
            self.drain()
        self.assertEqual(self.port.writes, [])
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.drain()
        self.port.send_all(recipients=[EXT])
        self.drain()
        self.assertEqual(len(self.port.writes), 1)
        self.assertEqual(self.result()["outcome"], "accepted")

    def test_a_failed_directory_fsync_of_the_counter_means_no_transport_write(self):
        events = []
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        counter_dir = str(inflight.counter_path(self.cfg, "alice").parent)
        state = {"failed": False}

        def fail(target):
            if target == ("dir", counter_dir) and not state["failed"]:
                state["failed"] = True
                return True
            return False

        a, b = self._spy(events, fail=fail)
        with a, b:
            self.drain()
        self.assertTrue(state["failed"], "the injected failure never fired")
        self.assertEqual(self.port.writes, [])
        self.drain()
        self.assertEqual(len(self.port.writes), 1)
        self.assertNotIn("00000001", self.port.writes, "a possibly-lost id was used")

    def test_a_failed_fsync_of_the_settlement_keeps_the_record(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.send_all(recipients=[EXT])
        events = []
        state = {"failed": False}

        def fail(target):
            kind, path = target
            if (kind == "file" and os.path.basename(path).startswith("00000001.json.")
                    and "inflight" not in path and not state["failed"]):
                state["failed"] = True
                return True
            return False

        a, b = self._spy(events, fail=fail)
        with a, b:
            self.drain()
        self.assertTrue(state["failed"], "the injected failure never fired")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])
        self.drain()
        self.assertEqual(self.result()["outcome"], "accepted")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.assertTrue(processed_path(self.cfg, "alice", "00000001").exists())
        self.assertEqual(len(self.port.writes), 1)


class RetryRepairsBarrierTests(_FsyncSpyCase):
    """A barrier that failed AFTER its rename is repaired by the retry, not
    taken as done because the name exists."""

    def test_a_settlement_whose_directory_fsync_failed_is_made_durable_before_cleanup(self):
        """THE WITNESS (P1): the private result's directory fsync fails after
        its rename. On the commit before this test the next poll saw the
        file, took it as settled, and removed the record with no fsync of the
        result at all."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.send_all(recipients=[EXT])
        private = outbound._private_result_path(self.cfg, "alice", "00000001")
        state = {"failed": False}

        def fail(target):
            if target == ("dir", str(private.parent)) and not state["failed"]:
                state["failed"] = True
                return True
            return False

        a, b = self._spy([], fail=fail)
        with a, b:
            self.drain()
        self.assertTrue(state["failed"], "the injected failure never fired")
        self.assertTrue(private.exists(), "the rename did not happen; wrong boundary")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])

        events = []
        real_unlink = Path.unlink
        record = str(inflight.record_path(self.cfg, "alice", "00000001"))

        def unlink(path, *a, **k):
            if str(path) == record:
                events.append(("unlink-record",))
            return real_unlink(path, *a, **k)

        a, b = self._spy(events)
        with a, b, mock.patch.object(Path, "unlink", unlink):
            self.drain()
        cut = events.index(("unlink-record",))
        synced = [e[1:] for e in events[:cut] if e[0] == "fsync"]
        self.assertIn(("file", str(private)), synced)
        self.assertIn(("dir", str(private.parent)), synced)
        self.assertEqual(self.result()["outcome"], "accepted")
        self.assertTrue(processed_path(self.cfg, "alice", "00000001").exists())
        self.assertEqual(self.port.writes, ["00000001"], "sent again")

    def test_an_invalid_anchor_keeps_the_record_and_never_resends(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.send_all(recipients=[EXT])
        private = outbound._private_result_path(self.cfg, "alice", "00000001")
        private.parent.mkdir(parents=True, exist_ok=True)
        private.write_text("{not json")
        with self.assertLogs("amap_router_local.outbound", logging.ERROR):
            self.drain()
        self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])
        self.assertEqual(private.read_text(), "{not json", "the anchor was rewritten")
        self.assertEqual(self.port.writes, ["00000001"])

    def test_a_failed_ancestor_barrier_is_repaired_by_the_next_write(self):
        """THE WITNESS (P2), through the real counter write: the first
        allocation creates state_dir/alice/transport/ and the fsync of
        state_dir fails. On the commit before this test the retry synced
        only the parent of the destination directory, so state_dir's entry
        for alice/ was never made durable."""
        state_dir = str(self.cfg.state_dir.resolve())
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        state = {"failed": False}

        def fail(target):
            if target == ("dir", state_dir) and not state["failed"]:
                state["failed"] = True
                return True
            return False

        a, b = self._spy([], fail=fail)
        with a, b:
            self.drain()
        self.assertTrue(state["failed"], "the injected failure never fired")
        self.assertEqual(self.port.writes, [])

        events = []
        a, b = self._spy(events)
        with a, b:
            self.drain()
        self.assertEqual(len(self.port.writes), 1)
        # Cut at the COUNTER's own file fsync: before it, only the counter
        # write has run, so the chain cannot have come from the record's.
        cut = next(i for i, e in enumerate(events) if e[0] == "fsync" and e[1] == "file"
                   and os.path.basename(e[2]).startswith("next_req_id."))
        dirs = [e[2] for e in events[:cut] if e[0] == "fsync" and e[1] == "dir"]
        for d in (state_dir, os.path.join(state_dir, "alice")):
            self.assertIn(d, dirs)


class RootChainPerWriteTests(_FsyncSpyCase):
    """`durable_root` on EACH in-flight write, witnessed per write: in the
    window between the previous write's file fsync and this write's own,
    state_dir and state_dir/alice are fsynced. Cut per write, so no other
    write's chain can satisfy it (the second-producer trap the counter's
    witness fell into)."""

    def test_the_record_marker_and_private_result_each_rebuild_the_chain(self):
        state_dir = str(self.cfg.state_dir.resolve())
        chain = {state_dir, os.path.join(state_dir, "alice")}
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        events = []
        a, b = self._spy(events)
        with a, b:
            self.drain()
            self.port.send_all(recipients=[EXT])
            self.drain()
        self.assertEqual(self.result()["outcome"], "accepted")
        prefixes = {"record": "inflight/00000001.json.",
                    "marker": "inflight/00000001.handed.",
                    "result": "results/00000001.json."}
        windows = {}
        since = []
        for e in events:
            if e[0] != "fsync":
                continue
            if e[1] == "dir":
                since.append(e[2])
                continue
            for label, prefix in prefixes.items():
                d, f = prefix.rsplit("/", 1)
                if (label not in windows and os.path.basename(e[2]).startswith(f)
                        and os.path.basename(os.path.dirname(e[2])) == d
                        and os.path.dirname(os.path.dirname(e[2])).startswith(state_dir)):
                    windows[label] = set(since)
            since = []
        self.assertEqual(set(windows), set(prefixes), windows)
        for label, seen in windows.items():
            with self.subTest(write=label):
                self.assertLessEqual(chain, seen)


class AnchorShapeTests(_InflightCase):

    def test_a_valid_json_anchor_of_the_wrong_shape_keeps_the_record(self):
        """The envelope check, not only the JSON check: valid JSON that is
        not a {digest, result} envelope is refused, and nothing is resent."""
        for bad in ('{"result": "x"}', '{"digest": null}', '[1, 2]',
                    '{"digest": null, "result": []}'):
            with self.subTest(anchor=bad):
                self.tearDown()
                self.setUp()
                write_request(self.cfg, "alice", "00000001", to=[EXT])
                self.drain()
                self.port.send_all(recipients=[EXT])
                private = outbound._private_result_path(self.cfg, "alice", "00000001")
                private.parent.mkdir(parents=True, exist_ok=True)
                private.write_text(bad)
                with self.assertLogs("amap_router_local.outbound", logging.ERROR):
                    self.drain()
                self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])
                self.assertEqual(private.read_text(), bad)
                self.assertEqual(self.port.writes, ["00000001"])
