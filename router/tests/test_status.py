"""Status is a file, not a socket (`status.py`'s design rationale).
`service.poll_once` is what one iteration of `run_forever`'s loop runs:
drain, fold into a `StatusTracker`, write `state_dir/status.json`. This
drives it directly — no threads, no sleeps — over a two-instance layout
where one instance has a hostile directory shape that must be isolated
per-instance, exactly like `test_exception_isolation.py` proves at the
per-request level."""

import json
import os
import unittest
from unittest import mock

from router import service
from router.status import NOT_WRITTEN_MSG, StatusTracker, read as status_read, render
from router.tests.helpers import RouterTestCase, write_request


class TestStatus(RouterTestCase):
    def test_two_polls_cumulative_totals_and_isolation(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"], "mallory": []})

        # mallory: outbound/ exists but is unreadable, forcing
        # list_outbound's iterdir() to raise and propagate out of
        # drain_instance — service.run_once (and so poll_once) must
        # isolate this per instance, never lose alice's healthy drain.
        mallory_outbound = cfg.instances["mallory"].outbox_root
        mallory_outbound.mkdir(parents=True, exist_ok=True)
        os.chmod(mallory_outbound, 0o000)

        try:
            write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

            tracker = StatusTracker()
            summary1 = service.poll_once(cfg, tracker)
            self.assertEqual(summary1["mallory"], {"instance_errored": 1})
            self.assertEqual(summary1["alice"]["drained"], 1)
            self.assertEqual(summary1["alice"]["accepted"], 1)

            # Second poll: alice has nothing left to drain; mallory keeps
            # erroring every time (the hostile shape is still there).
            summary2 = service.poll_once(cfg, tracker)
            self.assertEqual(summary2["mallory"], {"instance_errored": 1})
            self.assertEqual(summary2["alice"], {
                # 0, not absent: the first poll already took alice's
                # first-sight snapshot, so the second one is an ordinary
                # drain. A 1 here would mean the snapshot was retaken.
                "first_sight": 0,
                "outbound_seen": 0, "outbound_skipped_bad_name": 0,
                "outbound_resumed": 0, "outbound_req_id_reused": 0,
                "outbound_errored": 0, "drained": 0,
                "accepted": 0, "rejected": 0, "queued_for_human": 0,
                "quarantined": 0,
            })
        finally:
            os.chmod(mallory_outbound, 0o755)

        doc = status_read(cfg.state_dir)
        self.assertIsNotNone(doc)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["polls"], 2)
        self.assertEqual(doc["instances"]["mallory"]["totals"]["instance_errored"], 2)
        self.assertIsNotNone(doc["instances"]["mallory"]["last_error_ts"])
        # alice's healthy drain unaffected by mallory's isolated failure.
        self.assertEqual(doc["instances"]["alice"]["totals"]["drained"], 1)
        self.assertEqual(doc["instances"]["alice"]["totals"]["accepted"], 1)
        self.assertIsNone(doc["instances"]["alice"]["last_error_ts"])

        # status.json parses directly too — atomic_write's own guarantee,
        # exercised end to end rather than just asserted by contract.
        raw = (cfg.state_dir / "status.json").read_text(encoding="utf-8")
        json.loads(raw)

        rendered = render(doc)
        self.assertIn("alice", rendered)
        self.assertIn("drained=1", rendered)
        self.assertIn("accepted=1", rendered)
        self.assertIn("mallory", rendered)
        self.assertIn("errors=2", rendered)

    def test_read_missing_status_returns_none(self):
        cfg = self.make_config({"alice": []})
        self.assertIsNone(status_read(cfg.state_dir))
        self.assertTrue(NOT_WRITTEN_MSG)  # sanity: the message constant exists and is non-empty


if __name__ == "__main__":
    unittest.main()


class AdmittedSetIsNotTheInstancesMapTests(RouterTestCase):
    """`admitted` and `instances` answer different questions and one of them
    cannot answer this one.

    A peer's health check wanted "the router's own view of the fleet", and
    `status.json` already had an `instances` map whose keys, after a poll,
    ARE the admitted set — so it looked like the answer. It is not.
    `record_poll` builds that map with `setdefault` and nothing anywhere
    removes from it, so it is the union of every instance seen since process
    start. On a de-enrolment it keeps the departed instance for ever and a
    consumer reading it as "the set now" gets a stale answer with nothing in
    the document admitting it — trading a windowed producer for a monotonic
    one, which is worse, because at least a window knows it is a window.

    These tests pin the DIFFERENCE, on the surface where only the new field
    can produce it: a shrink. Asserting `admitted` after a single poll would
    pass just as well against the old map and prove nothing.
    """

    def test_admitted_shrinks_when_an_instance_is_de_enrolled(self):
        cfg = self.make_config({"alice": [], "bob": []})
        tracker = StatusTracker()
        service.poll_once(cfg, tracker)
        self.assertEqual(tracker.to_doc()["admitted"], ["alice", "bob"])

        # `run_forever` re-reads config every poll; simulate the reload
        # dropping one, which is what a de-enrolment looks like here.
        del cfg.instances["bob"]
        service.poll_once(cfg, tracker)

        doc = tracker.to_doc()
        self.assertEqual(doc["admitted"], ["alice"])
        # And the distinction itself: the map that CANNOT answer still names
        # bob. If this ever equals `admitted`, the two fields have merged and
        # the reason for the new one is gone.
        self.assertEqual(sorted(doc["instances"]), ["alice", "bob"])

    def test_a_poll_that_raised_WHOLESALE_still_reports_the_set(self):
        """The ordering guard: `record_admitted` runs BEFORE the drain.

        The first version of this test made one instance's outbox
        unreadable and asserted the set survived. It passed with the call
        moved AFTER the drain — because `run_once` isolates per-instance
        failures internally and returns normally, so that is not an errored
        POLL at all, and nothing about the ordering was under test. Pinned
        here against the outer belt instead, which is the only surface where
        the placement is the sole producer: `run_once` itself raising.
        """
        cfg = self.make_config({"alice": [], "bob": []})
        tracker = StatusTracker()

        def boom(_cfg):
            raise RuntimeError("the whole poll fell over")

        with mock.patch.object(service, "run_once", boom):
            summary = service.poll_once(cfg, tracker)

        self.assertEqual(summary, {})          # no drain data at all
        # ...and yet the set it was working on is still reported. Admission
        # is what the LOADER accepted; whether draining worked is a
        # different claim with its own counters.
        self.assertEqual(tracker.to_doc()["admitted"], ["alice", "bob"])

    def test_interval_is_omitted_when_unknown_never_defaulted(self):
        # A consumer computes a freshness bound from this (3x on the peer
        # side). A defaulted value is a wrong bound asserted confidently;
        # absence is a document saying it cannot answer.
        self.assertNotIn("interval_s", StatusTracker().to_doc())
        self.assertEqual(StatusTracker(interval_s=5.0).to_doc()["interval_s"], 5.0)

    def test_admitted_is_omitted_before_any_poll_not_reported_empty(self):
        # `[]` would mean "the loader accepted nothing", which is a fact.
        # A tracker that has not polled does not have that fact.
        self.assertNotIn("admitted", StatusTracker().to_doc())
