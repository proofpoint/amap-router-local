"""First sight: the snapshot replaces the approval gate, and what that means.

`approve` is retired. An instance is no longer refused until a human types its
name; the deliberate human act is ENROLMENT, which is upstream of this router
seeing the root at all. What survives — and is the whole of the protection —
is the SNAPSHOT: the first time the router sees a root it records every
`req-*.json` already in the outbox and never delivers those.

Three properties, and they fail for different reasons:

  THE SNAPSHOT PRECEDES THE FIRST DRAIN. Not "on the first poll" but before
  anything is drained in that poll, or the window is open for one poll.
  NEVER RE-SNAPSHOTS. A second snapshot moves the quarantine line forward
  over whatever appeared since — exactly the staging this refuses.
  UPGRADE ADOPTS THE OLD MARKER. Otherwise the first poll after retirement
  calls itself a first sight and quarantines a live fleet's outboxes.
"""

import json
import unittest

from router import firstsight, outbound
from router.status import StatusTracker, render
from router.tests.helpers import RouterTestCase, list_notices, read_json, write_request
from router.util import atomic_write


class SnapshotPrecedesTheFirstDrainTests(RouterTestCase):
    def test_a_request_already_staged_is_quarantined_never_delivered(self):
        """The case the whole mechanism exists for: a repo cloned into a
        workspace carries `outbox/req-*.json` with it."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        summary = outbound.drain_instance(cfg, "alice")

        self.assertEqual(summary["quarantined"], 1)
        self.assertEqual(summary["accepted"], 0)
        self.assertEqual(list_notices(cfg, "bob"), [],
                         "a staged request must never reach a recipient")
        result = read_json(cfg.instances["alice"].outbox_root / "results" / "00000001.json")
        self.assertEqual(result["reason_code"], "quarantined_pre_approval")

    def test_a_request_written_after_first_sight_is_an_ordinary_send(self):
        """The other half. A quarantine that swallowed everything would pass
        the test above and be useless."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        outbound.drain_instance(cfg, "alice")          # first sight, empty outbox

        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        summary = outbound.drain_instance(cfg, "alice")

        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

    def test_the_marker_exists_before_anything_is_delivered(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        marker = firstsight.read_marker(cfg.state_dir, "alice")
        self.assertIsNotNone(marker)
        self.assertEqual(
            {e["filename"] for e in marker["outbox_snapshot"]}, {"req-00000001.json"})


class NeverReSnapshotsTests(RouterTestCase):
    def test_a_second_poll_leaves_the_marker_untouched(self):
        """Re-snapshotting would retroactively bless whatever arrived between
        the two polls — which is the staging this refuses."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        first, was_new = firstsight.record_first_sight(cfg, "alice")
        self.assertTrue(was_new)

        write_request(cfg, "alice", "00000002", to=["agent.bob@local"])
        second, was_new_again = firstsight.record_first_sight(cfg, "alice")

        self.assertFalse(was_new_again)
        self.assertEqual(first, second)
        self.assertEqual(second["outbox_snapshot"], [],
                         "the file written after first sight must not join the snapshot")

    def test_the_later_request_is_delivered_rather_than_quarantined(self):
        """The observable consequence of not re-snapshotting."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        outbound.drain_instance(cfg, "alice")
        write_request(cfg, "alice", "00000002", to=["agent.bob@local"])

        self.assertEqual(outbound.drain_instance(cfg, "alice")["accepted"], 1)


class UpgradeAdoptsTheOldMarkerTests(RouterTestCase):
    """An existing deployment has `approval.json` from a human `approve`."""

    def _plant_legacy(self, cfg, name, filenames):
        doc = {
            "schema": firstsight.SCHEMA, "instance": name,
            "approved_ts": "2026-01-01T00:00:00Z", "mode": cfg.instances[name].mode,
            "declared_root": str(cfg.instances[name].root),
            "outbox_snapshot": [{"filename": f, "sha256": None, "size": None}
                                for f in filenames],
        }
        atomic_write(cfg.state_dir / name / firstsight.LEGACY_APPROVAL_FILENAME,
                     json.dumps(doc, sort_keys=True).encode("utf-8"))
        return doc

    def test_the_old_snapshot_is_adopted_not_replaced(self):
        """Without adoption the first poll after the upgrade snapshots a LIVE
        outbox and quarantines everything in it — a routine upgrade turned
        into a fleet-wide stall."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        self._plant_legacy(cfg, "alice", ["req-00000009.json"])
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        marker, was_new = firstsight.record_first_sight(cfg, "alice")

        self.assertTrue(was_new)
        self.assertEqual({e["filename"] for e in marker["outbox_snapshot"]},
                         {"req-00000009.json"},
                         "the adopted line is the one a human drew, not a new one")
        self.assertEqual(marker["first_seen_ts"], "2026-01-01T00:00:00Z")
        self.assertEqual(marker["adopted_from"], firstsight.LEGACY_APPROVAL_FILENAME)

    def test_a_request_staged_after_the_old_approval_still_delivers(self):
        """The point of adopting rather than re-snapshotting, observed."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        self._plant_legacy(cfg, "alice", ["req-00000009.json"])
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        self.assertEqual(outbound.drain_instance(cfg, "alice")["accepted"], 1)

    def test_a_corrupt_legacy_marker_falls_back_to_a_fresh_snapshot(self):
        """Fail closed: an unreadable old marker must not be read as "nothing
        was staged"."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        atomic_write(cfg.state_dir / "alice" / firstsight.LEGACY_APPROVAL_FILENAME,
                     b"{ not json")
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        marker, _ = firstsight.record_first_sight(cfg, "alice")
        self.assertEqual({e["filename"] for e in marker["outbox_snapshot"]},
                         {"req-00000001.json"})


class MarkerHandlingTests(RouterTestCase):
    def test_a_corrupt_marker_is_treated_as_unseen_and_re_snapshots(self):
        """Fail closed in the same direction: an unreadable marker means the
        line is unknown, so it is drawn again rather than assumed empty."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        atomic_write(firstsight.marker_path(cfg.state_dir, "alice"), b"{ not json")
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        self.assertEqual(outbound.drain_instance(cfg, "alice")["quarantined"], 1)

    def test_an_unknown_instance_is_refused(self):
        cfg = self.make_config({"alice": []}, seen=False)
        with self.assertRaises(firstsight.FirstSightError):
            firstsight.record_first_sight(cfg, "mallory")

    def test_nothing_is_written_where_an_agent_can_see_it(self):
        """The old `APPROVED.json` mirror advertised an approval that no
        longer happens. Nothing about first sight belongs in a tree an agent
        can read."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        outbound.drain_instance(cfg, "alice")

        inbox = cfg.instances["alice"].inbox_root
        self.assertFalse((inbox / "APPROVED.json").exists())
        self.assertFalse((inbox / firstsight.FIRST_SEEN_FILENAME).exists())


class StatusTests(RouterTestCase):
    """Two texts, and which one appears is the point.

    The loud banner is earned by `quarantined`, not by `first_sight`. A first
    sight over an EMPTY outbox quarantines nothing, and on a fresh fleet that
    is every instance at once — announcing quarantined requests there is
    false, and a banner an operator learns to scroll past protects nobody.
    """

    def _line_for(self, cfg, name):
        tracker = StatusTracker()
        tracker.record_poll({name: outbound.drain_instance(cfg, name)})
        rendered = render(json.loads(json.dumps(tracker.to_doc())))
        # The instance's OWN line, not the whole document: a page-wide
        # assertion is satisfied by any line and pins none.
        return next(ln for ln in rendered.splitlines() if ln.startswith(name))

    def test_a_staged_outbox_gets_the_loud_banner_with_the_count(self):
        """An operator whose full outbox went quiet needs to see why, once —
        and how much went quiet."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        write_request(cfg, "alice", "00000002", to=["agent.bob@local"])

        line = self._line_for(cfg, "alice")

        self.assertIn("** FIRST SIGHT", line)
        self.assertIn("2 staged request(s) quarantined", line,
                      "the banner must say HOW MANY, or it cannot be "
                      "reconciled against what the agent thinks it sent")
        self.assertIn("never delivered", line)

    def test_an_empty_outbox_does_not_claim_anything_was_quarantined(self):
        """The control, and the reason there are two texts at all. Without
        it, a banner keyed on `first_sight` alone passes the test above and
        lies here — on every instance of a fresh fleet simultaneously."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)

        line = self._line_for(cfg, "alice")

        self.assertIn("first sight", line.lower(),
                      "the boundary was still drawn this poll; say so")
        self.assertNotIn("**", line,
                         "nothing was quarantined — this must not be loud")
        self.assertNotIn("quarantined, never delivered", line)

    def test_a_later_poll_says_nothing_about_first_sight(self):
        """It is announced ONCE. A line that kept repeating it would make
        the one poll that matters indistinguishable from every poll after."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, seen=False)
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        self._line_for(cfg, "alice")          # the first sight itself

        line = self._line_for(cfg, "alice")   # an ordinary poll after it

        self.assertNotIn("first sight", line.lower())


if __name__ == "__main__":
    unittest.main()
