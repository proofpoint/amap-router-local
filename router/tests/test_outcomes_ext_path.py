"""The `outbound/ext/<name>/` connector id, and the one-release compat window.

The spec pins `<name>` (AMAP core §2, `outbound/ext/<name>` as a stable
connector id, v3.1.0 DRAFT): it MUST NOT change
when the connector's repository is renamed, and MUST be treated as opaque.
So the router reads `ext/claude-code/`, and — for one release — also the old
repo-tracking spelling `ext/amp-connector-claude-code/`, for a daemon that
has not been re-provisioned yet.

WHY THIS FILE EXISTS. Nothing fails when this goes wrong. An outcome the
router never reads is silence, and silence is exactly what a peer message
with no outcome yet looks like: the sender is simply never told, the operator
never sees the `held` banner, and `peer_placed_denied` never lists the notice.
The module docstring's own rule — this router never infers anything from
silence — is what makes the failure invisible. So the compat path gets a test
that fails loudly when it is removed, rather than a comment asking nicely.

Driven through `outcomes.consume_instance`, the unit whose directory scan
these tests are about; `test_outcomes.py` drives the same behaviour through
`service.run_once` for the deployment loop's view of it.
"""

import unittest
from unittest import mock

from router import outbound, outcomes
from router.tests.helpers import RouterTestCase, read_json, result_path, write_request
from router.tests.peer_helpers import addr, make_peer_config, outcomes_dir, write_outcome


class ConnectorIdTests(unittest.TestCase):
    """The ids themselves, before any filesystem is involved."""

    def test_pinned_id_is_not_a_repo_name(self):
        """The whole point of the spec ruling: the id outlives the rename of
        `amp-connector-claude-code` -> `amap-connector-claude`, so it must not
        carry a repo name at all."""
        self.assertEqual(outcomes.CONNECTOR_ID, "claude-code")
        self.assertNotIn("amp", outcomes.CONNECTOR_ID)
        self.assertNotIn("amap", outcomes.CONNECTOR_ID)

    def test_preferred_path_comes_first(self):
        """Preference is scan order plus the existing `(tree, notice_id,
        outcome)` dedup — there is no tie-break anywhere else, so the order
        of this tuple IS the preference."""
        self.assertEqual(
            outcomes.OUTCOMES_RELS,
            (outcomes.OUTCOMES_REL, outcomes.LEGACY_OUTCOMES_REL))
        self.assertEqual(outcomes.OUTCOMES_REL, outcomes.outcomes_rel("claude-code"))

    def test_the_two_paths_are_distinct(self):
        self.assertNotEqual(outcomes.OUTCOMES_REL, outcomes.LEGACY_OUTCOMES_REL)


class _ExtPathTestCase(RouterTestCase):
    """One a -> b fleet on the peer lane, and a way to place peer notices."""

    def setUp(self):
        super().setUp()
        self.cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        self._req = 0

    def task(self) -> str:
        """a tasks b; returns the peer id the SENDER learned from its result,
        which is the id an outcome has to name to resolve."""
        self._req += 1
        req_id = f"{self._req:08d}"
        write_request(self.cfg, "a", req_id, to=[addr("b")], body_text="task")
        outbound.drain_instance(self.cfg, "a")
        result = read_json(result_path(self.cfg, "a", req_id))
        self.assertEqual(result["reason_code"], "peer_routed")
        return result["message_id"]

    def consume(self):
        return outcomes.consume_instance(self.cfg, "b")


class EitherPathIsConsumedTests(_ExtPathTestCase):
    """An outcome is found under either id — the property the compat window
    exists to provide."""

    def test_outcome_under_the_pinned_id_is_consumed(self):
        write_outcome(self.cfg, "b", self.task(), "delivered")

        summary = self.consume()

        self.assertEqual(summary["peer_delivered"], 1)
        self.assertEqual(summary["peer_outcome_discarded"], 0)

    def test_outcome_under_the_legacy_id_is_consumed(self):
        """A daemon that has not been re-provisioned. If this stops passing,
        every such daemon's outcomes have become silence."""
        write_outcome(self.cfg, "b", self.task(), "delivered", legacy=True)

        summary = self.consume()

        self.assertEqual(summary["peer_delivered"], 1)
        self.assertEqual(summary["peer_outcome_discarded"], 0)

    def test_the_legacy_path_is_scanned_even_when_the_pinned_one_exists(self):
        """The failure mode worth naming: scanning only the preferred
        directory when it exists would strand exactly the outcomes the window
        is for, because a daemon writing the old id does not stop when the
        new directory appears."""
        outcomes_dir(self.cfg, "b").mkdir(parents=True, exist_ok=True)
        write_outcome(self.cfg, "b", self.task(), "delivered", legacy=True)

        summary = self.consume()

        self.assertEqual(summary["peer_delivered"], 1)

    def test_both_paths_are_consumed_in_one_poll(self):
        write_outcome(self.cfg, "b", self.task(), "delivered")
        write_outcome(self.cfg, "b", self.task(), "delivered", legacy=True)

        summary = self.consume()

        self.assertEqual(summary["peer_delivered"], 2)
        self.assertEqual(summary["peer_outcomes_seen"], 2)

    def test_a_consumed_file_is_unlinked_under_either_id(self):
        pinned = write_outcome(self.cfg, "b", self.task(), "delivered")
        legacy = write_outcome(self.cfg, "b", self.task(), "held", legacy=True)

        self.consume()

        self.assertFalse(pinned.exists())
        self.assertFalse(legacy.exists())


class PreferenceTests(_ExtPathTestCase):
    """The same notice reported under both ids at once."""

    def test_pinned_path_wins_when_both_carry_the_same_transition(self):
        """Recorded once, not twice: the second copy is the existing
        `duplicate` discard, and because the pinned path is scanned first it
        is the one that was acted on.

        The two files are made to DIFFER in content, so this test can tell
        which one won. Counting records cannot: both copies say `delivered`,
        so one record and one discard is the outcome whichever order they are
        scanned in, and an assertion on the counts alone would survive the
        order being reversed — a check that cannot fail."""
        notice_id = self.task()
        write_outcome(self.cfg, "b", notice_id, "delivered",
                      ts="2026-09-03T12:00:00Z", detail="from the pinned id")
        write_outcome(self.cfg, "b", notice_id, "delivered", legacy=True,
                      ts="2026-09-04T09:00:00Z", detail="from the legacy id")

        summary = self.consume()

        self.assertEqual(summary["peer_delivered"], 1)
        self.assertEqual(summary["peer_outcome_discarded"], 1)
        self.assertEqual(summary["peer_outcomes_seen"], 2)
        record = read_json(
            outcomes.record_path(self.cfg.state_dir, "b", "peer", notice_id, "delivered"))
        self.assertEqual(record["detail"], "from the pinned id")
        self.assertEqual(record["outcome_ts"], "2026-09-03T12:00:00Z")

    def test_both_copies_are_unlinked_so_neither_lingers(self):
        """The duplicate is consumed as well as discarded — a copy left
        behind would be re-read every poll for as long as it sat there."""
        notice_id = self.task()
        pinned = write_outcome(self.cfg, "b", notice_id, "delivered")
        legacy = write_outcome(self.cfg, "b", notice_id, "delivered", legacy=True)

        self.consume()

        self.assertFalse(pinned.exists())
        self.assertFalse(legacy.exists())

    def test_two_different_transitions_are_both_recorded(self):
        """Not a conflict to resolve: `held` under one id and `delivered`
        under the other is the same pair of transitions a single directory
        would carry over two polls, and the dedup key is per outcome."""
        notice_id = self.task()
        write_outcome(self.cfg, "b", notice_id, "delivered")
        write_outcome(self.cfg, "b", notice_id, "held", legacy=True)

        summary = self.consume()

        self.assertEqual(summary["peer_delivered"], 1)
        self.assertEqual(summary["peer_held"], 1)
        self.assertEqual(summary["peer_outcome_discarded"], 0)


class BudgetTests(_ExtPathTestCase):
    """`MAX_FILES_PER_POLL` bounds work per instance per poll."""

    def test_the_budget_is_shared_across_both_directories(self):
        """Two agent-writable directories must not buy twice the budget.

        THE NUMBERS ARE THE TEST. With a budget of 4 and three outcomes under
        each id, a shared budget takes three from the pinned directory and one
        from the legacy one: four. A per-directory budget takes all six, and
        the cap means twice what it says. A budget of 3 cannot tell those
        apart — the first directory exhausts it either way, both readings
        stop at three, and the assertion passes whichever is implemented.
        That version of this test was written first and survived its own
        mutation; these numbers are what killed it."""
        patch = mock.patch.object(outcomes, "MAX_FILES_PER_POLL", 4)
        patch.start()
        self.addCleanup(patch.stop)
        for _ in range(3):
            write_outcome(self.cfg, "b", self.task(), "delivered")
        for _ in range(3):
            write_outcome(self.cfg, "b", self.task(), "delivered", legacy=True)

        summary = self.consume()

        self.assertEqual(summary["peer_outcomes_seen"], 4)


class LegacyPathRetirementTests(unittest.TestCase):
    """The tripwire. See this module's docstring for why a comment would not
    have been enough."""

    def test_removing_the_legacy_path_is_a_deliberate_edit(self):
        """WHEN YOU ARE HERE TO RETIRE THE COMPAT PATH: that is this test
        doing its job, not an obstacle. Confirm every daemon in the fleet
        writes `ext/claude-code/` — one still writing the old id goes silent
        the moment the path is dropped, and nothing else in this suite or in
        production will say so — then delete this class along with
        `LEGACY_CONNECTOR_ID`, `LEGACY_OUTCOMES_REL`, the `legacy=` argument
        in `peer_helpers`, and the tests above that use it."""
        self.assertEqual(
            outcomes.LEGACY_CONNECTOR_ID, "amp-connector-claude-code",
            "the compatibility id changed; a daemon writing the old one is "
            "now unread, and unread outcomes are silence")
        self.assertIn(
            outcomes.LEGACY_OUTCOMES_REL, outcomes.OUTCOMES_RELS,
            "the compatibility path is no longer scanned — retiring it is a "
            "decision, so make it one: see this test's docstring")


if __name__ == "__main__":
    unittest.main()
