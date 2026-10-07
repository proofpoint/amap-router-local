"""The `outbound/ext/<name>/` connector ids: exactly the configured ones.

The spec makes `<name>` a stable connector id ("The Volume Layout",
`outbound/ext/<name>/`): it MUST NOT change when the connector's repository is
renamed, and MUST be treated as opaque. The router scans
`ext/<id>/outcomes/` for each id in `config.connector_outcome_ids` — default
`("claude-code",)` — and nothing else. A compatibility path under an old
repo-tracking spelling was scanned for one release and retired on 2026-09-22;
configurable ids followed, for mixed Claude/Codex fleets.

WHY THIS FILE EXISTS. Nothing fails when this goes wrong. An outcome the
router never reads is silence, and silence is exactly what a peer message
with no outcome yet looks like: the sender is simply never told, the operator
never sees the `held` banner, and `peer_placed_denied` never lists the notice.
The module docstring's own rule — this router never infers anything from
silence — is what makes the failure invisible. So the path the router scans
gets a test that fails loudly when it changes, rather than a comment asking
nicely. That argument is why any change to the scanned set is a RULING and
not a cleanup: dropping a scanned directory cannot be verified after the fact
from anything this router observes. Asserted on BEHAVIOUR — a file that is or
is not consumed — never on a constant: the change to configurable ids left a
constant behind that nothing read, and a test that went on pinning it.

Driven through `outcomes.consume_instance`, the unit whose directory scan
these tests are about; `test_outcomes.py` drives the same behaviour through
`service.run_once` for the deployment loop's view of it.
"""

import unittest
from dataclasses import replace
from unittest import mock

from router import config, outbound, outcomes
from router.tests.helpers import RouterTestCase, read_json, result_path, write_request
from router.tests.peer_helpers import addr, make_peer_config, outcomes_dir, write_outcome


class ConnectorIdTests(unittest.TestCase):
    """The ids themselves, before any filesystem is involved."""

    def test_the_default_id_is_not_a_repo_name(self):
        """The whole point of the spec ruling: an id outlives a rename of the
        connector's REPOSITORY, so it must not carry a repo name at all. The
        default did not change when that repository was renamed, and this test
        is what says so."""
        self.assertEqual(config.DEFAULT_CONNECTOR_OUTCOME_IDS, ("claude-code",))
        for cid in config.DEFAULT_CONNECTOR_OUTCOME_IDS:
            self.assertNotIn("amp", cid)
            self.assertNotIn("amap", cid)

    def test_the_path_is_ext_id_outcomes(self):
        self.assertEqual(str(outcomes.outcomes_rel("codex")), "ext/codex/outcomes")


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


class TheExtPathIsConsumedTests(_ExtPathTestCase):
    """An outcome under the pinned id is found — the whole of the scan."""

    def test_outcome_under_the_pinned_id_is_consumed(self):
        write_outcome(self.cfg, "b", self.task(), "delivered")

        summary = self.consume()

        self.assertEqual(summary["peer_delivered"], 1)
        self.assertEqual(summary["peer_outcome_discarded"], 0)

    def test_an_outcome_beside_the_pinned_dir_is_not_found(self):
        """The inverse of the test above, and the one the retirement needs.
        `ext/` is agent-writable, so a daemon writing any other id under it
        produces a file the router must leave alone — the cost of the pinned
        id is exactly that, and this is where it is stated.

        THE FILE IS A REAL ONE, moved. A hand-made file in the stray
        directory is refused by the FILENAME pattern long before the
        directory is ever chosen, so it stays unread under a scan that was
        broadened to reach it — the first version of this test did that and
        survived the mutation that adds a second scanned path. Moving a file
        `write_outcome` produced leaves the directory as the only reason it
        is not consumed.

        Asserted on `outcomes_seen`, not on `delivered`: an unread file and a
        read-then-discarded one both leave `delivered` at zero, so that
        surface cannot tell them apart."""
        real = write_outcome(self.cfg, "b", self.task(), "delivered")
        stray = outcomes_dir(self.cfg, "b").parent.parent / "some-other-id" / "outcomes"
        stray.mkdir(parents=True)
        real.rename(stray / real.name)

        summary = self.consume()

        self.assertEqual(summary["peer_outcomes_seen"], 0)
        self.assertTrue((stray / real.name).exists())


class TheConfiguredIdsAreScannedTests(_ExtPathTestCase):
    """What replaced the assertion on a constant: the scanned set, observed."""

    def test_an_outcome_under_a_second_CONFIGURED_id_is_consumed(self):
        """The inverse of `test_an_outcome_beside_the_pinned_dir_is_not_found`:
        the same move, into a directory the config DOES list, is consumed.
        Together they pin that the config — not a constant — decides."""
        self.cfg = replace(self.cfg, connector_outcome_ids=("claude-code", "codex"))
        real = write_outcome(self.cfg, "b", self.task(), "delivered")
        target = outcomes_dir(self.cfg, "b", "codex")
        target.mkdir(parents=True)
        real.rename(target / real.name)

        summary = self.consume()

        self.assertEqual(summary["peer_outcomes_seen"], 1)
        self.assertEqual(summary["peer_delivered"], 1)
        self.assertFalse((target / real.name).exists())


class BudgetTests(_ExtPathTestCase):
    """`MAX_FILES_PER_POLL` bounds work per instance per poll."""

    def test_the_budget_caps_one_poll_and_leaves_the_rest(self):
        """Agent-writable input: the directory holds whatever the daemon put
        there, so the scan is bounded rather than trusting the count.

        BOTH HALVES ARE THE TEST. That four were taken says the cap binds;
        that the other two are STILL ON DISK says they were deferred and not
        dropped, which is the difference between a bounded poll and silent
        loss. A count alone cannot tell those apart — six written, four seen
        reads the same either way."""
        patch = mock.patch.object(outcomes, "MAX_FILES_PER_POLL", 4)
        patch.start()
        self.addCleanup(patch.stop)
        written = [write_outcome(self.cfg, "b", self.task(), "delivered")
                   for _ in range(6)]

        summary = self.consume()

        self.assertEqual(summary["peer_outcomes_seen"], 4)
        self.assertEqual(sum(1 for f in written if f.exists()), 2)
