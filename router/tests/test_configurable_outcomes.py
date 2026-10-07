"""`config.connector_outcome_ids`: which `outbound/ext/<id>/outcomes/`
directories are scanned, for fleets that mix connectors.

A Codex connector writes its outcomes under `ext/codex/`, a Claude one under
`ext/claude-code/`. Scanning only one id makes every outcome from the other
silence — no `held` banner, no DSN — and nothing reports it, since this
router never infers anything from silence. So the scanned set is
configurable, and these tests pin the three properties that make a second
directory safe to add: the default is unchanged, a second directory buys no
extra budget, and one transition reported under two ids is acted on once.

The CASES are the ones the original change proposed; the casefold case and
the named-value check were added in review.
"""

import shutil
from dataclasses import replace
from unittest import mock

from router import config, outcomes
from router.tests.peer_helpers import outcomes_dir, write_outcome
from router.tests.test_outcomes_ext_path import _ExtPathTestCase

_MIN = {"state_dir": "/state", "instances": {"a": {"handoff_dir": "/a"}}}


class LoadTests(_ExtPathTestCase):

    def test_absent_means_the_default(self):
        """Every deployment that predates the key keeps exactly the scan it
        had."""
        self.assertEqual(config.load_obj(dict(_MIN)).connector_outcome_ids,
                         ("claude-code",))

    def test_a_listed_set_is_kept_in_order(self):
        cfg = config.load_obj({**_MIN, "connector_outcome_ids": ["codex", "claude-code"]})
        self.assertEqual(cfg.connector_outcome_ids, ("codex", "claude-code"))

    def test_unsafe_or_malformed_values_are_refused(self):
        """Each id becomes a path segment under an agent-writable tree."""
        for value in ([], "codex", [".."], ["x/y"], [True], [".hidden"],
                      ["codex\n"], ["codex", "codex"]):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                config.load_obj({**_MIN, "connector_outcome_ids": value})

    def test_ids_equal_ignoring_case_are_refused_naming_both(self):
        """On a case-insensitive filesystem `Codex` and `codex` are one
        directory. Asserted on the message naming BOTH spellings: the
        exact-duplicate case above raises too, so a bare assertRaises here
        could not tell the casefold check from the equality one."""
        with self.assertRaises(config.ConfigError) as cm:
            config.load_obj({**_MIN, "connector_outcome_ids": ["Codex", "codex"]})
        self.assertIn("'Codex'", str(cm.exception))
        self.assertIn("'codex'", str(cm.exception))

    def test_the_error_names_the_offending_value(self):
        with self.assertRaises(config.ConfigError) as cm:
            config.load_obj({**_MIN, "connector_outcome_ids": ["ok", "x/y"]})
        self.assertIn("'x/y'", str(cm.exception))


class AcrossDirectoriesTests(_ExtPathTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = replace(self.cfg, connector_outcome_ids=("claude-code", "codex"))

    def test_one_transition_under_two_ids_is_acted_on_once(self):
        """The dedup key is `(tree, notice_id, outcome)` with no directory in
        it. A `refused` reported in both directories sends ONE DSN; the second
        copy is the ordinary duplicate discard."""
        real = write_outcome(self.cfg, "b", self.task(), "refused")
        other = outcomes_dir(self.cfg, "b", "codex")
        other.mkdir(parents=True)
        shutil.copyfile(real, other / real.name)

        summary = self.consume()

        self.assertEqual(summary["peer_refused"], 1)
        self.assertEqual(summary["peer_dsn_sent"], 1)
        self.assertEqual(summary["peer_outcome_discarded"], 1)

    def test_the_budget_is_shared_across_directories(self):
        """THE NUMBERS ARE THE TEST. A budget of 1 and one file in each
        directory: shared, the first poll sees 1 and the second poll the
        other; per-directory, the first poll would see 2."""
        write_outcome(self.cfg, "b", self.task(), "delivered")
        second = write_outcome(self.cfg, "b", self.task(), "delivered")
        target = outcomes_dir(self.cfg, "b", "codex")
        target.mkdir(parents=True)
        second.rename(target / second.name)

        with mock.patch.object(outcomes, "MAX_FILES_PER_POLL", 1):
            self.assertEqual(self.consume()["peer_outcomes_seen"], 1)
            self.assertEqual(self.consume()["peer_outcomes_seen"], 1)
