from dataclasses import replace
import shutil
from unittest import mock

from router import config, outcomes
from router.tests.test_outcomes_ext_path import _ExtPathTestCase
from router.tests.peer_helpers import write_outcome


class ConfigurableOutcomesTests(_ExtPathTestCase):
    def test_default_and_invalid_ids(self):
        doc={'state_dir':'/state','instances':{'a':{'handoff_dir':'/a'}}}
        self.assertEqual(config.load_obj(doc).connector_outcome_ids, ('claude-code',))
        for value in ([], 'codex', ['..'], ['x/y'], ['codex','codex'], [True], ['.hidden']):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                config.load_obj({**doc,'connector_outcome_ids':value})

    def test_cross_directory_duplicate_does_not_repeat_transition(self):
        self.cfg=replace(self.cfg,connector_outcome_ids=('claude-code','codex'))
        real=write_outcome(self.cfg,'b',self.task(),'refused')
        other=real.parents[2]/'codex'/'outcomes'; other.mkdir(parents=True)
        shutil.copyfile(real,other/real.name)
        summary=self.consume()
        self.assertEqual(summary['peer_refused'],1)
        self.assertEqual(summary['peer_dsn_sent'],1)
        self.assertEqual(summary['peer_outcome_discarded'],1)

    def test_budget_is_shared_across_configured_extensions(self):
        self.cfg=replace(self.cfg,connector_outcome_ids=('claude-code','codex'))
        first=write_outcome(self.cfg,'b',self.task(),'delivered')
        second=write_outcome(self.cfg,'b',self.task(),'delivered')
        target=second.parents[2]/'codex'/'outcomes'; target.mkdir(parents=True)
        second.rename(target/second.name)
        with mock.patch.object(outcomes,'MAX_FILES_PER_POLL',1):
            self.assertEqual(self.consume()['peer_outcomes_seen'],1)
            self.assertEqual(self.consume()['peer_outcomes_seen'],1)
