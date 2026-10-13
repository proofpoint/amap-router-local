"""`router generation new` as the audited exit from a lost hop tree
(`generations.operator_new` with `hoplink.LostAcks`): the verb finds the lost
set itself, under the lock and before anything is written, by probing each
candidate through an upstream marker store only; it acknowledges each lost
generation only AFTER the new generation and its audit line are durable; a
crash in between is recovered by running it again."""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from router import generations, hoplink, service
from router.fsops import ListingTooLarge, UnsafeRead
from router.generations import OperatorRefused
from router.tests.helpers import keyed_for_poll, write_request
from router.tests.test_hop_fence import _Fence
from router.tests.test_hoplink_senders import EXTERNAL, GenerationAbsent, _Reasoned


class _Lost(_Fence):

    def setUp(self):
        super().setUp()
        self.loads = []
        # The verb captures the store's verdict class against the runtime's
        # own classes, as production does with its FsOps.
        fsops = SimpleNamespace(UnsafeRead=UnsafeRead, ListingTooLarge=ListingTooLarge)
        self.rt = service.HopRuntime(plugin=self.plugin, fsops=fsops, hop=self.cfg.hop)

    def load(self, cfg):
        self.loads.append(cfg)
        return self.rt

    def lost_tree(self):
        """G1 admitted with a request handed over, fenced, and its tree
        reported absent: the instance holds `hop_tree_lost`."""
        g1 = self.admitted_g1()
        self.lid_ = self.lid()
        self.fence()
        self.plugin.store_result = "absent"
        k, _ = self.drain()
        self.assertEqual(self.hold(k).reason, "hop_tree_lost")
        return g1

    def verb(self, **kw):
        return generations.operator_new(self.cfg, "alpha", "the disk died",
                                        lost=hoplink.LostAcks(self.cfg, self.load), **kw)

    def ack_path(self, gen):
        return hoplink.gen_transport_dir(self.state_dir, self.lid_, gen) / hoplink.LOST_ACK_FILE


class LostAckTests(_Lost):

    def test_the_verb_acknowledges_the_lost_tree_and_the_successor_sends(self):
        g1 = self.lost_tree()
        self.plugin.store_retired = GenerationAbsent("no tree")
        senders = len(self.plugin.calls)
        plan = self.verb()
        self.assertEqual(plan.get("lost_acknowledged"), [g1])
        self.assertEqual(len(self.plugin.calls), senders, "the verb constructed a sender")
        ack = hoplink._read_json_file(self.ack_path(g1))
        self.assertIsNotNone(ack, "no acknowledgement written")
        self.assertEqual(ack["reason"], "the disk died")
        self.assertEqual(ack["audit_ref"],
                         f"{generations.EVENT_GENERATION_MINTED}:{plan['generation']}")
        self.assertTrue(all(s.closes == 1 for s in self.plugin.stores[-1:]),
                        "the probe's store was not closed")
        hoplink.reset_process_state()             # the router was stopped for the verb
        self.drain()                              # the new generation's first sight
        write_request(self.cfg, "alpha", "00000002", to=[EXTERNAL])
        k, _ = self.drain()
        self.assertIsNone(self.hold(k))
        g3 = self.gen(k)
        self.assertEqual(g3, plan["generation"])
        self.assertIn(("admit", g3), self.log)
        self.assertNotIn(("admit", g1), self.log[1:], "the lost generation was served")

    def test_an_audit_failure_leaves_no_ack_and_the_hold(self):
        g1 = self.lost_tree()
        self.plugin.store_retired = GenerationAbsent("no tree")
        before = generations.read_doc(self.state_dir, self.lid_)
        with mock.patch.object(generations.audit_mod, "append", side_effect=OSError(28, "full")):
            with self.assertRaises(OperatorRefused):
                self.verb()
        self.assertFalse(self.ack_path(g1).exists(), "an ack without its audit line")
        self.assertEqual(generations.read_doc(self.state_dir, self.lid_), before)
        hoplink.reset_process_state()
        k, _ = self.drain()
        self.assertEqual(self.hold(k).reason, "hop_tree_lost")

    def test_a_crash_after_the_audit_line_is_recovered_by_running_the_verb_again(self):
        g1 = self.lost_tree()
        self.plugin.store_retired = GenerationAbsent("no tree")
        with mock.patch.object(hoplink, "write_lost_acks", side_effect=OSError(5, "crash")):
            with self.assertRaises(OperatorRefused) as cm:
                self.verb()
        self.assertIn("run this verb again", str(cm.exception))
        self.assertFalse(self.ack_path(g1).exists())
        first = generations.read_doc(self.state_dir, self.lid_)["current"]
        hoplink.reset_process_state()
        k, _ = self.drain()
        self.assertEqual(self.hold(k).reason, "hop_tree_lost", "released with no ack")
        plan = self.verb()                        # the re-run
        self.assertNotEqual(plan["generation"], first)
        self.assertEqual(plan.get("lost_acknowledged"), [g1])
        hoplink.reset_process_state()
        k, _ = self.drain()
        self.assertIsNone(self.hold(k))

    def test_a_present_tree_is_not_acknowledged(self):
        for answer in (True, False):
            with self.subTest(retired=answer):
                self.tearDown()
                self.setUp()
                g1 = self.lost_tree()
                self.plugin.store_retired = answer
                plan = self.verb()
                self.assertNotIn("lost_acknowledged", plan)
                self.assertFalse(self.ack_path(g1).exists())

    def test_a_probe_it_cannot_decide_refuses_with_nothing_changed(self):
        for err in (_Reasoned("layout"), _Reasoned("marker_unreadable"), OSError(5, "EIO")):
            with self.subTest(err=repr(err)):
                self.tearDown()
                self.setUp()
                g1 = self.lost_tree()
                self.plugin.store_retired = err
                before = generations.read_doc(self.state_dir, self.lid_)
                with self.assertRaises(OperatorRefused) as cm:
                    self.verb()
                self.assertIn("nothing was changed", str(cm.exception))
                self.assertEqual(generations.read_doc(self.state_dir, self.lid_), before)
                self.assertFalse(self.ack_path(g1).exists())

    def test_a_store_that_cannot_be_built_refuses(self):
        g1 = self.lost_tree()
        self.plugin.store_fail = _Reasoned("settings_invalid")
        with self.assertRaises(OperatorRefused):
            self.verb()
        self.assertFalse(self.ack_path(g1).exists())

    def test_no_candidate_never_loads_the_plugin(self):
        self.admitted_g1()
        self.lid_ = self.lid()
        plan = self.verb()
        self.assertEqual(self.loads, [])
        self.assertNotIn("lost_acknowledged", plan)

    def test_an_acknowledged_generation_is_no_longer_a_candidate(self):
        g1 = self.lost_tree()
        self.plugin.store_retired = GenerationAbsent("no tree")
        self.verb()
        doc = generations.read_doc(self.state_dir, self.lid_)
        self.assertEqual(hoplink.lost_candidates(self.cfg, self.lid_, doc), [])
        self.assertTrue(self.ack_path(g1).exists())

    def test_the_dry_run_lists_candidates_and_writes_nothing(self):
        g1 = self.lost_tree()
        before = generations.read_doc(self.state_dir, self.lid_)
        plan = self.verb(dry_run=True)
        self.assertEqual(plan["lost_candidates"], [g1])
        self.assertEqual(self.loads, [], "the dry run loaded the plugin")
        self.assertEqual(generations.read_doc(self.state_dir, self.lid_), before)
        self.assertFalse(self.ack_path(g1).exists())


if __name__ == "__main__":
    import unittest
    unittest.main()
