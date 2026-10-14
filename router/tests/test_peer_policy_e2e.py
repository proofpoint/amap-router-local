"""The receiver's sender-age refusals and a 5(b) value demotion, end to end:
each candidate goes through the real take and evaluate over a real journal,
a real decision key and bob's real peer tree.

The refusals are decided by the ROUTER'S OWN hook set,
`peerpolicy.production_hooks`, never a stand-in, so nothing between the
production age policy and the agent's tree is stubbed:

  * `sender_age_missing` and `quarantined` are each refused with their code,
    no notice reaches the agent and the replay marker says refused;
  * a quarantined refusal raises status's since-start count
    `peer_store.epochs.refusals.quarantined` by exactly one, read through
    `peerjournal.status_doc`, the function the poll writes into
    `status.json` and `status --json` prints;
  * a `statement_value` demotion (check 5(b), after the signature passed)
    carries its control, reserves nothing and places nothing.

The codec is the stand-in (`peer_standin`): the verdict that a given
statement fails 5(b) is the transport plugin's, and is proved against the
real plugin elsewhere. What is pinned here is what this router does with
that verdict."""
from __future__ import annotations

import dataclasses

from router import hoplink, peerclock, peerjournal, peerpolicy
from router.tests import test_peerevaluate as tpe
from router.tests.test_peercarries import _ValueRefusing
from router.tests.test_peerbind import STATEMENT_ID, T1

NOW = tpe.NOW
DAY = 86400
EXPOSED = {"asserted_by": f"amap.router@{T1}", "exposure": "internal"}


def ts(delta_s: int) -> str:
    from datetime import timedelta
    return (NOW + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _E2E(tpe._Eval):

    def setUp(self):
        super().setUp()
        hoplink.reset_process_state()
        self.addCleanup(hoplink.reset_process_state)

    def evaluate_production(self, key):
        """One pass as the router builds it: the clock advanced once, and the
        production hook set bound to that pass's context."""
        import json
        clock = peerclock.advance(self.state_dir, NOW)
        hctx = peerpolicy.hook_context(self.cfg, delegation=self.lane, state_dir=self.state_dir,
                                       now=NOW, clock=clock)
        ctx = peerjournal.Ctx(state_dir=self.state_dir, cfg=self.cfg, delegation=self.lane,
                              hooks=peerpolicy.production_hooks(hctx), now=NOW, clock=clock,
                              view=lambda raw: json.loads(raw), effects=self.effects,
                              retired=lambda _r: False)
        return peerjournal.evaluate(ctx, peerjournal.read_record(self.state_dir, tpe.OWNER, key))

    def quarantined_count(self):
        return peerjournal.status_doc(self.state_dir, NOW)["epochs"]["refusals"]["quarantined"]


class ProductionRefusalTests(_E2E):

    def refused(self, raw):
        return self.evaluate_production(self.take(raw))

    def assert_refused_unplaced(self, rec, code):
        self.assertEqual((rec["state"], rec["disposed"], rec["cause"], rec["policy_code"]),
                         ("done", "refused", "policy", code))
        self.assertEqual(self.notices(), [], "the agent never gets it")
        self.assertEqual(tpe.marker(self.state_dir, rec), "refused")

    def test_a_missing_sender_since_is_refused_and_never_placed(self):
        self.assert_refused_unplaced(self.refused(self.raw()), "sender_age_missing")

    def test_a_sender_younger_than_a_day_is_quarantined_and_never_placed(self):
        rec = self.refused(self.raw(sender_since=ts(-(DAY - 1))))
        self.assert_refused_unplaced(rec, "quarantined")

    def test_a_quarantined_refusal_raises_the_status_count_by_one(self):
        before = self.quarantined_count()
        self.refused(self.raw(sender_since=ts(-(DAY - 1))))
        self.assertEqual((before, self.quarantined_count()), (0, 1))

    def test_the_positive_control_a_day_old_exposed_sender_is_placed(self):
        # The same production hook set PLACES a sender exactly a day old with
        # its exposure asserted by its own runtime: the refusals above, not
        # some other gate, are what keep the agent's tree empty.
        rec = self.refused(self.raw(sender_since=ts(-DAY), sender_exposure=EXPOSED))
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"))
        self.assertEqual(len(self.notices()), 1)
        self.assertEqual(tpe.marker(self.state_dir, rec), "placed")
        self.assertEqual(self.quarantined_count(), 0)


class ValueDemotionUnplacedTests(_E2E):

    def test_a_statement_value_demotion_reserves_nothing_and_places_nothing(self):
        self.lane = dataclasses.replace(
            self.lane, codec=_ValueRefusing(self.lane.codec, "statement_value"))
        rec = self.evaluate_production(self.take(self.raw()))
        self.assertEqual((rec["state"], rec["disposed"], rec["cause"]),
                         ("done", "demoted", "statement_value"))
        control = rec["control"] or {}
        self.assertEqual((control.get("outcome"), control.get("about"), control.get("to")),
                         ("demoted", STATEMENT_ID, f"amap.router@{T1}"))
        self.assertEqual(self.replay_files(), [], "ahead of reservation")
        self.assertEqual(self.notices(), [], "never placed as a task")

    def test_the_companion_a_signed_candidate_the_codec_passes_reserves_and_places(self):
        # The surfaces above see a reservation and a placement when there is
        # one: an empty listing is a finding, not a listing that never ran.
        rec = self.evaluate_production(self.take(self.raw(
            sender_since=ts(-DAY), sender_exposure=EXPOSED)))
        self.assertEqual(rec["disposed"], "placed")
        self.assertNotEqual(self.replay_files(), [])
        self.assertEqual(len(self.notices()), 1)
