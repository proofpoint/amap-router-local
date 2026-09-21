"""A failing recipient must never leave the request un-answered.

Regression for a defect found in Loop-3 verification: the cold fan-out was a
list comprehension, so an exception on recipient N aborted the whole request
before the result-and-archive step. The request stayed in `outbound/`, and
every later poll re-delivered to the healthy recipients — unbounded
duplication, triggerable by any hostile RECIPIENT (under posture A it owns
its own namespace and can make a write fail).

The invariant: one governing result, written exactly once, no matter how any
individual delivery goes.
"""
from router import deliver as deliver_mod, outbound
from router.tests import helpers


class FanOutPartialFailureTest(helpers.RouterTestCase):
    def _cfg(self):
        return self.make_config({
            "alpha": ["beta", "gamma"], "beta": ["alpha"], "gamma": ["alpha"],
        })

    def _sabotage(self, victims):
        real = deliver_mod.deliver

        def flaky(cfg, state_dir, sender, recipient, request, **kw):
            if recipient in victims:
                raise OSError(f"namespace for {recipient} sabotaged")
            return real(cfg, state_dir, sender, recipient, request, **kw)

        outbound.deliver_mod.deliver = flaky
        self.addCleanup(setattr, outbound.deliver_mod, "deliver", real)

    def test_healthy_recipient_is_not_redelivered_on_later_polls(self):
        cfg = self._cfg()
        helpers.write_request(cfg, "alpha", "00000001",
                              to=["agent.beta@local", "agent.gamma@local"])
        self._sabotage({"gamma"})

        outbox_root = cfg.instances["alpha"].outbox_root
        for _ in range(3):
            outbound.drain_instance(cfg, "alpha")

        self.assertEqual(len(helpers.list_notices(cfg, "beta")), 1,
                         "healthy recipient was re-delivered on a later poll")
        self.assertEqual(list(outbox_root.glob("req-*.json")), [],
                         "request was left un-archived and will be replayed")
        self.assertTrue(helpers.result_path(cfg, "alpha", "00000001").is_file())

    def test_partial_failure_reports_only_delivered_recipients(self):
        cfg = self._cfg()
        helpers.write_request(cfg, "alpha", "00000001",
                              to=["agent.beta@local", "agent.gamma@local"])
        self._sabotage({"gamma"})
        outbound.drain_instance(cfg, "alpha")

        res = helpers.read_json(helpers.result_path(cfg, "alpha", "00000001"))
        self.assertEqual(res["outcome"], "accepted")
        self.assertEqual(res["reason_code"], outbound.REASON_PARTIAL_DELIVERY)
        # `recipients` is the authoritative record of who actually got it.
        self.assertEqual(res["recipients"], ["agent.beta@local"])
        self.assertIn("gamma", res["detail"])

    def test_total_failure_is_held_for_a_human_not_dropped(self):
        cfg = self._cfg()
        helpers.write_request(cfg, "alpha", "00000001",
                              to=["agent.beta@local", "agent.gamma@local"])
        self._sabotage({"beta", "gamma"})
        outbound.drain_instance(cfg, "alpha")

        res = helpers.read_json(helpers.result_path(cfg, "alpha", "00000001"))
        self.assertEqual(res["outcome"], "queued_for_human")
        self.assertEqual(res["reason_code"], outbound.REASON_DELIVERY_FAILED)
        self.assertEqual(res["recipients"], [])
        self.assertEqual(len(helpers.list_notices(cfg, "beta")), 0)

    def test_all_healthy_is_unchanged(self):
        cfg = self._cfg()
        helpers.write_request(cfg, "alpha", "00000001",
                              to=["agent.beta@local", "agent.gamma@local"])
        outbound.drain_instance(cfg, "alpha")

        res = helpers.read_json(helpers.result_path(cfg, "alpha", "00000001"))
        self.assertEqual(res["outcome"], "accepted")
        self.assertEqual(res["reason_code"], outbound.REASON_ALLOWLISTED)
        self.assertEqual(sorted(res["recipients"]),
                         ["agent.beta@local", "agent.gamma@local"])
