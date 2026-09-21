"""A hostile DIRECTORY SHAPE in the untrusted outbox — not just a hostile
filename — must never crash the router or wedge OTHER instances' mail.
Pre-creating `outbound/results` (or `processed`) as a regular file makes
`_mkdir_and_pin` refuse it (`NamespaceEscapeError`); that refusal is caught
inside `_publish_result_and_archive` itself (LOW-severity forever-retry
fix), so the request still resolves normally — logged, not counted as
`outbound_errored`, and never retried forever — rather than propagating out
of the drain loop the way an uncaught exception used to."""

import unittest

from router import outbound, service
from router.tests.helpers import RouterTestCase, list_notices, write_request


class TestExceptionIsolation(RouterTestCase):
    def test_results_dir_precreated_as_file_resolves_without_erroring(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        outbound_dir = cfg.instances["alice"].outbox_root
        outbound_dir.mkdir(parents=True, exist_ok=True)
        # Hostile directory shape: `outbound/results` is a regular FILE,
        # not a directory — `_mkdir_and_pin` refuses it
        # (`NamespaceEscapeError`), caught inside `_publish_result_and_
        # archive` (never propagated to `_finish`/`drain_instance`).
        (outbound_dir / "results").write_bytes(b"not a directory")

        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        # drain_instance must not raise, and — since the private result
        # under state_dir is already authoritative once delivery has
        # happened — this is NOT counted as an error: `outbound/processed/`
        # (untouched by the hostile shape) still receives the archived
        # request even though `outbound/results/` could not be published.
        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["outbound_errored"], 0)
        self.assertEqual(summary["drained"], 1)
        self.assertEqual(summary["accepted"], 1)

        # bob's notice IS written — delivery happens before the publish-
        # the-public-result step that hits the pre-created file.
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

        # Re-draining alice does not duplicate the delivery — still
        # exactly one notice for bob — and still does not error, even
        # though `outbound/results` is still hostile: the request was
        # already archived into `processed/` on the first pass (only
        # `results/` was ever unusable), so `outbound/` has nothing left
        # under this req_id for the second drain to see at all — not an
        # error, not a resume, just nothing to do.
        summary2 = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary2["outbound_errored"], 0)
        self.assertEqual(summary2["outbound_resumed"], 0)
        self.assertEqual(summary2["drained"], 0)
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

    def test_one_instances_hostile_shape_does_not_stop_another(self):
        cfg = self.make_config({
            "alice": ["carol"], "bob": ["carol"], "carol": ["alice", "bob"],
        })

        # alice: hostile shape -- resolves without erroring (see above),
        # but the point of THIS test is that bob's independent, healthy
        # drain is unaffected by it either way.
        alice_outbound = cfg.instances["alice"].outbox_root
        alice_outbound.mkdir(parents=True, exist_ok=True)
        (alice_outbound / "results").write_bytes(b"not a directory")
        write_request(cfg, "alice", "00000001", to=["agent.carol@local"])

        # bob: a perfectly normal request that must still be delivered.
        write_request(cfg, "bob", "00000001", to=["agent.carol@local"])

        summary = service.run_once(cfg)

        self.assertEqual(summary["alice"]["outbound_errored"], 0)
        self.assertEqual(summary["bob"]["outbound_errored"], 0)
        self.assertEqual(summary["bob"]["drained"], 1)

        # carol got both deliveries -- alice's hostile `results/` shape
        # never stopped alice's own delivery to carol (the refused publish
        # step happens after delivery), and bob's independent drain was
        # never touched by alice's hostile shape at all.
        self.assertEqual(len(list_notices(cfg, "carol")), 2)


if __name__ == "__main__":
    unittest.main()
