"""An instance's namespace is agent-owned filesystem territory. If an
agent replaces a subdirectory the router writes into (`inbound/`,
`outbound/results`, `outbound/processed`) with a symlink, the router must
refuse the write rather than follow the link — whether it points at an
arbitrary host path or, worse, a DIFFERENT instance's namespace."""

import os
import unittest

from router import deliver, outbound
from router.tests.helpers import RouterTestCase, list_notices, write_request
from router.util import NamespaceEscapeError


class TestNamespaceEscape(RouterTestCase):
    def test_delivery_refuses_symlinked_inbound_dir(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        bob_inbox_root = cfg.instances["bob"].inbox_root
        outside = self.tmp / "outside-the-namespace"
        outside.mkdir()

        # bob replaces his own `inbound/` (== inbox_root, in namespace
        # mode) with a symlink to a directory OUTSIDE every instance's root.
        os.symlink(outside, bob_inbox_root)

        with self.assertRaises(NamespaceEscapeError):
            deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob",
                {"req_id": "00000001",
                 "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"}},
            )

        # Nothing was written into the outside directory.
        self.assertEqual(list(outside.iterdir()), [])

    def test_delivery_refuses_inbound_symlinked_into_another_instance(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"], "mallory": ["alice"]})
        bob_inbox_root = cfg.instances["bob"].inbox_root
        mallory_root = cfg.instances["mallory"].root

        # bob replaces his own `inbound/` (== inbox_root) with a symlink
        # INTO mallory's entire declared root — cross-instance notice
        # injection, not just an escape to an arbitrary host path.
        os.symlink(mallory_root, bob_inbox_root)

        with self.assertRaises(NamespaceEscapeError):
            deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob",
                {"req_id": "00000001",
                 "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"}},
            )

        # mallory's namespace was never touched by this delivery attempt.
        self.assertEqual(list_notices(cfg, "mallory"), [])

    def test_drain_isolates_a_symlinked_outbound_results_dir(self):
        # End-to-end: the escape attempt is refused, logged, and never
        # written through -- and (the LOW-severity forever-retry fix:
        # `_publish_result_and_archive` no longer lets a refused `results/`
        # pin escape uncaught) the request still resolves normally instead
        # of being left to error on every future drain: the private result
        # under state_dir is already authoritative once delivery has
        # happened, so this counts as drained, not `outbound_errored`.
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        alice_ob = cfg.instances["alice"].outbox_root
        alice_ob.mkdir(parents=True, exist_ok=True)
        outside = self.tmp / "outside-alice"
        outside.mkdir()
        os.symlink(outside, alice_ob / "results")

        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["outbound_errored"], 0)
        self.assertEqual(summary["drained"], 1)
        # Never written through the symlink -- the escape attempt itself
        # is still refused, exactly as before.
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
