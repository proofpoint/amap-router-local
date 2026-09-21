"""A `req-*.json` entry that is a SYMLINK — not a hostile filename, a
hostile filesystem TYPE — must never be opened, even if its name passes
`REQ_NAME_RE` cleanly. `Path.is_file()` follows symlinks, so this has to be
checked before that ever happens; otherwise the router will read (and
deliver the body of) an arbitrary host-side file the target points at."""

import os
import unittest
from unittest import mock

from router import outbound
from router.tests.helpers import RouterTestCase, list_notices, write_request


class TestSymlinkedRequest(RouterTestCase):
    def test_symlinked_req_file_never_opened_and_left_in_place(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        ob = cfg.instances["alice"].outbox_root
        ob.mkdir(parents=True, exist_ok=True)

        # A host-side file OUTSIDE alice's namespace, containing a
        # well-formed request that would deliver to bob if ever read.
        outside_target = self.tmp / "outside-host-file.json"
        outside_target.write_bytes(
            b'{"contract_version":"2","req_id":"00000002",'
            b'"draft":{"to":["agent.bob@local"],"subject":"s","body_text":"exfil"}}'
        )
        os.symlink(outside_target, ob / "req-00000002.json")

        # One legitimate request too, to prove the drain continues past
        # the symlinked entry.
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="real")

        with mock.patch.object(outbound, "read_capped", wraps=outbound.read_capped) as spy:
            summary = outbound.drain_instance(cfg, "alice")

        opened_names = [call.args[0].name for call in spy.call_args_list]
        self.assertNotIn("req-00000002.json", opened_names)

        # The symlink is still sitting in outbound/, untouched (never
        # archived — an entry that was never opened is never processed).
        self.assertTrue((ob / "req-00000002.json").is_symlink())

        self.assertEqual(summary["outbound_skipped_bad_name"], 1)
        # The legitimate request still got through, and nothing carrying
        # the symlink target's "exfil" body was ever delivered.
        bob_notices = list_notices(cfg, "bob")
        self.assertEqual(len(bob_notices), 1)


if __name__ == "__main__":
    unittest.main()
