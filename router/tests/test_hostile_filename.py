"""A hostile/malformed filename under `outbound/` is never even opened —
filename hygiene (`REQ_NAME_RE`, verbatim from `gate/outbound.py:85`) runs
BEFORE any read. Real directory entries can never contain `/` (traversal
via a literal path separator isn't representable as a single filename at
all — the equivalent attack surface is an agent-supplied `req_id` INSIDE a
request body, which `validate.py`'s pattern check covers, proven against
`agent-mailbox-protocol/fixtures/invalid/request-traversal-reqid.json` in
`test_validate_fixtures.py`); what's tested here is every other way a
filename can fail hygiene: disallowed characters, wrong prefix, oversized
id, and a stray `.tmp` sibling."""

import unittest
from unittest import mock

from router import outbound
from router.tests.helpers import RouterTestCase, list_notices


class TestHostileFilename(RouterTestCase):
    def test_hostile_filenames_never_opened_and_left_in_place(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        ob = cfg.instances["alice"].outbox_root
        ob.mkdir(parents=True, exist_ok=True)

        hostile = [
            "req-bad.name.json",         # '.' not in the id charset
            "evil.json",                  # doesn't start with "req-"
            "req-" + ("x" * 65) + ".json",  # id longer than 64 chars
            "req-1.json.tmp",             # wrong suffix (a stray tmp file)
        ]
        good_body = (
            b'{"contract_version":"2","req_id":"00000001",'
            b'"draft":{"to":["agent.bob@local"],"subject":"s","body_text":"b"}}'
        )
        for name in hostile:
            (ob / name).write_bytes(good_body)  # well-formed CONTENT; only the name is hostile
        # One legitimate request too, to prove the drain continues past the hostile names.
        (ob / "req-00000001.json").write_bytes(good_body)

        with mock.patch.object(outbound, "read_capped", wraps=outbound.read_capped) as spy:
            summary = outbound.drain_instance(cfg, "alice")

        opened_names = [call.args[0].name for call in spy.call_args_list]
        for name in hostile:
            self.assertNotIn(name, opened_names, f"{name} should never have been opened")

        # All four hostile names are still sitting in outbound/, untouched.
        for name in hostile:
            self.assertTrue((ob / name).is_file(), f"{name} should be left in place")

        self.assertEqual(summary["outbound_skipped_bad_name"], len(hostile))
        # The drain continued: the one legitimate request was processed and delivered.
        self.assertEqual(len(list_notices(cfg, "bob")), 1)


if __name__ == "__main__":
    unittest.main()
