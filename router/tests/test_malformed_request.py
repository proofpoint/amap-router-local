import unittest

from router import outbound
from router.tests.helpers import (
    RouterTestCase, list_notices, processed_path, read_json, result_path, write_request,
)
from router.util import DEFAULT_READ_CAP


class TestMalformedRequest(RouterTestCase):
    def _run_one(self, cfg, **write_kwargs):
        write_request(cfg, "alice", "00000001", **write_kwargs)
        outbound.drain_instance(cfg, "alice")
        return read_json(result_path(cfg, "alice", "00000001"))

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def test_bad_json(self):
        write_request(self.cfg, "alice", "00000001", raw_override=b"{not json")
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "malformed_request")
        self._assert_archived_no_delivery()

    def test_version_absent(self):
        write_request(
            self.cfg, "alice", "00000001",
            raw_override=b'{"req_id":"00000001","draft":{"to":["agent.bob@local"],"subject":"s","body_text":"b"}}',
        )
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "unsupported_contract_version")
        self._assert_archived_no_delivery()

    def test_empty_to(self):
        result = self._run_one(self.cfg, to=[])
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "malformed_request")
        self._assert_archived_no_delivery()

    def test_req_id_mismatch(self):
        write_request(
            self.cfg, "alice", "00000001",
            raw_override=(
                b'{"contract_version":"2","req_id":"00000099",'
                b'"draft":{"to":["agent.bob@local"],"subject":"s","body_text":"b"}}'
            ),
        )
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "req_id_mismatch")
        self._assert_archived_no_delivery()

    def test_agent_id_mismatch(self):
        result = self._run_one(self.cfg, agent_id="not-alice")
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "agent_id_mismatch")
        self._assert_archived_no_delivery()

    def test_agent_id_match_is_fine(self):
        result = self._run_one(self.cfg, agent_id="alice", to=["agent.bob@local"])
        self.assertEqual(result["outcome"], "accepted")

    def test_oversized_request_rejected_uncounted(self):
        # The outbox is untrusted input (SCOPE.md "Trust story") — a
        # request over the 1 MiB cap must be refused via read_capped's
        # ReadTooLargeError path, not slurped, and never partially
        # delivered. Deliberately VALID JSON (padded via body_text, to a
        # real mutual peer) rather than garbage bytes: garbage would also
        # get rejected as malformed_request via the JSON-decode fallback,
        # which would pass even with the size cap disabled entirely and so
        # would not actually pin the cap. Only a well-formed-but-oversized
        # request distinguishes "refused for size" from "refused for
        # shape" — an uncapped read of this same payload would parse fine
        # and be delivered (`accepted`), which is exactly the delta this
        # test must catch.
        result = self._run_one(
            self.cfg,
            to=["agent.bob@local"],
            body_text="x" * (DEFAULT_READ_CAP + 1),
        )
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "malformed_request")
        self._assert_archived_no_delivery()

    def test_attachment_declared_with_no_sidecar_dir_is_rejected(self):
        # Attachment transport exists now (AMAP v2.3.0, `router/attachments.
        # py`) — a descriptor with no matching sidecar dir on disk is a
        # genuine integrity failure (`attachment_mismatch`), not the old
        # unconditional `attachments_unsupported` fail-closed. See
        # `router/tests/test_attachments_outbound.py` for the full
        # transport test suite (happy path, caps, TOCTOU, ...).
        result = self._run_one(
            self.cfg,
            attachments=[{
                "filename": "x.pdf", "media_type": "application/pdf",
                "size_bytes": 10, "sha256": "a" * 64,
            }],
        )
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "attachment_mismatch")
        self._assert_archived_no_delivery()

    def _assert_archived_no_delivery(self):
        self.assertTrue(processed_path(self.cfg, "alice", "00000001").is_file())
        self.assertEqual(list_notices(self.cfg, "bob"), [])


if __name__ == "__main__":
    unittest.main()
