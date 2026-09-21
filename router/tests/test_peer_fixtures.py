"""Step 7 of the peer-lane build: fixtures pinning three properties as
assertions rather than incidents.

  - `sender_exposure` on a submit-request — top-level or under `draft` — is
    `rejected`/`malformed_request` before policy runs (the closed envelope),
    and so is `lineage`, should it ever return;
  - a `peer` document fails `deliver-notice.schema.json` (what a consumer
    of `inbox/notices/` would drop);
  - a `deliver` document fails `peer-notice.schema.json` (what a consumer of
    `peer/notices/` would drop) — skipped while that schema has not landed
    in the AMAP checkout beside this repo.

The last two also run over documents THIS router produces, not just over
hand-built ones, so a drift in `deliver.py` shows up here."""

import json
import unittest

from router import deliver, outbound
from router.tests.helpers import (
    RouterTestCase, list_notices, notices_dir, read_json, result_path, write_request,
)
from router.tests.peer_helpers import (
    addr, list_peer_notices, load_amp_validate, make_peer_config, peer_notices_dir,
    peer_schema_present,
)
from router.validate import validate_request


def _request(**extra_top):
    doc = {
        "contract_version": "2", "req_id": "00000001",
        "draft": {"to": ["b@example.invalid"], "subject": "s", "body_text": "b"},
    }
    doc.update(extra_top)
    return doc


_STAMP = {"asserted_by": "a@example.invalid", "external_mail_delivered": False,
          "window_start": "t", "window_end": "t"}


class SenderCannotSetExposureTests(RouterTestCase):
    def test_validator_rejects_the_key_at_top_level_and_under_draft(self):
        for label, doc in (
            ("top", _request(sender_exposure=_STAMP)),
            ("draft", {**_request(), "draft": {**_request()["draft"], "sender_exposure": _STAMP}}),
            ("lineage-top", _request(lineage=[{"notice_id": "x"}])),
            ("lineage-draft", {**_request(), "draft": {**_request()["draft"], "lineage": []}}),
        ):
            with self.subTest(case=label):
                ok, reason, detail = validate_request(doc)
                self.assertFalse(ok)
                self.assertEqual(reason, "malformed_request")
                self.assertIn("unknown key", detail)

    def test_end_to_end_a_stamped_submit_on_an_edge_never_becomes_a_notice(self):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        outbox = cfg.instances["a"].outbox_root
        (outbox / "req-00000001.json").write_bytes(json.dumps(_request(sender_exposure=_STAMP)).encode())
        draft_doc = _request()
        draft_doc["req_id"] = "00000002"
        draft_doc["draft"]["sender_exposure"] = _STAMP
        (outbox / "req-00000002.json").write_bytes(json.dumps(draft_doc).encode())
        outbound.drain_instance(cfg, "a")
        for req_id in ("00000001", "00000002"):
            result = read_json(result_path(cfg, "a", req_id))
            self.assertEqual((result["outcome"], result["reason_code"]),
                             ("rejected", "malformed_request"), req_id)
        self.assertEqual(list_peer_notices(cfg, "b"), [])
        self.assertEqual(list_notices(cfg, "b"), [])


class SecondLockTests(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.amp = load_amp_validate()
        self.cfg = make_peer_config(self, {
            "a": {"peers": ["c"]}, "b": {"peer_senders": ["a"]}, "c": {"peers": ["a"]},
        })
        write_request(self.cfg, "a", "00000001", to=[addr("b")])
        write_request(self.cfg, "a", "00000002", to=[addr("c")])
        outbound.drain_instance(self.cfg, "a")
        self.peer_notice = read_json(peer_notices_dir(self.cfg, "b") / list_peer_notices(self.cfg, "b")[0])
        self.mail_notice = read_json(notices_dir(self.cfg, "c") / list_notices(self.cfg, "c")[0])

    def test_a_peer_document_fails_the_deliver_notice_schema(self):
        errs = self.amp.check_document("notice-produced.json", self.peer_notice)
        self.assertNotEqual(errs, [])
        self.assertTrue(any("kind" in e for e in errs), errs)
        # And the mail notice passes it, so the failure above is the kind.
        self.assertEqual(self.amp.check_document("notice-produced.json", self.mail_notice), [])

    def test_a_deliver_document_fails_the_peer_notice_schema(self):
        if not peer_schema_present():
            self.skipTest("peer-notice.schema.json has not landed in the AMAP checkout")
        errs = self.amp.check_document("peer-produced.json", self.mail_notice)
        self.assertNotEqual(errs, [])
        self.assertEqual(self.amp.check_document("peer-produced.json", self.peer_notice), [])

    def test_the_two_notices_differ_in_exactly_the_profile_fields(self):
        """`kind`, `mailbox`, `provenance` (absent on peer) and
        `sender_exposure` (present on peer): nothing else about the shape
        changes between lanes, which is what lets the message spool doc and
        the attachment machinery be reused byte for byte."""
        p, m = self.peer_notice, self.mail_notice
        self.assertEqual(set(p) , set(m))
        pm, mm = dict(p["message"]), dict(m["message"])
        self.assertEqual((pm.pop("mailbox"), mm.pop("mailbox")), ("peer", "inbox"))
        self.assertEqual(mm.pop("provenance"), "internal")
        self.assertNotIn("provenance", pm)
        pm.pop("sender_exposure")
        self.assertNotIn("sender_exposure", mm)
        self.assertEqual(set(pm), set(mm))

    def test_router_dsn_passes_the_deliver_schema(self):
        dsn = deliver.deliver_router_notice(
            self.cfg, self.cfg.state_dir, "a", subject="Not delivered: denied",
            body_text="x", in_reply_to="0" * 32,
        )
        notice = read_json(notices_dir(self.cfg, "a") / f"notice-{dsn['notice_id']}.json")
        self.assertEqual(self.amp.check_document("notice-produced.json", notice), [])


if __name__ == "__main__":
    unittest.main()
