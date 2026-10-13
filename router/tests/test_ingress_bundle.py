"""`ingress.parse_bundle`: the notice bundle checked as HOSTILE input, every
rule with a refusal witness beside the valid twin it is measured against."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest

from router import ingress, transport
from router.hoplink import canonical

NID = "1700000000-42"
CAP = 1024
#: Valid version-2 facts for the notice `make` builds: untrusted fleet mail
#: from fleet-b.example (the From's domain, P4), over link-a.
FACTS = {"hop_contract": 1, "notice_id": NID, "notice_class": "mail", "ingress": "hub",
         "admission": "fleet_hosts", "admission_link": "link-a",
         "admission_rule": "fleet-hosts.v1", "origin_host": "fleet-b.example",
         "facts_version": 2, "attachments": []}


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def make(*, blobs=(b"hello",), clean=True, notice_extra=None, drop_message_attachments=False,
         nid=NID, facts_extra=None):
    # `clean` is one flag for every part, or one per part.
    cleans = list(clean) if isinstance(clean, (list, tuple)) else [clean] * len(blobs)
    descs = []
    for k, blob in enumerate(blobs):
        d = {"filename": f"f{k}.txt", "media_type": "text/plain", "size_bytes": len(blob),
             "disposition": "clean" if cleans[k] else "stripped"}
        if cleans[k]:
            d["sha256"] = hashlib.sha256(blob).hexdigest()
            d["content_ref"] = f"{nid}.attachments/{k}"
        descs.append(d)
    message = {"id": "42", "from": "Someone <a@fleet-b.example>", "subject": "s",
               "preview": "b", "mailbox": "inbox", "provenance": "fleet-remote"}
    if not drop_message_attachments:
        message["attachments"] = descs
    notice = {"contract_version": "2", "kind": "deliver", "notice_id": nid,
              "ts": "2026-10-13T00:00:00Z", "hop_contract": 1, "message": message}
    if notice_extra:
        notice.update(notice_extra)
    rows = [{"source_sha256": hashlib.sha256(b).hexdigest(), "size_bytes": len(b)}
            for b in blobs] if not drop_message_attachments else []
    the_facts = dict(FACTS, notice_id=nid, attachments=rows)
    if facts_extra is not None:
        the_facts = facts_extra(the_facts)
    bundle = {"schema": transport.NOTICE_BUNDLE_SCHEMA,
              "notice": b64(json.dumps(notice).encode()),
              "spool": b64(json.dumps({"contract_version": "2", "notice_id": nid,
                                       "body_text": "b", "attachments": descs}).encode()),
              "hop": b64(canonical(the_facts)),
              "attachments": [b64(b) if c else None for b, c in zip(blobs, cleans)]}
    return bundle


def enc(bundle) -> bytes:
    return json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()


class BundleTests(unittest.TestCase):

    def parse(self, bundle, entry_id=NID):
        """A refusal of a bundle meant to be accepted is a FAILURE, not an error."""
        try:
            return ingress.parse_bundle(enc(bundle) if isinstance(bundle, dict) else bundle,
                                        entry_id, attachment_cap=CAP)
        except ingress.BundleRefused as e:
            self.fail(f"refused: {e.reason}: {e}")
        except Exception as e:  # noqa: BLE001
            self.fail(f"raised {e!r}")

    def refused(self, bundle, reason="bundle_invalid", entry_id=NID):
        with self.assertRaises(Exception) as cm:
            ingress.parse_bundle(enc(bundle) if isinstance(bundle, dict) else bundle,
                                 entry_id, attachment_cap=CAP)
        self.assertIsInstance(cm.exception, ingress.BundleRefused)
        self.assertEqual(cm.exception.reason, reason, str(cm.exception))

    def test_the_valid_twin(self):
        got = self.parse(make())
        self.assertEqual(got["attachments"], [b"hello"])
        self.assertEqual(got["notice"]["notice_id"], NID)
        self.assertEqual(got["facts"]["facts_version"], 2)

    def test_zero_attachments_with_the_member_absent(self):
        got = self.parse(make(blobs=(), drop_message_attachments=True))
        self.assertEqual(got["attachments"], [])

    def test_a_non_clean_part_has_no_bytes(self):
        got = self.parse(make(clean=False))
        self.assertEqual(got["attachments"], [None])

    def test_not_json_and_not_an_object(self):
        self.refused(b"{not json")
        self.refused(b"[1]")

    def test_an_older_bundle_schema(self):
        b = make()
        b["schema"] = "amap-hop-notice-entry/1"
        self.refused(b, "bundle_schema")

    def test_members_are_exactly_five(self):
        b = make()
        b["extra"] = 1
        self.refused(b)
        b = make()
        del b["hop"]
        self.refused(b)

    def test_base64_is_standard_canonical_and_capped(self):
        for bad in ("aGVsbG8=\n", "aGVsbG8", "a+b/c-_=", 7):
            with self.subTest(bad=bad):
                b = make()
                b["spool"] = bad
                self.refused(b)
        b = make(blobs=(b"x" * (CAP + 1),))
        self.refused(b)

    def test_non_canonical_base64_is_refused(self):
        # "aGVsbG9=" decodes to b"hello", the descriptor's own bytes, but does
        # not re-encode to itself: only the canonical check can refuse it.
        b = make()
        self.assertEqual(b["attachments"], ["aGVsbG8="])
        b["attachments"] = ["aGVsbG9="]
        self.refused(b)

    def test_the_document_cap_is_exact(self):
        def padded(member, size):
            b = make()
            doc = base64.b64decode(b[member])
            b[member] = b64(doc[:-1] + b" " * (size - len(doc)) + b"}")
            return b

        for member in ("notice", "spool"):
            with self.subTest(member=member):
                self.refused(padded(member, ingress.DOC_CAP + 1))
        self.assertIn("spool", self.parse(padded("spool", ingress.DOC_CAP)))

    def test_a_message_or_descriptor_that_is_not_an_object(self):
        # Zero attachments, so the positional check has nothing to refuse.
        for message in ("m", None):
            with self.subTest(message=message):
                self.refused(make(blobs=(), notice_extra={"message": message}))
        b = make()
        notice = json.loads(base64.b64decode(b["notice"]))
        notice["message"]["attachments"] = ["d"]
        b["notice"] = b64(json.dumps(notice).encode())
        b["attachments"] = [None]
        self.refused(b)

    def test_the_facts_cap(self):
        b = make()
        b["hop"] = b64(b"{" + b" " * transport.HOP_FACTS_MAX + b"}")
        self.refused(b)

    def test_the_notice_id_must_be_the_listed_entry(self):
        self.refused(make(), "entry_id_mismatch", entry_id="1700000000-43")
        # The notice's alone differing, the spool's still the listed entry.
        b = make(blobs=())
        notice = json.loads(base64.b64decode(b["notice"]))
        notice["notice_id"] = "1700000000-43"
        b["notice"] = b64(json.dumps(notice).encode())
        self.refused(b, "entry_id_mismatch")

    def test_the_spool_notice_id_must_be_the_listed_entry_too(self):
        b = make(blobs=())
        spool = json.loads(base64.b64decode(b["spool"]))
        spool["notice_id"] = "1700000000-43"
        b["spool"] = b64(json.dumps(spool).encode())
        self.refused(b, "entry_id_mismatch")

    def test_attachments_are_positional(self):
        b = make(blobs=(b"a", b"b"))
        b["attachments"] = b["attachments"][:1]
        self.refused(b)

    def test_content_ref_must_name_its_position_on_a_clean_part(self):
        b = make()
        notice = json.loads(base64.b64decode(b["notice"]))
        notice["message"]["attachments"][0]["content_ref"] = f"{NID}.attachments/1"
        b["notice"] = b64(json.dumps(notice).encode())
        self.refused(b)
        b = make()
        notice = json.loads(base64.b64decode(b["notice"]))
        notice["message"]["attachments"][0]["disposition"] = "stripped"
        b["notice"] = b64(json.dumps(notice).encode())
        self.refused(b)

    def test_bytes_without_a_ref_and_a_ref_without_bytes(self):
        b = make(clean=False)
        b["attachments"] = [b64(b"x")]
        self.refused(b)
        b = make()
        b["attachments"] = [None]
        self.refused(b)

    def test_size_and_digest_must_match_the_descriptor(self):
        b = make()
        b["attachments"] = [b64(b"hellO")]
        self.refused(b)
        b = make()
        notice = json.loads(base64.b64decode(b["notice"]))
        notice["message"]["attachments"][0]["size_bytes"] = 6
        b["notice"] = b64(json.dumps(notice).encode())
        self.refused(b)


if __name__ == "__main__":
    unittest.main()
