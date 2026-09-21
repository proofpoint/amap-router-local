"""router/tests/test_attachments_publish.py — §5 inbound publication.

`deliver.py`'s commit-sentinel write order extended for attachment blobs
(blobs -> message spool -> ledger -> notice LAST), the crash-midway trace
(a partially-written attachment is never visible as complete), namespace
containment on the WRITE side (mirrors `test_namespace_escape.py`, now
covering the attachment publish path specifically), and multi-recipient
isolation with attachments in play.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from router import attachments as attachments_mod
from router import deliver, outbound
from router.tests.helpers import (
    RouterTestCase,
    attachment_descriptor,
    inbound_sidecar_dir,
    list_notices,
    messages_dir,
    read_json,
    result_path,
    stage_outbound_sidecars,
    write_request,
)
from router.attachments import write_agent_visible as real_write_agent_visible
from router.util import NamespaceEscapeError
from router.util import atomic_write as real_atomic_write


def _va(data: bytes, filename: str = "f.bin") -> attachments_mod.VerifiedAttachment:
    import hashlib

    return attachments_mod.VerifiedAttachment(
        filename=filename, media_type="application/octet-stream",
        size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), data=data,
    )


class TestWriteOrderWithAttachments(RouterTestCase):
    def _request(self):
        return {
            "req_id": "00000001",
            "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"},
        }

    def test_blobs_precede_message_doc_precedes_notice(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        att = _va(b"attachment bytes")
        calls = []

        def recording_write_agent_visible(root, target_path, data):
            calls.append(str(target_path))
            return real_write_agent_visible(root, target_path, data)

        def recording_atomic_write(path, data):
            calls.append(str(path))
            return real_atomic_write(path, data)

        with mock.patch.object(
            deliver.attachments_mod, "write_agent_visible",
            side_effect=recording_write_agent_visible,
        ), mock.patch.object(deliver, "atomic_write", side_effect=recording_atomic_write):
            result = deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob", self._request(), attachments=[att],
            )

        notice_id = result["notice_id"]
        blob_path = inbound_sidecar_dir(cfg, "bob", notice_id) / "0"
        # The blob exists (written OUTSIDE the recorded calls above, via
        # `publish_attachment_blobs`'s own pinned-fd writer) and its mtime
        # precedes the message doc.
        self.assertTrue(blob_path.is_file())
        self.assertEqual(blob_path.read_bytes(), b"attachment bytes")

        self.assertEqual(len(calls), 3)
        self.assertIn("messages/notice-", calls[0])
        self.assertIn(str(cfg.state_dir), calls[1])
        self.assertIn("delivered/notice-", calls[1])
        self.assertIn("notices/notice-", calls[2])

    def test_blob_write_happens_before_any_message_write_call(self):
        """Direct proof the blob lands before the FIRST agent-visible
        write (the message spool) — patch `attachments.
        publish_attachment_blobs` to record when it ran relative to the
        first `write_agent_visible` call."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        att = _va(b"order-check bytes")
        order = []

        real_publish = deliver.attachments_mod.publish_attachment_blobs

        def recording_publish(*args, **kwargs):
            order.append("publish_blobs")
            return real_publish(*args, **kwargs)

        def recording_write_agent_visible(root, target_path, data):
            order.append("write_agent_visible")
            return real_write_agent_visible(root, target_path, data)

        with mock.patch.object(deliver.attachments_mod, "publish_attachment_blobs",
                                side_effect=recording_publish), \
             mock.patch.object(deliver.attachments_mod, "write_agent_visible",
                                side_effect=recording_write_agent_visible):
            deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob", self._request(), attachments=[att],
            )

        self.assertEqual(order[0], "publish_blobs")
        self.assertEqual(order.count("publish_blobs"), 1)

    def test_failure_on_notice_write_leaves_no_notice_but_blobs_are_already_complete(self):
        """Crash-midway trace, case (c): message doc + blobs committed,
        notice write fails — the blobs are complete and correct, but
        nothing relays them (no notice exists), so the delivery is not
        visible as done to the recipient's connector."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        att = _va(b"pre-notice-crash bytes")

        def failing_write_agent_visible(root, target_path, data):
            if "notices/" in str(target_path) and "messages" not in str(target_path):
                raise OSError("simulated failure writing the notice")
            return real_write_agent_visible(root, target_path, data)

        with mock.patch.object(
            deliver.attachments_mod, "write_agent_visible",
            side_effect=failing_write_agent_visible,
        ):
            with self.assertRaises(OSError):
                deliver.deliver(
                    cfg, cfg.state_dir, "alice", "bob", self._request(), attachments=[att],
                )

        self.assertEqual(list_notices(cfg, "bob"), [])
        # The message spool WAS written (write #2, before the simulated
        # failure) and its attachment descriptor is complete/correct...
        spool_files = list(messages_dir(cfg, "bob").glob("notice-*.json"))
        self.assertEqual(len(spool_files), 1)
        doc = read_json(spool_files[0])
        self.assertEqual(doc["attachments"][0]["sha256"], att.sha256)
        # ...and the blob bytes themselves are complete and correct...
        notice_id = doc["notice_id"]
        blob_path = inbound_sidecar_dir(cfg, "bob", notice_id) / "0"
        self.assertEqual(blob_path.read_bytes(), att.data)
        # ...but NOTHING relays this: the connector's watcher acts on the
        # NOTICE file, which does not exist, so this delivery is
        # unreachable from the agent's side despite the bytes being intact.

    def test_blob_write_is_atomic_no_partial_ordinal_ever_visible(self):
        """Crash-midway trace, case (a): a failure mid-blob-write must
        never leave a truncated ordinal visible — only an unreferenced
        temp name, if anything at all."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        att = _va(b"x" * 4096)

        real_fdopen = os.fdopen

        def failing_fdopen(fd, mode="r", *a, **kw):
            f = real_fdopen(fd, mode, *a, **kw)

            def bad_write(data):
                raise OSError("simulated mid-write crash")

            f.write = bad_write
            return f

        with mock.patch("os.fdopen", side_effect=failing_fdopen):
            with self.assertRaises(OSError):
                deliver.deliver(
                    cfg, cfg.state_dir, "alice", "bob", self._request(), attachments=[att],
                )

        # Nothing under bob's messages dir has the final ordinal name "0" —
        # at most an unreferenced temp file, never a complete-looking blob.
        bob_messages = messages_dir(cfg, "bob")
        for p in bob_messages.rglob("0"):
            self.fail(f"a complete-looking ordinal survived a mid-write crash: {p}")
        self.assertEqual(list_notices(cfg, "bob"), [])


class TestNamespaceContainmentOnPublish(RouterTestCase):
    def test_symlinked_inbound_root_refuses_attachment_publish(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        bob_inbox_root = cfg.instances["bob"].inbox_root
        outside = self.tmp / "outside-the-namespace"
        outside.mkdir()
        os.symlink(outside, bob_inbox_root)

        att = _va(b"must never land outside")
        with self.assertRaises(NamespaceEscapeError):
            deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob",
                {"req_id": "00000001",
                 "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"}},
                attachments=[att],
            )
        self.assertEqual(list(outside.iterdir()), [])

    def test_messages_leaf_pre_created_as_a_file_refuses_publish(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        inbox_root = cfg.instances["bob"].inbox_root
        inbox_root.mkdir(parents=True, exist_ok=True)
        (inbox_root / "messages").write_text("not a directory")

        att = _va(b"must never leak through a sabotaged leaf")
        with self.assertRaises(NamespaceEscapeError):
            deliver.deliver(
                cfg, cfg.state_dir, "alice", "bob",
                {"req_id": "00000001",
                 "draft": {"to": ["agent.bob@local"], "subject": "s", "body_text": "b"}},
                attachments=[att],
            )
        self.assertEqual((inbox_root / "messages").read_text(), "not a directory")


class TestMultiRecipientWithAttachments(RouterTestCase):
    def test_one_sabotaged_recipient_does_not_block_or_leak_to_the_healthy_one(self):
        cfg = self.make_config({
            "alpha": ["beta", "gamma"], "beta": ["alpha"], "gamma": ["alpha"],
        })
        # Sabotage gamma's `messages` leaf as a plain file, matching
        # `test_fanout_partial_failure.py`'s idiom of pre-creating a leaf
        # in the wrong shape.
        gamma_inbox = cfg.instances["gamma"].inbox_root
        gamma_inbox.mkdir(parents=True, exist_ok=True)
        (gamma_inbox / "messages").write_text("sabotaged")

        data = b"fan-out attachment bytes"
        desc = attachment_descriptor(data)
        write_request(
            cfg, "alpha", "00000001",
            to=["agent.beta@local", "agent.gamma@local"], attachments=[desc],
        )
        stage_outbound_sidecars(cfg, "alpha", "00000001", [data])

        outbound.drain_instance(cfg, "alpha")

        result = read_json(result_path(cfg, "alpha", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["reason_code"], outbound.REASON_PARTIAL_DELIVERY)
        self.assertEqual(result["recipients"], ["agent.beta@local"])

        # beta got the real bytes.
        beta_notices = list_notices(cfg, "beta")
        self.assertEqual(len(beta_notices), 1)
        notice_id = beta_notices[0][len("notice-"):-len(".json")]
        blob = inbound_sidecar_dir(cfg, "beta", notice_id) / "0"
        self.assertEqual(blob.read_bytes(), data)

        # gamma got nothing new beyond the sabotage file itself.
        self.assertEqual(list_notices(cfg, "gamma"), [])
        self.assertEqual((gamma_inbox / "messages").read_text(), "sabotaged")


if __name__ == "__main__":
    unittest.main()
