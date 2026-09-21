"""req_id reuse under a DIFFERENT request body must never replay the stale
verdict. An agent can trivially manufacture this: delete its own
`outbound/{results,processed}`, and `inbox-submit`'s monotonic req_id
counter (which reads those agent-writable dirs) restarts at `00000000` —
so a brand-new, different request can land under an id the router already
has a private result for. Resuming naively would silently answer the NEW
request with the OLD verdict (a false `accepted` for a message that was
never sent)."""

import shutil
import unittest
from unittest import mock

from router import outbound
from router.tests.helpers import RouterTestCase, list_notices, read_json, result_path, write_request


class TestReqIdReuse(RouterTestCase):
    def test_reused_id_different_content_is_refused_not_replayed(self):
        cfg = self.make_config({
            "alice": ["bob", "mallory"], "bob": ["alice"], "mallory": ["alice"],
        })

        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="first")
        summary1 = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary1["outbound_errored"], 0)
        first_result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(first_result["outcome"], "accepted")
        self.assertEqual(len(list_notices(cfg, "bob")), 1)
        self.assertEqual(len(list_notices(cfg, "mallory")), 0)

        # Agent wipes its own outbound/{results,processed} (agent-writable)
        # and resubmits a DIFFERENT request under the SAME req_id — as
        # inbox-submit's own counter would after such a wipe.
        outbound_dir = cfg.instances["alice"].outbox_root
        shutil.rmtree(outbound_dir / "results")
        shutil.rmtree(outbound_dir / "processed")
        write_request(cfg, "alice", "00000001", to=["agent.mallory@local"], body_text="second, different")

        summary2 = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary2["outbound_req_id_reused"], 1)
        self.assertEqual(summary2["outbound_resumed"], 0)
        self.assertEqual(summary2["outbound_errored"], 0)

        second_result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(second_result["outcome"], "rejected")
        self.assertEqual(second_result["reason_code"], "req_id_reused")

        # The second, different request was NEVER delivered anywhere —
        # mallory (its forged/actual target) got nothing.
        self.assertEqual(len(list_notices(cfg, "mallory")), 0)
        # Bob still has exactly the one notice from the original request.
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

        # The request itself was still archived (every drained request
        # ends with a result and is removed from the live outbound/ dir).
        self.assertFalse((outbound_dir / "req-00000001.json").exists())

    def test_reused_id_identical_content_still_resumes(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        req_path = write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="same")
        raw_bytes = req_path.read_bytes()

        outbound.drain_instance(cfg, "alice")
        self.assertEqual(len(list_notices(cfg, "bob")), 1)
        first_result = read_json(result_path(cfg, "alice", "00000001"))

        outbound_dir = cfg.instances["alice"].outbox_root
        shutil.rmtree(outbound_dir / "results")
        shutil.rmtree(outbound_dir / "processed")
        (outbound_dir / "req-00000001.json").write_bytes(raw_bytes)  # byte-identical resubmit

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["outbound_resumed"], 1)
        self.assertEqual(summary["outbound_req_id_reused"], 0)

        second_result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(second_result, first_result)
        # Still exactly one notice — the resume did not re-deliver.
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

    def test_transient_read_failure_during_resume_is_not_reported_as_reuse(self):
        """A SEPARATE bug bundled with the reply-path reprocessing fix
        (ROUTER-RELIABILITY.md): the resume path's digest re-read used to
        fold EVERY `ReadTooLargeError`/`OSError` into `current_digest =
        None`, which then always compared unequal to `stored_digest` and
        was reported as `req_id_reused` — a permanent, false `rejected`
        verdict for what could just be a transient disk/permission
        hiccup, never evidence the id was actually reused for different
        content."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        req_path = write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="first")
        raw_bytes = req_path.read_bytes()

        outbound.drain_instance(cfg, "alice")
        first_result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

        # Re-drop the byte-identical request (a naive resync/replay,
        # `test_replay.py`'s exact idiom) so the SECOND drain takes the
        # resume path and re-reads it to verify the digest.
        outbound_dir = cfg.instances["alice"].outbox_root
        (outbound_dir / "req-00000001.json").write_bytes(raw_bytes)

        with mock.patch.object(
            outbound, "_read_request_pinned",
            side_effect=PermissionError("simulated transient read failure"),
        ):
            summary = outbound.drain_instance(cfg, "alice")

        # NOT reported as reuse — no false rejected verdict, and the
        # original accepted result is untouched.
        self.assertEqual(summary["outbound_req_id_reused"], 0)
        self.assertEqual(summary["outbound_resumed"], 0)
        self.assertEqual(summary["outbound_errored"], 1)
        second_result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(second_result, first_result)
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

        # A clean drain afterward (no transient failure this time)
        # resumes normally — the earlier transient failure didn't poison
        # anything.
        summary2 = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary2["outbound_resumed"], 1)
        self.assertEqual(summary2["outbound_req_id_reused"], 0)

    def test_processed_deletion_alone_is_not_a_durability_concern(self):
        """AMAP v2.2.0 §2 'Deletion rights': a connector MAY delete
        `outbound/processed/` at will, and a runtime MUST NOT rely on its
        contents as durable state. Delete ONLY `processed/` (leaving
        `results/` and the private `state_dir` anchor untouched), then
        submit a FRESH req_id (never reused) — the drain must process it
        completely normally and simply recreate `processed/` as a
        courtesy, proving the router never treats that directory as
        anything but recreatable archive state."""
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], body_text="first")
        outbound.drain_instance(cfg, "alice")
        self.assertEqual(len(list_notices(cfg, "bob")), 1)

        outbound_dir = cfg.instances["alice"].outbox_root
        shutil.rmtree(outbound_dir / "processed")
        self.assertFalse((outbound_dir / "processed").exists())

        write_request(cfg, "alice", "00000002", to=["agent.bob@local"], body_text="second")
        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["outbound_errored"], 0)
        self.assertEqual(summary["outbound_req_id_reused"], 0)
        self.assertEqual(summary["accepted"], 1)

        second_result = read_json(result_path(cfg, "alice", "00000002"))
        self.assertEqual(second_result["outcome"], "accepted")
        self.assertEqual(len(list_notices(cfg, "bob")), 2)
        # `processed/` was recreated as a byproduct of archiving the fresh
        # request — never consulted to decide anything about it.
        self.assertTrue((outbound_dir / "processed" / "req-00000002.json").is_file())


if __name__ == "__main__":
    unittest.main()
