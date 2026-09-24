"""router/tests/test_attachments_outbound.py — §3 attachment ingest.

Happy path, caps (checked BEFORE any sidecar is opened), every rejection
shape `attachments.ingest_attachments` is documented to catch, and the
TOCTOU discipline that makes reading an agent-owned sidecar dir safe
(modeled on `test_reset.py`'s `TestResetMailboxTOCTOU`, extended with a
genuine cross-process race plus a path-based control that proves the race
harness can actually detect the bug class).
"""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import shutil
import signal
import unittest
from unittest import mock

from router import attachments as attachments_mod
from router import outbound
from router.tests.peer_helpers import load_amp_validate
from router.tests.helpers import (
    RouterTestCase,
    attachment_descriptor,
    list_notices,
    messages_dir,
    notices_dir,
    outbound_sidecar_dir,
    processed_path,
    read_json,
    result_path,
    stage_outbound_sidecars,
    write_request,
)

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class TestHappyPath(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def test_two_attachments_including_empty_file_delivered_and_verified(self):
        data0 = b"hello, this is report.pdf content"
        data1 = b""  # Q10: a legitimate zero-byte attachment
        desc0 = attachment_descriptor(data0, filename="report.pdf", media_type="application/pdf")
        desc1 = attachment_descriptor(data1, filename="empty.txt", media_type="text/plain")
        self.assertEqual(desc1["sha256"], EMPTY_SHA256)

        write_request(
            self.cfg, "alice", "00000001",
            to=["agent.bob@local"], attachments=[desc0, desc1],
        )
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [data0, data1])

        summary = outbound.drain_instance(self.cfg, "alice")
        self.assertEqual(summary["accepted"], 1)

        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(
            result["attachments"],
            [
                {"index": 0, "outcome": "accepted", "detail": None},
                {"index": 1, "outcome": "accepted", "detail": None},
            ],
        )

        # sender-side sidecar dir is gone once the request is archived.
        self.assertFalse(outbound_sidecar_dir(self.cfg, "alice", "00000001").exists())
        self.assertTrue(processed_path(self.cfg, "alice", "00000001").is_file())

        notices = list_notices(self.cfg, "bob")
        self.assertEqual(len(notices), 1)
        notice_id = notices[0][len("notice-"):-len(".json")]

        message_doc = read_json(messages_dir(self.cfg, "bob") / notices[0])
        atts = message_doc["attachments"]
        self.assertEqual(len(atts), 2)
        self.assertEqual(atts[0]["disposition"], "clean")
        self.assertEqual(atts[0]["sha256"], desc0["sha256"])
        self.assertEqual(atts[0]["size_bytes"], len(data0))
        self.assertEqual(atts[0]["content_ref"], f"{notice_id}.attachments/0")
        self.assertEqual(atts[1]["content_ref"], f"{notice_id}.attachments/1")
        self.assertEqual(atts[1]["sha256"], EMPTY_SHA256)

        side_dir = notices_dir(self.cfg, "bob") / f"{notice_id}.attachments"
        self.assertEqual((side_dir / "0").read_bytes(), data0)
        self.assertEqual((side_dir / "1").read_bytes(), b"")

        notice_names = self.cfg.instances["bob"].inbox_root / "notices"
        notice_doc = read_json(sorted(notice_names.glob("notice-*.json"))[0])
        # The notice now CARRIES content_ref, in the same form as the spool
        # doc, and both resolve to the one sidecar dir under `notices/`
        # (contract.md 2, v3.0.0: "there is no second, message-specific
        # sidecar directory"). It used to be omitted here deliberately --
        # this router would not assert a grant at a path it did not
        # populate, because it published under `messages/`. Once the bytes
        # moved, the omission's reason expired and the notice became
        # self-describing alone rather than only as a pair with the spool
        # doc. Pinned on BOTH documents because the two are built together
        # in `_message_and_notice` and are deliberately not identical.
        n_atts = notice_doc["message"]["attachments"]
        self.assertEqual(n_atts[0]["disposition"], "clean")
        self.assertEqual(n_atts[0]["content_ref"], f"{notice_id}.attachments/0")
        self.assertEqual(n_atts[1]["content_ref"], f"{notice_id}.attachments/1")

        # THE GATE, ON THE DOCUMENTS THAT CARRY THE FIELD IT GATES.
        #
        # Why it is here: `amap-spec`'s `fixtures/validate.py` has
        # `_check_content_ref_index_binding` (v3.0.0) -- every descriptor's
        # `content_ref` must equal `f"{notice_id}.attachments/{i}"` for its
        # own array position. That check was in the conformance gate, the
        # gate was in this suite, and it never fired: the only
        # attachment-bearing documents this router produces are built in
        # this file, and this file never called `check_document`. Every
        # other `check_document` call in the suite passes a message or
        # notice WITHOUT attachments, so the binding check passed
        # vacuously. This router published `notice-<id>.attachments/<i>`
        # under `messages/` for a year with the gate green throughout.
        #
        # WHAT THESE TWO LINES DO NOT DO, stated because the comment that
        # stood here first claimed otherwise and mutation testing refuted
        # it. They are NOT what catches a wrong `content_ref`. Four
        # mutations, run 2026-09-20:
        #   A. `sidecar_dir_name` re-adds the `notice-` prefix -> RED, but
        #      at the local assertion above, which fires first.
        #   B. `size_bytes` dropped from the descriptor -> RED, also at a
        #      local assertion.
        #   C. bytes published under `messages/` again -> RED at the path
        #      assertions, here and in `test_peer_routing`.
        #   D. `media_type` replaced with a non-conformant token that no
        #      local assertion reads -> **GREEN**. The gate did not catch
        #      it.
        # So there is currently NO mutation these lines catch alone. They
        # are a second satisfier for A-C and silent on D, which is the
        # exact defect CLAUDE.md's "Where to assert" section is about,
        # found in the test written to fix that defect's own instance.
        #
        # They stay anyway, and the reason is prospective rather than
        # demonstrated: the binding is enforced UPSTREAM, by a validator
        # this repo does not own and whose checks grow. When `amap-spec`
        # adds one, this is the only place in the suite where a document
        # carrying `content_ref` is put in front of it. Keeping it is
        # cheap; claiming it proves something today is not honest.
        amp = load_amp_validate()
        self.assertEqual(amp.check_document("message-produced.json", message_doc), [])
        self.assertEqual(amp.check_document("notice-produced.json", notice_doc), [])
        self.assertEqual(n_atts[0]["sha256"], desc0["sha256"])

    def test_no_attachments_is_unaffected(self):
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertNotIn("attachments", result)

    def test_empty_attachments_array_equivalent_to_absent(self):
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[])
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertNotIn("attachments", result)


class TestDirShapeViolations(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def _reject(self, req_id="00000001"):
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", req_id))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "attachment_mismatch")
        self.assertEqual(list_notices(self.cfg, "bob"), [])
        return result

    def test_dir_present_but_attachments_empty_is_rejected(self):
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[])
        outbound_sidecar_dir(self.cfg, "alice", "00000001").mkdir(parents=True)
        self._reject()

    def test_descriptors_present_dir_missing_is_rejected(self):
        desc = attachment_descriptor(b"x")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        self._reject()

    def test_missing_ordinal_is_rejected(self):
        d0, d1 = attachment_descriptor(b"a"), attachment_descriptor(b"b")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0, d1])
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [b"a"])  # only "0"
        self._reject()

    def test_extra_ordinal_is_rejected(self):
        d0 = attachment_descriptor(b"a")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0])
        side = stage_outbound_sidecars(self.cfg, "alice", "00000001", [b"a"])
        (side / "1").write_bytes(b"unexpected extra ordinal")
        self._reject()

    def test_tmp_turd_counts_as_extra_entry(self):
        d0 = attachment_descriptor(b"a")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0])
        side = stage_outbound_sidecars(self.cfg, "alice", "00000001", [b"a"])
        (side / "0.tmp.stray").write_bytes(b"leftover")
        self._reject()

    def test_zero_padded_ordinal_is_not_accepted_the_isdigit_trap(self):
        """`"01".isdigit()` is True — proving the ordinal-set check uses
        STRING equality against `str(i)`, never `isdigit()`."""
        d0 = attachment_descriptor(b"a")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0])
        side = outbound_sidecar_dir(self.cfg, "alice", "00000001")
        side.mkdir(parents=True)
        (side / "01").write_bytes(b"a")  # NOT "0"
        self._reject()

    def test_non_ascii_digit_ordinal_name_is_rejected(self):
        """`"٣".isdigit()` (Arabic-Indic digit three) is also True."""
        d0 = attachment_descriptor(b"a")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0])
        side = outbound_sidecar_dir(self.cfg, "alice", "00000001")
        side.mkdir(parents=True)
        (side / "٣").write_bytes(b"a")  # ٣ — not "0"
        self._reject()

    def test_sidecar_dir_itself_symlinked_canary_untouched(self):
        canary_dir = self.tmp / "canary-outside-root"
        canary_dir.mkdir()
        (canary_dir / "canary.txt").write_text("must survive untouched")

        d0 = attachment_descriptor(b"a")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0])
        side = outbound_sidecar_dir(self.cfg, "alice", "00000001")
        os.symlink(canary_dir, side)
        self._reject()

        self.assertEqual([p.name for p in canary_dir.iterdir()], ["canary.txt"])
        self.assertEqual((canary_dir / "canary.txt").read_text(), "must survive untouched")

    def test_hardlinked_ordinal_is_rejected(self):
        secret_dir = self.tmp / "secret"
        secret_dir.mkdir()
        secret_path = secret_dir / "secret.bin"
        secret_bytes = b"a router-readable file the agent should not get republished"
        secret_path.write_bytes(secret_bytes)
        desc = attachment_descriptor(secret_bytes)

        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        side = outbound_sidecar_dir(self.cfg, "alice", "00000001")
        side.mkdir(parents=True)
        os.link(secret_path, side / "0")  # nlink now 2

        self._reject()
        # never republished into bob's namespace.
        for path in (self.cfg.instances["bob"].inbox_root).rglob("*"):
            if path.is_file():
                self.assertNotIn(secret_bytes, path.read_bytes())

    def test_fifo_ordinal_is_rejected_and_drain_does_not_hang(self):
        """FIFO defect: `os.open(..., O_NOFOLLOW, dir_fd=side_fd)` with no
        `O_NONBLOCK` blocks forever opening a FIFO with no writer — the
        `stat.S_ISREG` guard runs one line too late to ever catch it. An
        agent creates ordinal "0" as a FIFO (`os.mkfifo`, no privilege, no
        race) and the next drain wedges the single router process
        permanently — every other instance's delivery/approval/reset with
        it. Reproduced deterministically, no separate process needed. A
        SIGALRM guard makes a regression fail loudly (an assertion) instead
        of hanging the test suite/CI."""
        d0 = attachment_descriptor(b"a")
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0])
        side = outbound_sidecar_dir(self.cfg, "alice", "00000001")
        side.mkdir(parents=True)
        os.mkfifo(side / "0")  # no writer -> a blocking O_RDONLY open hangs

        if hasattr(signal, "SIGALRM"):
            def _on_alarm(signum, frame):
                raise AssertionError(
                    "drain_instance hung opening a FIFO ordinal — the "
                    "O_NONBLOCK regression guard failed"
                )
            old_handler = signal.signal(signal.SIGALRM, _on_alarm)
            signal.alarm(10)
            try:
                self._reject()
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        else:  # pragma: no cover — no SIGALRM (non-POSIX); still must not hang
            self._reject()

    def test_symlinked_ordinal_to_secret_file_is_rejected_secret_never_leaks(self):
        secret_dir = self.tmp / "secret2"
        secret_dir.mkdir()
        secret_path = secret_dir / "secret.bin"
        secret_bytes = b"another secret file, referenced via a symlinked ordinal"
        secret_path.write_bytes(secret_bytes)
        desc = attachment_descriptor(secret_bytes)

        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        side = outbound_sidecar_dir(self.cfg, "alice", "00000001")
        side.mkdir(parents=True)
        os.symlink(secret_path, side / "0")

        self._reject()
        for path in (self.cfg.instances["bob"].inbox_root).rglob("*"):
            if path.is_file():
                self.assertNotIn(secret_bytes, path.read_bytes())


class TestIntegrityMismatch(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def _reject(self):
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "attachment_mismatch")
        self.assertEqual(list_notices(self.cfg, "bob"), [])
        return result

    def test_sha_mismatch_whole_request_rejected(self):
        data = b"real content"
        desc = attachment_descriptor(data)
        desc["sha256"] = "0" * 64  # wrong
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [data])
        result = self._reject()
        self.assertEqual(result["attachments"], [
            {"index": 0, "outcome": "rejected_type", "detail": result["attachments"][0]["detail"]},
        ])

    def test_declared_size_smaller_than_actual_is_rejected(self):
        data = b"a" * 100
        desc = attachment_descriptor(data)
        desc["size_bytes"] = 10  # lies short
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [data])
        self._reject()

    def test_declared_size_larger_than_actual_is_rejected(self):
        data = b"a" * 10
        desc = attachment_descriptor(data)
        desc["size_bytes"] = 100  # lies long
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [data])
        self._reject()

    def test_one_bad_attachment_rejects_the_whole_multi_attachment_request(self):
        good = b"good bytes"
        bad = b"bad bytes"
        desc_good = attachment_descriptor(good)
        desc_bad = attachment_descriptor(bad)
        desc_bad["sha256"] = "f" * 64
        write_request(
            self.cfg, "alice", "00000001", to=["agent.bob@local"],
            attachments=[desc_good, desc_bad],
        )
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [good, bad])
        self._reject()
        # Not even the GOOD attachment shows up anywhere — no partial send.
        for path in (self.cfg.instances["bob"].inbox_root).rglob("*"):
            if path.is_file():
                self.assertNotIn(good, path.read_bytes())


class TestCaps(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def test_count_cap_holds_for_human_no_sidecar_opened(self):
        n = self.cfg.attachment_max_count + 1
        descs = [attachment_descriptor(f"x{i}".encode()) for i in range(n)]
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=descs)
        # Deliberately no sidecar dir on disk at all — proves the cap check
        # never opens it (a read attempt against a missing dir would have
        # produced `attachment_mismatch`, not `attachment_count_exceeded`).
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], "attachment_count_exceeded")
        self.assertNotIn("attachments", result)
        self.assertTrue((self.state_dir / "alice" / "held" / "req-00000001.json").is_file())

    def test_per_file_size_cap_holds_for_human_no_read(self):
        desc = attachment_descriptor(b"x")
        desc["size_bytes"] = self.cfg.attachment_max_bytes + 1
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        # No sidecar dir staged — the cap must be checked before any open.
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], "attachment_too_large")
        self.assertEqual(result["attachments"], [
            {"index": 0, "outcome": "too_large", "detail": result["attachments"][0]["detail"]},
        ])

    def test_total_size_cap_holds_for_human(self):
        per_file = (self.cfg.attachment_max_total_bytes // 2) + 1
        d0 = attachment_descriptor(b"a")
        d0["size_bytes"] = per_file
        d1 = attachment_descriptor(b"b")
        d1["size_bytes"] = per_file
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[d0, d1])
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], "attachment_too_large")

    def test_held_copy_is_json_only_never_sidecar_bytes(self):
        desc = attachment_descriptor(b"x")
        desc["size_bytes"] = self.cfg.attachment_max_bytes + 1
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        outbound.drain_instance(self.cfg, "alice")
        held_path = self.state_dir / "alice" / "held" / "req-00000001.json"
        self.assertTrue(held_path.is_file())
        held_dir = self.state_dir / "alice" / "held"
        self.assertEqual(
            sorted(p.name for p in held_dir.iterdir()), ["req-00000001.json"],
        )

    def test_caps_are_configurable(self):
        doc = {
            "state_dir": str(self.state_dir),
            "instances": {
                "alice": {"namespace": str(self.tmp / "instances" / "alice"), "peers": ["bob"]},
                "bob": {"namespace": str(self.tmp / "instances" / "bob"), "peers": ["alice"]},
            },
            "attachment_max_count": 1,
        }
        from router.config import load_obj
        (self.tmp / "instances" / "alice").mkdir(parents=True, exist_ok=True)
        (self.tmp / "instances" / "bob").mkdir(parents=True, exist_ok=True)
        cfg = load_obj(doc)
        from router.tests.helpers import _mark_seen
        _mark_seen(cfg)
        self.assertEqual(cfg.attachment_max_count, 1)

        descs = [attachment_descriptor(b"a"), attachment_descriptor(b"b")]
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"], attachments=descs)
        outbound.drain_instance(cfg, "alice")
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["reason_code"], "attachment_count_exceeded")


class TestHostileDisplayStrings(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})

    def _deliver(self, filename):
        data = b"payload"
        desc = attachment_descriptor(data, filename=filename)
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [data])
        outbound.drain_instance(self.cfg, "alice")
        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        notice_name = list_notices(self.cfg, "bob")[0]
        notice_id = notice_name[len("notice-"):-len(".json")]
        message_doc = read_json(messages_dir(self.cfg, "bob") / notice_name)
        return notice_id, message_doc

    def test_path_traversal_filename_is_inert(self):
        notice_id, message_doc = self._deliver("../../etc/passwd")
        # blob lands ONLY at the ordinal path — never anywhere the string
        # itself might suggest.
        side = notices_dir(self.cfg, "bob") / f"{notice_id}.attachments"
        self.assertEqual(sorted(p.name for p in side.iterdir()), ["0"])
        self.assertTrue((side / "0").is_file())
        # nothing was created outside the instance's own namespace.
        outside = (self.cfg.instances["bob"].root / ".." / "etc").resolve()
        self.assertFalse(outside.exists())
        self.assertEqual(message_doc["attachments"][0]["filename"], "../../etc/passwd")

    def test_absolute_path_filename_is_inert(self):
        notice_id, message_doc = self._deliver("/etc/passwd")
        side = notices_dir(self.cfg, "bob") / f"{notice_id}.attachments"
        self.assertEqual(sorted(p.name for p in side.iterdir()), ["0"])

    def test_embedded_nul_filename_is_refused_at_validation(self):
        # A control character in `filename` is a header-injection payload
        # (§3 pins `filename` to no C0 and no DEL), so the request never
        # drains at all — it is refused on shape before any delivery.
        data = b"payload"
        desc = attachment_descriptor(data, filename="evil\x00name.txt")
        write_request(
            self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc]
        )
        stage_outbound_sidecars(self.cfg, "alice", "00000001", [data])
        outbound.drain_instance(self.cfg, "alice")

        result = read_json(result_path(self.cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "malformed_request")
        self.assertEqual(list_notices(self.cfg, "bob"), [])

    def test_display_sanitizer_still_strips_nul(self):
        # Defense in depth, tested directly now that validation refuses such
        # a filename upstream: if one ever reaches the renderer by another
        # path, the sanitizer must still not emit the NUL.
        cleaned = attachments_mod._sanitize_display("evil\x00name.txt", 300, "attachment-0")
        self.assertNotIn("\x00", cleaned)
        self.assertEqual(cleaned, "evil name.txt")


# --------------------------------------------------------------------
# TOCTOU: the sidecar dir is agent-owned and writable while the router
# reads it. Modeled on `test_reset.py`'s `TestResetMailboxTOCTOU`.
# --------------------------------------------------------------------


class TestOutboundSidecarTOCTOU(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")

    def test_deterministic_swap_after_pin_never_touches_swap_target(self):
        """The sidecar dir is swapped for a symlink to a secret-bearing
        dir AFTER the router pins it (`_open_child`) but the router must
        keep operating on the ORIGINAL directory's inode — the swap
        target is never read, and the secret never reaches bob."""
        secret_dir = self.tmp / "victim-outside-root"
        secret_dir.mkdir()
        secret_bytes = b"secret bytes that must never reach bob"
        (secret_dir / "0").write_bytes(secret_bytes)

        data = b"the real attachment"
        desc = attachment_descriptor(data)
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], attachments=[desc])
        side = stage_outbound_sidecars(self.cfg, "alice", "00000001", [data])

        real_scandir = os.scandir
        swapped = {"done": False}

        def racing_scandir(fd):
            if not swapped["done"] and isinstance(fd, int):
                swapped["done"] = True
                shutil.rmtree(side, ignore_errors=True)
                os.symlink(secret_dir, side)
            return real_scandir(fd)

        with mock.patch("os.scandir", racing_scandir):
            outbound.drain_instance(self.cfg, "alice")

        self.assertTrue(swapped["done"], "the race never triggered — test isn't exercising the gap")

        # Secret bytes never reach bob's namespace, under ANY outcome.
        for path in (self.cfg.instances["bob"].inbox_root).rglob("*"):
            if path.is_file():
                self.assertNotIn(secret_bytes, path.read_bytes())
        # The swap target itself is untouched. EXISTENCE FIRST, as its own
        # assertion: with the pin's O_NOFOLLOW removed, cleanup follows the
        # planted symlink and DELETES this file, and reading it back then
        # raised FileNotFoundError — red, but as an incidental ERROR rather
        # than this test failing for the reason it states.
        self.assertTrue((secret_dir / "0").exists(),
                        "the swap target was DELETED through the planted symlink")
        self.assertEqual((secret_dir / "0").read_bytes(), secret_bytes)

    def test_live_race_separate_process_secret_never_leaks(self):
        """STRESS, NOT PROOF. A separate process swaps the sidecar dir for a
        symlink to a secret-bearing dir and back, as fast as it can, while
        this process ingests the same request repeatedly. The secret must
        never come back from an ingest.

        The proof that no interleaving leaks is
        `TestOutboundSidecarEveryInterleaving`, which places each attack
        deterministically before every filesystem call the reader makes.
        What this adds is real parallelism — a second process the scheduler
        interleaves however it likes — and it claims nothing about WHICH
        interleavings it hit.

        THE DESCRIPTOR DECLARES THE SECRET'S size and sha256. This is what
        makes "never leaks" able to fail: an agent that knows a file's hash
        (hashes travel in descriptors; bytes need not) but not its bytes can
        only get them delivered by making the router READ that file. With the
        descriptor declaring the real attachment's hash — as this test once
        did — the hash check rejects the secret whatever the pinning does,
        and this test stayed green with BOTH `O_NOFOLLOW` guards removed.

        Companions: the attacker completed swaps while ingests ran, and it
        exited cleanly. A stress test whose attacker never ran is the no-op
        form of this test."""
        secret_dir = self.tmp / "victim-live-race"
        secret_dir.mkdir()
        secret_bytes = b"live-race secret bytes"
        (secret_dir / "0").write_bytes(secret_bytes)

        data = b"the agent's own attachment bytes"
        desc = attachment_descriptor(secret_bytes)   # the attacker knows the hash
        req_id = "00000002"
        write_request(self.cfg, "alice", req_id, to=["agent.bob@local"], attachments=[desc])
        side = stage_outbound_sidecars(self.cfg, "alice", req_id, [data])

        stop = multiprocessing.Event()
        swaps = multiprocessing.Value("i", 0)
        proc = multiprocessing.Process(
            target=_attacker_swap_loop, args=(str(side), str(secret_dir), stop, swaps),
        )
        proc.start()
        leaked = False
        try:
            for _ in range(150):
                try:
                    got = _try_ingest(self.cfg, "alice", req_id, [desc])
                except attachments_mod.AttachmentIngestError:
                    continue
                if any(att.data == secret_bytes for att in got):
                    leaked = True
        finally:
            stop.set()
            proc.join(timeout=5)
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=2)
        self.assertFalse(leaked, "TOCTOU: the secret was read through the swapped path")
        self.assertEqual(proc.exitcode, 0, "the attacker process did not exit cleanly")
        self.assertGreater(swaps.value, 0, "the attacker never completed a swap — no race ran")


class TestOutboundSidecarEveryInterleaving(RouterTestCase):
    """THE PROOF that no interleaving of an agent's swap with the reader
    redirects a read — by construction, not by sampling.

    The reader's safety argument is about the gaps BETWEEN filesystem calls:
    the sidecar dir is pinned by one `O_NOFOLLOW` open, and everything after
    goes through that fd; each ordinal is opened `O_NOFOLLOW` relative to it
    and its fstat must show a regular file with `st_nlink == 1`. So this
    intercepts every `os` call the reader makes and, for each k, performs the
    attack immediately before the k-th one — every gap, once, for each of the
    three attacks an agent owning the sidecar can mount.

    The descriptor declares the SECRET's size and sha256 (see the live-race
    test for why): a leak is then exactly "ingest returned the secret", and
    the hash check cannot mask a pinning failure.

    Each attack has a CONTROL that disables the one guard it targets, in the
    real reader, and requires a leak at some k. That replaces a test-local
    naive reader, which could only show that an attacker beats a reader with
    a deliberate sleep in it — never that these gaps are the ones that
    matter, and never deterministically."""

    _INTERCEPTED = ("open", "scandir", "fstat", "read", "close", "dup")
    REQ = "00000004"

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        self.secret_dir = self.tmp / "victim-every-interleaving"
        self.secret_dir.mkdir()
        self.secret = b"bytes the agent can hash but must never get delivered"
        (self.secret_dir / "0").write_bytes(self.secret)
        self.data = b"the agent's own, different attachment"
        self.desc = attachment_descriptor(self.secret)
        write_request(self.cfg, "alice", self.REQ, to=["agent.bob@local"],
                      attachments=[self.desc])
        self.side = stage_outbound_sidecars(self.cfg, "alice", self.REQ, [self.data])
        self.parked = self.side.with_name(self.side.name + ".parked")

    # -- the three attacks, each performed with the REAL os functions --------
    #
    # Each RETURNS what it observes afterwards, via lstat/stat (neither is
    # intercepted), and that observation — not the fact that the attack was
    # called — is what counts as "fired". The first version set `fired`
    # unconditionally after calling the attack, and a mutation that made the
    # attack do nothing left every proof test green: the companion was
    # checking a flag the harness set, not the thing it stood for.

    def _swap_dir_for_symlink(self):
        os.rename(self.side, self.parked)
        os.symlink(self.secret_dir, self.side)
        return os.path.islink(self.side)

    def _swap_ordinal_for_symlink(self):
        os.unlink(self.side / "0")
        os.symlink(self.secret_dir / "0", self.side / "0")
        return os.path.islink(self.side / "0")

    def _swap_ordinal_for_hardlink(self):
        os.unlink(self.side / "0")
        os.link(self.secret_dir / "0", self.side / "0")
        return os.stat(self.side / "0").st_nlink == 2

    def _restage(self):
        """Put the agent's own sidecar back, whatever the last attack did."""
        if os.path.islink(self.side):
            os.unlink(self.side)
        if self.parked.exists():
            if self.side.exists():
                shutil.rmtree(self.side)
            os.rename(self.parked, self.side)
        target = self.side / "0"
        if os.path.lexists(target):
            os.unlink(target)
        target.write_bytes(self.data)

    def _ingest(self, attack, k, *, disable=None):
        """Ingest once, performing `attack` immediately before the k-th
        intercepted `os` call (k=0: never). Returns (result or None, fired,
        calls). `disable` names one guard to switch off, for the controls."""
        real = {n: getattr(os, n) for n in self._INTERCEPTED}
        state = {"n": 0, "fired": False}

        def wrap(name):
            def intercepted(*a, **kw):
                state["n"] += 1
                if state["n"] == k:
                    state["fired"] = attack()
                if name == "open" and disable == "ordinal-nofollow" and "dir_fd" in kw \
                        and a and a[0] == "0":
                    a = (a[0], a[1] & ~os.O_NOFOLLOW) + a[2:]
                result = real[name](*a, **kw)
                if name == "fstat" and disable == "nlink":
                    return _NlinkOne(result)
                return result
            return intercepted

        patches = [mock.patch.object(os, n, wrap(n)) for n in self._INTERCEPTED]
        if disable == "dir-nofollow":
            patches.append(mock.patch.object(
                attachments_mod, "open_child_pinned", _open_child_FOLLOWING))
        for p in patches:
            p.start()
        try:
            try:
                result = attachments_mod.ingest_attachments(
                    self.cfg, "alice", self.REQ, [self.desc])
            except attachments_mod.AttachmentIngestError:
                result = None
        finally:
            for p in patches:
                p.stop()
            self._restage()
        return result, state["fired"], state["n"]

    def _every_gap(self, attack, *, disable=None):
        """Run the attack before each call of a clean ingest. Returns the ks
        at which the secret came back. Asserts the attack fired at EVERY k —
        a k it did not fire at is a gap this proved nothing about."""
        _, fired, calls = self._ingest(attack, 0, disable=disable)
        self.assertFalse(fired)
        self.assertGreater(calls, 5, "the reader made almost no calls — interception is not attached")
        leaks = []
        for k in range(1, calls + 1):
            result, fired, _ = self._ingest(attack, k, disable=disable)
            self.assertTrue(fired, f"the attack never fired before call {k}")
            if result is not None and any(a.data == self.secret for a in result):
                leaks.append(k)
        return leaks

    # -- the positive control every "rejected" below depends on ---------------

    def test_a_sidecar_that_really_holds_the_bytes_is_accepted(self):
        """With the descriptor declaring the secret's hash, every guarded
        run below is REJECTED — which would also be true if ingest rejected
        this descriptor for some unrelated reason. It does not: a sidecar
        that genuinely contains those bytes is accepted."""
        (self.side / "0").write_bytes(self.secret)
        result = attachments_mod.ingest_attachments(self.cfg, "alice", self.REQ, [self.desc])
        self.assertEqual([a.data for a in result], [self.secret])

    # -- the proof: no gap leaks, for each attack -----------------------------

    def test_no_gap_leaks_when_the_sidecar_dir_is_swapped_for_a_symlink(self):
        self.assertEqual(self._every_gap(self._swap_dir_for_symlink), [])

    def test_no_gap_leaks_when_the_ordinal_is_swapped_for_a_symlink(self):
        self.assertEqual(self._every_gap(self._swap_ordinal_for_symlink), [])

    def test_no_gap_leaks_when_the_ordinal_is_swapped_for_a_hardlink(self):
        self.assertEqual(self._every_gap(self._swap_ordinal_for_hardlink), [])

    # -- the controls: each guard, removed from the REAL reader, is caught ----

    def test_control_without_the_dir_pin_a_gap_leaks(self):
        self.assertTrue(self._every_gap(self._swap_dir_for_symlink, disable="dir-nofollow"),
                        "the dir attack found no gap even with the pin's O_NOFOLLOW removed "
                        "— this harness cannot detect the defect it exists for")

    def test_control_without_the_ordinal_nofollow_a_gap_leaks(self):
        self.assertTrue(self._every_gap(self._swap_ordinal_for_symlink,
                                        disable="ordinal-nofollow"),
                        "the ordinal-symlink attack found no gap with O_NOFOLLOW removed")

    def test_control_without_the_nlink_check_a_gap_leaks(self):
        self.assertTrue(self._every_gap(self._swap_ordinal_for_hardlink, disable="nlink"),
                        "the hardlink attack found no gap with the nlink check blinded")


class _NlinkOne:
    """An fstat result reporting `st_nlink == 1` whatever the file has — the
    nlink guard, blinded, for its control."""

    def __init__(self, st):
        self._st = st

    def __getattr__(self, name):
        return 1 if name == "st_nlink" else getattr(self._st, name)


def _open_child_FOLLOWING(parent_fd, name):
    """`util.open_child_pinned` WITHOUT `O_NOFOLLOW` — the pin, broken, for
    its control. Deliberately the one-flag difference and nothing else."""
    try:
        return "dir", os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "other", None


def _attacker_swap_loop(side_dir: str, secret_dir: str, stop, swaps) -> None:
    """Runs in a SEPARATE process: as fast as possible, park the real sidecar
    dir, put a symlink to `secret_dir` in its place, remove the symlink, and
    put the real dir back — counting completed swaps — until `stop` is set.

    The real dir is MOVED, never destroyed. The loop this replaces
    `rmtree`d it every cycle, so the victim had to rebuild it between
    attempts while the attacker kept deleting it — racing the attacker for
    its own setup, which is the race this test was not about and the source
    of "could not stabilize". `stop` is checked only between whole cycles,
    so the real dir is always back in place when this returns."""
    parked = side_dir + ".parked"
    while not stop.is_set():
        os.rename(side_dir, parked)
        os.symlink(secret_dir, side_dir)
        os.unlink(side_dir)
        os.rename(parked, side_dir)
        with swaps.get_lock():
            swaps.value += 1


def _try_ingest(cfg, name, req_id, descriptors):
    return attachments_mod.ingest_attachments(cfg, name, req_id, descriptors)


if __name__ == "__main__":
    unittest.main()
