"""A different request under a req_id this router already holds work for
must never be answered with that work's verdict, nor archived unsent.

`test_req_id_reuse.py` pins the case where the stored work is a SETTLED
anchor with a digest. This module pins the two branches that used to skip
the comparison:

  * IN FLIGHT. The record is settled from the transport's result, and
    settling used to publish that verdict into `outbound/results/` and
    archive whatever file now sits at `req-<id>.json`. After a connector
    reset that file is a different request, which was then reported as
    the old one's `accepted` and never sent. Now the stored work settles
    PRIVATELY (the anchor only), the live entry is held as
    `req_id_reused_pending` while the record is unsettled, and once it is
    settled the live entry gets `rejected`/`req_id_reused`.
  * DIGEST-LESS ANCHOR. An original too large to read has no digest, and
    its anchor used to resume for ANY later file under the id. Now it
    resumes only while the live entry still cannot be read for the same
    reason (still over the cap); a readable one is `req_id_reused`.

What stays a residual (README, "req_id reuse"): a byte-identical request
under a reused id IS the same request as far as anything here can tell,
and resumes. `test_req_id_reuse.test_reused_id_identical_content_still_resumes`
pins that.
"""

from __future__ import annotations

import errno
import os
import shutil
from unittest import mock

from router import inflight, outbound
from router.tests.helpers import (
    RouterTestCase, list_notices, processed_path, read_json, result_path, write_request,
)
from router.tests.test_inflight import EXT, _InflightCase
from router.util import DEFAULT_READ_CAP


def _connector_reset(cfg, name):
    """What a connector reset leaves: the agent-visible results and archive
    are gone, so its counter restarts and reuses ids."""
    outbox = cfg.instances[name].outbox_root
    for sub in ("results", "processed"):
        shutil.rmtree(outbox / sub, ignore_errors=True)


def _anchor(cfg, name, req_id="00000001"):
    path = outbound._private_result_path(cfg, name, req_id)
    if not path.is_file():
        raise AssertionError(f"no private anchor for {req_id}")
    return read_json(path)


def _published(test, cfg, name, req_id="00000001"):
    """The published result, asserted to exist first: a missing result is
    a FAILURE of the claim under test, not an error in reading it."""
    path = result_path(cfg, name, req_id)
    test.assertTrue(path.is_file(), f"no result published for {req_id}")
    return read_json(path)


class InflightReuseTests(_InflightCase):

    def _in_flight(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT], subject="original")
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])
        record = inflight.read_record(self.cfg, "alice", "00000001")
        self.assertIsNotNone(record, "the request never went in flight")
        return record

    def test_a_reused_id_is_held_while_the_record_is_unsettled(self):
        self._in_flight()
        _connector_reset(self.cfg, "alice")
        live = write_request(self.cfg, "alice", "00000001", to=["other@example.net"],
                             subject="brand new after reset")
        s = self.drain()
        self.assertEqual(s["outbound_req_id_reused_pending"], 1)
        self.assertEqual(s["outbound_inflight_waiting"], 0)
        self.assertFalse(self.has_result())
        self.assertTrue(live.is_file(), "the new request was consumed while held")

    def test_a_reused_id_never_settles_with_the_old_verdict(self):
        record = self._in_flight()
        _connector_reset(self.cfg, "alice")
        write_request(self.cfg, "alice", "00000001", to=["other@example.net"],
                      subject="brand new after reset")
        self.port.send_all()
        s = self.drain()

        r = _published(self, self.cfg, "alice")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        self.assertEqual(s["outbound_req_id_reused"], 1)
        # The old work settled PRIVATELY: its own verdict, under its own digest.
        anchor = _anchor(self.cfg, "alice")
        self.assertEqual(anchor["result"]["outcome"], "accepted")
        self.assertEqual(anchor["digest"], record["digest"])
        # The new request was never handed to the transport.
        self.assertEqual(self.port.writes, ["00000001"])
        archived = read_json(processed_path(self.cfg, "alice", "00000001"))
        self.assertEqual(archived["draft"]["subject"], "brand new after reset")
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])

    def test_an_oversized_reuse_is_refused_too(self):
        self._in_flight()
        _connector_reset(self.cfg, "alice")
        live = self.cfg.instances["alice"].outbox_root / "req-00000001.json"
        live.write_bytes(b"{" + b" " * (DEFAULT_READ_CAP + 1) + b"}")
        self.port.send_all()
        self.drain()
        r = _published(self, self.cfg, "alice")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        self.assertEqual(_anchor(self.cfg, "alice")["result"]["outcome"], "accepted")

    def test_a_hard_linked_reuse_is_refused(self):
        """A hard link at the name is refused for what it is (no errno), so
        it differs from the readable original: settled privately, then
        refused. It must not be skipped as a transient fault forever."""
        self._in_flight()
        _connector_reset(self.cfg, "alice")
        live = self.cfg.instances["alice"].outbox_root / "req-00000001.json"
        other = self.tmp / "elsewhere.json"
        other.write_bytes(live.read_bytes())
        live.unlink()
        os.link(other, live)
        self.port.send_all()
        s = self.drain()
        r = _published(self, self.cfg, "alice")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        self.assertEqual(s["outbound_errored"], 0)
        self.assertEqual(_anchor(self.cfg, "alice")["result"]["outcome"], "accepted")

    def test_a_directory_at_the_name_settles_privately(self):
        """Not a regular file: refused for what it is, so the readable
        original's verdict is kept privately and nothing is published. The
        listing never offers a non-regular entry, so no refusal follows; the
        point is that the record settles instead of stalling."""
        self._in_flight()
        _connector_reset(self.cfg, "alice")
        live = self.cfg.instances["alice"].outbox_root / "req-00000001.json"
        live.unlink()
        live.mkdir()
        self.port.send_all()
        s = self.drain()
        self.assertEqual(s["inflight_errored"], 0)
        self.assertEqual(inflight.list_records(self.cfg, "alice"), [])
        self.assertEqual(_anchor(self.cfg, "alice")["result"]["outcome"], "accepted")
        self.assertFalse(self.has_result())
        self.assertTrue(live.is_dir())

    def test_a_symlink_kind_at_the_open_is_refused(self):
        """ELOOP from the open names what the entry is: a verdict, not a
        transient fault."""
        self._in_flight()
        self.port.send_all()

        def eloop(cfg, name, filename, *a, **kw):
            raise OSError(errno.ELOOP, "a symlink at the name")
        with mock.patch.object(outbound, "_read_request_pinned", eloop):
            s = self.drain()
        r = _published(self, self.cfg, "alice")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        self.assertEqual(s["inflight_errored"], 0)
        self.assertEqual(_anchor(self.cfg, "alice")["result"]["outcome"], "accepted")

    def test_an_absent_live_entry_settles_as_before(self):
        """The control for the two above: with nothing at the name (the
        connector consumed or lost its own file) the verdict is published."""
        self._in_flight()
        (self.cfg.instances["alice"].outbox_root / "req-00000001.json").unlink()
        self.port.send_all()
        self.drain()
        r = _published(self, self.cfg, "alice")
        self.assertEqual((r["outcome"], r["reason_code"]), ("accepted", "allowlisted"))

    def test_the_unchanged_live_entry_settles_as_before(self):
        self._in_flight()
        self.port.send_all()
        s = self.drain()
        self.assertEqual(_published(self, self.cfg, "alice")["outcome"], "accepted")
        self.assertEqual(s["outbound_req_id_reused"], 0)

    def test_a_transient_read_fault_at_settle_decides_nothing(self):
        self._in_flight()
        self.port.send_all()
        real = outbound._read_request_pinned

        def eio(cfg, name, filename, *a, **kw):
            raise OSError(errno.EIO, "EIO reading the live entry")
        with mock.patch.object(outbound, "_read_request_pinned", eio):
            s = self.drain()
        self.assertFalse(self.has_result())
        self.assertFalse(outbound._private_result_path(self.cfg, "alice", "00000001").exists())
        self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])
        self.assertEqual(s["inflight_errored"], 1)
        self.assertIs(outbound._read_request_pinned, real)
        self.drain()
        self.assertEqual(_published(self, self.cfg, "alice")["outcome"], "accepted")


class DigestlessAnchorReuseTests(RouterTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        self.live = self.cfg.instances["alice"].outbox_root / "req-00000001.json"

    def _oversized(self, fill=b" "):
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"])
        self.live.write_bytes(b"{" + fill * (DEFAULT_READ_CAP + 1) + b"}")

    def _settle_oversized(self):
        self._oversized()
        outbound.drain_instance(self.cfg, "alice")
        anchor = _anchor(self.cfg, "alice")
        self.assertIsNone(anchor["digest"], "precondition: an anchor with no digest")
        self.assertEqual(anchor["result"]["reason_code"], "malformed_request")
        _connector_reset(self.cfg, "alice")

    def test_a_readable_request_under_a_digestless_anchor_is_refused(self):
        self._settle_oversized()
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], body_text="new")
        s = outbound.drain_instance(self.cfg, "alice")
        r = _published(self, self.cfg, "alice")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        self.assertEqual((s["outbound_req_id_reused"], s["outbound_resumed"]), (1, 0))
        self.assertEqual(list_notices(self.cfg, "bob"), [])
        self.assertIsNone(_anchor(self.cfg, "alice")["digest"], "the anchor was rewritten")

    def test_a_still_oversized_request_resumes(self):
        self._settle_oversized()
        self._oversized(fill=b"\t")
        s = outbound.drain_instance(self.cfg, "alice")
        r = _published(self, self.cfg, "alice")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "malformed_request"))
        self.assertEqual((s["outbound_req_id_reused"], s["outbound_resumed"]), (0, 1))

    def test_a_transient_fault_under_a_digestless_anchor_decides_nothing(self):
        self._settle_oversized()
        write_request(self.cfg, "alice", "00000001", to=["agent.bob@local"], body_text="new")

        def eio(cfg, name, filename, *a, **kw):
            raise OSError(errno.EIO, "EIO reading the live entry")
        with mock.patch.object(outbound, "_read_request_pinned", eio):
            s = outbound.drain_instance(self.cfg, "alice")
        self.assertEqual((s["outbound_req_id_reused"], s["outbound_resumed"],
                          s["outbound_errored"]), (0, 0, 1))
        self.assertFalse(result_path(self.cfg, "alice", "00000001").exists())
        self.assertTrue(self.live.is_file())
        s = outbound.drain_instance(self.cfg, "alice")
        self.assertEqual(s["outbound_req_id_reused"], 1)

    def test_a_hard_link_under_a_digestless_anchor_resumes(self):
        """Still unreadable for what it is (a hard link), so the stored
        refusal resumes; it is never skipped as a transient fault. (A
        directory or FIFO at the name is never listed, so this path sees
        only regular files and hard links.)"""
        self._settle_oversized()
        other = self.tmp / "elsewhere.json"
        other.write_bytes(b"{}")
        os.link(other, self.live)
        s = outbound.drain_instance(self.cfg, "alice")
        self.assertEqual((s["outbound_resumed"], s["outbound_req_id_reused"],
                          s["outbound_errored"]), (1, 0, 0))
        r = _published(self, self.cfg, "alice")
        self.assertEqual(r["reason_code"], "malformed_request")
