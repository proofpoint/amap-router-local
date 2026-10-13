"""The transport probes in the closed table (`inflight.advance`, PROBES):
under the hop, any exception from `has_result`, `has_pending`,
`has_archived` or `read_result` is a RETRY that never settles. The record,
its transport id and its HANDED marker are kept, no Result is written,
status names `hop_probe_failed:<reason or class>`, and the next poll
settles from the real result. Driven through the real drain under a
registry."""
from __future__ import annotations

from router import hoplink, inflight
from router.fsops import UnsafeRead
from router.tests.helpers import result_path, write_request
from router.tests.test_hoplink_senders import EXTERNAL
from router.tests.test_hoplink_status import FailingPlugin, _Status
from router.tests.test_hoplink_write_table import _FailingPort, _Reasoned


class ProbePort(_FailingPort):
    """`raises[method]` is raised by that probe, once per call, while set."""

    def __init__(self):
        super().__init__()
        self.raises = {}

    def _maybe(self, method):
        e = self.raises.get(method)
        if e is not None:
            raise e

    def has_result(self, n):
        self._maybe("has_result")
        return super().has_result(n)

    def has_pending(self, n):
        self._maybe("has_pending")
        return super().has_pending(n)

    def has_archived(self, n):
        self._maybe("has_archived")
        return super().has_archived(n)

    def read_result(self, n):
        self._maybe("read_result")
        return super().read_result(n)


class ProbePlugin(FailingPlugin):
    def make_sender(self, settings, fsops):
        self.calls.append(dict(settings))
        port = ProbePort()
        self.ports.append(port)
        return port


def _unsafe(reason):
    e = UnsafeRead.__new__(UnsafeRead)
    Exception.__init__(e, reason)
    e.reason = reason
    return e


class ProbeRetryTests(_Status):

    def setUp(self):
        super().setUp()
        self.plugin = ProbePlugin()
        self.rt = type(self.rt)(plugin=self.plugin, fsops=None, hop=self.cfg.hop)
        hoplink._RUNTIME_CLASSES[:] = [(UnsafeRead, "unsafe_read")]
        self.addCleanup(hoplink._RUNTIME_CLASSES.clear)

    def handed(self):
        write_request(self.cfg, "alpha", "00000001", to=[EXTERNAL])
        self.drain()
        port = self.plugin.ports[0]
        self.assertEqual(port.writes, ["00000001"])
        return port

    def test_each_probe_raising_settles_nothing_then_the_real_result_settles(self):
        cases = [
            # (the probe, what it raises, what the downstream side shows, the status)
            ("has_result", _Reasoned("protocol_violation"), "sent",
             "hop_probe_failed:protocol_violation"),
            ("has_pending", OSError(5, "EIO"), "pending", "hop_probe_failed:OSError"),
            ("has_archived", _unsafe("link_count"), "pending_gone", "hop_probe_failed:link_count"),
            ("read_result", FileNotFoundError(2, "after has_result"), "sent",
             "hop_probe_failed:FileNotFoundError"),
        ]
        for method, exc, shows, status in cases:
            with self.subTest(probe=method):
                self.tearDown()
                self.setUp()
                port = self.handed()
                if shows == "sent":
                    port.send_all()
                elif shows == "pending_gone":
                    port.archived.update(port.pending)
                    port.pending.clear()
                port.raises[method] = exc
                k, _ = self.drain()
                self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                                 "a probe failure settled the request")
                self.assertEqual(inflight.list_records(k, "alpha"), ["00000001"])
                self.assertTrue(inflight.handed_path(k, "alpha", "00000001").is_file())
                retry = self.section(k)["instances"]["alpha"]["retry"]
                self.assertEqual((retry["status"], retry["transport_req_id"]),
                                 (status, "00000001"))
                port.raises.clear()
                if shows == "pending":
                    port.send_all()               # the downstream side answers now
                elif shows == "pending_gone":
                    port.archived.pop("00000001")
                    port.pending["00000001"] = b"{}"
                    port.send("00000001")
                k, _ = self.drain()
                self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(),
                                "control: the next poll settles from the real result")
                self.assertNotIn("retry", self.section(k)["instances"].get("alpha", {}),
                                 "the probe failure outlived its recovery")

    def test_a_result_that_reads_but_fails_validation_is_still_a_verdict(self):
        port = self.handed()
        port.send("00000001", raw=b"not json")
        self.drain()
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists())
