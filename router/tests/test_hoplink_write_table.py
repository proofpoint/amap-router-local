"""The closed exception table's `write_request` and probe rows
(`inflight.advance`, `router/hoplink.py`): a reason no retry can change
LATCHES a hold on this generation's hand-overs; everything else is retried
next poll with the same record and the same transport id; a probe failure
never settles anything."""
from __future__ import annotations

from router import hoplink, inflight
from router.fsops import UnsafeRead
from router.tests.helpers import write_request
from router.tests.test_inflight import EXT, FakeTransport, _InflightCase


class _Reasoned(Exception):
    """A plugin-defined exception: a class this router never imports."""

    def __init__(self, reason):
        super().__init__(f"plugin said {reason}")
        self.reason = reason


class _FailingPort(FakeTransport):
    def __init__(self):
        super().__init__()
        self.raise_on_write = None
        self.attempts = []
        self.raise_on_probe = None

    def write_request(self, n, data):
        self.attempts.append(n)
        if self.raise_on_write is not None:
            e, self.raise_on_write = self.raise_on_write, None
            raise e
        return super().write_request(n, data)

    def has_result(self, n):
        if self.raise_on_probe is not None:
            raise self.raise_on_probe
        return super().has_result(n)


class _Case(_InflightCase):

    def setUp(self):
        super().setUp()
        self.port = _FailingPort()
        hoplink._RUNTIME_CLASSES.clear()
        self.addCleanup(hoplink._RUNTIME_CLASSES.clear)


class LatchTests(_Case):

    def test_each_latched_reason_holds_this_generation(self):
        for reason, hold in hoplink.LATCHED_WRITE_REASONS.items():
            with self.subTest(reason=reason):
                self.setUp()
                write_request(self.cfg, "alice", "00000001", to=[EXT])
                self.port.raise_on_write = _Reasoned(reason)
                self.drain()
                got = hoplink.write_hold(self.cfg, "alice")
                self.assertIsNotNone(got, "no hold latched")
                self.assertEqual((got["reason"], got["transport_req_id"]), (hold, "00000001"))
                self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])
                self.assertFalse(self.has_result(), "a held request was answered")
                # Later polls hand nothing over in this generation, this record or another.
                write_request(self.cfg, "alice", "00000002", to=[EXT])
                self.drain()
                self.drain()
                self.assertEqual(self.port.attempts, ["00000001"], "handed over while held")

    def test_a_held_generation_still_reads_results(self):
        """The latch blocks hand-overs, not settlement: a request handed over
        before it settles from its result."""
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.assertEqual(self.port.writes, ["00000001"])
        hoplink.set_write_hold(self.cfg, "alice", "hop_request_conflict", "x", "00000009")
        self.port.send_all()
        self.drain()
        self.assertTrue(self.has_result())


class RetryTests(_Case):

    def test_every_other_reason_and_exception_retries_the_same_id(self):
        retried = [_Reasoned(r) for r in ("version", "layout", "owner", "heal_state",
                                          "protocol_violation", "marker_unreadable",
                                          "not_a_reason")]
        retried += [OSError(5, "EIO"), ValueError("bare")]
        for exc in retried:
            with self.subTest(exc=exc):
                self.setUp()
                write_request(self.cfg, "alice", "00000001", to=[EXT])
                self.port.raise_on_write = exc
                self.drain()
                self.assertIsNone(hoplink.write_hold(self.cfg, "alice"), "latched a retry")
                self.assertFalse(self.has_result())
                self.drain()
                self.assertEqual(self.port.attempts, ["00000001", "00000001"],
                                 "not retried with the same transport id")
                self.assertEqual(self.port.writes, ["00000001"])

    def test_a_runtime_unsafe_read_with_a_colliding_reason_never_latches(self):
        hoplink._RUNTIME_CLASSES.extend([(UnsafeRead, "unsafe_read")])
        e = UnsafeRead.__new__(UnsafeRead)
        Exception.__init__(e, "collides")
        e.reason = "request_exists_different"
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.port.raise_on_write = e
        self.drain()
        self.assertIsNone(hoplink.write_hold(self.cfg, "alice"))


class ProbeTests(_Case):

    def test_a_probe_failure_never_settles(self):
        write_request(self.cfg, "alice", "00000001", to=[EXT])
        self.drain()
        self.port.send_all()
        for exc in (_Reasoned("protocol_violation"), FileNotFoundError(2, "gone"),
                    OSError(5, "EIO")):
            with self.subTest(exc=exc):
                self.port.raise_on_probe = exc
                self.drain()
                self.assertFalse(self.has_result(), "a probe failure settled the request")
                self.assertEqual(inflight.list_records(self.cfg, "alice"), ["00000001"])
        self.port.raise_on_probe = None
        self.drain()
        self.assertTrue(self.has_result(), "control: it settles once the probe works")


if __name__ == "__main__":
    import unittest
    unittest.main()
