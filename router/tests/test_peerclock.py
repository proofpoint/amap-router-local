"""The receiver's clock for signed peer candidates (`router/peerclock.py`):
the window, H, the floor, admission, window changes, store-loss recovery
and the operator's bound B.

The fixture-shaped rows cite the peer-origin profile's sequence cases at
amap-spec main f775266 (public): `seq-clock-rollback`,
`seq-store-loss-rollback-larger-f`, `seq-store-loss-at-equality`,
`seq-store-loss-after-rollback` and `seq-store-loss-h-lost`."""
import json
import unittest
from datetime import datetime, timedelta, timezone

from router import peerclock
from router.tests import helpers

T0 = datetime(2026, 10, 9, 15, 0, 0, tzinfo=timezone.utc)


def at(h, m, s=0):
    return T0.replace(hour=h, minute=m, second=s)


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class _Clock(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def init(self, now, **kw):
        c = peerclock.initial(now, **kw)
        peerclock.write(self.state_dir, c, previous=None)
        return c

    def accepts(self, now, statement_ts):
        clock = peerclock.read(self.state_dir)
        return peerclock.check7(clock, now)({"ts": ts(statement_ts)}, "k") is None


class WindowTests(_Clock):

    def test_both_bounds_are_inclusive(self):
        self.init(at(16, 0))
        clock = peerclock.advance(self.state_dir, at(16, 0))
        self.assertTrue(self.accepts(at(16, 0), at(15, 0)))                  # H - P exactly
        self.assertFalse(self.accepts(at(16, 0), at(14, 59, 59)))
        self.assertTrue(self.accepts(at(16, 0), at(16, 5)))                  # now + F exactly
        self.assertFalse(self.accepts(at(16, 0), at(16, 5, 1)))
        self.assertEqual(clock.p, 3600)

    def test_a_clock_stepped_back_demotes_and_never_holds(self):
        """seq-clock-rollback: placed at 15:10; H reaches 16:05; the clock
        steps back to 15:50 and the replay arrives. The lower bound uses H,
        so the replay is outside the window: ts_window, never a hold."""
        self.init(at(15, 10))
        peerclock.advance(self.state_dir, at(16, 5))
        clock = peerclock.advance(self.state_dir, at(15, 50))
        self.assertEqual(clock.H, at(16, 5), "H is never lowered")
        try:
            got = peerclock.check7(clock, at(15, 50))({"ts": ts(at(15, 0))}, "k")
        except peerclock.Held:
            self.fail("a stepped-back clock with H intact must not hold")
        self.assertEqual(got, peerclock.TS_WINDOW)
        self.assertTrue(peerclock.behind_h(clock, at(15, 50)))

    def test_closed_admission_holds(self):
        clock = self.init(at(16, 0))
        closed = peerclock.close(self.state_dir, clock, "test")
        with self.assertRaises(peerclock.Held):
            peerclock.check7(closed, at(16, 0))({"ts": ts(at(16, 0))}, "k")


class WindowChangeTests(_Clock):

    def test_widening_p_sets_the_floor_and_never_readmits(self):
        self.init(at(16, 0))
        peerclock.advance(self.state_dir, at(16, 0))
        clock = peerclock.change_window(self.state_dir, at(16, 0), p=7200, f=300)
        self.assertEqual(clock.floor, at(15, 0))
        self.assertFalse(self.accepts(at(16, 0), at(14, 30)))

    def test_every_f_joins_the_history(self):
        self.init(at(16, 0), f=900)
        clock = peerclock.change_window(self.state_dir, at(16, 0), p=3600, f=300)
        self.assertEqual(clock.fmax, 900)


class StoreLossTests(_Clock):

    def test_the_floor_is_strictly_above_max_c_h_plus_fmax(self):
        """seq-store-loss-at-equality / -after-rollback: floor = max(C, H) +
        Fmax + 1 s, never inclusive."""
        self.init(at(15, 0))
        peerclock.advance(self.state_dir, at(15, 30))
        clock = peerclock.raise_floor_for_loss(self.state_dir, at(15, 20))
        self.assertEqual(clock.floor, at(15, 30) + timedelta(seconds=301))

    def test_fmax_is_the_largest_f_ever_in_force(self):
        """seq-store-loss-rollback-larger-f: F was 900 near H, then 300;
        Fmax stays 900."""
        self.init(at(15, 0), f=900)
        peerclock.change_window(self.state_dir, at(15, 0), p=3600, f=300)
        clock = peerclock.raise_floor_for_loss(self.state_dir, at(15, 0))
        self.assertEqual(clock.floor, at(15, 0) + timedelta(seconds=901))

    def test_the_floor_is_never_lowered(self):
        self.init(at(15, 0))
        first = peerclock.raise_floor_for_loss(self.state_dir, at(16, 0))
        second = peerclock.raise_floor_for_loss(self.state_dir, at(15, 30))
        self.assertGreaterEqual(second.floor, first.floor)
        with self.assertRaises(ValueError):
            peerclock.write(self.state_dir, peerclock.Clock(**{**second.__dict__,
                                                               "floor": at(15, 0)}),
                            previous=second)

    def test_a_malformed_bound_makes_the_clock_untrusted(self):
        clock = peerclock.record_bound(self.state_dir, at(17, 0), at=at(16, 0),
                                       evidence="hub log line 4411", not_from_wall_clock=False,
                                       observed=())
        good = json.loads(peerclock.path(self.state_dir).read_text())
        self.assertEqual(peerclock.read(self.state_dir).bound_b, clock.bound_b)
        b = good["bound_b"]
        bad = [1, "x", [], {}, dict(b, extra=1), {k: v for k, v in b.items() if k != "by"},
               dict(b, B="yesterday"), dict(b, recorded_at=None), dict(b, evidence=" "),
               dict(b, by=""), dict(b, not_from_wall_clock="no"), dict(b, not_from_wall_clock=0)]
        for value in bad:
            with self.subTest(bound_b=value):
                peerclock.path(self.state_dir).write_text(json.dumps(dict(good, bound_b=value)))
                with self.assertRaises(peerclock.ClockUntrusted):
                    peerclock.read(self.state_dir)

    def test_an_absent_clock_is_untrusted(self):
        with self.assertRaises(peerclock.ClockUntrusted):
            peerclock.read(self.state_dir)


class BoundTests(_Clock):

    def bound(self, now, at_, evidence="hub log 2026-10-09 line 4411", flag=False, seen=()):
        return peerclock.record_bound(self.state_dir, now, at=at_, evidence=evidence,
                                      not_from_wall_clock=flag, observed=seen)

    def test_a_bound_reopens_with_the_floor_above_it(self):
        """seq-store-loss-h-lost: H is lost; the operator records B; floor =
        B + Fmax + 1 s; H := max(B, now); admission opens."""
        clock = self.bound(at(17, 0), at(16, 0), seen=[(at(15, 55), "audit ts")])
        self.assertEqual(clock.admission, "open")
        self.assertEqual(clock.floor, at(16, 0) + timedelta(seconds=901))
        self.assertEqual(clock.H, at(17, 0))
        self.assertTrue(clock.bound_b["by"].startswith("uid="))

    def test_a_bound_below_an_observed_time_is_refused_naming_it(self):
        with self.assertRaises(peerclock.BoundRefused) as cm:
            self.bound(at(17, 0), at(15, 0), seen=[(at(15, 55), "candidate first_seen_ts x")])
        self.assertIn("candidate first_seen_ts x", str(cm.exception))

    def test_evidence_is_required_and_never_now(self):
        for ev in ("", "  ", "now", "NOW", "current time"):
            with self.subTest(evidence=ev):
                with self.assertRaises(peerclock.BoundRefused):
                    self.bound(at(17, 0), at(16, 0), evidence=ev)

    def test_a_bound_near_wall_clock_needs_the_flag(self):
        with self.assertRaises(peerclock.BoundRefused):
            self.bound(at(17, 0), at(16, 59, 30))
        clock = self.bound(at(17, 0), at(16, 59, 30), flag=True)
        self.assertTrue(clock.bound_b["not_from_wall_clock"])

    def test_a_future_bound_needs_the_flag(self):
        with self.assertRaises(peerclock.BoundRefused) as cm:
            self.bound(at(17, 0), at(19, 0))
        self.assertIn("in the future", str(cm.exception))
        self.assertEqual(self.bound(at(17, 0), at(19, 0), flag=True).H, at(19, 0))

    def test_the_floor_is_by_max_never_refusal(self):
        self.init(at(15, 0))
        high = peerclock.raise_floor_for_loss(self.state_dir, at(18, 0))
        clock = self.bound(at(18, 0), at(16, 0))
        self.assertEqual(clock.floor, high.floor)


if __name__ == "__main__":
    unittest.main()
