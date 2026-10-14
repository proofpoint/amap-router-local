"""`router.clock`: the one production wall-clock read and its test-only
source. What a read returns with and without a source, strictness, and the
lifecycle rule: an installed source survives `hoplink.reset_process_state`
(the clock is environment, like the filesystem) and only `clock.reset()`
clears it."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from router import clock, hoplink, util
from router.tests.helpers import ClockMixin

T0 = datetime(2001, 2, 3, 4, 5, 6, tzinfo=timezone.utc)


class ReadTests(ClockMixin, unittest.TestCase):

    def tearDown(self):
        clock.reset()

    def test_no_source_reads_the_real_clock(self):
        before = datetime.now(timezone.utc)
        got = clock.now()
        after = datetime.now(timezone.utc)
        self.assertIsNotNone(got.utcoffset())
        self.assertTrue(before <= got <= after, (before, got, after))

    def test_an_installed_source_is_what_every_read_returns(self):
        # Not strict: a read that ignored the source would return real time
        # and fail the assertion, rather than raise.
        self.install_clock(clock.fixed(T0), strict=False)
        self.assertEqual(clock.now(), T0)
        self.assertEqual(clock.now(), T0)
        self.assertEqual(util.utc_ts(), "2001-02-03T04:05:06Z")

    def test_another_zone_comes_back_as_utc(self):
        self.install_clock(clock.fixed(T0.astimezone(timezone(timedelta(hours=5)))))
        got = clock.now()
        self.assertEqual(got, T0)
        self.assertEqual(got.utcoffset(), timedelta(0))

    def test_a_stepper_advances_one_step_per_read(self):
        s = self.install_clock(clock.Stepper(T0, timedelta(seconds=2)))
        self.assertEqual([clock.now(), clock.now()], [T0, T0 + timedelta(seconds=2)])
        s.advance(timedelta(hours=1))
        self.assertEqual(clock.now(), T0 + timedelta(hours=1, seconds=4))
        self.assertEqual(len(s.emitted), 3)

    def test_a_naive_source_is_refused(self):
        self.install_clock(lambda: datetime(2001, 2, 3))
        with self.assertRaises(TypeError):
            clock.now()

    def test_a_non_datetime_source_is_refused(self):
        self.install_clock(lambda: "2001-02-03T04:05:06Z")
        with self.assertRaises(TypeError):
            clock.now()

    def test_install_needs_a_callable_and_helpers_need_aware_times(self):
        with self.assertRaises(TypeError):
            clock.install(T0)
        with self.assertRaises(TypeError):
            clock.fixed(datetime(2001, 2, 3))
        with self.assertRaises(TypeError):
            clock.Stepper(datetime(2001, 2, 3))


class StrictTests(unittest.TestCase):

    def tearDown(self):
        clock.reset()

    def test_strict_raises_when_the_source_is_lost_other_than_by_reset(self):
        clock.install(clock.fixed(T0), strict=True)
        clock._INSTALLED.clear()
        with self.assertRaises(clock.ClockNotInstalled):
            clock.now()

    def test_not_strict_falls_back_to_the_real_clock(self):
        clock.install(clock.fixed(T0))
        clock._INSTALLED.clear()
        self.assertNotEqual(clock.now(), T0)

    def test_reset_clears_the_source_and_strictness(self):
        clock.install(clock.fixed(T0), strict=True)
        clock.reset()
        self.assertEqual(clock._INSTALLED, [])
        self.assertEqual(clock._STRICT, [])
        self.assertNotEqual(clock.now(), T0)


class LifecycleTests(unittest.TestCase):
    """The clock is environment: a modelled restart keeps it."""

    def tearDown(self):
        clock.reset()

    def test_the_source_survives_reset_process_state(self):
        s = clock.Stepper(T0)
        clock.install(s, strict=True)
        hoplink.reset_process_state()
        try:
            got = clock.now()
        except clock.ClockNotInstalled:     # dropped: a FAILURE, not an error
            got = None
        self.assertEqual(got, T0)
        self.assertEqual(s.emitted, [T0])

    def test_reset_is_what_clears_it(self):
        clock.install(clock.fixed(T0), strict=True)
        hoplink.reset_process_state()
        clock.reset()
        self.assertNotEqual(clock.now(), T0)


class MixinTests(ClockMixin, unittest.TestCase):

    def test_the_mixin_installs_strict_and_registers_the_reset(self):
        self.install_clock(clock.fixed(T0))
        self.assertEqual(clock._STRICT, [True])
        self.doCleanups()
        self.assertEqual(clock._INSTALLED, [])
        self.assertEqual(clock._STRICT, [])


if __name__ == "__main__":
    unittest.main()
