"""router/clock.py — the ONE production wall-clock read.

`now()` is the only place this package reads the wall clock. `util.utc_ts`
formats it, and every other module that needs the time of day calls one of
the two; `router/tests/test_one_clock.py` holds every other module to that,
including reflective, aliased and import-time reads.

A test, or a conformance driver, may `install` a source: a callable that
returns an aware datetime. Every read then returns the source's value, so a
fixture that runs at a fixed `now` days before real time sees no real time
anywhere in the router. `install(source, strict=True)` also makes a read with
NO source raise `ClockNotInstalled` instead of falling back, so a source lost
by anything other than `reset()` is loud.

The source is ENVIRONMENT, not process state: like the filesystem, it
survives `hoplink.reset_process_state()`, which models a restart in the
middle of a scenario. It is therefore deliberately absent from
`hoplink.PROCESS_STATE`, and only `reset()` clears it. Nothing in the router
calls `install` or `reset`; no config member, environment variable or CLI
flag reaches them.

What is NOT a clock read: a time passed in as data (a statement's `ts`, a
record's `recorded_ts`, a bound's `at`) and a file time (`st_mtime`), which the
kernel stamps. `time.monotonic` is allowed at exactly one site,
`hoplink._clock`, whose consumers are status ages and log levels only.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, List

#: [] or [source]. Environment, not process state: NOT in PROCESS_STATE.
_INSTALLED: List[Callable[[], datetime]] = []
#: [] or [True]: a read with no source raises. Kept apart from `_INSTALLED`
#: so that emptying that list alone leaves strictness on.
_STRICT: List[bool] = []


class ClockNotInstalled(RuntimeError):
    """A strict install's source is gone: no real time is substituted."""


def now() -> datetime:
    """The wall clock, as an aware UTC datetime: the installed source's
    value when one is installed, else the real time."""
    if _INSTALLED:
        t = _INSTALLED[0]()
        if not isinstance(t, datetime) or t.utcoffset() is None:
            raise TypeError(f"clock source must return an aware datetime, not {t!r}")
        return t.astimezone(timezone.utc)
    if _STRICT:
        raise ClockNotInstalled("strict clock: no source installed")
    return datetime.now(timezone.utc)


def install(source: Callable[[], datetime], *, strict: bool = False) -> None:
    """Every later `now()` returns `source()`. For tests and conformance
    drivers only."""
    if not callable(source):
        raise TypeError("clock source must be callable")
    _INSTALLED[:] = [source]
    _STRICT[:] = [True] if strict else []


def reset() -> None:
    """Back to the real clock, strictness off."""
    _INSTALLED.clear()
    _STRICT.clear()


def fixed(at: datetime) -> Callable[[], datetime]:
    """A source that always returns `at` (aware)."""
    if at.utcoffset() is None:
        raise TypeError("fixed: an aware datetime")
    return lambda: at


class Stepper:
    """A source that returns `start`, then `start + step`, … — one step per
    read. `advance(delta)` moves it without a read."""

    def __init__(self, start: datetime, step: timedelta = timedelta(seconds=1)):
        if start.utcoffset() is None:
            raise TypeError("Stepper: an aware start")
        self._next, self.step = start, step
        self.emitted: List[datetime] = []

    def __call__(self) -> datetime:
        t = self._next
        self._next = t + self.step
        self.emitted.append(t)
        return t

    def advance(self, delta: timedelta) -> None:
        self._next += delta
