"""router/peerclock.py — the receiver's clock for signed peer candidates.

THE WINDOW (the peer-origin profile, "the replay store, windows and
recovery"): a statement's `ts` is accepted when

    lower <= ts <= now + F,   lower = max(H - P, floor)

both bounds inclusive. H is the latest receiver time this router has ever
observed, kept durably and only ever raised (H := max(H, now)); a clock that
steps back below H never re-admits a pruned statement, because the lower
bound uses H. `floor` is set only by recovery and by window changes, and is
never lowered.

ADMISSION is `open` or `closed`. It is CLOSED when no trustworthy bound
exists: a first start that was not initialised, a lost or untrusted clock, a
restore the operator declared. While closed, check 7 cannot define a window
and HOLDS (`Held`): nothing is placed or demoted. It reopens only through
`peer-store init --never-admitted` (a fresh store) or `peer-bound` (an
operator-recorded bound B with evidence), each of which persists the floor
BEFORE admission opens.

A clock that is merely BEHIND H (H - now > F) is not a hold: the window is
defined, and a statement outside it is demoted, as the profile's clock-
rollback case requires. Status shows a `clock_behind_h` warning.

THE FILE, `state_dir/peer-clock.json`, closed, written by durable replace
under the drain lock (one writer):

    {"v": 1, "H": <ts>, "floor": <ts|null>, "admission": "open"|"closed",
     "p": int, "f": int, "f_history": [int, ...], "store_token": <hex>,
     "bound_b": null | {"B", "evidence", "recorded_at", "by", "not_from_wall_clock"},
     "store": null | {...}}

`store` is the candidate journal's bookkeeping (`peerjournal`), kept IN
this file so the clock and the counts that prove the stores complete can
only be rolled back together: an older clock restored alone disagrees with
the live stores and is detected. This module preserves `store` on every
write and never interprets it.

`f_history` holds every F ever in force, never shrinking, so Fmax is
provable (its maximum; 900, the profile's ceiling, when it is absent).
"""
from __future__ import annotations

import json
import os
import pwd
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from .util import atomic_write, format_utc_ts, parse_utc_ts

CLOCK_FILE = "peer-clock.json"
#: The profile's bounds: P in [300, 86400], F at most 900.
P_MIN, P_MAX, F_MAX_PROFILE = 300, 86400, 900
#: This fleet's values.
P_DEFAULT, F_DEFAULT = 3600, 300
TS_WINDOW = "ts_window"
#: A bound B this close to wall time needs an explicit operator flag.
NEAR_WALL_CLOCK_S = 60
_REFUSED_EVIDENCE = re.compile(r"\s*(now|current[ _-]?time|the current time)\s*\Z", re.I)
_MEMBERS = ("v", "H", "floor", "admission", "p", "f", "f_history", "store_token", "bound_b",
            "store")


class Held(Exception):
    """Check 7 cannot define a window: admission is closed."""


class ClockUntrusted(Exception):
    """The clock file is missing, unreadable, or not a closed clock record."""


class BoundRefused(ValueError):
    """`record_bound` refused the operator's bound B; nothing was written."""


@dataclass(frozen=True)
class Clock:
    H: datetime
    floor: Optional[datetime]
    admission: str
    p: int
    f: int
    f_history: Tuple[int, ...]
    store_token: str
    bound_b: Optional[Mapping[str, Any]]

    @property
    def fmax(self) -> int:
        """The largest F that could have governed an acceptance (900 when
        the history is empty)."""
        return max(self.f_history) if self.f_history else F_MAX_PROFILE

    def lower(self) -> datetime:
        lower = self.H - timedelta(seconds=self.p)
        return max(lower, self.floor) if self.floor is not None else lower

    def to_doc(self) -> Dict[str, Any]:
        return {"v": 1, "H": format_utc_ts(self.H),
                "floor": format_utc_ts(self.floor) if self.floor else None,
                "admission": self.admission, "p": self.p, "f": self.f,
                "f_history": list(self.f_history), "store_token": self.store_token,
                "bound_b": dict(self.bound_b) if self.bound_b else None}


def path(state_dir: Path) -> Path:
    return Path(state_dir) / CLOCK_FILE


def _parse(raw: bytes) -> Clock:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ClockUntrusted(f"not JSON: {e}") from None
    if not isinstance(doc, dict) or set(doc) != set(_MEMBERS) or doc["v"] != 1:
        raise ClockUntrusted("not a closed clock record")
    H = parse_utc_ts(doc["H"])
    floor = parse_utc_ts(doc["floor"]) if doc["floor"] is not None else None
    if H is None or (doc["floor"] is not None and floor is None):
        raise ClockUntrusted("H or floor is not a UTC timestamp")
    if doc["admission"] not in ("open", "closed"):
        raise ClockUntrusted("admission is neither open nor closed")
    p, f, hist = doc["p"], doc["f"], doc["f_history"]
    if not (type(p) is int and P_MIN <= p <= P_MAX and type(f) is int and 0 <= f <= F_MAX_PROFILE):
        raise ClockUntrusted("p or f out of the profile's bounds")
    if not (isinstance(hist, list) and all(type(x) is int and 0 <= x <= F_MAX_PROFILE
                                           for x in hist) and f in hist):
        raise ClockUntrusted("f_history is not the F values in force")
    if doc["store"] is not None and not isinstance(doc["store"], dict):
        raise ClockUntrusted("store is neither null nor an object")
    token = doc["store_token"]
    if not (isinstance(token, str) and re.fullmatch(r"[0-9a-f]{64}", token)):
        raise ClockUntrusted("store_token is not 64 lower hex")
    return Clock(H=H, floor=floor, admission=doc["admission"], p=p, f=f,
                 f_history=tuple(hist), store_token=token, bound_b=doc["bound_b"])


def read(state_dir: Path) -> Clock:
    """The clock, or `ClockUntrusted` (absent included)."""
    try:
        raw = path(state_dir).read_bytes()
    except FileNotFoundError:
        raise ClockUntrusted("absent") from None
    except OSError as e:
        raise ClockUntrusted(f"unreadable: {e.strerror}") from None
    return _parse(raw)


def write(state_dir: Path, clock: Clock, *, previous: Optional[Clock]) -> None:
    """Persist `clock` durably. Refuses to lower H or the floor relative to
    `previous` (the only legal changes raise them)."""
    if previous is not None:
        if clock.H < previous.H:
            raise ValueError("H is never lowered")
        if previous.floor is not None and (clock.floor is None or clock.floor < previous.floor):
            raise ValueError("the floor is never lowered")
        if not set(previous.f_history) <= set(clock.f_history):
            raise ValueError("f_history never shrinks")
    write_doc(state_dir, dict(clock.to_doc(), store=_store_member(state_dir)))


def _store_member(state_dir: Path) -> Optional[Dict[str, Any]]:
    """The `store` member as it is on disk now, or None."""
    try:
        doc = json.loads(path(state_dir).read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    store = doc.get("store") if isinstance(doc, dict) else None
    return store if isinstance(store, dict) else None


def read_doc(state_dir: Path) -> Dict[str, Any]:
    """The whole file, the clock verified (`ClockUntrusted`)."""
    read(state_dir)
    return json.loads(path(state_dir).read_bytes().decode("utf-8"))


def write_doc(state_dir: Path, doc: Mapping[str, Any]) -> None:
    """Persist the whole file durably (one writer, under the drain lock)."""
    atomic_write(path(state_dir), json.dumps(dict(doc), sort_keys=True).encode("utf-8"),
                 durable_root=Path(state_dir))


def initial(now: datetime, *, p: int = P_DEFAULT, f: int = F_DEFAULT) -> Clock:
    """A fresh clock for `peer-store init --never-admitted`: open, no floor."""
    return Clock(H=now, floor=None, admission="open", p=p, f=f, f_history=(f,),
                 store_token=secrets.token_hex(32), bound_b=None)


def advance(state_dir: Path, now: datetime) -> Clock:
    """H := max(H, now), persisted BEFORE anything relies on it. Returns the
    clock in force for this poll."""
    clock = read(state_dir)
    if now > clock.H:
        new = Clock(**{**clock.__dict__, "H": now})
        write(state_dir, new, previous=clock)
        return new
    return clock


def behind_h(clock: Clock, now: datetime) -> bool:
    """The status warning: the wall clock is more than F behind H."""
    return (clock.H - now).total_seconds() > clock.f


def check7(clock: Clock, now: datetime) -> Callable[[Mapping[str, Any], str], Optional[str]]:
    """The `check7` callable `peerbind.bind` requires, for one poll."""
    def check(payload: Mapping[str, Any], _key_id: str) -> Optional[str]:
        if clock.admission != "open":
            raise Held("peer admission is closed")
        ts = parse_utc_ts(payload.get("ts"))
        if ts is None:
            return TS_WINDOW
        upper = now + timedelta(seconds=clock.f)
        return None if clock.lower() <= ts <= upper else TS_WINDOW
    return check


def change_window(state_dir: Path, now: datetime, *, p: int, f: int) -> Clock:
    """A configured P/F change: narrowing takes effect at once; widening P
    sets the floor to the lower bound in force at the change; every F ever
    in force joins `f_history`."""
    clock = read(state_dir)
    if not (P_MIN <= p <= P_MAX and 0 <= f <= F_MAX_PROFILE):
        raise ValueError("p or f outside the profile's bounds")
    floor = clock.floor
    if p > clock.p:
        in_force = clock.lower()
        floor = max(floor, in_force) if floor is not None else in_force
    hist = tuple(sorted(set(clock.f_history) | {f}))
    new = Clock(**{**clock.__dict__, "p": p, "f": f, "floor": floor, "f_history": hist})
    write(state_dir, new, previous=clock)
    return new


def raise_floor_for_loss(state_dir: Path, now: datetime) -> Clock:
    """The store cannot be shown complete and H is intact: floor =
    max(existing, max(C, H) + Fmax + 1 s), C = now. Admission stays as it
    is."""
    clock = read(state_dir)
    bound = max(now, clock.H) + timedelta(seconds=clock.fmax + 1)
    floor = max(clock.floor, bound) if clock.floor is not None else bound
    new = Clock(**{**clock.__dict__, "floor": floor})
    write(state_dir, new, previous=clock)
    return new


def close(state_dir: Path, clock: Clock, why: str) -> Clock:
    """Admission CLOSED (persisted)."""
    new = Clock(**{**clock.__dict__, "admission": "closed"})
    write(state_dir, new, previous=clock)
    return new


def operator_by() -> str:
    """The router's own record of who acted: uid and user name."""
    uid = os.geteuid()
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = "?"
    return f"uid={uid}({name})"


def record_bound(state_dir: Path, now: datetime, *, at: datetime, evidence: str,
                 not_from_wall_clock: bool, observed: Iterable[Tuple[datetime, str]]) -> Clock:
    """The operator's bound B after a lost H. `observed` is every receiver
    time this router can see, each with its source; B below the largest is
    refused, naming it. Evidence is required and recorded verbatim; "now"
    is refused; a B within 60 s of wall time needs `not_from_wall_clock`.
    floor := max(floor, B + Fmax + 1), H := max(B, now), then admission
    opens, persisted in one write."""
    if not (isinstance(evidence, str) and evidence.strip()):
        raise BoundRefused("evidence is required")
    if _REFUSED_EVIDENCE.fullmatch(evidence):
        raise BoundRefused("current wall time is never evidence for B")
    seen = sorted(observed, key=lambda x: x[0])
    if seen and at < seen[-1][0]:
        raise BoundRefused(f"B {format_utc_ts(at)} is below the largest receiver time RL can "
                           f"see, {format_utc_ts(seen[-1][0])} from {seen[-1][1]}")
    if abs((now - at).total_seconds()) <= NEAR_WALL_CLOCK_S and not not_from_wall_clock:
        raise BoundRefused("B is within 60 s of wall time: pass --b-not-from-wall-clock if B "
                           "was not derived from the clock")
    try:
        clock = read(state_dir)
        previous: Optional[Clock] = clock
    except ClockUntrusted:
        # The F history was lost with the clock, so nothing proves a smaller
        # Fmax than the profile's ceiling: record it, and Fmax is 900.
        clock, previous = initial(now), None
        clock = Clock(**{**clock.__dict__, "admission": "closed", "H": at,
                         "f_history": tuple(sorted({clock.f, F_MAX_PROFILE}))})
    fmax = clock.fmax
    bound = at + timedelta(seconds=fmax + 1)
    floor = max(clock.floor, bound) if clock.floor is not None else bound
    record = {"B": format_utc_ts(at), "evidence": evidence, "recorded_at": format_utc_ts(now),
              "by": operator_by(), "not_from_wall_clock": bool(not_from_wall_clock)}
    new = Clock(**{**clock.__dict__, "floor": floor, "H": max(clock.H, at, now),
                   "admission": "open", "bound_b": record})
    write(state_dir, new, previous=previous)
    return new
