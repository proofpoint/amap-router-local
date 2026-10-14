"""router/peerjournal.py — the candidate journal and its store bookkeeping.

THE CANDIDATE JOURNAL holds one durable record per intake candidate, created
before any check, under a router-private journal root:

    state_dir/<owner>/peer-candidates/<key>/
        snapshot/candidate.json   the candidate's bytes, written once at take
        record.json               the record: lifecycle, hold, disposition
        decision.json             a decided placement (`peerbind`)
        supersede.json            a refusal superseding a decision (`peerbind`)

`<owner>` is the logical_id of the instance whose generation the candidate
came from, or `_host` for the host intakes. `_host` cannot collide with an
instance name, which begins with a letter or digit.

THE KEY is sha256 over the canonical {intake, gen, owner, entry_id}: one
record per DELIVERY, never per message. Message identity is check 2 and the
replay index.

THE TAKE SEQUENCE. Every take allocates `take_seq`, a router-wide, strictly
increasing integer, persisted BEFORE the record directory exists and written
into record.json. A seq is LIVE only when a record.json carries it. Takes are
serialised under the drain lock, so a crash can leave only the TOP seq
without a record; a synchronous failure after allocation removes its
directory and marks the seq VACANT before the lock is released, and if even
that fails the store is BLOCKED for the rest of the pass. VACANT counts as
settled for the frontier.

STORE BOOKKEEPING, the `store` member of `state_dir/peer-clock.json`
(closed, one writer), so the clock and the counts can only be rolled back
together (`peerclock`):

    {"v": 1, "take_seq": int, "reserve_seq": int, "settled_through": int,
     "roots": {<owner>: {"token", "live", "high_seq", "content_sum", "rev_total"}},
     "replay": {"token", "live", "high_reserve_seq", "content_sum", "rev_total"},
     "pending_op": null | {"op", ...}}

Every mutation writes `pending_op` BEFORE it acts and clears it AFTER the
counts are updated, so a crash leaves at most one operation whose effect is
uncertain. `content_sum` is an order-independent sum, mod 2^256, of a
canonical, length-prefixed sha256 contribution per live file (its name, its
revision, its bytes), and `rev_total` the sum of revisions. An immutable file
has revision 0. Startup recomputes both from disk: a deleted, added or
rolled-back file moves them, and the store then cannot be shown complete.
This detects corruption and rollback; it is not a defence against a writer of
`state_dir`, which is the trusted runtime's own.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import logging

from . import hoplink
from . import peerbind, peerclock
from .util import atomic_write, format_utc_ts, fsync_dir, parse_utc_ts

logger = logging.getLogger("amap_router_local.peerjournal")

JOURNAL_DIR = peerbind.JOURNAL_DIR
REPLAY_DIR = "peer-replay"
VACANT_DIR = "peer-vacant"
HOST_OWNER = "_host"
WITNESS = ".witness"
RECORD = "record.json"
SNAPSHOT_DIR = "snapshot"
SNAPSHOT_CANDIDATE = "candidate.json"
SNAPSHOT_VIEW = "view.json"
SNAPSHOT_STATEMENT = "statement"
SNAPSHOT_FILES = (SNAPSHOT_CANDIDATE, SNAPSHOT_VIEW, SNAPSHOT_STATEMENT)
INTAKES = ("candidates", ".unresolved", ".control")
_MOD = 1 << 256
_META_MEMBERS = ("v", "take_seq", "reserve_seq", "settled_through", "roots", "replay",
                 "pending_op")
_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")


class StoreBlocked(Exception):
    """An operation's cleanup failed: `pending_op` stays set, and no further
    store mutation runs until the next start reconciles it."""


class StoreRefused(Exception):
    """`init_store` refused: a peer artefact already exists."""


# ---------------------------------------------------------------------------
# Paths, keys and the content contribution
# ---------------------------------------------------------------------------

def record_key(*, intake: str, gen: str, owner: str, entry_id: str) -> str:
    if intake not in INTAKES:
        raise ValueError(f"unknown intake {intake!r}")
    return hashlib.sha256(hoplink.canonical(
        {"intake": intake, "gen": gen, "owner": owner, "entry_id": entry_id})).hexdigest()


def journal_root(state_dir: Path, owner: str) -> Path:
    return Path(state_dir) / owner / JOURNAL_DIR


def record_dir(state_dir: Path, owner: str, key: str) -> Path:
    return journal_root(state_dir, owner) / key


def record_dir_rel(owner: str, key: str) -> str:
    return f"{owner}/{JOURNAL_DIR}/{key}"


def contribution(name: str, rev: int, data: bytes) -> int:
    """One live file's share of `content_sum`: sha256 over the length-
    prefixed name, the revision and the sha256 of the bytes, as an
    integer."""
    n = name.encode("utf-8")
    r = str(rev).encode("ascii")
    payload = (str(len(n)).encode("ascii") + b":" + n + str(len(r)).encode("ascii") + b":" + r
               + hashlib.sha256(data).digest())
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


# ---------------------------------------------------------------------------
# The store's bookkeeping
# ---------------------------------------------------------------------------

class StoreAbsent(ValueError):
    """The clock file holds no store bookkeeping: the store was never
    initialised, or its bookkeeping was lost with the clock."""


def read_meta(state_dir: Path) -> Dict[str, Any]:
    doc = peerclock.read_doc(state_dir)
    store = doc.get("store")
    if store is None:
        raise StoreAbsent("no store bookkeeping in the clock file")
    if not isinstance(store, dict) or set(store) != set(_META_MEMBERS) or store["v"] != 1:
        raise ValueError("not a closed peer-store record")
    return store


def _write_meta(state_dir: Path, meta: Mapping[str, Any]) -> None:
    doc = peerclock.read_doc(state_dir)
    doc["store"] = dict(meta)
    peerclock.write_doc(state_dir, doc)


def _root_entry(token: str) -> Dict[str, Any]:
    return {"token": token, "live": 0, "high_seq": 0, "content_sum": "0", "rev_total": 0}


def _delta(store: str, owner: Optional[str], dsum: int, drev: int, dlive: int) -> Dict[str, Any]:
    """One store's exact change by an operation, recorded in `pending_op`
    BEFORE it acts: reconcile accepts that store as recorded (not applied)
    or recorded plus this (applied), and nothing else."""
    return {"store": store, "owner": owner, "sum": str(dsum % _MOD), "rev": drev, "live": dlive}


def _apply(meta: Dict[str, Any], d: Mapping[str, Any]) -> None:
    entry = meta["replay"] if d["store"] == "replay" else meta["roots"][d["owner"]]
    _add(entry, int(d["sum"]), d["rev"], d["live"])


def _add(entry: Dict[str, Any], delta_sum: int, delta_rev: int, delta_live: int) -> None:
    entry["content_sum"] = str((int(entry["content_sum"]) + delta_sum) % _MOD)
    entry["rev_total"] += delta_rev
    entry["live"] += delta_live


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def _artefacts(state_dir: Path) -> List[str]:
    found = []
    for name in (peerclock.CLOCK_FILE, REPLAY_DIR, VACANT_DIR):
        if (Path(state_dir) / name).exists():
            found.append(name)
    for child in sorted(Path(state_dir).iterdir()) if Path(state_dir).is_dir() else ():
        if (child / JOURNAL_DIR).exists():
            found.append(f"{child.name}/{JOURNAL_DIR}")
    return found


def _surviving(hop_root: Optional[Path], peer_roots: Iterable[Path]) -> List[str]:
    """Placement evidence that outlived a wiped `state_dir`: a disposal
    tombstone under the hop root, or a signed peer notice (a `kind: peer`
    notice whose message id is not a local-lane 32-hex id)."""
    found = []
    if hop_root is not None:
        disposed = Path(hop_root) / ".disposed"
        for intake in (".unresolved", ".control"):
            d = disposed / intake
            if d.is_dir():
                found += [f"{d}/{n}" for n in sorted(os.listdir(d)) if n != ".stage"]
    for root in peer_roots:
        notices = Path(root) / "notices"
        if not notices.is_dir():
            continue
        for p in sorted(notices.glob("notice-*.json")):
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            mid = (doc.get("message") or {}).get("id") if isinstance(doc, dict) else None
            if doc.get("kind") == "peer" and isinstance(mid, str) and not re.fullmatch(
                    r"[0-9a-f]{32}", mid):
                found.append(str(p))
    return found


def init_store(state_dir: Path, now: datetime, *, hop_root: Optional[Path],
               peer_roots: Iterable[Path], acknowledge_surviving: Optional[str] = None,
               p: int = peerclock.P_DEFAULT, f: int = peerclock.F_DEFAULT) -> peerclock.Clock:
    """`router peer-store init --never-admitted`: a fresh store, admission
    open, no floor. Refused over any peer artefact, and over surviving
    placement evidence unless the operator acknowledges it with evidence."""
    state_dir = Path(state_dir)
    existing = _artefacts(state_dir)
    if existing:
        raise StoreRefused(f"peer artefacts already exist: {existing}")
    surviving = _surviving(hop_root, peer_roots)
    if surviving and not (acknowledge_surviving and acknowledge_surviving.strip()):
        raise StoreRefused(f"placement evidence survives (pass --acknowledge-surviving with "
                           f"evidence): {surviving[:5]}")
    clock = peerclock.initial(now, p=p, f=f)
    replay = state_dir / REPLAY_DIR
    replay.mkdir(mode=0o700)
    atomic_write(replay / WITNESS, clock.store_token.encode("ascii"), durable_root=state_dir)
    meta = {"v": 1, "take_seq": 0, "reserve_seq": 0, "settled_through": 0, "roots": {},
            "replay": {"token": clock.store_token, "live": 0, "high_reserve_seq": 0,
                       "content_sum": "0", "rev_total": 0},
            "pending_op": None}
    peerclock.write(state_dir, clock, previous=None)
    _write_meta(state_dir, meta)
    return clock


# ---------------------------------------------------------------------------
# Roots, take, records
# ---------------------------------------------------------------------------

def _ensure_root(state_dir: Path, meta: Dict[str, Any], owner: str, token: str) -> None:
    if owner in meta["roots"]:
        return
    meta["pending_op"] = {"op": "register_root", "owner": owner}
    _write_meta(state_dir, meta)
    root = journal_root(state_dir, owner)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write(root / WITNESS, token.encode("ascii"), durable_root=Path(state_dir))
    meta["roots"][owner] = _root_entry(token)
    meta["pending_op"] = None
    _write_meta(state_dir, meta)


def _record_bytes(record: Mapping[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True).encode("utf-8")


def take(state_dir: Path, owner: str, *, intake: str, gen: str, entry_id: str, raw: bytes,
         now: datetime) -> Tuple[str, int]:
    """Take one intake candidate: allocate its seq (durable), create its
    directory, write the snapshot once, then record.json (`pending`, rev 1).
    Returns (key, take_seq). Call under the drain lock."""
    state_dir = Path(state_dir)
    meta = read_meta(state_dir)
    if meta["pending_op"] is not None:
        raise StoreBlocked(f"an operation is unreconciled: {meta['pending_op']}")
    _ensure_root(state_dir, meta, owner, meta["replay"]["token"])
    key = record_key(intake=intake, gen=gen, owner=owner, entry_id=entry_id)
    rdir = record_dir(state_dir, owner, key)
    if (rdir / RECORD).is_file():
        # The same delivery taken again: one record per delivery.
        return key, read_record(state_dir, owner, key)["take_seq"]
    if rdir.exists():
        raise StoreBlocked(f"record directory {key} has no record; reconcile at startup")
    seq = meta["take_seq"] + 1
    record = {"schema": "amap-router-local.peer-candidate/1", "key": key, "owner": owner,
              "intake": intake, "gen": gen, "entry_id": entry_id, "take_seq": seq,
              "rev": 1, "first_seen_ts": format_utc_ts(now), "state_ts": format_utc_ts(now),
              "state": "pending", "hold": None, "decided_sticky": False, "cause": None,
              "policy_code": None, "control": None, "replay_ref": None, "retry": None,
              "tombstone": None, "removed": False, "disposed": None, "done_ts": None}
    data = _record_bytes(record)
    snap_bytes = bytes(raw)
    delta = _delta("root", owner,
                   contribution(f"{key}/{SNAPSHOT_DIR}/{SNAPSHOT_CANDIDATE}", 0, snap_bytes)
                   + contribution(f"{key}/{RECORD}", 1, data), 1, 2)
    meta["take_seq"] = seq
    meta["pending_op"] = {"op": "take", "owner": owner, "key": key, "seq": seq, "delta": [delta]}
    _write_meta(state_dir, meta)
    created = False
    try:
        rdir.mkdir(mode=0o700)
        created = True
        fsync_dir(rdir.parent)
        snap = rdir / SNAPSHOT_DIR
        snap.mkdir(mode=0o700)
        fsync_dir(rdir)
        _write_once(snap, SNAPSHOT_CANDIDATE, snap_bytes)
        _write_once(rdir, RECORD, data)
    except Exception:
        try:
            if created:
                shutil.rmtree(rdir)
                fsync_dir(rdir.parent)
            _mark_vacant(state_dir, seq)
            meta["pending_op"] = None
            _write_meta(state_dir, meta)
        except Exception:
            raise StoreBlocked(f"take of seq {seq} failed and its cleanup failed too") from None
        raise
    _apply(meta, delta)
    entry = meta["roots"][owner]
    entry["high_seq"] = max(entry["high_seq"], seq)
    meta["pending_op"] = None
    _write_meta(state_dir, meta)
    return key, seq


def _write_once(dirpath: Path, name: str, data: bytes) -> None:
    fd = peerbind._open_dir(dirpath)
    try:
        peerbind._link_once(fd, name, data, stage_prefix=f".{name}.stage-")
    finally:
        os.close(fd)


def _mark_vacant(state_dir: Path, seq: int) -> None:
    vdir = Path(state_dir) / VACANT_DIR
    vdir.mkdir(exist_ok=True, mode=0o700)
    _write_once(vdir, str(seq), b"")


def _vacant(state_dir: Path) -> set:
    vdir = Path(state_dir) / VACANT_DIR
    if not vdir.is_dir():
        return set()
    return {int(n) for n in os.listdir(vdir) if n.isdigit()}


def add_snapshot(state_dir: Path, record: Mapping[str, Any], name: str, data: bytes) -> None:
    """Write one more immutable snapshot file (the view, the statement)
    once, under the intent discipline. Identical bytes already there are
    accepted; different bytes raise `peerbind.LinkConflict`."""
    if name not in (SNAPSHOT_VIEW, SNAPSHOT_STATEMENT):
        raise ValueError(f"{name!r} is not a later snapshot file")
    state_dir = Path(state_dir)
    owner, key = record["owner"], record["key"]
    snap = record_dir(state_dir, owner, key) / SNAPSHOT_DIR
    if (snap / name).is_file():
        if (snap / name).read_bytes() != data:
            raise peerbind.LinkConflict(name)
        return
    meta = read_meta(state_dir)
    if meta["pending_op"] is not None:
        raise StoreBlocked(f"an operation is unreconciled: {meta['pending_op']}")
    delta = _delta("root", owner, contribution(f"{key}/{SNAPSHOT_DIR}/{name}", 0, data), 0, 1)
    meta["pending_op"] = {"op": "snapshot", "owner": owner, "key": key, "name": name,
                          "delta": [delta]}
    _write_meta(state_dir, meta)
    _write_once(snap, name, data)
    _apply(meta, delta)
    meta["pending_op"] = None
    _write_meta(state_dir, meta)


def read_snapshot(state_dir: Path, record: Mapping[str, Any], name: str) -> Optional[bytes]:
    try:
        return (record_dir(state_dir, record["owner"], record["key"]) / SNAPSHOT_DIR
                / name).read_bytes()
    except FileNotFoundError:
        return None


def read_record(state_dir: Path, owner: str, key: str) -> Dict[str, Any]:
    return json.loads((record_dir(state_dir, owner, key) / RECORD).read_text(encoding="utf-8"))


def all_records(state_dir: Path) -> List[Dict[str, Any]]:
    """Every journal record, of every owner (read only; a record that cannot
    be read is skipped: reconcile reports it)."""
    state_dir = Path(state_dir)
    try:
        meta = read_meta(state_dir)
    except (OSError, ValueError, StoreAbsent, peerclock.ClockUntrusted):
        return []
    out = []
    for owner in sorted(meta["roots"]):
        root = journal_root(state_dir, owner)
        for d in sorted(root.iterdir()) if root.is_dir() else ():
            if not (d.is_dir() and _KEY_RE.fullmatch(d.name) and (d / RECORD).is_file()):
                continue
            try:
                out.append(json.loads((d / RECORD).read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
    return out


def write_record(state_dir: Path, record: Dict[str, Any]) -> Dict[str, Any]:
    """Replace a record with `record`, its revision raised by one, under the
    intent discipline. Returns the record as written."""
    state_dir = Path(state_dir)
    meta = read_meta(state_dir)
    if meta["pending_op"] is not None:
        raise StoreBlocked(f"an operation is unreconciled: {meta['pending_op']}")
    owner, key = record["owner"], record["key"]
    path = record_dir(state_dir, owner, key) / RECORD
    old = path.read_bytes()
    old_rev = json.loads(old)["rev"]
    new_record = dict(record, rev=old_rev + 1)
    new = _record_bytes(new_record)
    delta = _delta("root", owner, contribution(f"{key}/{RECORD}", old_rev + 1, new)
                   - contribution(f"{key}/{RECORD}", old_rev, old), 1, 0)
    meta["pending_op"] = {"op": "record", "owner": owner, "key": key, "rev": old_rev + 1,
                          "delta": [delta]}
    _write_meta(state_dir, meta)
    atomic_write(path, new, durable_root=state_dir)
    _apply(meta, delta)
    meta["pending_op"] = None
    _write_meta(state_dir, meta)
    return new_record


# ---------------------------------------------------------------------------
# Startup: reconcile and verify
# ---------------------------------------------------------------------------

def _scan_root(state_dir: Path, owner: str) -> Tuple[int, int, int, int, List[int]]:
    """(live files, max take_seq, content_sum, rev_total, seqs) recomputed
    from disk for one journal root."""
    root = journal_root(state_dir, owner)
    live = 0
    total = 0
    revs = 0
    high = 0
    seqs = []
    for d in sorted(root.iterdir()):
        if not d.is_dir() or not _KEY_RE.fullmatch(d.name):
            continue
        rec_path = d / RECORD
        if not rec_path.is_file():
            continue
        rec_bytes = rec_path.read_bytes()
        rec = json.loads(rec_bytes)
        seqs.append(rec["take_seq"])
        high = max(high, rec["take_seq"])
        total += contribution(f"{d.name}/{RECORD}", rec["rev"], rec_bytes)
        revs += rec["rev"]
        live += 1
        snapdir = d / SNAPSHOT_DIR
        for snap in sorted(snapdir.iterdir()) if snapdir.is_dir() else ():
            if snap.name in SNAPSHOT_FILES and snap.is_file():
                total += contribution(f"{d.name}/{SNAPSHOT_DIR}/{snap.name}", 0,
                                      snap.read_bytes())
                live += 1
    return live, high, total % _MOD, revs, seqs


#: A problem's prefix: the live stores hold MORE than the bookkeeping (it,
#: and the clock with it, is older than the stores: H is untrusted), or
#: LESS (the stores lost something: H is intact).
BEHIND, LOSS = "behind: ", "loss: "


def _rolled(entry: Mapping[str, Any], d: Optional[Mapping[str, Any]], live: int, total: int,
            revs: int) -> bool:
    """Whether a store with an operation pending on it (`d`, its exact
    change) is exactly as recorded, or exactly as recorded plus that
    change: the operation did not run, or ran completely. Without an
    operation on it, never: it is compared as usual."""
    if d is None:
        return False
    before = (entry["live"], int(entry["content_sum"]) % _MOD, entry["rev_total"])
    after = (entry["live"] + d["live"], (int(entry["content_sum"]) + int(d["sum"])) % _MOD,
             entry["rev_total"] + d["rev"])
    return (live, total % _MOD, revs) in (before, after)


def reconcile(state_dir: Path) -> List[str]:
    """Run at startup, under the drain lock, before any drain: settle an
    unreconciled operation, remove record directories without a record,
    mark the top seq VACANT if nothing carries it, then compare every store
    with its bookkeeping. Returns the problems found (empty: complete)."""
    state_dir = Path(state_dir)
    meta = read_meta(state_dir)
    problems: List[str] = []
    op = meta["pending_op"]
    # Directories without record.json (a crash or failure mid-take): removed;
    # no reservation can name one, because a reservation needs a record.
    for owner in list(meta["roots"]) + ([op["owner"]] if op and op.get("owner") else []):
        root = journal_root(state_dir, owner)
        if not root.is_dir():
            continue
        for d in sorted(root.iterdir()):
            if d.is_dir() and _KEY_RE.fullmatch(d.name) and not (d / RECORD).exists():
                if any(doc["candidate_ref"] == d.name for _rt, _idk, doc in _reservations(state_dir)):
                    problems.append(f"{LOSS}record {owner}/{d.name} is missing but a reservation "
                                    "names it")
                    continue
                shutil.rmtree(d)
    if op is not None and op["op"] == "prune":
        # A prune is completed, never half-undone: every target goes.
        _remove_targets(*_prune_targets(state_dir, {"owner": op["owner"], "key": op["key"],
                                                    "replay_ref": op.get("replay_ref")}))
    deltas = list((op or {}).get("delta") or ())
    if op is not None and op["op"] == "register_root":
        owner = op["owner"]
        root = journal_root(state_dir, owner)
        if owner not in meta["roots"]:
            if (root / WITNESS).is_file():
                meta["roots"][owner] = _root_entry(meta["replay"]["token"])
            elif root.is_dir() and not any(root.iterdir()):
                root.rmdir()
    # Recompute every root.
    carried = set()
    for owner, entry in sorted(meta["roots"].items()):
        root = journal_root(state_dir, owner)
        if not root.is_dir():
            problems.append(f"{LOSS}journal root {owner} is missing")
            continue
        try:
            token = (root / WITNESS).read_text(encoding="ascii")
        except OSError:
            token = None
        if token != entry["token"]:
            problems.append(f"{LOSS}journal root {owner}: witness does not match")
        live, high, total, revs, seqs = _scan_root(state_dir, owner)
        carried |= set(seqs)
        d = next((x for x in deltas if x["store"] == "root" and x["owner"] == owner), None)
        if _rolled(entry, d, live, total, revs):
            entry.update(live=live, high_seq=max(entry["high_seq"], high),
                         content_sum=str(total), rev_total=revs)
            continue
        # A high-water may exceed what is on disk (retention prunes), never
        # fall below it; counts, sums and revisions are exact.
        if (live, str(total), revs) != (entry["live"], entry["content_sum"],
                                        entry["rev_total"]) or high > entry["high_seq"]:
            ahead = high > entry["high_seq"] or revs > entry["rev_total"] or live > entry["live"]
            problems.append(f"{BEHIND if ahead else LOSS}journal root {owner}: content does not "
                            f"match its bookkeeping")
    # The replay store.
    replay = meta["replay"]
    try:
        rtoken = (state_dir / REPLAY_DIR / WITNESS).read_text(encoding="ascii")
    except OSError:
        rtoken = None
    if rtoken != replay["token"]:
        problems.append(f"{LOSS}replay store: witness does not match")
    rlive, rhigh, rtotal = _scan_replay(state_dir)
    d = next((x for x in deltas if x["store"] == "replay"), None)
    if d is not None and _rolled(replay, d, rlive, rtotal, replay["rev_total"]) and \
            rhigh <= max(replay["high_reserve_seq"], meta["reserve_seq"]):
        replay.update(live=rlive, high_reserve_seq=max(replay["high_reserve_seq"], rhigh),
                      content_sum=str(rtotal))
    elif ((rlive, str(rtotal)) != (replay["live"], replay["content_sum"])
          or rhigh > replay["high_reserve_seq"]):
        ahead = rhigh > replay["high_reserve_seq"] or rlive > replay["live"]
        problems.append(f"{BEHIND if ahead else LOSS}replay store: content does not match its "
                        f"bookkeeping")
    # Roots on disk that the bookkeeping does not know.
    for child in sorted(state_dir.iterdir()):
        if (child / JOURNAL_DIR).is_dir() and child.name not in meta["roots"]:
            problems.append(f"{BEHIND}journal root {child.name} is not recorded")
    if carried and max(carried) > meta["take_seq"]:
        problems.append(f"{BEHIND}a record carries take_seq {max(carried)}, above the recorded "
                        f"{meta['take_seq']}")
    # The top seq alone may lack a record after a crash: VACANT.
    vacant = _vacant(state_dir)
    top = meta["take_seq"]
    if top and top not in carried and top not in vacant and top > meta["settled_through"]:
        _mark_vacant(state_dir, top)
        vacant.add(top)
    for seq in range(meta["settled_through"] + 1, top):
        if seq not in carried and seq not in vacant:
            problems.append(f"{LOSS}take_seq {seq} has no record and is not vacant")
    meta["pending_op"] = None
    _write_meta(state_dir, meta)
    return problems


# ---------------------------------------------------------------------------
# The frontier
# ---------------------------------------------------------------------------

SETTLED_STATES = ("done",)


def advance_frontier(state_dir: Path) -> int:
    """Raise `settled_through` while the next seq is settled (a `done`
    record, or VACANT). Never lowers it."""
    state_dir = Path(state_dir)
    meta = read_meta(state_dir)
    by_seq: Dict[int, str] = {}
    for owner in meta["roots"]:
        root = journal_root(state_dir, owner)
        for d in root.iterdir() if root.is_dir() else ():
            if (d / RECORD).is_file():
                rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
                by_seq[rec["take_seq"]] = rec["state"]
    vacant = _vacant(state_dir)
    s = meta["settled_through"]
    while s + 1 <= meta["take_seq"] and (s + 1 in vacant or by_seq.get(s + 1) in SETTLED_STATES):
        s += 1
    if s != meta["settled_through"]:
        meta["settled_through"] = s
        _write_meta(state_dir, meta)
    return s


# ---------------------------------------------------------------------------
# The replay store: reservations, the digest index and `.done` markers
# ---------------------------------------------------------------------------
#
#   peer-replay/<rt>/<idk>.json        the MAC'd reservation (`peerbind`), rev 0
#   peer-replay/<rt>/<idk>.done        {"done_ts", "disposition"}, rev 0
#   peer-replay/digests/<sha256>       "<rt>/<idk>", check 2's index
#
# Reservations and markers are immutable and counted in the replay store's
# bookkeeping; the digest index is derived from the reservations and
# repaired at startup, so it is not.

DIGESTS_DIR = "digests"
DONE_SUFFIX = ".done"
DISPOSITIONS = ("placed", "refused", "dropped", "demoted", "mail")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")


def _replay(state_dir: Path) -> Path:
    return Path(state_dir) / REPLAY_DIR


def _require_clear(meta: Mapping[str, Any]) -> None:
    if meta["pending_op"] is not None:
        raise StoreBlocked(f"an operation is unreconciled: {meta['pending_op']}")


#: The kinds a digest index entry names: a signed statement's reservation,
#: or a control notice's (`peercontrol`, the receive side).
DIGEST_KINDS = ("statement", "control")


def known(state_dir: Path, statement_sha256: str, kind: str = "statement"
          ) -> Optional[Tuple[str, str]]:
    """Check 2's lookup: the (rt, idk) a retained reservation of this exact
    signed bytes, of this `kind`, is filed under, or None. An entry of the
    other kind is not a match. An entry without a kind (the form before the
    index recorded one) or with an unknown kind is corrupt, never guessed.
    The caller excludes its own record's reservation by comparing
    `candidate_ref`."""
    if not _HEX64.fullmatch(statement_sha256):
        raise ValueError("statement_sha256: 64 lower-case hex")
    if kind not in DIGEST_KINDS:
        raise ValueError(f"kind: one of {DIGEST_KINDS}")
    try:
        ref = (_replay(state_dir) / DIGESTS_DIR / statement_sha256).read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    entry_kind, sep, where = ref.partition(" ")
    rt, _, idk = where.partition("/")
    if not (sep and entry_kind in DIGEST_KINDS and _HEX32.fullmatch(rt) and _HEX64.fullmatch(idk)):
        raise peerbind.RecoveryCorrupt("digest", statement_sha256)
    return (rt, idk) if entry_kind == kind else None


def _link_digest(state_dir: Path, statement_sha256: str, rt: str, idk: str,
                 kind: str = "statement") -> None:
    if kind not in DIGEST_KINDS:
        raise ValueError(f"kind: one of {DIGEST_KINDS}")
    ddir = _replay(state_dir) / DIGESTS_DIR
    if not ddir.is_dir():
        ddir.mkdir(mode=0o700)
        fsync_dir(ddir.parent)
    _write_once(ddir, statement_sha256, f"{kind} {rt}/{idk}".encode("ascii"))


def reserve(state_dir: Path, checked: "peerbind.Checked", *, record: Dict[str, Any]
            ) -> Tuple["peerbind.PersistedReservation", Dict[str, Any]]:
    """Check 12 for a `pending` record, each step durable before the next:
    the reservation (link-once), its digest entry, then record.json
    `reserved` with its `replay_ref`. Returns the receipt and the record as
    written. `peerbind.ReservationCollision` (another candidate holds this
    (runtime, id)) leaves every file as it was."""
    state_dir = Path(state_dir)
    meta = read_meta(state_dir)
    _require_clear(meta)
    if record["state"] != "pending":
        raise ValueError(f"only a pending record is reserved, not {record['state']!r}")
    seq = meta["reserve_seq"] + 1
    rec = peerbind.reservation_record(checked, record_id=record["key"], reserve_seq=seq,
                                      state_dir=state_dir)
    doc = json.loads(rec)
    rt, idk = doc["rt"], doc["idk"]
    before = _replay_files(state_dir, rt, idk)
    # A reservation already there (ours, a retried step; or another's, the
    # collision) is never replaced, so it changes nothing.
    delta = _delta("replay", None, 0 if before else
                   contribution(f"{rt}/{idk}{peerbind.RESERVATION_SUFFIX}", 0, rec),
                   0, 0 if before else 1)
    meta["reserve_seq"] = seq
    meta["pending_op"] = {"op": "reserve", "owner": None, "rt": rt, "idk": idk, "seq": seq,
                          "delta": [delta]}
    _write_meta(state_dir, meta)
    try:
        receipt = peerbind.commit_reservation(state_dir, rt, idk, rec, record_id=record["key"])
    except peerbind.ReservationCollision:
        meta["pending_op"] = None
        _write_meta(state_dir, meta)
        raise
    _link_digest(state_dir, doc["statement_sha256"], rt, idk)
    if not before:
        _apply(meta, delta)
        meta["replay"]["high_reserve_seq"] = max(meta["replay"]["high_reserve_seq"], seq)
    meta["pending_op"] = None
    _write_meta(state_dir, meta)
    written = write_record(state_dir, dict(record, state="reserved", replay_ref=f"{rt}/{idk}"))
    return receipt, written


def _replay_files(state_dir: Path, rt: str, idk: str) -> List[str]:
    d = _replay(state_dir) / rt
    return [n for n in (idk + peerbind.RESERVATION_SUFFIX, idk + DONE_SUFFIX)
            if (d / n).is_file()]


def mark_done(state_dir: Path, rt: str, idk: str, *, disposition: str, now: datetime) -> None:
    """The replay record `reserved -> done`: a link-once `.done` marker; the
    MAC'd reservation is never rewritten. Idempotent for the same
    disposition."""
    state_dir = Path(state_dir)
    if disposition not in DISPOSITIONS:
        raise ValueError(f"unknown disposition {disposition!r}")
    meta = read_meta(state_dir)
    _require_clear(meta)
    d = _replay(state_dir) / rt
    if not (d / (idk + peerbind.RESERVATION_SUFFIX)).is_file():
        raise FileNotFoundError(f"no reservation {rt}/{idk}")
    name = idk + DONE_SUFFIX
    if (d / name).is_file():
        if json.loads((d / name).read_bytes())["disposition"] != disposition:
            raise peerbind.LinkConflict(name)
        return
    data = json.dumps({"done_ts": format_utc_ts(now), "disposition": disposition},
                      sort_keys=True).encode("utf-8")
    delta = _delta("replay", None, contribution(f"{rt}/{name}", 0, data), 0, 1)
    meta["pending_op"] = {"op": "done", "owner": None, "rt": rt, "idk": idk, "delta": [delta]}
    _write_meta(state_dir, meta)
    _write_once(d, name, data)
    _apply(meta, delta)
    meta["pending_op"] = None
    _write_meta(state_dir, meta)


def done_marker(state_dir: Path, rt: str, idk: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads((_replay(state_dir) / rt / (idk + DONE_SUFFIX)).read_bytes())
    except FileNotFoundError:
        return None


def discover(state_dir: Path, record_key: str, statement_sha256: str, *,
             scan: bool = True) -> Optional[Tuple[str, str]]:
    """The reservation a `pending` record already owns, found WITHOUT the
    current configuration: the digest index first, then (the gap between a
    reservation and its digest entry) a scan for one whose `candidate_ref`
    is this record. Reservations are read as data here; the caller reopens
    the one found, which verifies its MAC."""
    hit = known(state_dir, statement_sha256)
    if hit is not None:
        rt, idk = hit
        try:
            doc = peerbind.parse_reservation(
                (_replay(state_dir) / rt / (idk + peerbind.RESERVATION_SUFFIX)).read_bytes(), None)
        except FileNotFoundError:
            doc = None
        if doc is not None and doc["candidate_ref"] == record_key:
            return hit
    if not scan:
        return None
    for rt, idk, doc in _reservations(state_dir):
        if doc["candidate_ref"] == record_key:
            return rt, idk
    return None


def _reservations(state_dir: Path) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    root = _replay(state_dir)
    if not root.is_dir():
        return
    for rtdir in sorted(root.iterdir()):
        if not (rtdir.is_dir() and _HEX32.fullmatch(rtdir.name)):
            continue
        for f in sorted(rtdir.iterdir()):
            idk = f.name[:-len(peerbind.RESERVATION_SUFFIX)]
            if f.name.endswith(peerbind.RESERVATION_SUFFIX) and _HEX64.fullmatch(idk):
                yield rtdir.name, idk, peerbind.parse_reservation(f.read_bytes(), None)


def repair_done_markers(state_dir: Path, now: datetime) -> int:
    """At startup: every `done` record with a reservation gets its replay
    `.done` marker if a crash between the two left it out (its intake entry
    may already be gone, so no poll would settle it again)."""
    state_dir = Path(state_dir)
    meta = read_meta(state_dir)
    n = 0
    for owner in sorted(meta["roots"]):
        root = journal_root(state_dir, owner)
        for d in sorted(root.iterdir()) if root.is_dir() else ():
            if not (d / RECORD).is_file():
                continue
            rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
            if rec["state"] != "done" or not rec.get("replay_ref"):
                continue
            rt, idk = rec["replay_ref"].split("/")
            if done_marker(state_dir, rt, idk) is None and (
                    _replay(state_dir) / rt / (idk + peerbind.RESERVATION_SUFFIX)).is_file():
                mark_done(state_dir, rt, idk, disposition=_DONE_DISPOSITION[rec["disposed"]],
                          now=now)
                n += 1
    return n


def repair_digests(state_dir: Path) -> int:
    """At startup, before any drain: every reservation without its digest
    entry gets one (link-once). Returns how many were repaired."""
    n = 0
    for rt, idk, doc in list(_reservations(state_dir)):
        if known(state_dir, doc["statement_sha256"]) is None:
            _link_digest(state_dir, doc["statement_sha256"], rt, idk)
            n += 1
    return n


def _scan_replay(state_dir: Path) -> Tuple[int, int, int]:
    """(live files, max reserve_seq, content_sum) recomputed from disk."""
    live = high = total = 0
    root = _replay(state_dir)
    for rtdir in sorted(root.iterdir()) if root.is_dir() else ():
        if not (rtdir.is_dir() and _HEX32.fullmatch(rtdir.name)):
            continue
        for f in sorted(rtdir.iterdir()):
            stem, suffix = os.path.splitext(f.name)
            if not (_HEX64.fullmatch(stem) and suffix in (peerbind.RESERVATION_SUFFIX,
                                                          DONE_SUFFIX)):
                continue
            data = f.read_bytes()
            total += contribution(f"{rtdir.name}/{f.name}", 0, data)
            live += 1
            if suffix == peerbind.RESERVATION_SUFFIX:
                high = max(high, json.loads(data)["reserve_seq"])
    return live, high, total % _MOD


# ---------------------------------------------------------------------------
# The lifecycle: forward-only states, holds as metadata
# ---------------------------------------------------------------------------

TRANSITIONS: Mapping[str, frozenset] = {
    "pending": frozenset({"reserved", "demoted", "dropped", "mail"}),
    "reserved": frozenset({"decided", "dropped", "refused"}),
    "decided": frozenset({"done", "refused"}),
    "demoted": frozenset({"done"}),
    "dropped": frozenset({"done"}),
    "refused": frozenset({"done"}),
    "mail": frozenset({"done"}),
    "done": frozenset(),
}
HOLD_REASONS = frozenset({
    "candidate_view_unavailable", "candidate_view_refused", "candidate_malformed",
    "admission_closed", "undecided", "hook_absent", "key_runtime_changed",
    "recovery_corrupt", "recipient_gone", "unpublishable"})
#: Holds only an operator act clears: never re-evaluated by a poll.
OPERATOR_HOLDS = frozenset({"candidate_view_refused", "candidate_malformed",
                            "recovery_corrupt", "recipient_gone", "unpublishable"})
#: Of those, the ones re-tried without an operator verb: `recipient_gone`
#: once the decision's recipient is configured again (re-enrolment; checked
#: from config, so a recipient still gone is never attempted), and
#: `unpublishable` once per start (a published id's grammar changes only
#: with the code). Each stays visible in status, with its age, until then.
#: The codec causes whose demotion carries a control notice (check 5(b));
#: every binding cause (checks 6-11) carries one too.
CONTROL_CODEC_CAUSES = frozenset({"statement_value"})
NO_STATEMENT = "no_statement"
OVER_CAP = "over_cap"
CANDIDATE_OVER_CAP = "candidate_over_cap"
MISROUTED = "misrouted"
DUPLICATE = "duplicate"


class TransitionRefused(ValueError):
    """A write across states `TRANSITIONS` does not join: nothing written."""


def transition(state_dir: Path, record: Dict[str, Any], to: str, now: datetime,
               **fields: Any) -> Dict[str, Any]:
    """Move `record` to `to` (clearing any hold) with `fields`, in ONE
    write: a terminal disposition and its pending control notice are never
    written apart."""
    if to not in TRANSITIONS.get(record["state"], ()):
        raise TransitionRefused(f"{record['state']} -> {to}")
    if record["intake"] in HOST_INTAKES and to in _TOMBSTONE_DISPOSITION:
        # The tombstone's bytes are FROZEN in the same write that
        # records the disposition; the commit and recovery use exactly them.
        fields["tombstone"] = _tombstone_bytes(state_dir, record, _TOMBSTONE_DISPOSITION[to],
                                               now).decode("ascii")
    return write_record(state_dir, dict(record, state=to, state_ts=format_utc_ts(now), hold=None,
                                        **fields))


HOST_INTAKES = (".unresolved", ".control")
#: The tombstone's disposition for each state that records one.
_TOMBSTONE_DISPOSITION = {"decided": "placed", "demoted": "demoted", "dropped": "dropped",
                          "refused": "refused", "mail": "mail"}


def _tombstone_bytes(state_dir: Path, record: Mapping[str, Any], disposition: str,
                     now: datetime) -> bytes:
    from . import peerlane
    raw = read_snapshot(state_dir, record, SNAPSHOT_CANDIDATE)
    return peerlane.tombstone_bytes(intake=record["intake"], ident=record["entry_id"],
                                    candidate_sha256=hashlib.sha256(raw).hexdigest(),
                                    disposition=disposition, disposed_at=format_utc_ts(now))


def _done(ctx: "Ctx", record: Dict[str, Any], **fields: Any) -> Dict[str, Any]:
    """Every terminal side effect first; then the disposal (a host-intake
    candidate's tombstone, committed from its frozen bytes); then `done`;
    then the settle pass."""
    try:
        ctx.effects.dispose(record)
    except peerbind.RecoveryCorrupt as e:
        return set_hold(ctx.state_dir, record, "recovery_corrupt", e.detail or e.reason, ctx.now)
    record = transition(ctx.state_dir, record, "done", ctx.now, **fields)
    return _settle(ctx, record)


def set_hold(state_dir: Path, record: Dict[str, Any], reason: str, detail: Optional[str],
             now: datetime) -> Dict[str, Any]:
    """Hold `record` visibly, its state unchanged. An identical hold is not
    rewritten, so `since` keeps its first value."""
    if reason not in HOLD_REASONS:
        raise ValueError(f"{reason!r} is not a hold reason")
    if record["state"] == "done":
        raise TransitionRefused("a done record is never held")
    held = record.get("hold")
    if held and (held["reason"], held["detail"]) == (reason, detail):
        return record
    return write_record(state_dir, dict(record, hold={"reason": reason, "detail": detail,
                                                      "since": format_utc_ts(now)}))


# ---------------------------------------------------------------------------
# The hooks (required, no default)
# ---------------------------------------------------------------------------

class Hold:
    """A hook cannot decide yet: the record is held, nothing is written."""
    __slots__ = ("reason", "detail")

    def __init__(self, reason: str, detail: Optional[str] = None):
        if reason not in HOLD_REASONS:
            raise ValueError(f"{reason!r} is not a hold reason")
        self.reason, self.detail = reason, detail

    def __repr__(self):
        return f"Hold({self.reason!r}, {self.detail!r})"


class Refuse:
    """A receiver-side refusal after the reservation: `refused`, with a
    control notice pending."""
    __slots__ = ("cause", "policy_code")

    def __init__(self, cause: str, policy_code: Optional[str] = None):
        self.cause, self.policy_code = cause, policy_code


class Resolved:
    """The reply hook resolved (or found no) `in_reply_to`: continue."""
    __slots__ = ("in_reply_to",)

    def __init__(self, in_reply_to: Optional[str]):
        self.in_reply_to = in_reply_to


class DecideHooks:
    """check8 (pre-reservation), reply, edge and policy (post-reservation)
    and control_receive. Every one is required: a caller cannot skip one by
    omission. `context` is the `peerpolicy.HookContext` the set was built
    over (`peerpolicy.decide_hooks`), or None for a set built by hand
    (`absent_hooks`, and tests that drive `evaluate` directly)."""
    __slots__ = ("check8", "reply", "edge", "policy", "control_receive", "context")

    def __init__(self, *, check8: Any, reply: Any, edge: Any, policy: Any, control_receive: Any,
                 context: Any = None):
        for name, fn in (("check8", check8), ("reply", reply), ("edge", edge),
                         ("policy", policy), ("control_receive", control_receive)):
            if not callable(fn):
                raise TypeError(f"hook {name} is required and must be callable")
            object.__setattr__(self, name, fn)
        object.__setattr__(self, "context", context)

    def __setattr__(self, name, value):
        raise AttributeError("DecideHooks is immutable")


def absent_hooks() -> DecideHooks:
    """The production hooks of this build: every one holds (`hook_absent`),
    so nothing is decided, placed, demoted or dropped on an absent policy."""
    def absent(name):
        return lambda *_a, **_k: Hold("hook_absent", name)
    return DecideHooks(check8=absent("check8"), reply=absent("reply"), edge=absent("edge"),
                       policy=absent("policy"), control_receive=absent("control_receive"))


class _HookHeld(Exception):
    def __init__(self, hold: Hold):
        super().__init__(hold.reason)
        self.hold = hold


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

class ViewUnavailable(Exception):
    """The candidate-view seam is not available (the codec predates it)."""


def _retry_due(ctx: "Ctx", record: Mapping[str, Any], hold: Mapping[str, Any]) -> bool:
    if hold["reason"] == "unpublishable":
        return ctx.first_pass
    if hold["reason"] == "recipient_gone":
        try:
            _raw, dec = peerbind.read_decision_data(
                ctx.state_dir, record_dir_rel(record["owner"], record["key"]))
        except (OSError, peerbind.RecoveryCorrupt):
            return False
        return dec["hosted_instance"] in getattr(ctx.cfg, "instances", {})
    return False


class Ctx:
    """One poll's evaluation context. `view(raw)` is the codec's
    `candidate_view` (raising its CodecError, or `ViewUnavailable`);
    `effects` writes quarantine items and removes intake entries;
    `retired(record)` is the generation fence."""

    def __init__(self, *, state_dir: Path, cfg: Any, delegation: Any, hooks: DecideHooks,
                 now: datetime, clock: "peerclock.Clock", view: Any, effects: Any,
                 retired: Any, first_pass: bool = False):
        if not isinstance(hooks, DecideHooks):
            raise TypeError("hooks: a DecideHooks")
        bound = hooks.context
        if bound is not None and not (bound.cfg is cfg and bound.delegation is delegation
                                      and bound.state_dir == Path(state_dir)
                                      and bound.now is now and bound.clock is clock):
            raise TypeError("hooks: built over another pass's context")
        self.state_dir, self.cfg, self.delegation, self.hooks = Path(state_dir), cfg, delegation, hooks
        self.now, self.clock, self.view, self.effects, self.retired = now, clock, view, effects, retired
        #: The first pass of this process: unpublishable holds are re-tried
        #: and a reservation is discovered by the full scan, not only the
        #: digest index.
        self.first_pass = first_pass


def _control(outcome: str, cause: str, about: Optional[str],
             policy_code: Optional[str] = None, *, to: Optional[str] = None) -> Dict[str, Any]:
    """A pending control notice, written in the same journal write as its
    disposition. `to` is the destination: the configured runtime address of
    the statement key's owner at this write, or None when no configured
    runtime owns the key. The send re-checks it and never redirects."""
    c = {"outcome": outcome, "cause": cause, "about": about, "sent": False, "to": to}
    if policy_code is not None:
        c["policy_code"] = policy_code
    return c


def _control_to(ctx: "Ctx", key_id: Any) -> Optional[str]:
    """The configured runtime address of `key_id`'s owner, or None."""
    dc = getattr(ctx.delegation, "config", None) or getattr(ctx.cfg, "delegation", None)
    if dc is None or not isinstance(key_id, str):
        return None
    runtime = peerbind.runtime_for_key(dc, key_id)
    return runtime.runtime if runtime is not None else None


def _statement_id(raw: bytes) -> Optional[str]:
    """A statement's `id` from its bytes: strict JSON, the id grammar, or
    None."""
    from . import peerlane
    try:
        doc = peerbind._strict_json(raw)
    except (UnicodeDecodeError, ValueError):
        return None
    ident = doc.get("id") if isinstance(doc, dict) else None
    return ident if isinstance(ident, str) and peerlane.RECORD_ID_RE.fullmatch(ident) else None


def _snapshot_key_id(state_dir: Path, record: Mapping[str, Any]) -> Optional[str]:
    """The statement's key_id, from the snapshot."""
    raw = read_snapshot(state_dir, record, SNAPSHOT_STATEMENT)
    try:
        doc = json.loads(raw) if raw is not None else None
    except ValueError:
        return None
    key_id = doc.get("key_id") if isinstance(doc, dict) else None
    return key_id if isinstance(key_id, str) else None


def _codec_reason(ctx: Ctx, exc: BaseException) -> Optional[str]:
    from . import peerlane
    if peerlane.error_kind(ctx.delegation, exc) == "CodecError":
        return getattr(exc, "reason", None)
    return None


#: The candidate-view refusals (the codec's CANDIDATE_REASONS at (3, 4)):
#: a set of its own, distinct from the verifier's REASONS.
CANDIDATE_REASONS = frozenset({"candidate_json", "candidate_schema", OVER_CAP})


def _view_reason(ctx: Ctx, exc: BaseException) -> Optional[str]:
    """The reason when `exc` is exactly the plugin's CodecError with a
    candidate-view reason; None otherwise (a bug, which propagates)."""
    cls = ctx.delegation.errors.get("CodecError")
    reason = getattr(exc, "reason", None)
    if cls is not None and type(exc) is cls and type(reason) is str and reason in CANDIDATE_REASONS:
        return reason
    return None


def _view(ctx: Ctx, record: Dict[str, Any]) -> Union[Dict[str, Any], Tuple[str, Optional[str]]]:
    """The candidate view (snapshotted once), or ("hold"|"mail", detail)."""
    stored = read_snapshot(ctx.state_dir, record, SNAPSHOT_VIEW)
    if stored is not None:
        return json.loads(stored)
    raw = read_snapshot(ctx.state_dir, record, SNAPSHOT_CANDIDATE)
    try:
        view = ctx.view(raw)
    except ViewUnavailable:
        return ("candidate_view_unavailable", None)
    except Exception as e:  # noqa: BLE001 -- classified exactly
        reason = _view_reason(ctx, e)
        if reason == OVER_CAP:
            return ("mail", CANDIDATE_OVER_CAP)
        if reason in ("candidate_json", "candidate_schema"):
            return ("candidate_view_refused", reason)
        raise
    data = hoplink.canonical(view)
    add_snapshot(ctx.state_dir, record, SNAPSHOT_VIEW, data)
    return json.loads(data)


def _known(ctx: Ctx, record: Mapping[str, Any]):
    def known(kind: str, statement: bytes) -> bool:
        hit = known_fn(ctx.state_dir, hashlib.sha256(statement).hexdigest(), kind)
        if hit is None:
            return False
        rt, idk = hit
        try:
            doc = peerbind.parse_reservation(
                (_replay(ctx.state_dir) / rt / (idk + peerbind.RESERVATION_SUFFIX)).read_bytes(),
                None)
        except FileNotFoundError:
            return False
        return doc["candidate_ref"] != record["key"]
    return known


known_fn = known


def evaluate(ctx: Ctx, record: Dict[str, Any]) -> Dict[str, Any]:
    """Advance one record as far as it can go this poll; returns it as
    written. Operator-only holds are left alone. A record that cannot be
    recovered as recorded (`RecoveryCorrupt`, wherever it is raised) is held
    visibly, never failed with the rest of the pass."""
    try:
        return _evaluate(ctx, record)
    except peerbind.RecoveryCorrupt as e:
        current = read_record(ctx.state_dir, record["owner"], record["key"])
        if current["state"] == "done":
            raise
        return set_hold(ctx.state_dir, current, "recovery_corrupt", e.reason, ctx.now)


def _evaluate(ctx: Ctx, record: Dict[str, Any]) -> Dict[str, Any]:
    hold = record.get("hold")
    if hold and hold["reason"] in OPERATOR_HOLDS and not _retry_due(ctx, record, hold):
        return record
    state = record["state"]
    if state == "pending":
        return _pending(ctx, record)
    if state == "reserved":
        return _reserved(ctx, record)
    if state == "decided":
        return _decided(ctx, record)
    if state in ("demoted", "dropped", "refused", "mail"):
        return _finish(ctx, record)
    return record


def _pending(ctx: Ctx, record: Dict[str, Any]) -> Dict[str, Any]:
    now = ctx.now
    view = _view(ctx, record)
    if isinstance(view, tuple):
        what, detail = view
        if what == "mail":
            return _finish(ctx, transition(ctx.state_dir, record, "mail", now, cause=detail))
        return set_hold(ctx.state_dir, record, what, detail, now)
    # A reservation this record already owns (a crash, or a failure after
    # check 12): decided now, NEVER re-checked.
    statement = read_snapshot(ctx.state_dir, record, SNAPSHOT_STATEMENT)
    if statement is not None:
        found = discover(ctx.state_dir, record["key"], hashlib.sha256(statement).hexdigest(),
                         scan=ctx.first_pass)
        if found is not None:
            record = write_record(ctx.state_dir, dict(record, state="reserved",
                                                      state_ts=format_utc_ts(now),
                                                      replay_ref="/".join(found)))
            return _reserved(ctx, record)
    from . import peerverify
    try:
        fields = peerbind._view(view)[0]
    except peerbind.CandidateMalformed as e:
        return set_hold(ctx.state_dir, record, "candidate_malformed", str(e), now)
    verdict = peerverify.verify(fields, delegation=ctx.delegation, now=now,
                                known=_known(ctx, record))
    if isinstance(verdict, peerverify.Refused):
        cause = verdict.cause
        if cause == NO_STATEMENT:
            return _finish(ctx, transition(ctx.state_dir, record, "mail", now, cause=cause))
        if cause == peerverify.CHECK2_DUPLICATE:
            return _finish(ctx, transition(ctx.state_dir, record, "dropped", now, cause=DUPLICATE))
        control = None
        if cause in CONTROL_CODEC_CAUSES and verdict.statement is not None:
            # The demotion names its statement: the signature-verified bytes
            # are snapshotted BEFORE the disposition is written, and the
            # control's `about` and destination are read from them. A
            # statement whose id cannot be read gets no control at all.
            add_snapshot(ctx.state_dir, record, SNAPSHOT_STATEMENT, verdict.statement)
            about = _statement_id(verdict.statement)
            if about is not None:
                control = _control("demoted", cause, about,
                                   to=_control_to(ctx, verdict.key_id))
        return _finish(ctx, transition(ctx.state_dir, record, "demoted", now, cause=cause,
                                       control=control))
    about = verdict.payload.get("id") if hasattr(verdict.payload, "get") else None
    to = _control_to(ctx, verdict.key_id)
    if verdict.kind != "statement":
        out = ctx.hooks.control_receive(view, verdict)
        if isinstance(out, Hold):
            return set_hold(ctx.state_dir, record, out.reason, out.detail, now)
        raise TypeError("control candidates are not decided in this build")
    add_snapshot(ctx.state_dir, record, SNAPSHOT_STATEMENT, verdict.statement)

    def check8(payload, key_id):
        out = ctx.hooks.check8(payload, key_id)
        if isinstance(out, Hold):
            raise _HookHeld(out)
        return out

    try:
        checked = peerbind.bind_for_reservation(verdict, view, delegation=ctx.delegation,
                                                check7=peerclock.check7(ctx.clock, now),
                                                check8=check8)
    except peerclock.Held:
        return set_hold(ctx.state_dir, record, "admission_closed", None, now)
    except _HookHeld as h:
        return set_hold(ctx.state_dir, record, h.hold.reason, h.hold.detail, now)
    if isinstance(checked, peerbind.Demoted):
        return _finish(ctx, transition(ctx.state_dir, record, "demoted", now, cause=checked.cause,
                                       control=_control("demoted", checked.cause, about, to=to)))
    try:
        _rcp, record = reserve(ctx.state_dir, checked, record=record)
    except peerbind.ReservationCollision:
        return _finish(ctx, transition(ctx.state_dir, record, "dropped", now, cause=DUPLICATE,
                                       control=_control("dropped", DUPLICATE, about, to=to)))
    return _reserved(ctx, record)


def _snapshot(ctx: Ctx, record: Mapping[str, Any]) -> "peerbind.Snapshot":
    statement = read_snapshot(ctx.state_dir, record, SNAPSHOT_STATEMENT)
    view = read_snapshot(ctx.state_dir, record, SNAPSHOT_VIEW)
    if statement is None or view is None:
        raise peerbind.RecoveryCorrupt("snapshot", "incomplete")
    return peerbind.Snapshot(statement, json.loads(view))


def _reserved(ctx: Ctx, record: Dict[str, Any]) -> Dict[str, Any]:
    """Row 2: a reserved record is decided now, under the current
    configuration, from its reservation; checks 1-12 are never re-run."""
    now = ctx.now
    sd = ctx.state_dir
    if (record_dir(sd, record["owner"], record["key"]) / peerbind.DECISION_FILE).exists():
        record = transition(sd, record, "decided", now, decided_sticky=True)
        return _decided(ctx, record)
    if record.get("decided_sticky"):
        return set_hold(sd, record, "recovery_corrupt", "decision_missing", now)
    rt, idk = record["replay_ref"].split("/")
    try:
        rcp = peerbind.reopen_reservation(sd, rt, idk, record_id=record["key"])
        checked = peerbind.resume_reserved(rcp, _snapshot(ctx, record), state_dir=sd)
    except peerbind.RecoveryCorrupt as e:
        return set_hold(sd, record, "recovery_corrupt", e.reason, now)
    about = checked.payload.get("id")
    auth = peerbind.authorise_checked(checked, cfg=ctx.cfg)
    if isinstance(auth, peerbind.NotHosted):
        return _finish(ctx, transition(sd, record, "dropped", now, cause=MISROUTED,
                                       control=_control("dropped", MISROUTED, about,
                                                        to=_control_to(ctx, checked.key_id))))
    if isinstance(auth, peerbind.Undecided):
        return set_hold(sd, record, "undecided", auth.reason, now)
    try:
        auth = peerbind.confirm(auth, cfg=ctx.cfg)
    except peerbind.AuthorisationMismatch as e:
        if e.detail == "runtime":
            return set_hold(sd, record, "key_runtime_changed", None, now)
        return set_hold(sd, record, "undecided", f"stale:{e.detail}", now)
    payload = auth.payload
    for name, call in (("reply", lambda: ctx.hooks.reply(payload, auth.hosted)),
                       ("edge", lambda: ctx.hooks.edge(payload, auth.hosted)),
                       ("policy", lambda: ctx.hooks.policy(payload, auth.hosted))):
        out = call()
        if isinstance(out, Hold):
            return set_hold(sd, record, out.reason, out.detail, now)
        if isinstance(out, Refuse):
            return _finish(ctx, transition(sd, record, "refused", now, cause=out.cause,
                                           policy_code=out.policy_code,
                                           control=_control("refused", out.cause, about,
                                                            out.policy_code,
                                                            to=_control_to(ctx, checked.key_id))))
        if name == "reply" and not isinstance(out, Resolved):
            raise TypeError("the reply hook returns Resolved, Refuse or Hold")
        if name != "reply" and out is not None:
            raise TypeError(f"the {name} hook returns None, Refuse or Hold")
    rec = peerbind.decision_record(auth, record_id=record["key"],
                                   preset=(auth.notice_id, auth.ts), cfg=ctx.cfg, state_dir=sd)
    try:
        peerbind.commit_decision(sd, record_dir_rel(record["owner"], record["key"]), rec,
                                 record_id=record["key"])
    except peerbind.DecisionConflict:
        return set_hold(sd, record, "recovery_corrupt", "decision_conflict", now)
    record = transition(sd, record, "decided", now, decided_sticky=True)
    return _decided(ctx, record)


def _decided(ctx: Ctx, record: Dict[str, Any]) -> Dict[str, Any]:
    """Place a decided record through its durable decision; never
    re-decided. The generation fence runs first."""
    from . import deliver
    now = ctx.now
    sd = ctx.state_dir
    rel = record_dir_rel(record["owner"], record["key"])
    try:
        sup = peerbind.reopen_supersede(sd, rel, record_id=record["key"])
    except peerbind.RecoveryCorrupt as e:
        return set_hold(sd, record, "recovery_corrupt", e.reason, now)
    if sup is not None:
        return _refuse_superseded(ctx, record, sup)
    if ctx.retired(record):
        return supersede(ctx, record, policy_code=GENERATION_RETIRED, by="router")
    try:
        rcp = peerbind.reopen_decision(sd, rel, record_id=record["key"])
        auth = peerbind.resume(rcp, _snapshot(ctx, record), state_dir=sd)
    except peerbind.NoDecision:
        return set_hold(sd, record, "recovery_corrupt", "decision_missing", now)
    except peerbind.RecoveryCorrupt as e:
        return set_hold(sd, record, "recovery_corrupt", e.reason, now)
    try:
        _write_placed(ctx, auth)
    except Exception as e:  # noqa: BLE001 -- a placed record that cannot be written holds
        from . import peerledger
        if isinstance(e, peerledger.LedgerConflict):
            return set_hold(sd, record, "recovery_corrupt", "placed_conflict", now)
        raise
    try:
        deliver.deliver_signed_peer(ctx.cfg, sd, auth,
                                    in_reply_to_resolved=auth.payload.get("in_reply_to"))
    except deliver.RecipientHeld:
        retry = record.get("retry") or {"retry": "recipient_held", "since": format_utc_ts(now)}
        return record if record.get("retry") else write_record(sd, dict(record, retry=retry))
    except peerbind.RecipientGone:
        return set_hold(sd, record, "recipient_gone", None, now)
    except peerbind.Unpublishable as e:
        return set_hold(sd, record, "unpublishable", getattr(e, "member", None), now)
    except peerbind.RecoveryCorrupt as e:
        return set_hold(sd, record, "recovery_corrupt", e.reason, now)
    return _done(ctx, record, disposed="placed", done_ts=format_utc_ts(now), retry=None)


def _write_placed(ctx: Ctx, auth: Any) -> None:
    """The `placed` ledger record of a decided statement, durable BEFORE its
    notice (so a reply drafted the moment the notice appears resolves), and
    written again, idempotently, when a recovery re-places. A recipient no
    longer configured writes nothing: the placement itself refuses it."""
    from . import config as config_mod
    from . import generations as generations_mod
    from . import peerledger
    hosted = auth.hosted
    if hosted not in getattr(ctx.cfg, "instances", {}):
        return
    payload = auth.payload
    expires = parse_utc_ts(payload["ts"]) + timedelta(seconds=ctx.cfg.peer_reply_window_seconds)
    last = config_mod.gen_key(ctx.cfg, hosted).rsplit("/", 1)[-1]
    generation = (last[len(generations_mod.GEN_PREFIX):]
                  if last.startswith(generations_mod.GEN_PREFIX) else last)
    peerledger.write_placed(ctx.cfg, peerledger.placed_record(
        record_id=payload["id"], logical_id=config_mod.state_key(ctx.cfg, hosted),
        local_address=config_mod.address_for(hosted, ctx.cfg.fleet_domain),
        remote=payload["from"], generation=generation, expires_at=format_utc_ts(expires)))


def _finish(ctx: Ctx, record: Dict[str, Any]) -> Dict[str, Any]:
    """A terminal disposition's idempotent effect, then `done`."""
    state = record["state"]
    if state in ("demoted", "mail"):
        ctx.effects.quarantine(record)
    return _done(ctx, record, disposed=state, done_ts=format_utc_ts(ctx.now))


_DONE_DISPOSITION = {"placed": "placed", "demoted": "demoted", "mail": "mail",
                     "dropped": "dropped", "refused": "refused"}


def _settle(ctx: Ctx, record: Dict[str, Any]) -> Dict[str, Any]:
    """After `done`: the replay `.done` marker (when reserved), then the
    intake entry's removal. Both idempotent; recovery repeats them."""
    if record["state"] != "done":
        raise TransitionRefused("only a done record settles")
    if record.get("replay_ref"):
        rt, idk = record["replay_ref"].split("/")
        mark_done(ctx.state_dir, rt, idk, disposition=_DONE_DISPOSITION[record["disposed"]],
                  now=ctx.now)
    if ctx.effects.remove(record) is True and not record.get("removed"):
        record = write_record(ctx.state_dir, dict(record, removed=True))
    return record


# ---------------------------------------------------------------------------
# Supersession and the operator's drop
# ---------------------------------------------------------------------------

DECISION_UNRECOVERABLE = "decision_unrecoverable"
GENERATION_RETIRED = "generation_retired"


class DisposeDeferred(Exception):
    """A host-intake record's tombstone is committed by the next poll (under
    its fsops); the disposition before it is recorded."""


class DropRefused(ValueError):
    """`drop` refused: the record is not one the operator's drop applies
    to. Nothing was written."""


def _notice_present(cfg: Any, hosted: str, notice_id: str) -> Optional[bool]:
    """Whether the recorded recipient's peer tree holds the notice, opened
    without following a link; None when the recipient is not configured
    (presence cannot be established)."""
    inst = cfg.instances.get(hosted)
    if inst is None or inst.peer_root is None:
        return None
    try:
        fd = os.open(str(Path(inst.peer_root) / "notices" / f"notice-{notice_id}.json"),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise peerbind.RecoveryCorrupt("notice", "not a regular file")
        return True
    finally:
        os.close(fd)


def _refuse_superseded(ctx: Ctx, record: Dict[str, Any], sup: Mapping[str, Any]
                       ) -> Dict[str, Any]:
    if record["state"] != "refused":
        about = _about(ctx.state_dir, record)
        record = transition(ctx.state_dir, record, "refused", ctx.now, cause="policy",
                            policy_code=sup["policy_code"],
                            control=_control("refused", "policy", about, sup["policy_code"],
                                             to=_control_to(ctx, _snapshot_key_id(ctx.state_dir,
                                                                                  record))))
    return _finish(ctx, record)


def supersede(ctx: Ctx, record: Dict[str, Any], *, policy_code: str, by: str,
              key_lost: bool = False) -> Dict[str, Any]:
    """decided -> refused, ONLY through `supersede.json`, and NEVER for a
    message already placed: the recorded recipient's notice is checked
    first, under the reservation's `notice_id` (verified, or read as data
    only when the decision key is lost). A notice present makes the record
    `done(placed)` with no supersession and no control."""
    sd = ctx.state_dir
    rel = record_dir_rel(record["owner"], record["key"])
    try:
        existing = peerbind.reopen_supersede(sd, rel, record_id=record["key"])
    except peerbind.RecoveryCorrupt as e:
        return set_hold(sd, record, "recovery_corrupt", e.reason, ctx.now)
    if existing is not None:
        return _refuse_superseded(ctx, record, existing)
    rt, idk = record["replay_ref"].split("/")
    res_raw = (_replay(sd) / rt / (idk + peerbind.RESERVATION_SUFFIX)).read_bytes()
    res = peerbind.parse_reservation(res_raw, None if key_lost else peerbind._decision_key(sd))
    decision, dec = peerbind.read_decision_data(sd, rel)
    present = _notice_present(ctx.cfg, dec["hosted_instance"], res["notice_id"])
    if present is None:
        return set_hold(sd, record, "recipient_gone", None, ctx.now)
    if present:
        return _done(ctx, record, disposed="placed", done_ts=format_utc_ts(ctx.now), retry=None)
    rec = peerbind.supersede_record(sd, record_id=record["key"], decision=decision,
                                    policy_code=policy_code, by=by, at=format_utc_ts(ctx.now))
    sup = peerbind.commit_supersede(sd, rel, rec, record_id=record["key"],
                                    decision_sha256=hashlib.sha256(decision).hexdigest())
    return _refuse_superseded(ctx, record, sup)


def _about(state_dir: Path, record: Mapping[str, Any]) -> Optional[str]:
    """The statement id a control notice is about, from the snapshot."""
    raw = read_snapshot(state_dir, record, SNAPSHOT_STATEMENT)
    if raw is None:
        return None
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    ident = doc.get("id") if isinstance(doc, dict) else None
    return ident if isinstance(ident, str) else None


def drop(ctx: Ctx, record: Dict[str, Any], *, by: str) -> Dict[str, Any]:
    """`router peer-decision drop <key>`, operator-only, the exit from key
    loss and nothing else (`decision_unrecoverable`):
    - a decided record whose decision no longer verifies is superseded
      (never when its notice is present: that is `done(placed)`);
    - a reserved record (no decision) whose reservation no longer verifies
      is refused, control pending; there is no decision to supersede.
    Anything else, a reserved record held on `key_runtime_changed` whose
    reservation verifies included, is refused and nothing is written."""
    sd = ctx.state_dir
    rel = record_dir_rel(record["owner"], record["key"])
    has_decision = (record_dir(sd, record["owner"], record["key"])
                    / peerbind.DECISION_FILE).exists()
    if record["state"] == "reserved" and not has_decision:
        rt, idk = record["replay_ref"].split("/")
        try:
            peerbind.reopen_reservation(sd, rt, idk, record_id=record["key"])
        except peerbind.RecoveryCorrupt as e:
            if e.reason != "mac":
                raise DropRefused(f"{record['key']}: the reservation is corrupt ({e.reason}), "
                                  "not unrecoverable") from None
        else:
            raise DropRefused(f"{record['key']}: the reservation verifies; nothing to drop")
        return _finish(ctx, transition(sd, record, "refused", ctx.now, cause="policy",
                                       policy_code=DECISION_UNRECOVERABLE,
                                       control=_control("refused", "policy", _about(sd, record),
                                                        DECISION_UNRECOVERABLE,
                                                        to=_control_to(ctx, _snapshot_key_id(
                                                            sd, record)))))
    if record["state"] not in ("decided", "reserved") or not has_decision:
        raise DropRefused(f"{record['key']}: {record['state']} with no unrecoverable decision")
    try:
        peerbind.reopen_decision(sd, rel, record_id=record["key"])
    except peerbind.RecoveryCorrupt as e:
        if e.reason != "mac":
            raise DropRefused(f"{record['key']}: the decision is corrupt ({e.reason}), "
                              "not unrecoverable") from None
    else:
        raise DropRefused(f"{record['key']}: the decision verifies; nothing to drop")
    if record["state"] == "reserved":
        record = transition(sd, record, "decided", ctx.now, decided_sticky=True)
    return supersede(ctx, record, policy_code=DECISION_UNRECOVERABLE, by=by, key_lost=True)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def _recount(state_dir: Path, token: str, old: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """The bookkeeping recomputed from the live stores. `settled_through`,
    the take and reserve seqs and every high-water NEVER fall below `old`'s
    (retention may have pruned what they cover); without `old` the frontier
    is the contiguous settled prefix of what is on disk."""
    state_dir = Path(state_dir)
    meta: Dict[str, Any] = {"v": 1, "take_seq": 0, "reserve_seq": 0, "settled_through": 0,
                            "roots": {}, "replay": None, "pending_op": None}
    states: Dict[int, str] = {}
    for child in sorted(state_dir.iterdir()):
        if (child / JOURNAL_DIR).is_dir():
            live, high, total, revs, seqs = _scan_root(state_dir, child.name)
            prev = (old or {}).get("roots", {}).get(child.name) or {}
            meta["roots"][child.name] = {"token": token, "live": live,
                                         "high_seq": max(high, prev.get("high_seq", 0)),
                                         "content_sum": str(total), "rev_total": revs}
            meta["take_seq"] = max(meta["take_seq"], high)
            root = child / JOURNAL_DIR
            for d in root.iterdir():
                if (d / RECORD).is_file():
                    rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
                    states[rec["take_seq"]] = rec["state"]
    rlive, rhigh, rtotal = _scan_replay(state_dir)
    prev_replay = (old or {}).get("replay") or {}
    meta["replay"] = {"token": token, "live": rlive,
                      "high_reserve_seq": max(rhigh, prev_replay.get("high_reserve_seq", 0)),
                      "content_sum": str(rtotal), "rev_total": 0}
    vacant = _vacant(state_dir)
    meta["take_seq"] = max([meta["take_seq"], (old or {}).get("take_seq", 0)] + list(vacant))
    meta["reserve_seq"] = max(rhigh, (old or {}).get("reserve_seq", 0))
    if old is not None:
        meta["settled_through"] = old["settled_through"]
    else:
        floor_seq = min(states) if states else meta["take_seq"] + 1
        s = 0
        while s + 1 <= meta["take_seq"] and (s + 1 < floor_seq or s + 1 in vacant
                                             or states.get(s + 1) in SETTLED_STATES):
            s += 1
        meta["settled_through"] = s
    return meta


def _old_meta(state_dir: Path) -> Optional[Dict[str, Any]]:
    try:
        return read_meta(state_dir)
    except (StoreAbsent, ValueError, peerclock.ClockUntrusted):
        return None


def rebuild_meta(state_dir: Path) -> Dict[str, Any]:
    """Recompute the bookkeeping from the live stores: ONLY after the
    operator recorded a bound B (`peerclock.record_bound`), whose floor is
    what protects everything the lost bookkeeping could have proved. The
    frontier is never lowered (`_recount`)."""
    state_dir = Path(state_dir)
    clock = peerclock.read(state_dir)
    if clock.bound_b is None:
        raise StoreRefused("the bookkeeping is rebuilt only under a recorded bound B")
    token = clock.store_token
    for child in sorted(state_dir.iterdir()):
        if (child / JOURNAL_DIR).is_dir():
            atomic_write(child / JOURNAL_DIR / WITNESS, token.encode("ascii"),
                         durable_root=state_dir)
    replay = state_dir / REPLAY_DIR
    replay.mkdir(exist_ok=True, mode=0o700)
    atomic_write(replay / WITNESS, token.encode("ascii"), durable_root=state_dir)
    meta = _recount(state_dir, token, _old_meta(state_dir))
    _write_meta(state_dir, meta)
    return meta


def _rebase_after_loss(state_dir: Path, meta: Mapping[str, Any]) -> None:
    """Once the floor protecting a detected LOSS is persisted: the
    bookkeeping is rebased to the live stores (a lost root dropped, each
    seq lost below the top marked vacant), so the loss is accounted for
    once and the next start is clean. Never after an AHEAD finding: that
    closes admission, and only a bound B reopens it."""
    state_dir = Path(state_dir)
    carried = set()
    for child in sorted(state_dir.iterdir()):
        root = child / JOURNAL_DIR
        for d in root.iterdir() if root.is_dir() else ():
            if (d / RECORD).is_file():
                carried.add(json.loads((d / RECORD).read_text(encoding="utf-8"))["take_seq"])
    vacant = _vacant(state_dir)
    for seq in range(meta["settled_through"] + 1, meta["take_seq"] + 1):
        if seq not in carried and seq not in vacant:
            _mark_vacant(state_dir, seq)
    token = meta["replay"]["token"]
    # The witnesses are part of what was found lost: each surviving journal
    # root's and the replay store's is restored to the bookkeeping token
    # (durably), so the same loss is not found again at the next start.
    for child in sorted(state_dir.iterdir()):
        if (child / JOURNAL_DIR).is_dir():
            _restore_witness(state_dir, child / JOURNAL_DIR / WITNESS, token)
    replay = state_dir / REPLAY_DIR
    replay.mkdir(exist_ok=True, mode=0o700)
    _restore_witness(state_dir, replay / WITNESS, token)
    _write_meta(state_dir, _recount(state_dir, token, meta))


def _restore_witness(state_dir: Path, path: Path, token: str) -> None:
    try:
        if path.read_text(encoding="ascii") == token:
            return
    except (OSError, UnicodeDecodeError):
        pass
    atomic_write(path, token.encode("ascii"), durable_root=Path(state_dir))


def apply_window(state_dir: Path, now: datetime, dc: Any) -> Optional["peerclock.Clock"]:
    """The configured window (`delegation.windows`) made the clock's, under
    the drain lock, through `peerclock.change_window`: a narrowing takes
    effect at once, a wider P raises the floor to the bound in force, and
    every F joins the history. None when there is no trusted clock."""
    try:
        clock = peerclock.read(state_dir)
    except peerclock.ClockUntrusted:
        return None
    if dc is None or (clock.p, clock.f) == (dc.window_p, dc.window_f):
        return clock
    logger.info("peer clock: window changed from P=%s F=%s to P=%s F=%s",
                clock.p, clock.f, dc.window_p, dc.window_f)
    return peerclock.change_window(state_dir, now, p=dc.window_p, f=dc.window_f)


def startup(state_dir: Path, now: datetime) -> Dict[str, Any]:
    """Run once at start, under the drain lock, before any drain. Never
    opens admission; only `init_store` and a bound B do. Returns a report
    for status: {"admission", "why", "problems", "digests_repaired"}."""
    state_dir = Path(state_dir)
    try:
        clock = peerclock.read(state_dir)
    except peerclock.ClockUntrusted as e:
        found = _artefacts(state_dir)
        return {"admission": "closed",
                "why": "uninitialised" if not found else "clock_untrusted",
                "problems": [str(e)] if found else [], "digests_repaired": 0}
    try:
        problems = reconcile(state_dir)
    except StoreAbsent:
        clock = peerclock.close(state_dir, clock, "store bookkeeping absent")
        return {"admission": "closed", "why": "store_bookkeeping_absent", "problems": [],
                "digests_repaired": 0}
    why = None
    if any(p.startswith(BEHIND) for p in problems):
        # The clock file is older than the stores: its H proves nothing.
        clock = peerclock.close(state_dir, clock, "clock older than the stores")
        why = "clock_behind_stores"
    elif problems:
        clock = peerclock.raise_floor_for_loss(state_dir, now)
        _rebase_after_loss(state_dir, read_meta(state_dir))
        why = "store_loss"
    repaired = repair_digests(state_dir)
    markers = repair_done_markers(state_dir, now)
    clock = peerclock.advance(state_dir, now)
    return {"admission": clock.admission, "why": why, "problems": problems,
            "digests_repaired": repaired, "markers_repaired": markers}


def status_doc(state_dir: Path, now: datetime,
               startup_report: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """The `peer_store` section of status: admission and why, H, the floor,
    the bound B (its evidence cut to 80 characters), the warnings, the
    frontier, and every held record and transient retry with its age. Read
    only; never repairs."""
    state_dir = Path(state_dir)
    why = (startup_report or {}).get("why")
    try:
        clock = peerclock.read(state_dir)
    except peerclock.ClockUntrusted:
        return {"admission": "closed",
                "why": why or ("uninitialised" if not _artefacts(state_dir) else
                               "clock_untrusted")}
    doc: Dict[str, Any] = {"admission": clock.admission, "why": why,
                           "H": format_utc_ts(clock.H),
                           "floor": format_utc_ts(clock.floor) if clock.floor else None,
                           "warnings": ["clock_behind_h"] if peerclock.behind_h(clock, now) else []}
    if clock.bound_b:
        b = clock.bound_b
        doc["bound_b"] = {"B": b["B"], "by": b["by"], "recorded_at": b["recorded_at"],
                          "evidence": b["evidence"][:80]}
    try:
        meta = read_meta(state_dir)
    except (StoreAbsent, ValueError):
        return doc
    doc["take_seq"], doc["settled_through"] = meta["take_seq"], meta["settled_through"]
    holds, retries = [], []
    for owner in sorted(meta["roots"]):
        root = journal_root(state_dir, owner)
        for d in sorted(root.iterdir()) if root.is_dir() else ():
            try:
                rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for what, out in (("hold", holds), ("retry", retries)):
                item = rec.get(what)
                if not item:
                    continue
                since = parse_utc_ts(item["since"])
                out.append({"key": rec["key"], "take_seq": rec["take_seq"],
                            "state": rec["state"],
                            "reason": item.get("reason") or item.get("retry"),
                            "detail": item.get("detail"),
                            "age_s": int((now - since).total_seconds()) if since else None})
    doc["holds"] = sorted(holds, key=lambda h: h["take_seq"])
    doc["retries"] = sorted(retries, key=lambda h: h["take_seq"])
    return doc


# ---------------------------------------------------------------------------
# Operator acts (the CLI verbs; the caller holds the drain lock)
# ---------------------------------------------------------------------------

OPERATOR_AUDIT = "operator.audit.jsonl"


def _audit(state_dir: Path, act: str, now: datetime, **fields: Any) -> None:
    from . import audit
    line = json.dumps(dict(fields, ts=format_utc_ts(now), act=act, by=peerclock.operator_by()),
                      sort_keys=True).encode("utf-8") + b"\n"
    audit.append_router_line(Path(state_dir), REPLAY_DIR, OPERATOR_AUDIT, line)


def peer_roots(cfg: Any) -> List[Path]:
    return [i.peer_root for _n, i in sorted(cfg.instances.items()) if i.peer_root is not None]


def operator_init(cfg: Any, now: datetime, *, acknowledge_surviving: Optional[str]
                  ) -> Dict[str, Any]:
    """`router peer-store init --never-admitted`."""
    dc = cfg.delegation
    p, f = (dc.window_p, dc.window_f) if dc is not None else (peerclock.P_DEFAULT,
                                                             peerclock.F_DEFAULT)
    hop_root = Path(cfg.hop.root) if getattr(cfg, "hop", None) is not None else None
    clock = init_store(cfg.state_dir, now, hop_root=hop_root, peer_roots=peer_roots(cfg),
                       acknowledge_surviving=acknowledge_surviving, p=p, f=f)
    _audit(cfg.state_dir, "peer-store init --never-admitted", now,
           acknowledge_surviving=acknowledge_surviving)
    return {"admission": clock.admission, "H": format_utc_ts(clock.H), "p": p, "f": f}


def operator_declare_restored(state_dir: Path, now: datetime, *, evidence: str
                              ) -> Dict[str, Any]:
    """`router peer-store declare-restored --evidence`: after any restore of
    `state_dir`, H proves nothing; admission closes until a bound B."""
    if not (isinstance(evidence, str) and evidence.strip()):
        raise StoreRefused("evidence is required")
    clock = peerclock.close(state_dir, peerclock.read(state_dir), "declared restored")
    _audit(state_dir, "peer-store declare-restored", now, evidence=evidence)
    return {"admission": clock.admission}


def observed_times(state_dir: Path, hop_root: Optional[Path],
                   reply_window_s: Optional[int] = None) -> List[Tuple[datetime, str]]:
    """Every receiver time this router can see, each with its source (file
    and field): the bound B's mechanical lower bound. Among them, every
    in-flight record's `written_ts` (an agent's or the runtime control
    tree's: the exact time a signed request was begun), and, with
    `reply_window_s`, each issued peer-ledger record's issue time derived as
    `expires_at - reply_window_s` (it understates the issue time if the
    window has grown since, which only lowers this bound)."""
    state_dir = Path(state_dir)
    seen: List[Tuple[datetime, str]] = []

    def add(value: Any, source: str) -> None:
        t = parse_utc_ts(value) if isinstance(value, str) else None
        if t is not None:
            seen.append((t, source))

    try:
        add(format_utc_ts(peerclock.read(state_dir).H), f"{peerclock.CLOCK_FILE} H")
    except peerclock.ClockUntrusted:
        pass
    for child in sorted(state_dir.iterdir()) if state_dir.is_dir() else ():
        root = child / JOURNAL_DIR
        for d in sorted(root.iterdir()) if root.is_dir() else ():
            try:
                rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for field in ("first_seen_ts", "state_ts", "done_ts"):
                add(rec.get(field), f"{d / RECORD} {field}")
        log = child / "audit" / "log.jsonl"
        if log.is_file():
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    add(json.loads(line).get("ts"), f"{log} ts")
                except ValueError:
                    continue
    from . import inflight as inflight_mod
    from . import peerlane
    for pattern in (f"*/{inflight_mod.INFLIGHT_DIR}/*.json",
                    f"*/*/{inflight_mod.INFLIGHT_DIR}/*.json"):
        for f in sorted(state_dir.glob(pattern)):
            try:
                add(json.loads(f.read_bytes()).get("written_ts"), f"{f} written_ts")
            except (OSError, ValueError, AttributeError):
                continue
    if reply_window_s is not None:
        for f in sorted(state_dir.glob(f"*/{peerlane.PEER_LEDGER_DIR}/*.json")):
            try:
                doc = json.loads(f.read_bytes())
            except (OSError, ValueError):
                continue
            expires = parse_utc_ts(doc.get("expires_at")) if isinstance(doc, dict) else None
            if expires is not None and doc.get("direction") == "issued":
                add(format_utc_ts(expires - timedelta(seconds=reply_window_s)),
                    f"{f} issued (expires_at - window)")
    replay = state_dir / REPLAY_DIR
    for f in sorted(replay.glob("*/*" + DONE_SUFFIX)) if replay.is_dir() else ():
        try:
            add(json.loads(f.read_bytes()).get("done_ts"), f"{f} done_ts")
        except ValueError:
            continue
    for f in sorted(replay.glob("*/*" + peerbind.RESERVATION_SUFFIX)) if replay.is_dir() else ():
        try:
            add(json.loads(f.read_bytes()).get("ts"), f"{f} ts")
        except ValueError:
            continue
    oplog = replay / OPERATOR_AUDIT
    if oplog.is_file():
        for line in oplog.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                add(json.loads(line).get("ts"), f"{oplog} ts")
            except ValueError:
                continue
    if hop_root is not None:
        for f in sorted((Path(hop_root) / ".disposed").glob("*/*")):
            try:
                add(json.loads(f.read_bytes()).get("disposed_at"), f"{f} disposed_at")
            except (OSError, ValueError):
                continue
    return seen


def operator_bound(cfg: Any, now: datetime, *, at: datetime, evidence: str,
                   not_from_wall_clock: bool) -> Dict[str, Any]:
    """`router peer-bound --at <B> --evidence <text> [--b-not-from-wall-clock]`:
    the bound recorded (refused below any receiver time RL can see), then
    the store's bookkeeping rebuilt from the live stores under its floor."""
    hop_root = Path(cfg.hop.root) if getattr(cfg, "hop", None) is not None else None
    clock = peerclock.record_bound(cfg.state_dir, now, at=at, evidence=evidence,
                                   not_from_wall_clock=not_from_wall_clock,
                                   observed=observed_times(
                                       cfg.state_dir, hop_root,
                                       reply_window_s=getattr(cfg, "peer_reply_window_seconds",
                                                              None)))
    rebuild_meta(cfg.state_dir)
    _audit(cfg.state_dir, "peer-bound", now, B=format_utc_ts(at), evidence=evidence,
           not_from_wall_clock=bool(not_from_wall_clock))
    return {"admission": clock.admission, "floor": format_utc_ts(clock.floor),
            "H": format_utc_ts(clock.H)}


class _NoEffects:
    """The operator verbs' effects: a refusal publishes nothing, and the
    intake entry is removed (or, for a host intake, its tombstone committed)
    by the next poll's settle pass."""

    def dispose(self, record):
        if record["intake"] in HOST_INTAKES:
            raise DisposeDeferred(record["key"])

    def quarantine(self, record):
        raise StoreRefused("an operator verb never writes a quarantine item here")

    def remove(self, record):
        return None


def _find(state_dir: Path, key: str) -> Dict[str, Any]:
    if not _KEY_RE.fullmatch(key):
        raise StoreRefused("the key is 64 lower-case hex")
    for child in sorted(Path(state_dir).iterdir()):
        if (child / JOURNAL_DIR / key / RECORD).is_file():
            return read_record(state_dir, child.name, key)
    raise StoreRefused(f"no candidate record {key}")


def operator_drop(cfg: Any, now: datetime, *, key: str, evidence: str) -> Dict[str, Any]:
    """`router peer-decision drop <key> --evidence <text>` (`drop`)."""
    if not (isinstance(evidence, str) and evidence.strip()):
        raise StoreRefused("evidence is required")
    record = _find(cfg.state_dir, key)
    ctx = Ctx(state_dir=cfg.state_dir, cfg=cfg, delegation=None, hooks=absent_hooks(), now=now,
              clock=peerclock.read(cfg.state_dir), view=None, effects=_NoEffects(),
              retired=lambda _r: False)
    try:
        out = drop(ctx, record, by=peerclock.operator_by())
    except DisposeDeferred:
        out = read_record(cfg.state_dir, record["owner"], key)
        _audit(cfg.state_dir, "peer-decision drop", now, key=key, evidence=evidence,
               result=out["state"])
        return {"result": f"{out['state']}: {out.get('policy_code') or out.get('disposed')}, "
                          "tombstone committed by the next poll"}
    placed = out.get("disposed") == "placed"
    _audit(cfg.state_dir, "peer-decision drop", now, key=key, evidence=evidence,
           result="already_placed" if placed else "refused")
    if placed:
        rt, idk = out["replay_ref"].split("/")
        notice = peerbind.parse_reservation(
            (_replay(cfg.state_dir) / rt / (idk + peerbind.RESERVATION_SUFFIX)).read_bytes(),
            None)["notice_id"]
        return {"result": f"already placed: {notice}, marked done"}
    return {"result": f"refused: {DECISION_UNRECOVERABLE}, control pending"}


def operator_restore_key(cfg: Any, now: datetime, *, source: Path) -> Dict[str, Any]:
    """`router peer-decision restore-key --from <file>`: put the ORIGINAL
    decision key back. Refused unless no decision verifies under the
    current key and at least one verifies under the offered one."""
    sd = Path(cfg.state_dir)
    offered = Path(source).read_bytes()
    if len(offered) != peerbind.DECISION_KEY_BYTES:
        raise StoreRefused(f"a decision key is exactly {peerbind.DECISION_KEY_BYTES} bytes")
    decisions = []
    for child in sorted(sd.iterdir()):
        root = child / JOURNAL_DIR
        for d in sorted(root.iterdir()) if root.is_dir() else ():
            if (d / peerbind.DECISION_FILE).is_file():
                decisions.append((d.name, (d / peerbind.DECISION_FILE).read_bytes()))
    current = peerbind._decision_key(sd)

    def verifies(key: bytes, rid: str, raw: bytes) -> bool:
        try:
            peerbind._parse_record(raw, key, rid)
            return True
        except peerbind.RecoveryCorrupt:
            return False

    if any(verifies(current, rid, raw) for rid, raw in decisions):
        raise StoreRefused("a decision verifies under the current key: it is not lost")
    if not any(verifies(offered, rid, raw) for rid, raw in decisions):
        raise StoreRefused("no decision verifies under the offered key: it is not the original")
    atomic_write(sd / peerbind.DECISION_KEY_FILE, offered, durable_root=sd, mode=0o600)
    released = 0
    for child in sorted(sd.iterdir()):
        root = child / JOURNAL_DIR
        for d in sorted(root.iterdir()) if root.is_dir() else ():
            if not (d / RECORD).is_file():
                continue
            rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
            h = rec.get("hold") or {}
            if (h.get("reason"), h.get("detail")) == ("recovery_corrupt", "mac"):
                write_record(sd, dict(rec, hold=None))
                released += 1
    _audit(sd, "peer-decision restore-key", now, decisions=len(decisions), released=released)
    return {"restored": True, "decisions": len(decisions), "released": released}


# ---------------------------------------------------------------------------
# Retention (by analogy with O10: only the contiguous settled prefix)
# ---------------------------------------------------------------------------

#: How long a done record WITHOUT a reservation is kept, so a re-presented
#: intake id is still recognised: the ingress journal's horizon.
PRESENTATION_DAYS = 30


def _prune_targets(state_dir: Path, record: Mapping[str, Any]) -> Tuple[List[Path], Path]:
    """(replay files, digest first; the record directory) a prune removes."""
    files: List[Path] = []
    if record.get("replay_ref"):
        rt, idk = record["replay_ref"].split("/")
        d = _replay(state_dir) / rt
        res = d / (idk + peerbind.RESERVATION_SUFFIX)
        if res.is_file():
            doc = peerbind.parse_reservation(res.read_bytes(), None)
            files.append(_replay(state_dir) / DIGESTS_DIR / doc["statement_sha256"])
        files += [d / (idk + DONE_SUFFIX), res]
    return files, record_dir(state_dir, record["owner"], record["key"])


def _remove_targets(files: List[Path], rdir: Path) -> None:
    for f in files:                                     # the digest FIRST
        try:
            f.unlink()
            fsync_dir(f.parent)
        except FileNotFoundError:
            pass
    if rdir.exists():
        shutil.rmtree(rdir)
        fsync_dir(rdir.parent)


def _prune(state_dir: Path, meta: Dict[str, Any], record: Mapping[str, Any]) -> None:
    owner, key = record["owner"], record["key"]
    files, rdir = _prune_targets(state_dir, record)
    rsum = rlive = 0
    for f in files:
        if f.parent.name != DIGESTS_DIR and f.is_file():    # the index is not counted
            rsum -= contribution(f"{f.parent.name}/{f.name}", 0, f.read_bytes())
            rlive -= 1
    jsum = jrev = jlive = 0
    rec_path = rdir / RECORD
    if rec_path.is_file():
        rb = rec_path.read_bytes()
        rev = json.loads(rb)["rev"]
        jsum -= contribution(f"{key}/{RECORD}", rev, rb)
        jrev -= rev
        jlive -= 1
    for snap in sorted((rdir / SNAPSHOT_DIR).iterdir()) if (rdir / SNAPSHOT_DIR).is_dir() else ():
        if snap.name in SNAPSHOT_FILES and snap.is_file():
            jsum -= contribution(f"{key}/{SNAPSHOT_DIR}/{snap.name}", 0, snap.read_bytes())
            jlive -= 1
    deltas = [_delta("root", owner, jsum, jrev, jlive), _delta("replay", None, rsum, 0, rlive)]
    meta["pending_op"] = {"op": "prune", "owner": owner, "key": key,
                          "replay_ref": record.get("replay_ref"), "delta": deltas}
    _write_meta(state_dir, meta)
    _remove_targets(files, rdir)
    for d in deltas:
        _apply(meta, d)
    meta["pending_op"] = None
    _write_meta(state_dir, meta)


def sweep(state_dir: Path, now: datetime, *, enabled: bool,
          hop_root: Optional[Path] = None) -> Dict[str, int]:
    """Prune what retention allows: a `done` record at or below the
    settled-through frontier, with its replay record once H > ts + P + F,
    or, without a reservation, once its re-presentation horizon has passed.
    Never a reserved, decided or held record; never past the frontier.
    `enabled` is `delegation.retention.sweep` (off by default)."""
    out = {"pruned": 0}
    if not enabled:
        return out
    state_dir = Path(state_dir)
    meta = read_meta(state_dir)
    _require_clear(meta)
    clock = peerclock.read(state_dir)
    settled = meta["settled_through"]
    horizon = timedelta(seconds=clock.p + clock.f)
    for owner in sorted(meta["roots"]):
        root = journal_root(state_dir, owner)
        for d in sorted(root.iterdir()) if root.is_dir() else ():
            if not (d.is_dir() and _KEY_RE.fullmatch(d.name) and (d / RECORD).is_file()):
                continue
            rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
            if rec["state"] != "done" or rec["take_seq"] > settled:
                continue
            if rec["intake"] in HOST_INTAKES and (hop_root is None or os.path.lexists(
                    Path(hop_root) / ".disposed" / rec["intake"] / rec["entry_id"])):
                continue        # kept while its tombstone exists (or cannot be checked)
            if rec["intake"] not in HOST_INTAKES and not rec.get("removed"):
                continue        # kept until its entry's removal succeeded
            if rec.get("control") and not rec["control"].get("sent"):
                continue        # kept while its control notice is pending
            if rec.get("replay_ref"):
                rt, idk = rec["replay_ref"].split("/")
                res = _replay(state_dir) / rt / (idk + peerbind.RESERVATION_SUFFIX)
                ts = parse_utc_ts(peerbind.parse_reservation(res.read_bytes(), None)["ts"]) \
                    if res.is_file() else None
                if ts is None or not clock.H > ts + horizon:
                    continue
            else:
                done = parse_utc_ts(rec.get("done_ts"))
                if done is None or not now > done + timedelta(days=PRESENTATION_DAYS):
                    continue
            _prune(state_dir, meta, rec)
            out["pruned"] += 1
    return out


# ---------------------------------------------------------------------------
# The inbound poll: each generation's candidates/, through the reader port
# ---------------------------------------------------------------------------

#: PROCESS state: the listing cursor per (state_dir, logical_id, gen), so a
#: page full of held candidates never starves the entries after it.
_CURSORS: Dict[Tuple[str, str, str], Optional[str]] = {}
#: PROCESS state: the state_dirs this process has polled once (the first
#: pass re-tries `unpublishable` holds and runs the full discovery scan).
_POLLED: set = set()


#: A candidate this router FIRST observes in a generation that is not
#: current: quarantined to that generation, never placed into a later one.
LATE_INBOUND = "late_inbound"


class TreeEffects:
    """The effects for one generation's `candidates/`: a quarantine item in
    that generation (cause `cold_fleet_mail`, the profile's cause as
    evidence), and, after `done`, the entry's removal through the plugin's
    remover. A removal that does not succeed is retried by the next poll,
    which finds the entry again with its record `done`."""

    def __init__(self, cfg: Any, logical_id: str, gen: str, link: str, remover: Any):
        self.cfg, self.logical_id, self.gen, self.link, self.remover = (
            cfg, logical_id, gen, link, remover)
        self.removed: List[str] = []
        self.remove_held: List[str] = []

    def quarantine(self, record: Mapping[str, Any]) -> None:
        from . import ingress, quarantine
        snap = read_snapshot(self.cfg.state_dir, record, SNAPSHOT_CANDIDATE) or b""
        if self.link is None:
            raise peerbind.RecoveryCorrupt("quarantine", "no link pin for the generation")
        late = record["cause"] == LATE_INBOUND
        ingress.write_quarantine_item(
            Path(self.cfg.state_dir), self.logical_id, self.gen, "candidate", self.link,
            record["entry_id"],
            quarantine.CAUSE_LATE_INBOUND if late else quarantine.CAUSE_COLD_FLEET_MAIL,
            extra_evidence={"peer_cause": record["cause"],
                            "candidate_sha256": hashlib.sha256(snap).hexdigest()})

    def dispose(self, record: Mapping[str, Any]) -> None:
        """A tree candidate has no tombstone: its removal follows `done`."""

    def remove(self, record: Mapping[str, Any]) -> None:
        if self.remover is None:
            self.remove_held.append(record["entry_id"])
            return
        try:
            got = self.remover.remove_entry("candidate", record["entry_id"])
        except Exception:  # noqa: BLE001 -- a retry is always safe after done
            logger.warning("peer candidate %s: removal failed; retried next poll",
                           record["key"], exc_info=True)
            self.remove_held.append(record["entry_id"])
            return
        if got in ("removed", "absent"):
            self.removed.append(record["entry_id"])
            return True
        self.remove_held.append(record["entry_id"])
        return None


def _viewer(delegation: Any) -> Any:
    """The `Ctx.view` for this poll: the plugin's `candidate_view`, or
    `ViewUnavailable` when the plugin does not offer it (candidates hold)."""
    view = delegation.candidate_view if delegation is not None else None

    def view_of(raw: bytes) -> Any:
        if view is None:
            raise ViewUnavailable()
        return view(raw)
    return view_of


#: An entry-level anomaly the reader reports by a `.reason` (another owner,
#: a missing layout): the entry is held, counted under that reason, and the
#: rest of the page proceeds.
ENTRY_ANOMALY_REASONS = ("owner", "layout")


def _entry_failed(count: Any, where: str, exc: BaseException) -> None:
    reason = getattr(exc, "reason", None)
    if type(reason) is str and reason in ENTRY_ANOMALY_REASONS:
        count(f"held_{reason}")
        logger.warning("signed candidates: %s held (%s): %s", where, reason, exc)
    else:
        count("errored")
        logger.exception("signed candidates: %s errored; isolated, the page continues", where)


def _poll_tree_entry(ctx: "Ctx", effects: "TreeEffects", reader: Any, count: Any, *,
                     logical_id: str, gen: str, entry_id: str, now: datetime,
                     read_refused: Tuple[type, ...], current: bool = True,
                     touched: Optional[set] = None) -> None:
    state_dir = ctx.state_dir
    key = record_key(intake="candidates", gen=gen, owner=logical_id, entry_id=entry_id)
    if touched is not None:
        touched.add(key)
    if (record_dir(state_dir, logical_id, key) / RECORD).is_file():
        record = read_record(state_dir, logical_id, key)
        if record["state"] == "done":
            _settle(ctx, record)
            count("settled_again")
            return
    else:
        try:
            raw = reader.port.read_entry("candidate", entry_id)
        except FileNotFoundError:
            count("gone")
            return
        except (OSError,) + tuple(read_refused):
            count("read_refused")
            return
        key, _seq = take(state_dir, logical_id, intake="candidates", gen=gen,
                         entry_id=entry_id, raw=bytes(raw), now=now)
        record = read_record(state_dir, logical_id, key)
        count("taken")
        if not current:
            # First observed in a generation that is no longer current.
            _finish(ctx, transition(state_dir, record, "mail", now, cause=LATE_INBOUND))
            count(LATE_INBOUND)
            return
    out = evaluate(ctx, record)
    count(f"state_{out['state']}" if not out.get("hold") else f"held_{out['hold']['reason']}")


def _pass_hooks(cfg: Any, *, delegation: Any, state_dir: Path, now: datetime, clock: Any,
                profile_factory: Any) -> DecideHooks:
    """This pass's hooks: its context built from this pass's own objects (the
    clock the pass fixed, its `now`), then `profile_factory(context)` (None:
    `peerpolicy.production_profile`, the router's), whose profile must hold
    exactly that context, then `peerpolicy.decide_hooks`."""
    from . import peerpolicy
    factory = peerpolicy.production_profile if profile_factory is None else profile_factory
    hctx = peerpolicy.hook_context(cfg, delegation=delegation, state_dir=state_dir, now=now,
                                   clock=clock)
    profile = factory(hctx)
    if getattr(profile, "context", None) is not hctx:
        raise TypeError("profile_factory: the profile must hold the context it was given")
    return peerpolicy.decide_hooks(profile)


def poll_generation(cfg: Any, *, delegation: Any, clock: "peerclock.Clock",
                    now: datetime, logical_id: str, gen: str, link: str, reader: Any,
                    remover: Any, retired: Any, limit: int = 256,
                    read_refused: Tuple[type, ...] = (), first_pass: bool = False,
                    current: bool = True, touched: Optional[set] = None,
                    profile_factory: Any = None) -> Dict[str, int]:
    """One listing page of a generation's `candidates/`: each entry taken
    once (its bytes read once, into the snapshot) and evaluated; an entry
    whose record is `done` is settled again (its removal retried). The
    hooks are built here, over this pass's clock and `now`
    (`_pass_hooks`)."""
    state_dir = Path(cfg.state_dir)
    counts: Dict[str, int] = {}

    def count(what: str) -> None:
        counts[what] = counts.get(what, 0) + 1

    effects = TreeEffects(cfg, logical_id, gen, link, remover)
    view_of = _viewer(delegation)
    hooks = _pass_hooks(cfg, delegation=delegation, state_dir=state_dir, now=now, clock=clock,
                        profile_factory=profile_factory)
    ctx = Ctx(state_dir=state_dir, cfg=cfg, delegation=delegation, hooks=hooks, now=now,
              clock=clock, view=view_of, effects=effects, retired=retired, first_pass=first_pass)
    ckey = (str(state_dir), logical_id, gen)
    ids, truncated = reader.port.list_entries("candidate", limit=limit, after=_CURSORS.get(ckey))
    _CURSORS[ckey] = ids[-1] if (truncated and ids) else None
    for entry_id in ids:
        try:
            _poll_tree_entry(ctx, effects, reader, count, logical_id=logical_id, gen=gen,
                             entry_id=entry_id, now=now, read_refused=read_refused,
                             current=current, touched=touched)
        except StoreBlocked:
            raise
        except Exception as e:  # noqa: BLE001 -- one bad entry never wedges the page
            _entry_failed(count, f"{logical_id}/{gen} candidate {entry_id!r}", e)
    counts["removed"] = len(effects.removed)
    counts["remove_held"] = len(effects.remove_held)
    return counts


def poll(cfg: Any, runtime: Any, report: Any, *, delegation: Any, now: datetime,
         profile_factory: Any = None) -> Dict[str, Any]:
    """One poll's signed-candidate pass, under the drain lock, ONLY with
    `delegation.inbound`: H advanced first, then every identity's every
    generation's `candidates/` (`poll_generation`, each isolated), then the
    frontier and, when configured, the sweep. Without a trustworthy clock
    nothing is taken: candidates stay in their intake."""
    from . import generations as generations_mod
    from . import hoplink as hoplink_mod
    from . import ingress
    out: Dict[str, Any] = {}
    dc = cfg.delegation
    if dc is None or not dc.inbound or cfg.hop is None:
        return out
    try:
        apply_window(cfg.state_dir, now, dc)
        clock = peerclock.advance(cfg.state_dir, now)
    except peerclock.ClockUntrusted:
        out["held"] = "clock_untrusted"
        return out
    try:
        read_meta(cfg.state_dir)
    except (StoreAbsent, ValueError):
        out["held"] = "store_uninitialised"
        return out
    fsops = runtime.fsops
    read_refused = tuple(c for c in (getattr(fsops, "UnsafeRead", None),) if c)
    first = str(cfg.state_dir) not in _POLLED
    touched: set = set()
    for ident in ingress.identities(cfg, report):
        lid = ident["logical_id"]
        try:
            doc = generations_mod.read_doc(Path(cfg.state_dir), lid)
        except generations_mod.GenerationHeld:
            continue
        if doc is None:
            continue
        for g in doc["gens"]:
            gen = g["gen"]
            label = f"{lid}/{gen}"
            link = ingress.pump_link(cfg, lid, gen)
            if link is None:
                continue
            try:
                reader = hoplink_mod.reader_for(runtime, cfg, lid, gen)
            except hoplink_mod.HopHold as e:
                out[label] = {e.reason: 1}
                continue
            try:
                remover = hoplink_mod.remover_for(runtime, cfg, lid, gen)
            except hoplink_mod.HopHold:
                remover = None
            try:
                out[label] = poll_generation(
                    cfg, delegation=delegation, clock=clock, now=now,
                    logical_id=lid, gen=gen, link=link, reader=reader, remover=remover,
                    retired=lambda r: hoplink_mod._is_retired(runtime, cfg, r["owner"], r["gen"]),
                    read_refused=read_refused, first_pass=first,
                    current=gen == doc["current"], touched=touched,
                    profile_factory=profile_factory)
            except StoreBlocked:
                logger.error("peer store blocked: an operation is unreconciled; nothing more "
                             "is taken until the next start")
                out[label] = {"store_blocked": 1}
                return out
            except Exception:
                logger.exception("signed candidates %s: isolated, continuing", label)
                out[label] = {"errored": 1}
    for intake in HOST_INTAKES:
        try:
            out[intake] = poll_host(cfg, fsops, delegation=delegation, clock=clock,
                                    now=now, intake=intake, first_pass=first,
                                    touched=touched, profile_factory=profile_factory)
        except DisposedUnavailable as e:
            logger.error("signed candidates %s: not taken: %s", intake, e)
            out[intake] = {"held_disposed_unavailable": 1}
        except StoreBlocked:
            logger.error("peer store blocked: an operation is unreconciled; nothing more "
                         "is taken until the next start")
            out[intake] = {"store_blocked": 1}
            return out
        except Exception:
            logger.exception("signed candidates %s: isolated, continuing", intake)
            out[intake] = {"errored": 1}
    try:
        out["recovered"] = recover(cfg, runtime, delegation=delegation, clock=clock,
                                   now=now, first_pass=first, skip=touched,
                                   profile_factory=profile_factory)
    except StoreBlocked:
        out["recovered"] = {"store_blocked": 1}
        return out
    _POLLED.add(str(cfg.state_dir))
    advance_frontier(cfg.state_dir)
    out["swept"] = sweep(cfg.state_dir, now, enabled=dc.retention_sweep,
                         hop_root=Path(cfg.hop.root))
    return out


# ---------------------------------------------------------------------------
# Host intakes (.unresolved/, .control/) and their disposal tombstones
# ---------------------------------------------------------------------------
#
# A host-intake candidate is taken like a tree one, owned by `_host`, with
# no generation. It is disposed of by a TOMBSTONE, `<hop_root>/.disposed/
# <intake>/<id>`, committed with `commit_durable` from the bytes frozen in
# its record when its disposition was recorded, BEFORE the record is
# `done`; the downstream runtime removes the entry on a valid tombstone,
# and this router never does. The record stays `done` while its tombstone
# exists; the tombstone is removed once a complete listing taken after it
# was committed no longer shows the entry.

TOMBSTONE_MODE = 0o640
#: PROCESS state: per (fsops, intake), the pinned `.disposed/<intake>/` and
#: its `.stage/`, opened once (`disposed_dirs`).
_DISPOSED: Dict[Tuple[int, str], Tuple[int, int]] = {}


class DisposedUnavailable(Exception):
    """`.disposed/<intake>/` or its stage is missing or wrong: host-intake
    candidates are not taken (nothing could be disposed of)."""


def disposed_dirs(fsops: Any, hop_root: Path, intake: str) -> Tuple[int, int]:
    """(dest_fd, stage_fd) for `.disposed/<intake>/`: the deploy's directory,
    descended without following a link, and its writer-private `.stage/`,
    created and checked (`fsops.open_disposed_stage_dir`). Cached; a stale
    cached binding is reopened."""
    key = (id(fsops), intake)
    cached = _DISPOSED.get(key)
    if cached is not None:
        try:
            fsops.binding(cached[0])
            fsops.binding(cached[1])
            return cached
        except Exception:  # noqa: BLE001 -- stale: reopen below
            _DISPOSED.pop(key, None)
    try:
        root = fsops.open_root_nofollow(str(hop_root))
        dest = fsops.descend_pinned(root, f".disposed/{intake}")
        if dest is None:
            raise DisposedUnavailable(f".disposed/{intake} is missing (the deploy creates it)")
        stage = fsops.open_disposed_stage_dir(dest)
    except DisposedUnavailable:
        raise
    except Exception as e:  # noqa: BLE001 -- any binding failure refuses
        raise DisposedUnavailable(f".disposed/{intake}: {type(e).__name__}: {e}") from None
    _DISPOSED[key] = (dest, stage)
    return dest, stage


class HostEffects:
    """The effects for a host intake: no quarantine item (the tombstone
    carries the disposition), the tombstone committed before `done`, and no
    removal (the downstream runtime's, on the tombstone)."""

    def __init__(self, fsops: Any, hop_root: Path, intake: str):
        self.fsops, self.hop_root, self.intake = fsops, hop_root, intake
        self.committed: List[str] = []

    def quarantine(self, record: Mapping[str, Any]) -> None:
        return None

    def dispose(self, record: Mapping[str, Any]) -> None:
        frozen = record.get("tombstone")
        if not isinstance(frozen, str):
            raise peerbind.RecoveryCorrupt("tombstone", "no frozen tombstone in the record")
        dest, stage = disposed_dirs(self.fsops, self.hop_root, self.intake)
        self.fsops.commit_durable(stage, dest, record["entry_id"], frozen.encode("ascii"),
                                  TOMBSTONE_MODE)
        self.committed.append(record["entry_id"])

    def remove(self, record: Mapping[str, Any]) -> None:
        return None


def _host_entries(intake_dir: Path) -> Tuple[List[Tuple[str, Optional[bytes]]], set, bool]:
    """(entries, names, complete) for a host intake. `entries` is every
    32-hex entry whose `candidate.json` was read (with no link followed) or
    is in flight (absent, or caught at two links), as (id, bytes or None).
    `names` is EVERY 32-hex name the listing showed, read or not: an entry
    that could not be opened or read is still there. `complete` is False
    when the intake could not be listed, is missing (more likely a mount or
    deploy fault than an empty intake), or any entry could not be read: no
    tombstone is pruned on such a listing."""
    from . import quarantine
    out: List[Tuple[str, Optional[bytes]]] = []
    names: set = set()
    try:
        c_fd = quarantine._open_dir(str(intake_dir))
    except OSError:
        return out, names, False
    complete = True
    try:
        for entry in sorted(os.listdir(c_fd)):
            if entry == quarantine.STAGE_NAME or not re.fullmatch(r"[0-9a-f]{32}", entry):
                continue
            names.add(entry)
            try:
                d_fd = quarantine._open_dir(entry, c_fd)
            except OSError:
                complete = False
                continue
            try:
                raw, _st = quarantine.read_pinned(d_fd, "candidate.json",
                                                  quarantine.CANDIDATE_MAX_BYTES)
                out.append((entry, raw))
            except quarantine.Missing:
                out.append((entry, None))
            except quarantine.Linked as e:
                if e.nlink == 2:
                    out.append((entry, None))
                else:
                    complete = False
            except (quarantine.Damaged, OSError):
                complete = False
            finally:
                os.close(d_fd)
    finally:
        os.close(c_fd)
    return out, names, complete


def _poll_host_entry(ctx: "Ctx", effects: "HostEffects", count: Any, *, intake: str,
                     entry_id: str, raw: Optional[bytes], now: datetime,
                     touched: Optional[set] = None) -> None:
    state_dir = ctx.state_dir
    key = record_key(intake=intake, gen="", owner=HOST_OWNER, entry_id=entry_id)
    if touched is not None:
        touched.add(key)
    if (record_dir(state_dir, HOST_OWNER, key) / RECORD).is_file():
        record = read_record(state_dir, HOST_OWNER, key)
        if record["state"] == "done":
            effects.dispose(record)          # idempotent: exists_same
            _settle(ctx, record)             # the replay marker, if a crash left it
            count("disposed_again")
            return
    elif raw is None:
        count("in_flight")
        return
    else:
        key, _seq = take(state_dir, HOST_OWNER, intake=intake, gen="", entry_id=entry_id,
                         raw=raw, now=now)
        record = read_record(state_dir, HOST_OWNER, key)
        count("taken")
    out = evaluate(ctx, record)
    count(f"state_{out['state']}" if not out.get("hold") else f"held_{out['hold']['reason']}")


def poll_host(cfg: Any, fsops: Any, *, delegation: Any,
              clock: "peerclock.Clock", now: datetime, intake: str,
              first_pass: bool = False, touched: Optional[set] = None,
              profile_factory: Any = None) -> Dict[str, int]:
    """One pass over a host intake: each committed entry taken once and
    evaluated; a `done` record's tombstone committed again if missing; then,
    after a complete listing, the tombstones of entries no longer listed
    removed."""
    from . import quarantine
    state_dir = Path(cfg.state_dir)
    hop_root = Path(cfg.hop.root)
    counts: Dict[str, int] = {}

    def count(what: str) -> None:
        counts[what] = counts.get(what, 0) + 1

    disposed_dirs(fsops, hop_root, intake)     # nothing is taken that could not be disposed of
    effects = HostEffects(fsops, hop_root, intake)
    view_of = _viewer(delegation)
    hooks = _pass_hooks(cfg, delegation=delegation, state_dir=state_dir, now=now, clock=clock,
                        profile_factory=profile_factory)
    ctx = Ctx(state_dir=state_dir, cfg=cfg, delegation=delegation, hooks=hooks, now=now,
              clock=clock, view=view_of, effects=effects, retired=lambda _r: False,
              first_pass=first_pass)
    entries, listed, complete = _host_entries(hop_root / intake)
    for entry_id, raw in entries:
        try:
            _poll_host_entry(ctx, effects, count, intake=intake, entry_id=entry_id, raw=raw,
                             now=now, touched=touched)
        except (StoreBlocked, DisposedUnavailable):
            raise
        except Exception as e:  # noqa: BLE001 -- one bad entry never wedges the intake
            _entry_failed(count, f"{intake} {entry_id!r}", e)
    if complete:
        counts["tombstones_pruned"] = prune_tombstones(cfg, fsops, intake, listed)
    counts["tombstones_committed"] = len(effects.committed)
    return counts


def prune_tombstones(cfg: Any, fsops: Any, intake: str, listed: set) -> int:
    """Remove each tombstone whose entry a complete listing (taken after
    the tombstone was committed) no longer shows, and whose record is
    `done`. Returns how many."""
    state_dir = Path(cfg.state_dir)
    dest, _stage = disposed_dirs(fsops, Path(cfg.hop.root), intake)
    n = 0
    for name in sorted(os.listdir(dest)):
        if name in listed or not re.fullmatch(r"[0-9a-f]{32}", name):
            continue
        key = record_key(intake=intake, gen="", owner=HOST_OWNER, entry_id=name)
        path = record_dir(state_dir, HOST_OWNER, key) / RECORD
        if not path.is_file() or json.loads(path.read_text(encoding="utf-8"))["state"] != "done":
            continue
        fsops.remove_pinned(dest, name)
        n += 1
    return n


def tombstone_present(cfg: Any, record: Mapping[str, Any]) -> bool:
    hop = getattr(cfg, "hop", None)
    if hop is None or record["intake"] not in HOST_INTAKES:
        return False
    return os.path.lexists(Path(hop.root) / ".disposed" / record["intake"] / record["entry_id"])


def operator_quarantine_candidate(cfg: Any, now: datetime, *, key: str,
                                  evidence: str) -> Dict[str, Any]:
    """`router peer-candidate quarantine <key> --evidence <text>`: the exit
    from a hold that can never clear by itself (`candidate_view_refused`,
    `candidate_malformed`). The record becomes `mail` with cause
    `candidate_view_refused` and its detail, then its effect: a quarantine
    item (a generation's `candidates/`) or a tombstone (a host intake, by
    the next poll); then `done`, which settles it for the frontier."""
    from . import ingress
    if not (isinstance(evidence, str) and evidence.strip()):
        raise StoreRefused("evidence is required")
    record = _find(cfg.state_dir, key)
    held = (record.get("hold") or {}).get("reason")
    if record["state"] != "pending" or held not in ("candidate_view_refused",
                                                    "candidate_malformed"):
        raise StoreRefused(f"{key}: only a pending candidate held on candidate_view_refused or "
                           f"candidate_malformed is quarantined by the operator (it is "
                           f"{record['state']}, held {held})")
    detail = (record.get("hold") or {}).get("detail")
    record = transition(cfg.state_dir, record, "mail", now, cause="candidate_view_refused",
                        policy_code=None, control=None)
    _audit(cfg.state_dir, "peer-candidate quarantine", now, key=key, evidence=evidence,
           detail=detail)
    if record["intake"] in HOST_INTAKES:
        return {"result": "mail: candidate_view_refused, tombstone committed by the next poll"}
    link = ingress.pump_link(cfg, record["owner"], record["gen"]) if cfg.hop is not None else None
    if link is None:
        return {"result": "mail: candidate_view_refused, quarantined by the next poll"}
    ctx = Ctx(state_dir=cfg.state_dir, cfg=cfg, delegation=None, hooks=absent_hooks(), now=now,
              clock=peerclock.read(cfg.state_dir), view=None,
              effects=TreeEffects(cfg, record["owner"], record["gen"], link, None),
              retired=lambda _r: False)
    _finish(ctx, record)
    return {"result": "mail: candidate_view_refused, quarantined, done"}



def recover(cfg: Any, runtime: Any, *, delegation: Any,
            clock: "peerclock.Clock", now: datetime, first_pass: bool = False,
            skip: Iterable[str] = (), profile_factory: Any = None) -> Dict[str, int]:
    """Every record that is not `done` (and every done tree record whose
    entry's removal never succeeded), BY ITS RECORDED STATE, whether or not
    its entry is listed again: in `take_seq` order, each with the effects of
    its own intake, each isolated. `skip` is what this pass already
    evaluated."""
    from . import hoplink as hoplink_mod
    from . import ingress
    state_dir = Path(cfg.state_dir)
    counts: Dict[str, int] = {}

    def count(what: str) -> None:
        counts[what] = counts.get(what, 0) + 1

    skip = set(skip)
    pending: List[Dict[str, Any]] = []
    meta = read_meta(state_dir)
    for owner in sorted(meta["roots"]):
        root = journal_root(state_dir, owner)
        for d in root.iterdir() if root.is_dir() else ():
            if not (d.is_dir() and _KEY_RE.fullmatch(d.name) and (d / RECORD).is_file()):
                continue
            if d.name in skip:
                continue
            rec = json.loads((d / RECORD).read_text(encoding="utf-8"))
            if rec["state"] != "done" or (rec["intake"] not in HOST_INTAKES
                                          and not rec.get("removed")):
                pending.append(rec)
    view_of = _viewer(delegation)
    hop_root = Path(cfg.hop.root) if getattr(cfg, "hop", None) is not None else None
    hooks = _pass_hooks(cfg, delegation=delegation, state_dir=state_dir, now=now, clock=clock,
                        profile_factory=profile_factory)
    for rec in sorted(pending, key=lambda r: r["take_seq"]):
        try:
            if rec["intake"] in HOST_INTAKES:
                effects: Any = HostEffects(runtime.fsops, hop_root, rec["intake"])
            else:
                link = ingress.pump_link(cfg, rec["owner"], rec["gen"])
                if link is None:
                    count("held_link_unset")
                    continue
                try:
                    remover = hoplink_mod.remover_for(runtime, cfg, rec["owner"], rec["gen"])
                except Exception:  # noqa: BLE001 -- no remover: removal is retried later
                    remover = None
                effects = TreeEffects(cfg, rec["owner"], rec["gen"], link, remover)
            ctx = Ctx(state_dir=state_dir, cfg=cfg, delegation=delegation, hooks=hooks,
                      now=now, clock=clock, view=view_of, effects=effects,
                      retired=lambda r: hoplink_mod._is_retired(runtime, cfg, r["owner"],
                                                                r["gen"]),
                      first_pass=first_pass)
            if rec["state"] == "done":
                _settle(ctx, rec)
                count("settled")
                continue
            out = evaluate(ctx, rec)
            count(f"state_{out['state']}" if not out.get("hold")
                  else f"held_{out['hold']['reason']}")
        except StoreBlocked:
            raise
        except Exception as e:  # noqa: BLE001 -- one record never wedges recovery
            _entry_failed(count, f"recovery of {rec['key']}", e)
    return counts
