"""router/peerepochs.py — the receiver's epoch store: each sending agent's
accepted `sender_since`, per (runtime, from).

The policy hook (`peerpolicy`) consults it only when an age policy is in
force: an EARLIER `sender_since` than the one accepted is
`sender_since_inconsistent` and persists nothing; a LATER one (or the first
seen) is persisted and audited BEFORE the age test; an equal one changes
nothing.

LAYOUT, immutable files linked once:

    state_dir/peer-epochs/<sha256(runtime)[:32]>/<sha256(from)>/<sender_since>.json
    body: {"v": 1, "runtime": ..., "from": ..., "sender_since": ...}

`runtime` is the reservation's runtime address (never a key id, so a key
rotation keeps the pair); `from` is the signed sender with its local part
EXACT and its domain ASCII-lowercased, and nothing else (no alias). The
filename is `sender_since` in the canonical `YYYY-MM-DDTHH:MM:SSZ` form, so
names compare as instants. ONE live file per pair: accepting a later value
links the new file, then removes the old one, each its own bookkept
transaction; reconcile completes a pair caught between them (only while the
store shows no loss).

BOOKKEEPING is the store's fourth entry in the clock file (`store.v` 2):
`epochs` {token, live, content_sum, rev_total} and `epochs_untrusted`
(`peerjournal`). Any read or validation fault, and any LOSS or BEHIND finding
for this store, sets `epochs_untrusted`; while it is set every statement
reaching the consistency step HOLDS (`epoch_store_unavailable`) until the
audited operator verb `router peer-epochs trust --evidence` reseeds,
recounts, verifies and clears it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .util import format_utc_ts, fsync_dir, parse_utc_ts

EPOCH_DIR = "peer-epochs"
AUDIT_FILE = "epochs.audit.jsonl"
BODY_MEMBERS = ("v", "runtime", "from", "sender_since")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CANON_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SUFFIX = ".json"
INCONSISTENT, ACCEPTED, EQUAL = "inconsistent", "accepted", "equal"


class EpochFault(Exception):
    """The epoch store cannot be read as recorded: a HOLD, never "no record"."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Untrusted(Exception):
    """`epochs_untrusted` is set: the consistency step holds."""


def canonical_from(address: str) -> str:
    """The signed `from`, local part exact, domain ASCII-lowercased."""
    from . import peerledger
    return peerledger.canonical(address)


def canonical_ts(value: Any) -> Optional[str]:
    t = parse_utc_ts(value) if isinstance(value, str) else None
    return format_utc_ts(t) if t is not None else None


def root(state_dir: Path) -> Path:
    return Path(state_dir) / EPOCH_DIR


def pair_dir(state_dir: Path, runtime: str, from_canon: str) -> Path:
    return (root(state_dir) / hashlib.sha256(runtime.encode("utf-8")).hexdigest()[:32]
            / hashlib.sha256(from_canon.encode("utf-8")).hexdigest())


def body_bytes(runtime: str, from_canon: str, sender_since: str) -> bytes:
    return json.dumps({"v": 1, "runtime": runtime, "from": from_canon,
                       "sender_since": sender_since}, sort_keys=True).encode("utf-8")


def _validate(path: Path, data: bytes) -> Dict[str, Any]:
    """The file's body, checked against its own path; `EpochFault`."""
    name = path.name
    stem = name[:-len(SUFFIX)] if name.endswith(SUFFIX) else None
    if stem is None or not _CANON_TS.fullmatch(stem) or canonical_ts(stem) != stem:
        raise EpochFault(f"non-canonical epoch name {path}")
    try:
        doc = json.loads(data)
    except ValueError:
        raise EpochFault(f"unreadable epoch file {path}") from None
    if not isinstance(doc, dict) or set(doc) != set(BODY_MEMBERS) or doc["v"] != 1:
        raise EpochFault(f"not a closed epoch body {path}")
    if doc["sender_since"] != stem:
        raise EpochFault(f"epoch body {path} does not match its name")
    if not (isinstance(doc["runtime"], str) and isinstance(doc["from"], str)):
        raise EpochFault(f"epoch body {path} has no identity")
    if pair_dir(path.parents[2].parent, doc["runtime"], doc["from"]) != path.parent:
        raise EpochFault(f"epoch body {path} names another pair")
    return doc


def _read_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EpochFault(f"not a regular epoch file {path}")
    try:
        return path.read_bytes()
    except OSError as e:
        raise EpochFault(f"unreadable epoch file {path}: {e}") from None


def pair_files(state_dir: Path, runtime: str, from_canon: str) -> List[Path]:
    """The pair's files, oldest first, each validated."""
    d = pair_dir(state_dir, runtime, from_canon)
    if not d.exists():
        return []
    if d.is_symlink() or not d.is_dir():
        raise EpochFault(f"not an epoch pair directory {d}")
    files = sorted(d.iterdir())
    for f in files:
        _validate(f, _read_file(f))
    return files


def accepted(state_dir: Path, runtime: str, from_canon: str) -> Optional[str]:
    """The pair's accepted `sender_since` (the maximum), or None."""
    files = pair_files(state_dir, runtime, from_canon)
    return files[-1].name[:-len(SUFFIX)] if files else None


def is_witness(entry: Path) -> bool:
    """The ONE root entry that is not a runtime directory: the bookkeeping
    witness, by exact name, a regular file. Any other root entry, a dot
    name included, is an unexpected object."""
    from .peerjournal import WITNESS
    return entry.name == WITNESS and not entry.is_symlink() and entry.is_file()


def root_safe(r: Path) -> bool:
    """The epoch root is absent, or a real directory: never a link, a file
    or anything else, which no scan may read as an empty store."""
    return not os.path.lexists(r) or (not r.is_symlink() and r.is_dir())


def _real_dir(entry: Path, pattern: "re.Pattern[str]") -> bool:
    return not entry.is_symlink() and entry.is_dir() and bool(pattern.fullmatch(entry.name))


def scan(state_dir: Path, *, skip: frozenset = frozenset()) -> Tuple[int, int, int, int]:
    """(live files, content_sum, pairs, pairs mid-prune) recomputed from
    disk, leaving out the files in `skip`. Raises `EpochFault` on any other
    entry that does not validate."""
    from .peerjournal import _MOD, contribution
    live = total = pairs = midprune = 0
    r = root(state_dir)
    if not root_safe(r):
        raise EpochFault(f"the epoch root {r} is not a directory")
    for rtdir in sorted(r.iterdir()) if r.is_dir() else ():
        if is_witness(rtdir) or rtdir in skip:
            continue
        if not _real_dir(rtdir, _HEX32):
            raise EpochFault(f"unexpected entry {rtdir}")
        for fdir in sorted(rtdir.iterdir()):
            if fdir in skip:
                continue
            if not _real_dir(fdir, _HEX64):
                raise EpochFault(f"unexpected entry {fdir}")
            files = [f for f in sorted(fdir.iterdir()) if f not in skip]
            if files:
                pairs += 1
            if len(files) > 1:
                midprune += 1
            for f in files:
                data = _read_file(f)
                _validate(f, data)
                total += contribution(f"{rtdir.name}/{fdir.name}/{f.name}", 0, data)
                live += 1
    return live, total % _MOD, pairs, midprune


def _contribution(path: Path, data: bytes) -> int:
    from .peerjournal import contribution
    return contribution(f"{path.parent.parent.name}/{path.parent.name}/{path.name}", 0, data)


# ---------------------------------------------------------------------------
# Bookkept writes (the journal's intent discipline)
# ---------------------------------------------------------------------------

def _link(path: Path, data: bytes) -> None:
    from . import peerbind
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        peerbind._link_once(fd, path.name, data, stage_prefix=".epoch-stage-")
    finally:
        os.close(fd)
    fsync_dir(path.parent.parent)


def write_epoch(state_dir: Path, runtime: str, from_canon: str, sender_since: str) -> None:
    """Link a pair's new (later) epoch file: intent, file, counts, clear."""
    from . import peerjournal as pj
    state_dir = Path(state_dir)
    meta = pj.read_meta(state_dir)
    pj._require_clear(meta)
    path = pair_dir(state_dir, runtime, from_canon) / f"{sender_since}{SUFFIX}"
    data = body_bytes(runtime, from_canon, sender_since)
    existed = path.is_file()
    delta = pj._delta("epochs", None, 0 if existed else _contribution(path, data), 0,
                      0 if existed else 1)
    meta["pending_op"] = {"op": "epoch", "owner": None, "target": str(path), "delta": [delta]}
    pj._write_meta(state_dir, meta)
    _link(path, data)
    pj._apply(meta, delta)
    meta["pending_op"] = None
    pj._write_meta(state_dir, meta)


def prune_older(state_dir: Path, runtime: str, from_canon: str) -> int:
    """Remove every file of the pair but the newest, each its own bookkept
    transaction (intent, removal, counts, clear). Returns how many."""
    files = pair_files(state_dir, runtime, from_canon)
    for old in files[:-1]:
        remove_file(state_dir, old)
    return max(0, len(files) - 1)


def remove_file(state_dir: Path, path: Path) -> None:
    from . import peerjournal as pj
    state_dir = Path(state_dir)
    meta = pj.read_meta(state_dir)
    pj._require_clear(meta)
    data = path.read_bytes()
    delta = pj._delta("epochs", None, -_contribution(path, data), 0, -1)
    meta["pending_op"] = {"op": "epoch_prune", "owner": None, "target": str(path),
                          "delta": [delta]}
    pj._write_meta(state_dir, meta)
    complete_prune(path)
    pj._apply(meta, delta)
    meta["pending_op"] = None
    pj._write_meta(state_dir, meta)


def complete_prune(path: Path) -> None:
    """A pending prune is completed, never half-undone (`reconcile`)."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    fsync_dir(path.parent)


def complete_pairs(state_dir: Path) -> int:
    """Every pair caught between (+) and (-): its older files removed.
    Called by reconcile ONLY when the store shows no loss."""
    n = 0
    r = root(state_dir)
    for rtdir in sorted(r.iterdir()) if r.is_dir() else ():
        if is_witness(rtdir):
            continue
        for fdir in sorted(rtdir.iterdir()):
            files = sorted(fdir.iterdir())
            for old in files[:-1]:
                remove_file(state_dir, old)
                n += 1
    return n


def _audit(state_dir: Path, now: datetime, **fields: Any) -> None:
    from . import audit, peerjournal
    line = json.dumps(dict(fields, ts=format_utc_ts(now), event="peer_epoch_changed"),
                      sort_keys=True).encode("utf-8") + b"\n"
    audit.append_router_line(Path(state_dir), peerjournal.REPLAY_DIR, AUDIT_FILE, line)


def set_untrusted(state_dir: Path, why: str) -> None:
    """The durable fail-closed flag (controller R4, PROVISIONAL)."""
    from . import peerjournal as pj
    meta = pj.read_meta(state_dir)
    if not meta["epochs_untrusted"]:
        meta["epochs_untrusted"] = True
        pj._write_meta(state_dir, meta)


# ---------------------------------------------------------------------------
# The consistency step
# ---------------------------------------------------------------------------

def consult(state_dir: Path, *, runtime: str, sender: str, sender_since: str,
            now: datetime) -> str:
    """The consistency step for one statement: `INCONSISTENT` (nothing
    persisted), `EQUAL`, or `ACCEPTED` (a later value or the first seen,
    persisted and audited BEFORE returning). `Untrusted` while the flag is
    set; a read or validation fault sets the flag and raises `EpochFault`."""
    from . import peerjournal as pj
    state_dir = Path(state_dir)
    meta = pj.read_meta(state_dir)
    if meta["epochs_untrusted"]:
        raise Untrusted("the epoch store is untrusted")
    from_canon = canonical_from(sender)
    claim = canonical_ts(sender_since)
    if claim is None:
        raise ValueError("sender_since is not a utc_ts")
    try:
        old = accepted(state_dir, runtime, from_canon)
    except EpochFault as e:
        set_untrusted(state_dir, e.reason)
        raise
    if old is not None and claim < old:
        return INCONSISTENT
    if old == claim:
        return EQUAL
    write_epoch(state_dir, runtime, from_canon, claim)
    _audit(state_dir, now, runtime=runtime, **{"from": from_canon}, old=old, new=claim)
    prune_older(state_dir, runtime, from_canon)
    return ACCEPTED


# ---------------------------------------------------------------------------
# The trust verb (controller R4, PROVISIONAL; the DAN-ITEM)
# ---------------------------------------------------------------------------

#: The decided outcomes whose `sender_since` passed the consistency step.
RESEED_CODES = frozenset({"quarantined", "exposure_missing"})


def _reseed_claims(state_dir: Path) -> Dict[Tuple[str, str], str]:
    """Per pair, the maximum `sender_since` of every DECIDED record that
    passed the consistency step: placed, or refused (policy) quarantined
    or exposure_missing. Never an inconsistent one, an age-missing one, an
    edge refusal or a demotion. The journal is read strictly
    (`peerjournal.strict_records`): one that cannot be read reliably is
    `peerjournal.JournalBlind`, never a reseed from what happened to be
    visible."""
    from . import peerbind
    from . import peerjournal as pj
    out: Dict[Tuple[str, str], str] = {}
    for rec in pj.strict_records(Path(state_dir)):
        if rec.get("kind") == "control":
            continue
        passed = rec.get("disposed") == "placed" or (
            rec.get("cause") == "policy" and rec.get("policy_code") in RESEED_CODES)
        if not passed or not rec.get("replay_ref"):
            continue
        raw = pj.read_snapshot(Path(state_dir), rec, pj.SNAPSHOT_STATEMENT)
        try:
            payload = json.loads(raw) if raw is not None else None
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            continue
        claim = canonical_ts(payload.get("sender_since"))
        if claim is None:
            continue
        rt, idk = rec["replay_ref"].split("/")
        try:
            res = peerbind.parse_reservation(
                (Path(state_dir) / pj.REPLAY_DIR / rt / (idk + peerbind.RESERVATION_SUFFIX))
                .read_bytes(), None)
        except (OSError, peerbind.RecoveryCorrupt):
            continue
        key = (res["runtime"], canonical_from(payload["from"]))
        if claim > out.get(key, ""):
            out[key] = claim
    return out


def _invalid_entries(state_dir: Path) -> List[Path]:
    bad = []
    r = root(state_dir)
    if not root_safe(r):
        return [r]
    for rtdir in sorted(r.iterdir()) if r.is_dir() else ():
        if is_witness(rtdir):
            continue
        if not _real_dir(rtdir, _HEX32):
            bad.append(rtdir)
            continue
        for fdir in sorted(rtdir.iterdir()):
            if not _real_dir(fdir, _HEX64):
                bad.append(fdir)
                continue
            for f in sorted(fdir.iterdir()):
                try:
                    _validate(f, _read_file(f))
                except EpochFault:
                    bad.append(f)
    return bad


def operator_trust(state_dir: Path, now: datetime, *, evidence: str) -> Dict[str, Any]:
    """`router peer-epochs trust --evidence`: reseed, remove what is invalid,
    complete two-file pairs, recount and verify, and ONLY THEN clear
    `epochs_untrusted` in its own final write. Anything unsafe or
    unremovable keeps the flag; the report says what. Idempotent."""
    from . import peerjournal as pj
    state_dir = Path(state_dir)
    if not (isinstance(evidence, str) and evidence.strip()):
        raise ValueError("evidence is required")
    before = _pairs_report(state_dir)
    problems: List[str] = []
    # Invalid objects: regular files of ours are removed, in the recount's
    # own transaction; anything else is unsafe and keeps the flag.
    targets = []
    for bad in _invalid_entries(state_dir):
        if bad == root(state_dir):
            problems.append(f"unsafe object {bad}: the epoch root is not a directory")
        elif not bad.is_symlink() and bad.is_file() and os.stat(bad).st_uid == os.getuid():
            targets.append(bad)
        else:
            problems.append(f"unsafe object {bad}")
    if not problems:
        try:
            _restore_root_witness(state_dir)
        except OSError as e:
            problems.append(f"cannot restore the epoch root or its witness: {e}")
    if not problems:
        try:
            _recount_removing(state_dir, targets)
        except EpochFault as e:
            problems.append(e.reason)
        except OSError as e:
            problems.append(f"cannot remove an invalid file: {e}")
    if not problems:
        try:
            claims = _reseed_claims(state_dir)
        except pj.JournalBlind as e:
            # Nothing reseeded from a partial view; the flag stays.
            problems.append(f"the journal cannot be read reliably, so no epoch was reseeded: {e}")
            claims = {}
        for (runtime, from_canon), claim in sorted(claims.items()):
            old = accepted(state_dir, runtime, from_canon)
            if old is None or claim > old:
                write_epoch(state_dir, runtime, from_canon, claim)
        try:
            complete_pairs(state_dir)
        except OSError as e:
            problems.append(f"cannot complete a pair: {e}")
    meta = pj.read_meta(state_dir)
    entry = meta["epochs"]
    try:
        live, total, _pairs, midprune = scan(state_dir)
    except EpochFault as e:
        problems.append(e.reason)       # no derived counts after a scan fault
    else:
        if (live, str(total)) != (entry["live"], entry["content_sum"]):
            problems.append(f"the epoch store ({live} files) does not equal its bookkeeping "
                            f"({entry['live']})")
        if midprune:
            problems.append(f"{midprune} pair(s) still hold two files")
    if not _witness_holds(state_dir, entry["token"]):
        problems.append("the epoch root does not hold the exact witness with the recorded token")
    if not problems:
        meta = pj.read_meta(state_dir)
        meta["epochs_untrusted"] = False
        pj._write_meta(state_dir, meta)
    pj._audit(state_dir, "peer-epochs trust", now, evidence=evidence,
              cleared=not problems, problems=problems[:20])
    return {"cleared": not problems, "problems": problems, "before": before,
            "after": _pairs_report(state_dir)}


def _restore_root_witness(state_dir: Path) -> None:
    """The trust verb's witness repair, durable and idempotent: the epoch
    root created when absent, and the exact witness (re)written to the
    token the bookkeeping records, as `_rebase_after_loss` restores it.
    Runs only once every root entry is known safe (an unsafe `.witness`,
    a link or a directory, has already kept the flag)."""
    from . import peerjournal as pj
    r = root(state_dir)
    if not os.path.lexists(r):
        r.mkdir(mode=0o700)
        fsync_dir(Path(state_dir))
    pj._restore_witness(state_dir, r / pj.WITNESS, pj.read_meta(state_dir)["epochs"]["token"])


def _witness_holds(state_dir: Path, token: str) -> bool:
    """A real root holding the exact regular witness, its contents `token`."""
    from .peerjournal import WITNESS
    r = root(state_dir)
    if not (root_safe(r) and r.is_dir() and is_witness(r / WITNESS)):
        return False
    try:
        return (r / WITNESS).read_text(encoding="ascii") == token
    except (OSError, UnicodeDecodeError):
        return False


def _recount_removing(state_dir: Path, targets: List[Path]) -> None:
    """The trust verb's recount, ONE bookkept transaction: the intent names
    the invalid files and, in the same write, carries the epoch counts of
    the store WITHOUT them, recomputed from the verified remaining files
    (`scan` raises if any other entry is invalid); then the files go; then
    the intent is cleared. An invalid file's bytes are never taken for the
    bytes the bookkeeping once counted. A crash after the intent is
    completed at reconcile (the targets removed, the counts already theirs);
    the flag stays set throughout, and a re-run repeats it idempotently."""
    from . import peerjournal as pj
    meta = pj.read_meta(state_dir)
    pj._require_clear(meta)
    live, total, _pairs, _mid = scan(state_dir, skip=frozenset(targets))
    meta["epochs"] = dict(meta["epochs"], live=live, content_sum=str(total))
    meta["pending_op"] = {"op": "epoch_recount", "owner": None,
                          "targets": [str(t) for t in targets]}
    pj._write_meta(state_dir, meta)
    for t in targets:
        complete_prune(t)
    meta["pending_op"] = None
    pj._write_meta(state_dir, meta)


def _pairs_report(state_dir: Path) -> List[Dict[str, Any]]:
    out = []
    r = root(state_dir)
    for rtdir in sorted(r.iterdir()) if r.is_dir() else ():
        if is_witness(rtdir) or not _real_dir(rtdir, _HEX32):
            continue
        for fdir in sorted(rtdir.iterdir()) if rtdir.is_dir() else ():
            if not fdir.is_dir():
                continue
            out.append({"pair": f"{rtdir.name}/{fdir.name}",
                        "files": sorted(p.name for p in fdir.iterdir())})
    return out
