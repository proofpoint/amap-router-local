"""router/peerledger.py — the peer ledger's `placed` direction, and the one
resolution both ends use.

The peer ledger has two directions under a logical_id's private state:

- `issued` (`peerlane.write_issued`): written for every signed task or result
  this router sends, durable before the in-flight record. Its id is this
  router's own mint. Path `<state_dir>/<logical_id>/peer-ledger/<id>.json`.
- `placed` (`write_placed`, here): written for every signed statement this
  router places, after its decision and BEFORE the notice, so a reply drafted
  the moment the notice appears resolves. Its id is ANOTHER runtime's mint,
  unique only per runtime, so the path is keyed by the remote too:
  `<state_dir>/<logical_id>/peer-ledger/placed/<sha256(remote)[:32]>/<id>.json`.
  Link-once: identical bytes are accepted on a retry, different bytes are
  `LedgerConflict` (a visible hold, never a silent replace).

Both carry the same closed record (`peerlane.LEDGER_MEMBERS`), and both
accept the statement id grammar (`peerlane.RECORD_ID_RE`); only the mint is
held to `peerlane.PEER_ID_RE`.

`resolve` answers whether an `in_reply_to` names a record of this agent with
these participants, and is the same function at submit and at the receiver.
Possession of an id is never authority: the logical_id comes from the hosting
or submitting instance, never from the message. A mail notice id never
resolves here (a different store), and a peer id never resolves in the mail
ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from . import peerbind, peerlane
from .classify import Malformed, parse_address
from .util import parse_utc_ts

#: The placed records' directory under `peer-ledger/`.
PLACED_DIR = "placed"
#: The stage prefix of a placed record's link-once write.
_STAGE = ".placed-stage-"


class LedgerConflict(Exception):
    """A placed record already exists with different bytes: the decided path
    disagrees with what was placed before; hold it, never replace it."""


def canonical(address: str) -> str:
    """`address` normalised exactly as the deny check normalises it
    (`classify.parse_address`): the local part exact, the domain
    ASCII-lowercased."""
    return parse_address(address).canonical()


def remote_key(remote: str) -> str:
    """The placed records' per-remote directory name."""
    return hashlib.sha256(canonical(remote).encode("utf-8")).hexdigest()[:32]


def ledger_root(state_dir: Union[str, Path], logical_id: str) -> Path:
    return Path(state_dir) / logical_id / peerlane.PEER_LEDGER_DIR


def placed_path(state_dir: Union[str, Path], logical_id: str, remote: str,
                record_id: str) -> Path:
    return ledger_root(state_dir, logical_id) / PLACED_DIR / remote_key(remote) / f"{record_id}.json"


def placed_record(*, record_id: str, logical_id: str, local_address: str, remote: str,
                  generation: str, expires_at: str) -> Dict[str, str]:
    """The closed `placed` record. `local_address` is the hosted instance's
    own address (an alias in the statement's `to` is already resolved to it);
    `remote` is the statement's `from`, canonical."""
    return {"id": record_id, "local": logical_id, "local_address": local_address,
            "remote": canonical(remote), "direction": "placed", "generation": generation,
            "expires_at": expires_at}


def _check(record: Mapping[str, Any], direction: str) -> None:
    if set(record) != set(peerlane.LEDGER_MEMBERS) or record.get("direction") != direction:
        raise ValueError(f"not a closed {direction} record: {sorted(record)}")
    if not isinstance(record["id"], str) or not peerlane.RECORD_ID_RE.fullmatch(record["id"]):
        raise ValueError("the record id is outside the statement id grammar")
    if parse_utc_ts(record["expires_at"]) is None:
        raise ValueError("expires_at is not a utc_ts")


def write_placed(cfg: Any, record: Mapping[str, str]) -> str:
    """Write `record` once: "created", or "exists_same" when identical bytes
    are already there; `LedgerConflict` for different bytes. Durable before
    it returns."""
    _check(record, "placed")
    path = placed_path(cfg.state_dir, record["local"], record["remote"], record["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(dict(record), sort_keys=True).encode("utf-8")
    dirfd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return peerbind._link_once(dirfd, path.name, data, stage_prefix=_STAGE)
    except peerbind.LinkConflict:
        raise LedgerConflict(str(path)) from None
    finally:
        os.close(dirfd)


def _read(path: Path, direction: str) -> Optional[Dict[str, str]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    try:
        _check(doc, direction)
    except (ValueError, TypeError, AttributeError):
        return None
    return doc


def read_placed(state_dir: Union[str, Path], logical_id: str, remote: str,
                record_id: str) -> Optional[Dict[str, str]]:
    if not isinstance(record_id, str) or not peerlane.RECORD_ID_RE.fullmatch(record_id):
        return None
    try:
        path = placed_path(state_dir, logical_id, remote, record_id)
    except Malformed:
        return None
    return _read(path, "placed")


def placed_any_remote(state_dir: Union[str, Path], logical_id: str,
                      record_id: str) -> List[Dict[str, str]]:
    """Every placed record under `logical_id` with this id, whichever remote
    placed it: the submit side's lookup, where the remote is not yet known."""
    if not isinstance(record_id, str) or not peerlane.RECORD_ID_RE.fullmatch(record_id):
        return []
    root = ledger_root(state_dir, logical_id) / PLACED_DIR
    try:
        keys = sorted(e.name for e in os.scandir(root) if e.is_dir(follow_symlinks=False))
    except OSError:
        return []
    out = []
    for key in keys:
        doc = _read(root / key / f"{record_id}.json", "placed")
        if doc is not None:
            out.append(doc)
    return out


class Resolved:
    """`in_reply_to` names `record`, of this agent, with these participants,
    and its reply window is open. `record["direction"]` says which way."""
    __slots__ = ("record",)

    def __init__(self, record: Dict[str, str]):
        self.record = record

    @property
    def direction(self) -> str:
        return self.record["direction"]


class Expired:
    """`in_reply_to` names a record of this agent with these participants,
    but its reply window has closed."""
    __slots__ = ("record",)

    def __init__(self, record: Dict[str, str]):
        self.record = record


def resolve(cfg: Any, *, in_reply_to: str, local_logical_id: str, local_address: str,
            remote: Optional[str], now: datetime) -> Union[Resolved, Expired, None]:
    """The one resolution, both ends.

    - The candidates are the `issued` record with this id under
      `local_logical_id`, and the `placed` record(s) with this id: under
      `remote`'s key when the remote is known (the receiver: the statement's
      `from`), or under every remote at submit (`remote=None`).
    - Each must carry `local_address` and, when `remote` is given, that
      remote (both canonical).
    - An id that matches an issued AND a placed record is unresolved: never
      the issued one, which would grant permission with no edge.
    - At submit, more than one placed match (two remotes placed the same id
      for this agent) is unresolved: a guess would sign the result to the
      wrong remote.
    - `now >= expires_at` is `Expired`."""
    try:
        local = canonical(local_address)
        want = canonical(remote) if remote is not None else None
    except Malformed:
        return None
    issued = peerlane.read_ledger(cfg, local_logical_id, in_reply_to)
    if remote is not None:
        one = read_placed(cfg.state_dir, local_logical_id, remote, in_reply_to)
        placed = [one] if one is not None else []
    else:
        placed = placed_any_remote(cfg.state_dir, local_logical_id, in_reply_to)
    matches = []
    for rec in ([issued] if issued is not None else []) + placed:
        try:
            if canonical(rec["local_address"]) != local:
                continue
            if want is not None and canonical(rec["remote"]) != want:
                continue
        except Malformed:
            continue
        if rec["local"] != local_logical_id:
            continue
        matches.append(rec)
    if len(matches) != 1:
        return None
    rec = matches[0]
    expires = parse_utc_ts(rec["expires_at"])
    if expires is None:
        return None
    return Resolved(rec) if now < expires else Expired(rec)
