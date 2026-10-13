"""router/ingress.py — the ingress journal: one durable record per inbound
entry, per kind, per generation, through which every entry the transport
offers is placed, quarantined or held exactly once.

WHERE: `state_dir/<logical_id>/gen-<g>/ingress/<kind>/<key>.json`. One
namespace per KIND: entry ids are unique only within a kind, so a notice and
a candidate with the same id are different records.

THE KEY is the sha256 hex of the canonical encoding (`hoplink.canonical`) of
`{"kind", "link", "gen", "entry_id"}`. The entry id is opaque to this router
and never used raw as a path component.

THE RECORD, a JSON object:

    {"schema": "amap-router-local.ingress-journal/1",
     "kind": <kind>, "link": <link>, "gen": <32 hex>, "entry_id": <str>,
     "state": <STATE>, "reason": <str or null>,
     "first_seen_ts": <utc_ts>, "state_ts": <utc_ts>, ...state members}

Transitions only ever move FORWARD (`TRANSITIONS`). A write that would move a
record backwards, or across states the table does not join, raises
`JournalError` and writes nothing: the table is the state machine, and no
caller re-derives it. Every write is durable on return (`atomic_write` with
the state directory as its durable root).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from . import generations as generations_mod
from .hoplink import canonical
from .util import atomic_write, utc_ts

SCHEMA = "amap-router-local.ingress-journal/1"
DIR_NAME = "ingress"

#: The kinds an InboundPort serves (`transport.INBOUND_KINDS`).
KINDS = ("notice", "candidate", "unresolved")

#: The journal states.
HELD = "held"
PREPARED = "prepared"
PLACING = "placing"
PUBLISHED = "published"
PUBLISHED_WAITING_REMOVE = "published_waiting_remove"
COMPLETE = "complete"
QUARANTINED = "quarantined"
QUARANTINED_WAITING_REMOVE = "quarantined_waiting_remove"
QUARANTINED_COMPLETE = "quarantined_complete"
DUPLICATE_DIFFERENT_HELD = "duplicate_different_held"

STATES = (HELD, PREPARED, PLACING, PUBLISHED, PUBLISHED_WAITING_REMOVE, COMPLETE,
          QUARANTINED, QUARANTINED_WAITING_REMOVE, QUARANTINED_COMPLETE,
          DUPLICATE_DIFFERENT_HELD)

#: The terminal states that keep the key as a TOMBSTONE.
TOMBSTONES = (COMPLETE, QUARANTINED_COMPLETE)

#: state -> the states it may move to. A new record may be written in any of
#: `INITIAL`. Re-writing the SAME state (a refreshed reason or timestamp) is
#: allowed for `held` and `duplicate_different_held` only.
INITIAL = (HELD, PREPARED, QUARANTINED)
TRANSITIONS: Dict[str, tuple] = {
    HELD: (HELD, PREPARED, QUARANTINED),
    PREPARED: (PLACING, QUARANTINED),
    PLACING: (PUBLISHED, HELD),
    PUBLISHED: (PUBLISHED_WAITING_REMOVE,),
    PUBLISHED_WAITING_REMOVE: (COMPLETE,),
    COMPLETE: (PUBLISHED_WAITING_REMOVE, DUPLICATE_DIFFERENT_HELD),
    QUARANTINED: (QUARANTINED_WAITING_REMOVE,),
    QUARANTINED_WAITING_REMOVE: (QUARANTINED_COMPLETE,),
    QUARANTINED_COMPLETE: (QUARANTINED_WAITING_REMOVE, DUPLICATE_DIFFERENT_HELD),
    DUPLICATE_DIFFERENT_HELD: (DUPLICATE_DIFFERENT_HELD,),
}

_GEN_RE = re.compile(r"[0-9a-f]{32}\Z")
_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
#: A record is small; a larger file is damage, never read whole.
RECORD_MAX = 64 * 1024


class JournalError(Exception):
    """A journal write the state machine refuses, or a record that cannot be
    read as one. Nothing was written."""


def key_for(kind: str, link: str, gen: str, entry_id: str) -> str:
    """The record's key: sha256 over the canonical {kind, link, gen, entry_id}."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    if not (isinstance(link, str) and link):
        raise ValueError("link must be a non-empty string")
    if not (isinstance(gen, str) and _GEN_RE.fullmatch(gen)):
        raise ValueError(f"gen must be 32 lowercase hex, not {gen!r}")
    if not (isinstance(entry_id, str) and entry_id):
        raise ValueError("entry_id must be a non-empty string")
    doc = {"kind": kind, "link": link, "gen": gen, "entry_id": entry_id}
    return hashlib.sha256(canonical(doc)).hexdigest()


def kind_dir(state_dir: Path, logical_id: str, gen: str, kind: str) -> Path:
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    return generations_mod.gen_dir(state_dir, logical_id, gen) / DIR_NAME / kind


def record_path(state_dir: Path, logical_id: str, gen: str, kind: str, key: str) -> Path:
    if not _KEY_RE.fullmatch(key):
        raise ValueError(f"not a journal key: {key!r}")
    return kind_dir(state_dir, logical_id, gen, kind) / f"{key}.json"


def read(state_dir: Path, logical_id: str, gen: str, kind: str,
         key: str) -> Optional[Dict[str, Any]]:
    """The record, or None when there is none. A record that is not a regular
    file, is over `RECORD_MAX`, does not parse, or does not match its key's
    identity raises `JournalError`: a damaged journal is never read as
    absent, since absent would let the entry be placed again."""
    path = record_path(state_dir, logical_id, gen, kind, key)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise JournalError(f"{path}: cannot be opened ({e.strerror})") from e
    try:
        st = os.fstat(fd)
        if not (st.st_mode & 0o170000 == 0o100000 and st.st_nlink == 1):
            raise JournalError(f"{path}: not a regular file with one link")
        raw = os.read(fd, RECORD_MAX + 1)
    finally:
        os.close(fd)
    if len(raw) > RECORD_MAX:
        raise JournalError(f"{path}: over {RECORD_MAX} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise JournalError(f"{path}: not a journal record ({e})") from e
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise JournalError(f"{path}: not a journal record")
    if doc.get("state") not in STATES:
        raise JournalError(f"{path}: unknown state {doc.get('state')!r}")
    if doc.get("kind") != kind or doc.get("gen") != gen or key_for(
            kind, doc.get("link"), gen, doc.get("entry_id")) != key:
        raise JournalError(f"{path}: its identity does not match its key")
    return doc


def write(state_dir: Path, logical_id: str, gen: str, kind: str, link: str,
          entry_id: str, state: str, *, reason: Optional[str] = None,
          **members: Any) -> Dict[str, Any]:
    """Move the entry's record to `state` (creating it in one of `INITIAL`),
    durably, and return what was written. Refused (`JournalError`, nothing
    written) when the state machine does not allow the move."""
    if state not in STATES:
        raise ValueError(f"unknown state {state!r}")
    reserved = {"schema", "kind", "link", "gen", "entry_id", "state", "reason",
                "first_seen_ts", "state_ts"}
    if reserved & set(members):
        raise ValueError(f"reserved members: {sorted(reserved & set(members))}")
    key = key_for(kind, link, gen, entry_id)
    prior = read(state_dir, logical_id, gen, kind, key)
    if prior is None:
        if state not in INITIAL:
            raise JournalError(f"a new record cannot start in {state!r}")
        first_seen = utc_ts()
        carried: Dict[str, Any] = {}
    else:
        if state not in TRANSITIONS[prior["state"]]:
            raise JournalError(f"{prior['state']!r} cannot move to {state!r}")
        first_seen = prior["first_seen_ts"]
        carried = {k: v for k, v in prior.items() if k not in reserved}
    doc = dict(carried, **members)
    doc.update({"schema": SCHEMA, "kind": kind, "link": link, "gen": gen,
                "entry_id": entry_id, "state": state, "reason": reason,
                "first_seen_ts": first_seen, "state_ts": utc_ts()})
    atomic_write(record_path(state_dir, logical_id, gen, kind, key),
                 json.dumps(doc, sort_keys=True).encode("utf-8"),
                 mode=0o600, durable_root=state_dir)
    return doc


def journal_state(state_dir: Path, logical_id: str, gen: str, kind: str, link: str,
                  entry_id: str) -> Optional[Dict[str, Any]]:
    """Read-only probe: the entry's state, reason and minted notice id, or
    None when it has no record."""
    doc = read(state_dir, logical_id, gen, kind, key_for(kind, link, gen, entry_id))
    if doc is None:
        return None
    return {"state": doc["state"], "reason": doc.get("reason"),
            "notice_id": doc.get("notice_id")}
