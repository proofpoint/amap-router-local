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
from typing import Any, Dict, List, Optional

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
    # quarantined: the late check before placing; held: snapshot_invalid, or a
    # quarantine item conflict met on the way to quarantine.
    PREPARED: (PLACING, QUARANTINED, HELD),
    # Recovery row 1 (published), rows 1/3 (terminal holds), row 2 when the
    # generation is no longer current and nothing was committed (quarantined).
    PLACING: (PUBLISHED, HELD, QUARANTINED),
    PUBLISHED: (PUBLISHED_WAITING_REMOVE,),
    # A re-listed duplicate whose projection differs, under the interim rule.
    PUBLISHED_WAITING_REMOVE: (COMPLETE, DUPLICATE_DIFFERENT_HELD),
    COMPLETE: (PUBLISHED_WAITING_REMOVE, DUPLICATE_DIFFERENT_HELD),
    QUARANTINED: (QUARANTINED_WAITING_REMOVE,),
    QUARANTINED_WAITING_REMOVE: (QUARANTINED_COMPLETE, DUPLICATE_DIFFERENT_HELD),
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


def journal_records(state_dir: Path, logical_id: str, gen: str,
                    kind: str) -> Dict[str, Dict[str, Any]]:
    """Read-only enumeration of a generation's records of one kind:
    `{entry_id: {"state", "reason", "notice_id"}}`. A damaged record raises
    (`JournalError`), never omitted: an enumeration that hid one could prove a
    false absence."""
    d = kind_dir(state_dir, logical_id, gen, kind)
    try:
        names = sorted(os.listdir(d))
    except FileNotFoundError:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for name in names:
        if not name.endswith(".json"):
            continue
        key = name[:-len(".json")]
        if not _KEY_RE.fullmatch(key):
            raise JournalError(f"{d / name}: not a journal record name")
        doc = read(state_dir, logical_id, gen, kind, key)
        out[doc["entry_id"]] = {"state": doc["state"], "reason": doc.get("reason"),
                                "notice_id": doc.get("notice_id")}
    return out


# ---------------------------------------------------------------------------
# The facts version guard: this router's own strict check, ADDITIONAL to the
# plugin reader's and verdict-identical to it over its corpus.
# ---------------------------------------------------------------------------

class FactsInvalid(Exception):
    """The facts' version members are not a valid combination: the entry is
    `notice_invalid` (quarantined on first sight)."""


def facts_version(facts: Any) -> int:
    """The facts document's version: 1 when `facts_version` is ABSENT (no
    `attachments` member allowed, compared whole-bundle), 2 when it is
    PRESENT, exactly the integer 2 (`type(v) is int and v == 2`, so JSON
    `true` and `2.0` are refused), with `attachments` REQUIRED. Anything else,
    a present 1 included, raises `FactsInvalid`. Never a membership test over
    a list of readable versions: version 1 is expressed only by absence."""
    if not isinstance(facts, dict):
        raise FactsInvalid("the facts are not an object")
    if "facts_version" not in facts:
        if "attachments" in facts:
            raise FactsInvalid("version-1 facts carry no attachments member")
        return 1
    v = facts["facts_version"]
    if type(v) is int and v == 2:
        if "attachments" not in facts:
            raise FactsInvalid("version-2 facts require an attachments member")
        return 2
    raise FactsInvalid(f"facts_version {v!r} is not a version this router reads")


# ---------------------------------------------------------------------------
# The notice bundle, validated as HOSTILE input before anything is kept.
# ---------------------------------------------------------------------------

import base64 as _base64  # noqa: E402
import binascii as _binascii  # noqa: E402

from . import transport as transport_mod  # noqa: E402

#: The decoded cap on the notice and on the spool document, each.
DOC_CAP = 1 << 20

BUNDLE_MEMBERS = ("attachments", "hop", "notice", "schema", "spool")


class BundleRefused(Exception):
    """The bundle is not one this router keeps. `.reason` names why:
    `bundle_schema` (not the current bundle version) or `bundle_invalid`
    (anything else about its shape, encoding, caps or digests)."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def _invalid(detail: str) -> BundleRefused:
    return BundleRefused("bundle_invalid", detail)


def _b64(text: Any, what: str, cap: int) -> bytes:
    """Standard base64, no newlines, canonical (it re-encodes to itself), and
    at most `cap` bytes once decoded."""
    if not isinstance(text, str):
        raise _invalid(f"{what}: not a base64 string")
    if len(text) > 4 * ((cap + 2) // 3):
        raise _invalid(f"{what}: over its {cap}-byte cap")
    try:
        raw = _base64.b64decode(text.encode("ascii"), validate=True)
    except (_binascii.Error, UnicodeEncodeError):
        raise _invalid(f"{what}: not standard base64") from None
    if _base64.b64encode(raw).decode("ascii") != text:
        raise _invalid(f"{what}: not canonical base64")
    if len(raw) > cap:
        raise _invalid(f"{what}: {len(raw)} bytes, over its {cap}-byte cap")
    return raw


def _json_doc(raw: bytes, what: str) -> Dict[str, Any]:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _invalid(f"{what}: not a JSON document") from None
    if not isinstance(doc, dict):
        raise _invalid(f"{what}: not a JSON object")
    return doc


def parse_bundle(raw: bytes, entry_id: str, *, attachment_cap: int) -> Dict[str, Any]:
    """The bundle `read_entry` returned for notice `entry_id`, checked as
    HOSTILE input: exactly the five members; the current schema; each part
    canonical standard base64 within its cap (the notice and the spool
    `DOC_CAP`, the facts `transport.HOP_FACTS_MAX`, each attachment
    `attachment_cap`); the notice's `notice_id` equal to `entry_id`; and the
    attachments POSITIONAL, entry k present iff descriptor k carries
    `content_ref == "<notice_id>.attachments/<k>"`, its bytes matching that
    descriptor's `size_bytes` and `sha256`. Returns the decoded parts and the
    raw bytes of each (what a snapshot keeps). Raises `BundleRefused`."""
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, AttributeError):
        raise _invalid("the bundle is not a JSON document") from None
    if not isinstance(bundle, dict):
        raise _invalid("the bundle is not a JSON object")
    if not transport_mod.is_current_bundle_schema(bundle.get("schema")):
        raise BundleRefused("bundle_schema", f"schema {bundle.get('schema')!r}")
    if tuple(sorted(bundle)) != BUNDLE_MEMBERS:
        raise _invalid(f"members {sorted(bundle)}, not exactly {list(BUNDLE_MEMBERS)}")
    notice_raw = _b64(bundle["notice"], "notice", DOC_CAP)
    spool_raw = _b64(bundle["spool"], "spool", DOC_CAP)
    facts_raw = _b64(bundle["hop"], "hop", transport_mod.HOP_FACTS_MAX)
    notice = _json_doc(notice_raw, "notice")
    spool = _json_doc(spool_raw, "spool")
    facts = _json_doc(facts_raw, "hop facts")
    if notice.get("notice_id") != entry_id:
        raise BundleRefused("entry_id_mismatch",
                            f"the notice's notice_id is not the listed entry {entry_id!r}")
    message = notice.get("message")
    descs = message.get("attachments", []) if isinstance(message, dict) else None
    if not isinstance(descs, list):
        raise _invalid("message.attachments is not a list")
    atts = bundle["attachments"]
    if not isinstance(atts, list) or len(atts) != len(descs):
        raise _invalid("attachments are not positional with message.attachments")
    blobs: List[Optional[bytes]] = []
    for k, (d, a) in enumerate(zip(descs, atts)):
        if not isinstance(d, dict):
            raise _invalid(f"descriptor {k} is not an object")
        ref = d.get("content_ref")
        if ref is None:
            if a is not None:
                raise _invalid(f"attachment {k} present without a content_ref")
            blobs.append(None)
            continue
        if ref != f"{entry_id}.attachments/{k}" or d.get("disposition") != "clean":
            raise _invalid(f"descriptor {k}: content_ref {ref!r} on a non-clean or misnamed part")
        if a is None:
            raise _invalid(f"attachment {k} absent although its descriptor carries content_ref")
        blob = _b64(a, f"attachment {k}", attachment_cap)
        if (d.get("size_bytes") != len(blob)
                or d.get("sha256") != hashlib.sha256(blob).hexdigest()):
            raise _invalid(f"attachment {k}: size or sha256 differs from its descriptor")
        blobs.append(blob)
    return {"notice": notice, "spool": spool, "facts": facts,
            "raw": {"notice": notice_raw, "spool": spool_raw, "facts": facts_raw},
            "attachments": blobs}
