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

import base64 as _base64
import binascii as _binascii
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import generations as generations_mod
from . import quarantine as quarantine_mod
from . import transport as transport_mod
from .hoplink import canonical
from .util import _mkdir_durable, atomic_write, fsync_dir, utc_ts

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

#: The decoded cap on the notice and on the spool document, each.
DOC_CAP = 1 << 20

BUNDLE_MEMBERS = ("attachments", "hop", "notice", "schema", "spool")


class BundleRefused(Exception):
    """The bundle is not one this router keeps. `.reason` names why:
    `bundle_schema` (not the current bundle version), `entry_id_mismatch`
    (the notice's `notice_id` is not the listed entry) or `bundle_invalid`
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


# The AMAP document checks for the bundle's notice (`deliver-notice`) and
# spool (`inbound-message`): each schema's required members and types,
# hand-rolled because the package is stdlib-only, and proven against the
# spec's golden fixtures in the tests (`test_ingress_documents`). Both
# documents are OPEN (§7's tolerance rule): an unknown member is accepted.
_NOTICE_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")
_SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
_CONTENT_REF_RE = re.compile(r"[A-Za-z0-9_.-]+\.attachments/(0|[1-9][0-9]*)\Z")
DISPOSITIONS = ("clean", "stripped", "quarantined", "unscanned")


def _str(v: Any, *, nonempty: bool = False) -> bool:
    return isinstance(v, str) and (not nonempty or bool(v))


def _check_descriptors(descs: Any, notice_id: str, what: str) -> None:
    if not isinstance(descs, list):
        raise _invalid(f"{what}.attachments is not a list")
    for k, d in enumerate(descs):
        w = f"{what}.attachments[{k}]"
        if not isinstance(d, dict):
            raise _invalid(f"{w} is not an object")
        if not (_str(d.get("filename"), nonempty=True)
                and _str(d.get("media_type"), nonempty=True)):
            raise _invalid(f"{w}: filename and media_type must be non-empty strings")
        size = d.get("size_bytes")
        if not (type(size) is int and size >= 0):
            raise _invalid(f"{w}: size_bytes is not a non-negative integer")
        if d.get("disposition") not in DISPOSITIONS:
            raise _invalid(f"{w}: disposition is not one of {list(DISPOSITIONS)}")
        if "sha256" in d and not (_str(d["sha256"]) and _SHA256_RE.fullmatch(d["sha256"])):
            raise _invalid(f"{w}: sha256 is not 64 lowercase hex")
        if "content_ref" in d:
            ref = d["content_ref"]
            if not (_str(ref) and _CONTENT_REF_RE.fullmatch(ref)):
                raise _invalid(f"{w}: content_ref is not <id>.attachments/<index>")
            # The post-check the schema cannot state: the grant names THIS
            # notice and THIS position.
            if ref != f"{notice_id}.attachments/{k}":
                raise _invalid(f"{w}: content_ref does not name this notice and position")
        if ("content_ref" in d or "sha256" in d) and d["disposition"] != "clean":
            raise _invalid(f"{w}: content_ref or sha256 on a non-clean descriptor")


def _check_notice_id(doc: Dict[str, Any], what: str) -> str:
    nid = doc.get("notice_id")
    if not (_str(nid) and _NOTICE_ID_RE.fullmatch(nid)):
        raise _invalid(f"{what}: notice_id is not in the notice id grammar")
    return nid


def check_notice_doc(doc: Any) -> None:
    """`deliver-notice`, as a hostile document: raises `BundleRefused`
    (`bundle_invalid`) on the first rule it breaks."""
    if not isinstance(doc, dict):
        raise _invalid("the notice is not an object")
    if doc.get("contract_version") != "2":
        raise _invalid("the notice's contract_version is not \"2\"")
    nid = _check_notice_id(doc, "the notice")
    if not _str(doc.get("ts"), nonempty=True):
        raise _invalid("the notice's ts is not a non-empty string")
    if doc.get("kind") != "deliver":
        raise _invalid("the notice's kind is not \"deliver\"")
    m = doc.get("message")
    if not isinstance(m, dict):
        raise _invalid("the notice's message is not an object")
    for member in ("id", "from", "mailbox"):
        if not _str(m.get(member), nonempty=True):
            raise _invalid(f"message.{member} is not a non-empty string")
    for member in ("subject", "preview"):
        if not _str(m.get(member)):
            raise _invalid(f"message.{member} is not a string")
    for member in ("task_id",):
        if member in m and not _str(m[member], nonempty=True):
            raise _invalid(f"message.{member} is not a non-empty string")
    for member in ("thread_id", "in_reply_to", "sender_standing", "provenance"):
        if member in m and not _str(m[member]):
            raise _invalid(f"message.{member} is not a string")
    if "references" in m and not (isinstance(m["references"], list)
                                  and all(_str(r) for r in m["references"])):
        raise _invalid("message.references is not a list of strings")
    if "verdict" in m:
        v = m["verdict"]
        if not (isinstance(v, dict) and all(_str(v[k]) for k in ("auth", "screen", "entitlement")
                                            if k in v)):
            raise _invalid("message.verdict is not an object of strings")
    if "attachments" in m:
        _check_descriptors(m["attachments"], nid, "message")


def check_message_doc(doc: Any) -> None:
    """`inbound-message` (the spool), as a hostile document: raises
    `BundleRefused` (`bundle_invalid`) on the first rule it breaks."""
    if not isinstance(doc, dict):
        raise _invalid("the spool is not an object")
    if doc.get("contract_version") != "2":
        raise _invalid("the spool's contract_version is not \"2\"")
    nid = _check_notice_id(doc, "the spool")
    if not _str(doc.get("body_text")):
        raise _invalid("the spool's body_text is not a string")
    for member in ("id", "date", "from", "to", "cc", "subject"):
        if member in doc and not _str(doc[member]):
            raise _invalid(f"the spool's {member} is not a string")
    if "attachments" in doc:
        _check_descriptors(doc["attachments"], nid, "the spool")


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
    check_notice_doc(notice)
    check_message_doc(spool)
    if notice.get("notice_id") != entry_id or spool.get("notice_id") != entry_id:
        raise BundleRefused("entry_id_mismatch",
                            f"the notice's or the spool's notice_id is not the listed "
                            f"entry {entry_id!r}")
    # `check_notice_doc` has established the descriptors' shapes, and that a
    # `content_ref` sits only on a clean descriptor and names this notice and
    # its own position; what is left is the bytes beside them.
    descs = notice["message"].get("attachments", [])
    atts = bundle["attachments"]
    if not isinstance(atts, list) or len(atts) != len(descs):
        raise _invalid("attachments are not positional with message.attachments")
    blobs: List[Optional[bytes]] = []
    for k, (d, a) in enumerate(zip(descs, atts)):
        if "content_ref" not in d:
            if a is not None:
                raise _invalid(f"attachment {k} present without a content_ref")
            blobs.append(None)
            continue
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


# ---------------------------------------------------------------------------
# Snapshots: the validated bundle's bytes, kept beside the record so that
# placement and every later re-evaluation work from what was READ, never from
# a second read upstream.
#
# `<kind dir>/<key>.snap/`, mode 0700, holding mode-0600 regular files:
# `id` (the canonical {kind, link, gen, entry_id}, which re-derives the key),
# `notice`, `spool`, `hop`, and `att-<k>` for each attachment k with bytes.
# Every file is fsynced, then the directory, then its parent, before
# `take_snapshot` returns the digests the caller journals (`prepared`, or a
# hold that keeps its snapshot). `verify_snapshot` checks the whole directory
# against those digests and fails closed on any difference.
# ---------------------------------------------------------------------------

SNAP_SUFFIX = ".snap"
SNAP_PARTS = ("notice", "spool", "hop")


class SnapshotInvalid(Exception):
    """A kept snapshot that does not match its journalled digests. `.what`
    names the defect; the record is held as `snapshot_invalid:<what>`."""

    def __init__(self, what: str, detail: str):
        super().__init__(f"snapshot_invalid:{what}: {detail}")
        self.what = what

    @property
    def reason(self) -> str:
        return f"snapshot_invalid:{self.what}"


def snapshot_dir(state_dir: Path, logical_id: str, gen: str, kind: str, key: str) -> Path:
    if not _KEY_RE.fullmatch(key):
        raise ValueError(f"not a journal key: {key!r}")
    return kind_dir(state_dir, logical_id, gen, kind) / f"{key}{SNAP_SUFFIX}"


def _id_bytes(kind: str, link: str, gen: str, entry_id: str) -> bytes:
    return canonical({"kind": kind, "link": link, "gen": gen, "entry_id": entry_id})


def _write_new(dir_fd: int, name: str, data: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                 dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _discard_uncommitted(path: Path) -> None:
    """Remove a snapshot directory no record references: what a crash between
    its first file and the journal write left. Only a real directory is
    removed; anything else at that name is damage and raises."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        raise SnapshotInvalid("not_a_directory", f"{path} exists and is not a directory")
    shutil.rmtree(path)
    fsync_dir(path.parent)


def take_snapshot(state_dir: Path, logical_id: str, gen: str, kind: str, link: str,
                  entry_id: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Keep `parsed` (what `parse_bundle` returned) durably, and return the
    digests to journal: `{"notice", "spool", "hop": sha256,
    "attachments": [sha256 | None]}`. Call it only while the entry's record
    references NO snapshot: a directory found already is an uncommitted
    leftover and is replaced."""
    key = key_for(kind, link, gen, entry_id)
    path = snapshot_dir(state_dir, logical_id, gen, kind, key)
    _mkdir_durable(path.parent, Path(state_dir))
    _discard_uncommitted(path)
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)
    raw = parsed["raw"]
    files = [("id", _id_bytes(kind, link, gen, entry_id))]
    files += [(part, raw[{"hop": "facts"}.get(part, part)]) for part in SNAP_PARTS]
    files += [(f"att-{k}", blob) for k, blob in enumerate(parsed["attachments"])
              if blob is not None]
    dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, data in files:
            _write_new(dfd, name, data)
        os.fsync(dfd)
    finally:
        os.close(dfd)
    fsync_dir(path.parent)
    digests: Dict[str, Any] = {part: hashlib.sha256(raw[{"hop": "facts"}.get(part, part)])
                               .hexdigest() for part in SNAP_PARTS}
    digests["attachments"] = [None if b is None else hashlib.sha256(b).hexdigest()
                              for b in parsed["attachments"]]
    return digests


def _cap_for(name: str, attachment_cap: int) -> int:
    if name == "id":
        return RECORD_MAX
    if name == "hop":
        return transport_mod.HOP_FACTS_MAX
    if name in ("notice", "spool"):
        return DOC_CAP
    return attachment_cap


def verify_snapshot(state_dir: Path, logical_id: str, gen: str, kind: str, link: str,
                    entry_id: str, digests: Any, *,
                    attachment_cap: int) -> Dict[str, Any]:
    """The kept bytes, `{"notice", "spool", "hop": bytes, "attachments":
    [bytes | None]}`, after checking the whole directory against `digests`
    (the journalled ones). Raises `SnapshotInvalid` naming the first defect:
    `digests` (absent or malformed in the record), `missing` (no directory,
    or a member absent), `not_a_directory`, `mode`, `symlink`, `not_regular`,
    `links` (a link count other than 1), `unexpected` (a member the digests
    do not name), `over_cap`, `identity` (the `id` member is not this entry)
    or `hash`."""
    if not (isinstance(digests, dict) and set(digests) == set(SNAP_PARTS) | {"attachments"}
            and all(isinstance(digests[p], str) and _KEY_RE.fullmatch(digests[p])
                    for p in SNAP_PARTS)
            and isinstance(digests["attachments"], list)
            and all(d is None or (isinstance(d, str) and _KEY_RE.fullmatch(d))
                    for d in digests["attachments"])):
        raise SnapshotInvalid("digests", "the record carries no well-formed snapshot digests")
    key = key_for(kind, link, gen, entry_id)
    path = snapshot_dir(state_dir, logical_id, gen, kind, key)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise SnapshotInvalid("missing", f"{path} is absent") from None
    if stat.S_ISLNK(st.st_mode):
        raise SnapshotInvalid("symlink", f"{path} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise SnapshotInvalid("not_a_directory", f"{path} is not a directory")
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise SnapshotInvalid("mode", f"{path} is mode {stat.S_IMODE(st.st_mode):o}, not 700")
    expected = {"id": None}
    expected.update({p: digests[p] for p in SNAP_PARTS})
    expected.update({f"att-{k}": d for k, d in enumerate(digests["attachments"])
                     if d is not None})
    dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        present = sorted(os.listdir(dfd))
        extra = sorted(set(present) - set(expected))
        if extra:
            raise SnapshotInvalid("unexpected", f"{path}: members {extra}")
        got: Dict[str, bytes] = {}
        for name in sorted(expected):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            except FileNotFoundError:
                raise SnapshotInvalid("missing", f"{path}: no member {name}") from None
            except OSError as e:
                if stat.S_ISLNK(os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mode):
                    raise SnapshotInvalid("symlink", f"{path}/{name} is a symlink") from None
                raise SnapshotInvalid("not_regular", f"{path}/{name}: {e.strerror}") from None
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode):
                    raise SnapshotInvalid("not_regular", f"{path}/{name} is not a regular file")
                if fst.st_nlink != 1:
                    raise SnapshotInvalid("links", f"{path}/{name} has {fst.st_nlink} links")
                if stat.S_IMODE(fst.st_mode) != 0o600:
                    raise SnapshotInvalid(
                        "mode", f"{path}/{name} is mode {stat.S_IMODE(fst.st_mode):o}, not 600")
                cap = _cap_for(name, attachment_cap)
                data = b""
                while len(data) <= cap:
                    chunk = os.read(fd, cap + 1 - len(data))
                    if not chunk:
                        break
                    data += chunk
            finally:
                os.close(fd)
            if len(data) > cap:
                raise SnapshotInvalid("over_cap", f"{path}/{name} is over {cap} bytes")
            got[name] = data
    finally:
        os.close(dfd)
    if got["id"] != _id_bytes(kind, link, gen, entry_id):
        raise SnapshotInvalid("identity", f"{path}: the id member is not this entry")
    for name, want in expected.items():
        if want is not None and hashlib.sha256(got[name]).hexdigest() != want:
            raise SnapshotInvalid("hash", f"{path}/{name}: sha256 differs from the journal")
    return {"notice": got["notice"], "spool": got["spool"], "hop": got["hop"],
            "attachments": [None if d is None else got[f"att-{k}"]
                            for k, d in enumerate(digests["attachments"])]}


def snapshots(state_dir: Path, logical_id: str, gen: str, kind: str) -> List[str]:
    """Read-only enumeration: the `entry_id` of every snapshot directory of
    one kind in one generation, from each directory's own `id` member. A
    directory whose name is not a key, or whose `id` is unreadable or does not
    re-derive its key, raises `SnapshotInvalid`: an enumeration that skipped
    one could prove a false absence."""
    d = kind_dir(state_dir, logical_id, gen, kind)
    try:
        names = sorted(os.listdir(d))
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        if not name.endswith(SNAP_SUFFIX):
            continue
        key = name[:-len(SNAP_SUFFIX)]
        if not _KEY_RE.fullmatch(key):
            raise SnapshotInvalid("identity", f"{d / name}: not a snapshot name")
        try:
            dfd = os.open(d / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open("id", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            finally:
                os.close(dfd)
        except OSError as e:
            raise SnapshotInvalid("missing", f"{d / name}: no readable id ({e.strerror})") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SnapshotInvalid("not_regular", f"{d / name}/id is not a regular file")
            raw = os.read(fd, RECORD_MAX + 1)
        finally:
            os.close(fd)
        try:
            ident = json.loads(raw.decode("utf-8"))
            ok = (isinstance(ident, dict) and ident.get("kind") == kind
                  and ident.get("gen") == gen
                  and key_for(kind, ident.get("link"), gen, ident.get("entry_id")) == key)
        except (UnicodeDecodeError, ValueError):
            ok = False
        if not ok:
            raise SnapshotInvalid("identity", f"{d / name}: its id does not match its name")
        out.append(ident["entry_id"])
    return out


# ---------------------------------------------------------------------------
# The quarantine WRITER: exactly `quarantine`'s frozen item format, one item
# per journal key, CREATE-IF-ABSENT. `quarantine` stays read-only.
#
# The item id is `sha256(key)[:32]`. An item already there is ADOPTED when it
# is byte-identical to the one this call would write given that item's own
# `arrival_ts` (the time this router first observed the entry, which a
# crash-and-re-presentation must not move); any other existing entry at that
# name, a damaged one included, raises `QuarantineConflict` and is never
# overwritten. The journal moves to `quarantined` only after this returns.
# ---------------------------------------------------------------------------

#: A comma-joined per-part digest list longer than this is omitted from the
#: evidence (an evidence string's cap); the count and the aggregate digest
#: over the list are always recorded.
_ATT_LIST_SEP = ","
_ATT_NONE = "-"


class QuarantineConflict(Exception):
    """A different (or damaged) item already holds this key's name. The
    entry is held as `quarantine_item_conflict`."""

    reason = "quarantine_item_conflict"


def quarantine_item_id(key: str) -> str:
    if not _KEY_RE.fullmatch(key):
        raise ValueError(f"not a journal key: {key!r}")
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:32]


def _evidence(kind: str, link: str, entry_id: str, key: str,
              digests: Optional[Dict[str, Any]], extra: Dict[str, Any]) -> Dict[str, Any]:
    ev: Dict[str, Any] = {"kind": kind, "link": link, "entry_id": entry_id,
                          "journal_key": key}
    if digests is not None:
        atts = digests["attachments"]
        ev.update({"snapshot_notice_sha256": digests["notice"],
                   "snapshot_spool_sha256": digests["spool"],
                   "snapshot_hop_sha256": digests["hop"],
                   "snapshot_attachments_count": len(atts),
                   "snapshot_attachments_sha256":
                       hashlib.sha256(canonical(atts)).hexdigest()})
        joined = _ATT_LIST_SEP.join(_ATT_NONE if d is None else d for d in atts)
        if len(joined) <= quarantine_mod.EVIDENCE_STR_MAX:
            ev["snapshot_attachments"] = joined
    clash = set(ev) & set(extra)
    if clash:
        raise ValueError(f"extra evidence reuses reserved keys: {sorted(clash)}")
    ev.update(extra)
    return ev


def _item_bytes(doc: Dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_quarantine_item(state_dir: Path, logical_id: str, gen: str, kind: str, link: str,
                          entry_id: str, cause: str, *,
                          digests: Optional[Dict[str, Any]] = None,
                          extra_evidence: Optional[Dict[str, Any]] = None,
                          now: Optional[str] = None) -> str:
    """Write the entry's quarantine item in generation `gen`, or adopt the
    identical one already there. Returns `"created"` or `"adopted"`. The
    item is checked against the frozen format BEFORE anything is written
    (`ValueError` when this router would write a damaged one)."""
    key = key_for(kind, link, gen, entry_id)
    item_id = quarantine_item_id(key)
    if cause not in quarantine_mod.CAUSES:
        raise ValueError(f"{cause!r} is not in the closed cause vocabulary")
    evidence = _evidence(kind, link, entry_id, key, digests, dict(extra_evidence or {}))

    def build(ts: str) -> Dict[str, Any]:
        doc = {"schema": quarantine_mod.SCHEMA, "id": item_id, "generation": gen,
               "arrival_ts": ts, "causes": [cause], "evidence": evidence}
        try:
            quarantine_mod.check_item(doc, item_id=item_id, generation=gen,
                                      now=quarantine_mod._now(ts))
        except quarantine_mod.Damaged as e:
            raise ValueError(f"this router would write a damaged item: {e}") from None
        return doc

    qdir = generations_mod.gen_dir(state_dir, logical_id, gen) / quarantine_mod.DIR_NAME
    name = f"{item_id}.json"
    fresh = _item_bytes(build(now or utc_ts()))
    # The temporary file lives in THIS module's own directory, on the same
    # filesystem: one left by a crash is never an unexpected name in the
    # quarantine (which lists every such name as DAMAGED).
    stage = generations_mod.gen_dir(state_dir, logical_id, gen) / DIR_NAME
    _mkdir_durable(qdir, Path(state_dir))
    _mkdir_durable(stage, Path(state_dir))
    tmp = stage / f".quarantine-{item_id}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(fresh)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, qdir / name, follow_symlinks=False)
            created = True
        except FileExistsError:
            created = False
    finally:
        os.unlink(tmp)
    fsync_dir(qdir)
    if created:
        return "created"
    return _adopt(qdir, name, item_id, gen, build)


def _adopt(qdir: Path, name: str, item_id: str, gen: str, build) -> str:
    dfd = os.open(qdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            raw, _st = quarantine_mod.read_pinned(dfd, name, quarantine_mod.ITEM_MAX_BYTES)
            doc = quarantine_mod._strict_json(raw)
            ts = doc.get("arrival_ts") if isinstance(doc, dict) else None
            quarantine_mod.check_item(doc, item_id=item_id, generation=gen,
                                      now=quarantine_mod._now(None))
        except quarantine_mod.Damaged as e:
            raise QuarantineConflict(f"{qdir / name}: an existing entry is damaged ({e})") from None
    finally:
        os.close(dfd)
    if raw != _item_bytes(build(ts)):
        raise QuarantineConflict(f"{qdir / name}: an existing item differs")
    return "adopted"


def quarantine_items(state_dir: Path, logical_id: str, name: str, gen: str, *,
                     days: int) -> List[Dict[str, Any]]:
    """Read-only probe over one generation's ingress quarantine: per item,
    `entry_id`, `cause` (the first), `arrived_at`, the evidence and the
    snapshot digests `{notice, spool, hop, attachments}` as recorded
    (`attachments` is None when the list was too long to record). A DAMAGED
    item is returned with `damaged` set, never omitted."""
    out = []
    for item in quarantine_mod.list_ingress(state_dir, logical_id, name, days=days):
        if item.generation != gen:
            continue
        if item.damaged is not None:
            out.append({"id": item.id, "damaged": item.damaged})
            continue
        ev = item.doc["evidence"]
        digests = None
        if "snapshot_notice_sha256" in ev:
            joined = ev.get("snapshot_attachments")
            digests = {"notice": ev["snapshot_notice_sha256"],
                       "spool": ev["snapshot_spool_sha256"],
                       "hop": ev["snapshot_hop_sha256"],
                       "attachments": None if joined is None else [
                           None if d == _ATT_NONE else d
                           for d in (joined.split(_ATT_LIST_SEP) if joined else [])]}
        out.append({"id": item.id, "damaged": None, "entry_id": ev.get("entry_id"),
                    "cause": item.doc["causes"][0], "arrived_at": item.doc["arrival_ts"],
                    "evidence": ev, "digests": digests})
    return out
