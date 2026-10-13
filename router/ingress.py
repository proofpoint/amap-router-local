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
import logging
import os
import re
import secrets
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import aliases as aliases_mod
from . import attachments as attachments_mod
from . import binding as binding_mod
from . import classify as classify_mod
from . import config as config_mod
from . import deliver as deliver_mod
from . import generations as generations_mod
from . import quarantine as quarantine_mod
from . import transport as transport_mod
from .hoplink import canonical
from .util import _mkdir_durable, atomic_write, fsync_dir, mint_notice_id, utc_ts

logger = logging.getLogger("amap_router_local.ingress")

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
# The facts, re-checked as hostile input: this router's ADDITIONAL strict
# check, verdict-identical with the plugin's reader over its corpus (design
# delta v3.4 §4, from the codec owner's answers; member names and grammars
# only). The reader's CONTEXT layer (hop_contract in the versions read, each
# transaction's logical_id the tree's) is consumed from its verdict, never
# repeated here. Every failure is `FactsInvalid`, so notice_invalid.
# ---------------------------------------------------------------------------

_F_NOTICE_ID = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_F_LINK = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_F_RULE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_F_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_F_N = re.compile(r"[0-9]{8,18}\Z")
_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
_DOT_ATOM = rf"{_ATEXT}+(?:\.{_ATEXT}+)*"
_F_MSG_ID = re.compile(rf"<{_DOT_ATOM}@{_DOT_ATOM}>\Z")
_ADDR_SPEC = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+"
_F_ADDR = re.compile(_ADDR_SPEC + r"\Z")
#: The FINAL `<addr-spec>` group at the very end: the greedy prefix makes it
#: the last one, and the addr-spec alphabet has no angle bracket.
_F_FINAL_ADDR = re.compile(rf"(?s).*<({_ADDR_SPEC})>\Z")
_F_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_F_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
HOP_CONTRACT_MAX = 2 ** 31 - 1
_STATUS_DETAIL = {0: (0,), 1: (0, 1, 2, 3, 4, 6, 7, 8), 2: range(5), 3: range(6),
                  4: range(8), 5: range(6), 6: range(6), 7: range(8)}
#: The enumerated delivery-status codes, each "X.Y.Z" with X in {4, 5}.
STATUSES = frozenset(f"{x}.{y}.{z}" for x in (4, 5) for y, zs in _STATUS_DETAIL.items()
                     for z in zs)
_V1_REQUIRED = {"hop_contract", "notice_id", "notice_class", "ingress", "admission",
                "admission_link", "admission_rule"}
_V1_OPTIONAL = {"origin_host", "in_reply_to", "failure"}


def _bad(why: str) -> FactsInvalid:
    return FactsInvalid(why)


def _grammar(value: Any, rx: "re.Pattern[str]", what: str, *, maxlen: int = 0) -> None:
    if not (isinstance(value, str) and rx.fullmatch(value)
            and (not maxlen or len(value) <= maxlen)):
        raise _bad(f"{what} does not match its grammar")


def _origin_host(value: Any) -> None:
    if not (isinstance(value, str) and len(value) <= 253):
        raise _bad("origin_host is not a host name of at most 253 characters")
    labels = value.split(".")
    if len(labels) < 2 or not all(_F_LABEL.fullmatch(lab) for lab in labels):
        raise _bad("origin_host is not lowercase LDH with at least two labels")
    if value.endswith(".hosts.internal"):
        raise _bad("origin_host ends in .hosts.internal")


def _closed(doc: Any, members: set, what: str) -> Dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != members:
        raise _bad(f"{what} does not have exactly the members {sorted(members)}")
    return doc


def _transaction(t: Any, what: str) -> None:
    _closed(t, {"link", "logical_id", "generation", "n"}, what)
    _grammar(t["link"], _F_LINK, f"{what}.link")
    _grammar(t["logical_id"], _F_HEX32, f"{what}.logical_id")
    _grammar(t["generation"], _F_HEX32, f"{what}.generation")
    _grammar(t["n"], _F_N, f"{what}.n")


def addr_of(from_value: Any) -> Optional[str]:
    """P4's addr(from): `from` itself if it FULLY matches the bare addr-spec,
    else the final `<addr-spec>` group anchored at the very end, else None.
    No trimming or unfolding."""
    if not isinstance(from_value, str):
        return None
    if _F_ADDR.fullmatch(from_value):
        return from_value
    m = _F_FINAL_ADDR.fullmatch(from_value)
    return m.group(1) if m else None


def domain_of(addr: Optional[str]) -> Optional[str]:
    """P4's domain: ASCII-lowercased after the LAST "@"; no IDNA."""
    if addr is None or "@" not in addr:
        return None
    dom = addr.rsplit("@", 1)[1]
    return dom.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                                       "abcdefghijklmnopqrstuvwxyz"))


def check_facts(parsed: Dict[str, Any]) -> int:
    """The facts of a parsed bundle, checked whole: the version selector
    (`facts_version`), canonical bytes, closed members at every level, the
    grammars and the codec's conditional rules, then the pair rules P1-P4
    against the notice and, at version 2, P5 against the notice and the
    spool. Returns the version; raises `FactsInvalid`."""
    facts, raw = parsed["facts"], parsed["raw"]["facts"]
    version = facts_version(facts)
    try:
        if canonical(facts) != raw:
            raise _bad("the facts bytes are not canonical")
    except ValueError:
        raise _bad("the facts are not canonically encodable") from None
    allowed = _V1_REQUIRED | _V1_OPTIONAL | ({"facts_version", "attachments"}
                                            if version == 2 else set())
    required = _V1_REQUIRED | ({"facts_version", "attachments"} if version == 2 else set())
    if not (required <= set(facts) <= allowed):
        raise _bad("the facts do not have exactly their version's members")
    hc = facts["hop_contract"]
    if not (type(hc) is int and 1 <= hc <= HOP_CONTRACT_MAX):
        raise _bad("hop_contract is not an integer from 1 to 2^31-1")
    _grammar(facts["notice_id"], _F_NOTICE_ID, "notice_id")
    if facts["notice_class"] not in NOTICE_CLASSES:
        raise _bad("notice_class is outside its enum")
    if facts["ingress"] not in INGRESSES:
        raise _bad("ingress is outside its enum")
    if facts["admission"] not in ADMISSIONS:
        raise _bad("admission is outside its enum")
    _grammar(facts["admission_link"], _F_LINK, "admission_link")
    _grammar(facts["admission_rule"], _F_RULE, "admission_rule")
    fleet = facts["admission"] == "fleet_hosts"
    if ("origin_host" in facts) != fleet:
        raise _bad("origin_host is present iff admission is fleet_hosts")
    if fleet:
        _origin_host(facts["origin_host"])
    mail = facts["notice_class"] == "mail"
    if "in_reply_to" in facts:
        if not mail:
            raise _bad("in_reply_to is allowed only on mail")
        irt = _closed(facts["in_reply_to"], {"message_id", "transaction"}, "in_reply_to")
        _grammar(irt["message_id"], _F_MSG_ID, "in_reply_to.message_id", maxlen=250)
        _transaction(irt["transaction"], "in_reply_to.transaction")
    if ("failure" in facts) == mail:
        raise _bad("failure is required iff notice_class is failure_notice")
    if not mail:
        fl = _closed(facts["failure"], {"transaction", "correlated_by", "reports"}, "failure")
        _transaction(fl["transaction"], "failure.transaction")
        if fl["correlated_by"] not in ("envid", "message_id"):
            raise _bad("failure.correlated_by is outside its enum")
        reports = fl["reports"]
        if not (isinstance(reports, list) and 1 <= len(reports) <= 100):
            raise _bad("failure.reports is not 1 to 100 reports")
        seen = set()
        for k, rpt in enumerate(reports):
            _closed(rpt, {"recipient", "action", "status"}, f"failure.reports[{k}]")
            _grammar(rpt["recipient"], _F_ADDR, f"failure.reports[{k}].recipient", maxlen=254)
            if rpt["recipient"] in seen:
                raise _bad("failure.reports has a duplicate recipient")
            seen.add(rpt["recipient"])
            if rpt["action"] not in ("failed", "delayed"):
                raise _bad(f"failure.reports[{k}].action is outside its enum")
            if rpt["status"] not in STATUSES:
                raise _bad(f"failure.reports[{k}].status is outside its enum")
            if rpt["status"][0] != {"failed": "5", "delayed": "4"}[rpt["action"]]:
                raise _bad(f"failure.reports[{k}]: the status class does not fit the action")
    # -- the pair rules ---------------------------------------------------
    notice = parsed["notice"]
    message = notice.get("message") if isinstance(notice, dict) else None
    if not isinstance(message, dict):
        raise _bad("the notice has no message")
    if facts["notice_id"] != notice.get("notice_id"):
        raise _bad("P1: the facts' notice_id is not the notice's")
    nhc = notice.get("hop_contract")
    if not (type(nhc) is int and nhc == hc):
        raise _bad("P2: the notice carries no hop_contract equal to the facts'")
    want = "fleet-remote" if fleet else "unverified"
    if message.get("provenance") != want:
        raise _bad(f"P3: the notice's provenance is not {want!r}")
    if fleet and domain_of(addr_of(message.get("from"))) != facts["origin_host"]:
        raise _bad("P4: the From domain is undefined or is not origin_host")
    if version == 2:
        rows = facts["attachments"]
        if not isinstance(rows, list):
            raise _bad("attachments is not a list")
        for k, row in enumerate(rows):
            _closed(row, {"source_sha256", "size_bytes"}, f"attachments[{k}]")
            _grammar(row["source_sha256"], _F_SHA256, f"attachments[{k}].source_sha256")
            if not (type(row["size_bytes"]) is int and row["size_bytes"] >= 0):
                raise _bad(f"attachments[{k}].size_bytes is not a non-negative integer")
        descs = message.get("attachments", [])
        spool_atts = parsed["spool"].get("attachments", []) if isinstance(
            parsed["spool"], dict) else None
        if not isinstance(descs, list) or not isinstance(spool_atts, list):
            raise _bad("P5: a present attachments member is not a list")
        if len(rows) != len(descs):
            raise _bad("P5: the facts' row count is not the notice's descriptor count")
        for k, (row, d) in enumerate(zip(rows, descs)):
            if row["size_bytes"] != d.get("size_bytes"):
                raise _bad(f"P5: row {k}'s size_bytes is not descriptor {k}'s")
            if "sha256" in d and d["sha256"] != row["source_sha256"]:
                raise _bad(f"P5c: descriptor {k}'s sha256 is not row {k}'s source_sha256")
        if len(spool_atts) != len(rows):
            raise _bad("P5: the spool's attachment count is not the row count")
    return version


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
    if cause == quarantine_mod.CAUSE_NOTICE_INVALID and (digests is not None or extra_evidence):
        raise ValueError("a notice_invalid item records identifiers only (E17)")

    def evidence_at(ts: str) -> Dict[str, Any]:
        if cause == quarantine_mod.CAUSE_NOTICE_INVALID:
            # E17: EXACTLY the listed entry id, the journal key, the
            # attributed generation, arrived_at and the literal closed code;
            # nothing from or about the refused bytes.
            return {"entry_id": entry_id, "journal_key": key, "generation": gen,
                    "arrived_at": ts, "refusal": quarantine_mod.CAUSE_NOTICE_INVALID}
        return _evidence(kind, link, entry_id, key, digests, dict(extra_evidence or {}))

    def build(ts: str) -> Dict[str, Any]:
        doc = {"schema": quarantine_mod.SCHEMA, "id": item_id, "generation": gen,
               "arrival_ts": ts, "causes": [cause], "evidence": evidence_at(ts)}
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


# ---------------------------------------------------------------------------
# Placement: the RECORDED bytes, through `deliver`'s commit routine, at most
# once per upstream entry id.
#
# `prepare` keeps the snapshot, mints the target identity (`notice_id`, `ts`)
# ONCE, builds the ledger record, and journals `prepared` with the sha256 and
# length of every part it will write. `place` rebuilds the notice and spool
# from the snapshot and the minted identity (a pure function, so the bytes are
# the recorded ones or the record is held), runs the GENERATION CHECK (a
# generation that is no longer current gets the entry as `late_inbound` in
# its quarantine, nothing placed), journals `placing`, and commits through
# `deliver._place`: blobs, spool, ledger, notice LAST. Once `placing` is
# written, only `recover_placing`'s table decides.
#
# THE GUARANTEE, accepted by the owner: at most one agent-visible notice per
# upstream entry id, ever. A crash between the ledger write and the notice
# commit, with no delivery evidence, is a terminal, visible operator hold
# (`placing_ambiguous`). It rests on the ledger being durable before the
# notice (`deliver._commit`: `atomic_write`, then the notice).
# ---------------------------------------------------------------------------

#: The ledger's `transport` for a notice placed from the external leg.
LEDGER_TRANSPORT = "hop"

HELD_PLACING_AMBIGUOUS = "placing_ambiguous"
HELD_SURVIVOR_MISMATCH = "placing_survivor_mismatch"
HELD_EXISTS_DIFFERENT = "exists_different"
HELD_SNAPSHOT_FINAL = "snapshot_invalid:final"
#: The holds no pump re-evaluates; only an operator verb releases them.
TERMINAL_HOLDS = (HELD_PLACING_AMBIGUOUS, HELD_SURVIVOR_MISMATCH)


def _doc_bytes(doc: Dict[str, Any]) -> bytes:
    """Exactly the bytes `deliver._commit` writes for a document."""
    return json.dumps(doc, sort_keys=True).encode("utf-8")


def _part(data: bytes) -> Dict[str, Any]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "len": len(data)}


def _rewrite_refs(descs: Any, notice_id: str) -> None:
    if isinstance(descs, list):
        for k, d in enumerate(descs):
            if isinstance(d, dict) and "content_ref" in d:
                d["content_ref"] = attachments_mod.content_ref_for(notice_id, k)


def final_documents(notice_raw: bytes, spool_raw: bytes, notice_id: str,
                    ts: str) -> "tuple[Dict[str, Any], Dict[str, Any]]":
    """The (spool, notice) this router places for an upstream notice: the
    received documents with THIS router's minted `notice_id` (and the
    notice's `ts`), `mailbox` "inbox", and every `content_ref` re-pointed to
    the minted id at its own position. Everything else is as received. A
    pure function of its arguments, so a re-placement after a crash writes
    the same bytes."""
    notice = json.loads(notice_raw.decode("utf-8"))
    spool = json.loads(spool_raw.decode("utf-8"))
    notice["notice_id"] = notice_id
    notice["ts"] = ts
    notice["message"]["mailbox"] = "inbox"
    _rewrite_refs(notice["message"].get("attachments"), notice_id)
    spool["notice_id"] = notice_id
    _rewrite_refs(spool.get("attachments"), notice_id)
    return spool, notice


def _verified(notice: Dict[str, Any], blobs: List[Optional[bytes]]
              ) -> List[Optional[attachments_mod.VerifiedAttachment]]:
    out: List[Optional[attachments_mod.VerifiedAttachment]] = []
    for d, blob in zip(notice["message"].get("attachments", []), blobs):
        out.append(None if blob is None else attachments_mod.VerifiedAttachment(
            filename=d["filename"], media_type=d["media_type"], size_bytes=len(blob),
            sha256=hashlib.sha256(blob).hexdigest(), data=blob))
    return out


def prepare(cfg: Any, state_dir: Path, logical_id: str, gen: str, link: str,
            entry_id: str, parsed: Dict[str, Any], *, recipient: str,
            digests: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Snapshot `parsed` (unless `digests` names the snapshot already kept
    and verified for it, a held entry now placeable), mint the target
    identity once, and journal `prepared` with the final parts' digests and
    the ledger bytes."""
    if digests is None:
        digests = take_snapshot(state_dir, logical_id, gen, "notice", link, entry_id, parsed)
    notice_id, ts = mint_notice_id(), utc_ts()
    spool, notice = final_documents(parsed["raw"]["notice"], parsed["raw"]["spool"],
                                    notice_id, ts)
    ledger = binding_mod.record_delivery(
        state_dir, notice_id=notice_id, from_instance=None,
        from_address=notice["message"]["from"], to_instance=recipient, ts=ts, req_id="",
        message_id=notice["message"]["id"], transport=LEDGER_TRANSPORT,
        tree=deliver_mod.TREE_INBOX)
    ledger = deliver_mod._stamp_ids(cfg, ledger, None, recipient)
    final = {"notice": _part(_doc_bytes(notice)), "spool": _part(_doc_bytes(spool)),
             "ledger": _part(ledger),
             "attachments": [None if b is None else _part(b) for b in parsed["attachments"]]}
    return write(state_dir, logical_id, gen, "notice", link, entry_id, PREPARED,
                 snapshot=digests, notice_id=notice_id, ts=ts, recipient=recipient,
                 ledger=ledger.decode("utf-8"), final=final)


def generation_is_current(state_dir: Path, logical_id: str, gen: str) -> Optional[bool]:
    """True or False, or None when the generations file cannot say (held:
    no decision this pump)."""
    try:
        doc = generations_mod.read_doc(state_dir, logical_id)
    except generations_mod.GenerationHeld:
        return None
    if doc is None:
        return None
    return doc["current"] == gen


def _rebuild(state_dir: Path, logical_id: str, gen: str, link: str, entry_id: str,
             rec: Dict[str, Any], attachment_cap: int):
    """The recorded parts, rebuilt from the snapshot, or a hold reason."""
    try:
        kept = verify_snapshot(state_dir, logical_id, gen, "notice", link, entry_id,
                               rec.get("snapshot"), attachment_cap=attachment_cap)
    except SnapshotInvalid as e:
        return None, e.reason
    spool, notice = final_documents(kept["notice"], kept["spool"], rec["notice_id"], rec["ts"])
    ledger = rec["ledger"].encode("utf-8")
    final = rec["final"]
    if (_part(_doc_bytes(notice)) != final["notice"] or _part(_doc_bytes(spool)) != final["spool"]
            or _part(ledger) != final["ledger"]
            or [None if b is None else _part(b) for b in kept["attachments"]]
            != final["attachments"]):
        return None, HELD_SNAPSHOT_FINAL
    return {"notice": notice, "spool": spool, "ledger": ledger,
            "attachments": kept["attachments"]}, None


def _quarantine_late(state_dir: Path, logical_id: str, gen: str, link: str, entry_id: str,
                     rec: Dict[str, Any]) -> str:
    try:
        write_quarantine_item(state_dir, logical_id, gen, "notice", link, entry_id,
                              quarantine_mod.CAUSE_LATE_INBOUND, digests=rec.get("snapshot"))
    except QuarantineConflict:
        write(state_dir, logical_id, gen, "notice", link, entry_id, HELD,
              reason=QuarantineConflict.reason)
        return HELD
    write(state_dir, logical_id, gen, "notice", link, entry_id, QUARANTINED,
          reason=quarantine_mod.CAUSE_LATE_INBOUND)
    return QUARANTINED


def _commit_recorded(cfg: Any, state_dir: Path, rec: Dict[str, Any],
                     parts: Dict[str, Any]) -> None:
    recipient = rec["recipient"]
    icfg = cfg.instances[recipient]
    deliver_mod._place(
        cfg=cfg, root=icfg.root, tree_root=icfg.inbox_root, state_dir=state_dir,
        recipient=recipient, notice_id=rec["notice_id"],
        recipient_key=config_mod.state_key(cfg, recipient),
        message_doc=parts["spool"], notice_doc=parts["notice"], ledger_bytes=parts["ledger"],
        attachments=_verified(parts["notice"], parts["attachments"]))


def _published(state_dir: Path, logical_id: str, gen: str, link: str, entry_id: str) -> str:
    write(state_dir, logical_id, gen, "notice", link, entry_id, PUBLISHED)
    # Never a resting state: moved on in the same pump (a restart that finds
    # one moves it on first).
    write(state_dir, logical_id, gen, "notice", link, entry_id, PUBLISHED_WAITING_REMOVE)
    return PUBLISHED_WAITING_REMOVE


def place(cfg: Any, state_dir: Path, logical_id: str, gen: str, link: str, entry_id: str,
          *, attachment_cap: int) -> Optional[str]:
    """Move a `prepared` record on: held, quarantined (late), or placed and
    `published_waiting_remove`. None when nothing could be decided this pump
    (the record stays `prepared`). Call it under the drain lock."""
    key = key_for("notice", link, gen, entry_id)
    rec = read(state_dir, logical_id, gen, "notice", key)
    if rec is None or rec["state"] != PREPARED:
        raise JournalError(f"place: the record is {rec and rec['state']!r}, not prepared")
    parts, why = _rebuild(state_dir, logical_id, gen, link, entry_id, rec, attachment_cap)
    if parts is None:
        write(state_dir, logical_id, gen, "notice", link, entry_id, HELD, reason=why)
        return HELD
    # The local-delivery gate (`deliver._gate`'s, for a direct placement): a
    # recipient the registry holds gets nothing this pump.
    if config_mod.target_hold(cfg, rec["recipient"]) is not None:
        return None
    # THE GENERATION CHECK, immediately before the first commit byte.
    current = generation_is_current(state_dir, logical_id, gen)
    if current is None:
        return None
    if not current:
        return _quarantine_late(state_dir, logical_id, gen, link, entry_id, rec)
    write(state_dir, logical_id, gen, "notice", link, entry_id, PLACING)
    _commit_recorded(cfg, state_dir, rec, parts)
    return _published(state_dir, logical_id, gen, link, entry_id)


def _read_agent(root: Path, path: Path, cap: int) -> Optional[bytes]:
    """`path` under the agent-owned `root`, read pinned: None when it is
    absent; raises `SnapshotInvalid("not_regular")`-shaped `ValueError` when
    it is anything but a regular file with one link."""
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        dfd = attachments_mod._descend_pinned(root_fd, path.parent.relative_to(root))
    finally:
        os.close(root_fd)
    if dfd is None:
        return None
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise ValueError(f"{path}: {e.strerror}") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError(f"{path}: not a regular file with one link")
            data = b""
            while len(data) <= cap:
                chunk = os.read(fd, cap + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def _fsync_agent(root: Path, path: Path) -> None:
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        dfd = attachments_mod._descend_pinned(root_fd, path.parent.relative_to(root))
    finally:
        os.close(root_fd)
    if dfd is None:
        raise FileNotFoundError(str(path.parent))
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def recover_placing(cfg: Any, state_dir: Path, logical_id: str, gen: str, link: str,
                    entry_id: str, *, attachment_cap: int) -> Optional[str]:
    """THE recovery table, for a record found in `placing` (and only one):

    1. the notice is present: published only if EVERY recorded part (each
       blob, the spool, the ledger and the notice) is present with its
       recorded bytes, after fsyncing the notice and its directory; anything
       missing or different is `placing_survivor_mismatch`, terminal.
    2. the ledger and the notice are both absent: the generation check again;
       a generation no longer current gets `late_inbound` (the only
       `placing -> quarantined` edge, nothing having been committed); else a
       re-placement with the SAME identity and recorded bytes, after any
       part already there is found identical (`exists_different` holds).
    3. the ledger is present and the notice absent: `placing_ambiguous`,
       terminal. It never re-enters this table.

    None when nothing could be decided this pump."""
    key = key_for("notice", link, gen, entry_id)
    rec = read(state_dir, logical_id, gen, "notice", key)
    if rec is None or rec["state"] != PLACING:
        raise JournalError(f"recover_placing: the record is {rec and rec['state']!r}")

    def hold(why: str) -> str:
        write(state_dir, logical_id, gen, "notice", link, entry_id, HELD, reason=why)
        return HELD

    parts, why = _rebuild(state_dir, logical_id, gen, link, entry_id, rec, attachment_cap)
    if parts is None:
        return hold(why)
    recipient = rec["recipient"]
    icfg = cfg.instances[recipient]
    nid = rec["notice_id"]
    tree = icfg.inbox_root
    notice_path = tree / "notices" / f"notice-{nid}.json"
    spool_path = tree / "messages" / f"notice-{nid}.json"
    side = tree / "notices" / attachments_mod.sidecar_dir_name(nid)
    ledger_path = binding_mod.ledger_path(state_dir, recipient, nid,
                                          state_key=config_mod.state_key(cfg, recipient))
    expected = [(notice_path, _doc_bytes(parts["notice"])),
                (spool_path, _doc_bytes(parts["spool"]))]
    expected += [(side / str(k), b) for k, b in enumerate(parts["attachments"]) if b is not None]

    def present(path: Path, want: bytes) -> Optional[bool]:
        """True identical, False different or damaged, None absent."""
        try:
            got = _read_agent(icfg.root, path, len(want))
        except ValueError:
            return False
        return None if got is None else got == want

    try:
        ledger_got: Optional[bytes] = ledger_path.read_bytes()
    except FileNotFoundError:
        ledger_got = None
    notice_state = present(notice_path, expected[0][1])
    if notice_state is not None:
        # Row 1.
        if notice_state and ledger_got == parts["ledger"] and all(
                present(p, b) for p, b in expected[1:]):
            _fsync_agent(icfg.root, notice_path)
            return _published(state_dir, logical_id, gen, link, entry_id)
        return hold(HELD_SURVIVOR_MISMATCH)
    if ledger_got is not None:
        # Row 3.
        return hold(HELD_PLACING_AMBIGUOUS)
    # Row 2.
    current = generation_is_current(state_dir, logical_id, gen)
    if current is None:
        return None
    if not current:
        return _quarantine_late(state_dir, logical_id, gen, link, entry_id, rec)
    if any(present(p, b) is False for p, b in expected[1:]):
        return hold(HELD_EXISTS_DIFFERENT)
    if config_mod.target_hold(cfg, recipient) is not None:
        return None
    _commit_recorded(cfg, state_dir, rec, parts)
    return _published(state_dir, logical_id, gen, link, entry_id)


# ---------------------------------------------------------------------------
# The §7.2 order and A5 admission, on the FACTS only (provenance is never an
# input). FIRST MATCH WINS; one outcome per facts document:
#
#   1  notice_class is not "mail"           -> held (failure notice, RL-07b)
#   2  in_reply_to present                  -> held (bound reply, RL-07b)
#   3  admission "open"                     -> held admission_not_placeable
#   4  fleet_hosts, ingress not "hub"       -> held admission_inconsistent
#   5  admission_link is not this link      -> held admission_link_mismatch
#   6  origin_host a trusted fleet host     -> quarantined cold_fleet_mail
#   7  origin_host not a fleet host         -> held unknown_host
#   8  otherwise (D12, untrusted fleet mail)-> PLACE
#
# Untrusted fleet mail (row 8) is the ONLY placeable class, and that set is
# empty in every deployment today. A value outside the codec's enums is
# `FactsInvalid` (notice_invalid), never a row.
#
# Row 3 is "open" alone: the codec's admission enum is exactly
# {"open", "fleet_hosts"} (its owner's answer), so "inbound_allowlist" is
# notice_invalid here as in the plugin's reader (design delta v3.4).
# ---------------------------------------------------------------------------

PLACE = "place"
HOLD = "hold"
QUARANTINE = "quarantine"

HELD_FAILURE_NOTICE = "failure_notice"
HELD_BOUND_REPLY = "bound_reply"
HELD_NOT_PLACEABLE = "admission_not_placeable"
HELD_INCONSISTENT = "admission_inconsistent"
HELD_LINK_MISMATCH = "admission_link_mismatch"
HELD_UNKNOWN_HOST = "unknown_host"

NOTICE_CLASSES = ("mail", "failure_notice")
#: Exactly the frozen codec's enum: "inbound_allowlist" is refused there at
#: the schema layer, and so here (notice_invalid, verdict-identical).
ADMISSIONS = ("fleet_hosts", "open")
INGRESSES = ("hub",)


def classify_facts(facts: Dict[str, Any], *, link: str, fleet_hosts, trusted_fleet_hosts
                   ) -> "tuple[str, Optional[str]]":
    """`(PLACE, None)`, `(HOLD, reason)` or `(QUARANTINE, cause)` for one
    facts document already through `facts_version`. Raises `FactsInvalid`
    for a value outside the enums, or a member of the wrong type."""
    nc = facts.get("notice_class")
    if nc not in NOTICE_CLASSES:
        raise FactsInvalid(f"notice_class {nc!r} is not one of {list(NOTICE_CLASSES)}")
    admission = facts.get("admission")
    if admission not in ADMISSIONS:
        raise FactsInvalid(f"admission {admission!r} is not one of {list(ADMISSIONS)}")
    ingress_v = facts.get("ingress")
    if ingress_v not in INGRESSES:
        raise FactsInvalid(f"ingress {ingress_v!r} is not one of {list(INGRESSES)}")
    if not (_str(facts.get("admission_link"), nonempty=True)
            and _str(facts.get("admission_rule"), nonempty=True)):
        raise FactsInvalid("admission_link and admission_rule must be non-empty strings")
    origin = facts.get("origin_host")
    if admission == "fleet_hosts":
        try:
            canonical = classify_mod.canonical_host(origin)
        except classify_mod.Malformed:
            raise FactsInvalid("origin_host is not a host name") from None
        if canonical != origin:
            raise FactsInvalid("origin_host is not in canonical (lowercase) form")
    if nc != "mail":
        return HOLD, HELD_FAILURE_NOTICE
    if "in_reply_to" in facts:
        return HOLD, HELD_BOUND_REPLY
    if admission == "open":
        return HOLD, HELD_NOT_PLACEABLE
    # Row 4 is unreachable while the codec's ingress enum is {"hub"}: any
    # other value is refused above as notice_invalid, as the plugin's reader
    # refuses it. Kept, in its frozen place, for the version that adds one.
    if ingress_v != "hub":
        return HOLD, HELD_INCONSISTENT
    if facts["admission_link"] != link:
        return HOLD, HELD_LINK_MISMATCH
    if origin in trusted_fleet_hosts:
        return QUARANTINE, quarantine_mod.CAUSE_COLD_FLEET_MAIL
    if origin not in fleet_hosts:
        return HOLD, HELD_UNKNOWN_HOST
    return PLACE, None


# ---------------------------------------------------------------------------
# The inbound link, PINNED per generation (design delta v3.5 B1). The link is
# inside every journal key, so a config edit must never re-key: the first
# inbound use writes the pin, every later pump compares, and a difference
# latches that generation's inbound off. Changing the link means fencing a
# new generation.
# ---------------------------------------------------------------------------

LINK_PIN_SCHEMA = "amap-router-local.ingress-link/1"
LINK_PIN_NAME = "link.json"
HELD_LINK_UNSET = "hop_link_unset"
HELD_LINK_CHANGED = "hop_link_changed"
HELD_LINK_PIN_DAMAGED = "hop_link_pin_damaged"


def link_pin_path(state_dir: Path, logical_id: str, gen: str) -> Path:
    return generations_mod.gen_dir(state_dir, logical_id, gen) / DIR_NAME / LINK_PIN_NAME


def _any_record(state_dir: Path, logical_id: str, gen: str) -> bool:
    for kind in KINDS:
        try:
            if any(n.endswith(".json") for n in os.listdir(
                    kind_dir(state_dir, logical_id, gen, kind))):
                return True
        except FileNotFoundError:
            continue
    return False


def _read_pin(path: Path) -> Optional[bytes]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) and st.st_nlink == 1):
            raise ValueError("not a regular file with one link")
        return os.read(fd, RECORD_MAX + 1)
    finally:
        os.close(fd)


def pinned_link(state_dir: Path, logical_id: str, gen: str,
                configured: Optional[str]) -> "tuple[Optional[str], Optional[str]]":
    """`(link, None)` to pump this generation with, or `(None, reason)` to
    leave its inbound off: `hop_link_unset` (no `hop.link`),
    `hop_link_changed` (the config differs from the pin), or
    `hop_link_pin_damaged` (an unreadable pin, or journal records with no
    pin). The pin is written create-if-absent on first use and never
    rewritten."""
    if configured is None:
        return None, HELD_LINK_UNSET
    path = link_pin_path(state_dir, logical_id, gen)
    try:
        raw = _read_pin(path)
    except (OSError, ValueError):
        return None, HELD_LINK_PIN_DAMAGED
    if raw is None:
        if _any_record(state_dir, logical_id, gen):
            return None, HELD_LINK_PIN_DAMAGED
        doc = json.dumps({"schema": LINK_PIN_SCHEMA, "link": configured},
                         sort_keys=True).encode("utf-8")
        _mkdir_durable(path.parent, Path(state_dir))
        tmp = path.parent / f".{LINK_PIN_NAME}.{secrets.token_hex(8)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            try:
                os.write(fd, doc)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(tmp, path, follow_symlinks=False)
            except FileExistsError:
                pass                     # another writer pinned first: compare below
        finally:
            os.unlink(tmp)
        fsync_dir(path.parent)
        try:
            raw = _read_pin(path)
        except (OSError, ValueError):
            return None, HELD_LINK_PIN_DAMAGED
    try:
        pin = json.loads((raw or b"").decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, HELD_LINK_PIN_DAMAGED
    if not (isinstance(pin, dict) and set(pin) == {"schema", "link"}
            and pin["schema"] == LINK_PIN_SCHEMA and isinstance(pin["link"], str)
            and config_mod.HOP_LINK_RE.fullmatch(pin["link"])):
        return None, HELD_LINK_PIN_DAMAGED
    if pin["link"] != configured:
        return None, HELD_LINK_CHANGED
    return pin["link"], None


# ---------------------------------------------------------------------------
# The plain-mail RECIPIENT binding (design delta v3.5 B3): a notice read from
# L's tree is for L only if one of its named recipients resolves to L. Plain
# mail carries no transaction, so without this only the tree would bind it.
# ---------------------------------------------------------------------------

HELD_NOT_THIS_IDENTITY = "recipient_not_this_identity"


def named_addresses(spool: Dict[str, Any]) -> List[str]:
    """The spool's `to` and `cc`, each split on "," into elements, each
    element stripped of surrounding whitespace and read by P4's `addr` rule.
    An element with no address is skipped."""
    out: List[str] = []
    for member in ("to", "cc"):
        value = spool.get(member)
        if not isinstance(value, str):
            continue
        for element in value.split(","):
            addr = addr_of(element.strip())
            if addr is not None:
                out.append(addr)
    return out


def addressed_to(cfg: Any, report: Any, logical_id: str,
                 spool: Dict[str, Any]) -> Optional[bool]:
    """True when a named recipient resolves to `logical_id`, by name
    (`<name>@<fleet_domain>` for a configured name whose registry identity it
    is) or through an alias ACTIVE this poll whose target name's identity it
    is; False when none does; None when the registry report is not `ok`
    (no decision: the transient hold).

    THE CASE RULE, each half from the resolver it reuses: by name, the
    domain and the local part both match case-insensitively
    (`config.instance_for` against the configured names); through an alias,
    the local part matches EXACTLY and the domain case-insensitively
    (`aliases.match_key`, the alias table's own rule). A former name with no
    active alias resolves to nobody."""
    if getattr(report, "state", None) != "ok":
        return None
    known = dict(report.known or {})
    table = {a.old: a for a in (getattr(cfg, "aliases", None) or ())}
    view = getattr(cfg, "alias_view", None)
    for addr in named_addresses(spool):
        name = config_mod.instance_for(addr, cfg.fleet_domain, known=cfg.instances)
        if name is not None and known.get(name) == logical_id:
            return True
        k = aliases_mod.match_key(addr)
        a = table.get(k) if k else None
        d = view.decisions.get(a.old) if (a is not None and view is not None) else None
        if d is not None and d.status == aliases_mod.ACTIVE and known.get(d.target) == logical_id:
            return True
    return False


# ---------------------------------------------------------------------------
# THE PUMP: one dispatch order, per (identity, generation), under the drain
# lock (`run` and `once` hold it for the whole process).
#
#   0. recovery: every `placing` record through the table; every `prepared`
#      one through `place`; a `published` one moved on. These keys are never
#      re-dispatched below.
#   1. list the generation's notices.
#   2. key lookup on the listed id, BEFORE any read: a placed or quarantined
#      key is a DUPLICATE (compared whole-bundle, never placed again); a held
#      key goes to its row (terminal: skipped; snapshot kept: re-evaluated
#      from the snapshot; otherwise re-read).
#   3. read_entry: the reader's refusal class gives notice_incomplete (held)
#      or notice_invalid (first sight: quarantined, E17); a runtime class or
#      OSError gives no decision this pump.
#   4-5. the bundle (`parse_bundle`): bundle_schema, entry_id_mismatch,
#      bundle_invalid, each held, no snapshot.
#   6. the facts version (`facts_version`): notice_invalid.
#   7. LATE (E16): the generation is not current -> late_inbound.
#   8. the recipient: the registry names this identity's instance, or no
#      decision (a transient hold, no snapshot).
#   9-10. `classify_facts`.
#   11. snapshot, `prepared`, then `place` (the generation check again).
#
# Removal from upstream is not here: `*_waiting_remove` records wait for the
# remover (`advance_removal`).
# ---------------------------------------------------------------------------

#: A record held for one of these is never re-evaluated by a pump: only an
#: operator verb releases it.
TERMINAL_REASON_PREFIXES = ("snapshot_invalid:",)
TERMINAL_REASONS = TERMINAL_HOLDS + (QuarantineConflict.reason, HELD_EXISTS_DIFFERENT)
#: Holds that keep the snapshot and are re-evaluated FROM it, never re-read.
SNAPSHOT_HOLDS = (HELD_FAILURE_NOTICE, HELD_BOUND_REPLY, HELD_NOT_PLACEABLE,
                  HELD_INCONSISTENT, HELD_LINK_MISMATCH, HELD_UNKNOWN_HOST,
                  HELD_NOT_THIS_IDENTITY)
DUPLICATE_STATES = (PUBLISHED_WAITING_REMOVE, COMPLETE, QUARANTINED_WAITING_REMOVE,
                    QUARANTINED_COMPLETE)
HELD_NOTICE_INCOMPLETE = "notice_incomplete"
HELD_NOTICE_INVALID = "notice_invalid"


def is_terminal(reason: Optional[str]) -> bool:
    return reason in TERMINAL_REASONS or any(
        isinstance(reason, str) and reason.startswith(p) for p in TERMINAL_REASON_PREFIXES)


class Pump:
    """What one generation's dispatch needs, fixed for the pump: the config
    as the poll keyed it, the reader, and this router's own decisions about
    the identity (its instance name, or why there is none)."""

    def __init__(self, cfg: Any, reader: Any, logical_id: str, gen: str, link: str, *,
                 report: Any, recipient: Optional[str], unresolved: Optional[str],
                 attachment_cap: int, runtime_classes: tuple = (),
                 proven_unknown: bool = False):
        self.cfg, self.reader, self.report = cfg, reader, report
        # A4: the registry was read, valid, and the identity is absent or
        # retired. Every generation of it is then non-current (E16).
        self.proven_unknown = proven_unknown
        self.logical_id, self.gen, self.link = logical_id, gen, link
        self.recipient, self.unresolved = recipient, unresolved
        self.attachment_cap = attachment_cap
        self.runtime_classes = runtime_classes
        self.counts: Dict[str, int] = {}

    @property
    def state_dir(self) -> Path:
        return Path(self.cfg.state_dir)

    def count(self, what: str) -> None:
        self.counts[what] = self.counts.get(what, 0) + 1

    def jw(self, entry_id: str, state: str, **kw: Any) -> Dict[str, Any]:
        return write(self.state_dir, self.logical_id, self.gen, "notice", self.link,
                     entry_id, state, **kw)

    # -- 0. recovery ------------------------------------------------------

    def recover(self) -> None:
        records = journal_records(self.state_dir, self.logical_id, self.gen, "notice")
        for entry_id, rec in sorted(records.items()):
            st = rec["state"]
            if st == PLACING:
                self.count("recovered_placing")
                recover_placing(self.cfg, self.state_dir, self.logical_id, self.gen,
                                self.link, entry_id, attachment_cap=self.attachment_cap)
            elif st == PREPARED:
                self.count("recovered_prepared")
                place(self.cfg, self.state_dir, self.logical_id, self.gen, self.link,
                      entry_id, attachment_cap=self.attachment_cap)
            elif st == PUBLISHED:
                self.jw(entry_id, PUBLISHED_WAITING_REMOVE)
            elif st == QUARANTINED:
                self.jw(entry_id, QUARANTINED_WAITING_REMOVE)

    # -- 2. onward, one listed entry ---------------------------------------

    def dispatch(self, entry_id: str) -> Optional[str]:
        """One listed entry through steps 2-11. Returns what happened, for the
        counts; None when nothing could be decided this pump."""
        key = key_for("notice", self.link, self.gen, entry_id)
        rec = read(self.state_dir, self.logical_id, self.gen, "notice", key)
        if rec is not None:
            st, reason = rec["state"], rec.get("reason")
            if st in (PREPARED, PLACING, PUBLISHED, QUARANTINED):
                return None          # step 0's, never re-dispatched
            if st == DUPLICATE_DIFFERENT_HELD:
                return "terminal"
            if st in DUPLICATE_STATES:
                return self.duplicate(entry_id, rec)
            if st == HELD and is_terminal(reason):
                return "terminal"
            if st == HELD and "snapshot" in rec:
                return self.from_snapshot(entry_id, rec)
        return self.first_read(entry_id, rec)

    def _read(self, entry_id: str):
        """`(bytes, None)`, `(None, refusal_reason)`, or `(None, None)` for no
        decision this pump."""
        try:
            return self.reader.port.read_entry("notice", entry_id), None
        except self.reader.notice_refused as e:
            return None, getattr(e, "reason", None)
        except (OSError,) + tuple(self.runtime_classes):
            return None, None

    def first_read(self, entry_id: str, rec: Optional[Dict[str, Any]]) -> Optional[str]:
        raw, refusal = self._read(entry_id)
        if raw is None:
            if refusal == HELD_NOTICE_INCOMPLETE:
                self.jw(entry_id, HELD, reason=HELD_NOTICE_INCOMPLETE)
                return "held"
            if refusal == HELD_NOTICE_INVALID:
                return self.quarantine_refused(entry_id, rec)
            return None
        try:
            parsed = parse_bundle(raw, entry_id, attachment_cap=self.attachment_cap)
            check_facts(parsed)
        except BundleRefused as e:
            self.jw(entry_id, HELD, reason=e.reason)
            return "held"
        except FactsInvalid:
            return self.quarantine_refused(entry_id, rec)
        return self.decide(entry_id, parsed, rec=rec)

    def quarantine_refused(self, entry_id: str, rec: Optional[Dict[str, Any]]) -> str:
        """notice_invalid. On FIRST sight (no record for the key) it is
        quarantined, E17: the evidence is the refusal's reason, nothing read
        from the refused bytes. A key that already has a record (re-read
        holds) is held instead: its first sight was not invalid."""
        if rec is not None:
            self.jw(entry_id, HELD, reason=HELD_NOTICE_INVALID)
            return "held"
        try:
            write_quarantine_item(self.state_dir, self.logical_id, self.gen, "notice",
                                  self.link, entry_id, quarantine_mod.CAUSE_NOTICE_INVALID)
        except QuarantineConflict:
            self.jw(entry_id, HELD, reason=QuarantineConflict.reason)
            return "held"
        self.jw(entry_id, QUARANTINED, reason=quarantine_mod.CAUSE_NOTICE_INVALID)
        self.jw(entry_id, QUARANTINED_WAITING_REMOVE)
        return "quarantined"

    def decide(self, entry_id: str, parsed: Dict[str, Any],
               digests: Optional[Dict[str, Any]] = None,
               rec: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Steps 7-11 over a valid bundle. `rec` is the entry's record, if
        any; `digests` its snapshot, already kept, when re-evaluating a held
        one."""
        current = (False if self.proven_unknown
                   else generation_is_current(self.state_dir, self.logical_id, self.gen))
        if current is None:
            return None
        if not current:
            return self.quarantine(entry_id, parsed, digests, quarantine_mod.CAUSE_LATE_INBOUND)
        if self.recipient is None:
            return None              # a transient registry hold: no snapshot
        bound = addressed_to(self.cfg, self.report, self.logical_id, parsed["spool"])
        if bound is None:
            return None
        if not bound:
            return self.hold_with_snapshot(entry_id, parsed, digests, HELD_NOT_THIS_IDENTITY,
                                           rec)
        try:
            outcome, why = classify_facts(parsed["facts"], link=self.link,
                                          fleet_hosts=self.cfg.fleet_hosts,
                                          trusted_fleet_hosts=self.cfg.trusted_fleet_hosts)
        except FactsInvalid:
            return self.quarantine_refused(entry_id, rec)
        if outcome == QUARANTINE:
            return self.quarantine(entry_id, parsed, digests, why)
        if outcome == HOLD:
            return self.hold_with_snapshot(entry_id, parsed, digests, why, rec)
        # Placeable. A held entry places from the snapshot it already kept.
        prepare(self.cfg, self.state_dir, self.logical_id, self.gen, self.link, entry_id,
                parsed, recipient=self.recipient, digests=digests)
        got = place(self.cfg, self.state_dir, self.logical_id, self.gen, self.link, entry_id,
                    attachment_cap=self.attachment_cap)
        return {PUBLISHED_WAITING_REMOVE: "placed"}.get(got, got and got.lower())

    def _snapshot(self, entry_id: str, parsed: Dict[str, Any],
                  digests: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if digests is not None:
            return digests
        return take_snapshot(self.state_dir, self.logical_id, self.gen, "notice", self.link,
                             entry_id, parsed)

    def quarantine(self, entry_id: str, parsed: Dict[str, Any],
                   digests: Optional[Dict[str, Any]], cause: str) -> str:
        digests = self._snapshot(entry_id, parsed, digests)
        try:
            write_quarantine_item(self.state_dir, self.logical_id, self.gen, "notice",
                                  self.link, entry_id, cause, digests=digests)
        except QuarantineConflict:
            self.jw(entry_id, HELD, reason=QuarantineConflict.reason, snapshot=digests)
            return "held"
        self.jw(entry_id, QUARANTINED, reason=cause, snapshot=digests)
        self.jw(entry_id, QUARANTINED_WAITING_REMOVE)
        return "quarantined"

    def hold_with_snapshot(self, entry_id: str, parsed: Dict[str, Any],
                           digests: Optional[Dict[str, Any]], reason: str,
                           rec: Optional[Dict[str, Any]]) -> str:
        if digests is not None:
            if rec is not None and rec.get("reason") != reason:
                self.jw(entry_id, HELD, reason=reason)
            return "held"            # unchanged: no journal churn every pump
        digests = self._snapshot(entry_id, parsed, None)
        self.jw(entry_id, HELD, reason=reason, snapshot=digests)
        return "held"

    def from_snapshot(self, entry_id: str, rec: Dict[str, Any]) -> Optional[str]:
        """A snapshot-kept hold, re-evaluated from what was READ, never
        re-read: the late check first (E16 takes precedence), then the
        order again."""
        try:
            kept = verify_snapshot(self.state_dir, self.logical_id, self.gen, "notice",
                                   self.link, entry_id, rec.get("snapshot"),
                                   attachment_cap=self.attachment_cap)
        except SnapshotInvalid as e:
            self.jw(entry_id, HELD, reason=e.reason)
            return "held"
        parsed = {"notice": json.loads(kept["notice"]), "spool": json.loads(kept["spool"]),
                  "facts": json.loads(kept["hop"]),
                  "raw": {"notice": kept["notice"], "spool": kept["spool"],
                          "facts": kept["hop"]},
                  "attachments": kept["attachments"]}
        return self.decide(entry_id, parsed, digests=rec["snapshot"], rec=rec)

    # -- duplicates (whole-bundle until the projection gate opens) ----------

    def duplicate(self, entry_id: str, rec: Dict[str, Any]) -> Optional[str]:
        """A placed or quarantined key listed again. Never placed or
        quarantined again. Compared WHOLE-BUNDLE against its snapshot: the
        same bytes go back to removal; anything else is
        `duplicate_different_held`, terminal. A re-read refused as
        notice_incomplete is removed again; one refused as notice_invalid
        over a valid snapshot holds."""
        raw, refusal = self._read(entry_id)
        if raw is None:
            if refusal == HELD_NOTICE_INCOMPLETE:
                return self.remove_again(entry_id, rec)
            if refusal == HELD_NOTICE_INVALID:
                if "snapshot" not in rec:
                    # Quarantined as invalid on first sight, and invalid
                    # still: the same entry, removed again.
                    return self.remove_again(entry_id, rec)
                self.jw(entry_id, DUPLICATE_DIFFERENT_HELD, reason=HELD_NOTICE_INVALID)
                return "terminal"
            return None
        if "snapshot" not in rec:
            # Quarantined on first sight as invalid: nothing was kept to
            # compare with, and a listed copy that now reads is different.
            self.jw(entry_id, DUPLICATE_DIFFERENT_HELD, reason="differs")
            return "terminal"
        try:
            parsed = parse_bundle(raw, entry_id, attachment_cap=self.attachment_cap)
        except BundleRefused:
            self.jw(entry_id, DUPLICATE_DIFFERENT_HELD, reason="differs")
            return "terminal"
        same = (_digests_of(parsed) == rec["snapshot"])
        if not same:
            self.jw(entry_id, DUPLICATE_DIFFERENT_HELD, reason="differs")
            return "terminal"
        return self.remove_again(entry_id, rec)

    def remove_again(self, entry_id: str, rec: Dict[str, Any]) -> str:
        st = rec["state"]
        if st == COMPLETE:
            self.jw(entry_id, PUBLISHED_WAITING_REMOVE)
        elif st == QUARANTINED_COMPLETE:
            self.jw(entry_id, QUARANTINED_WAITING_REMOVE)
        return "duplicate"


def _digests_of(parsed: Dict[str, Any]) -> Dict[str, Any]:
    raw = parsed["raw"]
    return {"notice": hashlib.sha256(raw["notice"]).hexdigest(),
            "spool": hashlib.sha256(raw["spool"]).hexdigest(),
            "hop": hashlib.sha256(raw["facts"]).hexdigest(),
            "attachments": [None if b is None else hashlib.sha256(b).hexdigest()
                            for b in parsed["attachments"]]}


# ---------------------------------------------------------------------------
# Driving the pump: one listing page per reader per poll.
# ---------------------------------------------------------------------------

#: (state_dir, logical_id, gen) -> the listing cursor (`after`), kept per
#: process. A page with `truncated` False restarts it from None.
_CURSORS: Dict[tuple, Optional[str]] = {}
HELD_LISTING_TOO_LARGE = "hop_listing_too_large"


#: (state_dir, logical_id, gen) -> why inbound is latched off for the process.
_LINK_LATCHED: Dict[tuple, str] = {}


def pump_generation(pump: Pump, *, listing_too_large: Any = (),
                    limit: int = transport_mod.LIST_LIMIT_MAX) -> Dict[str, int]:
    """Step 0, then one listing page and each listed entry through
    `Pump.dispatch`. A `listing_too_large` (the runtime's class) is a
    self-clearing hold for this generation, counted; nothing is listed or
    read past it this pump. `pump.link` must be the generation's PIN
    (`pinned_link`), never the live config value."""
    pump.recover()
    key = (str(pump.state_dir), pump.logical_id, pump.gen)
    try:
        ids, truncated = pump.reader.port.list_entries("notice", limit=limit,
                                                         after=_CURSORS.get(key))
    except listing_too_large:
        pump.count(HELD_LISTING_TOO_LARGE)
        logger.error("ingress %s gen %s: listing too large; held this pump",
                     pump.logical_id, pump.gen)
        return pump.counts
    _CURSORS[key] = ids[-1] if (truncated and ids) else None
    for entry_id in ids:
        try:
            what = pump.dispatch(entry_id)
        except JournalError:
            # A damaged record is never read as absent (absent would let the
            # entry be placed again): logged, and the entry left alone.
            logger.exception("ingress %s gen %s: a damaged journal record",
                             pump.logical_id, pump.gen)
            what = "journal_damaged"
        pump.count(what or "undecided")
    return pump.counts


def identities(cfg: Any, report: Any) -> List[Dict[str, Any]]:
    """Every identity the pump reads for: each configured name's logical_id
    the registry knows (its instance the recipient when resolved, else none:
    a transient hold), plus each identity with generations in `state_dir`
    that no configured name maps to. That last is PROVEN UNKNOWN only when
    the registry was read and valid and has no active entry for it; any
    other reading is transient (no decision)."""
    out: List[Dict[str, Any]] = []
    known = dict(report.known or {})
    seen = set()
    for name in sorted(cfg.instances):
        lid = known.get(name)
        if lid is None:
            continue
        seen.add(lid)
        out.append({"logical_id": lid, "recipient": name if name in (report.resolved or {})
                    else None, "unresolved": (report.held or {}).get(name),
                    "proven_unknown": False})
    active = {e.logical_id for e in report.all_entries if e.state == "active"}
    try:
        names = sorted(os.listdir(cfg.state_dir))
    except FileNotFoundError:
        names = []
    for lid in names:
        if lid in seen or not _GEN_RE.fullmatch(lid):
            continue
        if not generations_mod.gen_file(Path(cfg.state_dir), lid).exists():
            continue
        proven = report.state == "ok" and lid not in active
        out.append({"logical_id": lid, "recipient": None,
                    "unresolved": None if proven else "identity_unresolved",
                    "proven_unknown": proven})
    return out


def pump_link(cfg: Any, logical_id: str, gen: str) -> Optional[str]:
    """The link to pump `gen` with: the generation's pin, checked against
    `config.hop.link` BEFORE anything is listed. A refusal latches that
    generation's inbound off for the process, with one ERROR; nothing is
    re-keyed or rewritten."""
    key = (str(cfg.state_dir), logical_id, gen)
    if key in _LINK_LATCHED:
        return None
    link, why = pinned_link(Path(cfg.state_dir), logical_id, gen, cfg.hop.link)
    if why is not None:
        _LINK_LATCHED[key] = why
        logger.error("ingress %s gen %s: inbound off (%s)", logical_id, gen, why)
        return None
    return link


def pump_all(cfg: Any, runtime: Any, report: Any) -> Dict[str, Dict[str, int]]:
    """One poll's inbound pass, under the drain lock: every identity
    (`identities`), every generation of it with a recorded tree, through
    `pump_link` (the pin, before any listing), the cached reader
    (`hoplink.reader_for`) and `pump_generation`. Each generation is
    isolated: a failure in one is logged and the next proceeds. Returns
    `{"<logical_id>/<gen>": counts}` for status; never part of the drain
    summary."""
    from . import hoplink as hoplink_mod   # local: hoplink imports this module's peers
    out: Dict[str, Dict[str, int]] = {}
    if cfg.hop is None or cfg.hop.link is None:
        return out
    fsops = runtime.fsops
    runtime_classes = tuple(c for c in (getattr(fsops, "UnsafeRead", None),) if c)
    too_large = getattr(fsops, "ListingTooLarge", ())
    for ident in identities(cfg, report):
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
            link = pump_link(cfg, lid, gen)
            if link is None:
                out[label] = {_LINK_LATCHED.get((str(cfg.state_dir), lid, gen),
                                                HELD_LINK_UNSET): 1}
                continue
            try:
                reader = hoplink_mod.reader_for(runtime, cfg, lid, gen)
            except hoplink_mod.HopHold as e:
                out[label] = {e.reason: 1}
                continue
            pump = Pump(cfg, reader, lid, gen, link, report=report,
                        recipient=ident["recipient"], unresolved=ident["unresolved"],
                        attachment_cap=cfg.hop.cap("attachment"),
                        runtime_classes=runtime_classes,
                        proven_unknown=ident["proven_unknown"])
            try:
                out[label] = pump_generation(pump, listing_too_large=too_large)
            except Exception:  # noqa: BLE001 -- isolated per generation
                logger.exception("ingress %s: pump failed; isolated", label)
                out[label] = {"pump_errored": 1}
    return out
