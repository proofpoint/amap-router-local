"""router/quarantine.py — the ingress quarantine's item format, frozen, and its
read-only inspection (`router quarantine list|show`).

OWNERSHIP IS SPLIT, deliberately. This module FREEZES the format and READS
it. The WRITER (cross-host inbound held in a generation's quarantine) and
the expiry SWEEP are a later step's, and that step must write exactly this
format. Nothing here creates, moves or deletes anything.

WHERE: `state_dir/<logical_id>/gen-<g>/ingress-quarantine/<id>.json`, one
file per item, in every generation of the identity (late inbound for a
retired or fenced generation is held in THAT generation's quarantine and is
never placed into a later one). Without a registry there are no
generations, and so no ingress quarantine.

THE ITEM, a JSON object with exactly these members:

    {"schema": "amap-router-local.ingress-quarantine/1",
     "id": "<32 lowercase hex>",          # equal to the filename stem
     "generation": "<32 lowercase hex>",  # equal to the directory's
     "arrival_ts": "YYYY-MM-DDTHH:MM:SSZ",
     "causes": ["<cause>", ...],          # non-empty, no duplicates, CAUSES
     "evidence": {"<key>": <value>, ...}} # see below

`causes` is drawn from a CLOSED vocabulary. Today it holds one cause,
`cold_fleet_mail`, for cold traffic from a trusted fleet host. The
peer-origin profile's §5 causes join it when the profile revision that
defines them is published: until then they are not this public
repository's to copy, and an item naming one is DAMAGED. No writer exists
yet, so nothing that could be written is lost meanwhile.

`evidence` is HOSTILE INPUT: what arrived, described by the writer from
what the sender controlled. At most 32 members; each key 1-64 printable
ASCII characters; each value a string of at most 1024 characters or an
integer (never a JSON boolean) of magnitude below 2**53; at most 16 KiB
serialized. It is printed JSON-escaped (`ensure_ascii`), never raw.

READING. The item file is at most 64 KiB, opened with `O_NOFOLLOW` beneath
directories each opened with `O_NOFOLLOW`, required to be a regular file
with one link, and read to its cap plus one byte. Anything that fails a
rule, a corrupt, oversize, linked or non-regular entry, an unexpected name,
an `arrival_ts` more than `SKEW_S` in the future, is listed as DAMAGED with
the reason, and never hidden. A DAMAGED item's content is never printed.

THE KEY. One item is named across identities, sources and generations as

    NAME SOURCE GEN ID

SOURCE is `ingress` or `control`. For `ingress`, GEN is the 32-hex
generation and ID the item id. For `control`, NAME and GEN are `-`: the
`.control/` intake belongs to the host, not to an identity.

`.control/` ENTRIES are candidates another runtime writes there; this
module only lists them. ID is the candidate's 32-hex DIRECTORY name, and
`show` gives METADATA ONLY (its `candidate.json`'s size, sha256 and mtime,
read pinned and bounded) until the inbound step freezes their format. A
`candidate.json` with exactly two links is a link-commit caught in
progress: listed IN FLIGHT and not read. Any other link count is DAMAGED. The
intake's path is the inbound step's to configure; until then the CLI takes
it as `--control-dir`.

RETENTION: `ingress_quarantine_days` (config, default 14). `list` shows each
item's age and how long until its writer's sweep removes it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import parse_utc_ts, utc_ts

SCHEMA = "amap-router-local.ingress-quarantine/1"
DIR_NAME = "ingress-quarantine"
GEN_PREFIX = "gen-"

SOURCE_INGRESS = "ingress"
SOURCE_CONTROL = "control"
SOURCES = (SOURCE_INGRESS, SOURCE_CONTROL)

#: This router's own cause for cold trusted-host traffic. The profile's §5
#: causes are added beside it once published (module docstring).
CAUSE_COLD_FLEET_MAIL = "cold_fleet_mail"
CAUSES = (CAUSE_COLD_FLEET_MAIL,)

ITEM_MAX_BYTES = 64 * 1024
CANDIDATE_MAX_BYTES = 1024 * 1024
EVIDENCE_MAX_KEYS = 32
EVIDENCE_KEY_MAX = 64
EVIDENCE_STR_MAX = 1024
EVIDENCE_INT_LIMIT = 2 ** 53
EVIDENCE_MAX_BYTES = 16 * 1024
#: How far in the future an `arrival_ts` may lie before the item is DAMAGED.
SKEW_S = 300

_KEYS = frozenset({"schema", "id", "generation", "arrival_ts", "causes", "evidence"})
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_ITEM_FILE = re.compile(r"([0-9a-f]{32})\.json\Z")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_EVIDENCE_KEY = re.compile(r"[\x20-\x7e]{1,%d}\Z" % EVIDENCE_KEY_MAX)


class Damaged(ValueError):
    """An entry outside the format. `str(e)` is the reason, and never echoes
    the entry's content."""


class Linked(Damaged):
    """A regular file with more than one link. `nlink` is how many."""

    def __init__(self, nlink: int):
        super().__init__("a regular file with more than one link")
        self.nlink = nlink


@dataclass
class Item:
    """One listed entry. `doc` is set only for an ingress item that passed
    every rule; `meta` only for a control entry."""
    source: str
    name: str
    generation: str
    id: str
    damaged: Optional[str] = None
    doc: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    age_s: Optional[int] = None
    expires_in_s: Optional[int] = None

    def key(self) -> str:
        return f"{self.name} {self.source} {self.generation} {self.id}"


def display(text: str) -> str:
    """A filesystem name or a string from an item, safe on a terminal."""
    return json.dumps(text, ensure_ascii=True)[1:-1]


def _strict_json(raw: bytes) -> Any:
    def pairs(items):
        out: Dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise Damaged("a duplicate member")
            out[k] = v
        return out

    def no_constant(_value: str) -> Any:
        raise Damaged("a non-finite number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Damaged("not JSON") from None


def _int_ok(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and abs(v) < EVIDENCE_INT_LIMIT


def check_evidence(ev: Any) -> None:
    if not isinstance(ev, dict):
        raise Damaged("evidence is not an object")
    if len(ev) > EVIDENCE_MAX_KEYS:
        raise Damaged(f"evidence has more than {EVIDENCE_MAX_KEYS} members")
    for k, v in ev.items():
        if not _EVIDENCE_KEY.fullmatch(k):
            raise Damaged("an evidence key is not 1-64 printable ASCII characters")
        if isinstance(v, str):
            if len(v) > EVIDENCE_STR_MAX:
                raise Damaged(f"an evidence string exceeds {EVIDENCE_STR_MAX} characters")
        elif not _int_ok(v):
            raise Damaged("an evidence value is neither a bounded string nor an integer")
    size = len(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    if size > EVIDENCE_MAX_BYTES:
        raise Damaged(f"evidence exceeds {EVIDENCE_MAX_BYTES} bytes")


def check_item(doc: Any, *, item_id: str, generation: str, now: datetime) -> Dict[str, Any]:
    """`doc` if it is an item in the frozen format, else `Damaged`."""
    if not isinstance(doc, dict):
        raise Damaged("not an object")
    if set(doc) != _KEYS:
        raise Damaged("members are not exactly " + ", ".join(sorted(_KEYS)))
    if doc["schema"] != SCHEMA:
        raise Damaged("unknown schema")
    if not (isinstance(doc["id"], str) and _HEX32.fullmatch(doc["id"])):
        raise Damaged("id is not 32 lowercase hex")
    if doc["id"] != item_id:
        raise Damaged("id differs from the filename")
    if not (isinstance(doc["generation"], str) and _HEX32.fullmatch(doc["generation"])):
        raise Damaged("generation is not 32 lowercase hex")
    if doc["generation"] != generation:
        raise Damaged("generation differs from the directory")
    ts = doc["arrival_ts"]
    arrived = parse_utc_ts(ts) if isinstance(ts, str) and _TS.fullmatch(ts) else None
    if arrived is None:
        raise Damaged("arrival_ts is not a UTC timestamp")
    if (arrived - now).total_seconds() > SKEW_S:
        raise Damaged(f"arrival_ts is more than {SKEW_S}s in the future")
    causes = doc["causes"]
    if not (isinstance(causes, list) and causes and all(isinstance(c, str) for c in causes)):
        raise Damaged("causes is not a non-empty list of strings")
    if len(set(causes)) != len(causes):
        raise Damaged("causes has a duplicate")
    if any(c not in CAUSES for c in causes):
        raise Damaged("causes has a cause outside the vocabulary")
    check_evidence(doc["evidence"])
    return doc


# -- pinned reads -------------------------------------------------------------

def _open_dir(name: str, dir_fd: Optional[int] = None) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)


def read_pinned(dir_fd: int, name: str, cap: int) -> "tuple[bytes, os.stat_result]":
    """A regular file with one link, opened without following a link, read
    to `cap` (one byte more is `Damaged`). The bound is on the bytes READ,
    never on a size the file reported before the read."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                     dir_fd=dir_fd)
    except OSError as e:
        raise Damaged(f"cannot be opened without following a link ({os.strerror(e.errno)})"
                      ) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Damaged("not a regular file")
        if st.st_nlink != 1:
            raise Linked(st.st_nlink)
        chunks, got = [], 0
        while got <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - got))
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        if got > cap:
            raise Damaged(f"larger than {cap} bytes")
        return b"".join(chunks), st
    finally:
        os.close(fd)


def _ages(arrived: datetime, now: datetime, days: int) -> "tuple[int, int]":
    age = int((now - arrived).total_seconds())
    return age, days * 86400 - age


# -- listing ------------------------------------------------------------------

def _now(now: Optional[str]) -> datetime:
    dt = parse_utc_ts(now or utc_ts())
    assert dt is not None
    return dt


def list_ingress(state_dir: Path, logical_id: str, name: str, *, days: int,
                 now: Optional[str] = None) -> List[Item]:
    """Every entry in every generation's ingress quarantine of `logical_id`,
    sorted by generation and id. An identity with no state lists nothing."""
    now_dt = _now(now)
    items: List[Item] = []
    try:
        lid_fd = _open_dir(str(Path(state_dir) / logical_id))
    except FileNotFoundError:
        return []
    try:
        gens = sorted(e.name for e in os.scandir(lid_fd)
                      if e.name.startswith(GEN_PREFIX)
                      and _HEX32.fullmatch(e.name[len(GEN_PREFIX):]))
        for gen_name in gens:
            gen = gen_name[len(GEN_PREFIX):]
            items.extend(_list_generation(lid_fd, gen_name, gen, name, days, now_dt))
    finally:
        os.close(lid_fd)
    return items


def _list_generation(lid_fd: int, gen_name: str, gen: str, name: str, days: int,
                     now: datetime) -> List[Item]:
    def damaged(item_id: str, why: str) -> Item:
        return Item(SOURCE_INGRESS, name, gen, item_id, damaged=why)

    try:
        gen_fd = _open_dir(gen_name, lid_fd)
    except OSError:
        return [damaged("-", "the generation is not a directory reachable without a link")]
    try:
        try:
            q_fd = _open_dir(DIR_NAME, gen_fd)
        except FileNotFoundError:
            return []
        except OSError:
            return [damaged("-", f"{DIR_NAME} is not a directory reachable without a link")]
        try:
            names = sorted(os.listdir(q_fd))
            out = []
            for entry in names:
                m = _ITEM_FILE.fullmatch(entry)
                if m is None:
                    out.append(damaged(display(entry), "an unexpected name"))
                    continue
                item_id = m.group(1)
                try:
                    raw, _st = read_pinned(q_fd, entry, ITEM_MAX_BYTES)
                    doc = check_item(_strict_json(raw), item_id=item_id, generation=gen,
                                     now=now)
                except Damaged as e:
                    out.append(damaged(item_id, str(e)))
                    continue
                age, left = _ages(parse_utc_ts(doc["arrival_ts"]), now, days)
                out.append(Item(SOURCE_INGRESS, name, gen, item_id, doc=doc,
                                age_s=age, expires_in_s=left))
            return out
        finally:
            os.close(q_fd)
    finally:
        os.close(gen_fd)


def list_control(control_dir: Path, *, now: Optional[str] = None) -> List[Item]:
    """Every entry in the `.control/` intake, metadata only (module
    docstring). Never moves, opens for writing, or deletes anything."""
    now_dt = _now(now)
    try:
        c_fd = _open_dir(str(control_dir))
    except FileNotFoundError:
        return []
    try:
        out = []
        for entry in sorted(os.listdir(c_fd)):
            out.append(_control_item(c_fd, entry, now_dt))
        return out
    finally:
        os.close(c_fd)


def _control_item(c_fd: int, entry: str, now: datetime) -> Item:
    if not _HEX32.fullmatch(entry):
        return Item(SOURCE_CONTROL, "-", "-", display(entry), damaged="an unexpected name")
    try:
        d_fd = _open_dir(entry, c_fd)
    except OSError:
        return Item(SOURCE_CONTROL, "-", "-", entry,
                    damaged="not a directory reachable without a link")
    try:
        raw, st = read_pinned(d_fd, "candidate.json", CANDIDATE_MAX_BYTES)
    except Linked as e:
        if e.nlink == 2:
            # Its writer commits candidate.json by link, then removes the
            # staged name: two links is a commit caught in progress, listed
            # as such and never read. Anything else stays DAMAGED.
            return Item(SOURCE_CONTROL, "-", "-", entry, meta={"in_flight": True})
        return Item(SOURCE_CONTROL, "-", "-", entry, damaged=f"candidate.json: {e}")
    except Damaged as e:
        return Item(SOURCE_CONTROL, "-", "-", entry, damaged=f"candidate.json: {e}")
    finally:
        os.close(d_fd)
    mtime = datetime.fromtimestamp(int(st.st_mtime), tz=timezone.utc)
    return Item(SOURCE_CONTROL, "-", "-", entry, age_s=int((now - mtime).total_seconds()),
                meta={"candidate_bytes": len(raw),
                      "candidate_sha256": hashlib.sha256(raw).hexdigest(),
                      "candidate_mtime": mtime.strftime("%Y-%m-%dT%H:%M:%SZ")})


# -- rendering ----------------------------------------------------------------

def render_line(item: Item) -> str:
    if item.damaged is not None:
        return f"{item.key()} DAMAGED {display(item.damaged)}"
    if item.source == SOURCE_CONTROL and item.meta.get("in_flight"):
        return f"{item.key()} IN FLIGHT (candidate.json is being committed)"
    if item.source == SOURCE_CONTROL:
        return f"{item.key()} candidate age={item.age_s}s bytes={item.meta['candidate_bytes']}"
    causes = ",".join(item.doc["causes"])  # vocabulary-checked: printable as is
    left = (f"expires_in={item.expires_in_s}s" if item.expires_in_s > 0
            else "expired (awaiting its sweep)")
    return f"{item.key()} age={item.age_s}s {left} causes={causes}"


def render_show(item: Item) -> str:
    """One item as JSON, escaped. A DAMAGED item shows its reason only; a
    control entry its metadata only."""
    doc: Dict[str, Any] = {"name": item.name, "source": item.source,
                           "generation": item.generation, "id": item.id}
    if item.damaged is not None:
        doc["status"] = "damaged"
        doc["reason"] = item.damaged
    elif item.source == SOURCE_CONTROL and item.meta.get("in_flight"):
        doc["status"] = "in_flight"
    elif item.source == SOURCE_CONTROL:
        doc["status"] = "candidate"
        doc.update(item.meta)
        doc["age_s"] = item.age_s
    else:
        doc["status"] = "held"
        doc["age_s"] = item.age_s
        doc["expires_in_s"] = item.expires_in_s
        doc["item"] = item.doc
    return json.dumps(doc, ensure_ascii=True, sort_keys=True, indent=2)


def counts(items: List[Item]) -> Dict[str, int]:
    return {"items": len(items), "damaged": sum(1 for i in items if i.damaged is not None)}
