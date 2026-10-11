"""router/aliases.py — the alias table (contract §2.3): an exact OLD address
normalised to an identity's current canonical address, before any routing
decision. Under a registry only.

THE TABLE lives in the router config (`config.aliases`, checked at load).
Each poll's pre-pass (`attach`, under the drain lock, before any drain)
decides every entry:

  * ACTIVE: unexpired, not tombstoned, its target a KNOWN identity (resolved
    or registry-held: a held target holds the delivery like a direct
    address would), old's local part in that identity's name history, and
    old's skeleton no OTHER identity's current name;
  * INACTIVE (deterministic): expired, tombstoned, target unknown or retired,
    no name history, not in it, or a skeleton collision. A request naming
    one is answered `recipient_unknown` at normalisation, before any policy;
  * UNVERIFIABLE: the tombstone store cannot be trusted, the target's name
    history is malformed, or the registry is not readable. A request naming
    one is NOT consumed: it stays in the outbox, is retried every poll, and
    is listed in status with a router-owned age and the remedy.

Matching is exact: the local part as written, the domain lowercased. A case
variant is not the alias (it fails closed as an unknown address).

THE TOMBSTONE STORE remembers every alias that expired, so that re-listing
it can never revive it. `state_dir/aliases/tombstones.json` holds
`{seq, tombstones}`. Outside it, in the router's own `state_dir/registry/`:
`aliases.floor` (the highest seq ever written), `aliases.created` (the
creation witness, written LAST at first initialisation), and the durable
audit log `aliases.audit.jsonl`. `store_row` decides every combination of
the three; anything it does not list is unverified. Only the drain
pre-pass writes, under the drain lock; status never does. The way out of
unverified is `router aliases reinit`, which PERMANENTLY retires every
configured alias.

Expiry is decided at use, whatever happened to the tombstone write: a
failed write is an ERROR in status, retried every poll, and never stops
anything else.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

from . import audit as audit_mod
from .registry import HELD_ROLLED_BACK, HELD_UNAVAILABLE, SEQ_DIR, skeleton
from .util import atomic_write, parse_utc_ts, utc_ts

logger = logging.getLogger("amap_router_local.aliases")

STORE_DIR = "aliases"
STORE_FILE = "tombstones.json"
STORE_SCHEMA = "amap-router-local.alias-tombstones/1"
WITNESS = "aliases.created"
FLOOR = "aliases.floor"
AUDIT_LOG = "aliases.audit.jsonl"
WITNESS_BYTES = b"amap-router-local alias store\n"
_FLOOR_CAP = 32

ACTIVE = "active"
INACTIVE = "inactive"
UNVERIFIABLE = "unverifiable"

HELD_STORE = "alias_store_unverified"
HELD_HISTORY = "alias_history_unverified"

EXPIRED = "expired"
TOMBSTONED = "tombstoned"
TARGET_UNKNOWN = "target_unknown"
NO_HISTORY = "no_name_history"
NOT_IN_HISTORY = "not_in_name_history"
COLLISION = "skeleton_collision"
NAME_REUSED = "name_held_by_another_identity"

#: The store rows `store_row` returns (README, "Aliases").
ROW_INIT = "init"
ROW_RECOVER_FLOOR = "recover_floor"
ROW_RECOVER_WITNESS = "recover_witness"
ROW_OK = "ok"
ROW_RAISE_FLOOR = "raise_floor"
ROW_UNVERIFIED = "unverified"

REINIT_WARNING = ("reinit permanently retires every configured alias; tombstoned "
                  "addresses can never be re-enabled")
HOLD_HINT = {
    HELD_STORE: "the alias tombstone store cannot be trusted; once the router is stopped, "
                "`router aliases reinit --reason ...` (permanently retires every configured "
                "alias)",
    HELD_HISTORY: "the target's registry name history is malformed; fix it at the registry",
    HELD_UNAVAILABLE: "the registry is unavailable; it is retried every poll",
    HELD_ROLLED_BACK: "the registry was rolled back; see the registry section",
}


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def store_path(state_dir: Path) -> Path:
    return Path(state_dir) / STORE_DIR / STORE_FILE


def _router_dir(state_dir: Path) -> Path:
    return Path(state_dir) / SEQ_DIR


def floor_path(state_dir: Path) -> Path:
    return _router_dir(state_dir) / FLOOR


def witness_path(state_dir: Path) -> Path:
    return _router_dir(state_dir) / WITNESS


def audit_path(state_dir: Path) -> Path:
    return _router_dir(state_dir) / AUDIT_LOG


# ---------------------------------------------------------------------------
# Reading the store, the floor and the witness
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Store:
    """The tombstone store as read: `kind` "absent", "corrupt" or "ok"."""
    kind: str
    seq: int = 0
    tombstones: Mapping[str, Mapping[str, str]] = field(default_factory=dict)


def _strict(raw: bytes) -> Any:
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate key {k!r}")
            out[k] = v
        return out
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


def read_store(state_dir: Path) -> Store:
    d = Path(state_dir) / STORE_DIR
    try:
        names = [e.name for e in os.scandir(d)]
    except FileNotFoundError:
        return Store("absent")
    except OSError:
        return Store("corrupt")
    # Only the store itself, and an `atomic_write` temporary of it a crash
    # left behind, may be there: anything else is not this router's.
    if any(n != STORE_FILE and not n.startswith(STORE_FILE + ".") for n in names):
        return Store("corrupt")
    if STORE_FILE not in names:
        return Store("absent")
    try:
        doc = _strict(store_path(state_dir).read_bytes())
    except (OSError, UnicodeDecodeError, ValueError):
        return Store("corrupt")
    if not (isinstance(doc, dict) and set(doc) == {"schema", "seq", "tombstones"}
            and doc["schema"] == STORE_SCHEMA
            and isinstance(doc["seq"], int) and not isinstance(doc["seq"], bool)
            and doc["seq"] >= 1 and isinstance(doc["tombstones"], dict)):
        return Store("corrupt")
    for old, t in doc["tombstones"].items():
        if not (isinstance(t, dict) and set(t) == {"expires", "tombstoned_ts"}
                and (t["expires"] is None or isinstance(t["expires"], str))
                and parse_utc_ts(t["tombstoned_ts"]) is not None):
            return Store("corrupt")
    return Store("ok", doc["seq"], doc["tombstones"])


def read_floor(state_dir: Path) -> Any:
    """The floor (an int), or "absent", or "corrupt"."""
    try:
        fd = os.open(str(floor_path(state_dir)), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "corrupt"
    try:
        raw = os.read(fd, _FLOOR_CAP + 1)
    except OSError:
        return "corrupt"
    finally:
        os.close(fd)
    text = raw.decode("ascii", "replace").strip()
    if len(raw) > _FLOOR_CAP or not text.isdigit() or text.startswith("0"):
        return "corrupt"
    return int(text)


def read_witness(state_dir: Path) -> str:
    try:
        raw = witness_path(state_dir).read_bytes()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "corrupt"
    return "ok" if raw == WITNESS_BYTES else "corrupt"


def store_row(state_dir: Path) -> Tuple[str, Store, Any, str]:
    """`(row, store, floor, witness)`: which of the documented states the
    store, the floor and the witness are in. Recovery (`ROW_RECOVER_*`,
    `ROW_RAISE_FLOOR`) is only ever of an EMPTY first store, or of a floor
    one behind its store; ANYTHING not listed is unverified."""
    s, f, w = read_store(state_dir), read_floor(state_dir), read_witness(state_dir)
    if s.kind == "absent" and f == "absent" and w == "absent":
        return ROW_INIT, s, f, w
    if s.kind == "ok" and s.seq == 1 and not s.tombstones:
        if f == "absent" and w == "absent":
            return ROW_RECOVER_FLOOR, s, f, w
        if f == 1 and w == "absent":
            return ROW_RECOVER_WITNESS, s, f, w
    if s.kind == "ok" and isinstance(f, int) and w == "ok":
        if s.seq == f:
            return ROW_OK, s, f, w
        if s.seq == f + 1:
            return ROW_RAISE_FLOOR, s, f, w
    return ROW_UNVERIFIED, s, f, w


# ---------------------------------------------------------------------------
# Writing (the drain pre-pass and `reinit` only, under the drain lock)
# ---------------------------------------------------------------------------

def _write_store(state_dir: Path, seq: int, tombstones: Mapping[str, Any]) -> None:
    doc = {"schema": STORE_SCHEMA, "seq": seq, "tombstones": dict(tombstones)}
    atomic_write(store_path(state_dir), json.dumps(doc, sort_keys=True).encode("utf-8"),
                 durable_root=state_dir)


def _write_floor(state_dir: Path, seq: int) -> None:
    atomic_write(floor_path(state_dir), str(seq).encode("ascii"), durable_root=state_dir)


def _write_witness(state_dir: Path) -> None:
    atomic_write(witness_path(state_dir), WITNESS_BYTES, durable_root=state_dir)


def _audit(state_dir: Path, **fields: Any) -> None:
    audit_mod.append_router_line(
        state_dir, SEQ_DIR, AUDIT_LOG,
        audit_mod.build_line(audit_mod.EVENT_ALIAS_STORE, "amap.router", fields))


def settle_store(state_dir: Path) -> Tuple[str, Store, str]:
    """Bring the store to a usable state if a documented recovery applies,
    in the documented order, and return `(state, store, detail)`, state
    "ok" or "unverified". First initialisation: the empty store at seq 1,
    then the floor, then the audit line (durable, complete), then the
    witness LAST: a failed audit append leaves no witness, so nothing is
    authorised without the line."""
    row, s, f, w = store_row(state_dir)
    try:
        if row == ROW_INIT:
            _write_store(state_dir, 1, {})
            _write_floor(state_dir, 1)
            _audit(state_dir, action="init", seq=1)
            _write_witness(state_dir)
        elif row == ROW_RECOVER_FLOOR:
            _write_floor(state_dir, 1)
            _audit(state_dir, action="recover_init", seq=1)
            _write_witness(state_dir)
        elif row == ROW_RECOVER_WITNESS:
            _audit(state_dir, action="recover_init", seq=1)
            _write_witness(state_dir)
        elif row == ROW_RAISE_FLOOR:
            _write_floor(state_dir, s.seq)
            _audit(state_dir, action="floor_raised", seq=s.seq)
        elif row == ROW_UNVERIFIED:
            detail = f"store {s.kind}" + (f" seq {s.seq}" if s.kind == "ok" else "") + \
                f", floor {f}, witness {w}"
            _note_unverified(state_dir, detail)
            return "unverified", s, detail
    except Exception as e:  # noqa: BLE001 -- a store that cannot settle holds
        logger.error("alias store: %s did not complete (%s: %s); held", row,
                     type(e).__name__, e)
        return "unverified", s, f"{row} did not complete: {type(e).__name__}"
    row, s, f, w = store_row(state_dir)
    if row != ROW_OK:
        return "unverified", s, f"after settling: {row}"
    return "ok", s, ""


def _note_unverified(state_dir: Path, detail: str) -> None:
    """One ERROR log line, and one audit line per move INTO unverified (the
    last store line in the audit log says whether it already is). Best
    effort: an unverified store is held whatever this manages."""
    logger.error("alias store unverified (%s): aliases naming it are held", detail)
    try:
        last = None
        for raw in audit_path(state_dir).read_bytes().splitlines():
            try:
                doc = json.loads(raw)
            except ValueError:
                continue
            if isinstance(doc, dict) and doc.get("event") == audit_mod.EVENT_ALIAS_STORE:
                last = doc.get("action")
        if last == "unverified":
            return
    except OSError:
        pass
    try:
        _audit(state_dir, action="unverified", detail=detail)
    except Exception:  # noqa: BLE001
        logger.exception("alias store: could not audit the move into unverified")


def write_tombstone(state_dir: Path, store: Store, old: str, expires: str) -> Store:
    """Tombstone `old`: the store at seq + 1, then the floor, then its audit
    line. Returns the new store. Raises on failure (the caller records it)."""
    tombs = dict(store.tombstones)
    tombs[old] = {"expires": expires, "tombstoned_ts": utc_ts()}
    seq = store.seq + 1
    _write_store(state_dir, seq, tombs)
    _write_floor(state_dir, seq)
    _audit(state_dir, action="tombstoned", old=old, seq=seq)
    return Store("ok", seq, tombs)


# ---------------------------------------------------------------------------
# Name history
# ---------------------------------------------------------------------------

_NAME_KEYS = frozenset({"name", "seq", "ts"})


def parse_names(entry: Any) -> Optional[List[str]]:
    """The names an identity has had, from its registry entry's raw
    `names[]`: None when it records NO history (absent or null, a valid
    state), else the list. Strict: a closed list of `{name, seq, ts}`,
    seqs strictly increasing, timestamps never decreasing, and the LAST
    `(name, seq)` the entry's current `(name, name_seq)`. ValueError
    otherwise."""
    text = getattr(entry, "names_json", "") or "null"
    hist = json.loads(text)
    if hist is None:
        return None
    if not (isinstance(hist, list) and hist):
        raise ValueError("names[] is not a non-empty list")
    prev_seq, prev_ts = 0, None
    for n in hist:
        if not (isinstance(n, dict) and set(n) == _NAME_KEYS and isinstance(n["name"], str)
                and n["name"] and isinstance(n["seq"], int) and not isinstance(n["seq"], bool)
                and n["seq"] >= 1):
            raise ValueError("a names[] element is not {name, seq, ts}")
        ts = parse_utc_ts(n["ts"])
        if ts is None or n["seq"] <= prev_seq or (prev_ts is not None and ts < prev_ts):
            raise ValueError("names[] is out of order")
        prev_seq, prev_ts = n["seq"], ts
    if (hist[-1]["name"], hist[-1]["seq"]) != (entry.name, entry.name_seq):
        raise ValueError("the last names[] element is not the current name")
    return [n["name"] for n in hist]


# ---------------------------------------------------------------------------
# One poll's decisions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    status: str                    # ACTIVE | INACTIVE | UNVERIFIABLE
    reason: Optional[str] = None
    target: Optional[str] = None   # the instance name, when ACTIVE


@dataclass(frozen=True)
class AliasView:
    """This poll's alias decisions, attached to the config by `attach`."""
    store: str                                  # "ok" | "unverified" | "pending" | "none"
    store_detail: str = ""
    decisions: Mapping[str, Decision] = field(default_factory=dict)
    tombstone_errors: Mapping[str, str] = field(default_factory=dict)


#: The drain pre-pass's failed tombstone writes, for status (which runs on its
#: own read-only view): process state. Each keeps the time the drain FIRST saw
#: it fail (`since`), so status can give its age; a success clears it.
LAST_TOMBSTONE_ERRORS: Dict[str, Dict[str, str]] = {}


def _decide(cfg: Any, report: Any, store_state: str, store: Store, now) -> Dict[str, Decision]:
    out: Dict[str, Decision] = {}
    registry_ok = getattr(report, "state", None) == "ok"
    known = dict(getattr(report, "known", None) or {})
    entries = dict(getattr(report, "entries", None) or {})
    every = tuple(getattr(report, "all_entries", None) or ())
    for a in cfg.aliases:
        old_local = a.old.split("@")[0]
        target = a.new.split("@")[0]
        if store_state != "ok":
            out[a.old] = Decision(UNVERIFIABLE, HELD_STORE)
        elif a.old in store.tombstones:
            out[a.old] = Decision(INACTIVE, TOMBSTONED)
        elif now >= parse_utc_ts(a.expires):
            out[a.old] = Decision(INACTIVE, EXPIRED)
        elif not registry_ok:
            out[a.old] = Decision(UNVERIFIABLE, HELD_ROLLED_BACK
                                  if getattr(report, "state", None) == "rolled_back"
                                  else HELD_UNAVAILABLE)
        elif target not in known or target not in entries:
            out[a.old] = Decision(INACTIVE, TARGET_UNKNOWN)
        else:
            try:
                names = parse_names(entries[target])
            except (ValueError, TypeError):
                out[a.old] = Decision(UNVERIFIABLE, HELD_HISTORY)
                continue
            # Every OTHER identity the registry holds, whether or not this router
            # serves it, and retired ones too: none may own the old local part,
            # or the alias would deliver one identity's old mail to another.
            rest = [e for e in every if e.logical_id != entries[target].logical_id]
            others = {skeleton(e.name) for e in rest if e.state == "active"}
            reuse = None
            for e in rest:
                try:
                    hist = parse_names(e)
                except (ValueError, TypeError):
                    reuse = UNVERIFIABLE
                    break
                past = hist if hist is not None else [e.name]
                if skeleton(old_local) in {skeleton(n) for n in past}:
                    reuse = NAME_REUSED
            if names is None:
                out[a.old] = Decision(INACTIVE, NO_HISTORY)
            elif old_local not in names:
                out[a.old] = Decision(INACTIVE, NOT_IN_HISTORY)
            elif reuse == UNVERIFIABLE:
                out[a.old] = Decision(UNVERIFIABLE, HELD_HISTORY)
            elif skeleton(old_local) in others:
                # Another ACTIVE identity is called this now (by skeleton).
                out[a.old] = Decision(INACTIVE, COLLISION)
            elif reuse == NAME_REUSED:
                # ...or some other identity was, or a retired one still is.
                out[a.old] = Decision(INACTIVE, NAME_REUSED)
            else:
                out[a.old] = Decision(ACTIVE, target=target)
    return out


def prepare(cfg: Any, report: Any, *, write: bool) -> AliasView:
    """This poll's decisions. `write` (the drain pre-pass, under the drain
    lock): settle the store, then tombstone every entry at or past its
    expiry that is not yet tombstoned (a failure is recorded, logged at
    ERROR, retried next poll, and never raised). Without `write` (status,
    the console): read only; a store awaiting its first initialisation or
    a recovery reads as "pending"."""
    if not cfg.aliases:
        return AliasView("none")
    now = _now()
    errors: Dict[str, str] = {}
    if write:
        state, store, detail = settle_store(cfg.state_dir)
        if state == "ok":
            for a in cfg.aliases:
                if a.old in store.tombstones or now < parse_utc_ts(a.expires):
                    continue
                try:
                    store = write_tombstone(cfg.state_dir, store, a.old, a.expires)
                except Exception as e:  # noqa: BLE001 -- never stops a poll
                    errors[a.old] = f"{type(e).__name__}: {e}"
                    logger.error("alias %s expired; its tombstone could not be written "
                                 "(%s); it is inactive anyway, and retried next poll",
                                 a.old, errors[a.old])
                    # The store may be one write ahead of its floor now; the
                    # next pre-pass settles that (`ROW_RAISE_FLOOR`) first.
                    break
        if state == "ok":
            # Cleared only by its own success: a failure this pass never got to
            # (an earlier one stopped it) keeps its first-seen time.
            for old in list(LAST_TOMBSTONE_ERRORS):
                if old in store.tombstones:
                    del LAST_TOMBSTONE_ERRORS[old]
        for old, err in errors.items():
            since = LAST_TOMBSTONE_ERRORS.get(old, {}).get("since") or utc_ts()
            LAST_TOMBSTONE_ERRORS[old] = {"error": err, "since": since}
    else:
        row, store, f, w = store_row(cfg.state_dir)
        state = {ROW_OK: "ok", ROW_RAISE_FLOOR: "ok", ROW_UNVERIFIED: "unverified"}.get(
            row, "pending")
        detail = row
    return AliasView(state, detail, _decide(cfg, report, state, store, now), errors)


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def attach(cfg: Any, report: Any) -> Any:
    """`cfg` with this poll's alias view (the drain pre-pass: writes)."""
    if not cfg.aliases:
        return cfg
    return dataclasses.replace(cfg, alias_view=prepare(cfg, report, write=True))


# ---------------------------------------------------------------------------
# Normalising a draft
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Normalised:
    draft: Mapping[str, Any]
    applied: Mapping[str, str]     # {old: new}, exactly what was mapped


@dataclass(frozen=True)
class Refuse:
    """A table-named address whose entry is inactive: `recipient_unknown`."""
    addresses: Tuple[str, ...]


@dataclass(frozen=True)
class Hold:
    """A table-named address that cannot be decided: not consumed."""
    reason: str
    addresses: Tuple[str, ...]


def match_key(addr: Any) -> Optional[str]:
    """The table key an address would match: the local part EXACTLY as
    written, the domain lowercased. None for anything that is not one
    address."""
    if not isinstance(addr, str) or addr.count("@") != 1:
        return None
    local, domain = addr.strip().split("@")
    return f"{local}@{domain.lower()}"


def normalise(cfg: Any, draft: Mapping[str, Any]) -> Any:
    """`Normalised`, `Refuse` or `Hold` for a draft's `to` and `cc`. Only
    addresses the table names are touched; the draft itself is never
    modified (a copy is returned). A hold wins over a refusal."""
    if not cfg.aliases:
        return Normalised(draft, {})
    table = {a.old: a for a in cfg.aliases}
    view = cfg.alias_view
    holds: List[Tuple[str, str]] = []
    refused: List[str] = []
    applied: Dict[str, str] = {}
    out = dict(draft)
    for key in ("to", "cc"):
        addrs = draft.get(key)
        if not isinstance(addrs, list):
            continue
        mapped = []
        for addr in addrs:
            k = match_key(addr)
            a = table.get(k) if k else None
            if a is None:
                mapped.append(addr)
                continue
            d = view.decisions.get(a.old) if view is not None else None
            if d is None or d.status == UNVERIFIABLE:
                holds.append((d.reason if d else HELD_STORE, addr))
                mapped.append(addr)
            elif d.status == INACTIVE:
                refused.append(addr)
                mapped.append(addr)
            else:
                applied[a.old] = a.new
                mapped.append(a.new)
        out[key] = mapped
    if holds:
        return Hold(holds[0][0], tuple(a for _r, a in holds))
    if refused:
        return Refuse(tuple(refused))
    return Normalised(out, applied)


def apply_pinned(draft: Mapping[str, Any], pinned: Mapping[str, str]) -> Mapping[str, Any]:
    """A pending record's draft normalised with the map PINNED when it was
    made, never the live table: a later expiry or edit cannot retarget or
    refuse it."""
    if not pinned:
        return draft
    out = dict(draft)
    for key in ("to", "cc"):
        addrs = draft.get(key)
        if isinstance(addrs, list):
            out[key] = [pinned.get(match_key(a) or "", a) for a in addrs]
    return out


# ---------------------------------------------------------------------------
# Requests held unconsumed: a router-owned age
# ---------------------------------------------------------------------------

HELD_DIR = "alias-held"


def _held_path(cfg: Any, name: str, req_id: str) -> Path:
    from .config import gen_state_dir
    return gen_state_dir(cfg, name) / HELD_DIR / req_id


def note_held(cfg: Any, name: str, req_id: str, digest: Optional[str], reason: str) -> None:
    """The drain holds `req_id`: record when, once per request digest (a
    changed request starts again). Best effort; written by the drain only."""
    p = _held_path(cfg, name, req_id)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("request_sha256") == digest:
            return
    except (OSError, ValueError):
        pass
    try:
        atomic_write(p, json.dumps({"req_id": req_id, "request_sha256": digest,
                                    "first_held_ts": utc_ts(), "reason": reason},
                                   sort_keys=True).encode("utf-8"),
                     durable_root=cfg.state_dir)
    except Exception:  # noqa: BLE001
        logger.exception("instance %r req %r: could not record an alias hold", name, req_id)


def clear_held(cfg: Any, name: str, req_id: str) -> None:
    """The request was consumed (or answered): its hold marker goes."""
    if not cfg.aliases:
        return
    try:
        os.unlink(_held_path(cfg, name, req_id))
    except Exception:  # noqa: BLE001 -- absent, or no generation: nothing to clear
        pass


def held_list(cfg: Any, name: str) -> List[Dict[str, Any]]:
    """Each request `name` has held unconsumed, with its reason, its age
    from the marker's own ts (never an mtime; it restarts in a new
    generation), and the remedy. A malformed marker is listed with an
    unknown age; it never decides anything."""
    from .config import gen_state_dir
    try:
        d = gen_state_dir(cfg, name) / HELD_DIR
        names = sorted(os.listdir(d))
    except Exception:  # noqa: BLE001
        return []
    out = []
    now = _now()
    for req_id in names:
        try:
            doc = json.loads((d / req_id).read_text(encoding="utf-8"))
            ts = parse_utc_ts(doc["first_held_ts"])
            age = max(0, int((now - ts).total_seconds())) if ts else None
            reason = doc.get("reason")
        except Exception:  # noqa: BLE001
            age, reason = None, None
        out.append({"req_id": req_id, "reason": reason, "age_s": age,
                    "hint": HOLD_HINT.get(reason, "see the aliases section") +
                    " (the age restarts in a new generation)"})
    return out


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def status_doc(cfg: Any, report: Any) -> Optional[Dict[str, Any]]:
    """`status.json`'s `aliases` section (read only), or None without a
    table."""
    if not cfg.aliases:
        return None
    view = prepare(cfg, report, write=False)
    store = read_store(cfg.state_dir)
    entries = []
    for a in cfg.aliases:
        d = view.decisions.get(a.old)
        entries.append({"old": a.old, "new": a.new, "expires": a.expires,
                        "status": d.status if d else None, "reason": d.reason if d else None})
    doc: Dict[str, Any] = {
        "store": {"state": view.store, "detail": view.store_detail,
                  "seq": store.seq if store.kind == "ok" else None,
                  "tombstones": sorted(store.tombstones) if store.kind == "ok" else None},
        "entries": entries,
    }
    if LAST_TOMBSTONE_ERRORS:
        now = _now()
        doc["store"]["tombstone_errors"] = {
            old: {"error": e["error"], "since": e["since"],
                  "age_s": max(0, int((now - parse_utc_ts(e["since"])).total_seconds()))}
            for old, e in sorted(LAST_TOMBSTONE_ERRORS.items())}
    held = {}
    for name in sorted(getattr(cfg, "gen_keys", {}) or {}):
        h = held_list(cfg, name)
        if h:
            held[name] = h
    if held:
        doc["held"] = held
    return doc


# ---------------------------------------------------------------------------
# The operator verb: `router aliases reinit`
# ---------------------------------------------------------------------------

class ReinitRefused(Exception):
    """`reinit` refused; nothing was written."""


def _audit_tombstoned(state_dir: Path) -> FrozenSet[str]:
    """Every address the audit log records as tombstoned (it only ever ADDS
    tombstones to a reinit; nothing in it proves an alias active)."""
    out = set()
    try:
        raw = audit_path(state_dir).read_bytes()
    except OSError:
        return frozenset()
    for line in raw.splitlines():
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if not (isinstance(doc, dict) and doc.get("event") == audit_mod.EVENT_ALIAS_STORE):
            continue
        if doc.get("action") == "tombstoned" and isinstance(doc.get("old"), str):
            out.add(doc["old"])
        if doc.get("action") == "reinit" and isinstance(doc.get("tombstoned"), list):
            out.update(x for x in doc["tombstoned"] if isinstance(x, str))
    return frozenset(out)


def reinit(cfg: Any, reason: str, *, dry_run: bool = False) -> Dict[str, Any]:
    """`router aliases reinit --reason TEXT [--dry-run]`: the way out of an
    unverified store. With the router stopped (the drain lock, fail-fast),
    write a fresh store that tombstones EVERY configured alias, plus every
    address the audit log records as tombstoned, at a seq above anything
    seen; then the floor, then an audit line, then the witness if absent.
    Nothing is ever taken as proof that an alias is still active, so this
    PERMANENTLY retires every configured alias. Residual: a tombstone lost
    with the store, for an alias since removed from config, is gone."""
    from . import lock as lock_mod
    if not (isinstance(reason, str) and reason.strip()):
        raise ReinitRefused("a --reason is required; it is written to the audit log")
    lk = None
    if not dry_run:
        try:
            lk = lock_mod.acquire(cfg.state_dir)
        except lock_mod.LockHeldError as e:
            raise ReinitRefused(f"the router is running (stop it first): {e}") from None
    try:
        row, s, f, w = store_row(cfg.state_dir)
        expires = {a.old: a.expires for a in cfg.aliases}
        # Everything that could deny, never anything that could permit: the
        # configured aliases, what the audit log records as tombstoned, and the
        # tombstones of a store that can still be READ, trusted or not.
        tombs = sorted(set(expires) | _audit_tombstoned(cfg.state_dir)
                       | (set(s.tombstones) if s.kind == "ok" else set()))
        seq = max(f if isinstance(f, int) else 0, s.seq if s.kind == "ok" else 0) + 1
        plan = {"previous": {"row": row, "store": s.kind, "seq": s.seq if s.kind == "ok" else None,
                             "floor": f, "witness": w},
                "seq": seq, "tombstoned": tombs, "warning": REINIT_WARNING,
                "residual": "a tombstone lost with the store, for an alias since removed from "
                            "config, is gone"}
        if dry_run:
            return dict(plan, dry_run=True)
        now = utc_ts()
        _write_store(cfg.state_dir, seq,
                     {t: {"expires": expires.get(t), "tombstoned_ts": now} for t in tombs})
        _write_floor(cfg.state_dir, seq)
        _audit(cfg.state_dir, action="reinit", reason=reason.strip(), seq=seq,
               tombstoned=tombs, previous=plan["previous"])
        if read_witness(cfg.state_dir) != "ok":
            _write_witness(cfg.state_dir)
        logger.warning("aliases reinit: %s (%d tombstoned)", REINIT_WARNING, len(tombs))
        return plan
    finally:
        if lk is not None:
            lk.release()
