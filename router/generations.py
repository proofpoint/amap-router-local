"""router/generations.py — an instance's connector generations, under a
registry (contract §2.2, as amended).

A GENERATION is one continuous life of an instance's connector state: one
registry binding (adapter, stable_key, binding_seq) and one instance root
(path, st_dev, st_ino). Everything this router keeps that is only
meaningful within that life lives under the generation:

    state_dir/<logical_id>/generations.json        which generations exist
    state_dir/<logical_id>/gen-<g>/results/         idempotency anchors
                                   inflight/        in-flight records, .handed
                                   transport/next_req_id
                                   pending/         held local deliveries
                                   quarantine/  held/
                                   first-seen.json  the first-sight marker

Per-identity state (`delivered/` ledgers, `audit/`, `outcomes/`,
`dsn-pending/`) stays directly under `state_dir/<logical_id>/`. Without a
registry nothing here applies: state stays name-keyed and there are no
generations.

WHEN A GENERATION BEGINS. Only on positive, durable evidence, re-checked
before any instance drains, every poll (`prepare`):

  * the registry binding changed (a rebind), or
  * the instance root's identity changed (re-created, or a new root), read
    from the descriptor this module opens, never from a path stat;

or by the operator (`router generation new`, or `router reset`). A
same-root connector counter reset is NOT inferred: AMAP gives a connector
no incarnation id, so there is nothing positive to read, and within a
generation a reused id fails closed (`outbound`, req_id_reused). A
`name_seq` or `enrollment_epoch` change never begins one.

Starting one FENCES the current generation: it is never current again,
never allocates a transport id, and keeps everything it holds. Its new
successor's transport counter starts at the predecessor's NEXT UNUSED value
(never 1 while ids were handed out), written durably before the successor
becomes current.

HOLDS, never guesses. An instance is held for the poll, with a reason, when:

  * its root cannot be opened (`connector_state_unverified`);
  * it has state in the pre-generation layout and no generations file
    (`legacy_state_unadopted`; the operator adopts or fences it);
  * the generations file, or its current generation, is unreadable or
    inconsistent, or a migration is unfinished (`state_layout_conflict`);
  * its current generation has state but no readable first-sight marker
    (`first_sight_marker_lost`: re-snapshotting would move the quarantine
    line forward over everything since);
  * a successor's counter cannot be established (`transport_counter_unverified`).

INTERIM (until the pending-v2 step): a fenced generation's in-flight and
pending records are kept, reported, and not stepped.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import re
import secrets
import dataclasses
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import audit as audit_mod
from .util import atomic_write, utc_ts

logger = logging.getLogger("amap_router_local.generations")

GEN_FILE = "generations.json"
GEN_PREFIX = "gen-"
MIGRATION_FILE = "migration.json"
SCHEMA = "amap-router-local.generations/1"
#: A generation id: 128 random bits, never reused.
_GEN_ID = re.compile(r"[0-9a-f]{32}\Z")

#: Entries that belong to a generation. Found directly under
#: `state_dir/<logical_id>/`, they are the pre-generation layout.
GEN_SCOPED = ("results", "inflight", "transport", "pending", "quarantine", "held",
              "first-seen.json", "approval.json")

HELD_CONNECTOR_UNVERIFIED = "connector_state_unverified"
HELD_LEGACY_UNADOPTED = "legacy_state_unadopted"
HELD_LAYOUT_CONFLICT = "state_layout_conflict"
HELD_MARKER_LOST = "first_sight_marker_lost"
HELD_COUNTER_UNVERIFIED = "transport_counter_unverified"
HOLD_REASONS = (HELD_CONNECTOR_UNVERIFIED, HELD_LEGACY_UNADOPTED, HELD_LAYOUT_CONFLICT,
                HELD_MARKER_LOST, HELD_COUNTER_UNVERIFIED)

#: Why a generation began.
REASON_FIRST = "first"
REASON_REBIND = "rebind"
REASON_ROOT = "root_changed"
REASON_OPERATOR = "operator"
REASON_RESET = "reset"

EVENT_GENERATION_MINTED = audit_mod.EVENT_GENERATION_MINTED

_COUNTER_RE = re.compile(r"[1-9][0-9]{0,17}\Z")


class AuditCommitFailed(Exception):
    """An operator verb's audit line could not be appended; the generations
    file was put back as it was (`begin`, `audit_required`)."""


class GenerationHeld(Exception):
    """`reason` is one of `HOLD_REASONS`; `detail` says what was seen."""

    def __init__(self, reason: str, detail: str):
        if reason not in HOLD_REASONS:
            raise ValueError(f"unknown generation hold reason {reason!r}")
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# Paths and the generations file
# ---------------------------------------------------------------------------

def lid_dir(state_dir: Path, logical_id: str) -> Path:
    return Path(state_dir) / logical_id


def gen_key(logical_id: str, gen: str) -> str:
    """The path of a generation's directory relative to `state_dir`."""
    return f"{logical_id}/{GEN_PREFIX}{gen}"


def gen_dir(state_dir: Path, logical_id: str, gen: str) -> Path:
    return Path(state_dir) / gen_key(logical_id, gen)


def gen_file(state_dir: Path, logical_id: str) -> Path:
    return lid_dir(state_dir, logical_id) / GEN_FILE


def _present(path: Path) -> bool:
    """Something is at `path`, in any shape. Unreadable counts as present."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def legacy_entries(state_dir: Path, logical_id: str) -> List[str]:
    """The pre-generation entries directly under `state_dir/<logical_id>/`."""
    d = lid_dir(state_dir, logical_id)
    return [n for n in GEN_SCOPED if _present(d / n)]


def _empty_leftover(d: Path) -> bool:
    """A generation directory an interrupted FIRST start left behind: its
    counter at 1 and nothing else (`begin` writes the counter before the
    generations file names it)."""
    if not _is_fresh(d):
        return False
    try:
        return _counter_path(d).read_text(encoding="ascii").strip() == "1"
    except OSError:
        return False


def check_unlisted(state_dir: Path, logical_id: str) -> None:
    """Without a generations file, any generation directory but an empty
    leftover of an interrupted first start means the file was LOST: what
    those generations hold (anchors, an allocated transport counter) would
    be ignored by a fresh start at counter 1, reusing ids. Raises
    `GenerationHeld(state_layout_conflict)`."""
    strays = [d.name for d in generation_dirs(lid_dir(state_dir, logical_id))
              if not _empty_leftover(d)]
    if strays:
        raise GenerationHeld(HELD_LAYOUT_CONFLICT,
                             f"generation directories {strays} exist but no {GEN_FILE}; "
                             "a fresh start would reuse their transport ids")


def read_doc(state_dir: Path, logical_id: str) -> Optional[Dict[str, Any]]:
    """The generations file, or None when it does not exist. Anything else
    that is not a well-formed file raises `GenerationHeld` (layout conflict)."""
    path = gen_file(state_dir, logical_id)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise GenerationHeld(HELD_LAYOUT_CONFLICT, f"{GEN_FILE} unreadable: {e}") from None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GenerationHeld(HELD_LAYOUT_CONFLICT, f"{GEN_FILE} is not JSON") from None
    _check_doc(doc)
    return doc


def _check_doc(doc: Any) -> None:
    def bad(why: str) -> GenerationHeld:
        return GenerationHeld(HELD_LAYOUT_CONFLICT, f"{GEN_FILE}: {why}")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise bad("unknown schema")
    gens = doc.get("gens")
    if not isinstance(gens, list) or not gens:
        raise bad("no generations")
    ids = []
    for g in gens:
        if not (isinstance(g, dict) and isinstance(g.get("gen"), str)
                and _GEN_ID.fullmatch(g["gen"])
                and isinstance(g.get("binding"), dict) and isinstance(g.get("root"), dict)):
            raise bad("a malformed generation")
        ids.append(g["gen"])
    if len(set(ids)) != len(ids):
        raise bad("a generation id appears twice")
    cur = doc.get("current")
    if cur not in ids:
        raise bad("the current generation is not listed")
    for g in gens:
        if (g["gen"] == cur) != (g.get("fenced_ts") is None):
            raise bad("exactly the current generation must be unfenced")


def current(doc: Mapping[str, Any]) -> Dict[str, Any]:
    return next(g for g in doc["gens"] if g["gen"] == doc["current"])


def predecessor(doc: Mapping[str, Any], gen: str) -> Optional[Dict[str, Any]]:
    """The generation immediately before `gen` in the chain, or None."""
    ids = [g["gen"] for g in doc["gens"]]
    i = ids.index(gen)
    return doc["gens"][i - 1] if i > 0 else None


def _write_doc(state_dir: Path, logical_id: str, doc: Dict[str, Any]) -> None:
    atomic_write(gen_file(state_dir, logical_id),
                 json.dumps(doc, sort_keys=True, indent=1).encode("utf-8"),
                 durable_root=state_dir)


# ---------------------------------------------------------------------------
# What identifies a generation
# ---------------------------------------------------------------------------

def binding_of(entry: Any) -> Dict[str, Any]:
    """The registry binding a generation records (never the name or epoch)."""
    return {"adapter": entry.adapter, "stable_key": entry.stable_key,
            "binding_seq": entry.binding_seq}


def root_identity(root: Path) -> Dict[str, Any]:
    """`{path, st_dev, st_ino}` of the instance root, from the descriptor
    an `O_NOFOLLOW | O_DIRECTORY` open returns: the identity of what is at
    the path NOW, never a separate stat of the path. Raises
    `GenerationHeld(connector_state_unverified)` when it cannot be opened."""
    try:
        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        raise GenerationHeld(HELD_CONNECTOR_UNVERIFIED,
                             f"instance root {str(root)!r} cannot be opened: "
                             f"{errno.errorcode.get(e.errno, e.errno)}") from None
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    return {"path": str(root), "st_dev": st.st_dev, "st_ino": st.st_ino}


def same_root(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    return (a.get("path"), a.get("st_dev"), a.get("st_ino")) == \
        (b.get("path"), b.get("st_dev"), b.get("st_ino"))


# ---------------------------------------------------------------------------
# The transport counter carried into a new generation
# ---------------------------------------------------------------------------

def _counter_path(d: Path) -> Path:
    return d / "transport" / "next_req_id"


def _handed_out(d: Path) -> bool:
    """Whether generation directory `d` shows ANY transport id allocated:
    an in-flight record or marker, or a settled anchor that recorded the
    transport id its record held (`outbound._write_anchor`), whatever its
    verdict: an anomaly settles a handed-out id just as surely as a result
    does. Read from that recorded field, never from the verdict's text."""
    try:
        if any(True for _ in os.scandir(d / "inflight")):
            return True
    except FileNotFoundError:
        pass
    except OSError:
        return True
    try:
        entries = list(os.scandir(d / "results"))
    except FileNotFoundError:
        return False
    except OSError:
        return True
    for e in entries:
        try:
            envelope = json.loads(Path(e.path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return True          # cannot be shown not to record an allocation
        if not isinstance(envelope, dict) or envelope.get("transport_req_id") is not None:
            return True
    return False


def next_counter(pred_dir: Optional[Path]) -> int:
    """The first transport id a successor of `pred_dir` may use: the
    predecessor's counter FILE value, which is its next UNUSED id (never
    "last used"), or 1 when it never handed one out. A missing counter
    while ids were handed out, or a corrupt one, raises
    `GenerationHeld(transport_counter_unverified)`."""
    if pred_dir is None:
        return 1
    try:
        text = _counter_path(pred_dir).read_text(encoding="ascii").strip()
    except FileNotFoundError:
        if _handed_out(pred_dir):
            raise GenerationHeld(HELD_COUNTER_UNVERIFIED,
                                 "the predecessor handed out transport ids but has no "
                                 "counter") from None
        return 1
    except (OSError, UnicodeDecodeError) as e:
        raise GenerationHeld(HELD_COUNTER_UNVERIFIED,
                             f"the predecessor's counter is unreadable: {e}") from None
    if not _COUNTER_RE.fullmatch(text):
        raise GenerationHeld(HELD_COUNTER_UNVERIFIED, "the predecessor's counter is corrupt")
    return max(int(text), 1)


# ---------------------------------------------------------------------------
# Beginning a generation
# ---------------------------------------------------------------------------

def begin(state_dir: Path, name: str, logical_id: str, binding: Mapping[str, Any],
          root: Mapping[str, Any], reason: str, *, note: Optional[str] = None,
          audit_required: bool = False) -> str:
    """Begin a new current generation for `logical_id`, fencing the current
    one if there is one. In this order, each step durable before the next:
    the new directory and its counter (carried from the predecessor), then
    the generations file naming it current. A crash before the file is
    written leaves an unlisted directory that nothing reads; one after it
    leaves the new generation current. Returns the new id.

    `audit_required` (an operator verb): the audit line is part of the
    commit. If it cannot be appended, the generations file is put back as
    it was and the failure raises; the new directory stays unlisted."""
    doc = read_doc(state_dir, logical_id)
    try:
        prior = gen_file(state_dir, logical_id).read_bytes()
    except FileNotFoundError:
        prior = None
    pred = current(doc) if doc is not None else None
    pred_dir = gen_dir(state_dir, logical_id, pred["gen"]) if pred is not None else None
    start = next_counter(pred_dir)
    gen = secrets.token_hex(16)
    d = gen_dir(state_dir, logical_id, gen)
    atomic_write(_counter_path(d), str(start).encode("ascii"), durable_root=state_dir)
    now = utc_ts()
    entry = {"gen": gen, "minted_ts": now, "reason": reason, "binding": dict(binding),
             "root": dict(root), "fenced_ts": None}
    if note:
        entry["note"] = note
    if doc is None:
        doc = {"schema": SCHEMA, "gens": []}
    for g in doc["gens"]:
        if g.get("fenced_ts") is None:
            g["fenced_ts"] = now
    doc["gens"].append(entry)
    doc["current"] = gen
    _write_doc(state_dir, logical_id, doc)
    try:
        audit_mod.append(state_dir, name, EVENT_GENERATION_MINTED, state_key=logical_id,
                         gen=gen, reason=reason, fenced=pred["gen"] if pred else None,
                         transport_counter=start, binding=dict(binding),
                         root=dict(root), **({"note": note} if note else {}))
    except Exception as e:  # noqa: BLE001
        if audit_required:
            if prior is None:
                gen_file(state_dir, logical_id).unlink()
                fd = os.open(str(lid_dir(state_dir, logical_id)), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            else:
                atomic_write(gen_file(state_dir, logical_id), prior, durable_root=state_dir)
            raise AuditCommitFailed(f"{type(e).__name__}: {e}") from e
        # Automatic: the generation is durable and in force; the line is best effort.
        logger.exception("instance %r: generation %s began but its audit line failed",
                         name, gen)
    logger.warning("instance %r (%s): generation %s began (%s)%s; transport ids from %d",
                   name, logical_id, gen, reason,
                   f", fencing {pred['gen']}" if pred else "", start)
    return gen


# ---------------------------------------------------------------------------
# The per-poll pre-pass
# ---------------------------------------------------------------------------

def _is_fresh(d: Path) -> bool:
    """A generation directory holding nothing but its minted counter."""
    try:
        names = {e.name for e in os.scandir(d)}
    except OSError:
        return False
    if names - {"transport"}:
        return False
    try:
        return {e.name for e in os.scandir(d / "transport")} <= {"next_req_id"}
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _marker_readable(d: Path) -> bool:
    try:
        doc = json.loads((d / "first-seen.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and isinstance(doc.get("outbox_snapshot"), list)


def resolve(state_dir: Path, name: str, entry: Any, root: Path) -> str:
    """The current generation for instance `name` (registry entry `entry`,
    instance root `root`), beginning one when the evidence requires it.
    Raises `GenerationHeld` instead of guessing. Called under the drain
    lock, before any instance of the poll drains."""
    lid = entry.logical_id
    observed = root_identity(root)
    binding = binding_of(entry)
    if _present(lid_dir(state_dir, lid) / MIGRATION_FILE):
        raise GenerationHeld(HELD_LAYOUT_CONFLICT, f"an unfinished {MIGRATION_FILE}")
    doc = read_doc(state_dir, lid)
    if doc is None:
        legacy = legacy_entries(state_dir, lid)
        if legacy:
            raise GenerationHeld(HELD_LEGACY_UNADOPTED,
                                 f"pre-generation state {legacy}; adopt it or fence it")
        check_unlisted(state_dir, lid)
        return begin(state_dir, name, lid, binding, observed, REASON_FIRST)
    cur = current(doc)
    d = gen_dir(state_dir, lid, cur["gen"])
    if not (d.is_dir() and not d.is_symlink()):
        raise GenerationHeld(HELD_LAYOUT_CONFLICT, f"current generation {cur['gen']} is missing")
    if cur["binding"] != binding:
        return begin(state_dir, name, lid, binding, observed, REASON_REBIND)
    if not same_root(cur["root"], observed):
        return begin(state_dir, name, lid, binding, observed, REASON_ROOT)
    if not _is_fresh(d) and not _marker_readable(d):
        raise GenerationHeld(HELD_MARKER_LOST,
                             f"generation {cur['gen']} has state but no readable first-sight "
                             "marker; it is never re-snapshotted")
    return cur["gen"]


@dataclass(frozen=True)
class Prepared:
    """The pre-pass's result: `keys` maps each drainable name to its
    generation key (`gen_key`), `held` each held name to its reason, and
    `detail` each held name to what was seen."""
    keys: Mapping[str, str]
    held: Mapping[str, str]
    detail: Mapping[str, str]


def prepare(cfg: Any) -> Prepared:
    """Resolve every registry-resolved instance's generation, beginning or
    holding as required, BEFORE any of them drains. Without a registry,
    nothing (empty)."""
    keys: Dict[str, str] = {}
    held: Dict[str, str] = {}
    detail: Dict[str, str] = {}
    report = getattr(cfg, "registry_report", None)
    if cfg.registry_dir is None or report is None:
        return Prepared({}, {}, {})
    for name, entry in sorted((report.resolved or {}).items()):
        if name not in cfg.instances:
            continue
        try:
            gen = resolve(cfg.state_dir, name, entry, cfg.instances[name].root)
        except GenerationHeld as e:
            held[name] = e.reason
            detail[name] = e.detail
            logger.warning("instance %r held: %s", name, e)
            continue
        except OSError as e:
            held[name] = HELD_LAYOUT_CONFLICT
            detail[name] = f"{type(e).__name__}: {e}"
            logger.exception("instance %r held: generation state failed", name)
            continue
        keys[name] = gen_key(entry.logical_id, gen)
    return Prepared(keys, held, detail)


def apply(cfg: Any, report: Any) -> Tuple[Any, Dict[str, str]]:
    """Run the pre-pass for `report`'s poll and fold its holds into the
    report: a generation-held instance leaves `resolved` and joins `held`
    with its reason, so it is not drained, local deliveries to it hold
    (`config.target_hold`), and status shows why. Returns `(report,
    gen_keys)`. Without a registry, `(report, {})` unchanged."""
    if cfg.registry_dir is None or getattr(report, "state", "off") == "off":
        return report, {}
    prep = prepare(dataclasses.replace(cfg, registry_report=report))
    if not prep.held:
        return report, dict(prep.keys)
    resolved = {n: e for n, e in (report.resolved or {}).items() if n not in prep.held}
    held = dict(report.held or {})
    held.update(prep.held)
    return dataclasses.replace(report, resolved=resolved, held=held), dict(prep.keys)


def peek(cfg: Any, report: Any) -> Dict[str, str]:
    """The generation keys a READ-ONLY caller (the console) may use: each
    resolved instance's current generation as the generations file records
    it, when that generation's directory exists. Nothing is begun, fenced or
    held here; an instance without one simply has no key."""
    keys: Dict[str, str] = {}
    if cfg.registry_dir is None or getattr(report, "state", "off") == "off":
        return keys
    for name, entry in (report.resolved or {}).items():
        try:
            doc = read_doc(cfg.state_dir, entry.logical_id)
        except GenerationHeld:
            continue
        if doc is None:
            continue
        d = gen_dir(cfg.state_dir, entry.logical_id, doc["current"])
        if d.is_dir() and not d.is_symlink():
            keys[name] = gen_key(entry.logical_id, doc["current"])
    return keys


#: `deliver`'s hold reasons for a recipient whose generation does not vouch
#: for the root being written.
HELD_RECIPIENT_UNRESOLVED = "recipient_generation_unresolved"
HELD_RECIPIENT_ROOT = "recipient_root_changed"


def expected_root(cfg: Any, name: str) -> Optional[Tuple[int, int]]:
    """The (st_dev, st_ino) of `name`'s root as its CURRENT generation
    records it, for a placement to verify on the descriptor it writes
    through. None without a registry (no check). Under one, a recipient
    with no generation this poll raises `LookupError`: nothing is placed on
    a guess."""
    if cfg.registry_dir is None:
        return None
    key = cfg.gen_keys.get(name)
    if key is None:
        raise LookupError(f"{name!r} has no current generation this poll")
    logical_id, _, gen_part = key.partition("/")
    doc = read_doc(cfg.state_dir, logical_id)
    gen = gen_part[len(GEN_PREFIX):]
    entry = next((g for g in (doc or {}).get("gens", []) if g["gen"] == gen), None)
    if entry is None:
        raise LookupError(f"{name!r}'s generation {gen} is not recorded")
    return int(entry["root"]["st_dev"]), int(entry["root"]["st_ino"])


def keyed(cfg: Any, gen_keys: Mapping[str, str]) -> Any:
    """`cfg` with this poll's generation keys attached (`config.gen_key`)."""
    if cfg.registry_dir is None:
        return cfg
    return dataclasses.replace(cfg, gen_keys=types.MappingProxyType(dict(gen_keys)))


# ---------------------------------------------------------------------------
# Reading generations (status, the stranded guard)
# ---------------------------------------------------------------------------

def generation_dirs(lid_path: Path) -> List[Path]:
    try:
        return sorted(Path(e.path) for e in os.scandir(lid_path)
                      if e.name.startswith(GEN_PREFIX) and e.is_dir(follow_symlinks=False))
    except OSError:
        return []


def fenced_work(state_dir: Path, logical_id: str) -> Dict[str, Dict[str, int]]:
    """For each FENCED generation, how many in-flight and pending records it
    still holds (kept, reported, not stepped until pending v2)."""
    try:
        doc = read_doc(state_dir, logical_id)
    except GenerationHeld:
        return {}
    if doc is None:
        return {}
    out: Dict[str, Dict[str, int]] = {}
    for g in doc["gens"]:
        if g["gen"] == doc["current"]:
            continue
        d = gen_dir(state_dir, logical_id, g["gen"])
        counts = {}
        for sub in ("inflight", "pending"):
            try:
                counts[sub] = sum(1 for e in os.scandir(d / sub) if e.name.endswith(".json"))
            except OSError:
                counts[sub] = 0
        if any(counts.values()):
            out[g["gen"]] = counts
    return out


# ---------------------------------------------------------------------------
# The operator verb: `router generation new`
# ---------------------------------------------------------------------------

class OperatorRefused(Exception):
    """An operator verb refused; nothing was written."""


def _root_or_unknown(root: Path) -> Dict[str, Any]:
    """The root identity, or a recorded "unknown" when the root cannot be
    opened: fencing must not wait on the connector. The next poll holds such
    a generation until the root reads, then begins another (`resolve`)."""
    try:
        return root_identity(root)
    except GenerationHeld:
        return {"path": str(root), "st_dev": None, "st_ino": None}


def operator_new(cfg: Any, name: str, reason: str, *, dry_run: bool = False) -> Dict[str, Any]:
    """`router generation new <name> --reason <text>`: fence `name`'s current
    generation and begin the next, for what the router cannot see (a
    same-root connector counter reset). In `reset`'s order: validate, take
    the drain lock (fail-fast: the router must be stopped), read the
    registry fresh, refuse a held instance, act, audit. `dry_run` takes no
    lock and writes nothing, the seq floor included, and returns the plan.

    Refused: no registry; an unknown or registry-held name; the
    pre-generation layout (adopt or fence it); no current generation (the
    next poll begins the first); an unfinished migration; a successor
    counter that cannot be carried; an empty reason. Allowed with the root
    unreadable: it fences."""
    from . import lock as lock_mod
    from . import registry as registry_mod
    if cfg.registry_dir is None:
        raise OperatorRefused("generations exist only under a registry (registry_dir)")
    if name not in cfg.instances:
        raise OperatorRefused(f"{name!r} names no configured instance")
    if not (isinstance(reason, str) and reason.strip()):
        raise OperatorRefused("a --reason is required; it is written to the audit log")
    lk = None
    if not dry_run:
        try:
            lk = lock_mod.acquire(cfg.state_dir)
        except lock_mod.LockHeldError as e:
            raise OperatorRefused(f"the router is running (stop it first): {e}") from None
    try:
        report = registry_mod.report_for(cfg.registry_dir, cfg.state_dir, cfg.instances,
                                         persist=not dry_run)
        if name not in (report.resolved or {}):
            raise OperatorRefused(
                f"{name!r} is held by the registry: "
                f"{(report.held or {}).get(name, report.state)}")
        entry = report.resolved[name]
        lid = entry.logical_id
        if _present(lid_dir(cfg.state_dir, lid) / MIGRATION_FILE):
            raise OperatorRefused(f"an unfinished {MIGRATION_FILE}; finish that verb first")
        try:
            doc = read_doc(cfg.state_dir, lid)
        except GenerationHeld as e:
            raise OperatorRefused(str(e)) from None
        if doc is None:
            if legacy_entries(cfg.state_dir, lid):
                raise OperatorRefused("pre-generation state: adopt it or fence it first")
            raise OperatorRefused("no current generation; the next poll begins the first")
        cur = current(doc)
        try:
            start = next_counter(gen_dir(cfg.state_dir, lid, cur["gen"]))
        except GenerationHeld as e:
            raise OperatorRefused(str(e)) from None
        root = _root_or_unknown(cfg.instances[name].root)
        plan = {"name": name, "logical_id": lid, "fences": cur["gen"],
                "transport_counter": start, "root": root, "reason": reason.strip()}
        if dry_run:
            return dict(plan, dry_run=True)
        try:
            plan["generation"] = begin(cfg.state_dir, name, lid, binding_of(entry), root,
                                       REASON_OPERATOR, note=reason.strip(),
                                       audit_required=True)
        except AuditCommitFailed as e:
            raise OperatorRefused(
                f"the audit line could not be written, so nothing was changed: {e}") from None
        return plan
    finally:
        if lk is not None:
            lk.release()


# ---------------------------------------------------------------------------
# What status shows
# ---------------------------------------------------------------------------

#: The operator's way out of a held reused id (status shows it with the entry).
REUSE_HINT = ("a different request is held under an id still in flight. Same-root "
              "connector counter reset? Stop the router, then `router generation new "
              "<instance> --reason ...`: the old work settles in the fenced generation, "
              "and the new generation's first sight quarantines the held request "
              "(rejected/quarantined_pre_approval) for the agent to resubmit.")


#: In a generation: how many requests it has settled as `req_id_reused`.
REUSE_COUNT_FILE = "req_id_reused"


def record_reuse(cfg: Any, name: str) -> None:
    """Count one `req_id_reused` refusal in `name`'s current generation (under
    a registry; nothing without one). A statistic for status: a fault here is
    logged and never fails the refusal it counts."""
    if cfg.registry_dir is None:
        return
    try:
        path = Path(cfg.state_dir) / cfg.gen_keys[name] / REUSE_COUNT_FILE
        try:
            n = int(path.read_text(encoding="ascii").strip())
        except FileNotFoundError:
            n = 0
        atomic_write(path, str(n + 1).encode("ascii"), durable_root=cfg.state_dir)
    except Exception:  # noqa: BLE001
        logger.exception("instance %r: could not count a req_id_reused refusal", name)


def reuse_counts(state_dir: Path, logical_id: str) -> Dict[str, int]:
    """`{generation: req_id_reused refusals it settled}`, for every
    generation with any."""
    out: Dict[str, int] = {}
    for d in generation_dirs(lid_dir(state_dir, logical_id)):
        try:
            n = int((d / REUSE_COUNT_FILE).read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            continue
        if n > 0:
            out[d.name[len(GEN_PREFIX):]] = n
    return out


def reuse_pending(cfg: Any, name: str) -> List[Dict[str, Any]]:
    """Each live request held as `req_id_reused_pending` in `name`'s current
    generation (a DIFFERENT request under an id still in flight), with its
    age from the live file's mtime. Read only; a fault reading an entry
    skips it (it is shown next poll)."""
    import time
    from . import inflight as inflight_mod
    from . import outbound as outbound_mod
    out: List[Dict[str, Any]] = []
    try:
        req_ids = inflight_mod.list_records(cfg, name)
    except Exception:  # noqa: BLE001 -- status never fails a poll
        return out
    now = time.time()
    for req_id in req_ids:
        try:
            record = inflight_mod.read_record(cfg, name, req_id)
            if record is None or not outbound_mod._live_differs(
                    cfg, name, req_id, record.get("digest")):
                continue
            st = os.stat(cfg.instances[name].outbox_root / f"req-{req_id}.json",
                         follow_symlinks=False)
        except Exception:  # noqa: BLE001
            continue
        out.append({"req_id": req_id, "age_s": max(0, int(now - st.st_mtime))})
    return out


def status_doc(cfg: Any, report: Any) -> Optional[Dict[str, Any]]:
    """`status.json`'s `generations` section, under a registry: for each
    instance with a current generation this poll, its logical_id and
    generation, the work its FENCED generations still hold, and any held
    reused ids with the operator hint. None without a registry."""
    if cfg.registry_dir is None or getattr(report, "state", "off") == "off":
        return None
    doc: Dict[str, Any] = {}
    for name, key in sorted(cfg.gen_keys.items()):
        logical_id, _, gen_part = key.partition("/")
        entry: Dict[str, Any] = {"logical_id": logical_id,
                                 "generation": gen_part[len(GEN_PREFIX):]}
        fenced = fenced_work(cfg.state_dir, logical_id)
        if fenced:
            entry["fenced_work"] = fenced
        counts = reuse_counts(cfg.state_dir, logical_id)
        if counts:
            entry["req_id_reused"] = counts
        held = reuse_pending(cfg, name)
        if held:
            entry["req_id_reused_pending"] = held
            entry["hint"] = REUSE_HINT
        doc[name] = entry
    return doc
