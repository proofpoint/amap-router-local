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

A FENCED generation's work is still stepped every poll (`outbound`): its
in-flight records advance under their existing transport ids, and its
pending records replay from their private snapshots. Each settles privately
(an anchor in that generation, nothing published, nothing archived) unless
the root is still the one it recorded and the live outbox entry is still its
request; and the current generation neither first-sights nor drains a file
that work still owns.
"""
from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import re
import secrets
import stat as stat_mod
import time
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
    """The pre-generation entries directly under `state_dir/<logical_id>/`.
    A migration's rollback blocker is not one, but only when the journal
    records it and it is still a real directory (`is_recorded_blocker`)."""
    d = lid_dir(state_dir, logical_id)
    return [n for n in GEN_SCOPED if _present(d / n)
            and not (n == BLOCKER and is_recorded_blocker(state_dir, logical_id))]


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


#: The path prefix of a root pinned by an open descriptor (`outbound._pin_own_root`).
PINNED_PREFIX = "/proc/self/fd/"


def root_identity(root: Path) -> Dict[str, Any]:
    """`{path, st_dev, st_ino}` of the instance root, from the descriptor
    an `O_NOFOLLOW | O_DIRECTORY` open returns: the identity of what is at
    the path NOW, never a separate stat of the path. Raises
    `GenerationHeld(connector_state_unverified)` when it cannot be opened."""
    # A root already pinned by a descriptor (a drain's view) is the opened
    # directory itself; the magic link is followed by design.
    flags = os.O_RDONLY | os.O_DIRECTORY
    if not str(root).startswith(PINNED_PREFIX):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(root), flags)
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
    `GenerationHeld(transport_counter_unverified)`.

    A predecessor made by a migration is known ONLY from the retained, done
    journal that names it, never from what its generations entry carries:
    it must carry the journal's legacy record exactly (`successor_counter`).
    An entry that carries a legacy record no done journal names holds."""
    if pred_dir is None:
        return 1
    lid_path = pred_dir.parent
    gen = pred_dir.name[len(GEN_PREFIX):]
    try:
        journal = read_journal(lid_path.parent, lid_path.name)
        doc = read_doc(lid_path.parent, lid_path.name)
    except GenerationHeld as e:
        raise GenerationHeld(HELD_COUNTER_UNVERIFIED, e.detail) from None
    entry = next((g for g in (doc or {}).get("gens", []) if g["gen"] == gen), {})
    if journal is not None and journal["gen"] == gen:
        if journal["phase"] != "done" or entry.get("legacy") != journal.get("legacy"):
            raise GenerationHeld(HELD_COUNTER_UNVERIFIED,
                                 "a migrated predecessor without its journal's legacy record")
        return successor_counter(pred_dir, journal["legacy"], journal.get("manifest"))
    if "legacy" in entry:
        raise GenerationHeld(HELD_COUNTER_UNVERIFIED,
                             "a legacy record on a generation no migration journal names")
    return _ordinary_counter(pred_dir)


def _ordinary_counter(pred_dir: Path) -> int:
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


def successor_counter(pred_dir: Path, legacy: Any, manifest: Any) -> int:
    """`next_counter` for a predecessor a migration made, given the legacy
    record its journal holds (already consistent: `read_journal` checks it
    against the manifest for every consumer). Basis "counter": the counter must exist and not be
    below the migrated value (lower means a rollback that could reuse ids).
    Basis "empty" or "attested": the legacy anchors are known to have handed
    out no id, so only what was written since counts, by the ordinary rule
    (in-flight entries, recorded transport ids, unreadable anchors)."""
    if legacy["basis"] == BASIS_COUNTER:
        if not _counter_path(pred_dir).exists():
            raise GenerationHeld(HELD_COUNTER_UNVERIFIED,
                                 "the migrated transport counter has been lost")
        start = _ordinary_counter(pred_dir)
        if start < int(legacy["counter"]):
            raise GenerationHeld(HELD_COUNTER_UNVERIFIED,
                                 "the transport counter is below the one migrated")
        return start
    return _ordinary_counter(pred_dir)


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
    migration_state(state_dir, lid)
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
    dev, ino = entry["root"].get("st_dev"), entry["root"].get("st_ino")
    if not (isinstance(dev, int) and isinstance(ino, int)):
        # Recorded as unknown (a root that could not be opened, or a legacy
        # generation whose marker kept only a path): it vouches for nothing.
        raise LookupError(f"{name!r}'s generation {gen} records no root identity")
    return dev, ino


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


#: `anchor_digest`'s answer for an anchor that cannot be read or is not an
#: anchor: distinct from `None`, which a well-formed anchor carries when its
#: original request could not be read.
DAMAGED_ANCHOR: Any = object()


def anchor_digest(path: Path) -> Any:
    """The digest a private anchor (`results/<req_id>.json`) records: a
    string, `None` (its original could not be read), or `DAMAGED_ANCHOR`."""
    try:
        env = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return DAMAGED_ANCHOR
    if not isinstance(env, dict) or not isinstance(env.get("result"), dict):
        return DAMAGED_ANCHOR
    digest = env.get("digest")
    return digest if digest is None or isinstance(digest, str) else DAMAGED_ANCHOR


def damaged_anchors(state_dir: Path, logical_id: str) -> Dict[str, List[Dict[str, Any]]]:
    """For each FENCED generation, its anchors that cannot be read, with
    their age: such an anchor keeps any live file under its id claimed
    (fail-closed), so it must not do so silently."""
    try:
        doc = read_doc(state_dir, logical_id)
    except GenerationHeld:
        return {}
    if doc is None:
        return {}
    out: Dict[str, List[Dict[str, Any]]] = {}
    now = time.time()
    for g in doc["gens"]:
        if g["gen"] == doc["current"]:
            continue
        d = gen_dir(state_dir, logical_id, g["gen"]) / "results"
        try:
            names = sorted(e.name for e in os.scandir(d) if e.name.endswith(".json"))
        except OSError:
            continue
        found = []
        for fn in names:
            if anchor_digest(d / fn) is not DAMAGED_ANCHOR:
                continue
            try:
                age = max(0, int(now - os.lstat(d / fn).st_mtime))
            except OSError:
                age = None
            found.append({"req_id": fn[:-len(".json")], "age_s": age})
        if found:
            out[g["gen"]] = found
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


def _verb_lock(cfg: Any, dry_run: bool) -> Any:
    """The drain lock for an operator verb, fail-fast (the router must be
    stopped), or None for a dry run, which takes none."""
    from . import lock as lock_mod
    if dry_run:
        return None
    try:
        return lock_mod.acquire(cfg.state_dir)
    except lock_mod.LockHeldError as e:
        raise OperatorRefused(f"the router is running (stop it first): {e}") from None


def _fresh_entry(cfg: Any, name: str, dry_run: bool) -> Tuple[Any, Any]:
    """`(report, entry)` from a FRESH registry read (persisting the seq floor
    only when not a dry run); a name the registry holds is refused."""
    from . import registry as registry_mod
    report = registry_mod.report_for(cfg.registry_dir, cfg.state_dir, cfg.instances,
                                     persist=not dry_run)
    if name not in (report.resolved or {}):
        raise OperatorRefused(
            f"{name!r} is held by the registry: "
            f"{(report.held or {}).get(name, report.state)}")
    return report, report.resolved[name]


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
    if cfg.registry_dir is None:
        raise OperatorRefused("generations exist only under a registry (registry_dir)")
    if name not in cfg.instances:
        raise OperatorRefused(f"{name!r} names no configured instance")
    if not (isinstance(reason, str) and reason.strip()):
        raise OperatorRefused("a --reason is required; it is written to the audit log")
    lk = _verb_lock(cfg, dry_run)
    try:
        report, entry = _fresh_entry(cfg, name, dry_run)
        lid = entry.logical_id
        try:
            migration_state(cfg.state_dir, lid, audit=True)
            warn_attested(cfg.state_dir, name, lid, "generation new")
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
# The migration verbs: `router generation adopt | fence-legacy`
#
# State written before generations existed sits directly under
# `state_dir/<logical_id>/`, and the instance holds (`legacy_state_unadopted`)
# until the operator says what it is:
#
#   * `adopt` attests that the root and binding are unchanged since that
#     state was written. It becomes the first CURRENT generation, every
#     entry moved exactly (the transport counter included), and each
#     version-1 pending record gains a snapshot taken from the live request
#     it still names, only where those bytes match its digest.
#   * `fence-legacy` makes it a FENCED generation (its work settles
#     privately; a version-1 record with no snapshot holds), and a fresh
#     current generation begins with its own first sight.
#
# Both are journaled in `migration.json`, written durably before the first
# rename and retained when done. Each phase is durable before the next
# begins; a re-run of the same verb resumes from the journal, deciding each
# path from what is at its source and its destination, and only while the
# binding (and, for adopt, the root) it recorded still verifies. The last
# step before `complete` leaves a DIRECTORY named `first-seen.json` where the
# legacy marker was: an older router run against the migrated layout then
# fails at its first statement, before any delivery, instead of taking a
# fresh first sight and restarting the transport counter. Rolling back past
# this version is not supported.
# ---------------------------------------------------------------------------

VERB_ADOPT = "adopt"
VERB_FENCE_LEGACY = "fence-legacy"
VERBS = (VERB_ADOPT, VERB_FENCE_LEGACY)
JOURNAL_SCHEMA = "amap-router-local.migration/1"
#: Each phase names the step that has COMPLETED, in this order.
PHASES = ("planned", "renamed", "converted", "blocked", "complete", "done")
#: Where the rollback blocker goes: the legacy first-sight marker's path.
BLOCKER = "first-seen.json"
#: Legacy files small enough to carry a digest in the plan.
_DIGESTED = ("first-seen.json", "approval.json")

REASON_ADOPTED = "adopted"
REASON_LEGACY = "legacy"
REASON_FENCE_LEGACY = "fence_legacy"


class MigrationConflict(Exception):
    """What is on disk does not match the journal; nothing more is moved."""


def journal_path(state_dir: Path, logical_id: str) -> Path:
    return lid_dir(state_dir, logical_id) / MIGRATION_FILE


def read_journal(state_dir: Path, logical_id: str) -> Optional[Dict[str, Any]]:
    """The migration journal, or None when there is none. Strict, for every
    consumer: anything that is not a well-formed journal for THIS identity
    raises `GenerationHeld(state_layout_conflict)` (`check_journal`)."""
    try:
        raw = journal_path(state_dir, logical_id).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise GenerationHeld(HELD_LAYOUT_CONFLICT, f"{MIGRATION_FILE} unreadable: {e}") from None
    try:
        doc = strict_json(raw)
    except (UnicodeDecodeError, ValueError):
        raise GenerationHeld(HELD_LAYOUT_CONFLICT, f"{MIGRATION_FILE} is not JSON") from None
    try:
        check_journal(doc, logical_id)
    except (ValueError, KeyError, TypeError) as e:
        raise GenerationHeld(HELD_LAYOUT_CONFLICT,
                             f"{MIGRATION_FILE} is malformed: {e}") from None
    return doc


_JOURNAL_BASE = frozenset({"schema", "verb", "phase", "planned_ts", "name", "logical_id",
                           "reason", "gen", "source", "paths", "legacy", "manifest",
                           "declared_root", "first_seen"})
_AUDIT_MEMBERS = ("audit_line", "journal_sha256")


def journal_digest(journal: Mapping[str, Any]) -> str:
    """The commitment the attestation line carries: the journal as it stood
    at `complete`, without the two audit members. Recomputed by every
    consumer, never taken from the journal's own claim."""
    body = {k: v for k, v in journal.items() if k not in _AUDIT_MEMBERS}
    body["phase"] = "complete"
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


def planned_fields(name: str, journal: Mapping[str, Any]) -> Dict[str, Any]:
    """The attestation line's facts, from the journal body (`_plan_audit`)."""
    legacy = journal["legacy"]
    return {"verb": journal["verb"], "reason": journal["reason"],
            "binding": journal["source"]["binding"], "root": journal["source"]["root"],
            "gen": journal["gen"], "fresh_gen": journal.get("fresh_gen"),
            "counts": {k: legacy[k] for k in ("basis", "counter", "local", "transport",
                                              "malformed", "inflight",
                                              "positive_evidence_count")},
            "converted": journal.get("converted"), "journal_sha256": journal_digest(journal)}


def check_journal(doc: Any, logical_id: str) -> None:
    """A migration journal, closed and typed per phase, for `logical_id`.
    From `complete` on, the stored digest must be the one recomputed from
    the body, and the planned attestation line must carry exactly the
    body's facts. Raises ValueError (or KeyError/TypeError) on anything
    else."""
    from .util import parse_utc_ts

    def need(cond: bool, why: str) -> None:
        if not cond:
            raise ValueError(why)
    need(isinstance(doc, dict), "not an object")
    phase, verb = doc.get("phase"), doc.get("verb")
    need(doc.get("schema") == JOURNAL_SCHEMA, "schema")
    need(verb in VERBS and phase in PHASES, "verb/phase")
    allowed = set(_JOURNAL_BASE)
    if verb == VERB_FENCE_LEGACY:
        allowed.add("fresh_gen")
    else:
        allowed.update(("converted", "first_sight"))
    allowed.add("blocker")
    late = PHASES.index(phase) >= PHASES.index("complete")
    if late:
        allowed.update(_AUDIT_MEMBERS)
    need(set(doc) <= allowed, f"unexpected members {sorted(set(doc) - allowed)}")
    need(_JOURNAL_BASE <= set(doc), f"missing members {sorted(_JOURNAL_BASE - set(doc))}")
    need(doc["logical_id"] == logical_id, "the journal is for another identity")
    need(isinstance(doc["name"], str) and bool(doc["name"]), "name")
    need(isinstance(doc["reason"], str) and bool(doc["reason"].strip()), "reason")
    need(parse_utc_ts(doc["planned_ts"]) is not None, "planned_ts")
    need(isinstance(doc["gen"], str) and bool(_GEN_ID.fullmatch(doc["gen"])), "gen")
    if verb == VERB_FENCE_LEGACY:
        fresh = doc.get("fresh_gen")
        need(isinstance(fresh, str) and bool(_GEN_ID.fullmatch(fresh))
             and fresh != doc["gen"], "fresh_gen")
    src = doc["source"]
    need(isinstance(src, dict) and set(src) == {"binding", "root"}, "source")
    b, r = src["binding"], src["root"]
    need(isinstance(b, dict) and set(b) == {"adapter", "stable_key", "binding_seq"}
         and isinstance(b["adapter"], str) and isinstance(b["stable_key"], str)
         and isinstance(b["binding_seq"], int) and not isinstance(b["binding_seq"], bool),
         "source binding")
    known = isinstance(r, dict) and set(r) == {"path", "st_dev", "st_ino"} \
        and isinstance(r["path"], str)
    need(known and (all(isinstance(r[k], int) and not isinstance(r[k], bool)
                        for k in ("st_dev", "st_ino"))
                    or (verb == VERB_FENCE_LEGACY and r["st_dev"] is None
                        and r["st_ino"] is None)), "source root")
    names = []
    for p in doc["paths"] if isinstance(doc["paths"], list) else [None]:
        need(isinstance(p, dict) and p.get("name") in GEN_SCOPED
             and p.get("type") in ("dir", "file")
             and set(p) <= {"name", "type", "digest"}, "a planned path")
        digested = p["type"] == "file" and p["name"] in _DIGESTED
        need(("digest" in p) == digested, "a digest is planned exactly for a digested file")
        if digested:
            need(isinstance(p["digest"], str) and bool(_HEX64.fullmatch(p["digest"])),
                 "a planned digest")
        names.append(p["name"])
    need(len(set(names)) == len(names), "a path planned twice")
    check_legacy(doc["legacy"], doc["manifest"])
    fs, dr = doc["first_seen"], doc["declared_root"]
    need(dr is None or isinstance(dr, str), "declared_root")
    if fs is not None:
        need(isinstance(fs, dict) and set(fs) == {"first_seen_ts", "declared_root", "source"}
             and parse_utc_ts(fs["first_seen_ts"]) is not None
             and fs["declared_root"] == dr
             and fs["source"] in ("first-seen.json", "approval.json"), "first_seen")
    if "converted" in doc:
        c = doc["converted"]
        need(isinstance(c, dict) and all(
            isinstance(k, str) and bool(_REQ_ID.fullmatch(k)) and v in CONVERSION_OUTCOMES
            for k, v in c.items()), "converted")
        if phase != "renamed":
            need(CONVERTING not in c.values(), "a conversion left undecided past its phase")
    if verb == VERB_ADOPT:
        need("first_sight" in doc, "an adopt journal without its first-sight plan")
        f = doc["first_sight"]
        need(isinstance(f, dict) and set(f) == {"sentinel", "marker"}
             and isinstance(f["sentinel"], str) and parse_utc_ts(f["sentinel"]) is not None
             and fs is not None and f["sentinel"] == fs["first_seen_ts"], "first_sight")
        m = f["marker"]
        need(m is None or (isinstance(m, dict) and set(m) == {"text", "sha256"}
                           and isinstance(m["text"], str)
                           and hashlib.sha256(m["text"].encode("utf-8")).hexdigest()
                           == m["sha256"]), "first_sight marker")
        if m is not None:
            check_marker_text(m["text"], doc["name"], fs)
        need((m is None) == ("first-seen.json" in names),
             "a marker is planned exactly when none is moved")
    if "blocker" in doc:
        need(doc["blocker"] is True, "blocker")
    if PHASES.index(phase) >= PHASES.index("blocked"):
        need(doc.get("blocker") is True, "a blocked journal without its blocker")
    if verb == VERB_ADOPT and PHASES.index(phase) >= PHASES.index("converted"):
        need("converted" in doc, "an adopt journal past conversion without its record")
    if late:
        need(_AUDIT_MEMBERS[0] in doc and _AUDIT_MEMBERS[1] in doc, "the planned attestation")
        digest = journal_digest(doc)
        need(doc["journal_sha256"] == digest,
             "the journal does not match the digest its attestation commits to")
        line = doc["audit_line"]
        need(isinstance(line, str) and line.endswith("\n"), "audit_line")
        planned = strict_json(line[:-1].encode("utf-8"))
        want = planned_fields(doc["name"], doc)
        need(isinstance(planned, dict) and planned.get("event") == audit_mod.EVENT_MIGRATION
             and planned.get("instance") == doc["name"]
             and parse_utc_ts(planned.get("ts")) is not None
             and {k: planned.get(k) for k in want} == want
             and set(planned) == set(want) | {"ts", "event", "instance"},
             "the planned attestation line does not carry the journal's facts")


def migration_state(state_dir: Path, logical_id: str, *, audit: bool = False) -> str:
    """THE reader of a migration's outcome, for every consumer (the
    pre-pass, reset, the operator verbs): "none" (no journal) or "done".
    "done" is never the phase alone. Checked on every call: the journal is
    well-formed and `done`; the generations file has exactly the chain the
    verb made, with the binding and root the journal recorded; every planned
    path is in the legacy generation with its type, and the digested files
    unchanged; the legacy record equals the journal's and is consistent with
    its manifest, every manifest anchor is still there unchanged, and the
    counter (basis "counter") is not below the one recorded; the recorded
    blocker is a real directory. With `audit` (at the verb's resume, before
    reset and before `generation new`; never on an ordinary poll), also
    that exactly one attestation line in the audit log is the planned one.
    Anything else raises `GenerationHeld(state_layout_conflict)`."""
    journal = read_journal(state_dir, logical_id)
    if journal is None:
        return "none"
    if journal["phase"] != "done":
        raise _held(f"unfinished ({journal['phase']})")
    _check_made(state_dir, logical_id, journal)
    if audit and audit_state(state_dir, logical_id, journal) != "present":
        raise _held("the attestation line is not in the audit log")
    return "done"


def _held(why: str) -> GenerationHeld:
    return GenerationHeld(HELD_LAYOUT_CONFLICT, f"{MIGRATION_FILE}: {why}")


def done_journal(state_dir: Path, logical_id: str) -> Optional[Dict[str, Any]]:
    """The journal when `migration_state` says "done", else None (raises
    what it raises)."""
    if migration_state(state_dir, logical_id) == "none":
        return None
    return read_journal(state_dir, logical_id)


def _check_made(state_dir: Path, logical_id: str, journal: Mapping[str, Any]) -> None:
    doc = read_doc(state_dir, logical_id)
    if doc is None:
        raise _held(f"done, but there is no {GEN_FILE}")
    gens, src = doc["gens"], journal["source"]
    if not gens or gens[0]["gen"] != journal["gen"]:
        raise _held(f"{GEN_FILE} does not begin with the generation it made")
    made = gens[0]
    if journal["verb"] == VERB_ADOPT:
        if not (made.get("reason") == REASON_ADOPTED and made["binding"] == src["binding"]
                and made["root"] == src["root"]):
            raise _held("the adopted generation is not the one the journal recorded")
    else:
        fresh = gens[1] if len(gens) > 1 else {}
        if not (made.get("reason") == REASON_LEGACY and made.get("fenced_ts") is not None
                and made["binding"] == _UNKNOWN_BINDING
                and made["root"] == {"path": journal.get("declared_root"),
                                     "st_dev": None, "st_ino": None}
                and fresh.get("gen") == journal["fresh_gen"]
                and fresh.get("reason") == REASON_FENCE_LEGACY
                and fresh.get("binding") == src["binding"] and fresh.get("root") == src["root"]):
            raise _held("the fenced legacy generation and its successor are not the ones "
                        "the journal recorded")
    d = gen_dir(state_dir, logical_id, journal["gen"])
    for p in journal["paths"]:
        try:
            ok = _matches(d / p["name"], p)
        except OSError:
            ok = False
        if not ok:
            raise _held(f"{p['name']} in the migrated generation is not what was planned")
    legacy = journal["legacy"]
    if made.get("legacy") != legacy:
        raise _held("the legacy record differs between the journal and the generation")
    for line in journal["manifest"]:
        req_id, _, sha = line.partition(" ")
        try:
            ok = _sha256(d / "results" / f"{req_id}.json") == sha
        except OSError:
            ok = False
        if not ok:
            raise _held(f"legacy anchor {req_id} is gone or changed")
    if legacy["basis"] == BASIS_COUNTER:
        try:
            now = _counter_path(d).read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            now = ""
        if not (_COUNTER_RE.fullmatch(now) and int(now) >= int(legacy["counter"])):
            raise _held("the transport counter is missing or below the one migrated")
    if journal["verb"] == VERB_ADOPT:
        from . import firstsight
        plan = journal["first_sight"]
        try:
            ok = (d / firstsight.FIRST_SIGHT_TAKEN).read_bytes() == plan["sentinel"].encode()
            if plan["marker"] is not None:
                ok = ok and _sha256(d / "first-seen.json") == plan["marker"]["sha256"]
        except OSError:
            ok = False
        if not ok:
            raise _held("the adopted generation's first-sight record is not what was planned")
    if not is_recorded_blocker(state_dir, logical_id):
        raise _held("done, but its rollback blocker is missing")


def attested(state_dir: Path, logical_id: str) -> Optional[Dict[str, Any]]:
    """`{gen, local_anchors, attested_ts}` when a done migration rests on an
    ATTESTED transport history (no counter, local anchors only), else None.
    Report-only; a fault reading it is None."""
    try:
        journal = done_journal(state_dir, logical_id)
    except GenerationHeld:
        return None
    if not journal or journal["legacy"]["basis"] != BASIS_ATTESTED:
        return None
    return {"gen": journal["gen"], "local_anchors": journal["legacy"]["local"],
            "attested_ts": journal["planned_ts"]}


def warn_attested(state_dir: Path, name: str, logical_id: str, verb: str) -> None:
    """The WARNING every later `generation new` and `reset` logs while the
    chain rests on an attested transport history."""
    a = attested(state_dir, logical_id)
    if a:
        logger.warning("instance %r (%s): %s on a chain whose migrated generation %s rests on "
                       "an ATTESTED transport history (%d local anchor(s), attested %s); a "
                       "false attestation can reuse a transport id", name, logical_id, verb,
                       a["gen"], a["local_anchors"], a["attested_ts"])


# -- The attestation: one planned line, committed exactly once ------------------

def audit_state(state_dir: Path, logical_id: str, journal: Mapping[str, Any]) -> str:
    """Where the journal's planned attestation line stands in the audit log:
    "present" (exactly one full copy), "absent", or "torn" (the log ends in a
    prefix of it). Read strictly (`audit.read_raw`); raises
    `GenerationHeld(state_layout_conflict)` for an unreadable log, a
    malformed line that carries this journal's digest, a well-formed line
    for this journal that differs from the planned one, or two copies. A
    malformed line that does not mention this journal (an older crash) is
    skipped with a WARNING."""
    planned = journal["audit_line"].encode("utf-8")
    body, digest = planned[:-1], journal["journal_sha256"]
    try:
        raw = audit_mod.read_raw(state_dir, logical_id)
    except (OSError, audit_mod.AuditError) as e:
        raise _held(f"the audit log cannot be read: {e}") from None
    if raw is None:
        return "absent"
    lines = raw.split(b"\n")
    tail = lines.pop()               # b"" when the log ends with a newline
    found = 0
    for line in lines:
        if line == body:
            found += 1
            continue
        if line and body.startswith(line):
            continue                 # a torn copy already repaired (`commit_audit`)
        try:
            doc = strict_json(line)
        except (UnicodeDecodeError, ValueError):
            if digest.encode("ascii") in line:
                raise _held("a malformed audit line carries this journal's digest") from None
            logger.warning("audit log for %s: an unparseable line is skipped", logical_id)
            continue
        if isinstance(doc, dict) and doc.get("journal_sha256") == digest:
            raise _held("an audit line for this journal differs from the planned one")
    if found > 1:
        raise _held("the attestation line is in the audit log more than once")
    if tail:
        if found == 0 and tail == body:
            return "unterminated_copy"   # whole, only its newline missing
        if found == 0 and body.startswith(tail):
            return "torn"
        if digest.encode("ascii") in tail:
            raise _held("a torn audit line carries this journal's digest")
        logger.warning("audit log for %s: an unterminated last line is skipped", logical_id)
    return "present" if found == 1 else ("absent" if not tail else "unterminated")


def commit_audit(state_dir: Path, name: str, logical_id: str,
                 journal: Mapping[str, Any]) -> None:
    """Make the planned attestation line present exactly once, durably."""
    planned = journal["audit_line"].encode("utf-8")
    state = audit_state(state_dir, logical_id, journal)
    if state == "present":
        return
    if state == "unterminated_copy":
        data = b"\n"                    # the copy is whole: terminate it
    elif state in ("torn", "unterminated"):
        # Terminate the torn (or unrelated) last line, then the whole line.
        data = b"\n" + planned
    else:
        data = planned
    audit_mod.append_bytes(state_dir, name, data, state_key=logical_id, durable=True)
    if audit_state(state_dir, logical_id, journal) != "present":
        raise _held("the attestation line did not land")


def is_recorded_blocker(state_dir: Path, logical_id: str) -> bool:
    """Whether `state_dir/<logical_id>/first-seen.json` is the migration's
    rollback blocker: the journal records it AND it is a real directory. An
    unrecorded one, or a file, is legacy state like any other."""
    try:
        doc = read_journal(state_dir, logical_id)
        st = os.lstat(lid_dir(state_dir, logical_id) / BLOCKER)
    except (GenerationHeld, OSError):
        return False
    return bool(doc and doc.get("blocker") is True and stat_mod.S_ISDIR(st.st_mode))


def _write_journal(state_dir: Path, logical_id: str, doc: Dict[str, Any]) -> bytes:
    raw = json.dumps(doc, sort_keys=True, indent=1).encode("utf-8")
    atomic_write(journal_path(state_dir, logical_id), raw, durable_root=state_dir)
    return raw


def _kind(path: Path) -> Optional[str]:
    """"dir", "file", None (absent), or "other" (a symlink or anything else)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat_mod.S_ISDIR(st.st_mode):
        return "dir"
    if stat_mod.S_ISREG(st.st_mode):
        return "file"
    return "other"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# -- Classifying legacy transport evidence (once, at plan time) --------------

#: `outbound._begin_external`'s two refusals before any transport id was
#: allocated (exact `detail` at every pre-generation version).
_BEGIN_EXTERNAL_DETAILS = frozenset({
    "the external leg is not configured for this instance",
    "attachments on the external leg are not supported yet",
})
#: `outbound._result_doc`'s members, as every pre-generation anchor has them.
_RESULT_REQUIRED = frozenset({"contract_version", "req_id", "outcome", "detail",
                              "reason_code", "ts", "message_id", "job_id"})
_RESULT_OPTIONAL = frozenset({"recipients", "attachments"})
_OUTCOMES = frozenset({"accepted", "queued_for_human", "rejected"})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
LOCAL, TRANSPORT, MALFORMED = "local", "transport", "malformed"
#: A request id (`validate._REQ_ID_RE`) and a manifest line `"<req_id> <sha256>"`.
_REQ_ID = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")
_MANIFEST_LINE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]* [0-9a-f]{64}\Z")
TRANSPORT_DETAIL_PREFIX = "transport: "
REASON_TRANSPORT_ANOMALY = "transport_anomaly"
#: How a migrated generation's transport counter is known (`legacy.basis`).
BASIS_COUNTER, BASIS_EMPTY, BASIS_ATTESTED = "counter", "empty", "attested"
_LEGACY_KEYS = frozenset({"basis", "counter", "local", "transport", "malformed", "inflight",
                          "positive_evidence_count", "manifest_sha256"})


def strict_json(raw: bytes) -> Any:
    """`json.loads`, refusing duplicate object keys (ValueError)."""
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate key {k!r}")
            out[k] = v
        return out
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


def classify_anchor(raw: bytes, req_id: str) -> str:
    """LOCAL, TRANSPORT or MALFORMED, for a pre-generation anchor's bytes.

    TRANSPORT is positive evidence that a transport id was allocated: a
    recorded `transport_req_id`, a verdict passed through from the transport
    (its detail begins "transport: "), or a `transport_anomaly` other than
    the two refusals `_begin_external` made before allocating. LOCAL is the
    exact shape every pre-generation anchor had (`{"digest", "result"}`, the
    result as `_result_doc` wrote it) and none of that. Anything else is
    MALFORMED: an arbitrary result object is not an anchor."""
    from .util import parse_utc_ts
    try:
        env = strict_json(raw)
    except (UnicodeDecodeError, ValueError):
        return MALFORMED
    if not isinstance(env, dict):
        return MALFORMED
    if "transport_req_id" in env:
        return TRANSPORT
    if set(env) != {"digest", "result"}:
        return MALFORMED
    digest, res = env["digest"], env["result"]
    if not (digest is None or (isinstance(digest, str) and _HEX64.fullmatch(digest))):
        return MALFORMED
    if not isinstance(res, dict) or not (_RESULT_REQUIRED <= set(res)
                                         <= _RESULT_REQUIRED | _RESULT_OPTIONAL):
        return MALFORMED
    detail, reason = res["detail"], res["reason_code"]
    ok = (res["contract_version"] == "2" and res["req_id"] == req_id
          and res["outcome"] in _OUTCOMES
          and (detail is None or isinstance(detail, str))
          and isinstance(reason, str) and reason != ""
          and parse_utc_ts(res["ts"]) is not None
          and (res["message_id"] is None or isinstance(res["message_id"], str))
          and res["job_id"] is None)
    if ok and "recipients" in res:
        ok = isinstance(res["recipients"], list) and all(
            isinstance(r, str) for r in res["recipients"])
    if ok and "attachments" in res:
        a = res["attachments"]
        ok = isinstance(a, list) and bool(a) and all(
            isinstance(x, dict) and set(x) == {"index", "outcome", "detail"}
            and isinstance(x["index"], int) and not isinstance(x["index"], bool)
            and x["index"] >= 0 and isinstance(x["outcome"], str)
            and (x["detail"] is None or isinstance(x["detail"], str)) for x in a)
    if not ok:
        return MALFORMED
    if isinstance(detail, str) and detail.startswith(TRANSPORT_DETAIL_PREFIX):
        return TRANSPORT
    if reason == REASON_TRANSPORT_ANOMALY and detail not in _BEGIN_EXTERNAL_DETAILS:
        return TRANSPORT
    return LOCAL


def manifest_digest(manifest: List[str]) -> str:
    return hashlib.sha256("".join(line + "\n" for line in manifest).encode("utf-8")).hexdigest()


def classify_legacy(d: Path) -> Tuple[Dict[str, Any], List[str]]:
    """`(facts, manifest)` for the legacy layout at `d`: the counter's text
    (None when there is no counter file), and how many anchors are LOCAL,
    TRANSPORT and MALFORMED, how many in-flight entries exist (each one is
    positive evidence), and the manifest of LOCAL anchors (`"<req_id>
    <sha256>"`, sorted). `facts["basis"]` is left for `legacy_basis`. A
    counter that exists but is not a positive decimal raises
    `OperatorRefused`."""
    counts = {LOCAL: 0, TRANSPORT: 0, MALFORMED: 0}
    manifest: List[str] = []
    try:
        entries = sorted(os.scandir(d / "results"), key=lambda e: e.name)
    except FileNotFoundError:
        entries = []
    for e in entries:
        if not (e.name.endswith(".json") and e.is_file(follow_symlinks=False)):
            counts[MALFORMED] += 1
            continue
        req_id = e.name[:-len(".json")]
        try:
            raw = Path(e.path).read_bytes()
        except OSError:
            counts[MALFORMED] += 1
            continue
        kind = classify_anchor(raw, req_id)
        counts[kind] += 1
        if kind == LOCAL:
            manifest.append(f"{req_id} {hashlib.sha256(raw).hexdigest()}")
    try:
        inflight = sum(1 for _ in os.scandir(d / "inflight"))
    except FileNotFoundError:
        inflight = 0
    try:
        counter: Optional[str] = _counter_path(d).read_text(encoding="ascii").strip()
    except FileNotFoundError:
        counter = None
    except (OSError, UnicodeDecodeError) as e:
        raise OperatorRefused(f"the legacy transport counter is unreadable: {e}") from None
    if counter is not None and not _COUNTER_RE.fullmatch(counter):
        raise OperatorRefused("the legacy transport counter is corrupt")
    manifest.sort()
    facts = {"basis": None, "counter": counter, "local": counts[LOCAL],
             "transport": counts[TRANSPORT], "malformed": counts[MALFORMED],
             "inflight": inflight,
             "positive_evidence_count": counts[TRANSPORT] + inflight,
             "manifest_sha256": manifest_digest(manifest)}
    return facts, manifest


def legacy_basis(facts: Mapping[str, Any], attested: Optional[int]) -> str:
    """How the counter is known, or `OperatorRefused`. A counter preserves
    exactly. Without one: any positive evidence, or any malformed anchor,
    refuses whatever is attested; nothing at all is "empty"; LOCAL anchors
    alone need `--no-transport-history=N` with N their exact count."""
    if facts["counter"] is not None:
        return BASIS_COUNTER
    if facts["positive_evidence_count"]:
        raise OperatorRefused(
            f"the transport counter is lost and {facts['positive_evidence_count']} "
            "transport id(s) are proven allocated (in-flight entries or transport "
            "verdicts); ids would be reused. Nothing can attest this away")
    if facts["malformed"]:
        raise OperatorRefused(
            f"the transport counter is absent and {facts['malformed']} anchor(s) cannot "
            "be classified; nothing shows they handed out no transport id")
    if not facts["local"]:
        return BASIS_EMPTY
    if attested is None:
        raise OperatorRefused(
            f"the transport counter is absent and {facts['local']} local anchor(s) "
            "remain; if this instance never had a transport route, attest it with "
            f"--no-transport-history={facts['local']}")
    if attested != facts["local"]:
        raise OperatorRefused(
            f"--no-transport-history={attested} does not match the {facts['local']} "
            "local anchor(s) found")
    return BASIS_ATTESTED


def check_legacy(rec: Any, manifest: Any) -> None:
    """A migrated generation's legacy record, strictly, with the manifest
    the journal kept. Raises ValueError on anything inconsistent."""
    if not (isinstance(rec, dict) and set(rec) == _LEGACY_KEYS):
        raise ValueError("not a legacy record")
    n = {k: rec[k] for k in ("local", "transport", "malformed", "inflight",
                             "positive_evidence_count")}
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in n.values()):
        raise ValueError("a count is not a non-negative integer")
    if n["positive_evidence_count"] != n["transport"] + n["inflight"]:
        raise ValueError("positive_evidence_count is not transport + inflight")
    if not (isinstance(manifest, list)
            and all(isinstance(x, str) and _MANIFEST_LINE.fullmatch(x) for x in manifest)
            and manifest == sorted(manifest) and len(manifest) == n["local"]
            and manifest_digest(manifest) == rec["manifest_sha256"]):
        raise ValueError("the manifest does not match its record")
    counter, basis = rec["counter"], rec["basis"]
    if basis == BASIS_COUNTER:
        if not (isinstance(counter, str) and _COUNTER_RE.fullmatch(counter)):
            raise ValueError("basis counter without a counter")
    elif basis == BASIS_EMPTY:
        if counter is not None or any(n.values()):
            raise ValueError("basis empty with legacy state")
    elif basis == BASIS_ATTESTED:
        if (counter is not None or n["local"] < 1 or n["transport"] or n["malformed"]
                or n["inflight"]):
            raise ValueError("basis attested with more than local anchors")
    else:
        raise ValueError(f"unknown basis {basis!r}")


def _plan_paths(state_dir: Path, logical_id: str) -> List[Dict[str, Any]]:
    d = lid_dir(state_dir, logical_id)
    paths = []
    for n in legacy_entries(state_dir, logical_id):
        kind = _kind(d / n)
        if kind not in ("dir", "file"):
            raise MigrationConflict(f"{n} is not a plain file or directory")
        entry: Dict[str, Any] = {"name": n, "type": kind}
        if kind == "file" and n in _DIGESTED:
            entry["digest"] = _sha256(d / n)
        paths.append(entry)
    return paths


def _fsync(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _matches(path: Path, planned: Mapping[str, Any]) -> bool:
    if _kind(path) != planned["type"]:
        return False
    return "digest" not in planned or _sha256(path) == planned["digest"]


def _move_paths(state_dir: Path, logical_id: str, journal: Mapping[str, Any]) -> None:
    """Each planned path into the legacy generation's directory, decided per
    path from what is at each end (never from the phase alone):

        source   destination   action
        present  absent        rename (never over anything)
        absent   as planned    already moved
        present  present       conflict
        absent   absent        conflict (it was planned present)

    The recorded blocker at its source path counts as absent ("moved")."""
    src_dir = lid_dir(state_dir, logical_id)
    dst_dir = gen_dir(state_dir, logical_id, journal["gen"])
    if _kind(dst_dir) is None:
        os.mkdir(dst_dir)
        _fsync(src_dir)
    elif _kind(dst_dir) != "dir":
        raise MigrationConflict(f"{dst_dir.name} is not a directory")
    blocker = is_recorded_blocker(state_dir, logical_id)
    for p in journal["paths"]:
        src, dst = src_dir / p["name"], dst_dir / p["name"]
        src_here = _kind(src) is not None and not (p["name"] == BLOCKER and blocker)
        dst_here = _kind(dst) is not None
        if src_here and not dst_here:
            if not _matches(src, p):
                raise MigrationConflict(f"{p['name']} changed since the plan")
            os.rename(src, dst)
            _fsync(src_dir)
            _fsync(dst_dir)
        elif not src_here and dst_here:
            if not _matches(dst, p):
                raise MigrationConflict(f"{p['name']} at the destination is not what was planned")
        elif src_here and dst_here:
            raise MigrationConflict(f"{p['name']} is at both the legacy path and the generation")
        else:
            raise MigrationConflict(f"{p['name']} is at neither the legacy path nor the generation")
    left = legacy_entries(state_dir, logical_id)
    if left:
        raise MigrationConflict(f"legacy entries {left} appeared that were not planned")


def _place_blocker(state_dir: Path, logical_id: str, journal: Dict[str, Any]) -> None:
    """The rollback blocker: recorded in the journal FIRST, then made, so a
    blocker is never there unrecorded (an unrecorded one reads as legacy)."""
    if journal.get("blocker") is not True:
        journal["blocker"] = True
        _write_journal(state_dir, logical_id, journal)
    path = lid_dir(state_dir, logical_id) / BLOCKER
    kind = _kind(path)
    if kind is None:
        os.mkdir(path)
        _fsync(lid_dir(state_dir, logical_id))
    elif kind != "dir":
        raise MigrationConflict(f"{BLOCKER} is at the legacy path and is not the blocker")


_UNKNOWN_BINDING = {"adapter": None, "stable_key": None, "binding_seq": None}


def _migrated_doc(journal: Mapping[str, Any], now: str) -> Dict[str, Any]:
    """The generations file the journal's verb ends in."""
    src = journal["source"]
    legacy = dict(journal["legacy"])
    if journal["verb"] == VERB_ADOPT:
        gens = [{"gen": journal["gen"], "minted_ts": now, "reason": REASON_ADOPTED,
                 "binding": dict(src["binding"]), "root": dict(src["root"]),
                 "fenced_ts": None, "note": journal["reason"], "legacy": legacy}]
        return {"schema": SCHEMA, "gens": gens, "current": journal["gen"]}
    # The legacy generation's binding was never recorded, and its marker
    # kept only a path: neither vouches for anything, so its work settles
    # privately (`expected_root`).
    gens = [{"gen": journal["gen"], "minted_ts": now, "reason": REASON_LEGACY,
             "binding": dict(_UNKNOWN_BINDING),
             "root": {"path": journal.get("declared_root"), "st_dev": None, "st_ino": None},
             "fenced_ts": now, "legacy": legacy},
            {"gen": journal["fresh_gen"], "minted_ts": now, "reason": REASON_FENCE_LEGACY,
             "binding": dict(src["binding"]), "root": dict(src["root"]),
             "fenced_ts": None, "note": journal["reason"]}]
    return {"schema": SCHEMA, "gens": gens, "current": journal["fresh_gen"]}


#: adopt's clock-skew margin: a rebind this close to first sight counts as after it.
SKEW_S = 1


def legacy_marker(state_dir: Path, logical_id: str) -> Optional[Dict[str, Any]]:
    """What the legacy layout says about when and where it began:
    `{"first_seen_ts", "declared_root", "source"}`, or None when it has no
    marker it can be read from. Either file must carry a list
    `outbox_snapshot`, as first sight requires of a marker (a pre-generation
    router adopted an `approval.json` only with one): otherwise the adopted
    generation could never drain. `first-seen.json` first; one a pre-generation
    router adopted from `approval.json` is trusted only when its
    `first_seen_ts` IS that `approved_ts` (otherwise it may have been the
    clock at adoption). Then `approval.json`, only with a valid
    `approved_ts`. Nothing here is ever synthesised."""
    from .util import parse_utc_ts
    d = lid_dir(state_dir, logical_id)

    def load(n: str) -> Optional[Dict[str, Any]]:
        try:
            doc = strict_json((d / n).read_bytes())
        except (OSError, UnicodeDecodeError, ValueError):
            return None
        return doc if isinstance(doc, dict) else None
    doc = load("first-seen.json")
    if doc is not None:
        ts, root = doc.get("first_seen_ts"), doc.get("declared_root")
        if doc.get("adopted_from") == "approval.json" and doc.get("approved_ts") != ts:
            return None
        if (isinstance(ts, str) and parse_utc_ts(ts) and isinstance(root, str)
                and isinstance(doc.get("outbox_snapshot"), list)):
            return {"first_seen_ts": ts, "declared_root": root, "source": "first-seen.json"}
        return None
    if _present(d / "first-seen.json"):
        return None
    doc = load("approval.json")
    if doc is not None:
        ts, root = doc.get("approved_ts"), doc.get("declared_root")
        if (isinstance(ts, str) and parse_utc_ts(ts) and isinstance(root, str)
                and isinstance(doc.get("outbox_snapshot"), list)):
            return {"first_seen_ts": ts, "declared_root": root, "source": "approval.json"}
    return None


_BINDING_KEYS = frozenset({"adapter", "seq", "stable_key", "ts"})


def parse_bindings(text: str, flat: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """A registry entry's binding history, strictly: a non-empty list of
    `{adapter, seq, stable_key, ts}` and nothing else, seqs strictly
    increasing, timestamps never decreasing, and the LAST element the flat
    current binding. Raises ValueError."""
    from .util import parse_utc_ts
    hist = json.loads(text)
    if not (isinstance(hist, list) and hist):
        raise ValueError("no binding history")
    prev_seq, prev_ts = 0, None
    for b in hist:
        if not (isinstance(b, dict) and set(b) == _BINDING_KEYS):
            raise ValueError("a binding is not {adapter, seq, stable_key, ts}")
        if not (isinstance(b["adapter"], str) and b["adapter"]
                and isinstance(b["stable_key"], str) and b["stable_key"]
                and isinstance(b["seq"], int) and not isinstance(b["seq"], bool)
                and b["seq"] >= 1):
            raise ValueError("a binding has a bad adapter, stable_key or seq")
        ts = parse_utc_ts(b["ts"])
        if ts is None:
            raise ValueError("a binding has a bad ts")
        if b["seq"] <= prev_seq:
            raise ValueError("binding seqs do not strictly increase")
        if prev_ts is not None and ts < prev_ts:
            raise ValueError("binding timestamps decrease")
        prev_seq, prev_ts = b["seq"], ts
    last = hist[-1]
    if (last["adapter"], last["stable_key"], last["seq"]) != (
            flat["adapter"], flat["stable_key"], flat["binding_seq"]):
        raise ValueError("the last binding is not the current one")
    return hist


def adopt_evidence(cfg: Any, name: str, entry: Any, marker: Optional[Mapping[str, Any]]) -> None:
    """adopt's refusals on contrary evidence (each points to fence-legacy):
    no marker to date or place the legacy state; a marker whose root is not
    this instance's root (compared as normalised paths, never resolved); a
    binding history that is malformed or does not end in the current
    binding; or any REBIND (a binding after the initial one) at or after
    first sight, less `SKEW_S`. The initial binding is not compared: a
    registry imported after the router first saw an instance records its
    initial binding later than that, and the root check and the operator's
    attestation stand for it."""
    from .util import parse_utc_ts
    hint = "; use `fence-legacy`"
    if marker is None:
        raise OperatorRefused("no legacy first-sight marker (or approval with a valid "
                              "approved_ts) to date and place this state" + hint)
    if os.path.normpath(marker["declared_root"]) != os.path.normpath(str(cfg.instances[name].root)):
        raise OperatorRefused(f"the legacy state was written for root "
                              f"{marker['declared_root']!r}, not this instance's" + hint)
    try:
        hist = parse_bindings(entry.bindings_json, binding_of(entry))
    except (ValueError, TypeError) as e:
        raise OperatorRefused(f"the registry's binding history: {e}" + hint) from None
    seen = parse_utc_ts(marker["first_seen_ts"])
    for b in hist[1:]:
        if (parse_utc_ts(b["ts"]) - seen).total_seconds() >= -SKEW_S:
            raise OperatorRefused(f"the registry records a rebind (seq {b['seq']}, {b['ts']}) "
                                  f"after the legacy state's first sight "
                                  f"({marker['first_seen_ts']})" + hint)


def operator_migrate(cfg: Any, name: str, verb: str, reason: str, *,
                     dry_run: bool = False,
                     no_transport_history: Optional[int] = None) -> Dict[str, Any]:
    """`router generation adopt|fence-legacy <name> --reason <text>
    [--no-transport-history=N]`. In `reset`'s order: validate, take the
    drain lock (fail-fast), read the registry fresh, refuse a held instance,
    act, audit. `dry_run` takes no lock, writes nothing, and returns the
    plan.

    Refused: no registry; an unknown or registry-held name; an empty reason;
    a journal of the OTHER verb; state already in the generation layout with
    no journal of this verb; nothing pre-generation to migrate; generation
    directories nothing lists; a legacy entry that is not a plain file or
    directory; a transport counter that cannot be preserved or attested
    (`legacy_basis`); for adopt, a root that cannot be opened and contrary
    evidence (`adopt_evidence`); on resume, a binding (or for adopt a root)
    that no longer matches the journal's. Re-running the same verb once it
    is done changes nothing and says so."""
    if verb not in VERBS:
        raise OperatorRefused(f"unknown migration verb {verb!r}")
    if cfg.registry_dir is None:
        raise OperatorRefused("generations exist only under a registry (registry_dir)")
    if name not in cfg.instances:
        raise OperatorRefused(f"{name!r} names no configured instance")
    if not (isinstance(reason, str) and reason.strip()):
        raise OperatorRefused("a --reason is required; it is written to the audit log")
    lk = _verb_lock(cfg, dry_run)
    try:
        report, entry = _fresh_entry(cfg, name, dry_run)
        lid = entry.logical_id
        binding = binding_of(entry)
        try:
            journal = read_journal(cfg.state_dir, lid)
        except GenerationHeld as e:
            raise OperatorRefused(str(e)) from None
        if journal is not None and journal["verb"] != verb:
            raise OperatorRefused(
                f"{MIGRATION_FILE} records `{journal['verb']}` ({journal['phase']}); "
                f"`{verb}` is refused")
        if journal is not None and journal["phase"] == "done":
            try:
                migration_state(cfg.state_dir, lid, audit=True)
            except GenerationHeld as e:
                raise OperatorRefused(str(e)) from None
            return {"name": name, "logical_id": lid, "verb": verb, "noop": True,
                    "generation": journal.get("fresh_gen") or journal["gen"]}
        if journal is None:
            journal = _new_journal(cfg, name, verb, reason.strip(), lid, entry,
                                   no_transport_history)
        else:
            if journal["name"] != name:
                raise OperatorRefused(f"{MIGRATION_FILE} was begun for {journal['name']!r}, "
                                      f"not {name!r}; it stays held for the operator")
            _verify_source(cfg, name, journal, binding)
        if dry_run:
            return dict(_summary(name, journal), dry_run=True)
        try:
            return _run_journal(cfg, name, journal, report)
        except (MigrationConflict, GenerationHeld) as e:
            raise OperatorRefused(
                f"state_layout_conflict: {e}; the journal is kept and the instance "
                "stays held") from None
    finally:
        if lk is not None:
            lk.release()


def _new_journal(cfg: Any, name: str, verb: str, reason: str, lid: str, entry: Any,
                 attested: Optional[int]) -> Dict[str, Any]:
    """The plan for a first run (not yet written): every fact the verb will
    act on, classified once."""
    try:
        doc = read_doc(cfg.state_dir, lid)
    except GenerationHeld as e:
        raise OperatorRefused(str(e)) from None
    if doc is not None:
        raise OperatorRefused("already in the generation layout; nothing to migrate")
    if not legacy_entries(cfg.state_dir, lid):
        raise OperatorRefused("no pre-generation state; the next poll begins the first generation")
    try:
        check_unlisted(cfg.state_dir, lid)
    except GenerationHeld as e:
        raise OperatorRefused(str(e)) from None
    marker = legacy_marker(cfg.state_dir, lid)
    if verb == VERB_ADOPT:
        try:
            root = root_identity(cfg.instances[name].root)
        except GenerationHeld as e:
            raise OperatorRefused(f"adopt needs the root it attests to: {e}") from None
        adopt_evidence(cfg, name, entry, marker)
    else:
        root = _root_or_unknown(cfg.instances[name].root)
    try:
        paths = _plan_paths(cfg.state_dir, lid)
    except MigrationConflict as e:
        raise OperatorRefused(str(e)) from None
    facts, manifest = classify_legacy(lid_dir(cfg.state_dir, lid))
    facts["basis"] = legacy_basis(facts, attested)
    journal: Dict[str, Any] = {
        "schema": JOURNAL_SCHEMA, "verb": verb, "phase": "planned", "planned_ts": utc_ts(),
        "name": name, "logical_id": lid, "reason": reason, "gen": secrets.token_hex(16),
        "source": {"binding": binding_of(entry), "root": root}, "paths": paths,
        "legacy": facts, "manifest": manifest,
        "declared_root": marker["declared_root"] if marker else None,
        "first_seen": marker,
    }
    if verb == VERB_FENCE_LEGACY:
        journal["fresh_gen"] = secrets.token_hex(16)
    else:
        journal["first_sight"] = _plan_first_sight(cfg, name, lid, marker, paths)
    return journal


def marker_from_approval(approval: Mapping[str, Any], name: str) -> str:
    """The first-sight marker text a pre-generation router's upgrade made
    from `approval.json`: the approval's members, with the marker schema,
    the instance, `first_seen_ts` = `approved_ts` verbatim, and
    `adopted_from`."""
    from . import firstsight
    doc = dict(approval)
    doc.update(schema=firstsight.SCHEMA, instance=name,
               first_seen_ts=approval["approved_ts"], adopted_from="approval.json")
    return json.dumps(doc, sort_keys=True)


def check_marker_text(text: str, name: str, first_seen: Optional[Mapping[str, Any]]) -> None:
    """A planned marker's meaning, not just its hash: a marker for `name`
    adopted from an approval, carrying the journal's first sight (its ts as
    the approval's `approved_ts`, its root) and a list snapshot. ValueError
    otherwise."""
    from . import firstsight
    doc = strict_json(text.encode("utf-8"))
    if not (isinstance(doc, dict) and first_seen is not None
            and first_seen["source"] == "approval.json"
            and doc.get("schema") == firstsight.SCHEMA and doc.get("instance") == name
            and doc.get("adopted_from") == "approval.json"
            and doc.get("first_seen_ts") == first_seen["first_seen_ts"]
            and doc.get("approved_ts") == first_seen["first_seen_ts"]
            and doc.get("declared_root") == first_seen["declared_root"]
            and isinstance(doc.get("outbox_snapshot"), list)):
        raise ValueError("the planned marker does not carry the journal's first sight")


def _plan_first_sight(cfg: Any, name: str, lid: str, marker: Mapping[str, Any],
                      paths: List[Dict[str, Any]]) -> Dict[str, Any]:
    """adopt: the adopted generation's first-sight record. Its sentinel
    always (so a later loss of the marker holds rather than re-snapshots).
    When the legacy layout has only `approval.json`, its marker too, written
    FROM that file exactly as a pre-generation router's upgrade did:
    `first_seen_ts` is the `approved_ts`, verbatim, never synthesised
    (`legacy_marker` has refused one that is not valid)."""
    from . import firstsight
    out: Dict[str, Any] = {"sentinel": marker["first_seen_ts"], "marker": None}
    if any(p["name"] == "first-seen.json" for p in paths):
        return out
    approval = strict_json((lid_dir(cfg.state_dir, lid) / "approval.json").read_bytes())
    text = marker_from_approval(approval, name)
    out["marker"] = {"text": text, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    return out


def _write_first_sight(state_dir: Path, journal: Mapping[str, Any]) -> None:
    """adopt: the planned sentinel and (from approval.json) marker, each
    durable; an existing one must be exactly what was planned."""
    from . import firstsight
    d = gen_dir(state_dir, journal["logical_id"], journal["gen"])
    plan = journal["first_sight"]
    files = [(d / firstsight.FIRST_SIGHT_TAKEN, plan["sentinel"].encode("utf-8"))]
    if plan["marker"] is not None:
        try:
            approval = strict_json((d / "approval.json").read_bytes())
        except (OSError, UnicodeDecodeError, ValueError) as e:
            raise MigrationConflict(f"the moved approval.json cannot be read: {e}") from None
        if marker_from_approval(approval, journal["name"]) != plan["marker"]["text"]:
            raise MigrationConflict("the planned marker is not the one the approval makes")
        files.append((d / "first-seen.json", plan["marker"]["text"].encode("utf-8")))
    for path, data in files:
        kind = _kind(path)
        if kind is None:
            atomic_write(path, data, durable_root=state_dir)
        elif kind != "file" or path.read_bytes() != data:
            raise MigrationConflict(f"{path.name} in the adopted generation is not what was planned")


def _verify_source(cfg: Any, name: str, journal: Mapping[str, Any],
                   binding: Mapping[str, Any]) -> None:
    """A resume continues only while what the journal recorded still holds."""
    if journal["source"].get("binding") != dict(binding):
        raise OperatorRefused("the registry binding changed since the journal was written; "
                              "it stays held for the operator")
    if journal["verb"] == VERB_ADOPT:
        try:
            root = root_identity(cfg.instances[name].root)
        except GenerationHeld as e:
            raise OperatorRefused(f"adopt cannot resume: {e}") from None
        if not same_root(journal["source"]["root"], root):
            raise OperatorRefused("the instance root changed since the journal was written; "
                                  "it stays held for the operator")


def _summary(name: str, journal: Mapping[str, Any]) -> Dict[str, Any]:
    out = {"name": name, "logical_id": journal["logical_id"], "verb": journal["verb"],
           "phase": journal["phase"], "paths": [p["name"] for p in journal["paths"]],
           "legacy": journal["legacy"], "root": journal["source"]["root"]}
    if journal["verb"] == VERB_ADOPT:
        out["generation"] = journal["gen"]
        out["converted"] = dict(journal.get("converted") or {})
    else:
        out["fenced"] = journal["gen"]
        out["generation"] = journal["fresh_gen"]
    return out


def _advance(cfg: Any, journal: Dict[str, Any], phase: str) -> None:
    journal["phase"] = phase
    _write_journal(cfg.state_dir, journal["logical_id"], journal)


def _plan_audit(name: str, journal: Dict[str, Any]) -> None:
    """The attestation line, planned ONCE (fixed bytes, fixed ts) into the
    journal before it is `complete`. It commits to `journal_digest`, and
    carries exactly the body's facts (`planned_fields`)."""
    fields = planned_fields(name, journal)
    line = audit_mod.build_line(audit_mod.EVENT_MIGRATION, name, fields)
    journal["journal_sha256"] = fields["journal_sha256"]
    journal["audit_line"] = line.decode("utf-8")


def _run_journal(cfg: Any, name: str, journal: Dict[str, Any], report: Any) -> Dict[str, Any]:
    """Every phase from where the journal stands, each durable before the next."""
    from . import registry as registry_mod
    lid = journal["logical_id"]
    state_dir = cfg.state_dir
    if journal["phase"] == "planned" and not _present(journal_path(state_dir, lid)):
        _write_journal(state_dir, lid, journal)       # durable before the first rename
    if journal["phase"] == "planned":
        _move_paths(state_dir, lid, journal)
        _advance(cfg, journal, "renamed")
    if journal["phase"] == "renamed":
        if journal["verb"] == VERB_ADOPT:
            _write_first_sight(state_dir, journal)
            view = keyed(registry_mod.keyed_config(cfg, report), {name: gen_key(lid, journal["gen"])})
            _convert_pending(view, name, journal)
        _advance(cfg, journal, "converted")
    if journal["phase"] == "converted":
        _place_blocker(state_dir, lid, journal)
        _advance(cfg, journal, "blocked")
    if journal["phase"] == "blocked":
        if journal["verb"] == VERB_ADOPT:
            view = keyed(registry_mod.keyed_config(cfg, report), {name: gen_key(lid, journal["gen"])})
            _verify_conversions(view, name, journal, complete=True)
        if journal["verb"] == VERB_FENCE_LEGACY:
            start = successor_counter(gen_dir(state_dir, lid, journal["gen"]),
                                      journal["legacy"], journal["manifest"])
            atomic_write(_counter_path(gen_dir(state_dir, lid, journal["fresh_gen"])),
                         str(start).encode("ascii"), durable_root=state_dir)
        _plan_audit(name, journal)
        _advance(cfg, journal, "complete")
    # complete: the generations file, the attestation (durable, once), then done.
    # A run that STARTS here re-verifies every conversion outcome first: the
    # records could have changed since the check before `complete`.
    if journal["verb"] == VERB_ADOPT:
        view = keyed(registry_mod.keyed_config(cfg, report), {name: gen_key(lid, journal["gen"])})
        _verify_conversions(view, name, journal, complete=True)
    want = journal.get("fresh_gen") or journal["gen"]
    doc = read_doc(state_dir, lid)
    if doc is None:
        _write_doc(state_dir, lid, _migrated_doc(journal, utc_ts()))
    elif doc["current"] != want:
        raise MigrationConflict(f"{GEN_FILE} names {doc['current']}, not {want}")
    _check_made(state_dir, lid, journal)
    try:
        commit_audit(state_dir, name, lid, journal)
    except GenerationHeld:
        raise
    except Exception as e:  # noqa: BLE001
        raise OperatorRefused(
            f"migrated, but the audit line could not be written ({type(e).__name__}: {e}); "
            "the journal stays at `complete` and the instance held until a re-run "
            "writes it") from None
    _advance(cfg, journal, "done")
    if journal["legacy"]["basis"] == BASIS_ATTESTED:
        logger.warning("instance %r (%s): %s on an ATTESTED transport history (%d local "
                       "anchor(s), no counter); a false attestation can reuse a transport "
                       "id", name, lid, journal["verb"], journal["legacy"]["local"])
    logger.warning("instance %r (%s): %s done; generation %s current", name, lid,
                   journal["verb"], want)
    return _summary(name, journal)


#: A conversion journaled as begun and not yet decided.
CONVERTING = "converting"
#: Every value `converted` may record (`outbound.convert_v1_pending`'s
#: outcomes, and CONVERTING), and the durable record version each implies.
_OUTCOME_VERSION = {"converted": 2, "already_v2": 2, "kept_v1_damaged": "damaged",
                    "kept_v1_request_unreadable": 1, "kept_v1_request_changed": 1,
                    "kept_v1_attachments_changed": 1}
CONVERSION_OUTCOMES = frozenset(_OUTCOME_VERSION) | {CONVERTING}


def _verify_conversions(view: Any, name: str, journal: Mapping[str, Any], *,
                        complete: bool) -> None:
    """Each recorded conversion outcome against the record it describes:
    "converted" and "already_v2" a version-2 record, a kept one version 1,
    "kept_v1_damaged" one that cannot be read (`outbound.pending_version`).
    With `complete`, every pending record has a decided outcome."""
    from . import outbound as outbound_mod
    d = gen_dir(view.state_dir, journal["logical_id"], journal["gen"]) / "pending"
    done = journal.get("converted") or {}
    try:
        present = sorted(e.name[:-len(".json")] for e in os.scandir(d)
                         if e.name.endswith(".json") and e.is_file(follow_symlinks=False))
    except FileNotFoundError:
        present = []
    for req_id, outcome in done.items():
        if outcome == CONVERTING:
            if complete:
                raise MigrationConflict(f"pending {req_id}: its conversion was never decided")
            continue
        if outbound_mod.pending_version(view, name, req_id) != _OUTCOME_VERSION[outcome]:
            raise MigrationConflict(f"pending {req_id}: recorded {outcome!r}, but the record "
                                    "does not show it")
    if complete:
        missing = [r for r in present if r not in done]
        if missing:
            raise MigrationConflict(f"pending records with no conversion outcome: {missing}")


def _convert_pending(view: Any, name: str, journal: Dict[str, Any]) -> None:
    """adopt only: each version-1 pending record gains a snapshot, from the
    live request it names, when those bytes still match its digest
    (`outbound.convert_v1_pending`). Each outcome is journaled as it is
    decided, so a resume after a crash part-way neither redoes nor
    misattributes one (`converted: {req_id: outcome}`)."""
    from . import outbound as outbound_mod
    d = gen_dir(view.state_dir, journal["logical_id"], journal["gen"])
    done = journal.setdefault("converted", {})
    _verify_conversions(view, name, journal, complete=False)
    try:
        names = sorted(e.name for e in os.scandir(d / "pending")
                       if e.name.endswith(".json") and e.is_file(follow_symlinks=False))
    except FileNotFoundError:
        names = []
    for fn in names:
        req_id = fn[:-len(".json")]
        if done.get(req_id, CONVERTING) != CONVERTING:
            continue
        resumed = done.get(req_id) == CONVERTING
        done[req_id] = CONVERTING          # journaled BEFORE the record can change
        _write_journal(view.state_dir, journal["logical_id"], journal)
        outcome = outbound_mod.convert_v1_pending(view, name, req_id)
        if resumed and outcome == outbound_mod.KEPT_V2:
            outcome = outbound_mod.CONVERTED   # this verb converted it before a crash
        # Persisted by the next record's intent, or by the phase that follows;
        # a crash before either resumes through CONVERTING, above.
        done[req_id] = outcome


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


def record_reuse(cfg: Any, name: str, req_id: Optional[str] = None) -> None:
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
    if req_id is not None:
        _release_reuse_pending(cfg, name, req_id)


#: In a generation: one marker per request held as `req_id_reused_pending`,
#: so its audit line is written once per transition.
REUSE_PENDING_DIR = "reuse-pending"


def note_reuse_pending(cfg: Any, name: str, req_id: str) -> None:
    """The first time a request under `req_id` is held as a reused id in
    `name`'s current generation: a marker and one audit line. Best effort."""
    if cfg.registry_dir is None or name not in cfg.gen_keys:
        return
    marker = Path(cfg.state_dir) / cfg.gen_keys[name] / REUSE_PENDING_DIR / req_id
    if marker.exists():
        return
    try:
        atomic_write(marker, b"", durable_root=cfg.state_dir)
        audit_mod.append(cfg.state_dir, name, audit_mod.EVENT_REUSE_PENDING,
                         state_key=cfg.gen_keys[name].partition("/")[0],
                         req_id=req_id, state="held")
    except Exception:  # noqa: BLE001
        logger.exception("instance %r: could not record a reused id held", name)


def _release_reuse_pending(cfg: Any, name: str, req_id: str) -> None:
    marker = Path(cfg.state_dir) / cfg.gen_keys[name] / REUSE_PENDING_DIR / req_id
    if not marker.exists():
        return
    try:
        audit_mod.append(cfg.state_dir, name, audit_mod.EVENT_REUSE_PENDING,
                         state_key=cfg.gen_keys[name].partition("/")[0],
                         req_id=req_id, state="refused")
        marker.unlink()
    except Exception:  # noqa: BLE001
        logger.exception("instance %r: could not record a reused id released", name)


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
    generation (a DIFFERENT request under an id whose in-flight or pending
    work is unsettled), with its age from the live file's mtime. Read only;
    a fault reading an entry skips it (it is shown next poll)."""
    import time
    from . import outbound as outbound_mod
    out: List[Dict[str, Any]] = []
    try:
        owned = outbound_mod._owned_digests(cfg, name)
    except Exception:  # noqa: BLE001 -- status never fails a poll
        return out
    now = time.time()
    for req_id, digest in owned:
        if digest is None:
            continue    # a record that cannot be read cannot show a reuse
        try:
            if not outbound_mod._live_differs(cfg, name, req_id, digest):
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
        legacy_attested = attested(cfg.state_dir, logical_id)
        if legacy_attested:
            entry["legacy_attested"] = legacy_attested
        damaged = damaged_anchors(cfg.state_dir, logical_id)
        if damaged:
            entry["fenced_damaged_anchors"] = damaged
        counts = reuse_counts(cfg.state_dir, logical_id)
        if counts:
            entry["req_id_reused"] = counts
        held = reuse_pending(cfg, name)
        if held:
            entry["req_id_reused_pending"] = held
            entry["hint"] = REUSE_HINT
        doc[name] = entry
    return doc
