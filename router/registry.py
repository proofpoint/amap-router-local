"""router/registry.py — reading the host registry. Read-only, always.

The registry (who exists, how each identity is bound, what it is called) has
ONE writer, the host-level registry owner, and this router is a consumer of
its snapshot: a read-only directory mount holding `registry.json`. This
module reads it, validates what this router relies on, and never writes it.

WHAT IS CHECKED, and why only this. The writer guarantees two things to its
consumers ("what a consumer may rely on"): it never makes a snapshot visible
that it has not fully validated, and `seq` never decreases except through an
operator restore. So this reader checks the schema token (by membership),
`seq`, and the shapes of the fields it uses; it does not re-run the writer's
cross-entry invariants. Anything short of that raises `RegistryUnavailable`,
and the caller HOLDS: an instance is never drained on a guessed identity.

SEQ NEVER GOES BACKWARDS HERE EITHER. The highest `seq` accepted is kept in
`state_dir/registry/seq`, written durably before the snapshot is used. A
lower `seq` is `RegistryRolledBack`, fail-closed, because it means a
restored registry, and adopting it could re-bind names to older identities.
The operator acknowledges a deliberate restore by removing that file.

NAMES. A name must fullmatch the instance-name rule. Two ACTIVE entries whose
`skeleton()`s are equal both resolve to nothing: their instances are held,
never guessed between (contract §2.1). `skeleton()` is the shared one, pinned
to the registry owner's fixture vectors by the test suite.

`stable_key` is opaque here: carried and compared exactly, never folded.
Nothing is derived from a name's history (aliases are a later step), and no
generation is minted here.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import unicodedata
import dataclasses
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .util import atomic_write

SNAPSHOT = "registry.json"
#: Schema tokens this reader understands, checked by membership only.
SUPPORTED_SCHEMAS = frozenset({"amap-host.registry/1"})
#: A larger snapshot is refused before it is read.
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
#: Where the highest accepted seq is kept, under `state_dir`.
SEQ_DIR = "registry"
SEQ_FILE = "seq"

_LOGICAL_ID = re.compile(r"[0-9a-f]{32}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_ADAPTERS = frozenset({"sandy", "openshell"})
_STATES = frozenset({"active", "retired"})

# The shared skeleton (the registry owner's model): NFC, casefold, a fixed
# confusables fold, and every `-`, `_` and `.` removed.
_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "i": "l", "5": "s"})
_SEPARATORS = re.compile(r"[-_.]+")
RESERVED_LOCAL_PARTS = ("amap.router", "postmaster", "abuse")


def skeleton(name: str) -> str:
    """The collision key for a name. Two names collide exactly when their
    skeletons are equal."""
    s = unicodedata.normalize("NFC", name).casefold().translate(_CONFUSABLES)
    return _SEPARATORS.sub("", s)


class RegistryUnavailable(Exception):
    """No usable registry: absent, unreadable, not a regular file, too
    large, not strict JSON, an unknown schema token, or a field of the wrong
    shape. `code` says which. The caller holds."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"registry unavailable ({code}): {detail}")
        self.code = code
        self.detail = detail


class RegistryRolledBack(RegistryUnavailable):
    """The snapshot's `seq` is lower than one already accepted."""


@dataclass(frozen=True)
class Entry:
    """The fields of one registry entry this router uses."""
    logical_id: str
    name: str
    adapter: str
    stable_key: str
    binding_seq: int
    name_seq: int
    enrollment_epoch: int
    first_registered_ts: str
    state: str


@dataclass(frozen=True)
class Registry:
    seq: int
    written_at: str
    entries: Tuple[Entry, ...]

    def resolve(self) -> Tuple[Dict[str, Entry], List[str]]:
        """`({name: entry}, held)`: the active entries by name, and the
        names held because their skeleton collides with another active
        entry's (both are held, never guessed between) or with a reserved
        local part."""
        by_skel: Dict[str, List[Entry]] = {}
        for e in self.entries:
            if e.state == "active":
                by_skel.setdefault(skeleton(e.name), []).append(e)
        resolved: Dict[str, Entry] = {}
        held: List[str] = []
        reserved = {skeleton(r) for r in RESERVED_LOCAL_PARTS}
        for skel, group in by_skel.items():
            if skel in reserved:
                # The writer never issues one; if a snapshot carries one
                # anyway, it is held, never treated as an agent.
                held.extend(e.name for e in group)
            elif len(group) == 1:
                resolved[group[0].name] = group[0]
            else:
                held.extend(e.name for e in group)
        return resolved, sorted(held)


def _strict_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member {k!r}")
        out[k] = v
    return out


def _no_constant(value: str) -> Any:
    raise ValueError(f"non-finite number {value}")


def _read_snapshot(directory: Path) -> bytes:
    path = os.path.join(os.fspath(directory), SNAPSHOT)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise RegistryUnavailable("absent", f"{path} does not exist") from None
    except OSError as e:
        code = "symlink" if e.errno == errno.ELOOP else "unreadable"
        raise RegistryUnavailable(code, f"{path}: {e.strerror}") from None
    try:
        try:
            st = os.fstat(fd)
        except OSError as e:
            raise RegistryUnavailable("unreadable", f"{path}: {e.strerror}") from None
        if not stat.S_ISREG(st.st_mode):
            raise RegistryUnavailable("not_regular", f"{path} is not a regular file")
        if st.st_size > MAX_SNAPSHOT_BYTES:
            raise RegistryUnavailable("too_large", f"{path} is {st.st_size} bytes")
        chunks, total = [], 0
        while True:
            try:
                chunk = os.read(fd, 1 << 20)
            except OSError as e:
                raise RegistryUnavailable("unreadable", f"{path}: {e.strerror}") from None
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SNAPSHOT_BYTES:
                raise RegistryUnavailable("too_large", f"{path} grew past the cap")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _field(obj: Mapping[str, Any], key: str, check, what: str) -> Any:
    if key not in obj:
        raise RegistryUnavailable("invalid", f"{what}: missing {key!r}")
    value = obj[key]
    if not check(value):
        raise RegistryUnavailable("invalid", f"{what}: {key!r} has the wrong shape")
    return value


def _int(v: Any) -> bool:
    # At most 19 digits: what the seq floor file stores and reads back.
    return isinstance(v, int) and not isinstance(v, bool) and 1 <= v < 10 ** 19


def _str(pattern):
    return lambda v: isinstance(v, str) and bool(pattern.fullmatch(v))


def parse(data: bytes) -> Registry:
    """Validate snapshot bytes into a `Registry`, or RegistryUnavailable."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise RegistryUnavailable("invalid", "the snapshot is not ASCII") from None
    try:
        doc = json.loads(text, object_pairs_hook=_strict_object, parse_constant=_no_constant)
    except ValueError as e:
        raise RegistryUnavailable("invalid", f"not strict JSON: {e}") from None
    if not isinstance(doc, dict):
        raise RegistryUnavailable("invalid", "the snapshot is not an object")
    schema = doc.get("schema")
    if not isinstance(schema, str) or schema not in SUPPORTED_SCHEMAS:
        raise RegistryUnavailable("schema", f"unsupported schema token {schema!r}")
    seq = _field(doc, "seq", _int, "snapshot")
    written_at = _field(doc, "written_at", _str(_TS), "snapshot")
    raw_entries = _field(doc, "entries", lambda v: isinstance(v, list), "snapshot")
    entries = []
    for i, e in enumerate(raw_entries):
        what = f"entry {i}"
        if not isinstance(e, dict):
            raise RegistryUnavailable("invalid", f"{what} is not an object")
        name = _field(e, "name", _str(_NAME), what)
        entries.append(Entry(
            logical_id=_field(e, "logical_id", _str(_LOGICAL_ID), what),
            name=name,
            adapter=_field(e, "adapter", lambda v: isinstance(v, str) and v in _ADAPTERS, what),
            stable_key=_field(e, "stable_key", lambda v: isinstance(v, str) and v != "", what),
            binding_seq=_field(e, "binding_seq", _int, what),
            name_seq=_field(e, "name_seq", _int, what),
            enrollment_epoch=_field(e, "enrollment_epoch", _int, what),
            first_registered_ts=_field(e, "first_registered_ts", _str(_TS), what),
            state=_field(e, "state", lambda v: isinstance(v, str) and v in _STATES, what),
        ))
    ids = [e.logical_id for e in entries]
    if len(set(ids)) != len(ids):
        raise RegistryUnavailable("invalid", "a logical_id appears twice")
    return Registry(seq=seq, written_at=written_at, entries=tuple(entries))


def seq_path(state_dir: Path) -> Path:
    return Path(state_dir) / SEQ_DIR / SEQ_FILE


#: The floor file is a decimal; anything longer is refused unread.
_SEQ_CAP = 64


def _accepted_seq(state_dir: Path) -> Optional[int]:
    """The highest seq accepted so far, or None when none has been. Read
    pinned: never following a symlink, never blocking on a FIFO, a regular
    file only, bounded."""
    p = seq_path(state_dir)
    try:
        fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise RegistryUnavailable("seq_unreadable", f"{p}: {e.strerror}") from None
    try:
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise RegistryUnavailable("seq_unreadable", f"{p} is not a regular file")
            if st.st_size > _SEQ_CAP:
                raise RegistryUnavailable("seq_unreadable", f"{p} is {st.st_size} bytes")
            raw = os.read(fd, _SEQ_CAP + 1)
        except OSError as e:
            raise RegistryUnavailable("seq_unreadable", f"{p}: {e.strerror}") from None
    finally:
        os.close(fd)
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise RegistryUnavailable("seq_unreadable", f"{p} is not ASCII") from None
    if not re.fullmatch(r"[1-9][0-9]{0,18}", text):
        raise RegistryUnavailable("seq_unreadable", f"{p} is not a positive integer")
    return int(text)


def load(directory: Path, state_dir: Path, *, persist: bool = True) -> Registry:
    """Read, validate, and check `seq` against the highest accepted; persist
    a new highest durably before returning. Raises RegistryUnavailable
    (RegistryRolledBack for a lower seq); never returns a partial view.

    `persist=False` is for a reader that stores nothing (the console): the
    floor is still READ and a rollback still refused, but it is not written.
    A drain never passes it."""
    reg = parse(_read_snapshot(directory))
    prior = _accepted_seq(state_dir)
    if prior is not None and reg.seq < prior:
        raise RegistryRolledBack(
            "rolled_back",
            f"snapshot seq {reg.seq} is below the accepted {prior}; treated as an operator "
            f"restore and held until {seq_path(state_dir)} is removed to acknowledge it")
    # The floor is (re)written durably on EVERY load, equal seq included,
    # before any view built on it is used: a floor that is visible but whose
    # barrier failed is not a floor. Never lowered (the check above).
    if not persist:
        return reg
    try:
        atomic_write(seq_path(state_dir), str(reg.seq).encode("ascii"),
                     durable_root=state_dir)
    except OSError as e:
        raise RegistryUnavailable(
            "seq_persist_failed", f"the seq floor could not be made durable: {e}") from None
    return reg


# ---------------------------------------------------------------------------
# What a poll does with it
# ---------------------------------------------------------------------------

#: Why an instance is held under a registry.
HELD_UNAVAILABLE = "registry_unavailable"
HELD_ROLLED_BACK = "registry_rolled_back"
HELD_NOT_REGISTERED = "not_registered"
HELD_COLLISION = "skeleton_collision"
#: The instance has private state under its NAME (`state_dir/<name>/`, from
#: before the registry) and none under its logical_id: the operator has not
#: moved it. Draining would start a fresh first-sight snapshot and an empty
#: reply ledger beside the old ones, so it is held until they do.
HELD_NOT_MIGRATED = "state_not_migrated"
#: State exists under BOTH the name and the logical_id. Which is current is
#: not this router's to guess.
HELD_STATE_CONFLICT = "state_conflict"
#: The name is one this router can never key state by under a registry: shaped
#: like a logical_id, or the name of a `state_dir` entry of its own.
HELD_NAME_SHAPE = "name_shape"
#: No registry is configured, yet `state_dir/<logical_id>/` still holds
#: pending deliveries or DSN intents from a time when one was. They cannot
#: be mapped back to instances without it, so nothing drains until the
#: operator restores `registry_dir` or drains/migrates that state.
HELD_STRANDED = "registry_state_without_registry"
#: The directories under a logical_id whose entries mean work in flight.
_IN_FLIGHT_DIRS = ("pending", "dsn-pending")

#: `state_dir` entries that are this router's own, never an instance's: the
#: seq floor's directory and the status file (compared casefolded, for a
#: case-insensitive state_dir).
_OWN_STATE_ENTRIES = frozenset({SEQ_DIR.casefold(), "status.json"})
_ID_SHAPED = re.compile(r"[0-9a-fA-F]{32}\Z")


def _present(path: Path) -> bool:
    """`lstat` says something is there, in any shape. A failure other than
    "no such entry" counts as present: unreadable is not proof of absence."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _state_hold(state_dir: Path, name: str, logical_id: str) -> Optional[str]:
    """Why `name`'s private state cannot yet be keyed by `logical_id`, or None."""
    if _ID_SHAPED.fullmatch(name) or name.casefold() in _OWN_STATE_ENTRIES:
        return HELD_NAME_SHAPE
    legacy = _present(Path(state_dir) / name)
    if not legacy:
        return None
    if _present(Path(state_dir) / logical_id):
        return HELD_STATE_CONFLICT
    return HELD_NOT_MIGRATED


@dataclass(frozen=True)
class Report:
    """One poll's reading of the registry, for the drain and for status.
    `state` is "off" (no registry configured: nothing changes), "ok",
    "unavailable" or "rolled_back". Under any state but "off", only names
    in `resolved` are drained; every other configured instance is in
    `held` with a reason."""
    state: str
    seq: Optional[int] = None
    code: Optional[str] = None
    detail: Optional[str] = None
    resolved: Mapping[str, Entry] = None  # type: ignore[assignment]
    held: Mapping[str, str] = None  # type: ignore[assignment]
    #: name -> logical_id for every configured name with an active entry of
    #: exactly that name, held or not (`state_not_migrated`, `state_conflict`
    #: and `skeleton_collision` names still have a known identity). Absent
    #: only for a name the registry does not know (`not_registered`).
    #: What a pending delivery pins, so a later rebind of the name is caught.
    known: Mapping[str, str] = None  # type: ignore[assignment]

    def to_doc(self) -> Dict[str, Any]:
        doc: Dict[str, Any] = {"state": self.state}
        if self.seq is not None:
            doc["seq"] = self.seq
        if self.code is not None:
            doc["code"] = self.code
        if self.detail is not None:
            doc["detail"] = self.detail
        doc["held"] = dict(sorted((self.held or {}).items()))
        return doc


OFF = Report(state="off", resolved={}, held={})


def report_for(registry_dir: Optional[Path], state_dir: Path,
               instances: Iterable[str], *, persist: bool = True) -> Report:
    """Read the registry (if one is configured) and decide, per configured
    instance, whether it may be drained. Never raises: a registry that
    cannot be used holds every instance."""
    names = sorted(instances)
    if registry_dir is None:
        stranded = stranded_state(state_dir)
        if stranded:
            return Report(state="stranded", code=HELD_STRANDED,
                          detail=f"in-flight registry state under {stranded}; restore "
                                 "registry_dir, or drain/migrate it first",
                          resolved={}, held={n: HELD_STRANDED for n in names})
        return OFF
    try:
        reg = load(registry_dir, state_dir, persist=persist)
    except RegistryRolledBack as e:
        return Report(state="rolled_back", code=e.code, detail=e.detail, resolved={},
                      held={n: HELD_ROLLED_BACK for n in names})
    except RegistryUnavailable as e:
        return Report(state="unavailable", code=e.code, detail=e.detail, resolved={},
                      held={n: HELD_UNAVAILABLE for n in names})
    except Exception as e:  # noqa: BLE001 -- a bug here must hold, never resolve
        return Report(state="unavailable", code="internal",
                      detail=f"{type(e).__name__}: {e}", resolved={},
                      held={n: HELD_UNAVAILABLE for n in names})
    active, colliding = reg.resolve()
    resolved: Dict[str, Entry] = {}
    held: Dict[str, str] = {}
    # Every configured name with an ACTIVE entry of exactly that name, held
    # or not: a skeleton collision holds the name but its identity is known.
    known = {e.name: e.logical_id for e in reg.entries
             if e.state == "active" and e.name in set(names)}
    for n in names:
        if n in colliding:
            held[n] = HELD_COLLISION
        elif n in active:
            why = _state_hold(state_dir, n, active[n].logical_id)
            if why is None:
                resolved[n] = active[n]
            else:
                held[n] = why
        else:
            held[n] = HELD_NOT_REGISTERED
    return Report(state="ok", seq=reg.seq, resolved=resolved, held=held, known=known)


def stranded_state(state_dir: Path) -> List[str]:
    """The logical_id directories under `state_dir` holding in-flight work
    (pending deliveries, DSN intents). Only ever non-empty after a registry
    was configured; checked when one is NOT, to fail closed."""
    out = []
    try:
        entries = list(os.scandir(state_dir))
    except OSError:
        return out
    for e in entries:
        if not (_LOGICAL_ID.fullmatch(e.name) and e.is_dir(follow_symlinks=False)):
            continue
        for sub in _IN_FLIGHT_DIRS:
            try:
                if any(c.name.endswith(".json") for c in os.scandir(os.path.join(e.path, sub))):
                    out.append(e.name)
                    break
            except OSError:
                continue
    return sorted(out)


def keyed_config(cfg: Any, report: Report) -> Any:
    """`cfg` with `state_keys` set from `report`, and `report` itself
    attached as THE poll's report (`config.target_hold`): every RESOLVED
    instance's private state is keyed by its logical_id, and every local
    delivery of the poll gates on this same report. Unchanged when no
    registry is configured. A held instance has no key here and is never
    drained."""
    if report.state == "off":
        return cfg
    keys = {n: e.logical_id for n, e in (report.resolved or {}).items()}
    return dataclasses.replace(cfg, state_keys=types.MappingProxyType(keys),
                               registry_report=report)


def state_key(report: Report, name: str) -> str:
    """The directory name for `name`'s private state: the instance name
    when no registry is configured, else its logical_id. A held name has
    no key (KeyError): it must not be touched."""
    if report.state == "off":
        return name
    return report.resolved[name].logical_id


def hop_key(report: Report, name: str) -> str:
    """The hop-tree directory for `name`: always its logical_id (contract
    §4.1), so a hop tree exists only under a registry."""
    if report.state == "off":
        raise RegistryUnavailable("off", "hop trees are keyed by logical_id; "
                                  "no registry is configured")
    return report.resolved[name].logical_id
