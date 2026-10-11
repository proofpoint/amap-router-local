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
        entry's (both are held, never guessed between)."""
        by_skel: Dict[str, List[Entry]] = {}
        for e in self.entries:
            if e.state == "active":
                by_skel.setdefault(skeleton(e.name), []).append(e)
        resolved: Dict[str, Entry] = {}
        held: List[str] = []
        for group in by_skel.values():
            if len(group) == 1:
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
        st = os.fstat(fd)
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
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def _str(pattern):
    return lambda v: isinstance(v, str) and bool(pattern.match(v))


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
            adapter=_field(e, "adapter", lambda v: v in _ADAPTERS, what),
            stable_key=_field(e, "stable_key", lambda v: isinstance(v, str) and v != "", what),
            binding_seq=_field(e, "binding_seq", _int, what),
            name_seq=_field(e, "name_seq", _int, what),
            enrollment_epoch=_field(e, "enrollment_epoch", _int, what),
            first_registered_ts=_field(e, "first_registered_ts", _str(_TS), what),
            state=_field(e, "state", lambda v: v in _STATES, what),
        ))
    ids = [e.logical_id for e in entries]
    if len(set(ids)) != len(ids):
        raise RegistryUnavailable("invalid", "a logical_id appears twice")
    return Registry(seq=seq, written_at=written_at, entries=tuple(entries))


def seq_path(state_dir: Path) -> Path:
    return Path(state_dir) / SEQ_DIR / SEQ_FILE


def _accepted_seq(state_dir: Path) -> Optional[int]:
    p = seq_path(state_dir)
    try:
        text = p.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:
        raise RegistryUnavailable("seq_unreadable", f"{p}: {e}") from None
    if not re.fullmatch(r"[1-9][0-9]{0,18}", text):
        raise RegistryUnavailable("seq_unreadable", f"{p} is not a positive integer")
    return int(text)


def load(directory: Path, state_dir: Path) -> Registry:
    """Read, validate, and check `seq` against the highest accepted; persist
    a new highest durably before returning. Raises RegistryUnavailable
    (RegistryRolledBack for a lower seq); never returns a partial view."""
    reg = parse(_read_snapshot(directory))
    prior = _accepted_seq(state_dir)
    if prior is not None and reg.seq < prior:
        raise RegistryRolledBack(
            "rolled_back",
            f"snapshot seq {reg.seq} is below the accepted {prior}; treated as an operator "
            f"restore and held until {seq_path(state_dir)} is removed to acknowledge it")
    if prior is None or reg.seq > prior:
        atomic_write(seq_path(state_dir), str(reg.seq).encode("ascii"),
                     durable_root=state_dir)
    return reg


# ---------------------------------------------------------------------------
# What a poll does with it
# ---------------------------------------------------------------------------

#: Why an instance is held under a registry.
HELD_UNAVAILABLE = "registry_unavailable"
HELD_ROLLED_BACK = "registry_rolled_back"
HELD_NOT_REGISTERED = "not_registered"
HELD_COLLISION = "skeleton_collision"


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
               instances: Iterable[str]) -> Report:
    """Read the registry (if one is configured) and decide, per configured
    instance, whether it may be drained. Never raises: a registry that
    cannot be used holds every instance."""
    names = sorted(instances)
    if registry_dir is None:
        return OFF
    try:
        reg = load(registry_dir, state_dir)
    except RegistryRolledBack as e:
        return Report(state="rolled_back", code=e.code, detail=e.detail, resolved={},
                      held={n: HELD_ROLLED_BACK for n in names})
    except RegistryUnavailable as e:
        return Report(state="unavailable", code=e.code, detail=e.detail, resolved={},
                      held={n: HELD_UNAVAILABLE for n in names})
    active, colliding = reg.resolve()
    resolved: Dict[str, Entry] = {}
    held: Dict[str, str] = {}
    for n in names:
        if n in colliding:
            held[n] = HELD_COLLISION
        elif n in active:
            resolved[n] = active[n]
        else:
            held[n] = HELD_NOT_REGISTERED
    return Report(state="ok", seq=reg.seq, resolved=resolved, held=held)


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
