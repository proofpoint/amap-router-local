"""router/firstsight.py — the first-sight snapshot and the staged-request quarantine.

A request can be staged in an outbox BEFORE this router has any business
draining it. A workspace config committed to a repository can create the
handoff pair; a repo cloned into a workspace can carry `outbox/req-*.json`
entries with it. If `drain_instance` simply drained whatever it found the
first time it ran, it would deliver a payload that was lying in wait.

So the FIRST time this router sees an instance root, before it drains
anything from it, it records the NAME of every `req-*.json`-shaped entry
already sitting there — and never delivers any of them. Anything that appears
afterwards is an ordinary send.

WHAT CHANGED, AND WHAT DID NOT. This was an explicit operator act: a human
ran `approve NAME`, and nothing was drained until they had. That command is
gone. The deliberate human act is now ENROLMENT — adding the instance to the
router's config, or enrolling its sandbox — which is upstream of this router
seeing the root at all, so the time boundary "nothing that existed before the
router first saw it" sits strictly after it.

The SNAPSHOT is unchanged and is the whole of the protection. Retiring the
command retired a second gate, not this one.

  * What the snapshot guarantees: no file that existed in the outbox at the
    moment the router first saw it is ever delivered — including a payload a
    repository staged in advance — regardless of any timestamp or
    content-rewrite games, and deterministically across restarts (it is
    persisted in the marker, not recomputed on every drain).

  * What it does NOT guarantee: it cannot distinguish content a live agent
    (re)writes under a NEW filename afterwards from a genuinely fresh send —
    those are indistinguishable in principle, and both are governed by the
    same controls every fresh send gets. The line only ensures that first
    sight never retroactively blesses what was already lying in wait under
    its OWN name. A snapshot-named file whose bytes are rewritten later is
    STILL quarantined (name membership decides, not content); the remedy is
    to resubmit under a fresh `req_id`.

  * WHOLESALE REPLACEMENT IS NOT COVERED, and was not covered before either.
    If an outbox is restored from a backup or re-cloned after first sight,
    the snapshot is stale and the restored files are delivered. `approve` was
    idempotent and deliberately did not re-snapshot, so re-running it caught
    this no better. `reset` is the remedy in both designs: it clears
    `state_dir/<name>/`, including this marker, so the next poll is a first
    sight again.

The marker is `state_dir/<name>/first-seen.json` — ROUTER-PRIVATE state,
outside every sandbox (config load guarantees `state_dir` is unreachable from
every instance root), so an agent can neither forge nor backdate it. There is
no copy anywhere an agent can see: the old `APPROVED.json` mirror advertised
an approval that no longer happens.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .config import RouterConfig
from .util import atomic_write, utc_ts

logger = logging.getLogger("amap_router_local.firstsight")

SCHEMA = 1
FIRST_SEEN_FILENAME = "first-seen.json"
#: The pre-retirement marker. Adopted once, on upgrade, so an existing
#: deployment does not take a fresh snapshot and quarantine a live outbox.
LEGACY_APPROVAL_FILENAME = "approval.json"


# Verbatim from outbound.py's REQ_NAME_RE — duplicated rather than imported
# to avoid a module-load cycle (outbound.py imports this module). The
# snapshot only ever needs to recognize the same filename shape the drain
# loop itself would ever open.
_REQ_NAME_RE = re.compile(r"^req-[A-Za-z0-9_-]{1,64}\.json$")


class FirstSightError(Exception):
    """Raised by `record_first_sight()` when asked for an instance name this
    config doesn't know."""


def marker_path(state_dir: Path, name: str) -> Path:
    return state_dir / name / FIRST_SEEN_FILENAME


def read_marker(state_dir: Path, name: str) -> Optional[Dict[str, Any]]:
    """Read + parse the router-private first-sight marker for `name`.
    `None` (never raises) if it doesn't exist, isn't readable, or isn't
    valid JSON — a corrupt/missing marker is treated exactly like "never
    seen" (fail closed: an ambiguous marker means `drain_instance` takes a
    fresh snapshot and quarantines what it finds, rather than draining an
    outbox it cannot vouch for)."""
    path = marker_path(state_dir, name)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def has_been_seen(state_dir: Path, name: str) -> bool:
    return read_marker(state_dir, name) is not None


def quarantined_filenames(marker_doc: Dict[str, Any]) -> Set[str]:
    """The set of `req-*.json` filenames the outbox contained at approval
    time — `outbound.drain_instance` refuses to process a FRESH request
    (no private result yet) whose filename is a member of this set."""
    snapshot = marker_doc.get("outbox_snapshot") or []
    return {
        e["filename"] for e in snapshot
        if isinstance(e, dict) and isinstance(e.get("filename"), str)
    }


def _snapshot_outbox(outbox_root: Path) -> List[Dict[str, Any]]:
    """Inventory every directory entry directly under `outbox_root` whose
    NAME matches `_REQ_NAME_RE` — DELIBERATELY regardless of type
    (regular file, symlink, directory) or whether it can currently be
    read. `quarantined_filenames()` (and `outbound.drain_instance`'s
    membership check) only ever consults the NAME; a snapshot that
    dropped an entry because it happened to be a symlink, a directory, or
    briefly unreadable at the exact moment of first sight would let that
    same name back in the moment it changes shape (symlink swapped for a
    regular file, directory replaced by a file, permissions relaxed) —
    every one of those was sitting in the outbox under this name when the
    router arrived, so "unreadable right now" must never mean "not in the
    outbox." Verified: a staged `req-*.json` chmod'd unreadable before the
    snapshot and restored after,
    a staged symlink later swapped for a regular file, and a staged
    directory later replaced by a file all previously slipped the
    snapshot and were then delivered as if fresh.

    `sha256`/`size` are best-effort FORENSIC SIDECAR DATA ONLY (surfaced
    in `_quarantine_one`'s meta file for the operator) — `None` when the
    entry isn't a readable regular non-symlink file at snapshot time.
    Membership is name-only and costs nothing when the digest is null.

    An entry whose name never appears in the initial `iterdir()` listing
    at all — genuinely absent, or created only after this snapshot runs —
    is correctly not recorded; this only ever reports names that existed
    in the listing, however briefly."""
    entries: List[Dict[str, Any]] = []
    if not outbox_root.is_dir():
        return entries
    try:
        names = sorted(p.name for p in outbox_root.iterdir())
    except OSError:
        return entries
    for name in names:
        if not _REQ_NAME_RE.match(name):
            continue
        p = outbox_root / name
        sha256: Optional[str] = None
        size: Optional[int] = None
        try:
            if p.is_file() and not p.is_symlink():
                data = p.read_bytes()
                sha256 = hashlib.sha256(data).hexdigest()
                size = len(data)
        except OSError:
            pass  # type/permission/race — the entry is STILL a quarantine
            # member by name; only the forensic digest is unavailable.
        entries.append({"filename": name, "sha256": sha256, "size": size})
    return entries


def record_first_sight(cfg: RouterConfig, name: str) -> Tuple[Dict[str, Any], bool]:
    """Ensure instance `name` has a first-sight marker, taking the snapshot if
    it does not. Returns `(doc, was_new)`.

    CALLED BY `drain_instance` BEFORE IT DRAINS, every poll. The first call
    snapshots; every later call returns the existing marker untouched. It
    must never re-snapshot: that would move the quarantine line forward and
    retroactively bless whatever appeared since, which is precisely the
    staging this exists to refuse.

    ON UPGRADE, an existing `approval.json` is ADOPTED rather than ignored.
    Without that, the first poll after retiring `approve` would find no
    marker, call itself a first sight, and quarantine every request sitting
    in a live outbox — turning a routine upgrade into a fleet-wide stall. The
    adopted snapshot is the one a human took, so the quarantine line does not
    move.

    Refuses (`FirstSightError`) if `name` names no configured instance."""
    if name not in cfg.instances:
        raise FirstSightError(
            f"first sight: {name!r} names no configured instance "
            f"(known: {sorted(cfg.instances)})"
        )
    existing = read_marker(cfg.state_dir, name)
    if existing is not None:
        return existing, False

    inst = cfg.instances[name]
    legacy = _read_json(cfg.state_dir / name / LEGACY_APPROVAL_FILENAME)
    if legacy is not None and isinstance(legacy.get("outbox_snapshot"), list):
        doc = dict(legacy)
        doc["schema"] = SCHEMA
        doc["instance"] = name
        doc["first_seen_ts"] = legacy.get("approved_ts") or utc_ts()
        doc["adopted_from"] = LEGACY_APPROVAL_FILENAME
        logger.info(
            "instance %r: adopting the existing %s as its first-sight marker "
            "(%d filename(s) stay quarantined) — the approval gate is retired, "
            "the snapshot it took is not",
            name, LEGACY_APPROVAL_FILENAME, len(doc["outbox_snapshot"]),
        )
    else:
        snapshot = _snapshot_outbox(inst.outbox_root)
        doc = {
            "schema": SCHEMA,
            "instance": name,
            "first_seen_ts": utc_ts(),
            "mode": inst.mode,
            "declared_root": str(inst.root),
            "outbox_snapshot": snapshot,
        }
        # Loud on purpose. On a router meeting an existing fleet for the
        # first time — a fresh container, a rebuilt state_dir — this fires
        # for every instance at once and quarantines whatever was already
        # staged. That is correct and it is surprising, so an operator
        # watching the log sees why their outboxes went quiet.
        logger.info(
            "instance %r: FIRST SIGHT. %d request(s) already in its outbox are "
            "quarantined and will never be delivered; anything written from now "
            "on is an ordinary send. Remedy for a false positive: resubmit under "
            "a fresh req_id.", name, len(snapshot),
        )
    atomic_write(
        marker_path(cfg.state_dir, name),
        json.dumps(doc, sort_keys=True).encode("utf-8"),
    )
    return doc, True


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None
