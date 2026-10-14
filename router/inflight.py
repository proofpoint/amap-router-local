"""router/inflight.py — a request that stays unsettled across polls.

Until this module, every request settled in the poll that consumed it:
"settled" means a private result exists (`outbound._finish`), and every
idempotency guarantee in `outbound` rests on that. A request handed to a
second runtime (through an optional transport plugin) cannot settle that
way: `accepted` means the downstream runtime accepted the message (the
draft's Result section, "Field semantics and obligations"), and only that
runtime's result says so. So between
the hand-off and that result, the request is IN FLIGHT.

WHAT THIS MODULE OWNS, and nothing else:

  * The RECORD, `state_dir/<name>/inflight/<req_id>.json`: the digest of the
    agent's request bytes, the transport req_id, the evaluated recipients and
    the staged copy of the request document, plus its HANDED marker (below). Every later step acts on the
    staged copy, never on the agent's file again (ingest by copy).
  * The COUNTER, `state_dir/<name>/transport/next_req_id`. Transport req_ids
    are monotonic per transport namespace and never reused; the draft's
    Submit Request section requires it of a Connector, which is the role this
    router plays toward the transport. The next value is persisted BEFORE the
    current one is used, so a crash burns an id and never repeats one. An id
    derived from the agent's request was considered and withdrawn: the
    downstream runtime's handling of a reused id is not idempotent (a
    resubmitted, already-sent id is rejected and overwrites the accepted
    verdict). One transport namespace per agent, so the counter lives under
    the agent's own state directory; a top-level `state_dir/transport/` would
    collide with an instance named `transport`. `reset` preserves it.
  * `advance`: one per-poll step for one record, deciding from what the
    transport side shows. The transport itself is a `TransportPort`, so the
    state machine is tested with no transport tree at all.

THE PER-POLL STEP, in this order (the downstream runtime writes its result
BEFORE it archives the request):

  | transport state for `n`              | action                                  |
  |--------------------------------------|-----------------------------------------|
  | a result exists                      | validate it, settle from it             |
  | the request is pending               | nothing; never rewrite                  |
  | archived, and still no result        | settle `queued_for_human`/`transport_anomaly`; never resubmit |
  | none of them, and still no result    | write it now, under the SAME `n`        |

Before that table, a record that was never handed over (no HANDED marker)
is checked twice: a transport trace under `n` settles it as an anomaly
(THE HANDED MARKER, below), and so does a draft whose `to` ∪ `cc` is not
the evaluated set.

The two "still no result" re-checks are not redundant. Between this step's
first probe and its later ones the downstream runtime may write the result
and archive the request; without the re-check that interleaving reads as
"archived without a result" and settles a sent message as an anomaly.

NO TIMEOUT. A record whose result never arrives stays in flight forever, by
operator decision (Q1, 2026-10-07): the downstream runtime has no atomic
claim, so nothing here can tell "not yet opened" from "opened and about to
send", and an answer given on age could contradict a send that then happens.
`summarize` reports the count, the oldest age and how many are past
`STALE_AFTER_S`, for `status.json`.

EXACTLY ONE RESULT. Settling is the caller's `settle` callback (in practice
`outbound._finish`, which writes the private result first — the existing
anchor). The record is deleted only AFTER settling. A crash between the two
leaves a record whose request is already settled; the next step sees
`already_settled` and only deletes the record.

RECIPIENTS: EXACTLY THE EVALUATED SET, OR NOBODY. The transport request
carries the staged draft, and the downstream runtime sends to everything in
its `to` and `cc`. So before anything is handed over, `recipient_mismatch`
requires the draft's `to` ∪ `cc` to be exactly the evaluated recipients
(domains case-insensitively, local parts exactly); any difference settles `queued_for_human`/
`transport_anomaly` with nothing sent, because cold sends are all-or-nothing
and narrowing the draft to the authorised part would be a partial send.
`transport_request_bytes` refuses a mismatched record as well, so no caller
can build a request that skips the check.

THE HANDED MARKER, `inflight/<req_id>.handed`, holds the transport id `n`
and is written after the record and BEFORE the transport request. A record
counts as handed over only when its marker exists AND names its own `n`, so
an orphan marker (a crash between the two unlinks in `_cleanup`, then a
reused agent req_id) never vouches for a new record.

A record NOT handed over that finds anything under `n` on the transport
cannot tell whose request that is. It may be another request's (the counter
went backwards: a restored or rolled-back state volume), and settling from
it would answer this request with that request's result. It may equally be
this request's own hand-off, if the state was restored to between the
record and its marker, and then handing it over again under a new id would
send it twice. Neither guess is safe, so it fails closed: settled
`queued_for_human`/`transport_anomaly`, logged as an ERROR, never handed
over again and never settled from the trace.

DURABILITY. Every write here goes through `util.atomic_write`, which fsyncs
the file and its directory, with `durable_root=state_dir`, so every
directory between `state_dir` and the file is re-established on each write
and a barrier that failed on an earlier attempt is repaired by the next.
The record is removed only after the settlement was written that way. When
a later poll finds the settlement already there (a crash, or a directory
fsync that failed after its rename), it validates that private result and
fsyncs it and its directory again BEFORE removing the record
(`_redurabilise`); existing is not proof of durable, and the request is
never sent again. That is necessary for durability and is not
by itself a claim that this scaffold is power-loss safe: the filesystem
underneath must honour fsync too, and nothing here measures that. Showing
it for a real transport is a separate, later step.

`_effect` is the one seam every side effect here passes through, so a test
can crash the sequence after any single write and prove the next poll
recovers. It does nothing else.

A `reset` removes every record with the rest of `state_dir/<name>/`. A
transport request already handed over then has no record, so its eventual
result is never read; the agent's outbox was emptied by the same reset.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import logging
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import transport as transport_mod
from . import config as config_mod
from . import hoplink
from .config import RouterConfig
from .util import atomic_write, fsync_dir, parse_utc_ts, utc_ts

logger = logging.getLogger("amap_router_local.inflight")

INFLIGHT_DIR = "inflight"
#: Suffix of the HANDED marker beside a record (module docstring).
HANDED_SUFFIX = ".handed"
#: Preserved by `reset`: the counter must never restart (module docstring).
TRANSPORT_STATE_DIR = "transport"
COUNTER_FILE = "next_req_id"

REASON_TRANSPORT_ANOMALY = "transport_anomaly"
#: `classify.REASON_NO_ROUTE`, named here so this module keeps its imports.
REASON_NO_ROUTE = "no_route"
DETAIL_FENCED_UNHANDED = "generation fenced before hand-over; nothing was sent"
DETAIL_PREFIX = "transport: "

#: Age past which a record counts as stale in `summarize`. Reporting only:
#: nothing is ever settled on age (module docstring, NO TIMEOUT).
STALE_AFTER_S = 3600
#: The hold a hand-over shows when its original could not be preserved.
PRESERVATION_FAILED = "peer_preservation_failed"

_OUTCOMES = ("accepted", "queued_for_human", "rejected")
_COUNTER_RE = re.compile(r"^[1-9][0-9]{0,17}\Z")
_REASON_RE = re.compile(r"^[\x21-\x7e]{1,128}\Z")
_DETAIL_CAP = 2000

# States `advance` reports.
SETTLED = "settled"
PENDING = "pending"
WRITTEN = "written"
CLEANED = "cleaned"
#: Not published this poll because the config reload is failing (`advance`).
BLOCKED = "blocked"


@dataclass(frozen=True)
class Recheck:
    """The caller's re-classification of a record's staged request under the
    CURRENT config (`outbound._recheck`). `permitted` means the same class,
    route and recipient set. When permitted, `policy_digest` is the sender's
    digest now; when not, `verdict` is the settlement and `why` says what
    changed, and `route` is the route it was permitted on."""
    permitted: bool
    policy_digest: Optional[str] = None
    verdict: Optional[Dict[str, Any]] = None
    why: str = ""
    #: When permitted: the request's route now (`classify.REMOTE_ROUTES`).
    route: Optional[str] = None


def withdraw_capable(port: Any) -> bool:
    """Whether the transport offers `withdraw_request`. It is part of
    `TransportPort` from API (3, 0), but the in-flight table does not call
    it yet: a withdrawn request needs its own branch in the table's
    "archived, still no result" row first. Reported so that a revoked
    request's log line and `status` say which case they are in."""
    return callable(getattr(port, "withdraw_request", None))


#: The transport port lives in `router/transport.py`, with the plugin seam;
#: the name stays here so every existing caller and type hint is unchanged.
TransportPort = transport_mod.TransportPort


class CounterCorrupt(Exception):
    """The counter file exists and is not a positive decimal. Raised, never
    repaired: restarting at 1 would reuse every id already handed over."""


def _effect(label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Every side effect in this module goes through here (module
    docstring). `label` names it for a test's crash injector."""
    return fn(*args, **kwargs)


def _inflight_dir(cfg: RouterConfig, name: str) -> Path:
    return config_mod.gen_state_dir(cfg, name) / INFLIGHT_DIR


def record_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return _inflight_dir(cfg, name) / f"{req_id}.json"


def handed_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return _inflight_dir(cfg, name) / f"{req_id}{HANDED_SUFFIX}"


# ---------------------------------------------------------------------------
# THE ATTACHMENT SNAPSHOT: the bytes ingest verified, copied ONCE into this
# router's private state at begin, so every hand-over of the request carries
# exactly them, whatever later happens to the agent's own sidecars.
#
#   <gen>/inflight-snapshots/<req_id>/<i>     0700 directories, 0600 blobs
#
# A SIBLING of `inflight/`, never inside it: `generations._handed_out` counts
# ANY entry of `inflight/` as an allocated transport id, and the status scans
# read its entries, so `inflight/` holds records and markers only.
#
# Written BEFORE the record, which is the commit point: a temp directory
# (`.tmp-<req_id>-<16 hex>`: a leading dot, so no req_id can collide with
# it), its blobs, the rename to `<req_id>`, then `inflight-snapshots/`
# fsynced. The record's own `attachments` member names what the snapshot must
# hold. A durable record therefore always has its snapshot; a snapshot can
# outlive its record (an orphan), never the reverse. Removed only after the
# record is durably gone (`_cleanup`), or by the sweep once the record's
# absence is PROVEN (ENOENT).
# ---------------------------------------------------------------------------

SNAPSHOT_DIR = "inflight-snapshots"
SNAPSHOT_DIR_MODE = 0o700
_TMP_PREFIX = ".tmp-"
_TMP_RE = re.compile(r"\.tmp-(.+)-[0-9a-f]{16}\Z")
_SNAP_REQ_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")

DETAIL_SNAPSHOT_DAMAGED = ("the router's attachment snapshot is damaged; "
                           "nothing was handed over")


class SnapshotDamaged(ValueError):
    """The attachment snapshot does not prove the bytes its record names.
    `reason` is one of `REASONS`. This router's own state damage, never the
    agent's: not handed over, the request is settled as an anomaly; handed
    over, this generation's hand-overs are held."""

    REASONS = ("missing", "size", "sha256", "not_regular", "linked", "not_a_directory")

    def __init__(self, reason: str, detail: str) -> None:
        assert reason in self.REASONS, reason
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def _open_dir_nofollow(path: Path) -> int:
    return os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _own_dir(fd: int) -> bool:
    st = os.fstat(fd)
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()


def write_snapshot(cfg: RouterConfig, name: str, req_id: str,
                   attachments: List[Any]) -> List[Dict[str, Any]]:
    """Write the snapshot of `attachments` (ingest's `VerifiedAttachment`s)
    durably, and return the record's `attachments` member. Call it BEFORE the
    record exists. A leftover `<req_id>` (or temp) found first is removed only
    when the record's absence is proven; anything uncertain raises."""
    from . import attachments as attachments_mod  # local: attachments -> reset -> inflight
    from .util import _mkdir_durable
    gen = config_mod.gen_state_dir(cfg, name)
    _mkdir_durable(gen, Path(cfg.state_dir))
    gen_fd = _open_dir_nofollow(gen)
    try:
        snaps_fd = attachments_mod._mkdir_and_pin(gen_fd, SNAPSHOT_DIR, mode=SNAPSHOT_DIR_MODE)
        try:
            for entry in os.listdir(snaps_fd):
                if _snapshot_owner(entry) == req_id:
                    if _record_absent(gen_fd, req_id) is not True:
                        raise OSError(f"{SNAPSHOT_DIR}/{entry}: a leftover whose record's "
                                      f"absence cannot be proven")
                    _remove_entry(snaps_fd, entry)
            tmp = f"{_TMP_PREFIX}{req_id}-{secrets.token_hex(8)}"
            tmp_fd = attachments_mod._mkdir_and_pin(snaps_fd, tmp, mode=SNAPSHOT_DIR_MODE)
            try:
                for i, a in enumerate(attachments):
                    attachments_mod._write_blob_pinned(tmp_fd, i, a.data)
            finally:
                os.close(tmp_fd)
            _effect("snapshot", os.rename, tmp, req_id, src_dir_fd=snaps_fd, dst_dir_fd=snaps_fd)
            os.fsync(snaps_fd)
        finally:
            os.close(snaps_fd)
    finally:
        os.close(gen_fd)
    return [{"size_bytes": a.size_bytes, "sha256": a.sha256} for a in attachments]


def read_snapshot(cfg: RouterConfig, name: str, req_id: str,
                  expected: List[Dict[str, Any]]) -> List[bytes]:
    """The snapshot's blobs, each re-proved against `expected` (the record's
    `attachments`): every directory and blob opened no-follow, each blob a
    regular file with one link, EXACTLY `size_bytes` long (read with a
    one-byte lookahead) and of digest `sha256`. The bound is the RECORD's,
    never the current config's. Raises `SnapshotDamaged` ONLY for what the
    snapshot itself shows (absent, a link, not a directory, not a regular
    file, the wrong size or digest); any other error (EMFILE, EIO, ENOMEM,
    EACCES, ...) propagates, so the poll is retried rather than the request
    settled or the generation held."""
    gen = config_mod.gen_state_dir(cfg, name)
    gen_fd = _open_snapshot_dir(None, str(gen), str(gen))
    fds = [gen_fd]
    try:
        cur = gen_fd
        for part in (SNAPSHOT_DIR, req_id):
            fd = _open_snapshot_dir(cur, part, part)
            fds.append(fd)
            if not _own_dir(fd):
                raise SnapshotDamaged("not_a_directory", f"{part}: not this uid's directory")
            cur = fd
        out = []
        for i, want in enumerate(expected):
            try:
                bfd = os.open(str(i), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=cur)
            except OSError as e:
                why = _DAMAGE_ERRNO.get(e.errno)
                if why is None:
                    raise          # transient: retried next poll, never damage
                raise SnapshotDamaged(why, f"blob {i}: {e.strerror}") from None
            try:
                st = os.fstat(bfd)
                if not stat.S_ISREG(st.st_mode):
                    raise SnapshotDamaged("not_regular", f"blob {i}")
                if st.st_nlink != 1:
                    raise SnapshotDamaged("linked", f"blob {i}: {st.st_nlink} links")
                size = want["size_bytes"]
                data = b""
                while len(data) <= size:
                    chunk = os.read(bfd, size + 1 - len(data))
                    if not chunk:
                        break
                    data += chunk
            finally:
                os.close(bfd)
            if len(data) != size:
                raise SnapshotDamaged("size", f"blob {i}: {len(data)} bytes, not {size}")
            if hashlib.sha256(data).hexdigest() != want["sha256"]:
                raise SnapshotDamaged("sha256", f"blob {i}: digest differs")
            out.append(data)
        return out
    finally:
        for fd in reversed(fds):
            os.close(fd)


#: The open errors that ARE the snapshot's own state; every other errno is
#: transient and propagates.
_DAMAGE_ERRNO = {errno.ENOENT: "missing", errno.ELOOP: "linked", errno.ENOTDIR: "not_a_directory"}


def _open_snapshot_dir(parent_fd: Optional[int], name: str, label: str) -> int:
    """A snapshot-path directory, opened `O_DIRECTORY | O_NOFOLLOW`
    (relative to `parent_fd` when given). Absent is `missing`, a link or a
    non-directory is `not_a_directory`; any other error propagates."""
    try:
        if parent_fd is None:
            return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise SnapshotDamaged("missing", f"{label}: absent") from None
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise SnapshotDamaged("not_a_directory", f"{label}: not a real directory") from None
        raise


def _pin_child(parent_fd: int, part: str) -> "Tuple[str, Optional[int]]":
    from .util import open_child_pinned
    return open_child_pinned(parent_fd, part)


def _snapshot_owner(entry: str) -> Optional[str]:
    """The req_id an `inflight-snapshots/` entry belongs to, or None for a
    name of neither form."""
    m = _TMP_RE.fullmatch(entry)
    if m is not None:
        return m.group(1) if _SNAP_REQ_ID_RE.fullmatch(m.group(1)) else None
    return entry if _SNAP_REQ_ID_RE.fullmatch(entry) else None


def _record_absent(gen_fd: int, req_id: str) -> Optional[bool]:
    """True only when `inflight/<req_id>.json` is PROVEN absent (ENOENT, or no
    `inflight/` at all), through a pinned, owner-checked, no-follow lookup;
    False when an entry is there; None when it cannot be told."""
    kind, ifd = _pin_child(gen_fd, INFLIGHT_DIR)
    if kind == "missing":
        return True
    if kind != "dir":
        return None
    try:
        if not _own_dir(ifd):
            return None
        try:
            os.stat(f"{req_id}.json", dir_fd=ifd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        except OSError:
            return None
        return False
    finally:
        os.close(ifd)


class SnapshotNotOwned(OSError):
    """A directory on a snapshot path that is not this uid's: never listed,
    never deleted. Begin fails (retried next poll); the sweep retains it and
    counts it uncertain; cleanup leaves it for the sweep."""


def _remove_entry(parent_fd: int, entry: str) -> None:
    """Remove one snapshot directory (its blobs, then itself), every step
    relative to a pinned descriptor and never following a link. EVERY
    directory is checked to be this uid's before it is listed or removed
    (`SnapshotNotOwned` otherwise, nothing more removed). A non-directory at
    that name is unlinked as it is."""
    kind, fd = _pin_child(parent_fd, entry)
    if kind == "missing":
        return
    if kind != "dir":
        os.unlink(entry, dir_fd=parent_fd)
        return
    try:
        if not _own_dir(fd):
            raise SnapshotNotOwned(f"{entry}: not this uid's directory; not removed")
        for child in os.listdir(fd):
            try:
                os.unlink(child, dir_fd=fd)
            except IsADirectoryError:
                _remove_entry(fd, child)
    finally:
        os.close(fd)
    os.rmdir(entry, dir_fd=parent_fd)


def _remove_snapshot_at(gen: Path, req_id: str) -> None:
    """`_cleanup`'s snapshot step: remove `<gen>/inflight-snapshots/<req_id>`
    and fsync `inflight-snapshots/`. A missing one is done; one that cannot
    be removed is logged and left for the sweep."""
    try:
        gen_fd = _open_dir_nofollow(gen)
    except FileNotFoundError:
        return
    try:
        kind, sfd = _pin_child(gen_fd, SNAPSHOT_DIR)
        if kind == "missing":
            return
        if kind != "dir":
            logger.error("%s/%s is not a real directory; snapshot %r left for the sweep",
                         gen, SNAPSHOT_DIR, req_id)
            return
        try:
            if not _own_dir(sfd):
                raise SnapshotNotOwned(f"{SNAPSHOT_DIR}: not this uid's directory")
            _remove_entry(sfd, req_id)
            os.fsync(sfd)
        finally:
            os.close(sfd)
    except OSError as e:
        logger.error("%s: snapshot %r not removed (%s); left for the sweep", gen, req_id, e)
    finally:
        os.close(gen_fd)


def sweep_snapshots(cfg: RouterConfig, name: str) -> int:
    """Remove orphan snapshots in `name`'s generation (the view's): an entry
    goes ONLY when its record's absence is PROVEN by ENOENT. A listing that
    fails, a name of neither form, or a lookup that cannot decide RETAINS it
    with an ERROR. Returns how many were retained as uncertain. Call under
    the drain lock."""
    gen = config_mod.gen_state_dir(cfg, name)
    try:
        gen_fd = _open_dir_nofollow(gen)
    except FileNotFoundError:
        return 0
    except OSError as e:
        logger.error("%s: snapshot sweep cannot open the generation (%s)", gen, e.strerror)
        return 1
    uncertain = 0
    try:
        kind, sfd = _pin_child(gen_fd, SNAPSHOT_DIR)
        if kind == "missing":
            return 0
        if kind != "dir" or not _own_dir(sfd):
            if sfd is not None:
                os.close(sfd)
            logger.error("%s/%s is not this uid's real directory: nothing swept", gen, SNAPSHOT_DIR)
            return 1
        try:
            try:
                entries = sorted(os.listdir(sfd))
            except OSError as e:
                logger.error("%s/%s cannot be listed (%s): nothing swept", gen, SNAPSHOT_DIR,
                             e.strerror)
                return 1
            removed = False
            for entry in entries:
                owner = _snapshot_owner(entry)
                if owner is None:
                    uncertain += 1
                    logger.error("%s/%s/%s: not a snapshot name; retained", gen, SNAPSHOT_DIR, entry)
                    continue
                absent = _record_absent(gen_fd, owner)
                if absent is None:
                    uncertain += 1
                    logger.error("%s/%s/%s: its record's absence cannot be proven; retained",
                                 gen, SNAPSHOT_DIR, entry)
                    continue
                if absent:
                    try:
                        _remove_entry(sfd, entry)
                        removed = True
                    except OSError as e:
                        uncertain += 1
                        logger.error("%s/%s/%s: orphan not removed (%s)", gen, SNAPSHOT_DIR,
                                     entry, e)
            if removed:
                os.fsync(sfd)
        finally:
            os.close(sfd)
    finally:
        os.close(gen_fd)
    return uncertain


def counter_path(cfg: RouterConfig, name: str) -> Path:
    return config_mod.gen_state_dir(cfg, name) / TRANSPORT_STATE_DIR / COUNTER_FILE


class RecordDamaged(ValueError):
    """A record outside the closed schema (`check_record`). Raised, never
    repaired: the per-record isolation in the drain keeps it, and the request
    is neither settled nor handed over on a guess."""


#: The CLOSED record schema: every member, with whether it is required.
#: `policy_digest` and `route` are written at `begin` by every caller that
#: classified the request; a record without them (written before they
#: existed, or by a test driving this module alone) is re-classified at
#: publication like any other. `revocation_unenforceable` is the ts at which
#: a handed record was found no longer permitted with no way to withdraw it
#: (`mark_unenforceable`).
_RECORD_KEYS = {
    "digest": False, "transport_req_id": True, "recipients": True, "request": True,
    "written_ts": True, "policy_digest": False, "route": False,
    "revocation_unenforceable": False, "from_address": False, "attachments": False,
    "bound_reply": False, "peer": False, "retransmit": False,
}
#: A retransmit's pin (`peerresend`): the original it carries, by its
#: generation, transport id and peer id. Its settlement is the retransmit's
#: own, never the agent's Result.
_RETRANSMIT_KEYS = frozenset({"of_generation", "of_n", "id"})
#: A signed kind's pin (`begin`'s `peer`): the statement, its signature and
#: header, and the envelope's `peer` members, exactly as signed at begin.
_PEER_KEYS = frozenset({"kind", "id", "message_id", "key_id", "statement", "signature",
                        "statement_header", "in_reply_to", "references"})
#: The signed kinds a PRODUCTION path begins. Control notices have no
#: producer yet, so a record pinning one is damaged, never handed over.
PRODUCED_SIGNED_KINDS = ("peer", "control")
#: The router's own runtime control namespace (`config.RUNTIME_NS`): the only
#: one whose records may pin a `control` statement. An agent's namespace
#: pinning one is damaged.
RUNTIME_ONLY_KINDS = ("control",)
#: A bound reply's pin (`begin`'s `bound_reply`): the ledger record's notice
#: id, the binding members as that record carried them at begin, and the
#: `bound` object every hand-over carries.
_BOUND_REPLY_KEYS = frozenset({"notice_id", "binding", "bound"})
_ROUTES = ("fleet_host", "internet", "trusted_fleet_host")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def check_record(doc: Any, *, runtime: bool = False) -> Dict[str, Any]:
    """`doc` if it is a record in the closed schema, else `RecordDamaged`.
    `runtime`: the record lives in the router's runtime control namespace,
    the only one where a `control` pin is not damaged."""
    if not isinstance(doc, dict):
        raise RecordDamaged("not an object")
    extra = sorted(set(doc) - set(_RECORD_KEYS))
    if extra:
        raise RecordDamaged(f"unknown member(s) {extra}")
    missing = sorted(k for k, req in _RECORD_KEYS.items() if req and k not in doc)
    if missing:
        raise RecordDamaged(f"missing member(s) {missing}")
    if not (isinstance(doc["transport_req_id"], str)
            and re.fullmatch(r"[0-9]{8,18}", doc["transport_req_id"])):
        raise RecordDamaged("transport_req_id is not 8-18 digits")
    if not (isinstance(doc["recipients"], list)
            and all(isinstance(r, str) for r in doc["recipients"])):
        raise RecordDamaged("recipients is not a list of strings")
    if not isinstance(doc["request"], dict):
        raise RecordDamaged("request is not an object")
    for key in ("written_ts", "revocation_unenforceable", "from_address"):
        if key in doc and not isinstance(doc[key], str):
            raise RecordDamaged(f"{key} is not a string")
    if doc.get("digest") is not None and not isinstance(doc["digest"], str):
        raise RecordDamaged("digest is not a string")
    if "policy_digest" in doc and not (isinstance(doc["policy_digest"], str)
                                       and _POLICY_DIGEST_RE.fullmatch(doc["policy_digest"])):
        raise RecordDamaged("policy_digest is not sha256:<64 hex>")
    if "route" in doc and doc["route"] not in _ROUTES:
        raise RecordDamaged("route is not a known route")
    if "attachments" in doc:
        _check_record_attachments(doc)
    if "bound_reply" in doc:
        _check_record_bound_reply(doc)
    if "retransmit" in doc:
        rt = doc["retransmit"]
        if not (isinstance(rt, dict) and set(rt) == _RETRANSMIT_KEYS
                and all(isinstance(v, str) for v in rt.values()) and "peer" in doc):
            raise RecordDamaged("retransmit is not {of_generation, of_n, id} beside a peer pin")
    if "peer" in doc:
        _check_record_peer(doc)
        if (doc["peer"]["kind"] in RUNTIME_ONLY_KINDS) != runtime:
            raise RecordDamaged(f"peer.kind {doc['peer']['kind']!r} in the wrong namespace")
    return doc


def _b64(value: Any, what: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (AttributeError, ValueError, UnicodeEncodeError):
        raise RecordDamaged(f"peer.{what} is not standard base64") from None


def _check_record_peer(doc: Dict[str, Any]) -> None:
    """The record's `peer` pin. The statement it pins must name the pinned
    id, key id and the ONE evaluated recipient, and its kind must have a
    production producer; the header's agreement with the statement and
    signature is checked through the codec at every hand-over."""
    pin = doc["peer"]
    if not (isinstance(pin, dict) and set(pin) == _PEER_KEYS):
        raise RecordDamaged(f"peer is not {sorted(_PEER_KEYS)}")
    if pin["kind"] not in PRODUCED_SIGNED_KINDS:
        raise RecordDamaged(f"peer.kind {pin['kind']!r} has no production producer")
    if "bound_reply" in doc:
        raise RecordDamaged("a record pins both a bound reply and a peer statement")
    statement = _b64(pin["statement"], "statement")
    if len(_b64(pin["signature"], "signature")) != 64:
        raise RecordDamaged("peer.signature is not 64 bytes")
    try:
        sdoc = json.loads(statement.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise RecordDamaged("peer.statement is not JSON") from None
    if not isinstance(sdoc, dict) or sdoc.get("kind") != pin["kind"]:
        raise RecordDamaged("peer.statement's kind is not the pin's")
    if sdoc.get("id") != pin["id"] or sdoc.get("key_id") != pin["key_id"]:
        raise RecordDamaged("peer.statement's id or key_id is not the pin's")
    if doc["recipients"] != [sdoc.get("to")]:
        raise RecordDamaged("peer.statement names a recipient other than the evaluated one")
    for key in ("statement_header", "message_id"):
        if not isinstance(pin[key], str):
            raise RecordDamaged(f"peer.{key} is not a string")



def _check_record_bound_reply(doc: Dict[str, Any]) -> None:
    """The record's `bound_reply` pin. Its `bound` must make a valid
    envelope, and name exactly the one evaluated recipient, which is its
    counterparty: a record that would hand over anything else is damaged."""
    pin = doc["bound_reply"]
    if not (isinstance(pin, dict) and set(pin) == _BOUND_REPLY_KEYS
            and isinstance(pin["notice_id"], str) and isinstance(pin["binding"], dict)):
        raise RecordDamaged(f"bound_reply is not {sorted(_BOUND_REPLY_KEYS)}")
    why = hoplink.bound_problem(pin["bound"])
    if why is not None:
        raise RecordDamaged(f"bound_reply.bound: {why}")
    if doc["recipients"] != [pin["bound"]["bound_address"]]:
        raise RecordDamaged("bound_reply.bound names a recipient other than the evaluated one")
    if doc.get("policy_digest") != pin["bound"]["policy_digest"]:
        raise RecordDamaged("bound_reply.bound.policy_digest is not the record's")


def _check_record_attachments(doc: Dict[str, Any]) -> None:
    """The record's own `attachments`: the snapshot's identity, one closed
    `{size_bytes, sha256}` per staged descriptor, in order. It must equal the
    staged request's `draft.attachments` (size and digest) position by
    position, or the record is damaged: the two never diverge silently."""
    atts = doc["attachments"]
    if not (isinstance(atts, list) and atts):
        raise RecordDamaged("attachments is not a non-empty list")
    for i, a in enumerate(atts):
        if not (isinstance(a, dict) and set(a) == {"size_bytes", "sha256"}
                and type(a["size_bytes"]) is int and a["size_bytes"] >= 0
                and isinstance(a["sha256"], str) and _SHA256_RE.fullmatch(a["sha256"])):
            raise RecordDamaged(f"attachments[{i}] is not {{size_bytes, sha256}}")
    draft = doc["request"].get("draft")
    descs = draft.get("attachments") if isinstance(draft, dict) else None
    if not (isinstance(descs, list) and len(descs) == len(atts) and all(
            isinstance(d, dict) and d.get("size_bytes") == a["size_bytes"]
            and d.get("sha256") == a["sha256"] for d, a in zip(descs, atts))):
        raise RecordDamaged("attachments does not match the staged draft's descriptors")


def read_record(cfg: RouterConfig, name: str, req_id: str) -> Optional[Dict[str, Any]]:
    try:
        raw = record_path(cfg, name, req_id).read_bytes()
    except FileNotFoundError:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RecordDamaged("not JSON") from e
    return check_record(doc, runtime=name == config_mod.RUNTIME_NS)


def list_records(cfg: RouterConfig, name: str) -> List[str]:
    """The agent req_ids with a record, sorted. Records are router-written,
    so a name that is not `<id>.json` is a stray and is skipped."""
    d = _inflight_dir(cfg, name)
    if not d.is_dir():
        return []
    return sorted(
        p.name[: -len(".json")] for p in d.iterdir()
        if p.name.endswith(".json") and p.is_file() and not p.is_symlink()
    )


def allocate_transport_req_id(cfg: RouterConfig, name: str) -> str:
    """The next transport req_id for `name`'s transport namespace. The
    successor is written before this returns, so the returned id is never
    handed out again, crash or not."""
    path = counter_path(cfg, name)
    try:
        text = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        n = 1
    else:
        if not _COUNTER_RE.fullmatch(text):
            raise CounterCorrupt(f"{path}: not a positive decimal; refusing to reuse ids")
        n = int(text)
    _effect("counter", atomic_write, path, str(n + 1).encode("ascii"),
            durable_root=cfg.state_dir)
    return f"{n:08d}"


def reserve_transport_id(cfg: RouterConfig, name: str) -> str:
    """The next transport id, allocated as its own step: the counter's
    successor is durable before this returns (`allocate_transport_req_id`),
    so a caller can record the id durably BEFORE it begins a record under
    it (`begin_reserved`)."""
    return allocate_transport_req_id(cfg, name)


def _next_transport_id(cfg: RouterConfig, name: str) -> int:
    try:
        text = counter_path(cfg, name).read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return 1
    if not _COUNTER_RE.fullmatch(text):
        raise CounterCorrupt(f"{counter_path(cfg, name)}: not a positive decimal")
    return int(text)


def begin(cfg: RouterConfig, name: str, req_id: str, **kw: Any) -> Dict[str, Any]:
    """`begin_reserved` under a transport id allocated now: put `req_id` in
    flight. See `begin_reserved` for the arguments."""
    return begin_reserved(cfg, name, req_id, reserve_transport_id(cfg, name), **kw)


def begin_reserved(
    cfg: RouterConfig, name: str, req_id: str, n: str,
    *, digest: Optional[str], request_doc: Dict[str, Any], recipients: List[str],
    policy_digest: Optional[str] = None, route: Optional[str] = None,
    from_address: Optional[str] = None, attachments: Optional[List[Any]] = None,
    bound_reply: Optional[Dict[str, Any]] = None,
    peer: Optional[Dict[str, Any]] = None,
    before_record: Optional[Callable[[], None]] = None,
    retransmit: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Put `req_id` in flight under the reserved transport id `n`: write the
    record. Returns the record. Under `begin`, a crash between the
    allocation and the record burns the id; the agent's request is still
    unsettled and unrecorded, so the next poll processes it afresh and
    allocates a new one. `policy_digest` and `route`
    are the sender's policy digest and the request's class when it was
    classified (`router/classify.py`), recorded BEFORE anything is handed
    over. `attachments` (ingest's verified attachments) are snapshotted
    BEFORE the record is written, and the record names them. `bound_reply`
    is a bound reply's pin, written once, here: every hand-over's `bound`
    comes from it and from nothing read later. `peer` is a signed kind's
    pin, likewise. `before_record` runs after the snapshot and before the
    record is written (the peer ledger's `issued` record, durable first).

    `n` is a transport id already reserved (`reserve_transport_id`): one
    at or above the counter was never allocated and is refused, and so is a
    record already in flight for `req_id` under a different id, so a
    re-drive after a crash can only ever resume the same request."""
    if not (isinstance(n, str) and re.fullmatch(r"[0-9]{8,18}", n)):
        raise ValueError(f"{n!r} is not a transport id")
    if int(n) >= _next_transport_id(cfg, name):
        raise ValueError(f"transport id {n} was never allocated in {name!r}")
    existing = read_record(cfg, name, req_id)
    if existing is not None and existing["transport_req_id"] != n:
        raise ValueError(f"{req_id!r} is already in flight under {existing['transport_req_id']}")
    snapshot = write_snapshot(cfg, name, req_id, attachments) if attachments else None
    record: Dict[str, Any] = {
        "digest": digest,
        "transport_req_id": n,
        "recipients": list(recipients),
        "request": request_doc,
        "written_ts": utc_ts(),
    }
    if policy_digest is not None:
        record["policy_digest"] = policy_digest
    if route is not None:
        record["route"] = route
    if from_address is not None:
        # Pinned here, never filled in later from the current config: a
        # retry must hand over exactly what the first attempt did.
        record["from_address"] = from_address
    if snapshot is not None:
        record["attachments"] = snapshot
    if bound_reply is not None:
        record["bound_reply"] = bound_reply
    if peer is not None:
        record["peer"] = peer
    if retransmit is not None:
        record["retransmit"] = dict(retransmit)
    check_record(record, runtime=name == config_mod.RUNTIME_NS)
    if before_record is not None:
        _effect("ledger", before_record)
    _write_record(cfg, name, req_id, record, "record")
    return record


def _write_record(cfg: RouterConfig, name: str, req_id: str, record: Dict[str, Any],
                  label: str) -> None:
    _effect(
        label, atomic_write, record_path(cfg, name, req_id),
        json.dumps(record, sort_keys=True).encode("utf-8"),
        durable_root=cfg.state_dir,
    )


class FrontierUndecidable(Exception):
    """This generation's in-flight directory cannot be read with certainty
    (an unreadable, damaged, non-regular or symlinked record, or a failed
    listing), so `settled_through` cannot be computed: nothing is handed
    over for this generation this poll."""


class HandoverDeferred(Exception):
    """A signed kind's record cannot be handed over THIS poll (delegation is
    not active): nothing is published and nothing is latched; the next poll
    tries again. The re-check settles such a record first, so this is a
    guard, never a route."""


class HandoverUnavailable(Exception):
    """A record that lacks what a handover needs (it predates `from_address`
    being pinned), never handed over; nothing is filled in from the current
    config."""


def settled_through(cfg: RouterConfig, name: str) -> int:
    """The settled frontier this generation hands to the transport: the
    LOWEST transport id still live, less one. Live means every `<id>.json`
    entry in this generation's in-flight directory, whatever its state,
    including a record settled but not yet deleted (a crash between the
    anchor and the unlink): a request counts as settled only once its
    private anchor is durable AND its record is gone. Fail closed: any entry
    that cannot be read as a record raises `FrontierUndecidable`, never
    skipped, since skipping a live id would declare it settled."""
    d = _inflight_dir(cfg, name)
    try:
        entries = sorted(os.listdir(d))
    except OSError as e:
        raise FrontierUndecidable(f"{d}: cannot be listed ({e.strerror})") from e
    live = []
    for entry in entries:
        if not entry.endswith(".json"):
            continue
        p = d / entry
        if p.is_symlink() or not p.is_file():
            raise FrontierUndecidable(f"{p}: not a regular file")
        try:
            record = read_record(cfg, name, entry[: -len(".json")])
        except (RecordDamaged, OSError) as e:
            raise FrontierUndecidable(f"{p}: {e}") from e
        if record is None:
            raise FrontierUndecidable(f"{p}: vanished while listed")
        live.append(int(record["transport_req_id"]))
    if not live:
        raise FrontierUndecidable(f"{d}: no live record, so no request to hand over")
    return min(live) - 1


def transport_request_bytes(cfg: RouterConfig, name: str, record: Dict[str, Any],
                            *, req_id: Optional[str] = None) -> bytes:
    """The HANDOVER DOCUMENT this router hands to the transport for one
    record (`router/hoplink.py`, API (3, 0)), built from the STAGED copy.
    The request's `req_id` is the transport id and its `agent_id` this
    instance's state key (its logical_id under a registry). `draft.to` and
    `draft.cc` go out unchanged, and ONLY when together they are exactly the
    evaluated set (`recipient_mismatch`); otherwise this raises
    `RecipientSetMismatch` and produces no bytes. Any threading key is
    dropped: mapping one to the downstream runtime's notice id is the
    re-placement step's. The envelope's `from_address` is the one pinned in
    the record at begin, never the current config's; a record without one
    raises `HandoverUnavailable`. `settled_through` is this generation's
    frontier, asserted below the record's own id. Request, envelope and
    attachments are identical on every retry of the same id; only
    `settled_through` may rise. The attachments are the SNAPSHOT's, re-proved
    against the record on every call (`read_snapshot`: `SnapshotDamaged`);
    `req_id` names the snapshot (the staged request's own, by default)."""
    mismatch = recipient_mismatch(record)
    if mismatch is not None:
        raise RecipientSetMismatch(mismatch)
    if not isinstance(record.get("from_address"), str):
        raise HandoverUnavailable("the record has no pinned from_address")
    doc = json.loads(json.dumps(record["request"]))
    doc["req_id"] = record["transport_req_id"]
    # The runtime tree's request is the router's own: its agent id is the
    # runtime identity marker's logical_id, never an instance's state key.
    doc["agent_id"] = ("runtime" if name == config_mod.RUNTIME_NS
                       else config_mod.state_key(cfg, name))
    doc.pop("in_reply_to", None)
    doc.get("draft", {}).pop("reply_to_message_id", None)
    frontier = settled_through(cfg, name)
    if not frontier < int(record["transport_req_id"]):
        raise FrontierUndecidable(
            f"settled_through {frontier} is not below {record['transport_req_id']}")
    if cfg.hop is not None:
        # The envelope's inputs come from the record and the PIN, never the
        # current config: the version this generation was pinned to.
        pin = hoplink.read_pin(cfg, name)
        if pin is None or type(pin.get("version_write")) is not int:
            raise HandoverUnavailable("this generation has no pinned version_write")
        version_write = pin["version_write"]
    else:
        # No `hop` configured: only a test's stand-in transport reaches here
        # (`config.load` requires `hop` beside a plugin, so a deployment
        # cannot), and the envelope's version is the first one.
        version_write = 1
    blobs: List[bytes] = []
    if record.get("attachments"):
        rid = req_id if req_id is not None else record["request"].get("req_id")
        blobs = read_snapshot(cfg, name, rid, record["attachments"])
    # A bound reply's `bound` is the RECORD's pin, never re-read from the
    # ledger: identical on every retry of the same id.
    bound = record["bound_reply"]["bound"] if "bound_reply" in record else None
    if "peer" in record:
        pin = record["peer"]
        _check_peer_header(cfg, pin)
        return hoplink.build_handover(
            doc, from_address=record["from_address"], version_write=version_write,
            attachments=[base64.b64encode(b).decode("ascii") for b in blobs],
            settled_through=frontier, kind=pin["kind"],
            peer={"statement_header": pin["statement_header"], "message_id": pin["message_id"],
                  "in_reply_to": pin["in_reply_to"], "references": list(pin["references"])})
    return hoplink.build_handover(
        doc, from_address=record["from_address"], version_write=version_write,
        attachments=[base64.b64encode(b).decode("ascii") for b in blobs],
        settled_through=frontier,
        kind=hoplink.BOUND_REPLY_KIND if bound is not None else hoplink.MAIL_KIND,
        bound=bound)


def _check_peer_header(cfg: RouterConfig, pin: Dict[str, Any]) -> None:
    """The pinned header re-parses, through the codec's check 1, to exactly
    the pinned statement and signature, or `HandoverUnavailable`: a record
    that would hand over anything else is never handed over."""
    from . import peerlane   # local: peerlane imports this module's neighbours
    delegation = peerlane.active(cfg)
    if delegation is None:
        raise HandoverDeferred("delegation is not active")
    field, want_kind = ((peerlane.CONTROL_FIELD, "control") if pin["kind"] == "control"
                        else (peerlane.STATEMENT_FIELD, "statement"))
    try:
        kind, k, statement, signature = delegation.codec.check1(
            [(field, pin["statement_header"])])
    except Exception as e:  # noqa: BLE001 -- classified exactly
        if peerlane.error_kind(delegation, e) == "CodecError":
            raise HandoverUnavailable(f"the pinned header fails check 1: {e.reason}") from None
        raise
    if (kind != want_kind or k != pin["key_id"]
            or statement != base64.b64decode(pin["statement"])
            or signature != base64.b64decode(pin["signature"])):
        raise HandoverUnavailable("the pinned header does not carry the pinned statement")



class RecipientSetMismatch(Exception):
    """The draft's `to`/`cc` are not exactly the evaluated recipients. Raised
    by `transport_request_bytes` so no transport request can carry them."""


def recipient_mismatch(record: Dict[str, Any]) -> Optional[str]:
    """None when the staged draft's `to` ∪ `cc` is EXACTLY the evaluated set
    (the domain compared case-insensitively, the local part exactly: the one
    address grammar, `router/classify.py`), else why not.

    The transport request carries the draft, and the downstream runtime
    sends to every address in it. So a policy that authorised only part of
    the draft would, without this check, still have the rest sent: the
    evaluated set was recorded and never applied. Narrowing the draft to the
    authorised part is not the answer either, because cold sends are
    all-or-nothing (`outbound`'s module docstring): a request whose
    recipients are not all authorised goes to nobody. So any difference, in
    either direction, fails closed."""
    draft = record.get("request", {}).get("draft")
    if not isinstance(draft, dict):
        return "the staged request has no draft"
    addrs = []
    for key in ("to", "cc"):
        value = draft.get(key) or []
        if not isinstance(value, list) or not all(isinstance(a, str) for a in value):
            return f"the staged draft's {key} is not a list of addresses"
        addrs.extend(value)
    evaluated = record.get("recipients")
    if not isinstance(evaluated, list) or not all(isinstance(a, str) for a in evaluated):
        return "the record's evaluated recipients are malformed"
    drafted, authorised = _canonical_set(addrs), _canonical_set(evaluated)
    if drafted is None or authorised is None or drafted != authorised:
        return "the draft's to/cc differ from the authorised recipients"
    return None


def _canonical_set(addrs: List[str]) -> Optional[set]:
    """The canonical forms (`classify.parse_address`: the domain folded, the
    local part exact), or None if any address is outside the grammar."""
    from . import classify as classify_mod   # local: keeps this module's imports minimal
    try:
        return {classify_mod.parse_address(a).canonical() for a in addrs}
    except classify_mod.Malformed:
        return None


def _anomaly(detail: str) -> Dict[str, Any]:
    return {"outcome": "queued_for_human", "reason_code": REASON_TRANSPORT_ANOMALY,
            "detail": detail, "recipients": []}


def verdict_from_result(raw: bytes, n: str, record: Dict[str, Any]) -> Dict[str, Any]:
    """Map the downstream Result to the agent's, as keyword arguments for
    `outbound._result_doc`. HOSTILE INPUT: anything that is not a Result for
    `n` with a known outcome is a `transport_anomaly`, never guessed at.

    The verdict passes through verbatim (Q2, 2026-10-07): the downstream
    outcome and reason_code, with `detail` prefixed `transport:`.
    `recipients` on an accepted result is the downstream list when it gives
    one, else the evaluated set. A downstream list naming anyone outside the
    evaluated set is still reported as given — the send happened — and logged
    as an ERROR, because recipient-set integrity was broken downstream."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _anomaly("transport result is not JSON")
    if not isinstance(doc, dict):
        return _anomaly("transport result is not an object")
    if doc.get("contract_version") != "2":
        return _anomaly("transport result has an unsupported contract_version")
    if doc.get("req_id") != n:
        return _anomaly("transport result names a different req_id")
    outcome = doc.get("outcome")
    if outcome not in _OUTCOMES:
        return _anomaly("transport result has no recognized outcome")

    reason = doc.get("reason_code")
    if reason is not None and not (isinstance(reason, str) and _REASON_RE.fullmatch(reason)):
        return _anomaly("transport result has a malformed reason_code")

    detail = doc.get("detail")
    if detail is not None and not isinstance(detail, str):
        return _anomaly("transport result has a non-string detail")
    detail = DETAIL_PREFIX + (detail or "")
    if len(detail) > _DETAIL_CAP:
        detail = detail[:_DETAIL_CAP]

    recipients = doc.get("recipients")
    if recipients is not None and not (
        isinstance(recipients, list) and all(isinstance(r, str) for r in recipients)
    ):
        return _anomaly("transport result has malformed recipients")

    message_id = doc.get("message_id")
    if not isinstance(message_id, str):
        message_id = None

    if outcome == "accepted":
        if recipients is None:
            recipients = list(record["recipients"])
        evaluated = {r.casefold() for r in record["recipients"]}
        extra = [r for r in recipients if r.casefold() not in evaluated]
        if extra:
            logger.error(
                "transport req %r: the downstream result reports %d recipient(s) "
                "outside the evaluated set — recipient-set integrity broken below "
                "the transport; reporting the send as given", n, len(extra),
            )

    verdict: Dict[str, Any] = {
        "outcome": outcome, "reason_code": reason, "detail": detail,
        "message_id": message_id,
    }
    if recipients is not None:
        verdict["recipients"] = recipients
    return verdict


def advance(
    cfg: RouterConfig, name: str, req_id: str, record: Dict[str, Any],
    port: TransportPort,
    *, settle: Callable[[Dict[str, Any], Optional[str]], Any],
    already_settled: bool,
    anchor: Optional[Path] = None,
    recheck: Optional[Callable[[Dict[str, Any]], Recheck]] = None,
    publish_blocked: bool = False,
    fenced_retired: bool = False,
    preserve: Optional[Callable[[Dict[str, Any]], None]] = None,
    found_handed: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> str:
    """One step for one record (module docstring's table). `settle(verdict,
    digest)` writes the agent's one result; `already_settled` says the
    private result exists already (a crash, or a failed barrier, after
    settling). `anchor` is that private result's path: before the record is
    removed on its strength, it is validated and made durable again
    (`_redurabilise`), because its existence alone does not prove it
    survives a power loss. Returns the state reached.

    `recheck` re-classifies the staged request (THE RE-CHECK, below). Every
    caller in production passes it; it is optional only so this state
    machine can be driven alone. `publish_blocked` is the failing-reload
    gate: nothing is written to the transport while it is set.

    THE RE-CHECK runs at EVERY publication attempt, the first and a
    handed-but-unwritten record's re-write alike, and on every poll while
    the request is pending. Not permitted at publication: settled from the
    re-check's verdict, nothing handed over. Permitted with a changed
    digest, or with no recorded route (a record from before routes were
    recorded): the record's digest and route are updated durably FIRST, so
    what is published with the request is current. Not permitted while
    pending: the request was handed over and cannot be withdrawn through any
    transport this router accepts, so the record is marked
    `revocation_unenforceable` and an ERROR is logged every poll; a result,
    if one arrives, still settles it as usual, because the send may have
    happened.

    `fenced_retired`: the record's generation is fenced and its hop tree is
    retired. A record never handed over is then settled `rejected`/
    `no_route` and never handed over: there is never a FIRST hand-over into
    a retired tree. A handed-over record carries on as before (a no-op
    retry, or completing a partial one).

    PROBES. Under the hop, any exception from `has_result`, `has_pending`,
    `has_archived` or `read_result` is a RETRY that never settles: the
    record, its transport id and its HANDED marker are kept, no Result is
    written, and status shows `hop_probe_failed:<reason or class>`. A
    result that reads fine but fails validation is still a verdict on
    readable bytes (`transport_anomaly`)."""
    try:
        state = _advance(cfg, name, req_id, record, port, settle=settle,
                         already_settled=already_settled, anchor=anchor, recheck=recheck,
                         publish_blocked=publish_blocked, fenced_retired=fenced_retired,
                         preserve=preserve, found_handed=found_handed)
        if _is_hop(cfg) and "transport_req_id" in record:
            hoplink.clear_retry(cfg, name, n=record["transport_req_id"], prefix=PROBE_FAILED)
        return state
    except ProbeFailed as failed:
        e = failed.raised
        if not _is_hop(cfg) or name == config_mod.RUNTIME_NS:
            # The runtime control namespace's caller holds the whole pass on
            # a plugin anomaly and names it (`peercontrol`), production shape
            # or not: never a silent per-record retry there.
            raise e from None
        status = probe_status(e)
        age = hoplink.note_retry(cfg, name, status, f"{type(e).__name__}: {e}",
                                 record["transport_req_id"])
        quiet = age < STALE_AFTER_S
        (logger.warning if quiet else logger.error)(
            "instance %r req %r: a transport probe failed (%s, for %ds): %s; nothing is "
            "settled, retried next poll", name, req_id, status, age, e)
        return BLOCKED


class ProbeFailed(Exception):
    """A transport probe raised (`advance`, PROBES); `raised` is what."""

    def __init__(self, raised: BaseException):
        super().__init__(repr(raised))
        self.raised = raised


PROBE_FAILED = "hop_probe_failed"


def probe_status(exc: BaseException) -> str:
    """`hop_probe_failed:<reason or class>`."""
    why = getattr(exc, "reason", None)
    return f"{PROBE_FAILED}:{why if type(why) is str and why else type(exc).__name__}"


class _Probed:
    """The port, with each probe's exception wrapped in `ProbeFailed`."""

    def __init__(self, port: TransportPort):
        self._port = port

    def _call(self, method: str, n: str) -> Any:
        try:
            return getattr(self._port, method)(n)
        except Exception as e:  # noqa: BLE001 -- a probe never settles (advance, PROBES)
            raise ProbeFailed(e) from e

    def has_result(self, n: str) -> bool:
        return self._call("has_result", n)

    def has_pending(self, n: str) -> bool:
        return self._call("has_pending", n)

    def has_archived(self, n: str) -> bool:
        return self._call("has_archived", n)

    def read_result(self, n: str) -> bytes:
        return self._call("read_result", n)


def _advance(
    cfg: RouterConfig, name: str, req_id: str, record: Dict[str, Any],
    port: TransportPort,
    *, settle: Callable[[Dict[str, Any], Optional[str]], Any],
    already_settled: bool,
    anchor: Optional[Path],
    recheck: Optional[Callable[[Dict[str, Any]], Recheck]],
    publish_blocked: bool,
    fenced_retired: bool,
    preserve: Optional[Callable[[Dict[str, Any]], None]] = None,
    found_handed: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> str:
    writer = port
    port = _Probed(port)
    path = record_path(cfg, name, req_id)
    handed = handed_path(cfg, name, req_id)
    if already_settled:
        if anchor is not None:
            _effect("anchor", _redurabilise, anchor)
        _effect("unlink", _cleanup, path, handed)
        return CLEANED

    n = record["transport_req_id"]

    if not _was_handed(handed, n):
        # Nothing is recorded as handed over under `n` for THIS request, yet
        # the transport shows `n`. Whose request it carries cannot be told
        # (module docstring, THE HANDED MARKER): settling from it could be
        # another request's result, and handing over again could send this
        # one twice. Fail closed.
        if port.has_result(n) or port.has_pending(n) or port.has_archived(n):
            logger.error(
                "instance %r req %r: transport req_id %r already exists on the "
                "transport but is not recorded as handed over for this request "
                "(the counter went backwards, or state was restored); settling "
                "as an anomaly, not handing over again", name, req_id, n,
            )
            _effect("settle", settle, _anomaly(
                "transport id already in use; cannot tell whose request it carries"),
                record.get("digest"))
            _effect("unlink", _cleanup, path, handed)
            return SETTLED
        mismatch = recipient_mismatch(record)
        if mismatch is not None:
            _effect("settle", settle, _anomaly(mismatch + "; nothing was sent"),
                    record.get("digest"))
            _effect("unlink", _cleanup, path, handed)
            return SETTLED
        if fenced_retired:
            _effect("settle", settle, {
                "outcome": "rejected", "reason_code": REASON_NO_ROUTE,
                "detail": DETAIL_FENCED_UNHANDED, "recipients": []}, record.get("digest"))
            _effect("unlink", _cleanup, path, handed)
            return SETTLED

    if found_handed is not None and _was_handed(handed, n):
        # A pass that FINDS the handed marker (never the pass that writes it):
        # the hand-over time it records is never earlier than the true one.
        try:
            found_handed(record)
        except Exception:  # noqa: BLE001 -- a bookkeeping note, never a verdict
            logger.exception("instance %r req %r: noting the hand-over failed; retried next "
                             "poll", name, req_id)

    def from_result() -> str:
        verdict = verdict_from_result(port.read_result(n), n, record)
        _effect("settle", settle, verdict, record.get("digest"))
        _effect("unlink", _cleanup, path, handed)
        return SETTLED

    if port.has_result(n):
        return from_result()
    if port.has_pending(n):
        if recheck is not None:
            _check_revocation(cfg, name, req_id, record, writer, recheck,
                              enact=not publish_blocked)
        return PENDING
    if port.has_archived(n):
        if port.has_result(n):
            return from_result()
        _effect("settle", settle,
                _anomaly("the transport request was archived without a result"),
                record.get("digest"))
        _effect("unlink", _cleanup, path, handed)
        return SETTLED
    if port.has_result(n):
        return from_result()
    if publish_blocked:
        logger.error(
            "instance %r req %r: NOT published: the config reload is failing, and "
            "the external leg fails closed until a reload succeeds", name, req_id)
        return BLOCKED
    if recheck is not None:
        rc = recheck(record)
        if not rc.permitted:
            logger.warning("instance %r req %r: not published: %s", name, req_id, rc.why)
            _effect("settle", settle, rc.verdict, record.get("digest"))
            _effect("unlink", _cleanup, path, handed)
            return SETTLED
        if _repin(name, req_id, record, rc):
            _write_record(cfg, name, req_id, record, "repin")
    held = hoplink.write_hold(cfg, name)
    if held is not None:
        logger.error(
            "instance %r req %r: NOT handed over: this generation's hand-overs are held "
            "(%s, latched by transport id %s); `router generation new` moves the instance "
            "on, and this record is left for disposal", name, req_id, held.get("reason"),
            held.get("transport_req_id"))
        return BLOCKED
    try:
        data = transport_request_bytes(cfg, name, record, req_id=req_id)
    except HandoverDeferred as e:
        logger.error("instance %r req %r: NOT handed over this poll: %s; retried next poll",
                     name, req_id, e)
        return BLOCKED
    except SnapshotDamaged as e:
        # This router's own state damage, decided BEFORE the handed marker
        # is written for this attempt. Handed over before: the request may
        # be pending downstream, so it is never settled from here and never
        # handed over different bytes: this generation's hand-overs are held.
        # Never handed over: nothing reached the hop, so it is settled.
        if _was_handed(handed, n):
            hoplink.set_write_hold(cfg, name, hoplink.HOLD_SNAPSHOT_DAMAGED,
                                   f"SnapshotDamaged: {e}", n)
            logger.error("instance %r req %r: hand-overs for this generation are HELD (%s): %s",
                         name, req_id, hoplink.HOLD_SNAPSHOT_DAMAGED, e)
            return BLOCKED
        logger.error("instance %r req %r: %s (%s); settled as an anomaly", name, req_id,
                     DETAIL_SNAPSHOT_DAMAGED, e)
        _effect("settle", settle, _anomaly(DETAIL_SNAPSHOT_DAMAGED), record.get("digest"))
        _effect("unlink", _cleanup, path, handed)
        return SETTLED
    except (FrontierUndecidable, HandoverUnavailable) as e:
        # Decided BEFORE the handed marker: nothing is published, the record
        # and its transport id stay as they are, and the hold is this
        # generation's until `router generation new` (the closed table's
        # deterministic rows: an undecidable frontier, a record that cannot
        # make a valid handover).
        hold = (hoplink.LATCHED_WRITE_REASONS["below_frontier"]
                if isinstance(e, FrontierUndecidable)
                else hoplink.LATCHED_WRITE_REASONS["handover_invalid"])
        hoplink.set_write_hold(cfg, name, hold, f"{type(e).__name__}: {e}", n)
        logger.error("instance %r req %r: hand-overs for this generation are HELD (%s): %s",
                     name, req_id, hold, e)
        return BLOCKED
    if preserve is not None:
        # The original is preserved, committed, BEFORE the handed marker: a
        # copy exists before any byte can reach the transport. A failure
        # holds the record unhanded, retried next poll, visibly.
        try:
            _effect("preserve", preserve, record)
        except Exception as e:  # noqa: BLE001 -- held, never handed without its copy
            if _is_hop(cfg):
                hoplink.note_retry(cfg, name, PRESERVATION_FAILED, f"{type(e).__name__}: {e}", n)
            logger.error("instance %r req %r: NOT handed over: the original could not be "
                         "preserved (%s: %s); retried next poll", name, req_id,
                         type(e).__name__, e)
            return BLOCKED
    _effect("handed", atomic_write, handed, n.encode("ascii"),
            durable_root=cfg.state_dir)
    try:
        _effect("transport", writer.write_request, n, data)
    except Exception as e:  # noqa: BLE001 -- the closed table decides
        # A settling reason FIRST, before the latched and retried rows: the
        # plugin raised it with no part of the request in the tree, so it is
        # a definite non-delivery, settled once and cleaned up (a crash
        # between the two repeats the refusal and settles again, idempotently).
        # Only the runtime control namespace's sender gives the guarantee the
        # settlement rests on; from an agent tree the reason stays a hold.
        settles = hoplink.settle_for_write(e) if name == config_mod.RUNTIME_NS else None
        if settles is not None:
            outcome, reason = settles
            logger.error("instance %r req %r: NOT handed over, settled %s/%s: %s",
                         name, req_id, outcome, reason, e)
            _effect("settle", settle, {"outcome": outcome, "reason_code": reason,
                                       "detail": f"{DETAIL_PREFIX}{e}"[:_DETAIL_CAP],
                                       "recipients": []}, record.get("digest"))
            _effect("unlink", _cleanup, path, handed)
            return SETTLED
        latched = hoplink.latch_for_write(e)
        if latched is not None:
            hoplink.set_write_hold(cfg, name, latched, str(e), n)
            logger.error("instance %r req %r: hand-overs for this generation are HELD (%s): %s",
                         name, req_id, latched, e)
            return BLOCKED
        # A retry: the same record and the same transport id, next poll.
        status = hoplink.retry_status(e)
        if status == "hop_object_closed":
            hoplink.evict_sender(cfg, name)
        if _is_hop(cfg):
            age = hoplink.note_retry(cfg, name, status, f"{type(e).__name__}: {e}", n)
        else:
            age = 0.0
        if status == hoplink.RETRY_UNEXPECTED:
            raise   # logged with its traceback by the caller
        quiet = status in hoplink.QUIET_RETRIES and age < STALE_AFTER_S
        (logger.warning if quiet else logger.error)(
            "instance %r req %r: NOT handed over this poll (%s, for %ds): %s; retried "
            "next poll with transport id %s", name, req_id, status, age, e, n)
        return BLOCKED
    if _is_hop(cfg):
        hoplink.clear_retry(cfg, name)
    return WRITTEN


def _is_hop(cfg: RouterConfig) -> bool:
    """A generation-keyed config with a hop: where retries are tracked."""
    return getattr(cfg, "hop", None) is not None and getattr(cfg, "registry_dir", None) is not None


def _check_revocation(
    cfg: RouterConfig, name: str, req_id: str, record: Dict[str, Any], port: Any,
    recheck: Callable[[Dict[str, Any]], Recheck], *, enact: bool,
) -> None:
    """The pending row's re-check (`advance`, THE RE-CHECK). Fail-visible:
    a marked record is logged as an ERROR on every poll it stays pending."""
    capable = withdraw_capable(port)
    how = ("the transport offers withdraw_request, approved at (3,0); not yet "
           "called by the in-flight table" if capable
           else "the transport has no way to withdraw it")
    since = record.get("revocation_unenforceable")
    if since is not None:
        logger.error(
            "instance %r req %r: REVOKED since %s but still pending: %s; it may "
            "still be sent", name, req_id, since, how)
        return
    rc = recheck(record)
    if rc.permitted:
        if record.get("route") is None and _repin(name, req_id, record, rc):
            _write_record(cfg, name, req_id, record, "repin")
        return
    if not enact:
        logger.error(
            "instance %r req %r: no longer permitted (%s), but the config reload is "
            "failing, so nothing is enacted", name, req_id, rc.why)
        return
    record["revocation_unenforceable"] = utc_ts()
    _write_record(cfg, name, req_id, record, "revoked")
    logger.error(
        "instance %r req %r: REVOKED: %s; it was already handed over and %s, so it "
        "may still be sent", name, req_id, rc.why, how)


def _repin(name: str, req_id: str, record: Dict[str, Any], rc: Recheck) -> bool:
    """Bring a permitted record's digest and route up to date in memory;
    True when the caller must write it. The route is only ever FILLED IN,
    for a record written before routes were recorded: a recorded route that
    differs is a refusal (`outbound._recheck`), never a re-pin. Without the
    backfill such a record would publish with no route, and a later change
    of route while it is pending could not be detected."""
    changed = False
    if rc.policy_digest is not None and rc.policy_digest != record.get("policy_digest"):
        logger.warning(
            "instance %r req %r: the sender's policy digest changed since the request "
            "was staged (%s -> %s); still permitted, publishing under the new digest",
            name, req_id, record.get("policy_digest"), rc.policy_digest)
        record["policy_digest"] = rc.policy_digest
        changed = True
    if record.get("route") is None and rc.route is not None:
        record["route"] = rc.route
        changed = True
    return changed


def revoked(cfg: RouterConfig, name: str) -> List[Dict[str, Any]]:
    """Every record of `name` marked `revocation_unenforceable`, with its
    req_id and the router-written ts it was marked at, for `status`."""
    out = []
    for req_id in list_records(cfg, name):
        try:
            rec = read_record(cfg, name, req_id)
        except (OSError, ValueError):
            continue
        if rec is not None and rec.get("revocation_unenforceable") is not None:
            out.append({"req_id": req_id, "since": rec["revocation_unenforceable"]})
    return out


class AnchorInvalid(Exception):
    """The private result a record would be cleaned up on is not a frozen
    `{"digest", "result"}` envelope. Raised, and the record is kept: it is
    never rewritten here, and the request is never sent again."""


def _redurabilise(anchor: Path) -> None:
    """Validate the existing private result and fsync it, then its
    directory. A settle whose directory fsync failed AFTER the rename leaves
    a result that exists and may not survive a power loss; removing the
    record on the strength of its existence alone would lose both. Any
    failure raises, so the record stays for the next poll."""
    fd = os.open(str(anchor), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        try:
            doc = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise AnchorInvalid(f"{anchor}: not JSON") from e
        if not (isinstance(doc, dict) and "digest" in doc
                and isinstance(doc.get("result"), dict)):
            raise AnchorInvalid(f"{anchor}: not a {{digest, result}} envelope")
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(anchor.parent)


def _was_handed(handed: Path, n: str) -> bool:
    """Whether the HANDED marker exists and names `n` (module docstring)."""
    try:
        return handed.read_bytes() == n.encode("ascii")
    except FileNotFoundError:
        return False


def _cleanup(record: Path, handed: Path) -> None:
    """Remove a settled record, then its marker, then its attachment
    snapshot, durably. The record goes FIRST and is made durably gone (its
    directory fsynced) BEFORE anything of the snapshot is touched: across a
    power loss a durable record then always has its snapshot, and what can
    be left is an orphan snapshot (swept) or an orphan marker (which never
    vouches for another record: THE HANDED MARKER)."""
    try:
        record.unlink()
    except FileNotFoundError:
        pass
    fsync_dir(record.parent)
    try:
        handed.unlink()
    except FileNotFoundError:
        pass
    _remove_snapshot_at(record.parent.parent, record.name[: -len(".json")])
    fsync_dir(record.parent)


def summarize(
    cfg: RouterConfig, name: str, *, now: Optional[str] = None,
) -> Tuple[Dict[str, int], List[str]]:
    """`inflight`, `inflight_oldest_age_s` and `inflight_stale` for the drain
    summary, plus the stale req_ids. A record with an unreadable timestamp
    counts as stale: unknown age is not young."""
    now_dt = parse_utc_ts(now or utc_ts())
    count = oldest = 0
    stale: List[str] = []
    for req_id in list_records(cfg, name):
        count += 1
        try:
            rec = read_record(cfg, name, req_id)
        except (OSError, ValueError):
            rec = None
        written = parse_utc_ts(rec.get("written_ts")) if isinstance(rec, dict) else None
        if written is None or now_dt is None:
            stale.append(req_id)
            continue
        age = max(0, int((now_dt - written).total_seconds()))
        oldest = max(oldest, age)
        if age >= STALE_AFTER_S:
            stale.append(req_id)
    return (
        {"inflight": count, "inflight_oldest_age_s": oldest, "inflight_stale": len(stale)},
        stale,
    )


_TRANSPORT_ID_RE = re.compile(r"[0-9]{8,18}\Z")


def settlement_record(state_dir: Path, logical_id: str, gen: str,
                      n: str) -> Optional[Dict[str, Any]]:
    """Where transport request `n` of generation `gen` stands, read-only, for
    the hop conformance fixture (and an operator): `{"state": "settled",
    "req_id", "outcome"}` from its private anchor, `{"state": "inflight",
    "req_id", "outcome": None}` from its in-flight record, or None when
    neither names `n` (a burned id, or an id never allocated). An anchor
    wins over a lingering record (the window between settling and deleting
    the record). A damaged record or anchor RAISES; it is never read as
    absent. `n` is the 8-18 digit string throughout."""
    if not (isinstance(n, str) and _TRANSPORT_ID_RE.fullmatch(n)):
        raise ValueError(f"{n!r} is not a transport id")
    gdir = Path(state_dir) / logical_id / f"gen-{gen}"
    results = gdir / "results"
    if results.is_dir():
        for p in sorted(results.iterdir()):
            if not p.name.endswith(".json"):
                continue
            doc = json.loads(p.read_bytes().decode("utf-8"))
            if not (isinstance(doc, dict) and isinstance(doc.get("result"), dict)):
                raise RecordDamaged(f"{p}: not an anchor envelope")
            if doc.get("transport_req_id") == n:
                return {"state": "settled", "req_id": p.name[: -len(".json")],
                        "outcome": doc["result"].get("outcome")}
    d = gdir / INFLIGHT_DIR
    if d.is_dir():
        for p in sorted(d.iterdir()):
            if not p.name.endswith(".json"):
                continue
            rec = check_record(json.loads(p.read_bytes().decode("utf-8")))
            if rec["transport_req_id"] == n:
                return {"state": "inflight", "req_id": p.name[: -len(".json")],
                        "outcome": None}
    return None


def transaction_facts(state_dir: Path, logical_id: str, gen: str,
                      n: str) -> Optional[Dict[str, Any]]:
    """What THIS router recorded of its own outbound transaction `n` in
    generation `gen`, for matching a correlation the downstream runtime
    makes back to it (a failure report, a reply): `{"req_id", "recipients",
    "message_id", "source"}`, or None. The recipients are what was actually
    SENT TO: the anchor Result's `recipients` when an anchor exists (source
    "anchor"); otherwise the evaluated set of an in-flight record that WAS
    HANDED OVER (its marker names `n`; source "record"). A record never
    handed over names nothing that was sent, so it matches nothing.
    `message_id` is the anchor Result's, when it has one. A damaged record
    or anchor RAISES (`RecordDamaged`, or the JSON error); it is never read
    as absent."""
    if not (isinstance(n, str) and _TRANSPORT_ID_RE.fullmatch(n)):
        raise ValueError(f"{n!r} is not a transport id")
    gdir = Path(state_dir) / logical_id / f"gen-{gen}"
    results = gdir / "results"
    if results.is_dir():
        for p in sorted(results.iterdir()):
            if not p.name.endswith(".json"):
                continue
            doc = json.loads(p.read_bytes().decode("utf-8"))
            if not (isinstance(doc, dict) and isinstance(doc.get("result"), dict)):
                raise RecordDamaged(f"{p}: not an anchor envelope")
            if doc.get("transport_req_id") != n:
                continue
            result = doc["result"]
            recipients = result.get("recipients")
            mid = result.get("message_id")
            return {"req_id": p.name[: -len(".json")], "source": "anchor",
                    "recipients": [r for r in recipients if isinstance(r, str)]
                    if isinstance(recipients, list) else [],
                    "message_id": mid if isinstance(mid, str) and mid else None}
    d = gdir / INFLIGHT_DIR
    if d.is_dir():
        for p in sorted(d.iterdir()):
            if not p.name.endswith(".json"):
                continue
            rec = check_record(json.loads(p.read_bytes().decode("utf-8")))
            if rec["transport_req_id"] != n:
                continue
            if not _was_handed(p.with_suffix(HANDED_SUFFIX), n):
                return None
            return {"req_id": p.name[: -len(".json")], "source": "record",
                    "recipients": list(rec["recipients"]), "message_id": None}
    return None
