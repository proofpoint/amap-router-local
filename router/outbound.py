"""router/outbound.py — drain one instance's outbound/ dropbox.

`drain_instance(cfg, name)` mirrors `gate/outbound.py:drain_outbound`'s
shape (list -> filename-hygiene filter -> idempotency check -> validate ->
policy -> deliver -> result -> archive), transplanted onto the router's own
config/binding/deliver primitives:

  1. List `<ns>/outbound/` entries; accept ONLY filenames matching
     `req-[A-Za-z0-9_-]{1,64}\\.json`, whole name (`REQ_NAME_RE`, fullmatch; from
     `gate/outbound.py:85`) — anything else is logged (`logger.warning`)
     and never opened. A symlinked entry is likewise never opened (`list_
     outbound` excludes it and reports the count) — it could resolve
     outside the namespace, and the filename passing hygiene says nothing
     about what it points at. The outbox is untrusted input to the host
     (SCOPE.md): a hostile or symlinked filename never even reaches
     `read_capped`.
  2. `req_id` is derived from the FILENAME, never the body. Idempotency
     anchor = router-private `state_dir/<name>/results/<req_id>.json` (the
     namespace copy under `<ns>/outbound/results/` is agent-writable and
     can never anchor anything — `gate/outbound.py` D4, trust fixed). The
     private anchor also carries a sha256 digest of the request bytes it
     was computed from: an agent that deletes its own `outbound/{results,
     processed}` and resubmits a DIFFERENT request under a REUSED req_id
     must never have that new request silently answered with the OLD
     verdict (a false `accepted`) — see step 2a.
     2a. Digest matches (or the original digest is unknown — a rare corner
         case, see below) -> resume: re-copy the private result into the
         namespace, archive the request, done — `process_one` (here:
         validate+deliver) never runs twice for the same id.
     2b. Digest differs -> the id has been reused for different content.
         Never replay the stale verdict. Issue a FRESH `rejected` /
         `req_id_reused` result for THIS submission and archive it,
         without touching the original anchor (so a later resubmission of
         the ORIGINAL bytes under this id still correctly resumes to the
         original verdict).
  3. Else: capped read -> `validate.py`. Cross-checks the schema can't
     express: body `req_id` != filename id -> `req_id_mismatch`; `agent_id`
     present and != instance name -> `agent_id_mismatch` (AMAP §2:
     namespace is attribution; the field is a cross-check only).
  4. Attachment ingest (`attachments.ingest_attachments`, AMAP v2.3.0 §3):
     verified BEFORE recipient policy — integrity before policy, §4's "two
     paths, never conflated." A malformed/mismatched attachment (bad sha/
     size, missing/extra sidecar ordinal, symlink/hardlink/non-regular
     entry, dir-shape violation) fails the WHOLE request `rejected`/
     `attachment_mismatch` — never a partial send. A policy cap on an
     otherwise-honest declaration (`attachment_max_count`/
     `attachment_max_bytes`/`attachment_max_total_bytes`) is
     `queued_for_human`/`attachment_count_exceeded` or
     `attachment_too_large`, with no sidecar ever opened for a count/size
     breach — see `router/attachments.py`'s module docstring for the full
     verification order and the TOCTOU discipline (pinned `dir_fd`s,
     mirroring `reset.py`'s removal engine) that makes reading an
     agent-owned sidecar dir safe. Reply -> `binding.resolve_binding`.
     Cold -> `binding.check_cold`, mutual, `to ∪ cc`, all-or-nothing.
     4a. THE PEER LANE (AMAP 3.1.0 peer-origin profile) is recipient policy
         on this same plain submit-request — no new request shape. Cold:
         `default_cold_policy` finds a declared edge sender -> recipient
         (`binding.check_peer_edge`) and returns a `PeerRoute`; exactly one
         recipient and no `cc`, or `rejected`/`peer_single_recipient` — a
         mixed-lane submit is refused whole. No edge -> the mail-lane
         decision below, unchanged (the loader guarantees an ordered pair
         is never both, so nothing the sender wrote picks the lane).
         Reply: a reply key that resolves to a ledger record with `tree:
         "peer"` travels the REVERSE edge as a peer notice with
         `in_reply_to` — always when an edge exists in that direction, else
         within `peer_reply_window_seconds` of the record's `ts`, else
         `rejected`/`peer_reply_window_expired`. Either way the result is
         `accepted`/`peer_routed` with `message_id` = the minted peer id.
         An unmatched reply key stays `rejected`/`unresolved_reply` on both
         lanes — never stripped and forwarded as a fresh task — which is
         what makes "a peer notice carries `in_reply_to` iff this router
         resolved it from its own ledger" an invariant the receiving
         daemon may rely on.
  5. One governing outcome per request, written EXACTLY ONCE. Delivery to
     multiple recipients is attempted per-recipient and never aborts the
     request: one failing recipient must not leave the request un-answered
     and un-archived, because the next poll would then re-deliver to the
     healthy ones without bound (a hostile recipient owns its own namespace
     under posture A and can arrange exactly that). Outcomes:
       - resolves (reply) / all-mutual (cold), every delivery succeeds ->
         `accepted` + `reason_code` (`recipient_bound` / `allowlisted`) +
         `recipients` + `ts`.
       - some deliveries succeed, some raise -> `accepted` /
         `partial_delivery`. `recipients` lists ONLY those actually
         delivered to (AMAP §4 makes it the authoritative record); the
         failures are named in `detail`. Not retried — a retry would
         re-deliver to the ones that already have it.
       - every delivery raises -> `queued_for_human` / `delivery_failed`.
         An infrastructure failure, not a policy refusal, so it is held for
         an operator rather than silently dropped.
       - every address is a KNOWN instance but at least one fails
         mutuality -> `queued_for_human` / `recipient_not_allowlisted`,
         the raw request copied to router-private `state_dir/<name>/held/`
         (operator-visible; no release mechanism in L1).
       - anything else (malformed, unresolved reply, an address that
         isn't a known instance, self-send) -> `rejected` with the
         specific `reason_code`. A policy miss is never a silent drop —
         every drained request ends with a result file.
  6. Write the private result -> copy atomically into
     `<ns>/outbound/results/<req_id>.json` -> rename the request into
     `<ns>/outbound/processed/<filename>` (v3.0.0: both writes are now
     `dir_fd`-relative off descriptors pinned `O_NOFOLLOW` from `root`,
     never a path-based `os.replace` — see `_publish_result_and_archive`'s
     docstring). result-before-archive: crash
     between the two just makes the next drain take the resume path in
     step 2 and re-copy/re-archive). `processed/` is a COURTESY archive
     only — the router never reads it back (the idempotency anchor is
     the private `state_dir` envelope from step 2, not this copy). AMAP
     v2.2.0 permits a connector to delete `outbound/processed/` at will
     (§2 "Deletion rights") and correspondingly forbids a runtime from
     relying on its contents as durable state; this router already didn't.

Isolation: a single hostile/malformed/malshaped request under one instance
must never take down the whole router process — every per-request body
(step 2 onward, both the resume path and `_drain_one`) runs inside a
`try/except Exception` in `drain_instance`; a failure is logged, counted as
`outbound_errored`, and the loop moves on to the next filename. Likewise
`service.run_once` isolates each instance's `drain_instance` call from every
other instance's.
"""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import inspect
import json
import logging
import os
import re
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple, Union

from datetime import timedelta

from . import aliases as aliases_mod
from . import attachments as attachments_mod, binding, firstsight
from . import classify as classify_mod
from . import generations as generations_mod
from . import audit as audit_mod
from . import deliver as deliver_mod, inflight as inflight_mod, validate as validate_mod
from . import hoplink
from .config import (RouterConfig, address_for, gen_state_dir, instance_for, state_key,
                     target_hold, target_known_id, target_logical_id)
from .util import (
    DEFAULT_READ_CAP,
    NamespaceEscapeError,
    ReadTooLargeError,
    atomic_write,
    fsync_dir,
    mint_notice_id,
    parse_utc_ts,
    read_capped,
    utc_ts,
)

logger = logging.getLogger("amap_router_local.outbound")

#: Applied with `fullmatch` and anchored with `\Z`: `$` also matches before a
#: trailing newline, so `req-1.json\n` passed the gate it was copied from.
REQ_NAME_RE = re.compile(r"req-[A-Za-z0-9_-]{1,64}\.json\Z")

# Reason-code vocabulary this router emits (README.md documents these for
# operators; AMAP §4 treats the vocabulary as extensible, not enum-locked).
REASON_RECIPIENT_BOUND = "recipient_bound"
REASON_ALLOWLISTED = "allowlisted"
REASON_RECIPIENT_NOT_ALLOWLISTED = "recipient_not_allowlisted"
REASON_RECIPIENT_UNKNOWN = "recipient_unknown"
REASON_UNRESOLVED_REPLY = "unresolved_reply"
REASON_SELF_SEND = "self_send"
REASON_REQ_ID_MISMATCH = "req_id_mismatch"
REASON_AGENT_ID_MISMATCH = "agent_id_mismatch"
REASON_ATTACHMENT_MISMATCH = attachments_mod.REASON_ATTACHMENT_MISMATCH
REASON_ATTACHMENT_TOO_LARGE = attachments_mod.REASON_ATTACHMENT_TOO_LARGE
REASON_ATTACHMENT_COUNT_EXCEEDED = attachments_mod.REASON_ATTACHMENT_COUNT_EXCEEDED
REASON_REQ_ID_REUSED = "req_id_reused"
REASON_PARTIAL_DELIVERY = "partial_delivery"
REASON_DELIVERY_FAILED = "delivery_failed"
REASON_MALFORMED = validate_mod.REASON_MALFORMED
REASON_UNSUPPORTED_VERSION = validate_mod.REASON_UNSUPPORTED_VERSION
# The mechanism was renamed (there is no approval step any more — see
# `router/firstsight.py`); this STRING was not. It is on the wire: it is what
# the agent reads back in `outbox/results/<req_id>.json`, and a connector or a
# human runbook may key on it. Renaming it would buy accuracy in one repo and
# spend it on every consumer, so the name stays and this comment carries the
# correction. "pre_approval" here means "already staged at first sight".
REASON_QUARANTINED = "quarantined_pre_approval"
# Peer lane (module docstring, step 4a). `peer_routed` is the one accepted
# reason on that lane, for a fresh task and a reply alike: the sender learns
# which TREE its message landed in from the reason code (`peer_routed` vs
# `allowlisted`/`recipient_bound`), and that is the distinction that matters.
REASON_PEER_ROUTED = "peer_routed"
REASON_PEER_SINGLE_RECIPIENT = "peer_single_recipient"
REASON_PEER_REPLY_WINDOW_EXPIRED = "peer_reply_window_expired"
REASON_TRANSPORT_ANOMALY = inflight_mod.REASON_TRANSPORT_ANOMALY


def _outbox_dir(cfg: RouterConfig, name: str) -> Path:
    return cfg.instances[name].outbox_root


def _private_result_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return gen_state_dir(cfg, name) / "results" / f"{req_id}.json"


def _held_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return gen_state_dir(cfg, name) / "held" / f"req-{req_id}.json"


class UnreadableRequest(OSError):
    """`_read_request_pinned` refused the entry for what it IS: not a
    regular file, or a hard link. An `OSError` so every existing `except
    OSError` keeps catching it; its own type so a caller can tell this
    deterministic refusal from a fault (`_unreadable_now`)."""


def _read_request_pinned(cfg: RouterConfig, name: str, filename: str,
                          cap: int = DEFAULT_READ_CAP) -> bytes:
    """Contract v3.0.0 §2's read-side rule, applied to `outbound/<filename>`
    — the one agent-authored file this router reads whose bytes decide
    what gets delivered. `util.read_capped` (still used by every OTHER
    read in this module — private, router-owned files) does a pre-open
    `path.stat()` then `path.read_bytes()`: a second, independent path
    resolution with no `O_NOFOLLOW`, no `fstat`, and no link-count check.
    A hard link planted at `outbox/req-<id>.json` pointing at a file
    OUTSIDE the instance root passes `list_outbound`'s `is_symlink()`
    filter (a hard link is not a symlink) and used to be read and
    delivered whole — the out-of-namespace file's body reaching the peer.

    Mirrors `attachments._verify_one`'s identical discipline for the
    sidecar files this same request may declare (`reset._open_child`'s
    `O_NOFOLLOW` pin, reused via `attachments._descend_pinned`): a pinned
    `dir_fd` chain from `root` (the containment ANCHOR — see
    `InstanceConfig.root`'s docstring) down to `outbox_root`, then
    `filename` opened `dir_fd`-relative with `O_NOFOLLOW|O_NONBLOCK`
    (never blocks on a planted FIFO), `fstat`-verified (never a pre-open
    `stat`) regular file with `st_nlink == 1`, then a bounded read off
    that descriptor.

    Raises `ReadTooLargeError` — the SAME type `read_capped` raises — when
    the file exceeds `cap`, so every existing caller's `except
    ReadTooLargeError` clause keeps working unchanged. Not a regular file,
    or an `nlink > 1` hard link, raises `UnreadableRequest` (an `OSError`).
    Every other refusal (missing file, outbox root not currently a real
    directory, ...) raises plain `OSError` (often a natural subtype like `FileNotFoundError` straight
    from the failing syscall, never re-wrapped into a fresh generic type —
    callers that specifically catch `FileNotFoundError` to distinguish a
    benign concurrent-archive race from a real failure, see
    `drain_instance`'s resume path, depend on that subtype surviving) —
    deliberately not a new exception type, so it folds into the same
    `except OSError` branches the old `read_capped`-based code already
    had at every call site. No message here ever echoes file content."""
    inst = cfg.instances[name]
    root = inst.root
    outbox_root = inst.outbox_root
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        outbox_fd = attachments_mod._descend_pinned(root_fd, outbox_root.relative_to(root))
        if outbox_fd is None:
            raise FileNotFoundError(
                f"outbox root for instance {name!r} is not currently a real directory"
            )
        try:
            fd = os.open(
                filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=outbox_fd,
            )
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise UnreadableRequest(f"{filename!r} is not a regular file")
                if st.st_nlink != 1:
                    raise UnreadableRequest(f"{filename!r} has nlink={st.st_nlink} (expected 1)")
                limit = cap + 1
                chunks: List[bytes] = []
                got = 0
                while got < limit:
                    chunk = os.read(fd, min(attachments_mod._READ_CHUNK, limit - got))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    got += len(chunk)
                data = b"".join(chunks)
                if len(data) > cap:
                    raise ReadTooLargeError(f"{filename}: exceeds cap of {cap}")
                return data
            finally:
                os.close(fd)
        finally:
            os.close(outbox_fd)
    finally:
        os.close(root_fd)


#: Errnos from opening the live request that say what the entry IS (a symlink,
#: a socket), not that reading it failed. Every other errno is a fault that
#: decides nothing about reuse (`_unreadable_now`).
_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO})


def _unreadable_now(e: BaseException) -> bool:
    """True when `_read_request_pinned` refused the live entry for what it
    is: over the cap, not a regular file or a hard link (`UnreadableRequest`),
    or a kind the open itself names (ELOOP, ENXIO). False for anything else
    (EIO, EACCES, EMFILE, ...), which must decide nothing. Positive
    identification only: an errno-less `OSError` from anywhere else is a
    fault, not a verdict."""
    if isinstance(e, (ReadTooLargeError, UnreadableRequest)):
        return True
    return isinstance(e, OSError) and e.errno in _KIND_ERRNOS


def _live_differs(cfg: RouterConfig, name: str, req_id: str,
                  stored_digest: Optional[str]) -> bool:
    """Does `outbound/req-<req_id>.json` now hold a DIFFERENT request from
    the one whose digest this router stored (an in-flight record's)? An
    absent entry differs from nothing: there is no other request to answer.
    An entry that cannot be read for what it is cannot be the readable
    original, so it differs. A transient fault RAISES: no settlement, no
    archive and no refusal may be decided on it."""
    try:
        raw = _read_request_pinned(cfg, name, f"req-{req_id}.json")
    except FileNotFoundError:
        return False
    except (ReadTooLargeError, OSError) as e:
        if _unreadable_now(e):
            return True
        raise
    return stored_digest is None or hashlib.sha256(raw).hexdigest() != stored_digest


def list_outbound(cfg: RouterConfig, name: str) -> Tuple[List[str], int]:
    """Bare filenames (not paths) of every regular, non-symlink file
    sitting directly under `<ns>/outbound/` — filename hygiene (`REQ_NAME_
    RE`) is applied by the caller, `drain_instance`. A symlinked entry is
    never opened here or anywhere downstream — `path.is_file()` follows a
    symlink, so this checks `is_symlink()` FIRST and excludes it before
    that follow ever happens, since it could resolve outside the
    namespace (a host path, or a different instance's namespace). Returns
    `(names, skipped_symlink_count)` so the caller can fold the count into
    its `outbound_skipped_bad_name` tally. Missing `outbound/` -> `([], 0)`,
    not an error."""
    inst = cfg.instances[name]
    # The directory is reached the way every read reaches it: an O_NOFOLLOW
    # descent from the root. An `outbound/` that is not a real directory
    # (a symlink to elsewhere) lists nothing, rather than enumerating a
    # tree the reads would refuse.
    root_fd = os.open(str(inst.root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        out_fd = attachments_mod._descend_pinned(root_fd, inst.outbox_root.relative_to(inst.root))
    finally:
        os.close(root_fd)
    if out_fd is None:
        try:
            st = os.lstat(inst.outbox_root)
        except FileNotFoundError:
            return [], 0          # missing outbound/: not an error
        if stat.S_ISDIR(st.st_mode):
            # A real directory that cannot be opened: a fault, not an empty
            # outbox. It propagates (the instance errors this poll).
            os.listdir(inst.outbox_root)
            raise PermissionError(f"outbound/ of {name!r} cannot be opened")
        logger.warning("outbound listing for instance %r: outbound/ is not a real "
                       "directory; nothing listed", name)
        return [], 0
    names: List[str] = []
    skipped_symlinks = 0
    try:
        entries = sorted(os.scandir(out_fd), key=lambda e: e.name)
    finally:
        os.close(out_fd)
    for e in entries:
        if e.is_symlink():
            skipped_symlinks += 1
            logger.warning(
                "outbound listing for instance %r has a symlinked entry, "
                "never opened, skipping: %r", name, e.name,
            )
            continue
        if e.is_file(follow_symlinks=False):
            names.append(e.name)
    return names, skipped_symlinks


def _result_doc(
    req_id: str,
    outcome: str,
    *,
    reason_code: str,
    detail: Optional[str] = None,
    recipients: Optional[List[str]] = None,
    message_id: Optional[str] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    doc: Dict[str, Any] = {
        "contract_version": "2",
        "req_id": req_id,
        "outcome": outcome,
        "detail": detail,
        "reason_code": reason_code,
        "ts": utc_ts(),
        "message_id": message_id,
        "job_id": None,
    }
    if recipients is not None:
        doc["recipients"] = recipients
    if attachments:
        doc["attachments"] = attachments
    return doc


def _refusal_diag(
    e: "attachments_mod.AttachmentIngestError", submitted: int,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """`(attachments, detail)` for an attachment-ingest refusal.

    AMAP §6.1: `attachments[]` carries one entry per SUBMITTED attachment,
    `index` equal to its array position, 0 through n-1. Ingest stops at the
    first failure, so the attachments after it have no verdict, and §6.1's
    vocabulary has no word for "not examined". The array is therefore written
    only when every submitted attachment has a real verdict: one submitted
    attachment, the one that failed. Otherwise the optional member is omitted
    and `detail` names the failing index and its outcome. A verdict is never
    fabricated."""
    if e.index is None:
        return None, e.detail
    if e.attachment_outcome is None:
        # MALFORMED (a size or digest mismatch, a sidecar that cannot be
        # opened, is not regular or is linked): §6.1's "two paths, never
        # conflated" makes it a top-level `rejected`, and its per-attachment
        # vocabulary has no word for it (`rejected_type` is the policy
        # verdict for a disallowed type). No array; the index in detail.
        return None, f"{e.detail} (attachment {e.index}: malformed)"
    if submitted == 1 and e.index == 0:
        return [{"index": 0, "outcome": e.attachment_outcome, "detail": e.detail}], e.detail
    return None, f"{e.detail} (attachment {e.index}: {e.attachment_outcome})"


def _attachments_accepted_diag(
    verified: List[attachments_mod.VerifiedAttachment],
) -> Optional[List[Dict[str, Any]]]:
    """§4's `attachments[]` diagnostic array for a request that was
    (fully or partially) delivered: one `accepted` entry per submitted
    attachment, in array order. `None` (not `[]`) when there was nothing
    to report, so `_result_doc` omits the key entirely rather than
    emitting an empty array."""
    if not verified:
        return None
    return [
        {"index": i, "outcome": attachments_mod.ATTACH_OUTCOME_ACCEPTED, "detail": None}
        for i in range(len(verified))
    ]


def _write_held_copy(cfg: RouterConfig, name: str, req_id: str) -> None:
    """Preserve a router-private copy of a HELD request's JSON (only the
    JSON — never sidecar bytes; copying those would be the DoS a size/
    count cap exists to prevent) at `state_dir/<name>/held/`, for operator
    visibility. Best-effort: the result already written is what actually
    governs the request; a failure here is silently swallowed. The single
    call site for BOTH hold paths this router has (`_drain_one`'s
    attachment-cap hold and `_drain_cold`'s `recipient_not_allowlisted`
    hold) — read through `_read_request_pinned` (contract §2 read-side
    discipline, same as `_drain_one`'s own read of these exact bytes
    moments earlier — see that function's docstring for why a bare
    `read_capped`/`Path.read_bytes()` isn't enough): the request path is
    agent-controlled, and even though `state_dir` itself is router-private
    and never agent-reachable, there is no reason for this second read of
    the same file to be less bounded, or less pinned, than the first."""
    held_path = _held_path(cfg, name, req_id)
    try:
        atomic_write(held_path, _read_request_pinned(cfg, name, f"req-{req_id}.json"))
    except (ReadTooLargeError, OSError):
        pass  # best-effort operator visibility; the result is authoritative


def _resolve_cold_recipients(cfg: RouterConfig, draft: Dict[str, Any]) -> Optional[List[str]]:
    """Parse `to ∪ cc` addresses to known instance names, preserving first-
    occurrence order and de-duplicating. Returns `None` (not an empty list)
    if ANY address fails to parse as one of this fleet's addresses
    (`config.instance_for` — `<x>@<fleet_domain>`, or the legacy
    `agent.<x>@local` without a domain) or names an instance this router
    doesn't know — that's the signal for `recipient_unknown`, distinct from
    an empty result."""
    addrs = list(draft.get("to") or []) + list(draft.get("cc") or [])
    seen: List[str] = []
    for addr in addrs:
        name = instance_for(addr, cfg.fleet_domain, cfg.instances)
        if name is None or name not in cfg.instances:
            return None
        if name not in seen:
            seen.append(name)
    return seen


def _drain_one(
    cfg: RouterConfig, name: str, filename: str, req_id: str,
    *, deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
    transport: Optional[inflight_mod.TransportPort] = None,
) -> str:
    """Validate, decide policy, and deliver (or refuse) exactly one
    request — everything between the idempotency check and the private
    result write. Always leaves a private result file behind. Returns the
    governing `outcome` string so `drain_instance` can tally it."""
    # Contract §2 read-side rule (`_read_request_pinned`'s docstring): a
    # pinned, dir_fd-relative, O_NOFOLLOW + fstat-verified regular/
    # nlink==1 read, never `read_capped`'s pre-open `stat` + `Path.
    # read_bytes()` — the request document is agent-influenceable, and a
    # hard link at this filename pointing outside the instance root used
    # to be read (and delivered) whole.
    try:
        raw = _read_request_pinned(cfg, name, filename)
    except ReadTooLargeError as e:
        result = _result_doc(req_id, "rejected", reason_code=REASON_MALFORMED, detail=str(e))
        return _finish(cfg, name, req_id, result, req_digest=None)
    except OSError as e:
        result = _result_doc(req_id, "rejected", reason_code=REASON_MALFORMED, detail=str(e))
        return _finish(cfg, name, req_id, result, req_digest=None)

    req_digest = hashlib.sha256(raw).hexdigest()

    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        result = _result_doc(
            req_id, "rejected", reason_code=REASON_MALFORMED, detail=f"invalid JSON: {e}"
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    ok, reason, detail = validate_mod.validate_request(doc)
    if not ok:
        result = _result_doc(req_id, "rejected", reason_code=reason, detail=detail)
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    # Cross-checks the schema can't express (§2/§3: namespace is
    # attribution; these fields are cross-checks only, never authority).
    if doc["req_id"] != req_id:
        result = _result_doc(
            req_id, "rejected", reason_code=REASON_REQ_ID_MISMATCH,
            detail=f"body req_id {doc['req_id']!r} != filename id {req_id!r}",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    agent_id = doc.get("agent_id")
    if agent_id is not None and agent_id != name:
        result = _result_doc(
            req_id, "rejected", reason_code=REASON_AGENT_ID_MISMATCH,
            detail=f"agent_id {agent_id!r} != namespace instance {name!r}",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    draft = doc["draft"]

    # §3 attachment ingest — verified BEFORE recipient policy (integrity
    # before policy, §4's "two paths, never conflated": a malformed/
    # mismatched attachment fails the whole request `rejected`; a policy
    # cap on an honest declaration is `queued_for_human`). Called
    # unconditionally (even with no attachments) so the dir-shape check
    # (sidecar dir must be ABSENT when attachments is absent/[]) always
    # runs — see `attachments.ingest_attachments`.
    descriptors = draft.get("attachments") or []
    try:
        verified_attachments = attachments_mod.ingest_attachments(
            cfg, name, req_id, descriptors
        )
    except attachments_mod.AttachmentIngestError as e:
        diag, detail = _refusal_diag(e, len(descriptors))
        result = _result_doc(
            req_id, e.outcome, reason_code=e.reason_code, detail=detail,
            attachments=diag,
        )
        if e.outcome == "queued_for_human":
            _write_held_copy(cfg, name, req_id)
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    # D1: the real `inbox-submit` binary never emits the top-level
    # `in_reply_to` field this router binds on (both its CLI `--reply-to-id`
    # and its MCP `in_reply_to` arg land only in `draft.reply_to_message_id`
    # — see router/README.md "Reply vs. cold send"). Fall back to that
    # field when the top-level one is absent; top-level wins when both are
    # present (it is AMAP's designated binding key). Resolution itself is
    # unchanged either way — `binding.read_ledger_record` still only trusts
    # the router's own private ledger, fail-closed.
    top_level_reply = doc.get("in_reply_to")
    draft_reply = draft.get("reply_to_message_id") or None
    if top_level_reply:
        reply_key = top_level_reply
        logger.debug(
            "instance %r req_id %r: reply key from top-level in_reply_to",
            name, req_id,
        )
    elif draft_reply:
        reply_key = draft_reply
        logger.debug(
            "instance %r req_id %r: reply key from draft.reply_to_message_id "
            "(D1 fallback — top-level in_reply_to absent)",
            name, req_id,
        )
    else:
        reply_key = None

    if reply_key:
        return _drain_reply(
            cfg, name, req_id, doc, reply_key,
            req_digest=req_digest, attachments=verified_attachments,
            deliver_backend=deliver_backend,
        )

    return _drain_cold(
        cfg, name, req_id, doc, draft,
        req_digest=req_digest, attachments=verified_attachments,
        deliver_backend=deliver_backend,
        cold_policy=cold_policy,
        transport=transport,
    )


def _drain_reply(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], in_reply_to: str,
    *, req_digest: Optional[str],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]] = None,
    deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
) -> str:
    """Reply routing: recipient set is EXACTLY the bound instance, resolved
    from the router's own ledger. `draft.to`/`draft.cc` are discarded
    outright — never consulted, never surfaced as if they mattered (qm
    D2), and a warning is logged when a reply that will be delivered had a
    `to`/`cc` to discard (instance + req_id only; the discarded addresses
    are agent-supplied and are never echoed verbatim into the log).
    Unresolvable -> `rejected`/`unresolved_reply` (fail closed). A record
    with no fleet sender that passes `_external_binding`'s three-part test
    goes to `_drain_external_reply` instead; one that fails it (a router
    DSN, or anything short of all three) is unresolved as before. Returns
    the governing `outcome` string."""
    record = binding.read_ledger_record(cfg.state_dir, name, str(in_reply_to),
                                        state_key=state_key(cfg, name))
    bound_instance = None
    if record is not None:
        from_instance = record.get("from_instance")
        if isinstance(from_instance, str) and from_instance:
            bound_instance = from_instance
        else:
            # A record with no fleet sender binds OUTSIDE only under the
            # three-part test below; a router-authored DSN record (also
            # `from_instance: null`) fails it and stays unresolved.
            external_address = _external_binding(record)
            if external_address is not None:
                return _drain_external_reply(
                    cfg, name, req_id, doc, in_reply_to, record, external_address,
                    req_digest=req_digest, attachments=attachments,
                    deliver_backend=deliver_backend,
                )

    if bound_instance is None:
        result = _result_doc(
            req_id, "rejected", reason_code=REASON_UNRESOLVED_REPLY,
            detail=f"in_reply_to {in_reply_to!r} does not resolve to a delivery this "
                   f"router made to {name!r}",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    if bound_instance == name:
        result = _result_doc(req_id, "rejected", reason_code=REASON_SELF_SEND)
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    if bound_instance not in cfg.instances:
        # Ledger points at an instance no longer configured — treat as
        # unresolved rather than delivering nowhere-known.
        result = _result_doc(req_id, "rejected", reason_code=REASON_UNRESOLVED_REPLY)
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    # draft.to/cc on a reply are ALWAYS discarded: the recipient is the bound
    # sender from the private ledger, never what the agent wrote. What varies
    # is only whether that is worth an operator's attention.
    #
    # It used to WARN whenever to/cc was non-empty — which is every reply,
    # because the spec requires `draft.to` (minItems 1) and the connector
    # tells agents to address a reply to its sender. A correct reply and a
    # misaddressed one logged the same line, so the warning carried no
    # signal. Found in a live run by amap-deploy-openshell.
    #
    # Now: naming ONLY the bound sender is the normal case (DEBUG); naming
    # anyone else WARNS. The comparison is casefolded — instance names are
    # casefold-unique (`config._check_casefold`), so this cannot conflate two
    # instances. The discarded addresses are still never echoed into the log
    # (`test_logging.py`): the warning carries a count, not the values.
    draft = doc.get("draft") or {}
    supplied = list(draft.get("to") or []) + list(draft.get("cc") or [])
    if supplied:
        bound_address = address_for(bound_instance, cfg.fleet_domain)
        others = [a for a in supplied
                  if not (isinstance(a, str) and a.casefold() == bound_address.casefold())]
        if others:
            logger.warning(
                "reply from instance %r (req_id=%r, in_reply_to=%r) addressed "
                "%d recipient(s) other than its bound sender — draft.to/cc "
                "discarded outright, bound to %r instead per the private ledger",
                name, req_id, in_reply_to, len(others), bound_instance,
            )
        else:
            logger.debug(
                "reply from instance %r (req_id=%r, in_reply_to=%r) addressed "
                "its bound sender %r — draft.to/cc discarded as always, bound "
                "per the private ledger",
                name, req_id, in_reply_to, bound_instance,
            )

    if record.get("tree") == deliver_mod.TREE_PEER:
        return _drain_peer_reply(
            cfg, name, req_id, doc, in_reply_to, record, bound_instance,
            req_digest=req_digest, attachments=attachments,
        )

    # FIXED (was a KNOWN GAP, ROUTER-RELIABILITY.md's reply-path
    # reprocessing loop): this single-recipient delivery now gets the same
    # per-delivery isolation `_drain_cold`'s loop already had below.
    # REMOVES the old unguarded call to `deliver_mod.deliver` — if that
    # raised (delivery failure, or `publish_attachment_blobs` raising
    # `NamespaceEscapeError` on a sabotaged recipient namespace), this
    # function raised too, `_drain_one` never reached `_finish`, NO
    # private result got written, and the request was left un-answered in
    # `outbound/` — the NEXT drain saw a fresh, un-answered request (no
    # private result to resume from) and reprocessed it from scratch,
    # unboundedly, for as long as the bound recipient kept failing: a
    # reply to a permanently-broken recipient retried forever instead of
    # ever being answered. ADDS a `try/except` around the delivery,
    # answering exactly once with `queued_for_human`/`delivery_failed` on
    # failure (mirroring `_drain_cold`'s "every delivery raises" outcome)
    # — the request is finished and archived either way, so the next
    # drain's idempotency check (D4, `drain_instance`) resumes cleanly
    # instead of reprocessing. `drain_instance`'s own outer try/except
    # (module docstring, "Isolation") still isolates one stuck reply from
    # the rest of the router on any OTHER unexpected failure; it was never
    # a substitute for this function answering the request itself.
    # Resolved LATE, per call, never as a def-time default: the default
    # has to be whatever `deliver_mod.deliver` names at the moment of the
    # call, not the function object that existed at import time.
    held = _any_held(cfg, [bound_instance])
    if req_digest is not None and (held or _placement_origin(deliver_backend) is not None):
        # The binding resolved now: pinned with the request digest, so a
        # hold never turns this reply into an unresolved one. Unheld, the
        # record is the placement's intent (`ORIGIN_DIRECT`).
        return _begin_pending(
            cfg, name, req_id, doc, kind="mail", recipients=[bound_instance],
            pin={"in_reply_to": str(in_reply_to), "bound_instance": bound_instance,
                 "record": record, "evaluated_ts": utc_ts(), "window_ok": True},
            req_digest=req_digest, attachments=attachments, deliver_backend=deliver_backend,
            aliases={}, origin=None if held else _placement_origin(deliver_backend))
    backend = deliver_backend if deliver_backend is not None else deliver_mod.deliver
    try:
        delivered = backend(
            cfg, cfg.state_dir, name, bound_instance, doc,
            reply_to_record=record, attachments=attachments,
        )
    except deliver_mod.RecipientHeld:
        # The recipient became held between the check above and the write
        # (its root replaced): nothing was placed, so the request goes
        # pending exactly as the check would have sent it.
        if req_digest is None or cfg.registry_dir is None:
            raise
        return _begin_pending(
            cfg, name, req_id, doc, kind="mail", recipients=[bound_instance],
            pin={"in_reply_to": str(in_reply_to), "bound_instance": bound_instance,
                 "record": record, "evaluated_ts": utc_ts(), "window_ok": True},
            req_digest=req_digest, attachments=attachments, deliver_backend=deliver_backend,
            aliases={})
    except Exception as e:  # noqa: BLE001 — must still answer exactly once
        logger.warning(
            "instance %r req %r: reply delivery to %r failed, answering "
            "queued_for_human/delivery_failed rather than leaving the "
            "request un-answered for the next drain to retry forever: "
            "%s: %s", name, req_id, bound_instance, type(e).__name__, e,
        )
        result = _result_doc(
            req_id, "queued_for_human", reason_code=REASON_DELIVERY_FAILED,
            recipients=[],
            # `type(e).__name__` only in the agent-visible `detail` — NOT
            # `{e}` (matches `_drain_cold`'s equivalent branch below, which
            # names only instance names in `detail` and keeps exception
            # text in the logger). The currently reachable exception here
            # (`NamespaceEscapeError`) happens to be identifier-clean, but
            # an `OSError` reaching this branch can carry an absolute host
            # path in `str(e)` — this is the only place in this module that
            # would otherwise put raw exception text into an agent-readable
            # artifact (`outbound/results/`).
            detail=f"delivery to {bound_instance!r} failed: {type(e).__name__}",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    result = _result_doc(
        req_id, "accepted", reason_code=REASON_RECIPIENT_BOUND,
        recipients=[address_for(bound_instance, cfg.fleet_domain)],
        message_id=delivered["message_id"],
        attachments=_attachments_accepted_diag(attachments or []),
    )
    return _finish(cfg, name, req_id, result, req_digest=req_digest)


def _external_binding(record: Dict[str, Any]) -> Optional[str]:
    """The address a `from_instance: null` ledger record binds a reply to
    OUTSIDE the fleet, or `None` (fail closed) unless ALL THREE hold on
    the record itself: `transport == "smtp"`, `origin == "external"`, and a
    non-empty string `from_address` (delivery_design.md §7.x). Each is
    tested for the exact value, so an absent key, a `null`, a non-string,
    or any other spelling is `None`. Nothing in this repo writes such a
    record; the combined runtime's inbound SMTP leg does, under the
    recipient instance. This router only reads it — and reads it from the
    private ledger, never from anything the agent supplied."""
    if record.get("transport") != "smtp":
        return None
    if record.get("origin") != "external":
        return None
    from_address = record.get("from_address")
    if not isinstance(from_address, str) or not from_address:
        return None
    return from_address


def _drain_external_reply(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], in_reply_to: str,
    record: Dict[str, Any], external_address: str,
    *, req_digest: Optional[str],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]],
    deliver_backend: Optional[deliver_mod.DeliveryBackend],
) -> str:
    """The one branch `_drain_reply` grew for a record that binds outside
    the fleet (`_external_binding`). Same discipline as the local reply:
    the recipient is the RECORD's `from_address`, `draft.to`/`cc` are
    discarded (logged, never echoed), and the delivery goes to the injected
    backend with `recipient=None` and the record (`deliver.DeliveryBackend`,
    "THE ONE EXTENSION"). The default local backend raises
    `deliver.ExternalReplyUnsupported`, so a standalone router meeting such
    a record — which it never writes — answers `queued_for_human`/
    `delivery_failed` once, exactly as for any other failed delivery, and
    places nothing anywhere. No self-send check applies (the outside is
    never `name`); no configured-instance check applies (there is none to
    check). Wire unchanged: the result is `accepted`/`recipient_bound`
    with the external address as its one recipient."""
    draft = doc.get("draft") or {}
    if draft.get("to") or draft.get("cc"):
        logger.warning(
            "external reply from instance %r (req_id=%r, in_reply_to=%r) supplied "
            "draft.to/cc — discarded outright, bound to the ledger record's "
            "from_address instead",
            name, req_id, in_reply_to,
        )
    backend = deliver_backend if deliver_backend is not None else deliver_mod.deliver
    try:
        delivered = backend(
            cfg, cfg.state_dir, name, None, doc,
            reply_to_record=record, attachments=attachments,
        )
    except Exception as e:  # noqa: BLE001 — must still answer exactly once
        logger.warning(
            "instance %r req %r: external reply delivery (in_reply_to=%r) failed, "
            "answering queued_for_human/delivery_failed: %s: %s",
            name, req_id, in_reply_to, type(e).__name__, e,
        )
        result = _result_doc(
            req_id, "queued_for_human", reason_code=REASON_DELIVERY_FAILED,
            recipients=[],
            # Exception TYPE only, never its text (same rule as the local
            # branch). The address is not named either: it is not needed
            # to act on the result, and the reply was not delivered.
            detail=f"external reply delivery failed: {type(e).__name__}",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    result = _result_doc(
        req_id, "accepted", reason_code=REASON_RECIPIENT_BOUND,
        recipients=[external_address],
        message_id=delivered["message_id"],
        attachments=_attachments_accepted_diag(attachments or []),
    )
    return _finish(cfg, name, req_id, result, req_digest=req_digest)


@dataclass(frozen=True)
class ColdRefusal:
    """A cold send refused by policy, before any delivery is attempted.

    `hold` asks for the raw request to be copied to `state_dir/<name>/held/`
    for operator inspection — the treatment a policy miss gets, as distinct
    from a malformed request nobody could act on.
    """
    outcome: str
    reason_code: str
    detail: Optional[str] = None
    hold: bool = False


@dataclass(frozen=True)
class PeerRoute:
    """A cold send the policy routed onto the PEER lane: exactly one
    recipient, reached along a declared edge. Carried by `deliver.
    deliver_peer` — never by an injected `deliver_backend`, which carries the
    mail lane; the peer lane has one tree and one writer in this repo, and a
    combined runtime that wants to intercept it should say so rather than
    have its mail backend silently receive peer traffic."""
    recipient: str


@dataclass(frozen=True)
class ExternalRoute:
    """A cold send the policy routed to the EXTERNAL leg: handed to a second
    runtime through a transport port and settled from that runtime's result,
    polls later (`router/inflight.py`). `recipients` is the evaluated set,
    and the transport request carries exactly it. No policy in this repo
    returns one yet: classification is a later step of the external-leg design,
    and this type exists so the in-flight state can be driven before it."""
    recipients: Tuple[str, ...]


# The cold-send POLICY seam, sibling to the delivery seam in `deliver.py`.
#
# The delivery seam alone was not enough, and the reason is worth stating: a
# combined local+external runtime must route recipients this router would
# refuse OUTRIGHT — `_resolve_cold_recipients` returns None for anything that
# is not a known instance, so an external address is rejected long BEFORE any
# backend is consulted. The seam was one step too late. This one sits at the
# decision itself.
#
# Returns either the authorized recipient list or a ColdRefusal. It CANNOT
# skip `_finish`: the caller writes exactly one governing outcome either way,
# which is the invariant a policy must not be able to break.
#
# CONTRACT FOR A CUSTOM POLICY: if you return recipients that are not
# instances of this config — which is the whole point for a combined runtime —
# you MUST also supply a `deliver_backend` that can carry them. The default
# `deliver.deliver` resolves `cfg.instances[recipient]` and will raise.
ColdPolicy = Callable[
    [RouterConfig, str, Dict[str, Any]],
    Union[List[str], ColdRefusal, PeerRoute, ExternalRoute],
]

def default_remote_policy(
    cfg: RouterConfig, sender: str, draft: Dict[str, Any]
) -> Union[ColdRefusal, ExternalRoute]:
    """This router's own decision for a request whose recipients are all in
    ONE cross-host class of item 6 or item 7 (`classify.remote_rule`). The
    only decision a custom `ColdPolicy` replaces."""
    remote = classify_mod.remote_of(cfg, draft)
    d = classify_mod.remote_rule(cfg, sender, remote)
    if isinstance(d, classify_mod.Refuse):
        return ColdRefusal(d.outcome, d.reason_code, detail=d.detail, hold=d.hold)
    return ExternalRoute(d.recipients)


def _remote_decision(
    cfg: RouterConfig, sender: str, draft: Dict[str, Any], remote: "classify_mod.Remote",
    cold_policy: Optional[ColdPolicy],
) -> Union[ColdRefusal, ExternalRoute]:
    """Items 6 and 7: the custom policy if one was supplied, else
    `default_remote_policy`. A policy cannot route a recipient into a class
    it is not in: only a refusal, or an external route naming recipients of
    THIS request's class, is accepted, and anything else is answered
    `queued_for_human`/`transport_anomaly` with nothing sent."""
    policy = cold_policy if cold_policy is not None else default_remote_policy
    decided = policy(cfg, sender, draft)
    if isinstance(decided, ColdRefusal):
        return decided
    if isinstance(decided, ExternalRoute) and all(
            _canonical_or_none(r) in remote.canonical for r in decided.recipients):
        return decided
    return ColdRefusal("queued_for_human", REASON_TRANSPORT_ANOMALY,
                       detail="the cold policy routed outside this request's recipient "
                              "class; nothing was sent")


#: Refusals that belong to the peer lane and are therefore audited
#: (`audit.EVENT_PEER_REFUSED`) under the refused SENDER.
_PEER_REFUSALS = frozenset({REASON_PEER_SINGLE_RECIPIENT, REASON_PEER_REPLY_WINDOW_EXPIRED})


def default_cold_policy(
    cfg: RouterConfig, sender: str, draft: Dict[str, Any]
) -> Union[List[str], ColdRefusal, PeerRoute]:
    """This router's own cold-send decision: every recipient must parse to a
    KNOWN instance; then the PEER lane if a declared edge exists (module
    docstring, step 4a), else the mutual allowlist check, unchanged.

    The peer check runs BEFORE the mail check, and the order does not
    matter for correctness — the loader guarantees an ordered pair is never
    both an edge and a mutual mail pair — but it matters for the refusal a
    mixed-lane submit gets: `to` on an edge plus `cc` on a mail pair is
    `peer_single_recipient`, naming the lane the sender evidently meant."""
    recipients = _resolve_cold_recipients(cfg, draft)
    if recipients is None:
        return ColdRefusal("rejected", REASON_RECIPIENT_UNKNOWN)
    if not recipients:
        return ColdRefusal("rejected", REASON_MALFORMED, detail="no recipients")
    if sender in recipients:
        return ColdRefusal("rejected", REASON_SELF_SEND)
    on_edge = [r for r in recipients if binding.check_peer_edge(cfg, sender, r)]
    if on_edge:
        if len(recipients) != 1 or draft.get("cc"):
            return ColdRefusal(
                "rejected", REASON_PEER_SINGLE_RECIPIENT,
                detail="a peer message is addressed to exactly one agent, in "
                       "draft.to, with no cc; the whole request is refused",
            )
        return PeerRoute(recipients[0])
    if not all(binding.check_cold(cfg, sender, r) for r in recipients):
        return ColdRefusal(
            "queued_for_human", REASON_RECIPIENT_NOT_ALLOWLISTED, hold=True)
    return recipients


def _audit_peer_refusal(
    cfg: RouterConfig, sender: str, req_id: str, reason_code: str,
    *, recipients: Optional[List[str]] = None, in_reply_to: Optional[str] = None,
) -> None:
    """Best-effort: the refusal result is what governs; a log failure must
    not turn a clean refusal into an errored request."""
    try:
        audit_mod.append(
            cfg.state_dir, sender, audit_mod.EVENT_PEER_REFUSED,
            state_key=state_key(cfg, sender),
            req_id=req_id, reason_code=reason_code,
            recipients=list(recipients or []), in_reply_to=in_reply_to,
        )
    except (audit_mod.AuditError, OSError) as e:
        logger.warning(
            "instance %r req %r: could not audit the peer-lane refusal (%s: %s)",
            sender, req_id, type(e).__name__, e,
        )


def _drain_peer_route(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], route: PeerRoute,
    *, req_digest: Optional[str],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]],
    reply_to_record: Optional[Dict[str, Any]] = None,
    pin: Optional[Dict[str, Any]] = None,
    aliases: Mapping[str, str],
) -> str:
    """Place one peer notice (fresh task or reply) and answer the request
    exactly once — `accepted`/`peer_routed` with the minted peer id, or
    `queued_for_human`/`delivery_failed` if the placement raised (the same
    isolation `_drain_reply`/`_drain_cold` give the mail lane; see the
    comment in `_drain_reply` for why an unguarded delivery would retry
    forever). Late-resolved so a test can patch `deliver_mod.deliver_peer`."""
    recipient = route.recipient
    if req_digest is not None:
        # Held or not, through the record: unheld, it is the placement's
        # intent (`ORIGIN_DIRECT`).
        return _begin_pending(
            cfg, name, req_id, doc, kind="peer", recipients=[recipient], pin=pin,
            req_digest=req_digest, attachments=attachments, deliver_backend=None,
            aliases=aliases,
            origin=None if _any_held(cfg, [recipient]) else ORIGIN_DIRECT)
    try:
        delivered = deliver_mod.deliver_peer(
            cfg, cfg.state_dir, name, recipient, doc,
            reply_to_record=reply_to_record, attachments=attachments,
        )
    except deliver_mod.RecipientHeld:
        if req_digest is None or cfg.registry_dir is None:
            raise
        return _begin_pending(
            cfg, name, req_id, doc, kind="peer", recipients=[recipient], pin=pin,
            req_digest=req_digest, attachments=attachments, deliver_backend=None,
            aliases=aliases)
    except Exception as e:  # noqa: BLE001 — must still answer exactly once
        logger.warning(
            "instance %r req %r: peer delivery to %r failed, answering "
            "queued_for_human/delivery_failed: %s: %s",
            name, req_id, recipient, type(e).__name__, e,
        )
        result = _result_doc(
            req_id, "queued_for_human", reason_code=REASON_DELIVERY_FAILED,
            recipients=[],
            detail=f"delivery to {recipient!r} failed: {type(e).__name__}",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)
    result = _result_doc(
        req_id, "accepted", reason_code=REASON_PEER_ROUTED,
        recipients=[address_for(recipient, cfg.fleet_domain)],
        message_id=delivered["message_id"],
        attachments=_attachments_accepted_diag(attachments or []),
    )
    return _finish(cfg, name, req_id, result, req_digest=req_digest)


def _drain_peer_reply(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], in_reply_to: str,
    record: Dict[str, Any], bound_instance: str,
    *, req_digest: Optional[str],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]],
) -> str:
    """The REVERSE edge (module docstring, step 4a). `record` is the
    sender's own ledger record for the peer notice it is answering, already
    resolved and already known to carry `tree: "peer"`; `bound_instance` is
    the instance that sent it. Permitted along a declared edge `name ->
    bound_instance`, else within `peer_reply_window_seconds` of `record["ts"]`
    (measured now, at drain time; an unparseable `ts` is treated as expired
    — fail closed), else `rejected`/`peer_reply_window_expired`. The
    unguessable id is the control; the window bounds a leaked id's
    lifetime. Several replies to one id within the window are fine, each a
    new notice with its own id."""
    if cfg.instances[bound_instance].peer_root is None:
        # The record says peer, the config no longer does (fleet_domain
        # dropped, or the instance moved to namespace mode). Nowhere
        # conformant to write it: the same fail-closed answer an
        # unconfigured bound instance gets.
        result = _result_doc(
            req_id, "rejected", reason_code=REASON_UNRESOLVED_REPLY,
            detail=f"in_reply_to {in_reply_to!r} resolves to a peer notice, but "
                   f"{bound_instance!r} has no peer tree under the current config",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    evaluated_ts = utc_ts()
    issued = parse_utc_ts(record.get("ts"))
    now = parse_utc_ts(evaluated_ts)
    window = timedelta(seconds=cfg.peer_reply_window_seconds)
    window_ok = not (issued is None or now is None or now - issued > window)
    if not binding.check_peer_edge(cfg, name, bound_instance):
        if not window_ok:
            _audit_peer_refusal(
                cfg, name, req_id, REASON_PEER_REPLY_WINDOW_EXPIRED,
                recipients=[bound_instance], in_reply_to=in_reply_to,
            )
            result = _result_doc(
                req_id, "rejected", reason_code=REASON_PEER_REPLY_WINDOW_EXPIRED,
                detail=f"in_reply_to {in_reply_to!r} names a peer notice issued more "
                       f"than {cfg.peer_reply_window_seconds}s ago and no edge "
                       f"{name!r} -> {bound_instance!r} is declared",
            )
            return _finish(cfg, name, req_id, result, req_digest=req_digest)

    # Eligible now (an edge, or within the window). If the target is held,
    # this is the first eligible evaluation and it is what gets pinned:
    # `window_ok` records whether the WINDOW held now, so a later loss of
    # the edge cannot be rescued by a window that had already passed.
    return _drain_peer_route(
        cfg, name, req_id, doc, PeerRoute(bound_instance),
        req_digest=req_digest, attachments=attachments, reply_to_record=record,
        pin={"in_reply_to": str(in_reply_to), "bound_instance": bound_instance,
             "record": record, "evaluated_ts": evaluated_ts, "window_ok": window_ok},
        aliases={},
    )


def _drain_cold(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], draft: Dict[str, Any],
    *, req_digest: Optional[str],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]] = None,
    deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
    transport: Optional[inflight_mod.TransportPort] = None,
) -> str:
    """Cold-send routing: recipient set = `to ∪ cc`, one governing outcome,
    never a partial delivery. WHICH recipients are permitted is the policy's
    decision (`cold_policy`, default `default_cold_policy` — every caller in
    this repo omits it, and the behaviour is then exactly as before). Returns
    the governing `outcome` string."""
    # ALIASES first (`router/aliases.py`): every policy, the default or a
    # custom one, sees only canonical addresses. An address the table names
    # but cannot decide holds the whole request UNCONSUMED; one whose entry
    # is inactive is answered here, before any policy can route it.
    norm = aliases_mod.normalise(cfg, draft)
    if isinstance(norm, aliases_mod.Hold):
        aliases_mod.note_held(cfg, name, req_id, req_digest, norm.reason)
        logger.warning("instance %r req %r: held unconsumed, alias undecidable (%s): %s",
                       name, req_id, norm.reason, list(norm.addresses))
        return HELD
    if isinstance(norm, aliases_mod.Refuse):
        result = _result_doc(req_id, "rejected", reason_code=REASON_RECIPIENT_UNKNOWN,
                             detail=f"{len(norm.addresses)} address(es) name an alias that "
                                    "is no longer active")
        return _finish(cfg, name, req_id, result, req_digest=req_digest)
    draft, applied = dict(norm.draft), dict(norm.applied)
    for old, new in sorted(applied.items()):
        logger.warning("instance %r req %r: alias used: %s -> %s", name, req_id, old, new)
    # THE ORDER (`router/classify.py`), outside any custom policy: steps 2-5
    # and item 5 are this router's, always. Only a single cross-host class
    # of item 6 or item 7 that passed them reaches a policy, and its answer
    # is checked against that class (`_remote_decision`).
    classified = classify_mod.classify(cfg, name, draft, plugin=transport is not None,
                                       now=utc_ts())
    klass: Optional[str] = None
    if isinstance(classified, classify_mod.Refuse):
        decided: Any = ColdRefusal(classified.outcome, classified.reason_code,
                                   detail=classified.detail, hold=classified.hold)
    elif isinstance(classified, classify_mod.PeerRemote):
        # Item 5 passed in full. No production path gets here: item 5e
        # refuses first while this router cannot sign a cross-host peer
        # statement. Answered, never dropped, and nothing is published.
        decided = ColdRefusal("queued_for_human", REASON_TRANSPORT_ANOMALY,
                              detail="the cross-host peer lane is not built; nothing was sent")
    elif isinstance(classified, classify_mod.Remote):
        klass = classified.klass
        decided = _remote_decision(cfg, name, draft, classified, cold_policy)
    else:
        # Every recipient is an instance here. An alias names only a LOCAL
        # identity, so an alias-normalised draft always lands in this branch
        # or in a step-5 refusal, and never reaches a custom policy or the
        # external leg: the agent's own bytes are what the external leg is
        # given, never a rewritten draft. Late resolution: a module-level
        # default bound at def-time cannot be patched by a test.
        decided = default_cold_policy(cfg, name, draft)

    if isinstance(decided, ColdRefusal):
        result = _result_doc(req_id, decided.outcome,
                             reason_code=decided.reason_code, detail=decided.detail)
        if decided.hold:
            _write_held_copy(cfg, name, req_id)
        if decided.reason_code in _PEER_REFUSALS:
            _audit_peer_refusal(
                cfg, name, req_id, decided.reason_code,
                recipients=_resolve_cold_recipients(cfg, draft),
            )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    if isinstance(decided, PeerRoute):
        return _drain_peer_route(
            cfg, name, req_id, doc, decided,
            req_digest=req_digest, attachments=attachments, aliases=applied,
        )

    if isinstance(decided, ExternalRoute):
        return _begin_external(
            cfg, name, req_id, doc, decided,
            req_digest=req_digest, attachments=attachments, transport=transport,
            klass=klass, cold_policy=cold_policy,
        )

    recipients = list(decided)
    if not recipients:
        # A policy that authorizes nobody without saying why still gets one
        # governing outcome; silence is not a delivery.
        result = _result_doc(
            req_id, "rejected", reason_code=REASON_MALFORMED, detail="no recipients"
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)

    # Per-recipient isolation. A list comprehension here would abort the whole
    # request on one bad recipient, skipping `_finish` — so the request stays
    # in `outbound/` un-answered and un-archived, and EVERY later poll
    # re-delivers to the healthy recipients without bound. Under posture A a
    # hostile recipient owns its own namespace and can arrange exactly that,
    # turning a peer into an amplifier. The request must be answered exactly
    # once no matter how any single delivery goes.
    # Under a registry, a held local target makes the whole request PENDING
    # (HELD LOCAL DELIVERY, below): nothing is answered until it resolves,
    # and the targets that can go now go through the pending record. With
    # nothing held, the same record is the placement's intent
    # (`ORIGIN_DIRECT`), so a failure after placement never places twice.
    if req_digest is not None and (
            _any_held(cfg, recipients) or _placement_origin(deliver_backend) is not None):
        return _begin_pending(
            cfg, name, req_id, doc, kind="mail", recipients=recipients, pin=None,
            req_digest=req_digest, attachments=attachments, deliver_backend=deliver_backend,
            aliases=applied,
            origin=None if _any_held(cfg, recipients) else _placement_origin(deliver_backend))

    # Late resolution, as in `_drain_reply` above — see that comment.
    backend = deliver_backend if deliver_backend is not None else deliver_mod.deliver
    delivered: List[Dict[str, Any]] = []
    failed: List[str] = []
    held_now: List[str] = []
    for r in recipients:
        try:
            delivered.append(
                backend(cfg, cfg.state_dir, name, r, doc, attachments=attachments)
            )
        except deliver_mod.RecipientHeld:
            if req_digest is None or cfg.registry_dir is None:
                failed.append(r)
                continue
            held_now.append(r)    # nothing placed for it: it goes pending, below
        except Exception as e:  # noqa: BLE001 — one recipient must not sink the request
            failed.append(r)
            logger.warning(
                "instance %r req %r: delivery to %r failed, continuing with the "
                "remaining recipients: %s: %s", name, req_id, r, type(e).__name__, e,
            )

    if held_now:
        # A recipient became held between the check and its write (its root
        # replaced): the request goes pending with what this pass already
        # did recorded as done, so nothing is placed twice and nothing is
        # answered before the held recipient resolves.
        return _begin_pending(
            cfg, name, req_id, doc, kind="mail", recipients=recipients, pin=None,
            req_digest=req_digest, attachments=attachments, deliver_backend=deliver_backend,
            settled={**{d["recipient"]: d for d in delivered}, **{r: None for r in failed}},
            aliases=applied)
    ok_addrs = [address_for(d["recipient"], cfg.fleet_domain) for d in delivered]
    message_id = delivered[0]["message_id"] if len(delivered) == 1 and not failed else None

    if not failed:
        result = _result_doc(
            req_id, "accepted", reason_code=REASON_ALLOWLISTED,
            recipients=ok_addrs, message_id=message_id,
            attachments=_attachments_accepted_diag(attachments or []),
        )
    elif delivered:
        # Some recipients have it and cannot be un-delivered. `recipients` is the
        # authoritative record of who actually received it (AMAP §4), so it lists
        # only those; the failures are named in `detail`. Not retried: a retry
        # would re-deliver to the ones that succeeded.
        result = _result_doc(
            req_id, "accepted", reason_code=REASON_PARTIAL_DELIVERY,
            recipients=ok_addrs, message_id=message_id,
            detail=f"delivered to {len(delivered)}; failed for: {', '.join(sorted(failed))}",
            attachments=_attachments_accepted_diag(attachments or []),
        )
    else:
        # Nothing went out. Not a policy refusal — an infrastructure failure the
        # operator has to look at, so it is held, never silently dropped (AMAP §4).
        result = _result_doc(
            req_id, "queued_for_human", reason_code=REASON_DELIVERY_FAILED,
            recipients=[],
            detail=f"no recipient could be delivered to: {', '.join(sorted(failed))}",
        )
    return _finish(cfg, name, req_id, result, req_digest=req_digest)


#: `_drain_cold`'s return for a request handed to the external leg: consumed,
#: not settled. `drain_instance` counts it apart from the three outcomes.
INFLIGHT = "inflight"


def _begin_external(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], route: ExternalRoute,
    *, req_digest: Optional[str],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]],
    transport: Optional[inflight_mod.TransportPort],
    klass: Optional[str] = None, cold_policy: Optional[ColdPolicy] = None,
) -> str:
    """Put a request in flight and take its first step (which writes the
    transport request). Two cases settle at once instead, both
    `queued_for_human`/`transport_anomaly`, because neither is the agent's
    fault and neither may be dropped: no transport configured, and
    attachments, whose staging to the transport is not built yet (the
    sidecars sit in the agent-writable outbox; ingest by copy needs them
    staged first)."""
    if isinstance(transport, hoplink.Held):
        # This generation's sender is held: nothing is consumed, so the
        # request is decided on a later poll, once the hold clears.
        logger.warning("instance %r req %r: held unconsumed, the hop sender is held (%s)",
                       name, req_id, transport.hold.reason)
        return HELD
    if transport is not None and hoplink.write_hold(cfg, name) is not None:
        # This generation's hand-overs are latched: a request begun now would
        # be stranded in it. Left unconsumed, it is decided once `router
        # generation new` has moved the instance on.
        logger.warning("instance %r req %r: held unconsumed, this generation's hand-overs "
                       "are held", name, req_id)
        return HELD
    if transport is None:
        result = _result_doc(
            req_id, "queued_for_human", reason_code=REASON_TRANSPORT_ANOMALY,
            recipients=[], detail="the external leg is not configured for this instance",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)
    if attachments:
        result = _result_doc(
            req_id, "queued_for_human", reason_code=REASON_TRANSPORT_ANOMALY,
            recipients=[], detail="attachments on the external leg are not supported yet",
        )
        return _finish(cfg, name, req_id, result, req_digest=req_digest)
    # Mail only (D4): the hand-over carries kind "mail", so a request the
    # classifier did not put in a cold mail class is refused before
    # anything is allocated, never handed over as mail.
    if klass not in (classify_mod.CLASS_FLEET, classify_mod.CLASS_INTERNET):
        result = _result_doc(
            req_id, "rejected", reason_code=classify_mod.REASON_NO_ROUTE, recipients=[],
            detail="only mail of the fleet-host or internet class is handed to the hop")
        return _finish(cfg, name, req_id, result, req_digest=req_digest)
    # The begin-time checks (`router/hoplink.py`): what the transport would
    # refuse for a reason no retry can change is answered NOW, before a
    # transport id is allocated, or the request would stay in flight forever
    # and hold this generation's frontier. Checked on the request exactly as
    # it will be handed over, with the longest transport id it can carry.
    from_address = address_for(name, cfg.fleet_domain)
    why = hoplink.from_address_problem(from_address)
    if why is not None:
        logger.error("instance %r: its address %r cannot be a handover's from_address "
                     "(%s); nothing is handed over", name, from_address, why)
        result = _result_doc(
            req_id, "queued_for_human", reason_code=REASON_TRANSPORT_ANOMALY, recipients=[],
            detail="this instance's address cannot be handed to the external leg")
        return _finish(cfg, name, req_id, result, req_digest=req_digest)
    probe = json.loads(json.dumps(doc))
    probe["req_id"] = "9" * hoplink.TRANSPORT_ID_MAX_DIGITS
    probe["agent_id"] = state_key(cfg, name)
    probe.pop("in_reply_to", None)
    probe.get("draft", {}).pop("reply_to_message_id", None) if isinstance(
        probe.get("draft"), dict) else None
    try:
        hoplink.check_begin(probe, request_cap=(cfg.hop.cap("request")
                                                if cfg.hop is not None else 1 << 62))
    except hoplink.Refused as e:
        result = _result_doc(req_id, e.outcome, reason_code=e.reason_code,
                             recipients=[], detail=e.detail)
        return _finish(cfg, name, req_id, result, req_digest=req_digest)
    record = inflight_mod.begin(
        cfg, name, req_id, digest=req_digest, request_doc=doc,
        recipients=list(route.recipients),
        policy_digest=classify_mod.policy_digest(cfg, name), route=klass,
        from_address=from_address,
    )
    _advance_one(cfg, name, req_id, record, transport, cold_policy=cold_policy)
    return INFLIGHT


def _advance_one(
    cfg: RouterConfig, name: str, req_id: str, record: Dict[str, Any],
    transport: inflight_mod.TransportPort, *, fenced: bool = False,
    cold_policy: Optional[ColdPolicy] = None, fenced_retired: bool = False,
) -> str:
    """`inflight.advance` with `_finish` as the settle step.

    A record settles PRIVATELY when the live entry under its req_id is now a
    different request (a connector reset reused the id): the anchor is
    written, so this request has its one verdict, and nothing is published
    into `outbound/results/` or archived from `outbound/`. Publishing it
    would answer the new file with the old verdict and archive it unsent.
    The listing then finds the anchor, compares digests, and refuses the
    new file as `req_id_reused`."""
    def settle(verdict: Dict[str, Any], digest: Optional[str]) -> str:
        result = _result_doc(req_id, **verdict)
        # A FENCED generation's record publishes only into the root it
        # recorded, and only while the live entry is still its request.
        if _live_differs(cfg, name, req_id, digest) or (fenced and not _same_root(cfg, name)):
            logger.warning(
                "instance %r req_id %r: the in-flight request settled %r, but "
                "the outbox now holds a different request under this id; the "
                "verdict is kept privately and the new request is refused as %s",
                name, req_id, result["outcome"], REASON_REQ_ID_REUSED,
            )
            _write_anchor(cfg, name, req_id, result, req_digest=digest,
                          transport_req_id=record.get("transport_req_id"))
            return result["outcome"]
        return _finish(cfg, name, req_id, result, req_digest=digest,
                       transport_req_id=record.get("transport_req_id"))

    anchor = _private_result_path(cfg, name, req_id)
    return inflight_mod.advance(
        cfg, name, req_id, record, transport, settle=settle,
        already_settled=anchor.is_file(), anchor=anchor,
        recheck=lambda rec: _recheck(cfg, name, rec, transport, cold_policy),
        publish_blocked=cfg.reload_failed, fenced_retired=fenced_retired,
    )


def _canonical_or_none(raw: Any) -> Optional[str]:
    try:
        return classify_mod.parse_address(raw).canonical()
    except classify_mod.Malformed:
        return None


def _recheck(
    cfg: RouterConfig, name: str, record: Dict[str, Any],
    transport: Optional[inflight_mod.TransportPort], cold_policy: Optional[ColdPolicy],
) -> inflight_mod.Recheck:
    """Re-classify a record's STAGED request under the current config, the
    whole order from alias normalisation on (`router/classify.py`). Still
    permitted means the same class, route and recipient set; anything else
    is `queued_for_human`/`recipient_not_allowlisted`, "policy changed before
    publication", saying what changed. A different route is refused, never
    rebuilt for the new one. The digest is not consulted to decide: what
    decides a permit is wider than what the digest covers."""
    def refused(why: str) -> inflight_mod.Recheck:
        return inflight_mod.Recheck(False, verdict={
            "outcome": "queued_for_human", "reason_code": REASON_RECIPIENT_NOT_ALLOWLISTED,
            "detail": f"policy changed before publication: {why}", "recipients": []},
            why=why)

    draft = record.get("request", {}).get("draft")
    if not isinstance(draft, dict):
        return refused("the staged request has no draft")
    norm = aliases_mod.normalise(cfg, draft)
    if not isinstance(norm, aliases_mod.Normalised) or norm.applied:
        return refused("an alias now names a recipient")
    old = record.get("route")
    kinds = set()
    for raw in classify_mod.recipients(draft):
        try:
            kinds.add(classify_mod.address_class(cfg, raw)[0])
        except classify_mod.Malformed:
            kinds.add(None)
    if old is not None and len(kinds) == 1 and None not in kinds and kinds != {old}:
        return refused(f"route changed from {old} to {next(iter(kinds))}")
    decided = classify_mod.classify(cfg, name, draft, plugin=transport is not None,
                                    now=utc_ts())
    if isinstance(decided, classify_mod.Refuse):
        return refused(f"now {decided.reason_code}")
    if not isinstance(decided, classify_mod.Remote):
        return refused(f"route changed from {old or 'external'} to "
                       f"{classify_mod.CLASS_LOCAL if isinstance(decided, classify_mod.Local) else classify_mod.CLASS_TRUSTED}")
    routed = _remote_decision(cfg, name, draft, decided, cold_policy)
    if isinstance(routed, ColdRefusal):
        return refused(f"now {routed.reason_code}")
    then = {_canonical_or_none(r) for r in record.get("recipients", [])}
    now_set = {_canonical_or_none(r) for r in routed.recipients}
    if None in then or then != now_set:
        return refused("the permitted recipient set changed")
    return inflight_mod.Recheck(True, policy_digest=classify_mod.policy_digest(cfg, name),
                                route=decided.klass)


#: What this process has already warned about, so a 5-second poll does not
#: repeat it: (instance, req_id) for a stale request, (instance, None) for
#: records left with no transport.
_STALE_WARNED: set = set()


def _advance_inflight(
    cfg: RouterConfig, name: str, transport: Optional[inflight_mod.TransportPort],
    outcomes: Dict[str, int], *, fenced: bool = False,
    cold_policy: Optional[ColdPolicy] = None, fenced_retired: bool = False,
) -> Dict[str, int]:
    """One step for every in-flight record of `name`, isolated per record.
    Runs BEFORE the outbox listing, so a request settled here is seen by the
    listing as already answered. Without a transport, records are left
    exactly as they are and only counted: nothing here may guess a verdict.
    `fenced_retired`: `name`'s generation is fenced and its hop tree retired,
    so a record never handed over is never handed over now."""
    settled = errored = 0
    req_ids = inflight_mod.list_records(cfg, name)
    if isinstance(transport, hoplink.Held):
        return {"inflight_settled": 0, "inflight_errored": 0}
    if req_ids and transport is None:
        if (name, None) not in _STALE_WARNED:
            _STALE_WARNED.add((name, None))
            logger.warning(
                "instance %r has %d in-flight request(s) and no transport "
                "configured; leaving them unsettled", name, len(req_ids),
            )
    elif transport is not None:
        for req_id in req_ids:
            try:
                record = inflight_mod.read_record(cfg, name, req_id)
                if record is None:
                    continue
                state = _advance_one(cfg, name, req_id, record, transport, fenced=fenced,
                                     cold_policy=cold_policy, fenced_retired=fenced_retired)
            except Exception:
                logger.exception(
                    "instance %r: error advancing in-flight request %r — isolated, "
                    "retried next poll", name, req_id,
                )
                errored += 1
                continue
            if state == inflight_mod.SETTLED:
                settled += 1
                result = json.loads(
                    _private_result_path(cfg, name, req_id).read_text(encoding="utf-8")
                )["result"]
                if result["outcome"] in outcomes:
                    outcomes[result["outcome"]] += 1
    return {"inflight_settled": settled, "inflight_errored": errored}


def _inflight_report(cfg: RouterConfig, name: str) -> Dict[str, int]:
    """The in-flight counts at the END of a drain (so a request handed off
    this poll is counted), warning once per process about each stale one."""
    summary, stale = inflight_mod.summarize(cfg, name)
    for req_id in stale:
        if (name, req_id) not in _STALE_WARNED:
            _STALE_WARNED.add((name, req_id))
            logger.warning(
                "instance %r: request %r has been in flight past %ds with no "
                "transport result; it stays pending (no timeout settles it)",
                name, req_id, inflight_mod.STALE_AFTER_S,
            )
    return summary


def _finish(
    cfg: RouterConfig, name: str, req_id: str, result: Dict[str, Any],
    *, req_digest: Optional[str], transport_req_id: Optional[str] = None,
    private: bool = False,
) -> str:
    """Write the private result (idempotency anchor), then copy it into the
    namespace's `outbound/results/`, then archive the request. Called
    exactly once per freshly-processed request. Returns `result["outcome"]`
    so callers up the chain can tally it.

    The private anchor is an envelope `{"digest", "result"}`, not the bare
    result doc — `digest` is the sha256 of the request bytes this result
    was computed from (`None` only in the rare case the request couldn't
    even be read, e.g. it exceeded the read cap). `drain_instance`'s resume
    path compares this against the CURRENT on-disk bytes before ever
    replaying a stored verdict — see `REASON_REQ_ID_REUSED`."""
    _write_anchor(cfg, name, req_id, result, req_digest=req_digest,
                  transport_req_id=transport_req_id)
    aliases_mod.clear_held(cfg, name, req_id)
    if private:
        # Settled PRIVATELY: the file under this id in the outbox is not the
        # request this verdict answers (or no longer this generation's to
        # write), so nothing is published there and nothing is archived.
        return result["outcome"]
    result_bytes = json.dumps(result, sort_keys=True).encode("utf-8")
    _publish_result_and_archive(cfg, name, req_id, result_bytes)
    return result["outcome"]


def _write_anchor(
    cfg: RouterConfig, name: str, req_id: str, result: Dict[str, Any],
    *, req_digest: Optional[str], transport_req_id: Optional[str] = None,
) -> None:
    """The private idempotency anchor alone (`_finish`'s first step). An
    anchor settled from an in-flight record also records the transport id
    that record held (`transport_req_id`): proof, whatever the verdict, that
    the id was allocated, which a successor generation's counter must never
    go below (`generations.next_counter`)."""
    envelope = {"digest": req_digest, "result": result}
    if transport_req_id is not None:
        envelope["transport_req_id"] = transport_req_id
    atomic_write(_private_result_path(cfg, name, req_id),
                 json.dumps(envelope, sort_keys=True).encode("utf-8"),
                 durable_root=cfg.state_dir)


def _publish_result_and_archive(
    cfg: RouterConfig, name: str, req_id: str, result_bytes: bytes
) -> None:
    """Publish the namespace-visible result, then move the drained request
    into `outbound/processed/`. The move is a courtesy archive for the
    connector's convenience only — nothing in this router ever reads
    `processed/` back to decide anything (the idempotency anchor lives in
    `state_dir`, see `_finish`). Per AMAP v2.2.0 §2 "Deletion rights," a
    connector MAY delete `outbound/processed/` at will; this function
    simply recreates the directory and the archived copy on the next
    drain that touches this req_id (see the D4 resume path in
    `drain_instance`), so a connector deleting it is not a durability
    concern for the router.

    REMOVES the old `verify_namespace_containment(root, ...)` + `atomic_
    write`/`os.replace` pairing this used for both the results write and
    the archive move. That pairing is ROUTER-SECURITY.md Finding 1's exact
    shape — the identity-forgery bug: `results_path`/`dst` were each
    checked by resolving a path string, then acted on by resolving the
    SAME path string again, independently; an agent that swaps `processed`
    (or `results`) for a symlink to a VICTIM instance's own `outbound/` in
    the gap between those two resolutions gets its own request moved into
    the victim's outbox, where it is attributed by namespace and can be
    sent AS the victim (reproduced 138/3000 in the adversarial review that
    found it, with a downstream proof showing a forged `from:` address).
    ADDS pinned-fd writes/renames instead: `results/` and `processed/` are
    each descended into via `attachments_mod._mkdir_descend_pinned`/`_mkdir_
    and_pin` — `O_NOFOLLOW` at every component, from `root` (the
    containment ANCHOR — see `InstanceConfig.root`'s docstring; NOT
    `outbox_root`, which would be a tautology if `outbox_root` is exactly
    the directory an agent replaced) — and the results write and the
    archive move both happen `dir_fd`-relative off those pinned
    descriptors (`attachments_mod._write_blob_pinned` / a `dir_fd`-relative
    `os.rename`). Neither operation ever resolves a path string a second
    time for the actual act, so there is no window left between "checked"
    and "acted on" for a symlink swap to land in.

    Also REMOVES the separate `src.is_file()` pre-check that used to guard
    the archive move (itself a lesser check-then-act: `is_file()` follows
    symlinks and resolves the path independently of the `os.replace` that
    followed it). The `dir_fd`-relative `os.rename` below is attempted
    unconditionally instead and its `FileNotFoundError` is the (now
    race-free) way "nothing to archive" is detected — matching the same
    case the old pre-check covered (already archived by an earlier
    attempt), without a separate resolution to race against the rename
    itself. `os.rename`, dir_fd-relative or not, never dereferences a
    symlink named at the SOURCE position either — if `filename` were ever
    a symlink (it never legitimately is one reaching this function:
    `list_outbound` excludes symlinked entries before a filename is ever
    queued for processing), the rename would relocate the link entry
    itself, never write through whatever it points at.

    ALSO handles the case where `results/` or `processed/` themselves
    cannot be used at all — an agent that replaces either with a FIFO,
    socket, symlink, or hard link makes `_mkdir_and_pin` refuse
    (`NamespaceEscapeError`) every single time, pinning this request in
    `outbound/` permanently: before this fix, that exception was never
    caught HERE, so it escaped to `drain_instance`'s per-request
    `try/except` instead, which counts it `outbound_errored` and retries
    the whole pin attempt on every future poll, forever (self-inflicted —
    the agent broke its OWN outbox — but still the one remaining
    "reprocessed forever" shape the v3.0.0 sweep set out to eliminate).
    The private result under `state_dir` (written by `_finish` BEFORE this
    function runs — see that function's docstring) is already the
    authoritative answer to this request regardless of whether either
    namespace-visible copy below ever lands, so on either step's refusal
    this function logs once and, in the `finally` below, removes
    `req-<id>.json` from `outbound/` directly (a pinned, `dir_fd`-relative
    `unlink` — never a second path-based act) rather than leaving it for
    endless retry (mirrors the equivalent SER `_finish`'s own fallback
    unlink in this sibling repo's twin site)."""
    inst = cfg.instances[name]
    root = inst.root  # containment ANCHOR — see InstanceConfig.root's docstring
    outbox_root = inst.outbox_root
    filename = f"req-{req_id}.json"
    archived = False
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        # Never publish into, or archive out of, a root the instance's current
        # generation did not record (see `_pin_own_root`).
        attachments_mod._check_root(root_fd, generations_mod.expected_root(cfg, name))
        outbox_fd = attachments_mod._mkdir_descend_pinned(
            root_fd, outbox_root.relative_to(root)
        )
        try:
            try:
                results_fd = attachments_mod._mkdir_and_pin(outbox_fd, "results")
                try:
                    attachments_mod._write_blob_pinned(
                        results_fd, f"{req_id}.json", result_bytes
                    )
                finally:
                    os.close(results_fd)
            except attachments_mod.PublishedNotDurable as e:
                # The Result IS visible, but its directory barrier failed, so
                # it may not survive a power loss. The request stays in the
                # outbox, unarchived: the next poll's resume re-publishes it
                # from the private result (no resend) and only then archives
                # it. Archiving now would leave nothing to retry from.
                logger.warning(
                    "instance %r req %r: outbound/results/%s.json was published "
                    "but its directory was not made durable (%s); the request "
                    "is left unarchived and the Result is re-published from the "
                    "private result next poll", name, req_id, req_id, e,
                )
                return
            except (NamespaceEscapeError, OSError) as e:
                logger.warning(
                    "instance %r req %r: could not publish outbound/results/"
                    "%s.json (%s: %s) -- the private result under state_dir "
                    "is still authoritative; continuing so this request is "
                    "not retried forever", name, req_id, req_id,
                    type(e).__name__, e,
                )

            try:
                try:
                    processed_fd = attachments_mod._mkdir_and_pin(outbox_fd, "processed")
                    try:
                        try:
                            os.rename(
                                filename, filename,
                                src_dir_fd=outbox_fd, dst_dir_fd=processed_fd,
                            )
                            archived = True
                            _sync_archive(name, req_id, processed_fd, outbox_fd)
                        except FileNotFoundError:
                            pass  # nothing to archive (already archived by an
                                  # earlier attempt at this req_id) — see docstring
                    finally:
                        os.close(processed_fd)
                except (NamespaceEscapeError, OSError) as e:
                    logger.warning(
                        "instance %r req %r: could not archive into outbound/"
                        "processed/ (%s: %s) -- removing %s from outbound/ "
                        "directly instead so this is not retried forever "
                        "(the private result is already authoritative)",
                        name, req_id, type(e).__name__, e, filename,
                    )
            finally:
                if not archived:
                    # Reached whether `processed/` was unusable (above) or
                    # `filename` was simply already gone (the benign
                    # `FileNotFoundError` case) -- idempotent either way.
                    try:
                        os.unlink(filename, dir_fd=outbox_fd)
                    except FileNotFoundError:
                        pass
                    except OSError as e:
                        logger.warning(
                            "instance %r req %r: could not remove %s from "
                            "outbound/ after failing to archive it (%s: %s) "
                            "-- may be retried next poll; the private result "
                            "is still authoritative", name, req_id, filename,
                            type(e).__name__, e,
                        )
        finally:
            os.close(outbox_fd)
    finally:
        os.close(root_fd)

    # The sidecar dir (if any) is now consumed either way — the request
    # has been answered and archived. Sweep it via the SAME pinned-fd
    # engine `reset.py` uses (never a path-based branch); running this
    # unconditionally (whether or not this request ever had attachments,
    # and on the D4 resume/reused paths too, since both call this
    # function) also cleans up any leftover dir from a crashed earlier
    # attempt. Best-effort: never lets a cleanup failure affect the result
    # already published above.
    try:
        attachments_mod.remove_outbound_sidecar_dir(cfg, name, req_id)
    except Exception:
        logger.exception(
            "instance %r req %r: failed sweeping the consumed attachment "
            "sidecar dir (non-fatal — the result above is authoritative)",
            name, req_id,
        )


def _sync_archive(name: str, req_id: str, processed_fd: int, outbox_fd: int) -> None:
    """The archive rename's barriers: `processed/` (the name arrived) and
    then the outbox (the name left). The rename has happened, so a failure
    cannot be retried from here: it is logged, and the private result stays
    authoritative."""
    for label, fd in (("processed/", processed_fd), ("the outbox", outbox_fd)):
        try:
            os.fsync(fd)
        except OSError as e:
            logger.warning(
                "instance %r req %r: archived, but %s was not made durable "
                "(%s: %s); the private result is still authoritative",
                name, req_id, label, type(e).__name__, e,
            )


def _quarantine_one(
    cfg: RouterConfig, name: str, filename: str, req_id: str,
    marker_doc: Dict[str, Any], req_digest: str, raw: bytes,
) -> str:
    """Called only when `filename` is a member of the first-sight
    snapshot (`firstsight.quarantined_filenames`) AND its current bytes were
    successfully read. Preserves a router-private copy for the operator,
    then answers via `_finish` with a fixed `rejected`/
    `REASON_QUARANTINED` result — exactly like any other governed outcome:
    written once, the request archived, no notice ever sent to any
    recipient. See `router/firstsight.py`'s module docstring for what the
    quarantine check does and does not guarantee."""
    first_seen_ts = marker_doc.get("first_seen_ts")
    q_dir = gen_state_dir(cfg, name) / "quarantine"
    try:
        atomic_write(q_dir / filename, raw)
        snap_entry = next(
            (
                e for e in (marker_doc.get("outbox_snapshot") or [])
                if isinstance(e, dict) and e.get("filename") == filename
            ),
            None,
        )
        sidecar = {
            "req_id": req_id,
            "filename": filename,
            "first_seen_ts": first_seen_ts,
            "snapshot_digest": snap_entry.get("sha256") if snap_entry else None,
            "current_digest": req_digest,
            "quarantined_ts": utc_ts(),
        }
        atomic_write(
            q_dir / f"{filename}.meta.json",
            json.dumps(sidecar, sort_keys=True).encode("utf-8"),
        )
    except OSError:
        # Best-effort operator visibility only — the reject result below
        # (published into outbox_root/results/ and archived) is what
        # actually governs whether this request was delivered, and that
        # path is not skipped just because the private preservation copy
        # failed to write.
        logger.exception(
            "instance %r req %r: failed writing router-private quarantine "
            "copy (continuing — the rejection result is still authoritative)",
            name, req_id,
        )

    result = _result_doc(
        req_id, "rejected", reason_code=REASON_QUARANTINED,
        detail=(
            f"outbox entry {filename!r} was already present when this router "
            f"first saw the instance ({first_seen_ts!r}) — staged-request "
            f"quarantine, never delivered; resubmit under a fresh req_id"
        ),
    )
    return _finish(cfg, name, req_id, result, req_digest=req_digest)


# ---------------------------------------------------------------------------
# HELD LOCAL DELIVERY, and every direct placement's intent record
#
# Under a registry, a LOCAL target the poll's report does not resolve is
# HELD, not failed (`config.target_hold`). AMAP gives a Runtime exactly one,
# terminal Result per consumed request and a closed outcome vocabulary, so
# "held" cannot be a Result: the request stays in `outbound/`, unconsumed,
# and the sender sees only "not yet". The operator sees the hold, with its
# reason, in status.json and in one audit line per transition.
#
# The state lives in a router-private PENDING RECORD per request,
# `state_dir/<sender>/pending/<req_id>.json`, written durably (file and
# directory fsync) at every transition:
#
#   * each target is `held` | `ready` | `delivering` | `delivered` | `failed`;
#   * before ANY placement for a target, the record moves it to
#     `delivering` with its full identity: a PRE-MINTED notice_id and ts,
#     the recipient's logical_id and the delivery kind. A crash anywhere
#     after that is recovered by REPLAYING the placement with the SAME
#     identity through the whole notice-last sequence, and the target is
#     `delivered` only once that placement returned. The ledger cannot be
#     the completion test: it is written BEFORE the notice. So the guarantee
#     is one stable notice id and ledger path per (request, recipient),
#     offered at least once, never two ids, never a lost notice once a
#     barrier has succeeded. A consumer that must not act twice dedups by id;
#   * a target whose name resolves to a DIFFERENT logical_id than the one
#     it was bound to holds as `identity_changed`; a retry is never
#     rerouted to whoever acquired the name;
#   * a reply's binding is PINNED at its first eligible evaluation (it
#     resolved, and passed the reply window then), together with the
#     request digest, so waiting in a hold cannot age it out. Fresh policy
#     still applies every poll, and a refusal is terminal and reports the
#     recipients already delivered to;
#   * when no target is still pending, the request gets its ONE Result
#     (from the delivered and failed sets, as an unheld drain would have
#     answered) and the record is removed.
#
# A damaged record fails closed: the request holds and the operator sees it.
# Holds exist only under a registry. The record itself also carries every
# DIRECT local placement (`ORIGIN_DIRECT`), with or without one: written
# before anything is placed, so a failure after placement (the private
# anchor, say) is answered from it instead of placing a second notice.
# ---------------------------------------------------------------------------

#: `drain_instance`'s tally for a request left pending this poll.
HELD = "held"
PENDING_DIR = "pending"
#: Version 2 carries a private snapshot of the request and its attachments
#: (PENDING SNAPSHOTS, below); version 1 records (no snapshot) are still read.
PENDING_VERSION = 2
#: A record that pins a NON-EMPTY alias map (`aliases`): an older router
#: holds it as damaged rather than re-run its policy on the old address.
PENDING_VERSION_ALIASED = 3
_PENDING_VERSIONS = (1, 2, 3)
#: Every member each version's writers and mutators have produced: version 1
#: as held local delivery first wrote it; version 2 adds the snapshot, the source
#: generation and the pinned sender (and, since the alias table, `aliases`
#: with each target's `address`, both or neither); version 3 is version 2
#: with a non-empty `aliases`. Anything else is damage.
_PENDING_KEYS_V1 = frozenset({"v", "req_id", "request_sha256", "kind", "sender_lid",
                              "created_ts", "block", "binding", "targets"})
_PENDING_KEYS_V2 = _PENDING_KEYS_V1 | {"snapshot", "source_gen", "from_address", "aliases",
                                       "origin"}
#: `origin` on a record made by a DIRECT placement (no target held when it
#: began): the record is the placement's intent, written before anything is
#: placed, so a failure after placement (the private anchor, say) replays the
#: same identity instead of minting a second notice. A non-held delivery
#: failure is then terminal for that target, as it always was on the direct
#: paths. Absent: a record made because a target was held, whose failing
#: targets are replayed every poll.
ORIGIN_DIRECT = "direct"
_TARGET_KEYS = frozenset({"recipient", "kind", "lid", "state", "reason", "notice_id", "ts",
                          "message_id", "error", "recipient_gen", "address"})
_TARGET_STATES = frozenset({"held", "ready", "delivering", "delivered", "failed"})
_PENDING_KINDS = frozenset({"mail", "peer"})
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
#: Request-level blocks: the request itself can no longer be trusted to be
#: the one the record was made for, or the route policy now chooses differs.
BLOCK_REQUEST_MISSING = "request_missing"
BLOCK_REQUEST_UNREADABLE = "request_unreadable"
BLOCK_REQUEST_CHANGED = "request_changed"
BLOCK_ATTACHMENTS_CHANGED = "attachments_changed"
BLOCK_ROUTE_CHANGED = "route_changed"
#: A snapshot that no longer matches the digests its record names.
BLOCK_SNAPSHOT_DAMAGED = "snapshot_damaged"
#: A fenced generation's version-1 record: no snapshot to replay from, and
#: the live entry is no longer this generation's to read.
BLOCK_LEGACY_SNAPSHOT_MISSING = "legacy_snapshot_missing"
HOLD_IDENTITY_CHANGED = "identity_changed"
#: A placement begun (`delivering`) for a recipient whose generation has
#: changed since: never continued into the new generation's root. No
#: automatic outcome; the sender sees "not yet" (router/README.md, runbook).
HOLD_RECIPIENT_GENERATION_CHANGED = "recipient_generation_changed"
#: An injected delivery backend that cannot take the pre-minted identity:
#: held, never placed with a fresh one.
HOLD_BACKEND_NO_PRESET = "backend_no_preset"
#: An injected backend that cannot take a pending record's pinned sender
#: address: held, never sent from a re-derived one.
HOLD_BACKEND_NO_FROM = "backend_no_from_address"


class PendingDamaged(Exception):
    """A pending record that cannot be trusted. The request holds."""


def _pending_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return gen_state_dir(cfg, name) / PENDING_DIR / f"{req_id}.json"


def _str_or_none(v: Any) -> bool:
    return v is None or (isinstance(v, str) and bool(v))


def _check_target(t: Any) -> None:
    if not isinstance(t, dict) or not isinstance(t.get("recipient"), str) or not t["recipient"]:
        raise PendingDamaged("target")
    if not set(t) <= _TARGET_KEYS:
        raise PendingDamaged(f"target members {sorted(set(t) - _TARGET_KEYS)}")
    if t.get("state") not in _TARGET_STATES:
        raise PendingDamaged("target state")
    for k in ("lid", "reason", "message_id", "error", "recipient_gen"):
        if not _str_or_none(t.get(k)):
            raise PendingDamaged(f"target {k}")
    if t.get("kind") not in _PENDING_KINDS:
        raise PendingDamaged("target kind")
    # The identity rule for EVERY state a target can reach: held/ready have
    # none; delivering/delivered must have one; failed has one iff it failed
    # after becoming delivering (always, here; either is consistent).
    nid, ts = t.get("notice_id"), t.get("ts")
    has = nid is not None or ts is not None
    valid = isinstance(nid, str) and bool(_HEX32.fullmatch(nid)) and parse_utc_ts(ts) is not None
    if t["state"] in ("delivering", "delivered"):
        if not valid:
            raise PendingDamaged("delivering identity")
    elif t["state"] == "failed":
        if has and not valid:
            raise PendingDamaged("failed identity")
    elif has:
        raise PendingDamaged("identity before delivering")


def _check_pending(doc: Any, req_id: str) -> Dict[str, Any]:
    """The record, or PendingDamaged. Strict: anything unexpected is damage."""
    if not isinstance(doc, dict) or doc.get("v") not in _PENDING_VERSIONS:
        raise PendingDamaged("version")
    allowed = _PENDING_KEYS_V1 if doc["v"] == 1 else _PENDING_KEYS_V2
    if not set(doc) <= allowed:
        raise PendingDamaged(f"members {sorted(set(doc) - allowed)}")
    if doc["v"] in (2, 3):
        snap = doc.get("snapshot")
        if not (isinstance(snap, dict) and isinstance(snap.get("nonce"), str)
                and _HEX32.fullmatch(snap["nonce"])
                and isinstance(snap.get("attachments"), list)):
            raise PendingDamaged("snapshot")
        for a in snap["attachments"]:
            if not (isinstance(a, dict) and isinstance(a.get("size_bytes"), int)
                    and isinstance(a.get("sha256"), str) and _HEX64.fullmatch(a["sha256"])
                    and isinstance(a.get("filename"), str)
                    and isinstance(a.get("media_type"), str)):
                raise PendingDamaged("snapshot attachment")
        if not _str_or_none(doc.get("source_gen")) or not _str_or_none(doc.get("from_address")):
            raise PendingDamaged("source_gen/from_address")
    if "origin" in doc and doc["origin"] != ORIGIN_DIRECT:
        raise PendingDamaged("origin")
    if doc.get("req_id") != req_id:
        raise PendingDamaged("req_id")
    if not (isinstance(doc.get("request_sha256"), str) and _HEX64.fullmatch(doc["request_sha256"])):
        raise PendingDamaged("request_sha256")
    if doc.get("kind") not in _PENDING_KINDS:
        raise PendingDamaged("kind")
    if not _str_or_none(doc.get("block")) or not _str_or_none(doc.get("sender_lid")):
        raise PendingDamaged("block/sender_lid")
    if parse_utc_ts(doc.get("created_ts")) is None:
        raise PendingDamaged("created_ts")
    targets = doc.get("targets")
    if not isinstance(targets, list) or not targets:
        raise PendingDamaged("targets")
    for t in targets:
        _check_target(t)
    if len({t["recipient"] for t in targets}) != len(targets):
        raise PendingDamaged("duplicate target")
    # Aliases: the map and each target's address together or not at all;
    # each address the target's own; each alias value one of them; and a
    # non-empty map exactly when the record is version 3.
    has_map = "aliases" in doc
    if any(("address" in t) != has_map for t in targets):
        raise PendingDamaged("aliases and target addresses must come together")
    if has_map:
        amap = doc["aliases"]
        if not (isinstance(amap, dict) and all(isinstance(k, str) and isinstance(v, str)
                                               for k, v in amap.items())):
            raise PendingDamaged("aliases")
        addrs = set()
        for t in targets:
            a = t["address"]
            # The target's own address in either form `address_for` gives:
            # `<name>@<fleet_domain>`, or the legacy `agent.<name>@local`
            # without a fleet domain (a direct record has no registry).
            if not (isinstance(a, str) and a.count("@") == 1
                    and (a == address_for(t["recipient"])
                         or (a.split("@")[0] == t["recipient"] and a.split("@")[1]))):
                raise PendingDamaged("target address")
            addrs.add(a)
        if not set(amap.values()) <= addrs:
            raise PendingDamaged("an alias maps to no target")
    if (doc["v"] == PENDING_VERSION_ALIASED) != bool(doc.get("aliases")):
        raise PendingDamaged("a non-empty alias map is version 3, and only it")
    pin = doc.get("binding")
    if pin is not None:
        if (not isinstance(pin, dict) or len(targets) != 1
                or pin.get("bound_instance") != targets[0]["recipient"]
                or not isinstance(pin.get("in_reply_to"), str)
                or not isinstance(pin.get("record"), dict)
                or parse_utc_ts(pin.get("evaluated_ts")) is None
                or not isinstance(pin.get("window_ok"), bool)):
            raise PendingDamaged("binding")
    return doc


def _read_pending(path: Path, req_id: str) -> Dict[str, Any]:
    try:
        raw = read_capped(path, DEFAULT_READ_CAP)
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ReadTooLargeError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise PendingDamaged(f"unreadable: {type(e).__name__}") from None
    return _check_pending(doc, req_id)


def _write_pending(cfg: RouterConfig, path: Path, rec: Dict[str, Any]) -> None:
    """Durably: the file, its directory, and every new parent (`atomic_write`
    with `durable_root`). A failure RAISES, and nothing that depends on the
    write happens."""
    atomic_write(path, json.dumps(rec, sort_keys=True).encode("utf-8"),
                 durable_root=cfg.state_dir)


def _remove_pending(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    fsync_dir(path.parent)


def _audit_held(cfg: RouterConfig, name: str, req_id: str, target: Dict[str, Any]) -> None:
    """One line per transition of a target's hold reason (best-effort: the
    record, not the log, is the state)."""
    try:
        audit_mod.append(
            cfg.state_dir, name, audit_mod.EVENT_DELIVERY_HELD,
            state_key=state_key(cfg, name), req_id=req_id,
            recipient=target["recipient"], reason=target["reason"], kind=target["kind"],
        )
    except (audit_mod.AuditError, OSError) as e:
        logger.warning("instance %r req %r: could not audit a hold (%s: %s)",
                       name, req_id, type(e).__name__, e)


def _hold_reason(cfg: RouterConfig, target: Dict[str, Any]) -> Optional[str]:
    """This poll's reason to hold `target`, or None. A non-instance target
    (a custom policy's) is not gated here; its backend owns it."""
    r = target["recipient"]
    if r not in cfg.instances:
        return None
    reason = target_hold(cfg, r)
    if reason is None and target.get("lid") is not None and \
            target_logical_id(cfg, r) != target["lid"]:
        return HOLD_IDENTITY_CHANGED
    if reason is None and target["state"] == "delivering" \
            and target.get("recipient_gen") is not None \
            and _recipient_gen(cfg, r) != target["recipient_gen"]:
        # Begun under the recipient's earlier generation: never continued
        # into its new root (router/README.md, "recipient_generation_changed").
        return HOLD_RECIPIENT_GENERATION_CHANGED
    return reason


def _recipient_gen(cfg: RouterConfig, recipient: str) -> Optional[str]:
    """The recipient's current generation id this poll, or None without one."""
    key = cfg.gen_keys.get(recipient)
    if key is None:
        return None
    return key.partition("/")[2][len(generations_mod.GEN_PREFIX):]


def _placement_origin(backend: Optional[Callable[..., Any]]) -> Optional[str]:
    """`ORIGIN_DIRECT` when a direct placement can go through an intent record:
    its backend takes the pre-minted identity and the pinned sender. A
    backend that cannot is placed directly, as before, and a failure after
    its placement can still re-place (router/README.md)."""
    if backend is None:
        return ORIGIN_DIRECT
    return ORIGIN_DIRECT if _accepts_preset(backend) and _accepts_kw(backend, "from_address") \
        else None


def _any_held(cfg: RouterConfig, recipients: List[str]) -> bool:
    return cfg.registry_dir is not None and any(
        r in cfg.instances and target_hold(cfg, r) is not None for r in recipients)


# ---------------------------------------------------------------------------
# PENDING SNAPSHOTS (version 2)
#
# A pending request is a complete, immutable PRIVATE transaction: before its
# record exists, the raw request bytes and every verified attachment are
# written as private files in `pending/<req_id>.<nonce>.snap/` (each durable,
# then the directory), and the record names them by digest and nonce. A
# reused req_id can therefore never adopt an orphan snapshot. Every replay
# re-verifies the digests (`snapshot_damaged` holds otherwise). Completion
# order: the anchor, then the record, then the snapshot directory; a crash at
# any point leaves either a record to finish or an orphan the sweep removes
# once the anchor exists. The current generation still checks the live entry
# every poll; a FENCED generation replays from its snapshot alone.
# ---------------------------------------------------------------------------

def _snap_dir(cfg: RouterConfig, name: str, req_id: str, nonce: str) -> Path:
    return gen_state_dir(cfg, name) / PENDING_DIR / f"{req_id}.{nonce}.snap"


def _write_snapshot(cfg: RouterConfig, name: str, req_id: str, raw: bytes,
                    attachments: List[attachments_mod.VerifiedAttachment]) -> Dict[str, Any]:
    """Write the snapshot files, durably, and return the record's
    `snapshot` member. Nothing names them until the record is written."""
    nonce = secrets.token_hex(16)
    d = _snap_dir(cfg, name, req_id, nonce)
    atomic_write(d / "request", raw, durable_root=cfg.state_dir)
    for i, att in enumerate(attachments):
        atomic_write(d / f"a{i}", att.data, durable_root=cfg.state_dir)
    return {"nonce": nonce, "attachments": [
        {"filename": a.filename, "media_type": a.media_type, "size_bytes": a.size_bytes,
         "sha256": a.sha256} for a in attachments]}


class SnapshotDamaged(Exception):
    """The snapshot does not match its record."""


def _read_snapshot(cfg: RouterConfig, name: str, rec: Dict[str, Any]
                   ) -> Tuple[bytes, Dict[str, Any], List[attachments_mod.VerifiedAttachment]]:
    """`(raw, doc, attachments)` from a version-2 record's snapshot, every
    digest re-verified. Raises `SnapshotDamaged`."""
    snap = rec["snapshot"]
    d = _snap_dir(cfg, name, rec["req_id"], snap["nonce"])
    try:
        raw = read_capped(d / "request", DEFAULT_READ_CAP)
    except (OSError, ReadTooLargeError) as e:
        raise SnapshotDamaged(f"request: {type(e).__name__}") from None
    if hashlib.sha256(raw).hexdigest() != rec["request_sha256"]:
        raise SnapshotDamaged("request digest")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SnapshotDamaged("request is not JSON") from None
    out = []
    for i, a in enumerate(snap["attachments"]):
        try:
            data = read_capped(d / f"a{i}", a["size_bytes"])
        except (OSError, ReadTooLargeError) as e:
            raise SnapshotDamaged(f"attachment {i}: {type(e).__name__}") from None
        if len(data) != a["size_bytes"] or hashlib.sha256(data).hexdigest() != a["sha256"]:
            raise SnapshotDamaged(f"attachment {i} digest")
        out.append(attachments_mod.VerifiedAttachment(
            filename=a["filename"], media_type=a["media_type"], size_bytes=a["size_bytes"],
            sha256=a["sha256"], data=data))
    return raw, doc, out


def _remove_snapshot(cfg: RouterConfig, name: str, rec: Dict[str, Any]) -> None:
    """After the record: the snapshot directory goes, durably."""
    snap = rec.get("snapshot")
    if not snap:
        return
    d = _snap_dir(cfg, name, rec["req_id"], snap["nonce"])
    try:
        shutil.rmtree(d)
    except FileNotFoundError:
        return
    fsync_dir(d.parent)


def _begin_pending(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], *,
    kind: str, recipients: List[str], pin: Optional[Dict[str, Any]],
    req_digest: str, attachments: Optional[List[attachments_mod.VerifiedAttachment]],
    deliver_backend: Optional[deliver_mod.DeliveryBackend],
    settled: Optional[Dict[str, Optional[Dict[str, Any]]]] = None,
    aliases: Mapping[str, str],
    origin: Optional[str] = None,
) -> str:
    """Make the request pending (durably, before anything is placed) and
    advance whatever can go now: because a target is held, or (`origin` =
    `ORIGIN_DIRECT`) as every direct local placement's intent record, so a
    failure after placement replays the same identity. A reply's target is
    pinned to the logical_id its ledger record names (the identity the task
    came from), else the one the registry knows now. `settled` names targets
    already delivered (with their delivery) or failed (None) by the pass
    that discovered the hold mid-way."""
    pinned = {}
    if pin is not None and isinstance(pin.get("record"), dict) and pin["record"].get("from_lid"):
        pinned[pin["bound_instance"]] = pin["record"]["from_lid"]
    targets = []
    settled = settled or {}
    for r in recipients:
        if r in settled:
            d = settled[r]
            targets.append({
                "recipient": r, "kind": kind,
                "lid": pinned.get(r) or (target_known_id(cfg, r) if r in cfg.instances else None),
                "state": "delivered" if d else "failed", "reason": None,
                "notice_id": (d.get("notice_id") or mint_notice_id()) if d else None,
                "ts": utc_ts() if d else None,
                "message_id": d.get("message_id") if d else None,
                "error": None if d else "failed before the hold",
                "recipient_gen": _recipient_gen(cfg, r) if d else None,
            })
            continue
        reason = target_hold(cfg, r) if r in cfg.instances else None
        targets.append({
            "recipient": r, "kind": kind,
            # The identity the registry KNOWS now, held or not: a later rebind
            # of the name holds as identity_changed instead of rerouting.
            "lid": pinned.get(r) or (target_known_id(cfg, r) if r in cfg.instances else None),
            "state": "held" if reason else "ready", "reason": reason,
            "notice_id": None, "ts": None, "message_id": None, "error": None,
        })
    # The snapshot is of the bytes that were EVALUATED: re-read with the same
    # pinned read and required to carry their digest. If the agent changed
    # the file since, nothing is recorded or placed; the next poll takes the
    # new file from the start.
    try:
        raw = _read_request_pinned(cfg, name, f"req-{req_id}.json")
    except (ReadTooLargeError, OSError):
        raw = None
    if raw is None or hashlib.sha256(raw).hexdigest() != req_digest:
        if settled and any(settled.values()):
            # Placements this pass already made must still get the request's
            # one Result: without the evaluated bytes there is no snapshot to
            # hold on, so it is answered now, the held recipients as failed.
            for r in recipients:
                settled.setdefault(r, None)
            rec = {"kind": kind, "binding": pin, "targets": [
                {"recipient": r, "state": "delivered" if settled[r] else "failed",
                 "message_id": (settled[r] or {}).get("message_id")} for r in recipients]}
            return _finish(cfg, name, req_id, _pending_result(cfg, req_id, rec, attachments),
                           req_digest=req_digest)
        return HELD
    snapshot = _write_snapshot(cfg, name, req_id, raw, list(attachments or []))
    gen = cfg.gen_keys.get(name, "").partition("/")[2]
    rec = {
        "v": PENDING_VERSION, "req_id": req_id, "request_sha256": req_digest,
        "kind": kind, "sender_lid": target_logical_id(cfg, name),
        "source_gen": gen[len(generations_mod.GEN_PREFIX):] if gen else None,
        "from_address": address_for(name, cfg.fleet_domain),
        "created_ts": utc_ts(), "block": None, "binding": pin, "targets": targets,
        "snapshot": snapshot, "aliases": dict(aliases),
    }
    if origin is not None:
        rec["origin"] = origin
    for t in targets:
        t["address"] = address_for(t["recipient"], cfg.fleet_domain)
    if aliases:
        # An older router cannot honour a pinned alias: it would re-run its
        # policy on the OLD address and refuse it. Version 3 makes it hold the
        # record as damaged instead.
        rec["v"] = PENDING_VERSION_ALIASED
    path = _pending_path(cfg, name, req_id)
    _write_pending(cfg, path, rec)
    aliases_mod.clear_held(cfg, name, req_id)
    for t in targets:
        if t["state"] == "held":
            _audit_held(cfg, name, req_id, t)
    return _advance_pending(cfg, name, req_id, rec, doc, attachments, deliver_backend)


def _place_target(
    cfg: RouterConfig, name: str, target: Dict[str, Any], doc: Dict[str, Any],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]],
    reply_record: Optional[Dict[str, Any]],
    deliver_backend: Optional[deliver_mod.DeliveryBackend],
    from_address: Optional[str] = None,
) -> Dict[str, str]:
    preset = (target["notice_id"], target["ts"])
    pinned = {"from_address": from_address} if from_address is not None else {}
    if target["kind"] == "peer":
        return deliver_mod.deliver_peer(
            cfg, cfg.state_dir, name, target["recipient"], doc,
            reply_to_record=reply_record, attachments=attachments, preset=preset, **pinned)
    backend = deliver_backend if deliver_backend is not None else deliver_mod.deliver
    # Every backend path places with the PRE-MINTED identity; one that cannot
    # take it is refused BEFORE placement (a replay would otherwise mint a
    # second id and a second ledger record).
    if not _accepts_preset(backend):
        raise deliver_mod.RecipientHeld(target["recipient"], HOLD_BACKEND_NO_PRESET)
    if pinned and not _accepts_kw(backend, "from_address"):
        raise deliver_mod.RecipientHeld(target["recipient"], HOLD_BACKEND_NO_FROM)
    return backend(cfg, cfg.state_dir, name, target["recipient"], doc,
                   reply_to_record=reply_record, attachments=attachments, preset=preset,
                   **pinned)


def _accepts_kw(backend: Callable[..., Any], kw: str) -> bool:
    """True when `backend` takes keyword `kw` (named, or **kwargs)."""
    try:
        params = inspect.signature(backend).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == kw and p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD)
               or p.kind is p.VAR_KEYWORD for p in params)


def _accepts_preset(backend: Callable[..., Any]) -> bool:
    """True when `backend` takes a `preset` keyword (named, or **kwargs)."""
    try:
        params = inspect.signature(backend).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == "preset" and p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD)
               or p.kind is p.VAR_KEYWORD for p in params)


def _place_one(
    cfg: RouterConfig, name: str, req_id: str, rec: Dict[str, Any], t: Dict[str, Any],
    doc: Dict[str, Any], attachments: Optional[List[attachments_mod.VerifiedAttachment]],
    deliver_backend: Optional[deliver_mod.DeliveryBackend],
) -> bool:
    """One target that this poll's report resolves: durable `delivering`
    identity FIRST (on a replay too), then the placement with that identity,
    then `delivered`. A failure after placement began keeps it `delivering`,
    to be replayed with the SAME identity next poll; nothing here is
    terminal, except on a DIRECT record (`ORIGIN_DIRECT`), where a non-held
    failure fails the target as the direct paths always did (the commit
    writes the notice last, so a raise means no notice was placed). The one
    raise that does NOT mean that is `PublishedNotDurable`: a file was
    renamed into place and its directory barrier failed, so the notice may
    be visible. That target stays `delivering` and is replayed with the same
    identity, on every record. Returns True when the record changed without
    being written."""
    path = _pending_path(cfg, name, req_id)
    pin = rec.get("binding")
    if t["state"] in ("held", "ready"):
        if t["recipient"] in cfg.instances and t["lid"] is None:
            t["lid"] = target_logical_id(cfg, t["recipient"])   # never known until now
        t.update(state="delivering", notice_id=mint_notice_id(), ts=utc_ts(),
                 recipient_gen=_recipient_gen(cfg, t["recipient"]))
    t["reason"] = None
    # Durable BEFORE the recipient is touched, on a REPLAY too: a record can
    # be visible after its directory barrier failed, and a placement must
    # never rest on that. A rewrite with `durable_root` repairs the whole
    # chain; if it fails again, this raises and nothing is placed.
    _write_pending(cfg, path, rec)
    try:
        delivered = _place_target(cfg, name, t, doc, attachments,
                                  pin["record"] if pin else None, deliver_backend,
                                  from_address=rec.get("from_address"))
    except deliver_mod.RecipientHeld as e:
        if rec.get("origin") == ORIGIN_DIRECT:
            # The direct paths always took a hold met during the write as
            # "nothing placed, goes pending": delivery raises it before the
            # notice, which is written last. So the target re-enters as held
            # with no identity, and is placed afresh once it resolves (into
            # its new generation's root, if that is what changed).
            t.update(state="held", reason=e.reason, notice_id=None, ts=None,
                     recipient_gen=None)
            return True
        t["reason"] = e.reason              # identity kept: a later poll replays it
        return True
    except Exception as e:  # noqa: BLE001 — one target must not sink the request
        if rec.get("origin") == ORIGIN_DIRECT and not isinstance(
                e, attachments_mod.PublishedNotDurable):
            logger.warning(
                "instance %r req %r: delivery to %r failed, continuing with the remaining "
                "recipients: %s: %s", name, req_id, t["recipient"], type(e).__name__, e)
            t.update(state="failed", error=type(e).__name__, reason=None)
            _write_pending(cfg, path, rec)
            return False
        logger.warning(
            "instance %r req %r: delivery to %r failed: %s: %s — kept, replayed next poll "
            "with the same identity", name, req_id, t["recipient"], type(e).__name__, e)
        t["reason"] = f"failing: {type(e).__name__}"
        return True
    t.update(state="delivered", message_id=delivered.get("message_id"), reason=None)
    _write_pending(cfg, path, rec)
    return False


def _advance_pending(
    cfg: RouterConfig, name: str, req_id: str, rec: Dict[str, Any], doc: Dict[str, Any],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]],
    deliver_backend: Optional[deliver_mod.DeliveryBackend],
    *, settle_only: bool = False, private: bool = False,
) -> str:
    """Advance every target that this poll's report resolves (P4'), then
    answer the request iff nothing is still pending. `settle_only` replays
    only targets already `delivering` (a refusal must first know every
    placement it would report) and never answers. `private` settles the
    answer as an anchor alone (`_finish`)."""
    path = _pending_path(cfg, name, req_id)
    dirty = False
    for t in rec["targets"]:
        if t["state"] in ("delivered", "failed"):
            continue
        if settle_only and t["state"] != "delivering":
            continue
        reason = _hold_reason(cfg, t)
        if reason is not None:
            if t["state"] == "ready":
                t["state"] = "held"
            if t["reason"] != reason:
                t["reason"] = reason
                dirty = True
                _audit_held(cfg, name, req_id, t)
            continue
        dirty = _place_one(cfg, name, req_id, rec, t, doc, attachments, deliver_backend) or False
    if dirty:
        _write_pending(cfg, path, rec)
    if settle_only or any(t["state"] not in ("delivered", "failed") for t in rec["targets"]):
        return HELD
    outcome = _finish(cfg, name, req_id, _pending_result(cfg, req_id, rec, attachments),
                      req_digest=rec["request_sha256"], private=private)
    _remove_pending(path)
    _remove_snapshot(cfg, name, rec)
    return outcome


def _delivered_addrs(cfg: RouterConfig, rec: Dict[str, Any]) -> List[str]:
    return [address_for(t["recipient"], cfg.fleet_domain)
            for t in rec["targets"] if t["state"] == "delivered"]


def _pending_result(
    cfg: RouterConfig, req_id: str, rec: Dict[str, Any],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]],
) -> Dict[str, Any]:
    """The ONE Result, as the unheld drain would have answered the same
    delivered and failed sets."""
    delivered = [t for t in rec["targets"] if t["state"] == "delivered"]
    failed = sorted(t["recipient"] for t in rec["targets"] if t["state"] == "failed")
    addrs = _delivered_addrs(cfg, rec)
    diag = _attachments_accepted_diag(attachments or [])
    if rec["kind"] == "peer":
        ok_reason = REASON_PEER_ROUTED
    elif rec.get("binding") is not None:
        ok_reason = REASON_RECIPIENT_BOUND
    else:
        ok_reason = REASON_ALLOWLISTED
    message_id = delivered[0]["message_id"] if len(delivered) == 1 and not failed else None
    if not failed:
        return _result_doc(req_id, "accepted", reason_code=ok_reason, recipients=addrs,
                           message_id=message_id, attachments=diag)
    if delivered:
        return _result_doc(
            req_id, "accepted", reason_code=REASON_PARTIAL_DELIVERY, recipients=addrs,
            message_id=None,
            detail=f"delivered to {len(delivered)}; failed for: {', '.join(failed)}",
            attachments=diag)
    if rec.get("origin") == ORIGIN_DIRECT and (rec["kind"] == "peer" or rec.get("binding")):
        # The single-target direct paths' own wording (a reply, a peer route).
        (t,) = rec["targets"]
        return _result_doc(
            req_id, "queued_for_human", reason_code=REASON_DELIVERY_FAILED, recipients=[],
            detail=f"delivery to {t['recipient']!r} failed: {t['error']}")
    return _result_doc(
        req_id, "queued_for_human", reason_code=REASON_DELIVERY_FAILED, recipients=[],
        detail=f"no recipient could be delivered to: {', '.join(failed)}")


def _pending_refusal(
    cfg: RouterConfig, req_id: str, rec: Dict[str, Any],
    outcome: str, reason_code: str, detail: Optional[str],
) -> Dict[str, Any]:
    """A fresh policy refusal is terminal, and reports what was already
    delivered rather than erasing it."""
    addrs = _delivered_addrs(cfg, rec)
    if addrs:
        detail = (f"{detail + '; ' if detail else ''}already delivered to "
                  f"{len(addrs)} recipient(s) before the refusal")
        return _result_doc(req_id, outcome, reason_code=reason_code, detail=detail,
                           recipients=addrs)
    return _result_doc(req_id, outcome, reason_code=reason_code, detail=detail)


def _pending_policy(
    cfg: RouterConfig, name: str, rec: Dict[str, Any], doc: Dict[str, Any],
    cold_policy: Optional[ColdPolicy],
) -> Union[None, str, ColdRefusal]:
    """This poll's policy for a pending request: None (proceed), a
    ColdRefusal (terminal), or BLOCK_ROUTE_CHANGED (the route policy now
    chooses is not the one the record was made for: hold, never reroute)."""
    recipients = [t["recipient"] for t in rec["targets"]]
    pin = rec.get("binding")
    if pin is None:
        policy = cold_policy if cold_policy is not None else default_cold_policy
        decided = policy(cfg, name, aliases_mod.apply_pinned(doc["draft"],
                                                             _pinned_map(cfg, rec)))
        if isinstance(decided, ColdRefusal):
            return decided
        if rec["kind"] == "peer":
            same = isinstance(decided, PeerRoute) and [decided.recipient] == recipients
        else:
            same = isinstance(decided, list) and sorted(decided) == sorted(recipients)
        return None if same else BLOCK_ROUTE_CHANGED
    bound = pin["bound_instance"]
    if bound == name:
        return ColdRefusal("rejected", REASON_SELF_SEND)
    if bound not in cfg.instances:
        return ColdRefusal("rejected", REASON_UNRESOLVED_REPLY)
    if rec["kind"] == "peer":
        if cfg.instances[bound].peer_root is None:
            return ColdRefusal("rejected", REASON_UNRESOLVED_REPLY)
        # The window was proven at the first eligible evaluation and is not
        # re-measured; a declared edge is checked FRESH.
        if not (pin["window_ok"] or binding.check_peer_edge(cfg, name, bound)):
            return ColdRefusal("rejected", REASON_PEER_REPLY_WINDOW_EXPIRED)
    return None


def _pinned_map(cfg: RouterConfig, rec: Dict[str, Any]) -> Dict[str, str]:
    """How a pending record's draft addresses its PINNED targets this poll:
    each target's pin-time address, and each alias pinned to it, map to that
    same target's address as the fleet names it NOW. So a later domain flip,
    expiry or table edit never refuses or retargets the work; the target's
    identity is still checked against its pinned lid (`identity_changed`).
    A record made before aliases (no `aliases`, no addresses) maps nothing."""
    if "aliases" not in rec:
        return {}
    now = {t["address"]: address_for(t["recipient"], cfg.fleet_domain) for t in rec["targets"]}
    out = dict(now)
    for old, new in (rec.get("aliases") or {}).items():
        out[old] = now.get(new, new)
    return out


def _block(cfg: RouterConfig, name: str, req_id: str, rec: Dict[str, Any], why: str) -> str:
    if rec.get("block") != why:
        rec["block"] = why
        _write_pending(cfg, _pending_path(cfg, name, req_id), rec)
        logger.warning("instance %r req %r: pending request blocked: %s", name, req_id, why)
    return HELD


def _drain_pending(
    cfg: RouterConfig, name: str, filename: str, req_id: str,
    *, deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None, fenced: bool = False,
) -> str:
    """One poll for a request that has a pending record.

    Version 2 (a snapshot): the request, its attachments and the policy are
    all taken from the SNAPSHOT. In the current generation the live entry is
    read too: gone, the work continues and the Result is published (nothing
    to archive); the same bytes, as ever; DIFFERENT (a reused id), the old
    work continues and settles PRIVATELY, after which the live file is
    refused as `req_id_reused`. In a FENCED generation (`fenced`), the
    snapshot is the only source, and the Result is published only if the
    root is still the one the generation recorded and the live entry is the
    same request; otherwise it settles privately.

    Version 1 (no snapshot): as before, the live entry must still be the
    request; a fenced generation's version-1 record holds
    (`legacy_snapshot_missing`)."""
    try:
        rec = _read_pending(_pending_path(cfg, name, req_id), req_id)
    except PendingDamaged as e:
        logger.warning("instance %r req %r: pending record damaged (%s) — held, "
                       "nothing delivered", name, req_id, e)
        return HELD
    if rec["v"] == 1:
        if fenced:
            return _block(cfg, name, req_id, rec, BLOCK_LEGACY_SNAPSHOT_MISSING)
        return _drain_pending_v1(cfg, name, filename, req_id, rec,
                                 deliver_backend=deliver_backend, cold_policy=cold_policy)
    try:
        _raw, doc, attachments = _read_snapshot(cfg, name, rec)
    except SnapshotDamaged as e:
        logger.warning("instance %r req %r: pending snapshot damaged (%s) — held",
                       name, req_id, e)
        return _block(cfg, name, req_id, rec, BLOCK_SNAPSHOT_DAMAGED)
    try:
        live = _live_differs(cfg, name, req_id, rec["request_sha256"])
    except OSError:
        return HELD                        # a transient fault decides nothing
    private = live or (fenced and not _same_root(cfg, name))
    if live and not fenced:
        generations_mod.note_reuse_pending(cfg, name, req_id)
    decided = _pending_policy(cfg, name, rec, doc, cold_policy)
    if decided == BLOCK_ROUTE_CHANGED:
        return _block(cfg, name, req_id, rec, BLOCK_ROUTE_CHANGED)
    if isinstance(decided, ColdRefusal):
        return _refuse_pending(cfg, name, req_id, rec, doc, attachments, decided,
                               deliver_backend, private=private)
    if rec.get("block") is not None:
        rec["block"] = None
        _write_pending(cfg, _pending_path(cfg, name, req_id), rec)
    return _advance_pending(cfg, name, req_id, rec, doc, attachments, deliver_backend,
                            private=private)


def _same_root(cfg: RouterConfig, name: str) -> bool:
    """Whether `name`'s root is still the one its generation (as `cfg` keys
    it) recorded. Without a registry, always."""
    try:
        expected = generations_mod.expected_root(cfg, name)
        if expected is None:
            return True
        seen = generations_mod.root_identity(cfg.instances[name].root)
    except (LookupError, generations_mod.GenerationHeld):
        return False
    return (seen["st_dev"], seen["st_ino"]) == expected


def _refuse_pending(cfg: RouterConfig, name: str, req_id: str, rec: Dict[str, Any],
                    doc: Dict[str, Any], attachments, decided: "ColdRefusal",
                    deliver_backend, *, private: bool = False) -> str:
    """A fresh policy refusal for a pending request (both versions). Every
    placement already begun is settled first (replayed with its identity),
    so the terminal Result can report EVERY target whose notice was placed.
    One that cannot settle now (held, failing) defers the refusal."""
    if any(t["state"] == "delivering" for t in rec["targets"]):
        _advance_pending(cfg, name, req_id, rec, doc, attachments, deliver_backend,
                         settle_only=True)
        if any(t["state"] == "delivering" for t in rec["targets"]):
            return HELD
    if decided.hold and not private:
        _write_held_copy(cfg, name, req_id)
    if decided.reason_code in _PEER_REFUSALS:
        _audit_peer_refusal(cfg, name, req_id, decided.reason_code,
                            recipients=[t["recipient"] for t in rec["targets"]])
    outcome = _finish(cfg, name, req_id,
                      _pending_refusal(cfg, req_id, rec, decided.outcome,
                                       decided.reason_code, decided.detail),
                      req_digest=rec["request_sha256"], private=private)
    _remove_pending(_pending_path(cfg, name, req_id))
    _remove_snapshot(cfg, name, rec)
    return outcome


def _drain_pending_v1(
    cfg: RouterConfig, name: str, filename: str, req_id: str, rec: Dict[str, Any],
    *, deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
) -> str:
    """A version-1 record in the current generation: the live entry must
    still be the request it was made for."""
    try:
        raw = _read_request_pinned(cfg, name, filename)
    except FileNotFoundError:
        return _block(cfg, name, req_id, rec, BLOCK_REQUEST_MISSING)
    except (ReadTooLargeError, OSError):
        return _block(cfg, name, req_id, rec, BLOCK_REQUEST_UNREADABLE)
    if hashlib.sha256(raw).hexdigest() != rec["request_sha256"]:
        return _block(cfg, name, req_id, rec, BLOCK_REQUEST_CHANGED)
    doc = json.loads(raw.decode("utf-8"))        # the bytes the record was made from
    try:
        attachments = attachments_mod.ingest_attachments(
            cfg, name, req_id, doc["draft"].get("attachments") or [])
    except attachments_mod.AttachmentIngestError:
        return _block(cfg, name, req_id, rec, BLOCK_ATTACHMENTS_CHANGED)
    decided = _pending_policy(cfg, name, rec, doc, cold_policy)
    if decided == BLOCK_ROUTE_CHANGED:
        return _block(cfg, name, req_id, rec, BLOCK_ROUTE_CHANGED)
    if isinstance(decided, ColdRefusal):
        return _refuse_pending(cfg, name, req_id, rec, doc, attachments, decided,
                               deliver_backend)
    if rec.get("block") is not None:
        rec["block"] = None
        _write_pending(cfg, _pending_path(cfg, name, req_id), rec)
    return _advance_pending(cfg, name, req_id, rec, doc, attachments, deliver_backend)


#: `convert_v1_pending`'s outcomes.
CONVERTED = "converted"
KEPT_V2 = "already_v2"
KEPT_DAMAGED = "kept_v1_damaged"
KEPT_UNREAD = "kept_v1_request_unreadable"
KEPT_CHANGED = "kept_v1_request_changed"
KEPT_ATTACHMENTS = "kept_v1_attachments_changed"


def pending_version(cfg: RouterConfig, name: str, req_id: str) -> Any:
    """A pending record's version (1 or 2), "damaged" when it cannot be
    trusted, or None when there is none."""
    path = _pending_path(cfg, name, req_id)
    if not os.path.lexists(path):
        return None
    try:
        return _read_pending(path, req_id)["v"]
    except PendingDamaged:
        return "damaged"


def convert_v1_pending(cfg: RouterConfig, name: str, req_id: str) -> str:
    """`router generation adopt` only, under the drain lock, with `cfg`
    keyed to the adopted generation: give a version-1 pending record its
    snapshot. The source is the live request the record names, read
    through the pinned path, and only when its bytes match the record's
    digest and its attachments verify against the descriptors those bytes
    declare. The snapshot is durable first; then the record is replaced
    atomically by its version-2 form. Anything else keeps the record at
    version 1, which holds as before; nothing is synthesised. Returns one
    of the outcomes above."""
    path = _pending_path(cfg, name, req_id)
    try:
        rec = _read_pending(path, req_id)
    except PendingDamaged:
        return KEPT_DAMAGED
    if rec["v"] != 1:
        return KEPT_V2
    try:
        raw = _read_request_pinned(cfg, name, f"req-{req_id}.json")
    except (ReadTooLargeError, OSError):
        return KEPT_UNREAD
    if hashlib.sha256(raw).hexdigest() != rec["request_sha256"]:
        return KEPT_CHANGED
    try:
        doc = json.loads(raw.decode("utf-8"))
        descriptors = doc["draft"].get("attachments") or []
        attachments = attachments_mod.ingest_attachments(cfg, name, req_id, descriptors)
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError,
            attachments_mod.AttachmentIngestError):
        return KEPT_ATTACHMENTS
    gen = cfg.gen_keys.get(name, "").partition("/")[2]
    new = dict(rec, v=PENDING_VERSION,
               snapshot=_write_snapshot(cfg, name, req_id, raw, attachments),
               source_gen=gen[len(generations_mod.GEN_PREFIX):] if gen else None,
               from_address=address_for(name, cfg.fleet_domain))
    _check_pending(new, req_id)
    _write_pending(cfg, path, new)
    return CONVERTED


def _sweep_answered_pending(cfg: RouterConfig, name: str) -> None:
    """A crash between a pending request's Result and the removal of its
    record leaves a record for a request already answered (and archived, so
    the resume path never sees it again). The private Result is the
    authority: its record goes, then its snapshot. A snapshot no record
    names is an orphan (a crash before its record was written, or after the
    record was removed); it is removed once its request's anchor exists, and
    otherwise left alone, never trusted."""
    d = gen_state_dir(cfg, name) / PENDING_DIR
    try:
        entries = list(d.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return
    named = set()
    for p in entries:
        if not p.name.endswith(".json"):
            continue
        req_id = p.name[:-len(".json")]
        try:
            rec = _read_pending(p, req_id)
        except PendingDamaged:
            rec = None
        if _private_result_path(cfg, name, req_id).is_file():
            _remove_pending(p)
            if rec is not None:
                _remove_snapshot(cfg, name, rec)
            continue
        if rec is not None and rec.get("snapshot"):
            named.add(f"{req_id}.{rec['snapshot']['nonce']}.snap")
    for p in entries:
        if not p.name.endswith(".snap") or p.name in named:
            continue
        req_id = p.name.split(".", 1)[0]
        if _private_result_path(cfg, name, req_id).is_file():
            shutil.rmtree(p, ignore_errors=True)
            fsync_dir(d)


def held_report(cfg: RouterConfig, name: str) -> List[Dict[str, Any]]:
    """Every pending request of `name`, for status.json: what is held, on
    whom, and why. A damaged record is listed as such."""
    d = gen_state_dir(cfg, name) / PENDING_DIR
    try:
        names = sorted(p.name for p in d.iterdir() if p.name.endswith(".json"))
    except (FileNotFoundError, NotADirectoryError):
        return []
    out: List[Dict[str, Any]] = []
    for fn in names:
        req_id = fn[:-len(".json")]
        try:
            rec = _read_pending(d / fn, req_id)
        except PendingDamaged as e:
            out.append({"req_id": req_id, "damaged": str(e)})
            continue
        out.append({
            "req_id": req_id, "since": rec["created_ts"], "block": rec.get("block"),
            "targets": [{"recipient": t["recipient"], "state": t["state"], "reason": t["reason"]}
                        for t in rec["targets"] if t["state"] not in ("delivered", "failed")],
        })
    return out


def _fenced_views(cfg: RouterConfig, name: str) -> List[RouterConfig]:
    """For each FENCED generation of `name` (work and anchors both matter:
    `_drain_fenced`), a view of `cfg` whose generation key for `name` is that
    generation's, so every generation-scoped path resolves into it. The
    other instances keep their current generations.

    The enumeration fails CLOSED: a generations file that cannot be read
    here (though it read for the root pin a moment earlier) raises
    `GenerationHeld`, and the drain stops before first sight or any current
    work. Read as "no fenced generations", it would release every file they
    own to the current generation, and a fenced replay later would deliver
    it again."""
    if cfg.registry_dir is None or name not in cfg.gen_keys:
        return []
    lid = cfg.gen_keys[name].partition("/")[0]
    doc = generations_mod.read_doc(cfg.state_dir, lid)
    if doc is None:
        raise generations_mod.GenerationHeld(
            generations_mod.HELD_LAYOUT_CONFLICT,
            f"{generations_mod.GEN_FILE} vanished during the drain")
    fenced = [g["gen"] for g in doc.get("gens", []) if g["gen"] != doc["current"]]
    out = []
    for gen in fenced:
        keys = dict(cfg.gen_keys)
        keys[name] = generations_mod.gen_key(lid, gen)
        out.append(generations_mod.keyed(cfg, keys))
    return out


def _drain_fenced(
    cfg: RouterConfig, name: str, transport: Optional[inflight_mod.TransportPort],
    *, deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
) -> Set[str]:
    """Step every fenced generation's work. Its in-flight records advance
    under their existing transport ids (a fenced generation never allocates
    one); its pending records replay from their snapshots. Each settles
    privately unless the root is still the one it recorded and the live
    entry is still its request (`_advance_one`, `_drain_pending`). Isolated
    per generation and per record; nothing is added to the drain summary.

    Returns the outbox filenames still owned by fenced work at the SAME root
    with matching bytes: the current generation neither takes them into its
    first-sight snapshot nor drains them (they are already handed over)."""
    owned: Set[str] = set()
    outbox = cfg.instances[name].outbox_root
    for view in _fenced_views(cfg, name):
        try:
            same_root = _same_root(view, name)
        except Exception:  # noqa: BLE001
            same_root = True     # cannot be shown otherwise: keep every claim
        # 1. Ownership FIRST, fail-closed: every live file a fenced record or
        #    anchor may own is claimed before any work is attempted, and an
        #    error below never shrinks the claim.
        if same_root:
            owned |= _fenced_claims(cfg, view, name)
        # 2. The work, each record isolated: an error keeps its claim. Under
        #    the hop each fenced generation has its own sender, constructed
        #    only once its tree is retired (`hoplink.FencedSenders`), and
        #    closed once its in-flight set is empty.
        if transport is not None:
            retired_hop = isinstance(transport, hoplink.FencedSenders)
            try:
                if inflight_mod.list_records(view, name):
                    port = transport.for_view(view, name) if retired_hop else transport
                    _advance_inflight(view, name, port, {}, fenced=True,
                                      cold_policy=cold_policy,
                                      fenced_retired=retired_hop)
                if retired_hop and not inflight_mod.list_records(view, name):
                    hoplink.evict_drained(view, name)
            except Exception:
                logger.exception("instance %r: error stepping fenced in-flight work — "
                                 "isolated, its files stay claimed", name)
        # A record whose anchor exists is already answered (an error after the
        # anchor left it behind): it goes, as in the current generation, and
        # its verdict is completed by step 3 below, never replayed here.
        try:
            _sweep_answered_pending(view, name)
        except Exception:
            logger.exception("instance %r: error sweeping fenced pending records — "
                             "isolated", name)
        for req_id in sorted(_pending_ids(view, name)):
            if _private_result_path(view, name, req_id).is_file():
                continue
            try:
                _drain_pending(view, name, f"req-{req_id}.json", req_id, fenced=True,
                               deliver_backend=deliver_backend, cold_policy=cold_policy)
            except Exception:
                logger.exception("instance %r: error replaying fenced pending %r — "
                                 "isolated, its file stays claimed", name, req_id)
        # 3. A fenced verdict whose publish or archive did not complete (an
        #    error after the anchor) is completed here, while the live file
        #    is still its request: the same resume the current generation's
        #    anchors get.
        if same_root:
            for req_id in sorted(_settled_unarchived(cfg, view, name)):
                try:
                    _publish_result_and_archive(
                        view, name, req_id, json.dumps(
                            _anchor_result(view, name, req_id), sort_keys=True).encode("utf-8"))
                except Exception:
                    logger.exception("instance %r: error completing fenced verdict %r — "
                                     "isolated, its file stays claimed", name, req_id)
    # 4. A claim is released only when its file has left the outbox.
    return {f for f in owned if os.path.lexists(outbox / f)}


def _fenced_claims(cfg: RouterConfig, view: RouterConfig, name: str) -> Set[str]:
    """Live outbox files a fenced generation (`view`) may own: those of its
    in-flight and pending records and of its anchors, unless the live bytes
    are demonstrably a DIFFERENT request. A record or anchor that cannot be
    read, or a live file that cannot be, stays claimed. A well-formed anchor
    with no digest (its original could not be read) claims the file only
    while the live entry still cannot be read for what it is: a readable file
    under that id is another request, the current generation's to answer."""
    out: Set[str] = set()
    outbox = cfg.instances[name].outbox_root
    for req_id, digest in _owned_digests(view, name):
        live = outbox / f"req-{req_id}.json"
        if not os.path.lexists(live):
            continue
        if digest is None:
            out.add(live.name)
            continue
        try:
            if not _live_differs(cfg, name, req_id, digest):
                out.add(live.name)
        except OSError:
            out.add(live.name)
    for req_id, digest in _anchor_digests(view, name):
        live = outbox / f"req-{req_id}.json"
        if not os.path.lexists(live):
            continue
        if digest is _DAMAGED_ANCHOR:
            out.add(live.name)
            continue
        try:
            if _live_is_original(cfg, name, req_id, digest):
                out.add(live.name)
        except (OSError, ReadTooLargeError):
            out.add(live.name)
    return out


_DAMAGED_ANCHOR = generations_mod.DAMAGED_ANCHOR


def _anchor_digests(cfg: RouterConfig, name: str) -> List[Tuple[str, Any]]:
    """(req_id, digest) of every anchor in `cfg`'s generation for `name`;
    an unreadable anchor's digest is `_DAMAGED_ANCHOR` (shown in status as
    `fenced_damaged_anchors`)."""
    d = gen_state_dir(cfg, name) / "results"
    try:
        names = [p.name for p in d.iterdir() if p.name.endswith(".json")]
    except (FileNotFoundError, NotADirectoryError):
        return []
    return [(fn[:-len(".json")], generations_mod.anchor_digest(d / fn)) for fn in names]


def _live_is_original(cfg: RouterConfig, name: str, req_id: str,
                      digest: Optional[str]) -> bool:
    """Is the live entry under `req_id` still the request an anchor with
    `digest` answered? With no digest the original could not be read, so the
    live entry is it only while it still cannot be read for what it is (the
    resume rule for a digest-less anchor). Absent is False; a transient fault
    RAISES."""
    if digest is not None:
        return not _live_differs(cfg, name, req_id, digest)
    try:
        _read_request_pinned(cfg, name, f"req-{req_id}.json")
    except FileNotFoundError:
        return False              # nothing there for the anchor to own
    except (ReadTooLargeError, OSError) as e:
        if _unreadable_now(e):
            return True
        raise
    return False


def _anchor_result(cfg: RouterConfig, name: str, req_id: str) -> Dict[str, Any]:
    return json.loads(_private_result_path(cfg, name, req_id).read_text(encoding="utf-8"))["result"]


def _settled_unarchived(cfg: RouterConfig, view: RouterConfig, name: str) -> List[str]:
    """Fenced anchors whose request is still in the outbox, the same bytes."""
    out = []
    for req_id, digest in _anchor_digests(view, name):
        if digest is _DAMAGED_ANCHOR or inflight_mod.record_path(view, name, req_id).exists() \
                or _pending_path(view, name, req_id).exists():
            continue
        try:
            if os.path.lexists(cfg.instances[name].outbox_root / f"req-{req_id}.json") \
                    and _live_is_original(cfg, name, req_id, digest):
                out.append(req_id)
        except (OSError, ReadTooLargeError):
            continue
    return out


def _pending_ids(cfg: RouterConfig, name: str) -> List[str]:
    d = gen_state_dir(cfg, name) / PENDING_DIR
    try:
        return [p.name[:-len(".json")] for p in d.iterdir() if p.name.endswith(".json")]
    except (FileNotFoundError, NotADirectoryError):
        return []


def _owned_digests(cfg: RouterConfig, name: str) -> List[Tuple[str, Optional[str]]]:
    """(req_id, digest) of every in-flight and pending record left in
    `cfg`'s generation for `name`."""
    out: List[Tuple[str, Optional[str]]] = []
    for req_id in inflight_mod.list_records(cfg, name):
        try:
            rec = inflight_mod.read_record(cfg, name, req_id)
        except Exception:  # noqa: BLE001 -- a damaged record keeps its claim
            rec = None
        out.append((req_id, rec.get("digest") if isinstance(rec, dict) else None))
    for req_id in _pending_ids(cfg, name):
        try:
            out.append((req_id, _read_pending(_pending_path(cfg, name, req_id), req_id)
                        ["request_sha256"]))
        except PendingDamaged:
            out.append((req_id, None))
    return out


def _pin_own_root(cfg: RouterConfig, name: str) -> Tuple[RouterConfig, Optional[int]]:
    """Under a registry: open `name`'s root ONCE (`O_NOFOLLOW`), check that
    descriptor is the directory its current generation recorded, and return
    a view of `cfg` in which every path of that instance (root, outbox,
    inbox, peer tree) goes THROUGH that descriptor (`/proc/self/fd/<fd>/…`,
    which resolves to the opened directory wherever it has been moved). So
    first sight, the listing, every read, the publish and the archive all
    act on the verified directory: a root replaced after this check is never
    read or written by this drain. The caller closes the descriptor.
    Without a registry: `(cfg, None)`, unchanged."""
    expected = generations_mod.expected_root(cfg, name)
    if expected is None:
        return cfg, None
    inst = cfg.instances[name]
    if not os.path.isdir(generations_mod.PINNED_PREFIX):
        raise generations_mod.GenerationHeld(
            generations_mod.HELD_CONNECTOR_UNVERIFIED,
            f"registry mode needs {generations_mod.PINNED_PREFIX} (Linux /proc) to pin "
            "an instance's root; it is not available here")
    try:
        fd = os.open(str(inst.root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        raise generations_mod.GenerationHeld(
            generations_mod.HELD_CONNECTOR_UNVERIFIED,
            f"{name!r}: the root cannot be opened: {type(e).__name__}") from None
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) != expected:
            raise generations_mod.GenerationHeld(
                generations_mod.HELD_CONNECTOR_UNVERIFIED,
                f"{name!r}: the root was replaced since this poll's generation check")
        pinned = Path(f"{generations_mod.PINNED_PREFIX}{fd}")
    except BaseException:
        os.close(fd)
        raise

    def through(p: Optional[Path]) -> Optional[Path]:
        return None if p is None else pinned / p.relative_to(inst.root)
    view_inst = dataclasses.replace(
        inst, root=pinned, inbox_root=through(inst.inbox_root),
        outbox_root=through(inst.outbox_root), peer_root=through(inst.peer_root))
    instances = dict(cfg.instances)
    instances[name] = view_inst
    return dataclasses.replace(cfg, instances=instances), fd


def with_pinned_root(cfg: RouterConfig, name: str,
                     fn: Callable[[RouterConfig, str], Any]) -> Any:
    """`fn(view, name)` on `_pin_own_root`'s view: anything that reads or
    writes inside an instance's root (the outcome consume, as the drain)
    does it through the verified descriptor. Raises `GenerationHeld` when
    the root does not check out; without a registry, `fn(cfg, name)`."""
    view, fd = _pin_own_root(cfg, name)
    try:
        return fn(view, name)
    finally:
        if fd is not None:
            os.close(fd)


def drain_instance(
    cfg: RouterConfig, name: str,
    *, deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
    transport: Optional[inflight_mod.TransportPort] = None,
) -> Dict[str, int]:
    """See `_drain_instance`. Under a registry the drain runs on the view
    `_pin_own_root` returns, so it can only act on the verified root."""
    view, fd = _pin_own_root(cfg, name)
    try:
        current, fenced = hoplink.resolve(transport, view, name)
        return _drain_instance(view, name, deliver_backend=deliver_backend,
                               cold_policy=cold_policy, transport=current,
                               fenced_transport=fenced)
    finally:
        if fd is not None:
            os.close(fd)


def _drain_instance(
    cfg: RouterConfig, name: str,
    *, deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
    transport: Optional[inflight_mod.TransportPort] = None,
    fenced_transport: Any = None,
) -> Dict[str, int]:
    """Drain instance `name`'s `outbound/` once. Returns a summary dict for
    logging (mirrors `gate.outbound.drain_outbound`'s shape).

    `deliver_backend` is the injection point for the delivery seam
    (`deliver.DeliveryBackend`): a caller may supply what performs each
    per-recipient delivery. Omitted — as every caller in this repo omits
    it — deliveries go to `deliver.deliver`, resolved at call time, and
    this router behaves exactly as if the seam were not there. Nothing
    here dispatches or classifies: whatever is injected receives every
    delivery this drain makes.

FIRST SIGHT (`router/firstsight.py`): the first time this router sees an
    instance's root it snapshots every `req-*.json` filename already in the
    outbox, BEFORE draining anything, and never delivers those. A request can
    be staged before this router has any business draining it — a workspace
    config committed to a repo can create the handoff pair, and a repo cloned
    into a workspace can carry requests with it — and the snapshot is what
    refuses them. Later polls reuse that marker and never re-snapshot.

    There is no operator approval step. The deliberate human act is
    ENROLMENT, which is upstream of this router seeing the root at all, so
    the boundary "nothing that existed before first sight" sits strictly
    after it. A FRESH request (no private result yet) whose filename is in
    the snapshot is quarantined (`_quarantine_one`) rather than processed —
    see `router/firstsight.py` for exactly what that guarantees and what it
    does not.

    Every per-request body (resume, quarantine, or fresh) runs inside a
    `try/except Exception`: the outbox is untrusted input (SCOPE.md), and a
    single hostile shape — e.g. `outbound/results` pre-created as a regular
    file, which makes `atomic_write`'s `mkdir` raise `FileExistsError` —
    must never abort the whole drain (this instance's remaining requests,
    or any OTHER instance's — see `service.run_once`'s matching per-
    instance isolation). A failure is logged and counted as
    `outbound_errored`.

    IN FLIGHT (`router/inflight.py`): a request handed to the external leg
    stays in the outbox, unanswered, until the transport's result arrives.
    Every record is stepped BEFORE the outbox is listed, and a listed request
    that has a record is skipped (`outbound_inflight_waiting`) rather than
    processed again — the record, not the agent's file, carries it from
    then on. `transport` is the port to the external leg; omitted, as every
    caller in this repo omits it today, nothing is ever put in flight."""
    # FIRST SIGHT, BEFORE ANY DRAIN OF THIS ROOT. The snapshot has to precede
    # the first drain in the same poll, or the window it exists to close is
    # open for exactly one poll. `record_first_sight` is idempotent after the
    # first call — it never re-snapshots, because that would move the
    # quarantine line forward over whatever appeared since.
    # Under a registry `drain_instance` has already pinned this instance's
    # root and checked it against the current generation's (`_pin_own_root`):
    # every path below goes through that descriptor.
    # A fenced generation's work first (its own transport ids, its own
    # snapshots); what it still owns at this root is neither first-sighted
    # nor drained by the current generation.
    fenced_owned = _drain_fenced(cfg, name, fenced_transport, deliver_backend=deliver_backend,
                                 cold_policy=cold_policy)
    marker_doc, first_sight = firstsight.record_first_sight(cfg, name, exclude=fenced_owned)
    quarantine_set = firstsight.quarantined_filenames(marker_doc)

    outcomes: Dict[str, int] = {"accepted": 0, "rejected": 0, "queued_for_human": 0}
    # The in-flight keys appear only where the external leg is in play, so a
    # router without one reports exactly the summary it always did.
    inflight_summary: Dict[str, int] = {}
    if transport is not None or inflight_mod.list_records(cfg, name):
        inflight_summary = _advance_inflight(cfg, name, transport, outcomes,
                                             cold_policy=cold_policy)

    _sweep_answered_pending(cfg, name)
    filenames, skipped_symlinks = list_outbound(cfg, name)

    drained = resumed = errored = reused = quarantined = held = 0
    inflight_begun = inflight_waiting = reused_pending = 0
    skipped_bad_name = skipped_symlinks
    for filename in filenames:
        if not REQ_NAME_RE.fullmatch(filename):
            skipped_bad_name += 1
            logger.warning(
                "outbound listing for instance %r has a filename that fails "
                "hygiene checks, never opened, skipping: %r", name, filename,
            )
            continue

        req_id = filename[len("req-") : -len(".json")]
        if filename in fenced_owned:
            continue    # a fenced generation's own request, still in its hands
        private_path = _private_result_path(cfg, name, req_id)

        try:
            if private_path.is_file():
                envelope = json.loads(private_path.read_text(encoding="utf-8"))
                stored_digest = envelope.get("digest")
                stored_result = envelope["result"]

                if stored_digest is None:
                    # D4: the original could not be read (over the cap, or
                    # not a readable regular file), so there is no digest.
                    # It resumes ONLY while the live entry still cannot be
                    # read for what it is: a readable file under this id is
                    # a different request, and resuming would answer it with
                    # the old verdict. A transient fault decides nothing.
                    try:
                        _read_request_pinned(cfg, name, filename)
                    except FileNotFoundError:
                        resume_ok = True
                    except (ReadTooLargeError, OSError) as e:
                        if not _unreadable_now(e):
                            logger.warning(
                                "instance %r req_id %r: transient error re-reading "
                                "the request under a digest-less anchor, skipping "
                                "this poll: %s: %s", name, req_id, type(e).__name__, e,
                            )
                            errored += 1
                            continue
                        resume_ok = True
                    else:
                        resume_ok = False
                else:
                    # FIXED: distinguish an ACTUAL digest mismatch from a
                    # transient failure to re-read the bytes at all — the
                    # old code folded every `ReadTooLargeError`/`OSError`
                    # here into `current_digest = None`, which then always
                    # compared unequal to `stored_digest` and was reported
                    # as `req_id_reused`: a false, permanent `rejected`
                    # verdict for what could just be a disk hiccup or a
                    # benign race, not evidence the id was ever reused for
                    # different content.
                    try:
                        current_digest = hashlib.sha256(
                            _read_request_pinned(cfg, name, filename)
                        ).hexdigest()
                    except FileNotFoundError:
                        # The file this call's own `list_outbound` listing
                        # (above) just saw is gone now — not evidence of
                        # reuse, just a benign race (e.g. a concurrent
                        # drainer already archived it; the single-drainer
                        # lock, Finding 3, is defense in depth here, not a
                        # guarantee every caller of this function goes
                        # through it). Resume normally: `_publish_result_
                        # and_archive`'s own rename is already a no-op
                        # (`FileNotFoundError`, caught there) when there is
                        # truly nothing left to archive.
                        resume_ok = True
                    except ReadTooLargeError:
                        # A file that is NOW over the read cap cannot be
                        # byte-identical to whatever `stored_digest` was
                        # computed from — this genuinely IS different
                        # content under a reused id, the same conclusion a
                        # digest mismatch reaches, just reached without
                        # ever reading the (oversized) bytes.
                        resume_ok = False
                    except OSError as e:
                        if _unreadable_now(e):
                            # Refused for what it IS (a hard link, not a
                            # regular file). The original was readable, or
                            # its anchor would have no digest, so this is a
                            # different request under the id, exactly as a
                            # now-oversized file is.
                            resume_ok = False
                        else:
                            # A genuine transient read failure (permission
                            # hiccup, disk error, ...) — not evidence of
                            # reuse either. Do not commit a false
                            # `rejected`/`req_id_reused` verdict here; skip
                            # this filename for THIS poll and let the next
                            # drain take a fresh read with a fair chance to
                            # resolve normally.
                            logger.warning(
                                "instance %r req_id %r: transient error "
                                "re-reading the request to verify its digest "
                                "against the resume anchor, skipping this poll "
                                "(NOT reporting req_id_reused): %s: %s",
                                name, req_id, type(e).__name__, e,
                            )
                            errored += 1
                            continue
                    else:
                        resume_ok = current_digest == stored_digest

                if resume_ok:
                    # D4: a previous drain already processed this id — do
                    # not re-validate/re-deliver, just make sure the
                    # namespace catches up (crash-safe resume).
                    _publish_result_and_archive(
                        cfg, name, req_id,
                        json.dumps(stored_result, sort_keys=True).encode("utf-8"),
                    )
                    if cfg.registry_dir is not None:
                        # A crash between a pending request's Result and
                        # the removal of its record leaves the record:
                        # the Result is the authority, so it goes.
                        _remove_pending(_pending_path(cfg, name, req_id))
                    resumed += 1
                else:
                    # req_id reuse with DIFFERENT content: never replay the
                    # stale verdict (that would be a silent false
                    # `accepted` for a request that was never delivered).
                    # Issue a fresh, honest refusal instead. The original
                    # anchor is left untouched, so a later resubmission of
                    # the ORIGINAL bytes under this id still resumes
                    # correctly.
                    logger.warning(
                        "req_id %r reused for instance %r with content that "
                        "does not match the original submission under this "
                        "id — refusing to resume, issuing %s",
                        req_id, name, REASON_REQ_ID_REUSED,
                    )
                    fresh = _result_doc(
                        req_id, "rejected", reason_code=REASON_REQ_ID_REUSED,
                        detail="req_id was already used for a different request",
                    )
                    _publish_result_and_archive(
                        cfg, name, req_id, json.dumps(fresh, sort_keys=True).encode("utf-8"),
                    )
                    reused += 1
                    generations_mod.record_reuse(cfg, name, req_id)
                    outcomes["rejected"] += 1
            elif _pending_path(cfg, name, req_id).exists():
                outcome = _drain_pending(
                    cfg, name, filename, req_id, deliver_backend=deliver_backend,
                    cold_policy=cold_policy,
                )
                if outcome == HELD:
                    held += 1
                    continue
                if outcome in outcomes:
                    outcomes[outcome] += 1
            elif inflight_mod.record_path(cfg, name, req_id).exists():
                # In flight: the record carries it now (docstring, IN
                # FLIGHT). Not drained this poll. A DIFFERENT request under
                # the id (a reset connector) is held, never consumed, until
                # the record settles; it is then refused as req_id_reused.
                record = inflight_mod.read_record(cfg, name, req_id)
                if record is not None and _live_differs(
                        cfg, name, req_id, record.get("digest")):
                    logger.warning(
                        "instance %r req_id %r: a different request sits under "
                        "an id still in flight; held until that settles",
                        name, req_id,
                    )
                    reused_pending += 1
                    generations_mod.note_reuse_pending(cfg, name, req_id)
                    continue
                inflight_waiting += 1
                continue
            elif filename in quarantine_set:
                try:
                    raw = _read_request_pinned(cfg, name, filename)
                except (ReadTooLargeError, OSError):
                    # Unreadable regardless of quarantine status — falls
                    # through to the ordinary fresh path, whose own
                    # read-capped handling produces the honest
                    # rejected/malformed_request result. It was never
                    # deliverable either way.
                    outcome = _drain_one(
                        cfg, name, filename, req_id, deliver_backend=deliver_backend,
                        cold_policy=cold_policy,
                    )
                else:
                    req_digest = hashlib.sha256(raw).hexdigest()
                    outcome = _quarantine_one(
                        cfg, name, filename, req_id, marker_doc, req_digest, raw,
                    )
                    quarantined += 1
                if outcome in outcomes:
                    outcomes[outcome] += 1
            else:
                outcome = _drain_one(
                    cfg, name, filename, req_id, deliver_backend=deliver_backend,
                        cold_policy=cold_policy, transport=transport,
                )
                if outcome == INFLIGHT:
                    inflight_begun += 1
                elif outcome == HELD:
                    held += 1
                    continue
                elif outcome in outcomes:
                    outcomes[outcome] += 1
        except Exception:
            logger.exception(
                "error draining instance %r, request %r — isolated, "
                "continuing with the next request", name, filename,
            )
            errored += 1
            continue

        drained += 1

    # A pending request whose live file is gone is not in the listing; its
    # record still carries it (from its snapshot, or blocked if version 1).
    listed = {f[len("req-"):-len(".json")] for f in filenames if REQ_NAME_RE.fullmatch(f)}
    for req_id in sorted(set(_pending_ids(cfg, name)) - listed):
        if _private_result_path(cfg, name, req_id).is_file():
            continue
        try:
            outcome = _drain_pending(cfg, name, f"req-{req_id}.json", req_id,
                                     deliver_backend=deliver_backend,
                                     cold_policy=cold_policy)
        except Exception:
            logger.exception("instance %r: error draining pending %r — isolated",
                             name, req_id)
            errored += 1
            continue
        if outcome == HELD:
            held += 1
        elif outcome in outcomes:
            outcomes[outcome] += 1

    return {
        # Surfaced so `status` can say once why a full outbox went quiet.
        "first_sight": 1 if first_sight else 0,
        "outbound_seen": len(filenames) + skipped_symlinks,
        "outbound_skipped_bad_name": skipped_bad_name,
        "outbound_resumed": resumed,
        "outbound_req_id_reused": reused,
        "outbound_errored": errored,
        "drained": drained,
        "accepted": outcomes["accepted"],
        "rejected": outcomes["rejected"],
        "queued_for_human": outcomes["queued_for_human"],
        "quarantined": quarantined,
        # Under a registry only, so an unregistered router reports exactly
        # the summary it always did.
        **({"outbound_held": held, "held_local": held_report(cfg, name)}
           if cfg.registry_dir is not None else {}),
        **({"outbound_inflight_begun": inflight_begun,
            "outbound_inflight_waiting": inflight_waiting,
            "outbound_req_id_reused_pending": reused_pending,
            **inflight_summary,
            **_inflight_report(cfg, name)} if transport is not None or inflight_summary else {}),
    }
