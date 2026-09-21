"""router/outbound.py — drain one instance's outbound/ dropbox.

`drain_instance(cfg, name)` mirrors `gate/outbound.py:drain_outbound`'s
shape (list -> filename-hygiene filter -> idempotency check -> validate ->
policy -> deliver -> result -> archive), transplanted onto the router's own
config/binding/deliver primitives:

  1. List `<ns>/outbound/` entries; accept ONLY filenames matching
     `^req-[A-Za-z0-9_-]{1,64}\\.json$` (verbatim `REQ_NAME_RE`,
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

import hashlib
import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from datetime import timedelta

from . import attachments as attachments_mod, binding, firstsight
from . import audit as audit_mod
from . import deliver as deliver_mod, validate as validate_mod
from .config import RouterConfig, address_for, instance_for
from .util import (
    DEFAULT_READ_CAP,
    NamespaceEscapeError,
    ReadTooLargeError,
    atomic_write,
    parse_utc_ts,
    read_capped,
    utc_ts,
)

logger = logging.getLogger("amap_router_local.outbound")

REQ_NAME_RE = re.compile(r"^req-[A-Za-z0-9_-]{1,64}\.json$")

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


def _outbox_dir(cfg: RouterConfig, name: str) -> Path:
    return cfg.instances[name].outbox_root


def _private_result_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return cfg.state_dir / name / "results" / f"{req_id}.json"


def _held_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return cfg.state_dir / name / "held" / f"req-{req_id}.json"


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
    ReadTooLargeError` clause keeps working unchanged. Every other
    refusal (missing file, outbox root not currently a real directory,
    not a regular file, an `nlink > 1` hard link, ...) raises plain
    `OSError` (often a natural subtype like `FileNotFoundError` straight
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
                    raise OSError(f"{filename!r} is not a regular file")
                if st.st_nlink != 1:
                    raise OSError(f"{filename!r} has nlink={st.st_nlink} (expected 1)")
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
    outbound_dir = _outbox_dir(cfg, name)
    if not outbound_dir.is_dir():
        return [], 0
    names: List[str] = []
    skipped_symlinks = 0
    for p in sorted(outbound_dir.iterdir(), key=lambda p: p.name):
        if p.is_symlink():
            skipped_symlinks += 1
            logger.warning(
                "outbound listing for instance %r has a symlinked entry, "
                "never opened, skipping: %r", name, p.name,
            )
            continue
        if p.is_file():
            names.append(p.name)
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
        diag = None
        if e.index is not None and e.attachment_outcome is not None:
            diag = [{"index": e.index, "outcome": e.attachment_outcome, "detail": e.detail}]
        result = _result_doc(
            req_id, e.outcome, reason_code=e.reason_code, detail=e.detail,
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
    record = binding.read_ledger_record(cfg.state_dir, name, str(in_reply_to))
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

    draft = doc.get("draft") or {}
    if draft.get("to") or draft.get("cc"):
        logger.warning(
            "reply from instance %r (req_id=%r, in_reply_to=%r) supplied "
            "draft.to/cc — discarded outright, bound to %r instead per the "
            "private ledger",
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
    backend = deliver_backend if deliver_backend is not None else deliver_mod.deliver
    try:
        delivered = backend(
            cfg, cfg.state_dir, name, bound_instance, doc,
            reply_to_record=record, attachments=attachments,
        )
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
    [RouterConfig, str, Dict[str, Any]], Union[List[str], ColdRefusal, PeerRoute]
]

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
) -> str:
    """Place one peer notice (fresh task or reply) and answer the request
    exactly once — `accepted`/`peer_routed` with the minted peer id, or
    `queued_for_human`/`delivery_failed` if the placement raised (the same
    isolation `_drain_reply`/`_drain_cold` give the mail lane; see the
    comment in `_drain_reply` for why an unguarded delivery would retry
    forever). Late-resolved so a test can patch `deliver_mod.deliver_peer`."""
    recipient = route.recipient
    try:
        delivered = deliver_mod.deliver_peer(
            cfg, cfg.state_dir, name, recipient, doc,
            reply_to_record=reply_to_record, attachments=attachments,
        )
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

    if not binding.check_peer_edge(cfg, name, bound_instance):
        issued = parse_utc_ts(record.get("ts"))
        now = parse_utc_ts(utc_ts())
        window = timedelta(seconds=cfg.peer_reply_window_seconds)
        if issued is None or now is None or now - issued > window:
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

    return _drain_peer_route(
        cfg, name, req_id, doc, PeerRoute(bound_instance),
        req_digest=req_digest, attachments=attachments, reply_to_record=record,
    )


def _drain_cold(
    cfg: RouterConfig, name: str, req_id: str, doc: Dict[str, Any], draft: Dict[str, Any],
    *, req_digest: Optional[str],
    attachments: Optional[List[attachments_mod.VerifiedAttachment]] = None,
    deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
) -> str:
    """Cold-send routing: recipient set = `to ∪ cc`, one governing outcome,
    never a partial delivery. WHICH recipients are permitted is the policy's
    decision (`cold_policy`, default `default_cold_policy` — every caller in
    this repo omits it, and the behaviour is then exactly as before). Returns
    the governing `outcome` string."""
    # Late resolution, like the backend below: a module-level default bound at
    # def-time cannot be patched by a test that imports this module.
    policy = cold_policy if cold_policy is not None else default_cold_policy
    decided = policy(cfg, name, draft)

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
            req_digest=req_digest, attachments=attachments,
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
    # Late resolution, as in `_drain_reply` above — see that comment.
    backend = deliver_backend if deliver_backend is not None else deliver_mod.deliver
    delivered: List[Dict[str, Any]] = []
    failed: List[str] = []
    for r in recipients:
        try:
            delivered.append(
                backend(cfg, cfg.state_dir, name, r, doc, attachments=attachments)
            )
        except Exception as e:  # noqa: BLE001 — one recipient must not sink the request
            failed.append(r)
            logger.warning(
                "instance %r req %r: delivery to %r failed, continuing with the "
                "remaining recipients: %s: %s", name, req_id, r, type(e).__name__, e,
            )

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


def _finish(
    cfg: RouterConfig, name: str, req_id: str, result: Dict[str, Any],
    *, req_digest: Optional[str],
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
    private_path = _private_result_path(cfg, name, req_id)
    envelope = {"digest": req_digest, "result": result}
    atomic_write(private_path, json.dumps(envelope, sort_keys=True).encode("utf-8"))
    result_bytes = json.dumps(result, sort_keys=True).encode("utf-8")
    _publish_result_and_archive(cfg, name, req_id, result_bytes)
    return result["outcome"]


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
    q_dir = cfg.state_dir / name / "quarantine"
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


def drain_instance(
    cfg: RouterConfig, name: str,
    *, deliver_backend: Optional[deliver_mod.DeliveryBackend] = None,
    cold_policy: Optional[ColdPolicy] = None,
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
    `outbound_errored`."""
    # FIRST SIGHT, BEFORE ANY DRAIN OF THIS ROOT. The snapshot has to precede
    # the first drain in the same poll, or the window it exists to close is
    # open for exactly one poll. `record_first_sight` is idempotent after the
    # first call — it never re-snapshots, because that would move the
    # quarantine line forward over whatever appeared since.
    marker_doc, first_sight = firstsight.record_first_sight(cfg, name)
    quarantine_set = firstsight.quarantined_filenames(marker_doc)

    filenames, skipped_symlinks = list_outbound(cfg, name)

    drained = resumed = errored = reused = quarantined = 0
    skipped_bad_name = skipped_symlinks
    outcomes: Dict[str, int] = {"accepted": 0, "rejected": 0, "queued_for_human": 0}
    for filename in filenames:
        if not REQ_NAME_RE.match(filename):
            skipped_bad_name += 1
            logger.warning(
                "outbound listing for instance %r has a filename that fails "
                "hygiene checks, never opened, skipping: %r", name, filename,
            )
            continue

        req_id = filename[len("req-") : -len(".json")]
        private_path = _private_result_path(cfg, name, req_id)

        try:
            if private_path.is_file():
                envelope = json.loads(private_path.read_text(encoding="utf-8"))
                stored_digest = envelope.get("digest")
                stored_result = envelope["result"]

                if stored_digest is None:
                    # D4, rare corner case: the original processing attempt
                    # never got far enough to read the request bytes (e.g.
                    # it exceeded the read cap), so no digest exists to
                    # compare against. Resume as before rather than
                    # refusing forever on an id we can't disambiguate.
                    resume_ok = True
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
                        # A genuine transient read failure (permission
                        # hiccup, disk error, ...) — not evidence of reuse
                        # either. Do not commit a false `rejected`/
                        # `req_id_reused` verdict here; skip this filename
                        # for THIS poll and let the next drain take a
                        # fresh read with a fair chance to resolve
                        # normally.
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
                    outcomes["rejected"] += 1
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
                        cold_policy=cold_policy,
                )
                if outcome in outcomes:
                    outcomes[outcome] += 1
        except Exception:
            logger.exception(
                "error draining instance %r, request %r — isolated, "
                "continuing with the next request", name, filename,
            )
            errored += 1
            continue

        drained += 1

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
    }
