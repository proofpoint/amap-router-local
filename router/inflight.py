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
(case-insensitively); any difference settles `queued_for_human`/
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

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

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
DETAIL_PREFIX = "transport: "

#: Age past which a record counts as stale in `summarize`. Reporting only:
#: nothing is ever settled on age (module docstring, NO TIMEOUT).
STALE_AFTER_S = 3600

_OUTCOMES = ("accepted", "queued_for_human", "rejected")
_COUNTER_RE = re.compile(r"^[1-9][0-9]{0,17}\Z")
_REASON_RE = re.compile(r"^[\x21-\x7e]{1,128}\Z")
_DETAIL_CAP = 2000

# States `advance` reports.
SETTLED = "settled"
PENDING = "pending"
WRITTEN = "written"
CLEANED = "cleaned"


class TransportPort(Protocol):
    """The transport, as `advance` needs it. A real implementation comes
    from an optional transport plugin; tests supply a fake."""

    def has_result(self, n: str) -> bool: ...
    def has_pending(self, n: str) -> bool: ...
    def has_archived(self, n: str) -> bool: ...
    def read_result(self, n: str) -> bytes: ...
    def write_request(self, n: str, data: bytes) -> None: ...


class CounterCorrupt(Exception):
    """The counter file exists and is not a positive decimal. Raised, never
    repaired: restarting at 1 would reuse every id already handed over."""


def _effect(label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Every side effect in this module goes through here (module
    docstring). `label` names it for a test's crash injector."""
    return fn(*args, **kwargs)


def _inflight_dir(cfg: RouterConfig, name: str) -> Path:
    return cfg.state_dir / name / INFLIGHT_DIR


def record_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return _inflight_dir(cfg, name) / f"{req_id}.json"


def handed_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return _inflight_dir(cfg, name) / f"{req_id}{HANDED_SUFFIX}"


def counter_path(cfg: RouterConfig, name: str) -> Path:
    return cfg.state_dir / name / TRANSPORT_STATE_DIR / COUNTER_FILE


def read_record(cfg: RouterConfig, name: str, req_id: str) -> Optional[Dict[str, Any]]:
    try:
        raw = record_path(cfg, name, req_id).read_bytes()
    except FileNotFoundError:
        return None
    return json.loads(raw.decode("utf-8"))


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
        if not _COUNTER_RE.match(text):
            raise CounterCorrupt(f"{path}: not a positive decimal; refusing to reuse ids")
        n = int(text)
    _effect("counter", atomic_write, path, str(n + 1).encode("ascii"),
            durable_root=cfg.state_dir)
    return f"{n:08d}"


def begin(
    cfg: RouterConfig, name: str, req_id: str,
    *, digest: Optional[str], request_doc: Dict[str, Any], recipients: List[str],
) -> Dict[str, Any]:
    """Put `req_id` in flight: allocate its transport id, then write the
    record. Returns the record. A crash between the two burns the id; the
    agent's request is still unsettled and unrecorded, so the next poll
    processes it afresh and allocates a new one."""
    n = allocate_transport_req_id(cfg, name)
    record = {
        "digest": digest,
        "transport_req_id": n,
        "recipients": list(recipients),
        "request": request_doc,
        "written_ts": utc_ts(),
    }
    _effect(
        "record", atomic_write, record_path(cfg, name, req_id),
        json.dumps(record, sort_keys=True).encode("utf-8"),
        durable_root=cfg.state_dir,
    )
    return record


def transport_request_bytes(cfg: RouterConfig, name: str, record: Dict[str, Any]) -> bytes:
    """The Submit Request this router hands to the transport, built from the
    STAGED copy. `req_id` is the transport id and `agent_id` the namespace.
    `draft.to`/`draft.cc` go out unchanged, and ONLY when together they are
    exactly the evaluated set (`recipient_mismatch`); otherwise this raises
    `RecipientSetMismatch` and produces no bytes. Any threading key is
    dropped: mapping one to the downstream runtime's notice id is the
    re-placement step's, and until it exists an unmapped id is dropped
    rather than passed to the transport."""
    mismatch = recipient_mismatch(record)
    if mismatch is not None:
        raise RecipientSetMismatch(mismatch)
    doc = json.loads(json.dumps(record["request"]))
    doc["req_id"] = record["transport_req_id"]
    doc["agent_id"] = name
    doc.pop("in_reply_to", None)
    doc.get("draft", {}).pop("reply_to_message_id", None)
    return json.dumps(doc, sort_keys=True).encode("utf-8")


class RecipientSetMismatch(Exception):
    """The draft's `to`/`cc` are not exactly the evaluated recipients. Raised
    by `transport_request_bytes` so no transport request can carry them."""


def recipient_mismatch(record: Dict[str, Any]) -> Optional[str]:
    """None when the staged draft's `to` ∪ `cc` is EXACTLY the evaluated set
    (case-insensitively), else why not.

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
    if {a.casefold() for a in addrs} != {a.casefold() for a in evaluated}:
        return "the draft's to/cc differ from the authorised recipients"
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
    if reason is not None and not (isinstance(reason, str) and _REASON_RE.match(reason)):
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
) -> str:
    """One step for one record (module docstring's table). `settle(verdict,
    digest)` writes the agent's one result; `already_settled` says the
    private result exists already (a crash, or a failed barrier, after
    settling). `anchor` is that private result's path: before the record is
    removed on its strength, it is validated and made durable again
    (`_redurabilise`), because its existence alone does not prove it
    survives a power loss. Returns the state reached."""
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

    def from_result() -> str:
        verdict = verdict_from_result(port.read_result(n), n, record)
        _effect("settle", settle, verdict, record.get("digest"))
        _effect("unlink", _cleanup, path, handed)
        return SETTLED

    if port.has_result(n):
        return from_result()
    if port.has_pending(n):
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
    data = transport_request_bytes(cfg, name, record)
    _effect("handed", atomic_write, handed, n.encode("ascii"),
            durable_root=cfg.state_dir)
    _effect("transport", port.write_request, n, data)
    return WRITTEN


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
    """Remove a settled record, then its marker, durably. The record goes
    FIRST: a record left without its marker by a crash here is already
    settled (`already_settled`), so the missing marker is never consulted."""
    for p in (record, handed):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
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
