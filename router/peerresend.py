"""router/peerresend.py — the NO-RESIGN resend workflow for signed peer tasks.

A peer task this router signed is never signed again: a peer id is minted
once (`peerlane.write_issued` refuses a second), and nothing here calls a
signer, the statement builder, the id minter or the Message-ID builder. What
this module adds is the ORIGINAL, kept, and three operator actions over it:
reconcile (`show`), retransmit the original bytes unchanged under a new
transport id, or (the agent's) a new task with a new request id and a new
peer id.

PRESERVATION. Every signed peer task handed to the external leg is copied to
`state_dir/<logical_id>/peer-sent/<id>/` BEFORE its handed marker, from the
in-flight record AS HANDED (after its policy repin) and its attachment
snapshot: `record.json` (the record's canonical bytes), `origin.json`
(`{v, id, logical_id, generation, transport_req_id, req_id, preserved_ts}`;
`req_id` is the agent's request id, the map to its one Result) and
`attachments/<index>`. The copy is committed by a link-once `COMMIT`
sentinel; an uncommitted directory is never read and is written again; a
committed copy is compared on every field but `preserved_ts` and kept. A
failure leaves the record unhanded (the caller holds it, visibly).
`handed.json` (`{v, handed_ts}`) is linked by the first pass that FINDS the
handed marker, so its time is never earlier than the true hand-over;
`settled.json` (`{v, outcome, reason_code, settled_ts}`) by the settlement.

RETRANSMIT. `operator_retransmit` checks the copy, the two contract triggers
(a `delivery_unknown` settlement; or no signed Result and no control notice
for the id past `STALE_AFTER_S` since `handed_ts`, only with
`allow_pending`), the window, the signing key (conservatively: the preserved
key must be the current signing key), the generation and the sender's
current policy, then claims `retransmit.json` (link-once, carrying `by` and
the evidence verbatim), audits the request, and writes an in-flight record
`rtx.<n>` in the current generation, whose members are the copy's (request
with `req_id` `rtx.<n>`, recipients, from_address, attachments, peer,
digest), a fresh `written_ts`, and `retransmit: {of_generation, of_n, id}`.
Before its FIRST hand-over the gate (`gate`) re-runs every dynamic check;
a failure is a terminal cancellation. Its settlement, whatever the path, is
`retransmits/<generation>-<n>.json` and never the agent's Result or anchor:
only the original in-flight record ever writes those. Then the settled
audit line; then, LAST, the claim is removed.

PRUNE. A copy is removed only when settled, with no retransmit claim and no
retransmit record, and `clock.now() > ts + P + F + 7 days`: a `prune` claim,
then the directory bottom-up, then the claim. ON by default
(`peer_sent_prune`).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import config as config_mod
from .util import atomic_write, format_utc_ts, fsync_dir, parse_utc_ts

PEER_SENT_DIR = "peer-sent"
COMMIT = "COMMIT"
RECORD = "record.json"
ORIGIN = "origin.json"
HANDED = "handed.json"
SETTLED = "settled.json"
CLAIM = "retransmit.json"
PRUNE_CLAIM = "prune.json"
RETRANSMITS = "retransmits"
ATTACHMENTS = "attachments"
#: The in-flight record name of a retransmit: the dot is outside the agent
#: request-id grammar, so no agent request can collide with one.
RTX_PREFIX = "rtx."
#: A copy is kept at least this long past its window (`ts + P + F`).
PRUNE_GRACE = timedelta(days=7)
#: The retransmit's terminal outcome before any hand-over.
CANCELLED = "cancelled"
#: Dynamic refusals that are ROUTER states, not task states: before the first
#: hand-over they HOLD a retransmit record (unhanded, unsettled, gated again
#: next poll), never cancel it. They clear by themselves.
HOLD_CODES = frozenset({"clock_untrusted", "journal_unreadable"})
_PEER_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{22}\Z")
_RTX_RE = re.compile(r"rtx\.[0-9]{8,18}\Z")

#: The audit acts.
REQUESTED = "peer-request retransmit requested"
SETTLED_ACT = "peer-request retransmit settled"


class PreservationConflict(Exception):
    """A committed copy differs from what would be written: never replaced."""


class Refused(ValueError):
    """A verb refused before anything is written; `code` names why."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def sent_root(state_dir: Path, logical_id: str) -> Path:
    return Path(state_dir) / logical_id / PEER_SENT_DIR


def copy_dir(state_dir: Path, logical_id: str, peer_id: str) -> Path:
    if not _PEER_ID_RE.fullmatch(peer_id):
        raise ValueError(f"{peer_id!r} is not a peer id")
    return sent_root(state_dir, logical_id) / peer_id


def is_rtx(req_id: str) -> bool:
    return bool(_RTX_RE.fullmatch(req_id))


def rtx_name(n: str) -> str:
    return f"{RTX_PREFIX}{n}"


def _gen_of(cfg: Any, name: str) -> Tuple[str, str]:
    from . import hoplink
    return hoplink.split_gen_key(config_mod.gen_key(cfg, name))


def _canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _link_once(path: Path, data: bytes, state_dir: Path) -> bool:
    """Write `data` at `path` exactly once: a temporary file linked to the
    name (EEXIST: already there, nothing written). True when written."""
    tmp = path.with_name(f".tmp-{path.name}-{os.getpid()}-{os.urandom(4).hex()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp, path)
        written = True
    except FileExistsError:
        written = False
    finally:
        os.unlink(tmp)
    fsync_dir(path.parent)
    return written


def committed(d: Path) -> bool:
    return (d / COMMIT).is_file()


# ---------------------------------------------------------------------------
# Preservation (called by the hand-over, before the handed marker)
# ---------------------------------------------------------------------------

def enabled(cfg: Any) -> bool:
    """The workflow exists only where a copy can be keyed: a generation-keyed
    config with a hop (`registry_dir` and `hop`), the only one with an
    external leg to retransmit over. Elsewhere nothing is preserved, and
    `retransmit` refuses `not_preserved`."""
    from . import inflight
    return inflight._is_hop(cfg)


def preservable(cfg: Any, name: str, record: Mapping[str, Any]) -> bool:
    """A signed peer TASK in an agent's namespace, not a retransmit, under a
    config where the workflow is `enabled`."""
    peer = record.get("peer") or {}
    return (enabled(cfg) and name != config_mod.RUNTIME_NS and peer.get("kind") == "peer"
            and "retransmit" not in record)


def preserve(cfg: Any, name: str, req_id: str, record: Dict[str, Any],
             blobs: List[bytes]) -> Path:
    """The committed copy of `record` as handed, with its `blobs`. Idempotent:
    a committed copy equal on every field but `preserved_ts` is accepted and
    kept; a different one is `PreservationConflict`; an uncommitted directory
    is removed and written again."""
    from . import clock
    lid, gen = _gen_of(cfg, name)
    peer_id = record["peer"]["id"]
    d = copy_dir(cfg.state_dir, lid, peer_id)
    origin = {"v": 1, "id": peer_id, "logical_id": lid, "generation": gen,
              "transport_req_id": record["transport_req_id"], "req_id": req_id,
              "preserved_ts": format_utc_ts(clock.now())}
    if committed(d):
        _compare_committed(d, record, origin, blobs)
        return d
    if d.exists():
        shutil.rmtree(d)                       # uncommitted: never read as a copy
    (d / ATTACHMENTS).mkdir(parents=True, mode=0o700)
    for i, data in enumerate(blobs):
        atomic_write(d / ATTACHMENTS / str(i), data, durable_root=Path(cfg.state_dir))
    atomic_write(d / RECORD, _canonical(record), durable_root=Path(cfg.state_dir))
    atomic_write(d / ORIGIN, _canonical(origin), durable_root=Path(cfg.state_dir))
    fsync_dir(d / ATTACHMENTS)
    fsync_dir(d)
    _link_once(d / COMMIT, b"1\n", Path(cfg.state_dir))
    fsync_dir(d.parent)
    return d


def _compare_committed(d: Path, record: Mapping[str, Any], origin: Mapping[str, Any],
                       blobs: List[bytes]) -> None:
    have = _read_json(d / ORIGIN) or {}
    want = {k: v for k, v in origin.items() if k != "preserved_ts"}
    if ((d / RECORD).read_bytes() != _canonical(record)
            or {k: v for k, v in have.items() if k != "preserved_ts"} != want
            or [(d / ATTACHMENTS / str(i)).read_bytes() for i in range(len(blobs))] != blobs
            or len(list((d / ATTACHMENTS).iterdir())) != len(blobs)):
        raise PreservationConflict(f"{d}: a committed copy differs")


def has_copy(cfg: Any, name: str, record: Mapping[str, Any]) -> bool:
    """Whether `record`'s original has a committed copy."""
    lid, _gen = _gen_of(cfg, name)
    return committed(copy_dir(cfg.state_dir, lid, record["peer"]["id"]))


def note_handed(cfg: Any, name: str, record: Mapping[str, Any]) -> bool:
    """`handed.json`, linked once by a pass that FINDS the handed marker."""
    from . import clock
    if not preservable(cfg, name, record):
        return False
    lid, _gen = _gen_of(cfg, name)
    d = copy_dir(cfg.state_dir, lid, record["peer"]["id"])
    if not committed(d) or (d / HANDED).exists():
        return False
    return _link_once(d / HANDED, _canonical({"v": 1, "handed_ts": format_utc_ts(clock.now())}),
                      Path(cfg.state_dir))


def note_settled(cfg: Any, name: str, record: Mapping[str, Any],
                 verdict: Mapping[str, Any]) -> bool:
    """`settled.json`, linked once by the original's settlement."""
    from . import clock
    if not preservable(cfg, name, record):
        return False
    lid, _gen = _gen_of(cfg, name)
    d = copy_dir(cfg.state_dir, lid, record["peer"]["id"])
    if not committed(d):
        return False
    return _link_once(d / SETTLED, _canonical({
        "v": 1, "outcome": verdict.get("outcome"), "reason_code": verdict.get("reason_code"),
        "settled_ts": format_utc_ts(clock.now())}), Path(cfg.state_dir))


# ---------------------------------------------------------------------------
# Reading a copy
# ---------------------------------------------------------------------------

def find(cfg: Any, peer_id: str) -> List[Tuple[str, str, Path]]:
    """Every (instance name, logical_id, directory) holding a COMMITTED copy
    of `peer_id`, by the identities this config resolves."""
    out = []
    for name in sorted(cfg.instances):
        try:
            lid = config_mod.state_key(cfg, name)
        except config_mod.StateKeyUnresolved:
            continue
        d = copy_dir(cfg.state_dir, lid, peer_id)
        if committed(d):
            out.append((name, lid, d))
    return out


def load(d: Path) -> Dict[str, Any]:
    """The copy, re-checked: `Refused("preservation_damaged")` otherwise."""
    from . import inflight, peerlane
    record, origin = _read_json(d / RECORD), _read_json(d / ORIGIN)
    if record is None or origin is None:
        raise Refused("preservation_damaged", f"{d}: record or origin unreadable")
    try:
        inflight.check_record(record)
    except inflight.RecordDamaged as e:
        raise Refused("preservation_damaged", f"{d}: {e}") from None
    pin = record.get("peer") or {}
    import base64
    try:
        statement = base64.b64decode(pin["statement"], validate=True)
        stmt = json.loads(statement)
    except (KeyError, ValueError, TypeError):
        raise Refused("preservation_damaged", f"{d}: the statement does not decode") from None
    draft = record["request"].get("draft") or {}
    body = draft.get("body_text")
    if not isinstance(body, str) or hashlib.sha256(
            peerlane.normalise_body(body).encode("utf-8")).hexdigest() != stmt.get("body_sha256"):
        raise Refused("preservation_damaged", f"{d}: the body does not match body_sha256")
    if draft.get("subject") != stmt.get("subject") or draft.get("to") != [stmt.get("to")]:
        raise Refused("preservation_damaged", f"{d}: subject or to differs from the statement")
    blobs = []
    for i, want in enumerate(record.get("attachments") or []):
        try:
            data = (d / ATTACHMENTS / str(i)).read_bytes()
        except OSError:
            raise Refused("preservation_damaged", f"{d}: attachment {i} unreadable") from None
        if len(data) != want["size_bytes"] or hashlib.sha256(data).hexdigest() != want["sha256"]:
            raise Refused("preservation_damaged", f"{d}: attachment {i} differs")
        signed = (stmt.get("attachments") or [])[i] if i < len(stmt.get("attachments") or []) else {}
        if signed.get("sha256") != want["sha256"]:
            raise Refused("preservation_damaged", f"{d}: attachment {i} is not the signed one")
        blobs.append(data)
    return {"record": record, "origin": origin, "statement": stmt, "blobs": blobs,
            "handed": _read_json(d / HANDED), "settled": _read_json(d / SETTLED),
            "claim": _read_json(d / CLAIM), "dir": d}


def retransmits(d: Path) -> List[Dict[str, Any]]:
    r = d / RETRANSMITS
    return [doc for p in sorted(r.iterdir()) if p.name.endswith(".json")
            for doc in [_read_json(p)] if doc] if r.is_dir() else []


# ---------------------------------------------------------------------------
# Eligibility and the gate
# ---------------------------------------------------------------------------

def answered(cfg: Any, lid: str, peer_id: str) -> Optional[str]:
    """Why the original is answered, or None: a control notice received for
    `peer_id` (the one-per-message `notified/` marker), or a signed Result:
    a placed peer statement whose signed `in_reply_to` is `peer_id`, found
    in the receive journal (its record outlives the original's window).

    The journal is read strictly (`peerjournal.strict_records`): a journal
    that cannot be read reliably, or a placed statement whose snapshot is
    missing or unreadable, is `peerjournal.JournalBlind`, never "not
    answered". No journal at all (never journaled) is "not answered"."""
    from . import peerjournal, peerledger
    if peerledger.notified_path(cfg.state_dir, lid, peer_id).exists():
        return "a control notice was received for it"
    for rec in peerjournal.strict_records(Path(cfg.state_dir)):
        if rec.get("disposed") != "placed":
            continue
        try:
            raw = peerjournal.read_snapshot(Path(cfg.state_dir), rec,
                                            peerjournal.SNAPSHOT_STATEMENT)
            doc = json.loads(raw) if raw is not None else None
        except (OSError, ValueError) as e:
            raise peerjournal.JournalBlind(
                f"a placed statement's snapshot cannot be read ({rec.get('key')}: "
                f"{type(e).__name__}), so whether it answers this task cannot be told") from None
        if not isinstance(doc, dict):
            raise peerjournal.JournalBlind(
                f"a placed statement's snapshot is missing or not a statement "
                f"({rec.get('key')}), so whether it answers this task cannot be told")
        if doc.get("in_reply_to") == peer_id:
            return "a signed Result was received for it"
    return None


def journal_blind(cfg: Any) -> Optional[str]:
    """Why the receive journal cannot be read reliably, or None: every
    resend step that needs `answered` holds while it is (never "not
    answered", never a hand-over)."""
    from . import peerjournal
    try:
        peerjournal.strict_records(Path(cfg.state_dir))
    except peerjournal.JournalBlind as e:
        return str(e)
    return None


def window_end(cfg: Any, statement: Mapping[str, Any]) -> Optional[datetime]:
    """`ts + P + F` on this router's configured window (the stated
    assumption: fleet receivers run the same frozen bounds, and clocks obey
    F), or None when `ts` does not parse."""
    ts = parse_utc_ts(statement.get("ts"))
    dc = getattr(cfg, "delegation", None)
    if ts is None or dc is None:
        return None
    return ts + timedelta(seconds=dc.window_p + dc.window_f)


def clock_trusted(cfg: Any) -> bool:
    """Whether the peer clock is trusted. The receive journal, and so a
    received signed Result (`answered`), is readable only under it: while
    it is untrusted nothing here may conclude "not answered"."""
    from . import peerclock
    try:
        peerclock.read(Path(cfg.state_dir))
    except peerclock.ClockUntrusted:
        return False
    return True


def check_dynamic(cfg: Any, name: str, lid: str, copy: Mapping[str, Any], *,
                  allow_pending: bool, now: datetime, configured: bool = False) -> None:
    """Every check that can change between the verb and the first hand-over
    (refusals 3, 4, 5 and 6); `Refused` naming the first that fails. The
    signing key is the ACTIVE delegation's in the drain; an operator
    command (`configured`) never activates delegation (only the drain's
    startup and reload do), so it checks the CONFIGURED key, which is the
    one activation signs with, and the drain checks again before the first
    hand-over."""
    from . import inflight, peerjournal, peerlane
    pin = copy["record"]["peer"]
    if not clock_trusted(cfg):
        raise Refused("clock_untrusted", "the peer clock is untrusted: a received Result "
                                         "cannot be seen; recover the clock first")
    if configured:
        dc = getattr(cfg, "delegation", None)
        key_id = dc.signing_key_id if dc is not None else None
    else:
        delegation = peerlane.active(cfg)
        key_id = delegation.key_id if delegation is not None else None
    if key_id is None:
        raise Refused("peer_lane_inactive", "the peer lane is not active")
    if pin["key_id"] != key_id:
        # Conservative: during a rotation overlap a receiver may still accept
        # the old key, so this can refuse a retransmit that would succeed; it
        # never sends one a stricter check would refuse.
        raise Refused("key_rotated", f"signed under {pin['key_id']}, the signing key is now "
                                     f"{key_id}")
    end = window_end(cfg, copy["statement"])
    if end is None or now > end:
        raise Refused("outside_window", f"ts {copy['statement'].get('ts')} is past ts + P + F")
    try:
        why = answered(cfg, lid, pin["id"])
    except peerjournal.JournalBlind as e:
        raise Refused("journal_unreadable", f"a received Result cannot be ruled out: {e}") from None
    if why:
        raise Refused("answered", why)
    settled = copy.get("settled")
    if settled is not None and settled.get("reason_code") == "delivery_unknown":
        pass                                     # trigger 1
    elif settled is not None and settled.get("outcome") != "accepted":
        raise Refused("not_eligible", f"settled {settled.get('outcome')}/"
                                      f"{settled.get('reason_code')}")
    else:                                        # trigger 2: still pending, or accepted
        handed = parse_utc_ts((copy.get("handed") or {}).get("handed_ts"))
        if handed is None:
            raise Refused("not_eligible", "no hand-over time yet (trigger 2 needs one)")
        if (now - handed).total_seconds() < inflight.STALE_AFTER_S:
            raise Refused("not_yet_stale", f"handed {format_utc_ts(handed)}; the threshold is "
                                           f"{inflight.STALE_AFTER_S}s")
        if not allow_pending:
            raise Refused("not_eligible", "no Result and no control notice: pass "
                                          "--allow-pending to retransmit beside the original")
    try:
        config_mod.gen_key(cfg, name)
    except config_mod.StateKeyUnresolved as e:
        raise Refused("generation_unavailable", str(e)) from None


def gate(cfg: Any, name: str, record: Mapping[str, Any], now: datetime) -> Optional[Tuple[str, str]]:
    """Before a retransmit record's FIRST hand-over: every dynamic refusal
    again, the copy's re-checks included. `(code, detail)` cancels it,
    unless the code is in `HOLD_CODES`, which hold it instead. (The
    drain holds a record BEFORE this, unhanded and unsettled, while the clock
    is untrusted or the receive journal cannot be read reliably:
    `outbound._advance_one`.) (A
    record in a fenced generation never reaches it: under the hop a fenced
    generation advances only once its tree is retired, and an unhanded
    record there settles `rejected/no_route` first, `inflight.advance`.)"""
    rt = record["retransmit"]
    lid = config_mod.state_key(cfg, name)
    try:
        copy = load(copy_dir(cfg.state_dir, lid, rt["id"]))
        check_dynamic(cfg, name, lid, copy, allow_pending=True, now=now)
    except Refused as e:
        return e.code, e.detail
    return None


# ---------------------------------------------------------------------------
# The verb
# ---------------------------------------------------------------------------

def _audit(cfg: Any, act: str, now: datetime, **fields: Any) -> None:
    """One operator-audit line per (act, id, generation, n): idempotent."""
    from . import peerjournal
    sd = Path(cfg.state_dir)
    path = sd / peerjournal.REPLAY_DIR / peerjournal.OPERATOR_AUDIT
    key = (act, fields.get("id"), fields.get("generation"), fields.get("n"))
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            doc = json.loads(line)
            if (doc.get("act"), doc.get("id"), doc.get("generation"), doc.get("n")) == key:
                return
    except (OSError, ValueError):
        pass
    peerjournal._audit(sd, act, now, **fields)


def operator_retransmit(cfg: Any, peer_id: str, *, now: datetime, evidence: str,
                        allow_pending: bool = False) -> Dict[str, Any]:
    """`router peer-request retransmit <id>`: refusals first, nothing written;
    then the claim, the requested line, and the retransmit record."""
    from . import inflight, peerclock
    if not (isinstance(evidence, str) and evidence.strip()):
        raise Refused("evidence_required", "evidence is required")
    found = find(cfg, peer_id) if _PEER_ID_RE.fullmatch(peer_id) else []
    if not found:
        raise Refused("not_preserved", f"no committed copy of {peer_id}")
    if len(found) > 1:
        raise Refused("ambiguous", f"{peer_id} is committed under {[f[1] for f in found]}")
    name, lid, d = found[0]
    copy = load(d)
    if copy["claim"] is not None:
        raise Refused("retransmit_pending", f"a retransmit of {peer_id} is claimed: "
                                            f"{copy['claim'].get('generation')}-"
                                            f"{copy['claim'].get('n')}")
    check_dynamic(cfg, name, lid, copy, allow_pending=allow_pending, now=now, configured=True)
    rc = _sender_recheck(cfg, name, copy)
    if rc is not None:
        raise Refused("policy_changed", rc)
    _lid, gen = _gen_of(cfg, name)
    n = inflight.reserve_transport_id(cfg, name)
    claim = {"v": 1, "generation": gen, "n": n, "claimed_ts": format_utc_ts(now),
             "by": peerclock.operator_by(), "evidence": evidence}
    if not _link_once(d / CLAIM, _canonical(claim), Path(cfg.state_dir)):
        raise Refused("retransmit_pending", f"a retransmit of {peer_id} was claimed meanwhile")
    _audit(cfg, REQUESTED, now, id=peer_id, generation=gen, n=n, by=claim["by"],
           evidence=evidence)
    begin_record(cfg, name, copy, claim)
    return {"result": f"retransmit of {peer_id} claimed as {gen}-{n}", "generation": gen,
            "n": n, "audited": True}


def _sender_recheck(cfg: Any, name: str, copy: Mapping[str, Any]) -> Optional[str]:
    """The sender's current policy over the copy's request, or why it refuses."""
    from . import outbound
    rec = dict(copy["record"])
    rec["request"] = dict(rec["request"], req_id=rtx_name("00000000"))
    # The CONFIGURED key: this runs in an operator command, which never
    # activates delegation (check_dynamic(configured=True) proved one is set).
    rc = outbound._recheck_peer(cfg, name, rec, lambda why: _Refusal(why),
                                key_id=cfg.delegation.signing_key_id)
    return None if rc.permitted else rc.why


class _Refusal:
    def __init__(self, why: str):
        self.permitted, self.why = False, why


def begin_record(cfg: Any, name: str, copy: Mapping[str, Any], claim: Mapping[str, Any]) -> None:
    """The retransmit's in-flight record `rtx.<n>`, from the copy: request
    (its `req_id` the record's own name), recipients, from_address,
    attachments, peer, digest; a fresh `written_ts`; the `retransmit` pin.
    Idempotent: a record already there under `n` is kept."""
    from . import attachments as attachments_mod
    from . import inflight
    rec = copy["record"]
    n = claim["n"]
    rid = rtx_name(n)
    if inflight.read_record(cfg, name, rid) is not None:
        return
    request = dict(rec["request"], req_id=rid)
    draft = request.get("draft") or {}
    atts = [attachments_mod.VerifiedAttachment(
        filename=a.get("filename", ""), media_type=a.get("media_type", ""),
        size_bytes=w["size_bytes"], sha256=w["sha256"], data=data)
        for a, w, data in zip(draft.get("attachments") or [{}] * len(copy["blobs"]),
                              rec.get("attachments") or [], copy["blobs"])]
    inflight.begin_reserved(
        cfg, name, rid, n, digest=rec.get("digest"), request_doc=request,
        recipients=list(rec["recipients"]), from_address=rec["from_address"],
        attachments=atts or None, peer=dict(rec["peer"]),
        retransmit={"of_generation": copy["origin"]["generation"],
                    "of_n": copy["origin"]["transport_req_id"], "id": rec["peer"]["id"]})


def settle_retransmit(cfg: Any, name: str, record: Mapping[str, Any],
                      verdict: Mapping[str, Any]) -> str:
    """A retransmit's settlement, from ANY settle path: `retransmits/
    <generation>-<n>.json`, linked once. Never the agent's Result or anchor."""
    from . import clock
    rt = record["retransmit"]
    lid, gen = _gen_of(cfg, name)
    d = copy_dir(cfg.state_dir, lid, rt["id"])
    (d / RETRANSMITS).mkdir(exist_ok=True, mode=0o700)
    _link_once(d / RETRANSMITS / f"{gen}-{record['transport_req_id']}.json", _canonical({
        "v": 1, "generation": gen, "n": record["transport_req_id"],
        "outcome": verdict.get("outcome"), "reason_code": verdict.get("reason_code"),
        "settled_ts": format_utc_ts(clock.now())}), Path(cfg.state_dir))
    return str(verdict.get("outcome") or "")


def retransmit_settled(cfg: Any, name: str, record: Mapping[str, Any]) -> bool:
    lid, gen = _gen_of(cfg, name)
    d = copy_dir(cfg.state_dir, lid, record["retransmit"]["id"])
    return (d / RETRANSMITS / f"{gen}-{record['transport_req_id']}.json").is_file()


def finish(cfg: Any, name: str, now: datetime, *, fenced: bool = False) -> int:
    """`fenced`: `cfg` is a view of a FENCED generation (`outbound._drain_fenced`);
    a claim there whose record was never begun is cancelled
    `generation_unavailable` (refusal 6), never begun.

    Recovery and completion for every claimed copy of `name`: a claim
    without its requested line gets it; a claim with neither record nor
    settlement gets its record (or, failing the gate, a cancellation); a
    settled claim whose record is gone gets its settled line, then the claim
    is removed, LAST. Returns how many claims were finished."""
    if not enabled(cfg):
        return 0
    from . import inflight
    try:
        lid, gen_now = _gen_of(cfg, name)
    except config_mod.StateKeyUnresolved:
        return 0
    root = sent_root(cfg.state_dir, lid)
    done = 0
    for d in sorted(root.iterdir()) if root.is_dir() else ():
        claim = _read_json(d / CLAIM)
        if claim is None or not committed(d):
            continue
        gen, n = claim["generation"], claim["n"]
        _audit(cfg, REQUESTED, parse_utc_ts(claim["claimed_ts"]) or now, id=d.name,
               generation=gen, n=n, by=claim["by"], evidence=claim["evidence"])
        settled = _read_json(d / RETRANSMITS / f"{gen}-{n}.json")
        if gen != gen_now:
            continue                          # its generation's own pass finishes it
        live = inflight.read_record(cfg, name, rtx_name(n))
        if settled is None and live is None and (not clock_trusted(cfg) or journal_blind(cfg)):
            continue                          # held, never cancelled, until the journal reads
        if settled is None and live is None:
            try:
                if fenced:
                    raise Refused("generation_unavailable", "its generation is fenced")
                copy = load(d)
                check_dynamic(cfg, name, lid, copy, allow_pending=True, now=now)
                begin_record(cfg, name, copy, claim)
            except Refused as e:
                settle_retransmit(cfg, name, {"retransmit": {"id": d.name},
                                              "transport_req_id": n},
                                  {"outcome": CANCELLED, "reason_code": e.code})
                settled = _read_json(d / RETRANSMITS / f"{gen}-{n}.json")
        if settled is not None and live is None:
            _audit(cfg, SETTLED_ACT, now, id=d.name, generation=gen, n=n, by=claim["by"],
                   outcome=settled.get("outcome"), reason_code=settled.get("reason_code"))
            os.unlink(d / CLAIM)
            fsync_dir(d)
            done += 1
    return done


# ---------------------------------------------------------------------------
# Reconcile
# ---------------------------------------------------------------------------

def show(cfg: Any, peer_id: str, *, now: datetime) -> Dict[str, Any]:
    """`router peer-request show <id>`: read-only, for ANY issued id."""
    from . import peerlane
    out: Dict[str, Any] = {"id": peer_id}
    issued = []
    for name in sorted(cfg.instances):
        try:
            lid = config_mod.state_key(cfg, name)
        except config_mod.StateKeyUnresolved:
            continue
        rec = _read_json(peerlane.ledger_path(cfg, name, peer_id)) \
            if _PEER_ID_RE.fullmatch(peer_id) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", peer_id) \
            else None
        if rec is not None:
            issued.append({"instance": name, "logical_id": lid, "record": rec})
    out["issued"] = issued
    found = find(cfg, peer_id) if _PEER_ID_RE.fullmatch(peer_id) else []
    if not found:
        out["preserved"] = None
        out["actions"] = {"retransmit": "not available: " + (
            "not_preserved" if issued else "no issued record")}
        return out
    if len(found) > 1:
        out["preserved"] = [f[1] for f in found]
        out["actions"] = {"retransmit": "refused: ambiguous"}
        return out
    name, lid, d = found[0]
    try:
        copy = load(d)
    except Refused as e:
        out["preserved"] = {"damaged": e.detail}
        out["actions"] = {"retransmit": f"refused: {e.code}"}
        return out
    origin, pin = copy["origin"], copy["record"]["peer"]
    out["preserved"] = {"logical_id": lid, "generation": origin["generation"],
                        "transport_req_id": origin["transport_req_id"], "req_id": origin["req_id"],
                        "key_id": pin["key_id"], "message_id": pin["message_id"],
                        "ts": copy["statement"].get("ts"), "preserved_ts": origin["preserved_ts"]}
    out["handed"] = copy["handed"]
    out["settled"] = copy["settled"]
    out["claim"] = ({k: v for k, v in copy["claim"].items() if k != "evidence"}
                    if copy["claim"] else None)
    out["retransmits"] = retransmits(d)
    out["agent_result"] = _origin_result(cfg, lid, origin)
    # A received signed Result is readable only under a trusted clock: never
    # report "not answered" when it cannot be known.
    from . import peerjournal
    if not clock_trusted(cfg):
        out["answered"] = "unknown (clock untrusted)"
    else:
        try:
            out["answered"] = answered(cfg, lid, peer_id)
        except peerjournal.JournalBlind as e:
            out["answered"] = f"unknown (journal unreadable: {e})"
    try:
        check_dynamic(cfg, name, lid, copy, allow_pending=True, now=now, configured=True)
        rc = _sender_recheck(cfg, name, copy)
        verdict = ("refused: policy_changed" if rc is not None
                   else "available" if copy["claim"] is None else "refused: retransmit_pending")
    except Refused as e:
        verdict = f"refused: {e.code}"
    out["actions"] = {"reconcile": "this output, and the receiving router's status for the id",
                      "retransmit": verdict,
                      "new_task": "the agent submits a new request (new request id, new peer id)"}
    return out


def _origin_result(cfg: Any, lid: str, origin: Mapping[str, Any]) -> bool:
    """The original's Result, read by path in its own generation's
    directory, retired or not."""
    return (Path(cfg.state_dir) / lid / f"gen-{origin['generation']}" / "results"
            / f"{origin['req_id']}.json").is_file()


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------

def sweep(cfg: Any, name: str, now: datetime) -> int:
    """Remove every copy of `name` that is settled, unclaimed, without a
    retransmit record, and past `ts + P + F + PRUNE_GRACE`: a prune claim,
    then the directory bottom-up, then the claim. A copy found with a prune
    claim is finished first. Off only when `peer_sent_prune` is false."""
    if not enabled(cfg):
        return 0
    from . import inflight
    if not clock_trusted(cfg):
        return 0                              # held, like every resend step, until it recovers
    if not getattr(cfg, "peer_sent_prune", True):
        return 0
    try:
        lid = config_mod.state_key(cfg, name)
    except config_mod.StateKeyUnresolved:
        return 0
    root = sent_root(cfg.state_dir, lid)
    pruned = 0
    for d in sorted(root.iterdir()) if root.is_dir() else ():
        if (d / PRUNE_CLAIM).exists():
            _remove(d)
            pruned += 1
            continue
        if not committed(d) or (d / CLAIM).exists() or not (d / SETTLED).exists():
            continue
        record = _read_json(d / RECORD) or {}
        try:
            stmt = json.loads(base64.b64decode(record["peer"]["statement"]))
        except Exception:  # noqa: BLE001 -- unreadable: never pruned blind
            continue
        end = window_end(cfg, stmt)
        if end is None or now <= end + PRUNE_GRACE:
            continue
        if any(inflight.read_record(cfg, n, r) is not None
               for n in [name] for r in inflight.list_records(cfg, n)
               if is_rtx(r) and (inflight.read_record(cfg, n, r) or {}).get(
                   "retransmit", {}).get("id") == d.name):
            continue
        _link_once(d / PRUNE_CLAIM, b"1\n", Path(cfg.state_dir))
        _remove(d)
        pruned += 1
    return pruned


def _remove(d: Path) -> None:
    """Bottom-up, the prune claim LAST."""
    for p in sorted(d.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if p.name == PRUNE_CLAIM and p.parent == d:
            continue
        if p.is_dir() and not p.is_symlink():
            p.rmdir()
        else:
            p.unlink()
    fsync_dir(d)
    (d / PRUNE_CLAIM).unlink()
    d.rmdir()
    fsync_dir(d.parent)


def status(cfg: Any, name: str) -> Dict[str, int]:
    """Per identity: copies, in flight (no `settled.json`), settled,
    claimed, retransmits by outcome."""
    try:
        lid = config_mod.state_key(cfg, name)
    except config_mod.StateKeyUnresolved:
        return {}
    root = sent_root(cfg.state_dir, lid)
    out: Dict[str, int] = {"preserved": 0, "in_flight": 0, "settled": 0, "claimed": 0}
    for d in sorted(root.iterdir()) if root.is_dir() else ():
        if not committed(d):
            continue
        out["preserved"] += 1
        out["settled" if (d / SETTLED).exists() else "in_flight"] += 1
        out["claimed"] += int((d / CLAIM).exists())
        for doc in retransmits(d):
            key = f"retransmit_{doc.get('outcome')}"
            out[key] = out.get(key, 0) + 1
    return out
