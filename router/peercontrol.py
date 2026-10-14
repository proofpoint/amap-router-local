"""router/peercontrol.py — control notices OUT, through the router's own
runtime control tree.

A statement this router decided not to place (refused, dropped, demoted)
carries a PENDING control notice in its journal record (`record.control`,
written with the disposition: outcome, cause, about, the destination `to`,
`sent: false`). This module sends each one, once, to the configured runtime
of the statement key's owner, as a signed `kind: control` statement in the
router's own runtime tree `<hop_root>/.runtime/<generation>/`, never through
an agent's.

THE RUNTIME CAPABILITY (provisional). The runtime tree is reached ONLY through
the plugin's runtime capability, named in one table, `transport.RUNTIME_CAPABILITY`
(provisional until HOP-RUNTIME-IDENTITY freezes):

- `make_runtime_sender(settings, fsops)`, bound to one generation, with closed
  settings `{hop_root, generation, peer_uid, address}`: the sender protocol,
  and `retire(retired_at)`, `retired()`, `retired_at()`, `identity()`.
- `make_runtime_lister(settings, fsops)`, with closed settings
  `{hop_root, peer_uid}`, READ-ONLY: `generations()` lists every runtime
  generation as `(generation, state)`, state `live`, `retired` or
  `unreadable`; an absent tree lists empty.

A plugin that declares neither (every plugin today) leaves the capability OFF:
pending controls stay pending, status says the runtime tree is unavailable,
the operator verbs refuse `runtime_tree_unavailable`, and no plugin factory is
ever called with the runtime tree. Nothing here reads or writes the runtime
tree except through the capability, and nothing classifies a generation but
from what the lister returns.

THE ONE RUNTIME GENERATION. Recorded at `state_dir/_runtime/generation.json`.
A new one is minted only when the lister shows no generation that is `live`
or `unreadable` (an unreadable marker blocks the mint: fail closed). A lost
record beside a live generation, or two live generations, holds until an
audited operator verb adopts or retires one.

THE ATTEMPT (one per pending notice), each step durable before the next:
  0. the coalescing owner, link-once, `_runtime/coalesce/<sha256(runtime NUL
     about NUL cause)>`, naming the record that sends for that triple; any
     other record with the triple is `coalesced` and never attempted;
  1. `control.attempt = {id, at}`, the intent;
  2. a transport id reserved in the runtime namespace;
  3. the statement built, validated and signed at `ts` = the clock NOW, and
     frozen with the attempt (`statement_b64`, `signature_b64`, `header`):
     never signed again;
  4. the runtime in-flight record begun under exactly that id;
  5. advanced (the handed marker, then the request);
  6. settled from the runtime tree's result: `sent`, with the outcome;
     `delivery_unknown`, `rejected` and `halted` are recorded, never retried.
Recovery resumes at the step reached: after 2 and before 3 the id is burned
(nothing was signed); after 3 the frozen bytes are begun under the recorded
id, in the attempt's OWN generation, reconciled before anything else. A
lost generation record is restored to it, AUDITED, when the lister shows it
live or does not list it at all (never admitted, so nothing was handed over
in it) and shows no other generation live or unreadable. Otherwise the
attempt is held visibly (`attempt_generation_unrecorded`, or
`attempt_generation_not_recorded_one` when another is recorded); no other
generation is ever selected for it, and while any unsent attempt is frozen
in a generation other than the recorded one, none is minted (read from the
journal's state, whatever order a pass visits records in; frozen attempts are
also visited first). Its exits are `adopt`, or the audited `abandon-attempt`, which
suppresses the notice (`attempt_abandoned`). After 4 the in-flight machinery
drives it. A handed marker with no
record holds, recorded on the record as `control.stuck` (reason
`handed_without_record`), never re-sent. An attempt with no result past the
settle horizon (`SETTLE_HORIZON_S`) is recorded stuck too (reason
`unsettled_past_horizon`), and is still driven, so a late result settles it;
it is never re-signed or re-sent. Status counts both, with their age.

THE GENERATION IS CLASSIFIED EVERY TIME. A recorded generation is used only
when the lister shows it `live` (or not yet listed: minted, its tree not yet
admitted) and shows no other generation `live` or `unreadable`. A recorded
generation the lister shows `retired` (a crash after the capability retired
it and before the record was removed) is never written again; an
`unreadable` one holds. An attempt whose generation is now `retired` is not
handed over.

RATE AND SUPPRESSION. Per destination runtime, a token bucket (default 60 per
hour) in `_runtime/rate-buckets.json`, refilled on H (the store's clock,
raised only), never on raw wall time. A notice over the limit is deferred,
released oldest first by `take_seq`, and suppressed (`rate_limited`) once
deferred for 24 h of H. A destination no longer configured for the key's
owner is suppressed (`unconfigured_runtime`), never redirected. While H is
untrusted (the clock unreadable, or peer admission closed) nothing is
attempted, nothing is minted and no bucket refills. A notice deferred past
the 24 h horizon is suppressed BEFORE any token is taken. `sent` means handed and
settled by the hop, never delivered.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import config as config_mod
from . import peerbind, peerclock, peerjournal
from .util import atomic_write, format_utc_ts, fsync_dir, parse_utc_ts

logger = logging.getLogger("amap_router_local.peercontrol")

#: The control schema's outcome -> cause sets (closed).
CAUSES: Mapping[str, frozenset] = {
    "refused": frozenset({"unresolved_reply", "no_edge", "policy"}),
    "dropped": frozenset({"duplicate", "misrouted"}),
    "demoted": frozenset({"statement_value", "key_domain", "ts_window", "exposure_signer",
                          "body_charset", "body_digest", "attachment_count",
                          "attachment_digest", "message_id"}),
}
COALESCE_DIR = "coalesce"
RATE_FILE = "rate-buckets.json"
DEFAULT_RATE_PER_HOUR = 60
DEFER_LIMIT_S = 86400
SUPPRESS_UNCONFIGURED = "unconfigured_runtime"
SUPPRESS_RATE = "rate_limited"
SUPPRESS_COALESCED = "coalesced"
SUPPRESS_ABANDONED = "attempt_abandoned"
RESTORE_VERB = "runtime-generation restore (automatic)"
ABANDON_VERB = "runtime-generation abandon-attempt"
UNAVAILABLE = "runtime_tree_unavailable"
STUCK_HANDED = "handed_without_record"
STUCK_UNSETTLED = "unsettled_past_horizon"
#: A pending notice with no `about` or no `to` cannot be addressed: HELD,
#: visibly, under this reason, never labelled `unconfigured_runtime`.
HELD_NO_DESTINATION = "destination_unknown"
DELEGATION_INACTIVE = "delegation_inactive"
#: A frozen attempt whose generation cannot be used as recorded: held
#: visibly (status `held`), never re-signed, never moved to another
#: generation. The exits: `router runtime-generation adopt <gen>` when the
#: lister shows that generation as the only live one, or
#: `router runtime-generation abandon-attempt <record key>`, which ends the
#: notice suppressed `attempt_abandoned`. While any unsent attempt is frozen
#: in a generation other than the recorded one, no new generation is minted.
HELD_GENERATION_UNRECORDED = "attempt_generation_unrecorded"
HELD_GENERATION_MISMATCH = "attempt_generation_not_recorded_one"
GENERATION_HOLDS = frozenset({HELD_GENERATION_UNRECORDED, HELD_GENERATION_MISMATCH})
#: The settle horizon: an attempt with no result this long after it was
#: signed is recorded stuck. Reporting only, the in-flight records' own
#: staleness bound (`inflight.STALE_AFTER_S`): nothing is settled on age.
SETTLE_HORIZON_S = 3600
#: The settled outcomes that mean the hop took the notice; every other
#: settled outcome (`rejected`, `halted`, `delivery_unknown`, anything
#: unknown) is counted as a failure, never as sent.
SENT_OUTCOMES = frozenset({"accepted", "queued_for_human"})
#: The runtime tree's identity marker logical_id (contract W6); its settings
#: spelling is HOP-RUNTIME-IDENTITY's to fix.
RUNTIME_AGENT_ID = "runtime"
_STAGE = ".coalesce-stage-"


class Unavailable(Exception):
    """The runtime tree cannot be used this pass; `reason` says why."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


def runtime_address(cfg: Any) -> str:
    """This router's own runtime address."""
    return f"amap.router@{cfg.fleet_domain}"


def runtime_dir(cfg: Any) -> Path:
    return Path(cfg.state_dir) / config_mod.RUNTIME_NS


# ---------------------------------------------------------------------------
# The statement
# ---------------------------------------------------------------------------

def check_statement(doc: Mapping[str, Any]) -> None:
    """The control statement's closed shape, before it is signed: a mismatch
    is a bug in this router, so it raises."""
    want = {"v", "key_id", "kind", "id", "from", "to", "ts", "about", "outcome", "cause"}
    if doc.get("cause") == "policy":
        want = want | {"policy_code"}
    if set(doc) != want:
        raise ValueError(f"control statement members {sorted(doc)} are not {sorted(want)}")
    if doc["v"] != 1 or doc["kind"] != "control":
        raise ValueError("a control statement is v 1, kind control")
    if doc["cause"] not in CAUSES.get(doc["outcome"], ()):
        raise ValueError(f"cause {doc['cause']!r} is not one of outcome {doc['outcome']!r}'s")
    for key in ("id", "about"):
        if not (isinstance(doc[key], str) and doc[key]
                and all(c.isascii() and (c.isalnum() or c in "_-") for c in doc[key])):
            raise ValueError(f"{key} is outside the id grammar")
    if parse_utc_ts(doc["ts"]) is None:
        raise ValueError("ts is not a utc_ts")


def statement_doc(*, key_id: str, control_id: str, from_address: str, to: str, ts: str,
                  control: Mapping[str, Any]) -> Dict[str, Any]:
    doc = {"v": 1, "key_id": key_id, "kind": "control", "id": control_id,
           "from": from_address, "to": to, "ts": ts, "about": control["about"],
           "outcome": control["outcome"], "cause": control["cause"]}
    if control["cause"] == "policy":
        doc["policy_code"] = control.get("policy_code")
    check_statement(doc)
    return doc


# ---------------------------------------------------------------------------
# The capability
# ---------------------------------------------------------------------------

class Capability:
    """The plugin's runtime capability, when it declares one."""

    def __init__(self, plugin: Any, fsops: Any, cfg: Any):
        self.plugin, self.fsops, self.cfg = plugin, fsops, cfg

    def lister(self) -> Any:
        from . import transport as transport_mod
        settings = {"hop_root": str(self.cfg.hop.root), "peer_uid": self.cfg.hop.peer_uid}
        return transport_mod.runtime_factory(self.plugin, "lister")(settings, self.fsops)

    def generations(self) -> List[Tuple[str, str]]:
        from . import transport as transport_mod
        names = transport_mod.RUNTIME_CAPABILITY
        out = getattr(self.lister(), names["generations"])()
        listed = []
        for gen, state in out:
            if state not in ("live", "retired", "unreadable"):
                state = "unreadable"     # never read as definite
            listed.append((gen, state))
        return listed

    def sender(self, generation: str) -> Any:
        from . import transport as transport_mod
        settings = {"hop_root": str(self.cfg.hop.root), "generation": generation,
                    "peer_uid": self.cfg.hop.peer_uid, "address": runtime_address(self.cfg)}
        return transport_mod.runtime_factory(self.plugin, "factory")(settings, self.fsops)

    def retire(self, generation: str, retired_at: str) -> Any:
        from . import transport as transport_mod
        names = transport_mod.RUNTIME_CAPABILITY
        return getattr(self.sender(generation), names["retire"])(retired_at)


def capability(cfg: Any, runtime: Any) -> Optional[Capability]:
    """The runtime capability, or None when the loaded plugin does not
    declare BOTH factories at the minor that introduces them (OFF)."""
    from . import transport as transport_mod
    plugin = getattr(runtime, "plugin", None)
    fsops = getattr(runtime, "fsops", None)
    if plugin is None or fsops is None or getattr(cfg, "hop", None) is None:
        return None
    if not transport_mod.runtime_capability_declared(plugin):
        return None
    return Capability(plugin, fsops, cfg)


# ---------------------------------------------------------------------------
# The runtime generation
# ---------------------------------------------------------------------------

def generation(cfg: Any, cap: Optional[Capability], *, now: datetime) -> str:
    """The runtime generation to send in: the recorded one, or a new one
    minted when the lister shows nothing live or unreadable. `Unavailable`
    otherwise, saying why."""
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    try:
        recorded: Optional[str] = config_mod.runtime_generation(cfg)
    except config_mod.StateKeyUnresolved:
        recorded = None
    listed = cap.generations()
    states = dict(listed)
    others = [(g, s) for g, s in listed if s in ("live", "unreadable") and g != recorded]
    if recorded is not None:
        state = states.get(recorded)
        if state == "unreadable":
            raise Unavailable(UNAVAILABLE, f"the recorded generation {recorded} is unreadable")
        if state in ("live", None):
            if others:
                raise Unavailable(UNAVAILABLE, f"the recorded generation {recorded} beside "
                                               f"{others}: retire one (router runtime-generation)")
            return recorded
        # Retired: never written again, whatever the record says.
    if others:
        raise Unavailable(UNAVAILABLE, f"no usable recorded generation beside {others}: adopt "
                                       "or retire one (router runtime-generation)")
    frozen = _frozen_elsewhere(cfg, recorded)
    if frozen:
        # A frozen attempt still names a generation of its own: a new one
        # would split the runtime tree. It is restored, adopted or abandoned.
        raise Unavailable(UNAVAILABLE, f"a frozen attempt names another generation ({frozen[0]}):"
                                       " it is restored, adopted or abandoned first")
    gen = secrets.token_hex(16)
    record_generation(cfg, gen, now=now)
    return gen


def _frozen_elsewhere(cfg: Any, recorded: Optional[str]) -> List[str]:
    """The record keys of unsent, unsuppressed attempts frozen in a
    generation other than `recorded` (any generation, when none is
    recorded). Read from the journal's state, so the answer does not depend
    on which records a pass has visited."""
    out = []
    for rec in peerjournal.all_records(Path(cfg.state_dir)):
        c = rec.get("control") or {}
        gen = (c.get("attempt") or {}).get("gen")
        if gen is not None and gen != recorded and not c.get("sent") and not c.get("suppressed"):
            out.append(rec["key"])
    return out


class Committed(Exception):
    """An operator act COMMITTED its effect and something after it failed.
    Never a refusal: the CLI says COMMITTED and exits 3."""


class AuditPending(Committed):
    """An audited operator act COMMITTED, but its audit line could not be
    appended: a pending marker (on the record, or the verb marker file) is
    left, and the next pass or verb appends it."""

    def __init__(self, result: str, cause: BaseException):
        super().__init__(f"{result}; COMMITTED, but the audit line is pending "
                         f"({type(cause).__name__}: {cause})")
        self.result = result


def _verb_marker_path(cfg: Any) -> Path:
    return runtime_dir(cfg) / VERB_AUDIT_FILE


def _begin_verb_audit(cfg: Any, verb: str, now: datetime, **detail: Any) -> Dict[str, Any]:
    """A runtime-generation verb's pending audit marker, durable before the
    act. Verbs run one at a time under the drain lock, and each repairs any
    earlier marker first, so there is at most one."""
    marker = _audit_marker(verb, now, **detail)
    runtime_dir(cfg).mkdir(parents=True, exist_ok=True)
    atomic_write(_verb_marker_path(cfg), json.dumps(marker, sort_keys=True).encode("utf-8"),
                 durable_root=cfg.state_dir)
    return marker


def _finish_verb_audit(cfg: Any, marker: Mapping[str, Any], **extra: Any) -> None:
    sd = Path(cfg.state_dir)
    if not any(line.get("audit_id") == marker["id"] for line in _audit_lines(sd)):
        peerjournal._audit(sd, marker["verb"], parse_utc_ts(marker["at"]),
                           audit_id=marker["id"], **dict(marker["detail"], **extra))
    try:
        os.unlink(_verb_marker_path(cfg))
    except FileNotFoundError:
        pass
    fsync_dir(runtime_dir(cfg))


class PlanPending(Exception):
    """A verb's durable plan cannot be completed yet; it stays pending."""


def _complete_plan(cfg: Any, cap: Optional[Capability], marker: Mapping[str, Any],
                   now: datetime) -> str:
    """Carry a runtime-generation verb's durable plan forward, idempotently,
    and return its result: every step is checked against the state it
    produces and skipped once done. `PlanPending` when it cannot complete
    yet (no capability; a planned mint whose conditions do not hold)."""
    verb, d = marker["verb"], marker["detail"]
    if verb == ADOPT_VERB:
        record_generation(cfg, d["generation"], now=now)   # the record and the pin, rewritten
        return f"adopted {d['generation']}"
    if cap is None:
        raise PlanPending("the plugin declares no runtime capability")
    if verb == RETIRE_VERB:
        return _retire_idempotent(cfg, cap, d["generation"], now)
    if verb == NEW_VERB:
        retired = _retire_idempotent(cfg, cap, d["retired"], now)
        try:
            recorded: Optional[str] = config_mod.runtime_generation(cfg)
        except config_mod.StateKeyUnresolved:
            recorded = None
        if recorded is None:
            listed = dict(cap.generations())
            others = [g for g, st in listed.items() if st in ("live", "unreadable")]
            frozen = _frozen_elsewhere(cfg, None)
            if others or frozen:
                raise PlanPending(f"the planned mint is blocked by {others or frozen}")
        elif recorded != d["minted"]:
            raise PlanPending(f"another generation {recorded} is recorded")
        # The planned generation's FULL effect, the record AND its pin, is
        # replayed even when the record already names it: a pin write that
        # failed after the record committed is completed here.
        record_generation(cfg, d["minted"], now=now)
        return f"{retired}, minted {d['minted']}"
    raise PlanPending(f"unknown verb {verb!r}")


def _run_plan(cfg: Any, cap: Optional[Capability], marker: Mapping[str, Any],
              now: datetime) -> Dict[str, Any]:
    """Complete a verb's plan now. Once the plan is durable the act is
    committed: any failure from here on is `Committed` (exit 3), never a
    refusal, and the next pass or verb completes it."""
    try:
        result = _complete_plan(cfg, cap, marker, now)
    except Exception as e:  # noqa: BLE001 -- the plan is durable: never "refused"
        raise Committed(f"{marker['verb']}: COMMITTED (its plan is durable); completing it is "
                        f"pending ({type(e).__name__}: {e}); the next pass or verb completes "
                        "it") from e
    return _complete_verb(cfg, marker, result)


def _complete_verb(cfg: Any, marker: Mapping[str, Any], result: str,
                   **extra: Any) -> Dict[str, Any]:
    try:
        _finish_verb_audit(cfg, marker, result=result, **extra)
    except Exception as e:  # noqa: BLE001 -- committed; the audit is repaired later
        raise AuditPending(result, e) from e
    return {"result": result, "audited": True}


def _repair_verb_audit(cfg: Any, cap: Optional[Capability]) -> int:
    """A verb's pending plan: completed forward (idempotently), then its
    audit line appended once and the marker removed. A plan that cannot
    complete yet stays pending, and nothing else is lost."""
    try:
        marker = json.loads(_verb_marker_path(cfg).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return 0
    try:
        result = _complete_plan(cfg, cap, marker, parse_utc_ts(marker["at"]))
    except Exception:  # noqa: BLE001 -- pending; retried by the next pass or verb
        logger.warning("a runtime-generation plan (%s) is still pending", marker.get("verb"))
        return 0
    _finish_verb_audit(cfg, marker, result=result, completed_on_repair=True)
    return 1


ABANDON_PLAN_VERB = "runtime-generation abandon-plan"


def _pending_plan(cfg: Any) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(_verb_marker_path(cfg).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def _refuse_while_plan_pending(cfg: Any, cap: Optional[Capability]) -> None:
    """ONE plan at a time: every verb refuses, BEFORE any effect, while an
    earlier plan is still pending (the caller has already tried to complete
    it), naming why and its exits, so a committed effect's audit line is
    never overwritten."""
    marker = _pending_plan(cfg)
    if marker is None:
        return
    try:
        _complete_plan(cfg, cap, marker, parse_utc_ts(marker["at"]))
        why = "its completion has not been recorded yet"
    except Exception as e:  # noqa: BLE001 -- the reason it is still pending
        why = f"{type(e).__name__}: {e}"
    raise ValueError(
        f"a {marker.get('verb')} plan is pending: {why}. Its exits: it completes on its own "
        "once its conditions hold (the next pass or verb retries it), or end it with "
        "`router runtime-generation abandon-plan --evidence TEXT`, which audits what it "
        "committed")


def operator_abandon_plan(cfg: Any, cap: Optional[Capability], *, now: datetime,
                          evidence: str) -> Dict[str, Any]:
    """`router runtime-generation abandon-plan --evidence TEXT`: end a plan
    that cannot complete. Intent first: the PLAN's own audit line (its id,
    once) is appended, naming what it committed and that it was abandoned,
    BEFORE the plan is removed. Idempotent: a repeat after a crash finds the
    line and only removes the plan."""
    if not evidence:
        raise ValueError("evidence is required")
    marker = _pending_plan(cfg)
    if marker is None:
        raise ValueError("no runtime-generation plan is pending")
    try:
        result = _complete_plan(cfg, cap, marker, parse_utc_ts(marker["at"]))
        _finish_verb_audit(cfg, marker, result=result, completed_on_repair=True)
        return {"result": f"the {marker['verb']} plan completed: {result}", "audited": True}
    except Exception as e:  # noqa: BLE001 -- it cannot complete: abandoned, audited
        why = f"{type(e).__name__}: {e}"
    try:
        _finish_verb_audit(cfg, marker, result=f"abandoned incomplete ({why})",
                           committed=_committed_so_far(cfg, cap, marker),
                           abandoned_by=ABANDON_PLAN_VERB, evidence=evidence,
                           abandoned_at=format_utc_ts(now))
    except Exception as e:  # noqa: BLE001
        raise AuditPending(f"the {marker['verb']} plan was not abandoned", e) from e
    return {"result": f"abandoned the {marker['verb']} plan ({why})", "audited": True}


def _committed_so_far(cfg: Any, cap: Optional[Capability], marker: Mapping[str, Any]) -> str:
    """What of a plan took effect, read from the state it produces."""
    verb, d = marker.get("verb"), marker.get("detail") or {}
    try:
        recorded: Optional[str] = config_mod.runtime_generation(cfg)
    except config_mod.StateKeyUnresolved:
        recorded = None
    listed = dict(cap.generations()) if cap is not None else {}
    if verb == ADOPT_VERB:
        return "recorded" if recorded == d.get("generation") else "nothing"
    gen = d.get("generation") if verb == RETIRE_VERB else d.get("retired")
    parts = []
    if listed.get(gen) == "retired":
        parts.append(f"retired {gen}")
    if verb == NEW_VERB and recorded == d.get("minted"):
        parts.append(f"minted {recorded}")
    return ", ".join(parts) or ("unknown (no capability)" if cap is None else "nothing")


def _audit_marker(verb: str, now: datetime, **detail: Any) -> Dict[str, Any]:
    return {"id": secrets.token_hex(16), "verb": verb, "at": format_utc_ts(now),
            "detail": detail}


def _begin_audit(cfg: Any, record: Dict[str, Any], verb: str, now: datetime,
                 **detail: Any) -> Dict[str, Any]:
    """The pending-audit marker, durable on the record before the act."""
    return _update(Path(cfg.state_dir), record,
                   audit_pending=_audit_marker(verb, now, **detail))


def _audit_lines(state_dir: Path) -> List[Dict[str, Any]]:
    p = Path(state_dir) / peerjournal.REPLAY_DIR / peerjournal.OPERATOR_AUDIT
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    out = []
    for line in text.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            # A torn trailing line (a crash mid-append) is skipped; its marker
            # is still pending, so a fresh complete line is appended: harmless
            # for exactly-once, which is keyed by the marker's id.
            continue
    return out


def _finish_audit(cfg: Any, record: Dict[str, Any]) -> Dict[str, Any]:
    """Append the record's pending audit line (once: keyed by the marker's
    id), then clear the marker."""
    sd = Path(cfg.state_dir)
    marker = (record.get("control") or {}).get("audit_pending")
    if not marker:
        return record
    if not any(line.get("audit_id") == marker["id"] for line in _audit_lines(sd)):
        peerjournal._audit(sd, marker["verb"], parse_utc_ts(marker["at"]),
                           audit_id=marker["id"], **marker["detail"])
    return _update(sd, record, audit_pending=None)


def _audited_effect_present(cfg: Any, record: Mapping[str, Any]) -> bool:
    """Whether the act a pending marker announces took effect: the restore
    recorded its generation; the abandonment suppressed the notice."""
    c = record.get("control") or {}
    marker = c.get("audit_pending") or {}
    if marker.get("verb") == RESTORE_VERB:
        try:
            return config_mod.runtime_generation(cfg) == marker["detail"].get("generation")
        except config_mod.StateKeyUnresolved:
            return False
    if marker.get("verb") == ABANDON_VERB:
        return c.get("suppressed") == SUPPRESS_ABANDONED
    return False


def repair_audits(cfg: Any, cap: Optional[Capability] = None) -> int:
    """Every record with a pending audit marker: its audit line appended (once)
    when the act took effect, then the marker cleared; a marker whose act did
    not take effect (a crash between the marker and the act) is cleared with
    no line, and the act is re-tried in the ordinary way. Returns how many
    lines were appended."""
    sd = Path(cfg.state_dir)
    n = 0
    for rec in peerjournal.all_records(sd):
        if not (rec.get("control") or {}).get("audit_pending"):
            continue
        if _audited_effect_present(cfg, rec):
            _finish_audit(cfg, rec)
            n += 1
        else:
            _update(sd, rec, audit_pending=None)
    return n + _repair_verb_audit(cfg, cap)


def _inflight_dir(cfg: Any, gen: str) -> Path:
    """The runtime in-flight directory of generation `gen`, keyed by `gen`
    itself (inflight's own path helpers resolve through the RECORDED
    generation, which is what may be missing here)."""
    from . import inflight
    return Path(cfg.state_dir) / config_mod.RUNTIME_NS / gen / inflight.INFLIGHT_DIR


def _inflight_entries(cfg: Any, gen: str) -> List[str]:
    """Every in-flight record and handed marker name in generation `gen`."""
    from . import inflight
    d = _inflight_dir(cfg, gen)
    if not d.is_dir():
        return []
    return sorted(p.name for p in d.iterdir()
                  if p.name.endswith(".json") or p.name.endswith(inflight.HANDED_SUFFIX))


def operator_abandon_attempt(cfg: Any, cap: Optional[Capability], key: str, *,
                             now: datetime, evidence: str) -> Dict[str, Any]:
    """`router runtime-generation abandon-attempt <record key>`: end a frozen
    control attempt whose generation can be neither restored nor adopted.
    The notice is suppressed `attempt_abandoned`: never re-signed, never
    sent. Refused while the lister shows the attempt's generation live or
    unreadable (adopt or retire it instead), or while the attempt has an
    in-flight record or a handed marker in that generation."""
    from . import inflight
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    if not evidence:
        raise ValueError("evidence is required")
    sd = Path(cfg.state_dir)
    record = peerjournal._find(sd, key)
    control = record.get("control") or {}
    attempt = control.get("attempt") or {}
    if "gen" not in attempt or control.get("sent") or control.get("suppressed"):
        raise ValueError(f"{key} has no frozen, unsent control attempt")
    gen = attempt["gen"]
    state = dict(cap.generations()).get(gen)
    if state in ("live", "unreadable"):
        raise ValueError(f"the attempt's generation {gen} is {state}: adopt or retire it")
    for name in (f"{attempt['id']}.json", f"{attempt['id']}{inflight.HANDED_SUFFIX}"):
        if name in _inflight_entries(cfg, gen):
            raise ValueError(f"the attempt {attempt['id']} is in flight in {gen}")
    marker = _audit_marker(ABANDON_VERB, now, key=key, evidence=evidence,
                           attempt=attempt["id"], generation=gen)
    # The suppression and its pending audit in ONE journal write.
    record = _update(sd, record, suppressed=SUPPRESS_ABANDONED, held=None, audit_pending=marker)
    result = f"abandoned the control attempt {attempt['id']} of {key}"
    try:
        _finish_audit(cfg, record)
    except Exception as e:  # noqa: BLE001 -- committed; the audit is repaired later
        raise AuditPending(result, e) from e
    return {"result": result, "audited": True}


def record_generation(cfg: Any, gen: str, *, now: datetime) -> None:
    from . import hoplink
    d = runtime_dir(cfg)
    d.mkdir(parents=True, exist_ok=True)
    atomic_write(d / config_mod.RUNTIME_GENERATION_FILE,
                 json.dumps({"generation": gen, "minted_ts": format_utc_ts(now)},
                            sort_keys=True).encode("utf-8"), durable_root=cfg.state_dir)
    pin = hoplink.transport_dir(cfg, config_mod.RUNTIME_NS) / hoplink.PIN_FILE
    pin.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(pin, hoplink.canonical(hoplink.pin_doc(cfg.hop, format_utc_ts(now))),
                 durable_root=cfg.state_dir)


def unsettled_attempts(cfg: Any) -> List[str]:
    """Runtime in-flight records not yet settled."""
    from . import inflight
    try:
        return inflight.list_records(cfg, config_mod.RUNTIME_NS)
    except config_mod.StateKeyUnresolved:
        return []


ADOPT_VERB = "runtime-generation adopt"
RETIRE_VERB = "runtime-generation retire"
NEW_VERB = "runtime-generation new"
VERB_AUDIT_FILE = "verb-audit-pending.json"


def operator_adopt(cfg: Any, cap: Optional[Capability], gen: str, *, now: datetime,
                   evidence: str) -> Dict[str, Any]:
    """`router runtime-generation adopt <gen>`: the only live generation
    becomes the recorded one again. Audited intent first (`_begin_verb_audit`)."""
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    if not evidence:
        raise ValueError("evidence is required")
    _refuse_while_plan_pending(cfg, cap)
    listed = dict(cap.generations())
    live = [g for g, s in listed.items() if s in ("live", "unreadable")]
    if live != [gen] or listed.get(gen) != "live":
        raise ValueError(f"{gen} is not the only live generation: {sorted(listed.items())}")
    marker = _begin_verb_audit(cfg, ADOPT_VERB, now, generation=gen, evidence=evidence)
    return _run_plan(cfg, cap, marker, now)


def _check_retirable(cfg: Any, cap: Capability, gen: str) -> None:
    """Refuse, BEFORE any effect, to retire `gen` while anything of it is
    unsettled: an unsent attempt frozen in it (read from the journal, as
    `_frozen_elsewhere` reads it), an in-flight record, or a handed marker
    without one (read from this router's own state in `gen`'s directory). The operator order: a frozen attempt in a LIVE
    generation resumes on its own on the next pass, so let it proceed and
    retire once it has settled; `abandon-attempt` applies only once its
    generation is no longer live or unreadable."""
    frozen = _frozen_in(cfg, gen)
    if frozen:
        raise ValueError(
            f"{gen} has a frozen control attempt ({frozen[0]}): an attempt in a live generation "
            "resumes on its own on the next pass, so let it proceed and retire after it settles; "
            "abandon-attempt applies only once its generation is no longer live or unreadable")
    try:
        recorded = config_mod.runtime_generation(cfg)
    except config_mod.StateKeyUnresolved:
        recorded = None
    if recorded == gen and unsettled_attempts(cfg):
        raise ValueError(f"{gen} has unsettled control notices; they would settle unsent")
    entries = _inflight_entries(cfg, gen)
    if entries:
        # An in-flight record, or a handed marker without one: rotating would
        # strand it (held as a mismatch, and abandon refuses a handed one).
        raise ValueError(f"{gen} has a control attempt in flight ({entries[0]}): let it settle "
                         "first")
    listed = dict(cap.generations())
    if gen not in listed:
        # Never construct a sender for a generation the lister does not show.
        raise ValueError(f"{gen} is not a listed runtime generation: {sorted(listed.items())}")


def _retire_idempotent(cfg: Any, cap: Capability, gen: str, now: datetime) -> str:
    """Retire `gen` through the capability unless the lister already shows
    it retired, then remove the generation record when it names `gen`. Each
    step is skipped once done, so a completion repeated after a failure
    between them finishes the rest."""
    if dict(cap.generations()).get(gen) != "retired":
        cap.retire(gen, format_utc_ts(now))
    try:
        recorded = config_mod.runtime_generation(cfg)
    except config_mod.StateKeyUnresolved:
        recorded = None
    if recorded == gen:
        try:
            os.unlink(runtime_dir(cfg) / config_mod.RUNTIME_GENERATION_FILE)
        except FileNotFoundError:
            pass
        fsync_dir(runtime_dir(cfg))
    return f"retired {gen}"


def operator_retire(cfg: Any, cap: Optional[Capability], gen: str, *, now: datetime,
                    evidence: str) -> Dict[str, Any]:
    """`router runtime-generation retire <gen>`, through the capability;
    refused before any effect while anything of `gen` is unsettled
    (`_check_retirable`). Audited intent first."""
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    if not evidence:
        raise ValueError("evidence is required")
    _refuse_while_plan_pending(cfg, cap)
    _check_retirable(cfg, cap, gen)
    marker = _begin_verb_audit(cfg, RETIRE_VERB, now, generation=gen, evidence=evidence)
    return _run_plan(cfg, cap, marker, now)


def operator_new(cfg: Any, cap: Optional[Capability], *, now: datetime,
                 evidence: str) -> Dict[str, Any]:
    """`router runtime-generation new`: retire the recorded generation, then
    mint. Everything that could refuse either step is checked BEFORE the
    retire (`_check_retirable`, and that the mint would be allowed: no other
    live or unreadable generation, no frozen attempt anywhere), so a refusal
    never leaves a committed retire behind it. Audited intent first."""
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    if not evidence:
        raise ValueError("evidence is required")
    _refuse_while_plan_pending(cfg, cap)
    gen = config_mod.runtime_generation(cfg)
    _check_retirable(cfg, cap, gen)
    _check_mint_after_retire(cfg, cap, gen)
    # The generation to mint is chosen IN the plan, so completing it is
    # idempotent: a repeat records the same one.
    marker = _begin_verb_audit(cfg, NEW_VERB, now, retired=gen, minted=secrets.token_hex(16),
                               evidence=evidence)
    return _run_plan(cfg, cap, marker, now)


def _check_mint_after_retire(cfg: Any, cap: Capability, gen: str) -> None:
    listed = dict(cap.generations())
    others = [(g, st) for g, st in listed.items() if st in ("live", "unreadable") and g != gen]
    if others:
        raise ValueError(f"after retiring {gen} no generation could be minted beside {others}: "
                         "retire them first")
    frozen = _frozen_elsewhere(cfg, None)
    if frozen:
        raise ValueError(f"a frozen control attempt ({frozen[0]}) blocks a new generation")


def _frozen_in(cfg: Any, gen: str) -> List[str]:
    """The record keys of unsent, unsuppressed attempts frozen in `gen`."""
    out = []
    for rec in peerjournal.all_records(Path(cfg.state_dir)):
        c = rec.get("control") or {}
        if ((c.get("attempt") or {}).get("gen") == gen and not c.get("sent")
                and not c.get("suppressed")):
            out.append(rec["key"])
    return out


def _named_elsewhere(cfg: Any, gen: str, key: str) -> List[str]:
    """Every OTHER journal record whose attempt names `gen`, whatever became
    of it: evidence that `gen` carried traffic."""
    out = []
    for rec in peerjournal.all_records(Path(cfg.state_dir)):
        if rec["key"] != key and ((rec.get("control") or {}).get("attempt") or {}).get("gen") == gen:
            out.append(rec["key"])
    return out


# ---------------------------------------------------------------------------
# Rate, coalescing
# ---------------------------------------------------------------------------

def _rate(cfg: Any) -> int:
    dc = getattr(cfg, "delegation", None)
    return int(getattr(dc, "control_rate_per_hour", None) or DEFAULT_RATE_PER_HOUR)


def _read_buckets(cfg: Any) -> Dict[str, Any]:
    try:
        doc = json.loads((runtime_dir(cfg) / RATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def take_token(cfg: Any, destination: str, h: datetime) -> bool:
    """One notice's token from `destination`'s bucket, refilled on H; the
    bucket is persisted before this returns."""
    rate = _rate(cfg)
    buckets = _read_buckets(cfg)
    b = buckets.get(destination) or {"tokens": float(rate), "at": format_utc_ts(h)}
    last = parse_utc_ts(b.get("at")) or h
    elapsed = max(0.0, (h - last).total_seconds())     # H only rises
    tokens = min(float(rate), float(b.get("tokens", rate)) + elapsed * rate / 3600.0)
    ok = tokens >= 1.0
    if ok:
        tokens -= 1.0
    buckets[destination] = {"tokens": tokens, "at": format_utc_ts(max(h, last))}
    runtime_dir(cfg).mkdir(parents=True, exist_ok=True)
    atomic_write(runtime_dir(cfg) / RATE_FILE, json.dumps(buckets, sort_keys=True).encode("utf-8"),
                 durable_root=cfg.state_dir)
    return ok


def coalesce_owner(cfg: Any, destination: str, control: Mapping[str, Any], key: str) -> str:
    """The record key that sends for (destination, about, cause): link-once,
    so the first record to claim the triple keeps it for the owner's whole
    life, whether its attempt succeeds, fails or settles."""
    d = runtime_dir(cfg) / COALESCE_DIR
    d.mkdir(parents=True, exist_ok=True)
    name = hashlib.sha256("\0".join((destination, str(control["about"]),
                                     control["cause"])).encode("utf-8")).hexdigest()
    fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            peerbind._link_once(fd, name, key.encode("ascii"), stage_prefix=_STAGE)
            return key
        except peerbind.LinkConflict:
            pass
    finally:
        os.close(fd)
    return (d / name).read_text(encoding="ascii").strip()


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

def _misaddressed(control: Mapping[str, Any]) -> bool:
    """Suppressed `unconfigured_runtime` with no `about` or no `to`: the
    label an earlier build gave a 5(b) demotion it wrote without either. It
    was never a finding about the runtime, so the notice is pending again."""
    return (control.get("suppressed") == SUPPRESS_UNCONFIGURED
            and (control.get("about") is None or control.get("to") is None))


def pending(state_dir: Path) -> List[Dict[str, Any]]:
    """Every journal record with an unsent, unsuppressed control notice, in
    take order (a misaddressed suppression counts as pending)."""
    out = []
    for rec in peerjournal.all_records(state_dir):
        c = rec.get("control")
        if c and not c.get("sent") and not c.get("coalesced_with") and (
                not c.get("suppressed") or _misaddressed(c)):
            out.append(rec)
    return sorted(out, key=lambda r: r["take_seq"])


def _update(state_dir: Path, record: Dict[str, Any], **changes: Any) -> Dict[str, Any]:
    return peerjournal.write_record(state_dir, dict(record, control=dict(record["control"],
                                                                           **changes)))


def send_pending(cfg: Any, runtime: Any, *, delegation: Any, now: datetime) -> Dict[str, int]:
    """One pass over the pending control notices: each isolated."""
    counts: Dict[str, int] = {}

    def count(what: str) -> None:
        counts[what] = counts.get(what, 0) + 1

    state_dir = Path(cfg.state_dir)
    try:
        clock = peerclock.read(state_dir)
    except peerclock.ClockUntrusted:
        return {"held_clock_untrusted": len(pending(state_dir))}
    if clock.admission != "open":
        # H is untrusted until admission reopens: no token, no mint, no attempt.
        return {"held_admission_closed": len(pending(state_dir))}
    # A pending audited act (its audit line, or a verb's plan) is completed
    # BEFORE anything is attempted or handed over, whether or not any notice
    # is pending.
    cap = capability(cfg, runtime)
    try:
        repaired = repair_audits(cfg, cap)
        if repaired:
            counts["audit_repaired"] = repaired
    except Exception:  # noqa: BLE001 -- retried next pass; nothing is attempted meanwhile
        logger.exception("control notices: an audit repair failed; nothing attempted this pass")
        return dict(counts, audit_repair_failed=1)
    if delegation is None:
        # No signing key: nothing can be signed, so nothing is tried.
        n = len(pending(state_dir))
        return dict(counts, **({DELEGATION_INACTIVE: n} if n else {}))
    # Frozen attempts first: their generation is reconciled before any fresh
    # notice could need one.
    for record in sorted(pending(state_dir),
                         key=lambda r: ("gen" not in ((r["control"] or {}).get("attempt") or {}),
                                        r["take_seq"])):
        try:
            count(_one(cfg, cap, record, delegation=delegation, h=clock.H, now=now))
        except Unavailable as e:
            count(e.reason)
        except Exception:  # noqa: BLE001 -- one record never stops the others
            logger.exception("control notice for %s: isolated, retried next pass", record["key"])
            count("errored")
    return counts


def _one(cfg: Any, cap: Optional[Capability], record: Dict[str, Any], *, delegation: Any,
         h: datetime, now: datetime) -> str:
    sd = Path(cfg.state_dir)
    control = record["control"]
    if control.get("attempt"):
        return _resume(cfg, cap, record, delegation=delegation, now=now)
    if control.get("about") is None or control.get("to") is None:
        filled = _destination_from_snapshot(cfg, delegation, record)
        if filled is not None:
            # Re-pended: the statement's id and its key owner's runtime,
            # read from the snapshot taken with the disposition.
            record = _update(sd, record, about=filled[0], to=filled[1], held=None,
                             suppressed=None)
            control = record["control"]
    if control.get("about") is None or control.get("to") is None:
        if control.get("held") != HELD_NO_DESTINATION:
            _update(sd, record, held=HELD_NO_DESTINATION)
        return "held_" + HELD_NO_DESTINATION
    key_id = peerjournal._snapshot_key_id(sd, record)
    dc = getattr(delegation, "config", None) or getattr(cfg, "delegation", None)
    owner = peerbind.runtime_for_key(dc, key_id) if (dc is not None and key_id) else None
    if owner is None or owner.runtime != control["to"]:
        _update(sd, record, suppressed=SUPPRESS_UNCONFIGURED)
        return "suppressed_" + SUPPRESS_UNCONFIGURED
    if cap is None:
        raise Unavailable(UNAVAILABLE)
    gen = generation(cfg, cap, now=now)
    sender_key = coalesce_owner(cfg, control["to"], control, record["key"])
    if sender_key != record["key"]:
        _update(sd, record, coalesced_with=sender_key)
        return "suppressed_" + SUPPRESS_COALESCED
    since = parse_utc_ts(control.get("deferred_since"))
    if since is not None and (h - since).total_seconds() >= DEFER_LIMIT_S:
        # The horizon first: a refilled bucket never revives a notice
        # deferred for 24 h of H, and the suppression takes no token.
        _update(sd, record, suppressed=SUPPRESS_RATE)
        return "suppressed_" + SUPPRESS_RATE
    if not take_token(cfg, control["to"], h):
        if "deferred_since" not in control:
            _update(sd, record, deferred_since=format_utc_ts(h))
        return "deferred"
    record = _update(sd, record, attempt={"id": _mint_id(), "at": format_utc_ts(now)})
    return _resume(cfg, cap, record, delegation=delegation, now=now, gen=gen)


def _destination_from_snapshot(cfg: Any, delegation: Any, record: Mapping[str, Any]
                               ) -> Optional[Tuple[str, str]]:
    """(about, to) from the record's statement snapshot and the configured
    runtime that owns its key, or None when either cannot be read."""
    sd = Path(cfg.state_dir)
    raw = peerjournal.read_snapshot(sd, record, peerjournal.SNAPSHOT_STATEMENT)
    about = peerjournal._statement_id(raw) if raw is not None else None
    key_id = peerjournal._snapshot_key_id(sd, record)
    dc = getattr(delegation, "config", None) or getattr(cfg, "delegation", None)
    owner = peerbind.runtime_for_key(dc, key_id) if (dc is not None and key_id) else None
    if about is None or owner is None:
        return None
    return about, owner.runtime


def _mint_id() -> str:
    from . import peerlane
    return peerlane.mint_peer_id()


def _resume(cfg: Any, cap: Optional[Capability], record: Dict[str, Any], *, delegation: Any,
            now: datetime, gen: Optional[str] = None) -> str:
    from . import clock as clock_mod
    from . import inflight, peerlane
    sd = Path(cfg.state_dir)
    if cap is None:
        raise Unavailable(UNAVAILABLE)
    attempt = record["control"]["attempt"]
    if "gen" in attempt:
        # The attempt is frozen in ITS generation, whose private counter
        # holds its `n`: reconcile that generation first, never select (or
        # mint) another and read the counter through it.
        held = _attempt_generation(cfg, cap, attempt["gen"], now=now, record=record)
        record = peerjournal.read_record(sd, record["owner"], record["key"])
        if held is not None:
            if record["control"].get("held") != held:
                _update(sd, record, held=held)
            return "held_" + held
        if record["control"].get("held") in GENERATION_HOLDS:
            record = _update(sd, record, held=None)
        gen = attempt["gen"]
    else:
        gen = gen or generation(cfg, cap, now=now)
    if "n" not in attempt:
        n = inflight.reserve_transport_id(cfg, config_mod.RUNTIME_NS)
        ts = format_utc_ts(clock_mod.now())        # signed now, never at the intent time
        doc = statement_doc(key_id=delegation.key_id, control_id=attempt["id"],
                            from_address=runtime_address(cfg), to=record["control"]["to"],
                            ts=ts, control=record["control"])
        signed = peerlane.sign_control(delegation, doc)
        attempt = dict(attempt, n=n, gen=gen, ts=ts,
                       statement_b64=base64.b64encode(signed.statement).decode("ascii"),
                       signature_b64=base64.b64encode(signed.signature).decode("ascii"),
                       header=signed.header)
        record = _update(sd, record, attempt=attempt)
    rid = attempt["id"]
    ns = config_mod.RUNTIME_NS
    existing = inflight.read_record(cfg, ns, rid)
    if existing is None:
        handed = inflight.handed_path(cfg, ns, rid)
        if inflight._was_handed(handed, attempt["n"]):
            if not record["control"].get("stuck"):
                _update(sd, record, stuck={"reason": STUCK_HANDED, "since": format_utc_ts(now)})
            return "stuck_" + STUCK_HANDED
        _require_writable(cap, attempt["gen"])
        existing = inflight.begin_reserved(
            cfg, ns, rid, attempt["n"], digest=None,
            request_doc=request_doc(cfg, record, attempt), recipients=[record["control"]["to"]],
            from_address=runtime_address(cfg), peer=pin(cfg, attempt))
    port = cap.sender(attempt["gen"])

    def settle(verdict: Dict[str, Any], _digest: Optional[str]) -> str:
        _update(sd, record, sent=True, stuck=None,
                settled={"outcome": verdict.get("outcome"), "at": format_utc_ts(clock_mod.now())})
        return verdict.get("outcome") or ""

    if not inflight._was_handed(inflight.handed_path(cfg, ns, rid), attempt["n"]):
        _require_writable(cap, attempt["gen"])
    state = inflight.advance(cfg, ns, rid, existing, port, settle=settle,
                             already_settled=bool(record["control"].get("settled")))
    if state not in (inflight.SETTLED, inflight.CLEANED):
        current = peerjournal.read_record(sd, record["owner"], record["key"])
        signed = parse_utc_ts(attempt.get("ts"))
        if (signed is not None and (now - signed).total_seconds() >= SETTLE_HORIZON_S
                and not current["control"].get("sent")):
            if not current["control"].get("stuck"):
                _update(sd, current, stuck={"reason": STUCK_UNSETTLED,
                                            "since": format_utc_ts(now)})
            return "stuck_" + STUCK_UNSETTLED
    return f"attempt_{state}"


def _attempt_generation(cfg: Any, cap: Capability, gen: str, *, now: datetime,
                        record: Dict[str, Any]) -> Optional[str]:
    """None when a frozen attempt's generation `gen` is the recorded one, or
    when the record is lost and `gen` may be restored: the lister shows it
    `live`, or does not list it at all (minted and never admitted, so nothing
    was handed over in it), AND shows no other generation `live` or
    `unreadable`. A restore is audited (`RESTORE_VERB`, naming the attempt's
    record key), intent first: the record's `control.audit_pending` marker
    is durable before the generation is recorded, the audit line is
    appended, then the marker is cleared (`repair_audits` finishes it after
    a failure). Otherwise the reason the attempt is HELD, visibly:
    `HELD_GENERATION_UNRECORDED` (no record, and `gen` cannot be restored),
    or `HELD_GENERATION_MISMATCH` (another generation is recorded). Nothing
    is minted here."""
    try:
        recorded: Optional[str] = config_mod.runtime_generation(cfg)
    except config_mod.StateKeyUnresolved:
        recorded = None
    if recorded == gen:
        return None
    if recorded is not None:
        return HELD_GENERATION_MISMATCH
    listed = dict(cap.generations())
    others = [g for g, st in listed.items() if st in ("live", "unreadable") and g != gen]
    # "Not listed" is read as "never admitted" only while this router's own
    # state shows no traffic in that generation: nothing in flight in it, and
    # no other journal record naming it (a settled attempt leaves no in-flight
    # file behind). A generation that carried traffic and lost both its tree
    # and its record is held.
    unlisted_ok = (listed.get(gen) is None and not _inflight_entries(cfg, gen)
                   and not _named_elsewhere(cfg, gen, record["key"]))
    if (listed.get(gen) == "live" or unlisted_ok) and not others:
        record = _begin_audit(cfg, record, RESTORE_VERB, now, key=record["key"], generation=gen,
                              listed=listed.get(gen) or "not listed")
        record_generation(cfg, gen, now=now)
        _finish_audit(cfg, record)
        return None
    return HELD_GENERATION_UNRECORDED


def _require_writable(cap: Capability, gen: str) -> None:
    """Nothing is handed over into a generation the lister shows retired or
    unreadable: the record alone is never trusted."""
    state = dict(cap.generations()).get(gen)
    if state in ("retired", "unreadable"):
        raise Unavailable(UNAVAILABLE, f"the attempt's generation {gen} is {state}")


def request_doc(cfg: Any, record: Mapping[str, Any], attempt: Mapping[str, Any]) -> Dict[str, Any]:
    """The runtime request: one recipient (the configured destination), no
    subject, ZERO body octets (the content type is the downstream runtime's
    composition), no attachments."""
    return {"req_id": attempt["id"],
            "draft": {"to": [record["control"]["to"]], "subject": "", "body_text": ""}}


def pin(cfg: Any, attempt: Mapping[str, Any]) -> Dict[str, Any]:
    """The runtime in-flight record's frozen signed pin."""
    from . import peerlane
    return {"kind": "control", "id": attempt["id"],
            "message_id": peerlane.message_id(attempt["id"], cfg.fleet_domain),
            "key_id": json.loads(base64.b64decode(attempt["statement_b64"]))["key_id"],
            "statement": attempt["statement_b64"], "signature": attempt["signature_b64"],
            "statement_header": attempt["header"], "in_reply_to": None, "references": []}


def status_doc(cfg: Any, runtime: Any, *, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Status `peer_store.controls`: pending, sent (settled with an outcome
    in `SENT_OUTCOMES`), failed (any other settled outcome, by outcome),
    suppressed by reason, held by reason, deferred, stuck (by reason; each
    record's `since` is when it was first marked stuck, and its `age_s` is
    measured from the attempt's signing time, `attempt.ts`, falling back to
    the intent time `attempt.at` when nothing was signed),
    and the runtime tree: `unavailable` without the capability; otherwise
    the recorded generation and, read through the read-only lister, every
    listed generation with its state, so a lost record shows what an
    operator must adopt or retire. Reads only."""
    sd = Path(cfg.state_dir)
    doc: Dict[str, Any] = {"pending": 0, "sent": 0, "failed": {}, "suppressed": {},
                           "deferred": 0, "attempting": 0, "held": {}, "stuck": 0,
                           "stuck_records": []}
    for rec in peerjournal.all_records(sd):
        c = rec.get("control")
        if not c:
            continue
        if c.get("sent"):
            outcome = (c.get("settled") or {}).get("outcome")
            if outcome in SENT_OUTCOMES:
                doc["sent"] += 1
            else:
                key = outcome if isinstance(outcome, str) else "unknown"
                doc["failed"][key] = doc["failed"].get(key, 0) + 1
        elif c.get("suppressed") and not _misaddressed(c):
            doc["suppressed"][c["suppressed"]] = doc["suppressed"].get(c["suppressed"], 0) + 1
        elif c.get("coalesced_with"):
            doc["suppressed"][SUPPRESS_COALESCED] = doc["suppressed"].get(SUPPRESS_COALESCED, 0) + 1
        elif c.get("held"):
            doc["held"][c["held"]] = doc["held"].get(c["held"], 0) + 1
        elif c.get("stuck"):
            doc["stuck"] += 1
            attempt = c.get("attempt") or {}
            since = parse_utc_ts(attempt.get("ts") or attempt.get("at"))
            doc["stuck_records"].append({
                "key": rec["key"], "reason": c["stuck"].get("reason"),
                "since": c["stuck"].get("since"),
                "age_s": (int((now - since).total_seconds())
                          if now is not None and since is not None else None)})
        else:
            doc["pending"] += 1
            if c.get("deferred_since"):
                doc["deferred"] += 1
            if c.get("attempt"):
                doc["attempting"] += 1
    cap = capability(cfg, runtime)
    if cap is None:
        doc["runtime_tree"] = "unavailable"
        return doc
    try:
        recorded: Optional[str] = config_mod.runtime_generation(cfg)
    except config_mod.StateKeyUnresolved:
        recorded = None
    tree: Dict[str, Any] = {"generation": recorded}
    try:
        tree["generations"] = [[g, s] for g, s in cap.generations()]
    except Exception as e:  # noqa: BLE001 -- status never fails on the lister
        tree["generations"] = None
        tree["lister_error"] = f"{type(e).__name__}: {e}"
    doc["runtime_tree"] = tree
    return doc


# ---------------------------------------------------------------------------
# Control notices IN: the issuing agent's failure notice
# ---------------------------------------------------------------------------

#: What the receiving runtime's report means, in this router's own words,
#: keyed by the control schema's (outcome, cause). Nothing from the control
#: notice is rendered but its vocabulary values and the message id.
FAILURE_TEXT: Mapping[Tuple[str, str], str] = {
    ("refused", "unresolved_reply"): "refused it: it answered a message the receiving runtime "
                                     "could not match to a task it had delivered",
    ("refused", "no_edge"): "refused it: you may not task that recipient there",
    ("refused", "policy"): "refused it: refused by the receiving runtime's policy ({code})",
    ("dropped", "duplicate"): "dropped it as a duplicate. The receiving runtime already holds a "
                              "record of this message, and that record may have been placed: "
                              "this report is NOT proof that the task failed",
    ("dropped", "misrouted"): "dropped it: the recipient is not hosted there",
    ("demoted", "statement_value"): "did not accept it as a signed task: a signed value was "
                                    "invalid",
    ("demoted", "key_domain"): "did not accept it as a signed task: the signing key does not "
                               "cover the sender's domain",
    ("demoted", "ts_window"): "did not accept it as a signed task: it arrived outside the "
                              "receiver's time window",
    ("demoted", "exposure_signer"): "did not accept it as a signed task: the exposure "
                                    "assertion was not signed by its asserter",
    ("demoted", "body_charset"): "did not accept it as a signed task: the body's charset did "
                                 "not decode",
    ("demoted", "body_digest"): "did not accept it as a signed task: the body did not match "
                                "its signed digest",
    ("demoted", "attachment_count"): "did not accept it as a signed task: the attachments did "
                                     "not match their signed count",
    ("demoted", "attachment_digest"): "did not accept it as a signed task: an attachment did "
                                      "not match its signed digest",
    ("demoted", "message_id"): "did not accept it as a signed task: its Message-ID did not "
                               "match the signed id",
}


def escaped_token(value: Any) -> str:
    """A token from a control notice, rendered and never interpreted: ASCII
    letters, digits, `_`, `.` and `-` kept, every other character as
    `\\xNN`/`\\uNNNN`, at most 64 characters before escaping."""
    text = value if isinstance(value, str) else repr(value)
    out = []
    for ch in text[:64]:
        if ch.isascii() and (ch.isalnum() or ch in "_.-"):
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


def failure_notice(*, about: str, outcome: str, cause: str,
                   policy_code: Optional[str]) -> Tuple[str, str]:
    """(subject, body) of the issuing agent's failure notice, entirely
    runtime-authored."""
    text = FAILURE_TEXT.get((outcome, cause))
    if text is None:
        text = (f"reported it as {escaped_token(outcome)} "
                f"({escaped_token(cause)}), which this router has no description for")
    if (outcome, cause) == ("refused", "policy"):
        # The code is deployment-defined: shown escaped, never interpreted.
        text = text.format(code=escaped_token(policy_code) if policy_code is not None
                           else "no code")
    subject = f"Delivery report for peer message {about}"
    body = (f"The receiving runtime {text}.\n\n"
            f"Message: {about}\n"
            "This report was written by your router from the receiving runtime's signed "
            "control notice; no text from that notice is included.\n")
    return subject, body
