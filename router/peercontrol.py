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
    _update(sd, record, suppressed=SUPPRESS_ABANDONED, held=None)
    return {"result": f"abandoned the control attempt {attempt['id']} of {key}"}


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


def operator_adopt(cfg: Any, cap: Optional[Capability], gen: str, *, now: datetime,
                   evidence: str) -> Dict[str, Any]:
    """`router runtime-generation adopt <gen>`: the only live generation
    becomes the recorded one again."""
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    if not evidence:
        raise ValueError("evidence is required")
    listed = dict(cap.generations())
    live = [g for g, s in listed.items() if s in ("live", "unreadable")]
    if live != [gen] or listed.get(gen) != "live":
        raise ValueError(f"{gen} is not the only live generation: {sorted(listed.items())}")
    record_generation(cfg, gen, now=now)
    return {"result": f"adopted {gen}"}


def operator_retire(cfg: Any, cap: Optional[Capability], gen: str, *, now: datetime,
                    evidence: str) -> Dict[str, Any]:
    """`router runtime-generation retire <gen>`, through the capability."""
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    if not evidence:
        raise ValueError("evidence is required")
    try:
        recorded = config_mod.runtime_generation(cfg)
    except config_mod.StateKeyUnresolved:
        recorded = None
    if recorded == gen and unsettled_attempts(cfg):
        raise ValueError(f"{gen} has unsettled control notices; they would settle unsent")
    listed = dict(cap.generations())
    if gen not in listed:
        # Never construct a sender for a generation the lister does not show.
        raise ValueError(f"{gen} is not a listed runtime generation: {sorted(listed.items())}")
    result = cap.retire(gen, format_utc_ts(now))
    if recorded == gen:
        os.unlink(runtime_dir(cfg) / config_mod.RUNTIME_GENERATION_FILE)
        fsync_dir(runtime_dir(cfg))
    return {"result": f"retired {gen}: {result}"}


def operator_new(cfg: Any, cap: Optional[Capability], *, now: datetime,
                 evidence: str) -> Dict[str, Any]:
    """`router runtime-generation new`: retire the recorded generation (never
    while it has unsettled attempts), then mint."""
    if cap is None:
        raise Unavailable(UNAVAILABLE, "the plugin declares no runtime capability")
    gen = config_mod.runtime_generation(cfg)
    operator_retire(cfg, cap, gen, now=now, evidence=evidence)
    return {"result": f"retired {gen}, minted {generation(cfg, cap, now=now)}"}


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

def pending(state_dir: Path) -> List[Dict[str, Any]]:
    """Every journal record with an unsent, unsuppressed control notice, in
    take order."""
    out = []
    for rec in peerjournal.all_records(state_dir):
        c = rec.get("control")
        if c and not c.get("sent") and not c.get("suppressed") and not c.get("coalesced_with"):
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
    if delegation is None:
        # No signing key: nothing can be signed, so nothing is tried.
        n = len(pending(state_dir))
        return {DELEGATION_INACTIVE: n} if n else {}
    cap = capability(cfg, runtime)
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
        held = _attempt_generation(cfg, cap, attempt["gen"], now=now, key=record["key"])
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
                        key: str) -> Optional[str]:
    """None when a frozen attempt's generation `gen` is the recorded one, or
    when the record is lost and `gen` may be restored: the lister shows it
    `live`, or does not list it at all (minted and never admitted, so nothing
    was handed over in it), AND shows no other generation `live` or
    `unreadable`. A restore is audited (`RESTORE_VERB`, naming the attempt's
    record key). Otherwise the reason the attempt is HELD, visibly:
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
    # state shows nothing in flight in that generation: a generation that
    # carried traffic and lost both its tree and its record is held.
    unlisted_ok = listed.get(gen) is None and not _inflight_entries(cfg, gen)
    if (listed.get(gen) == "live" or unlisted_ok) and not others:
        record_generation(cfg, gen, now=now)
        peerjournal._audit(cfg.state_dir, RESTORE_VERB, now, key=key, generation=gen,
                           listed=listed.get(gen) or "not listed")
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
    suppressed by reason, held by reason, deferred, stuck (by reason, each with its age),
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
        elif c.get("suppressed"):
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
