"""router/peerpolicy.py — the decide hooks, built in one place.

The candidate journal (`peerjournal`) decides a reserved statement through
five hooks: `check8` (before the reservation), then `reply`, `edge` and
`policy`, and `control_receive` for a control candidate. They are never
assembled by a caller: `decide_hooks(profile)` builds all five from a
`Profile`, and every pass entry builds its own inside the pass
(`peerjournal.poll` and the entries it forwards to), from a profile FACTORY
it is handed:

    profile_factory(hook_context(cfg, delegation=, state_dir=, now=, clock=))

The router passes no factory, so every pass runs `production_profile`. A
conformance driver passes one that returns `conformance_profile(...)`; that
is the only difference between the two, and both run the same hook code.

A `Profile` is DATA: an edge part (`TRUSTED_HOST_DEFAULT`, or a frozenset of
canonical `(from, to)` pairs from `conformance_edges`) and a policy part, a
frozen `PolicyPart(exposure_required, min_sender_age_s)`. `decide_hooks`
validates every part's exact type, so a factory contributes nothing a hook
could run. Each hook reads only its call arguments, its profile and the
profile's `HookContext`, which is frozen and bound to one pass's `cfg`,
`delegation`, `state_dir`, `now` and clock; `peerjournal.Ctx` refuses hooks
bound to any other. Hooks read time from the context, never from the clock.

What each hook reads:

| hook | reads |
|---|---|
| `check8` | `delegation` ONLY: the key's configured runtime and its address (the exposure asserter); identical under every profile |
| `reply` | `cfg.instances[hosted].task_deny` (the deny, first), the hosted instance's state key and address, `state_dir` (the peer ledger), `now` |
| `edge` | the same resolution; the edge part; `delegation.config` (the key's runtime and its domains) |
| `policy` | the policy part; `state_dir` (the epoch store, `peerepochs`); `now`; the reservation's runtime (a call argument) |
| `control_receive` | `delegation.config` (the key's configured runtime and its domains), `cfg.fleet_domain` (this router's runtime address), the clock and `now` (freshness), `state_dir` (the `issued` records) |

The decide order is deny, reply, edge, policy. The deny is the reply hook's
first step, so a denied sender is refused `(policy, denied)` whatever its
`in_reply_to`, and learns nothing about the ledger.

THE POLICY HOOK's order (the first failure decides): `sender_age_missing`
(no `sender_since`, under an age policy); consistency against the epoch
store (an earlier `sender_since` is `sender_since_inconsistent` and persists
nothing; a later one is persisted and audited BEFORE the age test); then
`quarantined` (`now - sender_since < min_sender_age_s`, `now` the router's
own, a future value quarantined); then `exposure_missing`. With no age
policy the epoch store is not consulted at all. An unreadable or untrusted
epoch store HOLDS (`epoch_store_unavailable`), never refuses.

PRODUCTION is `production_policy(cfg)`: `PolicyPart(exposure_required=True,
min_sender_age_s=cfg.min_sender_age_s)`, built in that ONE function from the
pass's config (contract §8.6 as amended by E30). The top-level
`min_sender_age_s` is the only member that changes it (default 86400; 0 is
an active policy, never None); exposure stays required; a delegation naming
either overlay is refused at load (contract §8.8).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, FrozenSet, Mapping, Optional, Tuple, Union

from . import peerledger


class _Marker:
    """A closed, named profile part: compared by identity, carries no code."""
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return self.name


@dataclass(frozen=True)
class PolicyPart:
    """The policy part of a profile: whether `sender_exposure` is required,
    and the minimum sender age in seconds (None: no age policy; 0 is an
    ACTIVE zero-second policy that still runs the consistency rule)."""
    exposure_required: bool
    min_sender_age_s: Optional[int]


def production_policy(cfg: Any) -> PolicyPart:
    """Production's policy part, from `cfg` (contract §8.6/§8.8): exposure
    required, and the sender-age duration the config sets. The ONLY place
    the production `PolicyPart` is built; `production_profile` calls it, and
    the sender side reads the same `cfg.min_sender_age_s`
    (`classify.sender_age_refusal`), so the two cannot diverge."""
    return PolicyPart(exposure_required=True, min_sender_age_s=cfg.min_sender_age_s)

#: The edge part production uses: the edge exists when the key's runtime owns
#: the domain of `from` (`peerbind.check6`, the same predicate check 6 runs).
TRUSTED_HOST_DEFAULT = _Marker("TRUSTED_HOST_DEFAULT")
_EDGE_MARKERS = (TRUSTED_HOST_DEFAULT,)


@dataclass(frozen=True)
class HookContext:
    """One pass's context, frozen. Built only by `hook_context`, at the same
    place and from the same objects as that pass's `peerjournal.Ctx`."""
    cfg: Any
    delegation: Any
    state_dir: Path
    now: datetime
    clock: Any


def hook_context(cfg: Any, *, delegation: Any, state_dir: Union[str, Path], now: datetime,
                 clock: Any) -> HookContext:
    if now.utcoffset() is None:
        raise TypeError("hook_context: an aware now")
    return HookContext(cfg=cfg, delegation=delegation, state_dir=Path(state_dir), now=now,
                       clock=clock)


@dataclass(frozen=True)
class Profile:
    """The data a hook set is built from: its context, an edge part and a
    policy part."""
    context: HookContext
    edges: Any
    policy: Any


def production_profile(ctx: HookContext) -> Profile:
    """The only profile the router builds."""
    return Profile(context=ctx, edges=TRUSTED_HOST_DEFAULT, policy=production_policy(ctx.cfg))


def conformance_edges(pairs) -> FrozenSet[Tuple[str, str]]:
    """An explicit edge allowlist: canonical `(from, to)` pairs. A pair absent
    from it is `no_edge`. For tests and conformance drivers only."""
    out = set()
    for pair in pairs:
        frm, to = pair
        out.add((peerledger.canonical(frm), peerledger.canonical(to)))
    return frozenset(out)


def conformance_profile(ctx: HookContext, receiver_patch: Optional[Mapping[str, Any]],
                        pairs) -> Profile:
    """A conformance driver's profile: the given edges; exposure not
    required (the spec test receiver's); `min_sender_age_s` the receiver
    patch's when it sets one, else None. Absent maps to None, never a
    falsy value: a patch of 0 is an active policy. For tests and conformance
    drivers only."""
    if receiver_patch is not None and not isinstance(receiver_patch, Mapping):
        raise TypeError("receiver_patch: a mapping or None")
    patch = receiver_patch or {}
    age = patch["min_sender_age_s"] if "min_sender_age_s" in patch else None
    return Profile(context=ctx, edges=conformance_edges(pairs),
                   policy=PolicyPart(exposure_required=False, min_sender_age_s=age))


def _check_profile(profile: Any) -> None:
    """Every part exactly one of its allowed data shapes; nothing callable."""
    if type(profile) is not Profile:
        raise TypeError("decide_hooks: a Profile")
    if type(profile.context) is not HookContext:
        raise TypeError("decide_hooks: the profile's context is not a HookContext")
    edges = profile.edges
    if not (any(edges is m for m in _EDGE_MARKERS)
            or (type(edges) is frozenset
                and all(type(p) is tuple and len(p) == 2
                        and all(type(a) is str for a in p) for p in edges))):
        raise TypeError("decide_hooks: the edge part is TRUSTED_HOST_DEFAULT or a frozenset "
                        "of (from, to) string pairs")
    part = profile.policy
    if not (type(part) is PolicyPart and type(part.exposure_required) is bool
            and (part.min_sender_age_s is None
                 or (type(part.min_sender_age_s) is int and part.min_sender_age_s >= 0))):
        raise TypeError("decide_hooks: the policy part is a PolicyPart(bool, int >= 0 | None)")


def decide_hooks(profile: Profile):
    """The complete hook set, every member built from `profile` alone."""
    from . import peerjournal
    _check_profile(profile)
    ctx = profile.context
    return peerjournal.DecideHooks(
        check8=_check8(profile), reply=_reply(profile), edge=_edge(profile),
        policy=_policy(profile), control_receive=_control_receive(profile), context=ctx)


def production_hooks(ctx: HookContext):
    """The router's hooks: `decide_hooks(production_profile(ctx))`."""
    return decide_hooks(production_profile(ctx))


# ---------------------------------------------------------------------------
# The hooks
# ---------------------------------------------------------------------------

def _hosted_identity(ctx: HookContext, hosted: str) -> Tuple[str, str]:
    from . import config as config_mod
    return (config_mod.state_key(ctx.cfg, hosted),
            config_mod.address_for(hosted, ctx.cfg.fleet_domain))


def _resolution(ctx: HookContext, payload: Mapping[str, Any], hosted: str):
    lid, address = _hosted_identity(ctx, hosted)
    return peerledger.resolve(ctx.cfg, in_reply_to=payload["in_reply_to"],
                              local_logical_id=lid, local_address=address,
                              remote=payload["from"], now=ctx.now)


EXPOSURE_SIGNER = "exposure_signer"


def _same_address(a: Any, b: Any) -> bool:
    """The local part EXACTLY, the domain ASCII case-insensitively."""
    if not (isinstance(a, str) and isinstance(b, str)) or a.count("@") != 1 or b.count("@") != 1:
        return False
    al, ad = a.split("@")
    bl, bd = b.split("@")
    return al == bl and ad.isascii() and bd.isascii() and ad.lower() == bd.lower()


def _check8(profile: Profile) -> Callable:
    from . import peerbind
    ctx = profile.context

    def check8(payload: Mapping[str, Any], key_id: str):
        """Check 8: a present `sender_exposure` must be asserted by the
        configured runtime that owns the verifying key (never this
        receiver's own). Absence is the policy hook's, never check 8's."""
        exposure = payload.get("sender_exposure")
        if exposure is None:
            return None
        runtime = peerbind.runtime_for_key(ctx.delegation.config, key_id)
        asserted = exposure.get("asserted_by") if isinstance(exposure, Mapping) else None
        if runtime is None or not _same_address(asserted, runtime.runtime):
            return EXPOSURE_SIGNER
        return None
    return check8


def _reply(profile: Profile) -> Callable:
    from . import classify, peerjournal
    ctx = profile.context

    def reply(payload: Mapping[str, Any], hosted: str):
        # The deny first: whatever the in_reply_to, and before the ledger.
        try:
            sender = classify.parse_address(payload["from"])
        except classify.Malformed:
            return peerjournal.Refuse("unresolved_reply")
        if classify.task_denied(ctx.cfg, hosted, sender):
            return peerjournal.Refuse("policy", "denied")
        in_reply_to = payload.get("in_reply_to")
        if in_reply_to is None:
            return peerjournal.Resolved(None)
        if not isinstance(_resolution(ctx, payload, hosted), peerledger.Resolved):
            return peerjournal.Refuse("unresolved_reply")
        return peerjournal.Resolved(in_reply_to)
    return reply


def _edge(profile: Profile) -> Callable:
    from . import peerbind, peerjournal
    ctx = profile.context

    def edge(payload: Mapping[str, Any], hosted: str):
        """A reverse result (resolved against an `issued` record) needs no
        edge. Anything else needs `from -> to` in the edge part: the trusted
        host default (the key's runtime owns `from`'s domain), or an explicit
        pair. One function for both, so a conformance run exercises the
        production edge code."""
        if payload.get("in_reply_to") is not None:
            got = _resolution(ctx, payload, hosted)
            if isinstance(got, peerledger.Resolved) and got.direction == "issued":
                return None
        if profile.edges is TRUSTED_HOST_DEFAULT:
            ok = peerbind.check6(payload, ctx.delegation.config) is None
        else:
            _lid, address = _hosted_identity(ctx, hosted)
            try:
                ok = (peerledger.canonical(payload["from"]),
                      peerledger.canonical(address)) in profile.edges
            except Exception:  # noqa: BLE001 -- an unparseable address has no edge
                ok = False
        return None if ok else peerjournal.Refuse("no_edge")
    return edge


SENDER_AGE_MISSING = "sender_age_missing"
SENDER_SINCE_INCONSISTENT = "sender_since_inconsistent"
QUARANTINED = "quarantined"
EXPOSURE_MISSING = "exposure_missing"
EPOCH_STORE_UNAVAILABLE = "epoch_store_unavailable"


def _policy(profile: Profile) -> Callable:
    from . import peerepochs, peerjournal
    from .util import parse_utc_ts
    ctx = profile.context
    part = profile.policy

    def policy(payload: Mapping[str, Any], hosted: str, runtime: str):
        """The order (module docstring): age missing, consistency, quarantined,
        exposure missing. `runtime` is the RESERVATION's runtime."""
        if part.min_sender_age_s is not None:
            since = payload.get("sender_since")
            if since is None:
                return peerjournal.Refuse("policy", SENDER_AGE_MISSING)
            try:
                seen = peerepochs.consult(ctx.state_dir, runtime=runtime, sender=payload["from"],
                                          sender_since=since, now=ctx.now)
            except (peerepochs.Untrusted, peerepochs.EpochFault):
                return peerjournal.Hold(EPOCH_STORE_UNAVAILABLE)
            if seen == peerepochs.INCONSISTENT:
                return peerjournal.Refuse("policy", SENDER_SINCE_INCONSISTENT)
            age = (ctx.now - parse_utc_ts(since)).total_seconds()
            if age < part.min_sender_age_s:
                return peerjournal.Refuse("policy", QUARANTINED)
        if part.exposure_required and payload.get("sender_exposure") is None:
            return peerjournal.Refuse("policy", EXPOSURE_MISSING)
        return None
    return policy


#: The control receive checks' refusal causes (every one is a drop).
CONTROL_SIGNER = "control_signer"
CONTROL_MISROUTED = "misrouted"
CONTROL_TS_WINDOW = "ts_window"
UNKNOWN_ABOUT = "unknown_about"
CONTROL_DUPLICATE = "duplicate"


def _already_reserved(state_dir: Any, runtime: str, ident: str) -> bool:
    """Whether (runtime, id) already holds a reservation in the replay store."""
    from . import peerbind
    rt, idk = peerbind.replay_keys(runtime, ident)
    return (Path(state_dir) / "peer-replay" / rt / (idk + peerbind.RESERVATION_SUFFIX)).exists()


def _control_receive(profile: Profile) -> Callable:
    from . import config as config_mod
    from . import peerbind, peerclock, peerjournal
    ctx = profile.context

    def control_receive(view: Any, verdict: Any):
        """A verified control notice's checks after 1-5, in order: `from` is
        the configured runtime that owns the verifying key; `to` is this
        router's own runtime address; `ts` is fresh (check 7; closed
        admission holds); `about` names exactly one `issued` record of an
        agent whose remote is in that runtime's domains (`expires_at` not
        applied). Check 4, that (runtime, `id`) is new, is the journal's
        reservation. A failure is `Refuse(cause)`, which the journal drops;
        success is `ControlAccepted`, naming the issued record."""
        payload = verdict.payload
        runtime = peerbind.runtime_for_key(ctx.delegation.config, verdict.key_id)
        own = config_mod.router_address(ctx.cfg.fleet_domain)
        if own is None:
            return peerjournal.Hold("no_fleet_domain")
        try:
            signer_ok = (runtime is not None and peerledger.canonical(payload["from"])
                         == peerledger.canonical(runtime.runtime))
        except Exception:  # noqa: BLE001 -- an unparseable address is not the runtime's
            signer_ok = False
        if not signer_ok:
            return peerjournal.Refuse(CONTROL_SIGNER)
        try:
            to_ok = peerledger.canonical(payload["to"]) == peerledger.canonical(own)
        except Exception:  # noqa: BLE001
            to_ok = False
        if not to_ok:
            return peerjournal.Refuse(CONTROL_MISROUTED)
        try:
            if peerclock.check7(ctx.clock, ctx.now)(payload, verdict.key_id) is not None:
                return peerjournal.Refuse(CONTROL_TS_WINDOW)
        except peerclock.Held:
            return peerjournal.Hold("admission_closed")
        # Check 4 before check 5 (the spec oracle's order, v2.1 §3.1): a
        # (runtime, id) already reserved is a duplicate, whatever `about`
        # now names. The journal's reservation is the backstop.
        if _already_reserved(ctx.state_dir, runtime.runtime, payload["id"]):
            return peerjournal.Refuse(CONTROL_DUPLICATE)
        domains = {d.lower() for d in runtime.domains}
        matches = []
        for lid, rel, data, rec in peerledger.find_issued(ctx.state_dir, payload["about"]):
            try:
                domain = peerledger.canonical(rec["remote"]).rsplit("@", 1)[1]
            except Exception:  # noqa: BLE001
                continue
            if domain in domains:
                matches.append((lid, rel, data))
        if len(matches) != 1:
            return peerjournal.Refuse(UNKNOWN_ABOUT)
        lid, rel, data = matches[0]
        return peerjournal.ControlAccepted(
            runtime=runtime.runtime, logical_id=lid, issued_path=rel,
            issued_sha256=hashlib.sha256(data).hexdigest())
    return control_receive
