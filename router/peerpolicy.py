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
canonical `(from, to)` pairs from `conformance_edges`) and a policy part (in
this build the closed markers `HOLD` or `PERMISSIVE`). `decide_hooks`
validates every part's exact type, so a factory contributes nothing a hook
could run. Each hook reads only its call arguments, its profile and the
profile's `HookContext`, which is frozen and bound to one pass's `cfg`,
`delegation`, `state_dir`, `now` and clock; `peerjournal.Ctx` refuses hooks
bound to any other. Hooks read time from the context, never from the clock.

What each hook reads:

| hook | reads |
|---|---|
| `check8` | the policy part only, in this build (the real check is a later build's) |
| `reply` | `cfg.instances[hosted].task_deny` (the deny, first), the hosted instance's state key and address, `state_dir` (the peer ledger), `now` |
| `edge` | the same resolution; the edge part; `delegation.config` (the key's runtime and its domains) |
| `policy` | the policy part only, in this build |
| `control_receive` | `delegation.config` (the key's configured runtime and its domains), `cfg.fleet_domain` (this router's runtime address), the clock and `now` (freshness), `state_dir` (the `issued` records) |

The decide order is deny, reply, edge, policy. The deny is the reply hook's
first step, so a denied sender is refused `(policy, denied)` whatever its
`in_reply_to`, and learns nothing about the ledger. Until the policy build
lands, the PRODUCTION profile holds every statement at `check8` and at
`policy` (`hook_absent`), so production places nothing; only a conformance
profile has the interim permissive policy part.
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


#: The edge part production uses: the edge exists when the key's runtime owns
#: the domain of `from` (`peerbind.check6`, the same predicate check 6 runs).
TRUSTED_HOST_DEFAULT = _Marker("TRUSTED_HOST_DEFAULT")
#: The policy part production uses until the policy build: hold everything.
HOLD = _Marker("HOLD")
#: The interim policy part a conformance profile uses until the policy build.
PERMISSIVE = _Marker("PERMISSIVE")

_EDGE_MARKERS = (TRUSTED_HOST_DEFAULT,)
_POLICY_MARKERS = (HOLD, PERMISSIVE)


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
    return Profile(context=ctx, edges=TRUSTED_HOST_DEFAULT, policy=HOLD)


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
    """A conformance driver's profile: the given edges, and (in this build)
    the interim permissive policy part. `receiver_patch` is accepted for the
    policy build, which maps it; here it must be a mapping or None. For tests
    and conformance drivers only."""
    if receiver_patch is not None and not isinstance(receiver_patch, Mapping):
        raise TypeError("receiver_patch: a mapping or None")
    return Profile(context=ctx, edges=conformance_edges(pairs), policy=PERMISSIVE)


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
    if not any(profile.policy is m for m in _POLICY_MARKERS):
        raise TypeError("decide_hooks: the policy part is HOLD or PERMISSIVE")


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


def _check8(profile: Profile) -> Callable:
    from . import peerjournal

    def check8(payload: Mapping[str, Any], key_id: str):
        if profile.policy is HOLD:
            return peerjournal.Hold("hook_absent", "check8")
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


def _policy(profile: Profile) -> Callable:
    from . import peerjournal

    def policy(payload: Mapping[str, Any], hosted: str):
        if profile.policy is HOLD:
            return peerjournal.Hold("hook_absent", "policy")
        return None
    return policy


#: The control receive checks' refusal causes (every one is a drop).
CONTROL_SIGNER = "control_signer"
CONTROL_MISROUTED = "misrouted"
CONTROL_TS_WINDOW = "ts_window"
UNKNOWN_ABOUT = "unknown_about"


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
