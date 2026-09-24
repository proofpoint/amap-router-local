"""router/config.py — load + validate the router's JSON config.

Config shape (see README.md for the full example)::

    {
      "state_dir": "/path/to/router-state",
      "instances": {
        "alice": { "handoff_dir": "/path/to/sandboxes/alice/handoff",
                   "peers": ["bob"] },
        "bob":   { "namespace": "/path/to/sandboxes/bob/claude/mail",
                   "peers": ["ALLOW_ANY"] }
      }
    }

Each instance declares EXACTLY ONE of two root shapes, distinguished by
DEPLOYMENT POSTURE rather than by any particular host tool:

  - `handoff_dir` (primary) — a SPLIT-ROOT posture: inbound and outbound are
    two SEPARATELY MOUNTED roots under one parent, so the host can enforce
    different trust properties on each (typically inbound read-only,
    outbound read-write). Any host that can mount two directories
    independently produces this posture; one sandbox manager's
    `the host's split-root mode` is one implementation of it, and the one this
    router is exercised against.
  - `namespace` — the older SINGLE-TREE layout, kept working so an existing
    deployment need not migrate:

  - `handoff_dir: P`  -> `inbox_root = P/"inbox"`,   `outbox_root = P/"outbox"`
  - `namespace: P`    -> `inbox_root = P/"inbound"`, `outbox_root = P/"outbound"`

`inbox_root` (host-written: `notices/`, `messages/`) and `outbox_root`
(agent-written: `req-*.json`, `results/`, `processed/`) are two roots with
DIFFERENT trust properties, in EITHER mode. Under `handoff_dir` the HOST
enforces the split with a real `:ro` mount on `inbox` — which is what makes
a delivered notice unforgeable, since permission bits alone do not bind an
agent running as the owning uid (it can `chmod` past them). Under
`namespace` both sides remain agent-writable, the split is conceptual only,
but the SAME two-root model applies so router code never special-cases
either mode.

The loader fails loud (`ConfigError`, naming the exact offending field) on
anything that could otherwise silently produce a router with an insecure or
nonsensical configuration — see `load()` for the full checklist. This
module's OWN code has ZERO filesystem side effects beyond `Path.resolve()`-style
normalization of the strings the config already contains; it never creates a
directory. (A caller-supplied `validate_extra` runs inside the load, so what
that callable does is the caller's responsibility, not this module's claim.)

Three optional top-level keys govern attachment transport (AMAP v2.3.0 §3/§5,
enforced in `router/attachments.py` BEFORE any sidecar is opened):
`attachment_max_bytes` (per-file cap), `attachment_max_count` (per-request
count cap), `attachment_max_total_bytes` (per-request combined-size cap).
Each must be a positive integer if given; `attachment_max_total_bytes` must
be >= `attachment_max_bytes`. These are router-wide, not per-instance — the
cap protects the router process itself (a local DoS via an unbounded copy
between sandboxes), not any one instance's policy.

Five optional top-level keys govern the PEER LANE (the peer-origin profile,
AMAP 3.1.0; see `router/README.md` "Peer lane"):

  - `fleet_domain` — a bare, lowercase domain label sequence
    (`example.invalid`). When set, EVERY address this router emits or parses
    is `<instance>@<fleet_domain>` on both lanes (`address_for`/
    `instance_for`), and the router's own address is
    `amap.router@<fleet_domain>` (`router_address`). When absent, addressing
    stays `agent.<name>@local` and peer routing is unavailable.
  - `peer_senders` (PER INSTANCE) — the directed task graph, declared on the
    RECEIVER: `B.peer_senders = ["A"]` means A may task B, and nothing else.
    No wildcard, no mutuality. Refused without `fleet_domain`; refused when
    either end is a `namespace`-mode instance (its whole tree is
    agent-writable, so a peer notice there asserts nothing — and the reverse
    edge on a reply would place one in the SENDER's tree, so the sender
    must be handoff-mode too); refused when the same ordered pair is ALSO a
    mutual mail pair under `peers` — the lanes are disjoint per ordered pair
    by construction, so nothing the sender writes can move a message
    between them.
  - `sender_exposure_window_seconds` (default 86400) — the window the
    `sender_exposure` stamp on a peer notice covers (`router/exposure.py`).
  - `peer_reply_window_seconds` (default 604800) — how long after a peer
    notice its recipient may reply along the REVERSE edge without a
    declared edge of its own (`router/outbound.py`).
  - `intake_dir` — the parent of the cross-host intake spool
    (`<intake_dir>/<instance>/`, created by `provision`). Same containment
    rules as `state_dir`. Nothing in this repo reads it yet: it exists so the
    adapter can express the mount before an email router is real.

A caller may declare ADDITIONAL permitted instance keys (`extra_instance_keys`)
together with a `validate_extra` callable; validated values surface on
`InstanceConfig.extra`. Any instance key not declared that way is still
rejected, exactly as before — the hook widens WHO may define a key, never the
strictness. This module defines no such key and interprets none of them: a
caller that declares, say, `"quota"` owns both its meaning and its validation.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import (
    Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple, Union,
)

ALLOW_ANY = "ALLOW_ANY"

# An instance name is not merely a label: it is a PATH COMPONENT in
# router-private state. Everything that binds an agent's traffic to the
# router's own record of it is filed under `state_dir/<name>/` —
# `first-seen.json` (the first-sight marker, `firstsight.py`), `delivered/` (the
# reply-binding ledger, `binding.py`, which is what makes a reply bind to
# what the router actually delivered rather than to anything the agent can
# write), and `results/`/`held/` (`outbound.py`). So the name must be safe
# as a single path segment: no separator, no `.`/`..`, no leading dot, no
# whitespace or shell-active character. This character class is what
# guarantees that, and `load()` applies it to every key in `instances`.
#
# THE CHARSET IS SANDY'S SLUG ALPHABET, and that is the point: a sandbox has
# ONE name — sandbox directory, container, instance, `state_dir/<name>`,
# address local part — so nothing derives one name from another and nothing
# has to hold a mapping between them. Deriving a router-legal name from a
# slug was the single largest source of confusion across this family, and it
# is gone because the two names are now one name.
#
# It was narrower before (`^[a-z0-9][a-z0-9-]{0,63}$`) for one reason, and
# the reason was real: `state_dir` routinely lives on a case-insensitive
# filesystem, so `SunRoom-x` and `sunroom-x` would be two identities in this
# config sharing ONE directory on disk — one first-sight marker and one reply
# ledger between them. Seeing one would mark the other seen; a reply bound
# for one could bind against the other's delivery record.
#
# That collision was unrepresentable under the old rule. Under this one it is
# merely impossible in practice and LOUD if it ever happens: `load()` now
# carries an explicit casefold-collision guard (see `_check_casefold`). In
# practice, because a sandy slug is `<basename>-<8 hex>` and the hex half is
# never folded, two slugs collide under casefold only if their path digests
# are identical AND their basenames differ only by case. The guard is one
# comparison at load and should never fire; it exists so that if it ever
# does, it is a refusal naming both names rather than two agents silently
# sharing a ledger.
#
# First character stays alphanumeric: a leading `.` would make the state
# directory hidden, and a leading `-` reads as a flag to every command-line
# tool that ever touches it.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_TOP_KEYS = {
    "state_dir", "instances",
    "attachment_max_bytes", "attachment_max_count", "attachment_max_total_bytes",
    "fleet_domain", "intake_dir",
    "sender_exposure_window_seconds", "peer_reply_window_seconds",
    "task_graph", "mail_graph",
    "instances_dir", "selected_json",
    "peer_senders", "peers",
}
_INSTANCE_KEYS = {"namespace", "handoff_dir", "peers", "peer_senders"}

#: The only value `task_graph` takes. A fleet-level statement that every
#: handoff-mode instance may task every other.
TASK_GRAPH_ALL = "all"

#: The only value `mail_graph` takes: every instance may cold-initiate mail
#: to every other. The peer lane's `task_graph` for the mail lane, and named
#: the same way — for what it IS, a graph, not for the per-instance field it
#: expands into.
#:
#: NOT SPELLED `peers`, and that was a late correction. `peers` is already an
#: INSTANCE key holding a LIST, so a top-level `peers` holding a STRING would
#: put one word at two nesting levels with two types, and a reader would have
#: to check the indentation to know which they were looking at. This repo
#: shipped that defect once already this week — a status line where `held=`
#: and a `PEER HELD` banner counted opposite directions one line apart — and
#: it is not being reintroduced in a config schema, where it would be
#: permanent. `task_graph`/`mail_graph` is a pair; `task_graph`/`peers` is a
#: puzzle.
#:
#: IT IS NOT `ALLOW_ANY`, EITHER, AND THE DIFFERENCE IS THE WHOLE POINT.
#: `ALLOW_ANY` is a member of ONE instance's list and relaxes only the side
#: that declares it — mutuality is still owed by the other end, and a
#: one-sided `ALLOW_ANY` grants nothing in either direction. `mail_graph`
#: declares BOTH directions for every pair, so mutuality is satisfied by
#: construction rather than waived. Same outcome for a full mesh, opposite
#: mechanism, and rendering one into the other would replace a mutual mesh
#: with N unilateral declarations that mesh today and stop the moment one
#: list is edited.
#:
#: DELIBERATELY THE SAME STRING AS `TASK_GRAPH_ALL`, AND DO NOT "DIFFERENTIATE"
#: THEM. The two keys are a pair and read as one — `task_graph: "all"` and
#: `mail_graph: "all"` — and the word means the same thing in both: every
#: instance, both directions. Making the VALUES differ to buy a test
#: something would trade a schema two operators read for a property one
#: assertion wanted.
#:
#: The temptation has a specific source, so it is written down. A host
#: adapter pins its rendered token against these constants, and its own
#: workbench observed — correctly — that a value assertion cannot tell the
#: two apart while both are `"all"`, concluding "the value pin starts working
#: the day the tokens are differentiated". That framing is off by one. The
#: value pin already does its job: it fails if the token changes HERE, which
#: is the contract it exists to defend. What it cannot detect is that repo
#: importing the wrong constant of the two — a defect in the test, on its
#: side, which differentiating a wire token here would be a strange way to
#: fix. The KEY assertion is what carries the distinction, and theirs does.
MAIL_GRAPH_ALL = "all"

#: DISCOVERY. `instances_dir` replaces `instances`: the instance set is the
#: directories under it, and the two keys are mutually exclusive. The lane
#: names below are the FIXED leaf names inside `<instances_dir>/<slug>/` —
#: the same three the handoff tree already used, so nothing about a drained
#: instance changes except how this loader learned it exists.
#:
#: They are constants because a host adapter creates these directories and
#: pins their names against this module. A rename here is a cross-repo
#: change.
LANE_INBOX = "inbox"
LANE_PEER = "peer"
LANE_OUTBOX = "outbox"
LANES = (LANE_INBOX, LANE_PEER, LANE_OUTBOX)

#: The AMAP §2-canonical leaves inside each lane. THE SINGLE SOURCE: the
#: host adapter renders its `create` block from this, `provision` builds its
#: skeleton from it, and the discovery-mode presence check requires it — so
#: the three cannot drift into two lists that agree until they do not.
#:
#: The LANE ROOT itself is not listed. It is implied: creating
#: `<lane>/<leaf>` creates `<lane>`, and requiring a leaf requires its
#: parent. Listing it as `"."` — which this router's own creation path once
#: did — reads as a fourth leaf to anyone rendering a `create` block from
#: it, and produces `outbox/.` in a manifest.
LANE_LEAVES = {
    LANE_INBOX: ("notices", "messages"),
    LANE_PEER: ("notices", "messages"),
    LANE_OUTBOX: ("results", "processed"),
}

#: The verdict file that ADMITS a discovered directory. Discovery alone is
#: not admission: a directory is an instance only if the host's verdict says
#: that slug was selected. Written by the host, read-only here, re-read every
#: poll — never cached, never mtime-compared.
SELECTED_SCHEMA = 1


# A fleet domain is a bare domain label sequence, LOWERCASE — it appears in
# every `from`, `to`, DSN and audit line, and the adapter diffs this router's
# `peers --json` against each agent's `peers.json` byte for byte, so
# two spellings of one domain would make a correct fleet look misconfigured.
# Refused rather than folded, like instance names.
_FLEET_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)

# The router's own local part. The `.` is outside the instance-name charset
# (`_NAME_RE`), so this can never collide with an agent and never parses as an
# instance (a reply to a DSN cannot bind). Derived, never configured. The
# daemon no longer keeps an allowlist for it to be absent from (ruling 16);
# what the daemon does check is that a peer notice does not claim to come from
# this local part, since the router never tasks agents.
ROUTER_LOCAL_PART = "amap.router"

#: `sender_exposure` window (seconds) — see `router/exposure.py`.
SENDER_EXPOSURE_WINDOW_SECONDS_DEFAULT = 86400
#: reverse-edge reply window (seconds) — see `router/outbound.py`.
PEER_REPLY_WINDOW_SECONDS_DEFAULT = 604800

#: Name of the peer tree under a handoff-mode instance's declared root.
PEER_TREE = "peer"

# A caller-supplied validator for a caller-declared instance key:
# `(instance_name, key, raw_value) -> normalized_value`. It may raise anything;
# `load_obj` converts every failure into a `ConfigError` naming the instance and
# the key, so a caller's own exception type never escapes the loader.
ExtraValidator = Callable[[str, str, Any], Any]

MODE_HANDOFF = "handoff"
MODE_NAMESPACE = "namespace"

# Attachment transport caps (AMAP v2.3.0, §3/§5) — see router/attachments.py.
# Configurable per router instance (not per host sandbox); these are the
# defaults when the config omits the corresponding top-level key.
ATTACHMENT_MAX_BYTES_DEFAULT = 8 * 1024 * 1024        # per-file cap
ATTACHMENT_MAX_COUNT_DEFAULT = 16                     # per-request attachment count cap
ATTACHMENT_MAX_TOTAL_BYTES_DEFAULT = 32 * 1024 * 1024  # per-request combined cap

# Which config key maps to which mode, and the leaf names it derives.
_ROOT_KEY_MODE = {"handoff_dir": MODE_HANDOFF, "namespace": MODE_NAMESPACE}


class ConfigError(Exception):
    """Raised by `load()`/`loads()` on any invalid config. The message
    always names the exact field at fault — this loader never guesses or
    repairs, only refuses."""


def _derive_roots(mode: str, root: Path) -> Tuple[Path, Path]:
    """The ONE place inbox/outbox roots are derived from an instance's
    declared root — every call site (config load here; nothing else ever
    re-derives this) goes through this function so the two modes' layouts
    can never drift out of step with each other or with `mcp-servers.json`
    (see `test_layout_agreement.py` — in the HOST ADAPTER's repo, not this
    one: it asserts the two repos agree, so it is built from the adapter
    side using this package's declared test surface)."""
    if mode == MODE_HANDOFF:
        return root / "inbox", root / "outbox"
    return root / "inbound", root / "outbound"


@dataclass(frozen=True)
class InstanceConfig:
    name: str
    mode: str  # MODE_HANDOFF | MODE_NAMESPACE
    # The declared path (`handoff_dir` or `namespace`) — the containment
    # ANCHOR for every write this router makes into this instance. Deliberately
    # NOT `inbox_root`/`outbox_root` themselves: an agent that replaces
    # `root/"inbound"` (or `root/"inbox"`) wholesale with a symlink must
    # still be caught, and anchoring the check at the very directory that
    # got replaced is a tautology that lets the escape through silently
    # (both the anchor and the write target resolve through the same
    # symlink) — see `deliver.py`/`outbound.py`/`provision.py`, all of
    # which anchor on `root`, never on `inbox_root`/`outbox_root`.
    root: Path
    inbox_root: Path   # host-written (or, in `namespace` mode, conceptually so): notices/, messages/
    outbox_root: Path  # agent-written: req-*.json, results/, processed/
    peers: FrozenSet[str] = field(default_factory=frozenset)
    # The directed task graph, RECEIVER side: the instances that may task
    # this one on the peer lane. Validated at load (see the module docstring);
    # enforced by `binding.check_peer_edge`. Empty in every config written
    # before the peer lane existed.
    peer_senders: FrozenSet[str] = field(default_factory=frozenset)
    # `root/"peer"` — the peer tree this router writes and the adapter mounts
    # read-only — for a handoff-mode instance in a fleet with a
    # `fleet_domain`; `None` otherwise. THE predicate for "this instance is
    # on the peer lane": provision creates the tree, reset empties it, the
    # outcome reader runs, iff this is set. A namespace-mode instance never
    # has one (loader refuses any edge touching it), and a fleet without a
    # domain has no peer lane at all.
    peer_root: Optional[Path] = None
    # Values a CALLER declared (`extra_instance_keys`) and validated
    # (`validate_extra`). The router itself defines none of these keys and
    # reads none of them — they exist so a downstream runtime can carry its
    # own per-instance config through this loader instead of forking it.
    # ALWAYS a mapping, never None: the loader always looks, so `{}` means
    # "looked, nothing declared or present" rather than "unknown". A key
    # declared but ABSENT from the instance is simply not here.
    # `hash=False` because a MappingProxyType is not hashable, and without it
    # this frozen dataclass silently stopped being hashable the moment the
    # field was added -- a real behaviour change on a module that is now
    # declared public API, caught only by review. Excluding it from the hash is
    # sound: equal instances agree on every other field, so they still hash
    # equal. It stays in `__eq__`.
    extra: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}), hash=False)


@dataclass(frozen=True)
class DiscoveryReport:
    """What discovery SAW and did not admit.

    Admission is not validation, and this type is the difference. An authored
    `instances` object is checked all-or-nothing: a contradiction is the
    author's to fix and refusing is safe because nothing is running. A
    DISCOVERED set is not authored — the filesystem supplies it, and one bad
    directory must not stop a running fleet. So every rejection here is a
    SKIP plus an entry in this report, never an exception.

    Which makes the report load-bearing rather than decorative: it is the
    only place a skipped instance exists at all. A silent skip and a clean
    fleet are indistinguishable from the outside, and the whole reason for
    reporting rather than swallowing is that a condition which MIGHT be
    benign gets a report, not a silence — the silence is what removes the
    evidence.
    """

    #: Directories whose names this router will not accept, with the reason.
    #: `{slug: reason}`.
    skipped: Dict[str, str] = field(default_factory=dict)
    #: Discovered directories with no verdict entry in `selected.json`. NEVER
    #: deleted and never drained — every workspace rename produces one, and
    #: deleting on a guess is unrecoverable.
    no_verdict: Tuple[str, ...] = ()
    #: Slugs the host's verdict SELECTED for which no directory exists. A
    #: verdict exists only after a launch, and the launch creates the
    #: directory — so this is broken state, not a pending one, and it is
    #: reported rather than tolerated.
    verdict_without_directory: Tuple[str, ...] = ()
    #: True when `selected.json` was absent or unreadable. Distinct from "it
    #: said nothing": absent means UNANSWERED, and nothing is admitted.
    verdict_unavailable: bool = False
    #: Edge endpoints naming a slug this router has not admitted, and why.
    #: `{slug: reason}`. The edge is INERT — it cannot be exercised, because
    #: a message is only ever drained from an admitted outbox and a recipient
    #: only resolves against the admitted set — but it is never SILENT.
    #:
    #: TWO TIERS, because the same absence has two very different causes and
    #: the host's verdict tells them apart at no cost. A slug the host has
    #: issued a verdict for is a sandbox that has not launched yet: PENDING,
    #: and unremarkable. A slug in NEITHER of the host's lists is a name
    #: nobody has ever used, which is as close to "this is a typo" as a
    #: machine can honestly get here.
    inert_edges: Dict[str, str] = field(default_factory=dict)

    def is_clean(self) -> bool:
        return not (self.skipped or self.no_verdict or self.inert_edges
                    or self.verdict_without_directory or self.verdict_unavailable)


@dataclass(frozen=True)
class RouterConfig:
    state_dir: Path
    instances: Dict[str, InstanceConfig]
    # Attachment transport caps (AMAP v2.3.0 §3/§5) — enforced BEFORE any
    # sidecar is opened (`router/attachments.py`). Defaults apply when the
    # config omits the corresponding top-level key.
    attachment_max_bytes: int = ATTACHMENT_MAX_BYTES_DEFAULT
    attachment_max_count: int = ATTACHMENT_MAX_COUNT_DEFAULT
    attachment_max_total_bytes: int = ATTACHMENT_MAX_TOTAL_BYTES_DEFAULT
    # Peer lane (module docstring). `None` fleet_domain = no peer lane.
    fleet_domain: Optional[str] = None
    intake_dir: Optional[Path] = None
    sender_exposure_window_seconds: int = SENDER_EXPOSURE_WINDOW_SECONDS_DEFAULT
    peer_reply_window_seconds: int = PEER_REPLY_WINDOW_SECONDS_DEFAULT
    #: Present only under discovery. An authored `instances` object cannot
    #: produce one: everything it could report is an error there.
    discovery: Optional[DiscoveryReport] = None
    #: The host's admission verdict, kept because `roster.roster_dir` derives
    #: the roster's location from it. Present only under discovery, like
    #: `discovery` above — an authored config has no verdict file, and
    #: therefore no roster.
    selected_json: Optional[Path] = None


def address_for(name: str, fleet_domain: Optional[str] = None) -> str:
    """The address for instance `name`: `<name>@<fleet_domain>` when the
    fleet has a domain, else the legacy synthetic `agent.<name>@local`.
    ONE identity per agent on BOTH lanes — a peer notice's `from` and a mail
    notice's `from` are the same string. Does not validate `name`; callers
    pass an already-validated instance name (config load enforces
    `_NAME_RE`). Callers pass `cfg.fleet_domain`; the parameter exists (rather
    than a bare `cfg`) so the two address forms stay a pure function of two
    strings."""
    if fleet_domain:
        return f"{name}@{fleet_domain}"
    return f"agent.{name}@local"


def router_address(fleet_domain: Optional[str]) -> Optional[str]:
    """`amap.router@<fleet_domain>` — this router's own address: `asserted_by`
    on every `sender_exposure` stamp, the `from` of every DSN it authors,
    and (cross-host, later) the signer. `None` without a fleet domain: the
    router never authors a message on the legacy addressing scheme."""
    if not fleet_domain:
        return None
    return f"{ROUTER_LOCAL_PART}@{fleet_domain}"


_ADDR_RE = re.compile(r"^agent\.([A-Za-z0-9][A-Za-z0-9._-]{0,63})@local$")


def instance_for(address: str, fleet_domain: Optional[str] = None,
                 known: Optional[Iterable[str]] = None) -> Union[str, None]:
    """Strict inverse of `address_for`: parse an address back to `<name>`,
    lowercased. With a `fleet_domain`, ONLY `<name>@<fleet_domain>` parses —
    the legacy `agent.<name>@local` form is not an alias, because one agent
    has one address. Returns `None` (never raises) on anything that doesn't
    match the shape — callers treat that as "not one of ours".

    THE ROUTER'S OWN ADDRESS NEVER PARSES, and this is now explicit rather
    than incidental. It used to fall out of the charset: `amap.router`
    contains a `.` and names could not. Names can now, because sandy slugs
    can (`example-1a2b3c4d.bak` is the shape), so the exclusion is a check.
    Without it a reply to a DSN could bind, and a peer notice could claim to
    come from this router.

    `known`, when given, is the configured instance names, and the match
    against it is CASE-INSENSITIVE while the value returned is the CANONICAL
    spelling. Local parts are case-insensitive in practice — every mail
    system treats them so — but the name is also a directory under
    `state_dir` and a key in `cfg.instances`, where only one spelling exists.
    Folding the returned name instead (which this did while names were
    lowercase-only) silently stopped resolving the moment a name could carry
    case. Without `known` the local part is returned folded, which is correct
    for an all-lowercase fleet and is what the legacy scheme has always
    done."""
    if not isinstance(address, str):
        return None
    candidate = address.strip().lower()
    if fleet_domain:
        m = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]{0,63})@" + re.escape(fleet_domain) + r"$",
            candidate,
        )
    else:
        m = _ADDR_RE.match(candidate)
    if m is None:
        return None
    name = m.group(1)
    if name.casefold() == ROUTER_LOCAL_PART.casefold():
        return None          # the router is not an instance — see the docstring
    if known is None:
        return name
    folded = name.casefold()
    for candidate in known:
        if candidate.casefold() == folded:
            return candidate
    return None


def _require_object(value, what: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{what}: expected an object, got {type(value).__name__}")
    return value


def _require_absolute(raw: str, what: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ConfigError(f"{what}: expected a non-empty string path")
    p = Path(raw)
    if not p.is_absolute():
        raise ConfigError(f"{what}: must be an absolute path, got {raw!r}")
    # Normalize (resolve '..'/'.' lexically) WITHOUT touching the
    # filesystem (no symlink resolution — the path need not exist yet).
    return Path(os.path.normpath(str(p)))


def _is_within(inner: Path, outer: Path) -> bool:
    """True iff `inner` is `outer` itself or lives anywhere underneath it,
    compared lexically (no filesystem access, no symlink resolution —
    config validation must not depend on paths existing yet)."""
    try:
        inner.relative_to(outer)
        return True
    except ValueError:
        return False


def _read_selected(path: Path) -> Optional[Tuple[frozenset, frozenset]]:
    """`(selected, not_selected)` slug sets from the host's verdict file, or
    `None` if it is absent, unreadable or malformed.

    `None` IS NOT AN EMPTY VERDICT. Absent means the host has not answered —
    nothing is admitted, and the fleet drains nothing rather than draining
    everything. Empty means it answered and selected nobody. Collapsing the
    two would turn a missing file into a full fleet.

    Never raises. A verdict this router cannot read is a condition to report,
    not a reason to refuse a config that may be governing a running fleet.

    WHAT THIS CANNOT DETECT, and it is not a gap that can be closed here. A
    verdict written non-atomically — two concurrent writers through one fixed
    temp path, which is sandy#329 — usually tears into bytes that fail to
    parse, and those land on `None` and admit nobody. But two renders of one
    feature can also SPLICE into a document that parses:

        A: selected = [alice, bob]      B: selected = [carol]
        on disk:    [{carol, T2}, {bob, T1}]      <- parses clean

    a membership NEITHER launch computed. It carries the right schema and
    well-formed entries, so nothing here can tell it from a correct
    document — not a checksum this router does not have, not a timestamp,
    not a shape check. Only an atomic write prevents it, which is why that
    fix is a correctness fix rather than a robustness one.

    Recorded rather than guarded because a guard would be a lie: any check
    added here would pass on the spliced document above.
    """
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None

    def _slugs(key: str) -> frozenset:
        entries = doc.get(key)
        if not isinstance(entries, list):
            return frozenset()
        out = set()
        for e in entries:
            # Entries are objects carrying `slug` (+ `at`, and `why` on the
            # not-selected side). A bare string is not the shape and is
            # ignored rather than guessed at.
            if isinstance(e, dict) and isinstance(e.get("slug"), str):
                out.add(e["slug"])
        return frozenset(out)

    return _slugs("selected"), _slugs("not_selected")


def _inert_reason(slug: str, host_knows: frozenset) -> str:
    """Why an edge endpoint is inert, in the two tiers the host's verdict
    makes free.

    A slug the host has issued ANY verdict for — selected or not — is a
    sandbox that exists and has not launched under this manifest. A slug in
    NEITHER list is a name nobody has ever used, which is as close to "this
    is a typo" as anything here can honestly claim.
    """
    if slug in host_knows:
        return "not discovered yet — the host has a verdict for it (pending)"
    return (
        "not discovered, and the host has NO verdict for this slug — it "
        "names a sandbox that has never existed (probable typo)"
    )


def _has_state(state_dir: Path, name: str) -> bool:
    """True if this router already holds router-private state for `name`.

    The incumbency signal for a casefold collision. Checked as a DIRECTORY
    rather than by importing `firstsight` for its marker path: that module
    imports this one, and a cycle to answer "does this directory exist" would
    be a poor trade. Any state at all counts — a ledger without a marker is
    still state that would be stranded.
    """
    try:
        return (state_dir / name).is_dir()
    except OSError:
        return False


def _discover_instances(
    instances_dir: Path, selected_json: Path, state_dir: Path
) -> Tuple[Dict[str, Dict[str, str]], DiscoveryReport, frozenset]:
    """The instance set, from directories under `instances_dir`, ADMITTED by
    the host's verdict.

    Returns the same `{name: {"handoff_dir": path}}` shape an authored
    `instances` object produces, so everything downstream — the name rule,
    the reserved-name refusal, roots, peers, lane disjointness — runs
    unchanged and knows nothing about discovery.

    EVERY REJECTION IS A SKIP AND A REPORT ENTRY, never an exception. See
    `DiscoveryReport`.
    """
    verdict = _read_selected(selected_json)
    selected = verdict[0] if verdict is not None else frozenset()
    not_selected = verdict[1] if verdict is not None else frozenset()

    try:
        found = sorted(
            e.name for e in os.scandir(instances_dir)
            # `is_dir()` WITHOUT following symlinks: a symlink pointing out
            # of the tree is not an instance root, and following it here
            # would hand the rest of the loader a path outside everything
            # `state_dir` containment was checked against.
            if e.is_dir(follow_symlinks=False)
        )
    except OSError:
        found = []

    skipped: Dict[str, str] = {}
    admitted: Dict[str, Dict[str, str]] = {}
    folded: Dict[str, str] = {}
    no_verdict = []

    # Which discovered names fold together, computed BEFORE admitting any of
    # them — a collision cannot be decided by looking at one side of it.
    contested: Dict[str, List[str]] = {}
    for slug in found:
        contested.setdefault(slug.casefold(), []).append(slug)
    contested = {f: names for f, names in contested.items() if len(names) > 1}

    for slug in found:
        if not _NAME_RE.match(slug):
            skipped[slug] = "name is not a valid instance name"
            continue
        if slug.casefold() == ROUTER_LOCAL_PART.casefold():
            skipped[slug] = "this router's own address local-part"
            continue
        # CASEFOLD: skip the NEWCOMER, keep the INCUMBENT. `state_dir/<name>/`
        # holds the first-sight marker, the reply ledger and the quarantine,
        # so on a case-insensitive state_dir two names that fold together are
        # ONE directory — two agents sharing one ledger. An authored config
        # refuses the whole document for this; a discovered set must not,
        # because one `mkdir` would then take down a running fleet.
        #
        # INCUMBENCY DECIDES, NOT SORT ORDER, and the difference is the whole
        # rule. The incumbent is the one that ALREADY HAS ROUTER-PRIVATE
        # STATE — a `state_dir/<name>/` entry means this router has seen it,
        # snapshotted its outbox and possibly bound replies to it. Dropping
        # THAT one in favour of a newcomer would strand a live ledger.
        #
        # The first version of this sorted `found` and took the first match,
        # which is deterministic and wrong: `sorted()` puts `Alice-deadbeef`
        # before `alice-deadbeef`, so the winner was decided by CAPITALISATION
        # rather than by which instance was actually running. The plan this
        # implements says adoption order must come from the marker and "never
        # from directory listing order"; sort order is directory listing
        # order with extra steps.
        fold = slug.casefold()
        prior = folded.get(fold)
        if prior is not None:
            skipped[slug] = (
                f"folds together with {prior!r}, which holds the state_dir "
                f"entry they would share"
            )
            continue
        if fold in contested and not _has_state(state_dir, slug):
            # Some other candidate folds to the same name and this one has no
            # state. Defer: if the incumbent is later in `found`, it is the
            # one that must be admitted.
            incumbents = [o for o in contested[fold] if _has_state(state_dir, o)]
            if incumbents:
                skipped[slug] = (
                    f"folds together with {incumbents[0]!r}, which already has "
                    f"router-private state and is the incumbent"
                )
                continue
        if slug not in selected:
            # Discovered but not admitted. NEVER DELETED: every workspace
            # rename produces one of these, and a directory this router did
            # not create is not its to remove.
            no_verdict.append(slug)
            continue
        folded[slug.casefold()] = slug
        admitted[slug] = {"handoff_dir": str(instances_dir / slug)}

    # A verdict that names a slug with no directory. The launch that produced
    # the verdict also creates the directory, so this cannot happen in normal
    # operation — which is exactly why it is REPORTED rather than tolerated
    # as "pending". A tolerated impossibility removes the report that would
    # have found the bug.
    missing = tuple(sorted(s for s in selected if s not in found))

    return admitted, DiscoveryReport(
        skipped=skipped,
        no_verdict=tuple(no_verdict),
        verdict_without_directory=missing,
        verdict_unavailable=verdict is None,
    ), (selected | not_selected)


def loads(
    text: str,
    *,
    extra_instance_keys: Optional[Iterable[str]] = None,
    validate_extra: Optional[ExtraValidator] = None,
) -> RouterConfig:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"config: invalid JSON: {e}") from e
    return load_obj(
        doc, extra_instance_keys=extra_instance_keys, validate_extra=validate_extra
    )


def load(
    path: Union[str, Path],
    *,
    extra_instance_keys: Optional[Iterable[str]] = None,
    validate_extra: Optional[ExtraValidator] = None,
) -> RouterConfig:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"config: could not read {p}: {e}") from e
    return loads(
        text, extra_instance_keys=extra_instance_keys, validate_extra=validate_extra
    )


def load_obj(
    doc,
    *,
    extra_instance_keys: Optional[Iterable[str]] = None,
    validate_extra: Optional[ExtraValidator] = None,
) -> RouterConfig:
    # The caller's own arguments are checked BEFORE the document is looked at:
    # a mistake in how the hook was invoked is the caller's bug, and reporting
    # it as a config error about somebody's instance would misdirect.
    extra_keys = frozenset(extra_instance_keys or ())
    # Type-check BEFORE sorting. `sorted()` over a mixed-type set raises a raw
    # TypeError ("'<' not supported between 'int' and 'str'") before any
    # isinstance check runs -- so the one guard whose job is to report caller
    # mistakes as ConfigError missed the mistake most likely to reach it.
    for k in extra_keys:
        if not isinstance(k, str) or not k:
            raise ConfigError(
                f"extra_instance_keys: expected non-empty strings, got {k!r}"
            )
    reserved = extra_keys & _INSTANCE_KEYS
    if reserved:
        # Structural, not stylistic: a declared key that shadowed `peers`,
        # `namespace` or `handoff_dir` would route a caller's unvalidated value
        # into this loader's own security-relevant handling of that key.
        raise ConfigError(
            f"extra_instance_keys: {sorted(reserved)} are reserved instance "
            f"key(s) this loader defines itself and cannot be redeclared"
        )
    if extra_keys and validate_extra is None:
        raise ConfigError(
            "extra_instance_keys: a declared extra instance key requires a "
            "validator (validate_extra); an unvalidated value must not reach "
            "InstanceConfig.extra"
        )

    top = _require_object(doc, "config")
    unknown = set(top) - _TOP_KEYS
    if unknown:
        raise ConfigError(f"config: unknown top-level key(s): {sorted(unknown)}")

    if "state_dir" not in top:
        raise ConfigError("config.state_dir: required field is missing")
    state_dir = _require_absolute(top["state_dir"], "config.state_dir")

    # AUTHORED or DISCOVERED, never both. `instances` is an object the
    # operator wrote; `instances_dir` is a directory this router scans and the
    # host's verdict admits. They answer the same question from opposite
    # sides of the trust boundary, and a document carrying both would leave
    # "which one wins" to whoever read it last.
    discovery: Optional[DiscoveryReport] = None
    host_knows: frozenset = frozenset()
    if "instances" in top and "instances_dir" in top:
        raise ConfigError(
            "config: `instances` and `instances_dir` are two sources for one "
            "instance set — one or the other, never both"
        )
    selected_json: Optional[Path] = None
    if "instances_dir" in top:
        instances_dir = _require_absolute(top["instances_dir"], "config.instances_dir")
        if "selected_json" not in top:
            # No default, and deliberately not derived from `instances_dir`'s
            # parent: the admission file's location is a fact about the host's
            # layout, and guessing it would make "nothing is admitted" look
            # like "the host selected nobody".
            raise ConfigError(
                "config.selected_json: required with `instances_dir` — discovery "
                "finds directories, but only the host's verdict admits them"
            )
        selected_json = _require_absolute(top["selected_json"], "config.selected_json")
        for label, path in (("instances_dir", instances_dir),
                            ("selected_json", selected_json)):
            if _is_within(path, state_dir) or _is_within(state_dir, path):
                raise ConfigError(
                    f"config.{label} ({path}) and config.state_dir ({state_dir}) "
                    f"must not be nested inside one another — state_dir is "
                    f"router-private and must stay unreachable from the tree "
                    f"the host writes"
                )
        instances_raw, discovery, host_knows = _discover_instances(
            instances_dir, selected_json, state_dir)
        # NOT an error when empty. A fleet whose sandboxes have not launched
        # yet, or whose verdict is unreadable, is a fleet with nothing to
        # drain — which `run` handles by draining nothing. Refusing here would
        # take down a router that is correctly idle, and the report carries
        # the reason.
    else:
        if "instances" not in top:
            raise ConfigError(
                "config: either `instances` (authored) or `instances_dir` "
                "(discovered) is required"
            )
        instances_raw = _require_object(top["instances"], "config.instances")
        if not instances_raw:
            raise ConfigError("config.instances: must contain at least one instance")

    def _positive_int(key: str, default: int) -> int:
        if key not in top:
            return default
        v = top[key]
        if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            raise ConfigError(f"config.{key}: expected a positive integer, got {v!r}")
        return v

    attachment_max_bytes = _positive_int("attachment_max_bytes", ATTACHMENT_MAX_BYTES_DEFAULT)
    attachment_max_count = _positive_int("attachment_max_count", ATTACHMENT_MAX_COUNT_DEFAULT)
    attachment_max_total_bytes = _positive_int(
        "attachment_max_total_bytes", ATTACHMENT_MAX_TOTAL_BYTES_DEFAULT
    )
    if attachment_max_total_bytes < attachment_max_bytes:
        raise ConfigError(
            "config.attachment_max_total_bytes "
            f"({attachment_max_total_bytes}) must be >= "
            f"config.attachment_max_bytes ({attachment_max_bytes}) — otherwise "
            "no single attachment could ever pass both caps"
        )

    fleet_domain: Optional[str] = None
    if "fleet_domain" in top:
        fd = top["fleet_domain"]
        if not isinstance(fd, str) or not _FLEET_DOMAIN_RE.match(fd):
            raise ConfigError(
                f"config.fleet_domain: expected a bare, lowercase domain label "
                f"sequence such as 'example.invalid', got {fd!r}"
            )
        fleet_domain = fd

    intake_dir: Optional[Path] = None
    if "intake_dir" in top:
        intake_dir = _require_absolute(top["intake_dir"], "config.intake_dir")
        if _is_within(intake_dir, state_dir) or _is_within(state_dir, intake_dir):
            raise ConfigError(
                f"config.intake_dir ({intake_dir}) and config.state_dir ({state_dir}) "
                f"must not be nested inside one another"
            )

    sender_exposure_window_seconds = _positive_int(
        "sender_exposure_window_seconds", SENDER_EXPOSURE_WINDOW_SECONDS_DEFAULT
    )
    peer_reply_window_seconds = _positive_int(
        "peer_reply_window_seconds", PEER_REPLY_WINDOW_SECONDS_DEFAULT
    )

    # Pass 1: shape + name + root (mode/root_key/root), per instance (peers
    # resolved in pass 2 so an unknown-peer error can name the actual set
    # of known instances).
    roots: Dict[str, Tuple[str, str, Path]] = {}  # name -> (mode, root_key, root)
    peers_raw: Dict[str, List[str]] = {}
    peer_senders_raw: Dict[str, List[str]] = {}
    extras: Dict[str, Dict[str, Any]] = {}  # name -> caller-validated extra keys
    for name, spec in instances_raw.items():
        if not _NAME_RE.match(name):
            raise ConfigError(
                f"config.instances: instance name {name!r} must match "
                f"^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$ — sandy's slug alphabet, "
                f"because the slug IS the instance name (it is also the address "
                f"local-part and a directory under state_dir)"
            )
        if name.casefold() == ROUTER_LOCAL_PART.casefold():
            # The router's own local part is not available as an instance
            # name. It used to be unreachable because names could not contain
            # `.`; now that they can, it is a refusal. An instance holding
            # this name would receive the router's own DSNs and could be
            # named as the sender of a peer notice.
            raise ConfigError(
                f"config.instances: {name!r} is this router's own address "
                f"local-part and cannot be an instance name"
            )
        spec_obj = _require_object(spec, f"config.instances.{name}")
        unknown_i = set(spec_obj) - (_INSTANCE_KEYS | extra_keys)
        if unknown_i:
            raise ConfigError(
                f"config.instances.{name}: unknown key(s): {sorted(unknown_i)}"
            )

        # Declared-and-present keys only: a declared key the instance omits is
        # ABSENT, not empty, so the validator is not called for it and it does
        # not appear in `extra`. Kept in its own dict — extras never join
        # `roots` (so they cannot widen the nesting/overlap checks) and never
        # join `peers_raw` (so they cannot widen who may be reached).
        for k in sorted(set(spec_obj) & extra_keys):
            try:
                extras.setdefault(name, {})[k] = validate_extra(name, k, spec_obj[k])
            except Exception as e:  # including a ConfigError from the caller
                raise ConfigError(f"config.instances.{name}.{k}: {e}") from e

        present = [k for k in ("handoff_dir", "namespace") if k in spec_obj]
        if len(present) != 1:
            got = "not both" if len(present) == 2 else "got neither"
            raise ConfigError(
                f"config.instances.{name}: give exactly one of 'handoff_dir' "
                f"(split-root: separately-mounted inbox/outbox) or 'namespace' (single-tree "
                f"AMAP layout), {got}"
            )
        root_key = present[0]
        mode = _ROOT_KEY_MODE[root_key]
        root = _require_absolute(spec_obj[root_key], f"config.instances.{name}.{root_key}")
        roots[name] = (mode, root_key, root)

        peers_val = spec_obj.get("peers", [])
        if not isinstance(peers_val, list) or not all(isinstance(p, str) for p in peers_val):
            raise ConfigError(f"config.instances.{name}.peers: expected an array of strings")
        peers_raw[name] = peers_val

        ps_val = spec_obj.get("peer_senders", [])
        if not isinstance(ps_val, list) or not all(isinstance(p, str) for p in ps_val):
            raise ConfigError(
                f"config.instances.{name}.peer_senders: expected an array of strings"
            )
        peer_senders_raw[name] = ps_val

    _check_casefold(list(instances_raw))

    known_names = set(roots)

    # `task_graph: "all"` — expanded HERE, once, into the same per-instance
    # `peer_senders` sets an explicit graph produces, so everything
    # downstream (validation, `binding.check_peer_edge`, `peers --json`,
    # the lane-disjointness check) sees one shape and knows nothing about
    # the shorthand.
    #
    # FLEET-LEVEL RATHER THAN A WILDCARD IN `peer_senders`, which is still
    # refused. `peer_senders: ["ALL"]` on one instance is a local statement
    # with a global effect: reading that entry does not tell you the fleet is
    # fully connected, and adding an instance later silently grants it the
    # ability to task everything and be tasked by everything. A top-level key
    # is a global statement with a global effect — one line to read, one line
    # to change, and `peers --json` still renders the expansion rather than
    # the shorthand, so the audit surface is unchanged.
    task_graph = top.get("task_graph")
    if task_graph is not None:
        if task_graph != TASK_GRAPH_ALL:
            raise ConfigError(
                f"config.task_graph: expected {TASK_GRAPH_ALL!r}, got {task_graph!r}"
            )
        if fleet_domain is None:
            raise ConfigError(
                "config.task_graph: requires a top-level fleet_domain — without "
                "one the peer lane does not exist and no edge can be declared"
            )
        declared = {n for n in instances_raw if peer_senders_raw.get(n)}
        if declared:
            raise ConfigError(
                f"config.task_graph: {TASK_GRAPH_ALL!r} is the whole graph, but "
                f"{sorted(declared)} also declare peer_senders — one source or "
                f"the other, never both"
            )
        eligible = [n for n in instances_raw if roots[n][0] != MODE_NAMESPACE]
        for name in eligible:
            peer_senders_raw[name] = sorted(n for n in eligible if n != name)

    # `mail_graph: "all"` — the same shorthand for the MAIL lane, expanded
    # here into the same per-instance `peers` sets an explicit list produces,
    # so `binding.check_cold`, `derive_matrix` and `peers`/`matrix` see one
    # shape and know nothing about the word.
    #
    # TWO DELIBERATE DIFFERENCES FROM `task_graph`, BOTH OF WHICH LOOK LIKE
    # OVERSIGHTS AND ARE NOT:
    #
    # 1. NO `fleet_domain` REQUIREMENT. The peer lane cannot exist without
    #    one — a peer address is `<name>@<fleet_domain>`. The mail lane
    #    addresses instances as `agent.<name>@local` and has never needed a
    #    domain, so requiring one here would refuse a configuration that
    #    works.
    #
    # 2. NAMESPACE-MODE INSTANCES ARE **INCLUDED**. `task_graph` excludes
    #    them because that whole tree is agent-writable, so a peer notice
    #    placed there asserts nothing about who sent it. That reasoning is
    #    about the PEER lane's trust story and does not transfer: `namespace`
    #    is the older, still-supported mail layout, and a deliver notice in
    #    it is exactly as meaningful as it has always been. Making these two
    #    expansions symmetric would silently drop every namespace instance
    #    out of the mail mesh, and nothing would report it.
    mail_graph = top.get("mail_graph")
    if mail_graph is not None:
        if mail_graph != MAIL_GRAPH_ALL:
            raise ConfigError(
                f"config.mail_graph: expected {MAIL_GRAPH_ALL!r}, got {mail_graph!r}"
            )
        declared = {n for n in instances_raw if peers_raw.get(n)}
        if declared:
            raise ConfigError(
                f"config.mail_graph: {MAIL_GRAPH_ALL!r} is the whole graph, but "
                f"{sorted(declared)} also declare peers — one source or the "
                f"other, never both"
            )
        for name in instances_raw:
            peers_raw[name] = sorted(n for n in instances_raw if n != name)

    # TOP-LEVEL `peer_senders` / `peers` MAPS — the explicit graphs, for a
    # fleet whose policy does not reduce to a wildcard.
    #
    # They are top-level because under discovery there IS no per-instance
    # config section: instances are directories. The per-instance spelling
    # stays exactly as it was for an authored config, so nothing that works
    # today changes; these are the same fields addressed from the other end.
    inert: Dict[str, str] = {}

    def _graph_map(key: str, into: Dict[str, List[str]], exclusive_with: str) -> None:
        raw = top.get(key)
        if raw is None:
            return
        if top.get(exclusive_with) is not None:
            raise ConfigError(
                f"config.{key}: an explicit map and config.{exclusive_with} are "
                f"two sources for one graph — one or the other, never both"
            )
        declared = {n for n in instances_raw if into.get(n)}
        if declared:
            raise ConfigError(
                f"config.{key}: a top-level map and per-instance {key} on "
                f"{sorted(declared)} are two sources for one graph — one or the "
                f"other, never both"
            )
        if not isinstance(raw, dict):
            raise ConfigError(f"config.{key}: expected an object, got {raw!r}")
        for holder, members in raw.items():
            if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
                raise ConfigError(
                    f"config.{key}.{holder}: expected an array of strings"
                )
            # AN ENDPOINT THIS ROUTER HAS NOT ADMITTED IS INERT, NEVER A
            # REFUSAL — but never silent either. The map is fleet-wide and
            # rendered before anything launches, so one un-launched sandbox
            # must not make the whole fleet unloadable. Inert adds no risk
            # because it is already the behaviour: a message is only drained
            # from an ADMITTED outbox and a recipient only resolves against
            # the ADMITTED set, so such an edge cannot be exercised.
            #
            # What it COSTS is the typo guard an authored config has (an
            # unknown name there is a ConfigError, and still is). A typo'd
            # slug becomes an inert edge, the edge the operator MEANT is
            # absent, and the delegation is refused at runtime as "no edge" —
            # a correct-looking reason for a policy that was never in force.
            # Hence the report, and hence two tiers.
            if holder not in instances_raw:
                inert.setdefault(holder, _inert_reason(holder, host_knows))
                continue
            kept = []
            for m in members:
                if m == ALLOW_ANY or m in instances_raw:
                    kept.append(m)
                else:
                    inert.setdefault(m, _inert_reason(m, host_knows))
            into[holder] = sorted(set(kept))

    if discovery is not None:
        _graph_map("peer_senders", peer_senders_raw, "task_graph")
        _graph_map("peers", peers_raw, "mail_graph")
    elif "peer_senders" in top or "peers" in top:
        # An AUTHORED config declares graphs per instance. A top-level map
        # there would be a second spelling of something the document already
        # says, and this loader does not offer two ways to say one thing.
        raise ConfigError(
            "config: top-level `peer_senders`/`peers` maps belong to a "
            "discovered fleet (`instances_dir`); an authored `instances` "
            "object declares them per instance"
        )

    # Pass 2: peers must name a known instance or the ALLOW_ANY literal.
    instances: Dict[str, InstanceConfig] = {}
    for name in instances_raw:
        for peer in peers_raw[name]:
            if peer != ALLOW_ANY and peer not in known_names:
                raise ConfigError(
                    f"config.instances.{name}.peers: {peer!r} names no configured "
                    f"instance (known: {sorted(known_names)}; or the literal {ALLOW_ANY!r})"
                )
        mode, _root_key, root = roots[name]
        senders = peer_senders_raw[name]
        where = f"config.instances.{name}.peer_senders"
        if senders and fleet_domain is None:
            raise ConfigError(
                f"{where}: requires a top-level fleet_domain — without one the "
                f"peer lane does not exist and no edge can be declared"
            )
        if senders and mode == MODE_NAMESPACE:
            raise ConfigError(
                f"{where}: {name!r} is a namespace-mode instance and can never be a "
                f"peer target — its whole tree is agent-writable, so a peer notice "
                f"there would assert nothing"
            )
        if len(set(senders)) != len(senders):
            raise ConfigError(f"{where}: duplicate entries in {senders!r}")
        for s_name in senders:
            if s_name == ALLOW_ANY:
                raise ConfigError(
                    f"{where}: {ALLOW_ANY!r} is not permitted — the task graph "
                    f"names instances, never a wildcard"
                )
            if s_name not in known_names:
                raise ConfigError(
                    f"{where}: {s_name!r} names no configured instance "
                    f"(known: {sorted(known_names)})"
                )
            if s_name == name:
                raise ConfigError(f"{where}: an instance cannot task itself")
            if roots[s_name][0] == MODE_NAMESPACE:
                raise ConfigError(
                    f"{where}: {s_name!r} is a namespace-mode instance and cannot "
                    f"task a peer — the reply to its task travels the reverse edge "
                    f"as a peer notice into ITS tree, which is agent-writable and "
                    f"asserts nothing"
                )
        inbox_root, outbox_root = _derive_roots(mode, root)
        peer_root = root / PEER_TREE if (mode == MODE_HANDOFF and fleet_domain) else None
        instances[name] = InstanceConfig(
            name=name, mode=mode, root=root,
            inbox_root=inbox_root, outbox_root=outbox_root,
            peers=frozenset(peers_raw[name]),
            peer_senders=frozenset(senders),
            peer_root=peer_root,
            extra=MappingProxyType(extras.get(name, {})),
        )

    # state_dir must be unreachable from every instance's declared root, and
    # vice versa — the security core's precondition (router-private state
    # must never be mountable/visible inside any sandbox).
    for name, (_mode, root_key, root) in roots.items():
        if _is_within(state_dir, root) or _is_within(root, state_dir):
            raise ConfigError(
                f"config.state_dir ({state_dir}) and config.instances.{name}.{root_key} "
                f"({root}) must not be nested inside one another"
            )

    # No two declared roots may overlap (be equal, or one nested in the
    # other) — otherwise one instance's connector could read/write another
    # instance's files. Checked over the DECLARED root (not the derived
    # inbox_root/outbox_root leaves): comparing leaves would miss, e.g.,
    # one instance's `namespace` nested inside another's `handoff_dir`.
    names_sorted = sorted(roots)
    for i, a in enumerate(names_sorted):
        for b in names_sorted[i + 1 :]:
            _mode_a, _key_a, ra = roots[a]
            _mode_b, _key_b, rb = roots[b]
            if ra == rb or _is_within(ra, rb) or _is_within(rb, ra):
                raise ConfigError(
                    f"config.instances: roots for {a!r} and {b!r} overlap ({ra} vs {rb})"
                )

    if intake_dir is not None:
        for name, (_mode, root_key, root) in roots.items():
            if _is_within(intake_dir, root) or _is_within(root, intake_dir):
                raise ConfigError(
                    f"config.intake_dir ({intake_dir}) and config.instances.{name}."
                    f"{root_key} ({root}) must not be nested inside one another"
                )

    cfg = RouterConfig(
        state_dir=state_dir, instances=instances,
        attachment_max_bytes=attachment_max_bytes,
        attachment_max_count=attachment_max_count,
        attachment_max_total_bytes=attachment_max_total_bytes,
        fleet_domain=fleet_domain, intake_dir=intake_dir,
        sender_exposure_window_seconds=sender_exposure_window_seconds,
        peer_reply_window_seconds=peer_reply_window_seconds,
        discovery=(replace(discovery, inert_edges=inert)
                   if discovery is not None else None),
        selected_json=selected_json,
    )

    # The two lanes are DISJOINT per ordered pair. A pair that is both a
    # declared edge (peer lane) and a mutual mail pair (mail lane) would let
    # the sender pick its lane by how it addressed the message — exactly the
    # sender-controlled lane choice the peer-origin profile forbids. Checked
    # with the SAME predicate `check_cold` enforces (imported locally, like
    # `derive_matrix`), never a re-implementation of mutuality.
    from .binding import check_cold  # local: module-load cycle, see derive_matrix
    for name in sorted(instances):
        for s_name in sorted(instances[name].peer_senders):
            if check_cold(cfg, s_name, name):
                raise ConfigError(
                    f"config.instances.{name}.peer_senders: the ordered pair "
                    f"{s_name!r} -> {name!r} is BOTH a peer edge and a mutual "
                    f"mail pair under 'peers'; the two lanes must be disjoint "
                    f"per ordered pair, or the sender could choose its lane"
                )
    return cfg


def _check_casefold(names: List[str]) -> None:
    """Refuse two instance names that differ only by case.

    `state_dir/<name>/` holds the first-sight marker, the reply-binding ledger
    and the quarantine. On a case-insensitive filesystem — macOS APFS by
    default — two names that fold together are one directory, so two agents
    would share one ledger: first sight of one marks the other seen, and a reply
    bound for one could bind against the other's delivery record.

    Under the old lowercase-only charset that collision was unrepresentable
    and this function did not exist. It exists now because the charset is
    sandy's, which preserves case.

    IT SHOULD NEVER FIRE. A slug is `<basename>-<8 hex>` and the hex half is
    never folded, so two slugs fold together only if their path digests are
    identical AND their basenames differ only by case. That is a digest
    collision, not a naming accident. The guard is one comparison at load,
    and its value is entirely in what happens if the reasoning above is ever
    wrong: a refusal naming both, rather than two agents quietly sharing a
    ledger."""
    seen: Dict[str, str] = {}
    for name in names:
        folded = name.casefold()
        if folded in seen:
            raise ConfigError(
                f"config.instances: {seen[folded]!r} and {name!r} differ only by "
                f"case, and `state_dir` may be on a case-insensitive filesystem — "
                f"they would share one first-sight marker and one reply ledger"
            )
        seen[folded] = name


def derive_matrix(cfg: RouterConfig) -> Dict[str, Dict[str, bool]]:
    """Derive the n x n "can A cold-initiate to B" matrix for `peers`/
    `matrix` display only — this is NEVER stored, always recomputed from
    `cfg.instances[*].peers`. `matrix[a][b]` is True iff `binding.
    check_cold(cfg, a, b)` — the SAME enforcement rule, called directly
    (not re-implemented here) so the review artifact and the enforcement
    path can never drift apart. Imported locally to avoid a module-load
    cycle (`binding` imports `ALLOW_ANY`/`RouterConfig` from this module)."""
    from .binding import check_cold  # local: see docstring

    names = sorted(cfg.instances)
    matrix: Dict[str, Dict[str, bool]] = {a: {} for a in names}
    for a in names:
        for b in names:
            matrix[a][b] = False if a == b else check_cold(cfg, a, b)
    return matrix


def derive_peer_graph(cfg: RouterConfig) -> Dict[str, List[str]]:
    """The directed task graph as `{recipient: [sender, ...]}` by INSTANCE
    NAME, every instance present (an instance nobody may task maps to `[]`),
    lists sorted. Display/diff only — enforcement is `binding.check_peer_edge`,
    which reads the same `peer_senders` sets, so the two cannot drift.
    `peers.render_peers_json` renders this as addr-specs for the adapter's
    `--verify` to diff against each agent's `peers.json`."""
    return {name: sorted(cfg.instances[name].peer_senders) for name in sorted(cfg.instances)}
