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
  - `mail_reply_window_seconds` (default 604800, at most 7776000) — how long
    after an inbound hop mail is placed its recipient may reply to it as a
    bound reply (`router/ingress.py`'s mail binding, fixed when the entry is
    prepared, so a later change never moves a recorded binding).
  - `delivered_domains_file` — optional absolute path to the delivered-domain
    file (`_delivered_domains`); while its set differs from `fleet_hosts`,
    every bound reply is held and mail is unaffected.
  - `min_sender_age_s` (default 86400, from 0 to 31536000) — the sender-age
    duration (contract §8.6 as amended by E30): the receiver refuses a
    signed statement `quarantined`, and the sender refuses a cross-host
    task `peer_quarantined`, while the sender's identity is younger than
    this. ONE value governs both (`classify.sender_age_refusal`,
    `peerpolicy.production_policy`). `0` is an ACTIVE policy, never "off":
    `sender_since` stays mandatory, the epoch rules still run, and a future
    `sender_since` is still refused. Restart-only: a reload that changes
    the effective value is refused (`service.reload_config`). The only
    configuration that may change the duration; `delegation` may never
    name it (`_OVERLAY_TOKENS`).
  - `intake_dir` — the parent of the cross-host intake spool
    (`<intake_dir>/<instance>/`, created by `provision`). Same containment
    rules as `state_dir`. Nothing in this repo reads it yet: it exists so the
    adapter can express the mount before an email router is real.
  - `registry_dir` — the host registry's directory (a read-only mount
    holding `registry.json`; `router/registry.py`). Present, each poll reads
    it and drains only instances whose name is an active, uncontested
    registry entry; every other instance is HELD and reported. Absent,
    nothing changes. It must not be inside `state_dir` or any instance
    root: an agent-reachable registry would let an agent choose identities.
  - `aliases` — the alias table, `[{"old", "new", "expires"}]`, under a
    registry and a fleet domain only (`router/aliases.py`; README,
    "Aliases"). What does not depend on the registry is checked here.
  - `transport_plugin` — `{"path": <absolute path>, "sha256": <64 hex>}`,
    the optional transport plugin, pinned by path and content hash, never
    by import name (`router/transport.py`). Both members or the key absent:
    absent means no plugin (`transport.NullTransport`), and the external
    leg settles as not configured. This module checks only the shape; the
    file itself is checked, and refused, when the router starts.
  - `hop` — `{"root", "peer_uid", "version_write", "caps": {"document",
    "request", "attachment", "total"}}`, the hop tree the transport plugin
    writes. Required exactly when `transport_plugin` is present, and only
    under a `registry_dir` (a handover names its sender by logical_id).
    `root` is used VERBATIM: it must be absolute and already in normal form
    (no trailing `/`, `//`, `.` or `..`), and must not equal, contain or sit
    inside `state_dir`, `registry_dir`, `intake_dir` or any instance root.
    The caps are positive byte counts, and `caps.document` must be large
    enough for the largest handover any accepted request can make
    (`router/hoplink.py`, `document_floor`). Restart-only: a reload that
    changes it is refused, like `transport_plugin`.

A caller may declare ADDITIONAL permitted instance keys (`extra_instance_keys`)
together with a `validate_extra` callable; validated values surface on
`InstanceConfig.extra`. Any instance key not declared that way is still
rejected, exactly as before — the hook widens WHO may define a key, never the
strictness. This module defines no such key and interprets none of them: a
caller that declares, say, `"quota"` owns both its meaning and its validation.
"""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import re
import stat
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
# `\Z`, not `$`, and applied with `fullmatch`: `$` also matches before a
# final newline, so `match` accepted "name\n" and handed it on as a path
# component.
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

#: A name shaped like a logical_id: 32 hex digits, EITHER case. Under a
#: registry, private state lives at `state_dir/<logical_id>/`, so such a name
#: would be indistinguishable from an identity's state directory, and on a
#: case-insensitive filesystem the upper-case spelling folds onto it too.
#: The host registry refuses to issue one (its `name_shape` rule); this
#: router refuses to run one under a registry.
ID_SHAPED_NAME_RE = re.compile(r"[0-9a-fA-F]{32}\Z")

#: The entries directly under `state_dir` that are this router's own, never
#: an instance's: the registry seq floor's directory (`registry.SEQ_DIR`) and
#: the status file (`status.STATUS_FILENAME`). An instance by one of these
#: names would have its private state joined onto them. Compared casefolded,
#: for a case-insensitive `state_dir`. The drain lock (`.router.lock`) and
#: `atomic_write`'s temporaries (`tmp*`, `mkstemp`'s fresh names, which never
#: replace an existing entry) need no entry here: the first is not a valid
#: name, the second cannot take over a directory that exists.
#: `test_state_rekey` pins this set against the modules that own them.
RESERVED_STATE_NAMES = frozenset({"registry", "status.json", "aliases"})
#: The peer lane's stores directly under `state_dir`: the decision key
#: (`peerbind.DECISION_KEY_FILE`), the replay store and its vacant markers
#: (`peerjournal.REPLAY_DIR`, `VACANT_DIR`), the clock
#: (`peerclock.CLOCK_FILE`, which also holds the store's bookkeeping). A
#: reset of an instance by one of these names would clear them.
PEER_STATE_NAMES = frozenset({"peer-decision.key", "peer-replay", "peer-vacant",
                              "peer-clock.json"})
RESERVED_STATE_NAMES = RESERVED_STATE_NAMES | PEER_STATE_NAMES
#: The router's own runtime control namespace (`router/peercontrol.py`):
#: `state_dir/_runtime/`, with its one generation's transport state under
#: `_runtime/<generation>/` exactly as an agent's. Never an instance name
#: (names begin with a letter or digit), and never touched by a reset.
RUNTIME_NS = "_runtime"
RUNTIME_GENERATION_FILE = "generation.json"
RESERVED_STATE_NAMES = RESERVED_STATE_NAMES | frozenset({RUNTIME_NS})

#: Connector ids for `outbound/ext/<id>/outcomes/` — the directories
#: `outcomes._consume_dir` scans, in this order. The spec ("The Volume
#: Layout", `outbound/ext/<name>/`) makes `<name>` a stable connector id,
#: chosen once and opaque to the runtime: it must not change when a
#: connector's repository is renamed, and nothing here parses it. Each id
#: becomes a PATH SEGMENT under an agent-writable tree, so the alphabet is
#: narrow and has no dot (no `.`, `..` or hidden names). `\Z`, not `$`, which
#: in Python also matches before a trailing newline.
_CONNECTOR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
#: The default keeps every deployment that predates the key exactly as it
#: was. `claude-code` is the first id the spec names.
DEFAULT_CONNECTOR_OUTCOME_IDS: Tuple[str, ...] = ("claude-code",)

_TOP_KEYS = {
    "state_dir", "instances", "connector_outcome_ids",
    "attachment_max_bytes", "attachment_max_count", "attachment_max_total_bytes",
    "fleet_domain", "intake_dir", "peer_sent_prune",
    "sender_exposure_window_seconds", "peer_reply_window_seconds",
    "mail_reply_window_seconds",
    "task_graph", "mail_graph",
    "instances_dir", "selected_json",
    "peer_senders", "peers",
    "transport_plugin", "registry_dir", "aliases", "hop",
    "trusted_fleet_hosts", "fleet_hosts", "egress", "ingress_quarantine_days",
    "ingress_dedup_horizon_days", "delivered_domains_file", "delegation",
    "min_sender_age_s",
}
_INSTANCE_KEYS = {"namespace", "handoff_dir", "peers", "peer_senders",
                  "task_deny", "send_to", "remote_fleet"}

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
    r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z"
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
#: `min_sender_age_s` (module docstring): the default, and the largest value
#: accepted. The ONLY sender-age literal in the package: `classify` and
#: `peerpolicy` read `RouterConfig.min_sender_age_s`, never this.
MIN_SENDER_AGE_S_DEFAULT = 86400
MIN_SENDER_AGE_S_MAX = 31536000
#: The canonical sender-age policy object's version (`sender_age_policy`).
SENDER_AGE_POLICY_VERSION = 1
#: reverse-edge reply window (seconds) — see `router/outbound.py`.
PEER_REPLY_WINDOW_SECONDS_DEFAULT = 604800
#: The mail-reply binding window (seconds): a placed inbound hop mail may be
#: replied to as a bound reply until its recorded `expires_at`. Bounded, so
#: no binding is practically permanent.
MAIL_REPLY_WINDOW_SECONDS_DEFAULT = 604800
MAIL_REPLY_WINDOW_SECONDS_MAX = 90 * 86400

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

#: Days an ingress-quarantine item is kept before its writer sweeps it
#: (`router/quarantine.py`). Defined here; the writer reads it.
INGRESS_QUARANTINE_DAYS_DEFAULT = 14
INGRESS_QUARANTINE_DAYS_MAX = 365
#: The ingress dedup horizon: default 30 days, at most ten years.
INGRESS_DEDUP_HORIZON_DAYS_DEFAULT = 30
INGRESS_DEDUP_HORIZON_DAYS_MAX = 3650

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
    # Cross-host classification inputs (`router/classify.py`), each a tuple
    # of CANONICAL entries, empty when absent. `task_deny`: addresses or
    # `@domain` entries at trusted fleet hosts, removed from the trusted
    # default edge. `send_to`: addresses or `@domain` entries this agent may
    # send to on the internet. `remote_fleet`: fleet hosts outside the
    # trusted list this agent may send fleet mail to.
    task_deny: Tuple[str, ...] = ()
    send_to: Tuple[str, ...] = ()
    remote_fleet: Tuple[str, ...] = ()


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
    mail_reply_window_seconds: int = MAIL_REPLY_WINDOW_SECONDS_DEFAULT
    #: Present only under discovery. An authored `instances` object cannot
    #: produce one: everything it could report is an error there.
    discovery: Optional[DiscoveryReport] = None
    #: The host's admission verdict, kept because `roster.roster_dir` derives
    #: the roster's location from it. Present only under discovery, like
    #: `discovery` above — an authored config has no verdict file, and
    #: therefore no roster.
    selected_json: Optional[Path] = None
    #: Which `outbound/ext/<id>/outcomes/` directories are scanned, in order.
    #: One budget and one dedup key span all of them (`outcomes._consume_dir`).
    connector_outcome_ids: Tuple[str, ...] = DEFAULT_CONNECTOR_OUTCOME_IDS
    #: The pinned transport plugin, or None for none (`transport_plugin`
    #: in the module docstring).
    transport_plugin: Optional["TransportPluginPin"] = None
    #: The host registry's directory, or None for none (`registry_dir` in
    #: the module docstring).
    registry_dir: Optional[Path] = None
    #: The hop tree the transport plugin writes, or None without a plugin
    #: (`hop` in the module docstring).
    hop: Optional["HopConfig"] = None
    #: The alias table (`aliases` in the module docstring; `router/aliases.py`),
    #: validated at load. Empty without one.
    aliases: Tuple["AliasEntry", ...] = ()
    #: Per poll: this poll's alias decisions (`aliases.AliasView`), attached by
    #: the service's pre-pass. None means none was computed: aliases are then
    #: never applied (and a table-named address is held, `aliases.normalise`).
    alias_view: Any = field(default=None, compare=False)
    #: Per poll, under a registry: instance name -> the directory name its
    #: private state lives under (its logical_id). Empty otherwise, and a
    #: name absent from it keeps its own name (`state_key`). Set by the
    #: service from the poll's registry report, never by a config file.
    state_keys: Mapping[str, str] = field(default_factory=dict)
    #: Per poll, under a registry: THE one immutable registry report every
    #: delivery gate of that poll reads (`target_hold`). Set together with
    #: `state_keys` by `registry.keyed_config`, never by a config file; None
    #: means no report was attached, which under a registry fails closed.
    registry_report: Any = field(default=None, compare=False)
    #: Per poll, under a registry: instance name -> its CURRENT generation's
    #: directory relative to `state_dir` (`<logical_id>/gen-<g>`), set by the
    #: generation pre-pass (`router/generations.py`), never by a config file.
    gen_keys: Mapping[str, str] = field(default_factory=dict)
    #: Cross-host classification (`router/classify.py`): the trusted fleet
    #: hosts, every fleet host (a superset of the trusted ones), and whether
    #: this host has internet egress. Canonical; empty and False when absent,
    #: which reproduces the behaviour before them ONLY without a transport
    #: plugin (with one, an absent `egress` makes every internet address
    #: `no_route`).
    trusted_fleet_hosts: Tuple[str, ...] = ()
    fleet_hosts: Tuple[str, ...] = ()
    egress: bool = False
    ingress_quarantine_days: int = INGRESS_QUARANTINE_DAYS_DEFAULT
    #: `min_sender_age_s` (module docstring): the sender-age duration, in
    #: seconds. The ONE runtime source both enforcing paths read.
    min_sender_age_s: int = MIN_SENDER_AGE_S_DEFAULT
    #: The ingress dedup horizon (`router/ingress.py`): a completed entry's
    #: tombstone is kept at least this long. It must exceed the longest time
    #: the downstream runtime can be down after a crash.
    ingress_dedup_horizon_days: int = INGRESS_DEDUP_HORIZON_DAYS_DEFAULT
    #: `delivered_domains_file` (`_delivered_domains`): its path, or None.
    delivered_domains_file: Optional[Path] = None
    #: When the artifact's delivered set differs from `fleet_hosts`: the two
    #: COUNTS (delivered but not in `fleet_hosts`, in `fleet_hosts` but not
    #: delivered). Every bound reply is held while it is set; nothing else is.
    delivered_drift: Optional[Tuple[int, int]] = None
    #: `delegation` (`_delegation`): cross-host signed peer traffic, or None.
    #: What needs the plugin (the key gate, the signing-key probe) is checked
    #: when it is activated (`router/peerlane.py`), at startup and each reload.
    delegation: Optional["DelegationConfig"] = None
    #: PROCESS state, never read from a file: the last reload of the config
    #: failed or was refused (`service.reload_config`), and this is the last
    #: good config kept in its place. While it is set the external leg fails
    #: closed: nothing new is published and no revocation is enacted.
    reload_failed: bool = field(default=False, compare=False)
    #: `peer_sent_prune`: whether preserved signed peer tasks (`peerresend`)
    #: are pruned once settled, unclaimed and past ts + P + F + 7 days. ON by
    #: default (decided 2026-10-14): the copies, attachments included, would
    #: otherwise grow without bound.
    peer_sent_prune: bool = True


@dataclass(frozen=True)
class TransportPluginPin:
    """`transport_plugin` as configured: where the plugin is and what its
    bytes must hash to. Nothing here has looked at the file."""
    path: str
    sha256: str


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}\Z")

#: `hop.caps`'s members, exactly.
HOP_CAPS = ("document", "request", "attachment", "total")
#: The least `hop.caps.attachment` loads: the hop codec's per-sidecar cap.
#: The peer may commit an inbound sidecar of up to that size, and a smaller
#: cap here would refuse it on every read, an entry held for ever; refusing
#: the config turns that into a startup refusal.
HOP_ATTACHMENT_CAP_MIN = 1 << 20
#: The largest `hop.version_write`: the envelope's `hop_contract` is a JSON
#: integer 1..2^31-1, and a larger one would load here and then have every
#: handover refused.
HOP_CONTRACT_MAX = 2 ** 31 - 1


#: The hop codec's link grammar, applied with `fullmatch`.
HOP_LINK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")


@dataclass(frozen=True)
class HopConfig:
    """`hop` as configured (module docstring). `root` is the string exactly
    as written, already checked to be in normal form: it is handed to the
    filesystem port and to the plugin's settings unchanged, so the two can
    never name the tree differently."""
    root: str
    peer_uid: int
    version_write: int
    caps: Tuple[Tuple[str, int], ...]
    #: The inbound reader's link: the journal key's `link` and admission's
    #: comparand. Absent, inbound is
    #: disabled; the outbound leg does not read it.
    link: Optional[str] = None

    def cap(self, name: str) -> int:
        return dict(self.caps)[name]


def _positive_int(value, what: str, *, minimum: int = 1,
                  maximum: Optional[int] = None) -> int:
    if type(value) is not int or value < minimum:
        raise ConfigError(f"{what}: expected an integer >= {minimum}, got {value!r}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{what}: expected an integer <= {maximum}, got {value!r}")
    return value


def agent_reachable_roots(instances: Mapping[str, Any]) -> List[Path]:
    """Every directory an agent can reach, per instance: its root and the
    trees derived from it. The ONE list both the plugin loader (no plugin
    inside one) and `hop.root`'s overlap check (no hop tree inside one, nor
    one inside it) use, so the two cannot drift."""
    roots: List[Path] = []
    for inst in instances.values():
        for p in (inst.root, inst.inbox_root, inst.outbox_root, inst.peer_root):
            if p is not None:
                roots.append(p)
    return roots


def _hop(top: Dict[str, Any], *, transport_plugin, registry_dir: Optional[Path],
         state_dir: Path, intake_dir: Optional[Path], instances,
         attachment_caps: Tuple[int, int, int]) -> Optional[HopConfig]:
    if "hop" not in top:
        if transport_plugin is not None:
            raise ConfigError(
                "config.hop: required with config.transport_plugin (the hop tree the "
                "plugin writes)")
        return None
    if transport_plugin is None:
        raise ConfigError("config.hop: only with config.transport_plugin")
    if registry_dir is None:
        raise ConfigError(
            "config.hop: requires config.registry_dir: a handover names its sender by "
            "logical_id, and generations exist only under a registry")
    raw = _require_object(top["hop"], "config.hop")
    required = {"root", "peer_uid", "version_write", "caps"}
    if not (required <= set(raw) <= required | {"link"}):
        raise ConfigError(
            "config.hop: needs exactly 'root', 'peer_uid', 'version_write' and 'caps', "
            f"and may have 'link'; got {sorted(raw)}")
    link = raw.get("link")
    if "link" in raw and not (isinstance(link, str) and HOP_LINK_RE.fullmatch(link)):
        raise ConfigError(
            f"config.hop.link: {link!r} is not a link name ([a-z0-9][a-z0-9-]{{0,62}})")
    root = raw["root"]
    if not isinstance(root, str) or not os.path.isabs(root):
        raise ConfigError(f"config.hop.root: must be an absolute path, got {root!r}")
    if os.path.normpath(root) != root:
        raise ConfigError(
            f"config.hop.root: {root!r} is not in normal form (a trailing '/', '//', '.' "
            "or '..'); it is used exactly as written, so write it that way")
    rp = Path(root)
    others = [("config.state_dir", state_dir), ("config.registry_dir", registry_dir)]
    if intake_dir is not None:
        others.append(("config.intake_dir", intake_dir))
    for name in sorted(instances):
        for iroot in agent_reachable_roots({name: instances[name]}):
            others.append((f"config.instances.{name}'s agent-reachable directory", iroot))
    for what, other in others:
        if _is_within(rp, other) or _is_within(other, rp):
            raise ConfigError(
                f"config.hop.root ({root}) and {what} ({other}) must not be nested inside "
                "one another")
    peer_uid = _positive_int(raw["peer_uid"], "config.hop.peer_uid", minimum=0)
    version_write = _positive_int(raw["version_write"], "config.hop.version_write",
                                  maximum=HOP_CONTRACT_MAX)
    caps = _require_object(raw["caps"], "config.hop.caps")
    if set(caps) != set(HOP_CAPS):
        raise ConfigError(f"config.hop.caps: needs exactly {list(HOP_CAPS)}; got {sorted(caps)}")
    hop = HopConfig(
        root=root, peer_uid=peer_uid, version_write=version_write,
        caps=tuple((k, _positive_int(caps[k], f"config.hop.caps.{k}")) for k in HOP_CAPS),
        link=link)
    if hop.cap("attachment") < HOP_ATTACHMENT_CAP_MIN:
        raise ConfigError(
            f"config.hop.caps.attachment: {hop.cap('attachment')} is below "
            f"{HOP_ATTACHMENT_CAP_MIN}, the hop's per-sidecar cap: an inbound sidecar the "
            "peer may commit would be refused on every read")
    from .hoplink import document_floor  # local: hoplink is a leaf, kept out of load order
    count_cap, file_cap, total_cap = attachment_caps
    floor = document_floor(
        request_cap=hop.cap("request"), count_cap=count_cap,
        file_cap=min(hop.cap("attachment"), file_cap),
        total_cap=min(hop.cap("total"), total_cap), version_write=version_write)
    if hop.cap("document") < floor:
        raise ConfigError(
            f"config.hop.caps.document: {hop.cap('document')} is below {floor}, the largest "
            "handover an accepted request can make (the request cap less its newline, the "
            "largest attachment array the attachment caps admit, and the fixed members)")
    return hop


def _transport_plugin(top: Dict[str, Any]) -> Optional[TransportPluginPin]:
    if "transport_plugin" not in top:
        return None
    raw = top["transport_plugin"]
    if not isinstance(raw, dict):
        raise ConfigError("config.transport_plugin: expected an object {path, sha256}")
    keys = set(raw)
    if keys != {"path", "sha256"}:
        raise ConfigError(
            "config.transport_plugin: needs exactly 'path' and 'sha256', both or "
            f"neither; got {sorted(keys)}")
    # Checked absolute, but kept EXACTLY as written: the normalised path
    # `_require_absolute` returns is a different path when a component is a
    # symlink, and the loader is the one place a non-canonical plugin path
    # is refused (`transport`, step 1). So the pin is never rewritten here.
    _require_absolute(raw["path"], "config.transport_plugin.path")
    path = raw["path"]
    sha = raw["sha256"]
    if not (isinstance(sha, str) and _SHA256_HEX_RE.fullmatch(sha)):
        raise ConfigError("config.transport_plugin.sha256: expected 64 lowercase hex digits")
    return TransportPluginPin(path=str(path), sha256=sha)


class StateKeyUnresolved(LookupError):
    """Under a registry, `name` has no resolved state key (the registry holds
    it), so nothing may be read or written for it under `state_dir`."""


def state_key(cfg: "RouterConfig", name: str) -> str:
    """The directory under `cfg.state_dir` holding `name`'s private state.
    Every `state_dir/<instance>` join in the package goes through this.

    Without a registry: the instance's own name. Under a registry: its
    logical_id as this poll resolved it, and NOTHING ELSE. A held instance
    has no key, and this raises `StateKeyUnresolved` rather than fall back
    to the name: a name directory written under a registry becomes a
    `state_conflict`, strands what was written there, and for a name like
    `status.json` would replace a file this router owns."""
    key = cfg.state_keys.get(name)
    if key is not None:
        return key
    if cfg.registry_dir is not None:
        raise StateKeyUnresolved(
            f"{name!r} has no resolved state key under the registry (held); "
            "no state is read or written for it")
    return name


#: `target_hold`'s reason when a registry is configured but no report was
#: attached to this config: nothing may be delivered on a guess.
HELD_REPORT_MISSING = "registry_report_missing"


def target_hold(cfg: "RouterConfig", name: str) -> Optional[str]:
    """Why a LOCAL delivery to instance `name` must hold this poll, or None.

    Without a registry: always None (nothing changes). Under one: None only
    when THIS POLL's report (`cfg.registry_report`) resolved `name`;
    otherwise the report's hold reason for it. A registry with no report
    attached fails closed (`HELD_REPORT_MISSING`). Every local placement
    path, and every recovery of one, asks this before it reads or writes
    anything on the recipient's side."""
    if cfg.registry_dir is None:
        return None
    report = cfg.registry_report
    if report is None:
        return HELD_REPORT_MISSING
    if name not in (report.resolved or {}):
        return (report.held or {}).get(name, "not_registered")
    # Resolved: its current generation must still vouch for the root a
    # placement would write through (router/generations.py).
    # A root replaced since the poll's pre-pass holds here, BEFORE anything
    # is placed, so the request goes pending instead of failing.
    from . import generations as generations_mod
    try:
        expected = generations_mod.expected_root(cfg, name)
        if expected is None:
            return None
        seen = generations_mod.root_identity(cfg.instances[name].root)
    except (LookupError, generations_mod.GenerationHeld):
        return generations_mod.HELD_RECIPIENT_UNRESOLVED
    if (seen["st_dev"], seen["st_ino"]) != expected:
        return generations_mod.HELD_RECIPIENT_ROOT
    return None


def target_logical_id(cfg: "RouterConfig", name: str) -> Optional[str]:
    """`name`'s logical_id in this poll's report, or None (no registry, no
    report, or not resolved)."""
    report = cfg.registry_report
    if cfg.registry_dir is None or report is None:
        return None
    entry = (report.resolved or {}).get(name)
    return entry.logical_id if entry is not None else None


def target_known_id(cfg: "RouterConfig", name: str) -> Optional[str]:
    """`name`'s logical_id as this poll's report KNOWS it, held or not, or
    None when the registry has no single active entry for it. A pending
    delivery pins this, so a later rebind of the name to another identity
    holds instead of rerouting; only a truly unknown identity is bound at
    its first resolution."""
    report = cfg.registry_report
    if cfg.registry_dir is None or report is None:
        return None
    return (getattr(report, "known", None) or {}).get(name) or target_logical_id(cfg, name)


def instance_state_dir(cfg: "RouterConfig", name: str) -> Path:
    """`state_dir/<state_key>`: where `name`'s PER-IDENTITY private state
    lives (ledgers, audit, outcomes, DSN intents)."""
    return cfg.state_dir / state_key(cfg, name)


def gen_key(cfg: "RouterConfig", name: str) -> str:
    """The directory, relative to `cfg.state_dir`, holding `name`'s
    GENERATION-scoped state: anchors, in-flight records and the transport
    counter, pending deliveries, quarantine, held copies and the
    first-sight marker (`router/generations.py`).

    Without a registry: the instance's own name, exactly as before. Under a
    registry: its current generation as THIS POLL's pre-pass resolved it,
    and nothing else; an instance without one raises `StateKeyUnresolved`
    (it is held), never falling back to the logical_id or the name."""
    if name == RUNTIME_NS:
        return f"{RUNTIME_NS}/{runtime_generation(cfg)}"
    key = cfg.gen_keys.get(name)
    if key is not None:
        return key
    if cfg.registry_dir is not None:
        raise StateKeyUnresolved(
            f"{name!r} has no current generation this poll (held); no generation "
            "state is read or written for it")
    return name


def runtime_generation(cfg: "RouterConfig") -> str:
    """The runtime control namespace's one generation, as recorded at
    `state_dir/_runtime/generation.json` (`peercontrol` mints and records
    it); `StateKeyUnresolved` when none is recorded or it cannot be read."""
    path = Path(cfg.state_dir) / RUNTIME_NS / RUNTIME_GENERATION_FILE
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise StateKeyUnresolved("the runtime control namespace has no recorded generation") from None
    gen = doc.get("generation") if isinstance(doc, dict) else None
    if not (isinstance(gen, str) and len(gen) == 32
            and all(c in "0123456789abcdef" for c in gen)):
        raise StateKeyUnresolved("the runtime control namespace's generation is not 32 hex")
    return gen


def gen_state_dir(cfg: "RouterConfig", name: str) -> Path:
    """`state_dir/<gen_key>`: where `name`'s generation-scoped state lives."""
    return cfg.state_dir / gen_key(cfg, name)


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
    router never authors a message on the legacy addressing scheme.

    THE ONE construction of this router's own address, in canonical form: the
    domain ASCII-lowercased, so every surface that names this router (the
    runtime identity, a control notice's `from` and its envelope's
    `from_address`, a DSN's `from`, `sender_exposure.asserted_by`, and the
    receive side's check of a control notice's `to`) carries the same bytes.
    `load` already refuses a fleet domain that is not lowercase; this holds
    for a config built any other way too."""
    if not fleet_domain:
        return None
    domain = fleet_domain.lower() if fleet_domain.isascii() else fleet_domain
    return f"{ROUTER_LOCAL_PART}@{domain}"


def router_runtime(fleet_domain: Optional[str]) -> str:
    """`router_address`, or, without a fleet domain, the bare local part and
    its `@` (the own-key gate's runtime name when no domain is configured)."""
    return router_address(fleet_domain) or f"{ROUTER_LOCAL_PART}@"


_ADDR_RE = re.compile(r"agent\.([A-Za-z0-9][A-Za-z0-9._-]{0,63})@local\Z")


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
        m = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9._-]{0,63})@" + re.escape(fleet_domain) + r"\Z",
            candidate,
        )
    else:
        m = _ADDR_RE.fullmatch(candidate)
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
    instances_dir: Path, selected_json: Path, state_dir: Path, registry: bool = False,
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
        if not _NAME_RE.fullmatch(slug):
            skipped[slug] = "name is not a valid instance name"
            continue
        if slug.casefold() == ROUTER_LOCAL_PART.casefold():
            skipped[slug] = "this router's own address local-part"
            continue
        if slug.casefold() in RESERVED_STATE_NAMES:
            skipped[slug] = "the name of an entry this router keeps in state_dir"
            continue
        if registry and ID_SHAPED_NAME_RE.fullmatch(slug):
            # Under a registry the host keys its own per-identity directories
            # by logical_id, so a 32-hex directory here is one of those, not a
            # sandbox slug (and could not be one: the registry refuses to issue
            # that shape as a name).
            skipped[slug] = "shaped like a logical_id; under a registry that is not a slug"
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
            instances_dir, selected_json, state_dir, registry="registry_dir" in top)
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
        if not isinstance(fd, str) or not _FLEET_DOMAIN_RE.fullmatch(fd):
            raise ConfigError(
                f"config.fleet_domain: expected a bare, lowercase domain label "
                f"sequence such as 'example.invalid', got {fd!r}"
            )
        fleet_domain = fd

    peer_sent_prune = top.get("peer_sent_prune", True)
    if type(peer_sent_prune) is not bool:
        raise ConfigError("config.peer_sent_prune: true or false")
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
    mail_reply_window_seconds = _positive_int(
        "mail_reply_window_seconds", MAIL_REPLY_WINDOW_SECONDS_DEFAULT
    )
    if mail_reply_window_seconds > MAIL_REPLY_WINDOW_SECONDS_MAX:
        raise ConfigError(
            f"config.mail_reply_window_seconds: at most {MAIL_REPLY_WINDOW_SECONDS_MAX} "
            f"(90 days), got {mail_reply_window_seconds}")

    # Pass 1: shape + name + root (mode/root_key/root), per instance (peers
    # resolved in pass 2 so an unknown-peer error can name the actual set
    # of known instances).
    roots: Dict[str, Tuple[str, str, Path]] = {}  # name -> (mode, root_key, root)
    peers_raw: Dict[str, List[str]] = {}
    peer_senders_raw: Dict[str, List[str]] = {}
    extras: Dict[str, Dict[str, Any]] = {}  # name -> caller-validated extra keys
    classify_raw: Dict[str, Dict[str, Any]] = {}  # name -> task_deny/send_to/remote_fleet
    for name, spec in instances_raw.items():
        if not _NAME_RE.fullmatch(name):
            raise ConfigError(
                f"config.instances: instance name {name!r} must match "
                f"^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$ — sandy's slug alphabet, "
                f"because the slug IS the instance name (it is also the address "
                f"local-part and a directory under state_dir)"
            )
        if name.casefold() in RESERVED_STATE_NAMES:
            raise ConfigError(
                f"config.instances: {name!r} is the name of an entry this router "
                f"keeps directly under state_dir ({sorted(RESERVED_STATE_NAMES)}), and "
                f"an instance's private state lives there too; rename the instance")
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
        classify_raw[name] = {k: spec_obj[k] for k in _CLASSIFY_INSTANCE_KEYS
                              if k in spec_obj}

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

    outcome_ids = _connector_outcome_ids(top)
    transport_plugin = _transport_plugin(top)
    registry_dir: Optional[Path] = None
    if "registry_dir" in top:
        registry_dir = _require_absolute(top["registry_dir"], "config.registry_dir")
        if _is_within(registry_dir, state_dir) or _is_within(state_dir, registry_dir):
            raise ConfigError(
                f"config.registry_dir ({registry_dir}) and config.state_dir ({state_dir}) "
                "must not be nested inside one another")
        for name, (_mode, root_key, root) in roots.items():
            if _is_within(registry_dir, root) or _is_within(root, registry_dir):
                raise ConfigError(
                    f"config.registry_dir ({registry_dir}) and config.instances.{name}."
                    f"{root_key} ({root}) must not be nested inside one another: an "
                    "agent-reachable registry would let an agent choose identities")
        shaped = sorted(n for n in instances if ID_SHAPED_NAME_RE.fullmatch(n))
        if shaped:
            raise ConfigError(
                f"config.registry_dir: instance name(s) {shaped} are shaped like a "
                "logical_id (32 hex digits). Under a registry private state lives at "
                "state_dir/<logical_id>/, so such a name cannot be told from an "
                "identity's state; rename the instance")
    hop = _hop(top, transport_plugin=transport_plugin, registry_dir=registry_dir,
               state_dir=state_dir, intake_dir=intake_dir, instances=instances,
               attachment_caps=(attachment_max_count, attachment_max_bytes,
                                attachment_max_total_bytes))
    if hop is not None:
        # Every handover's envelope carries its instance's address as
        # `from_address`, and the document floor assumes it is at most 254
        # octets: an instance whose address cannot be one is refused here, by
        # the same check begin runs (`hoplink.from_address_problem`).
        from .hoplink import from_address_problem  # local, as `_hop`'s
        for name in sorted(roots):
            why = from_address_problem(address_for(name, fleet_domain))
            if why is not None:
                raise ConfigError(
                    f"config.instances.{name}: its address "
                    f"{address_for(name, fleet_domain)!r} cannot be a handover's "
                    f"from_address ({why})")


    trusted, fleet_hosts, egress, per_instance = _classification(
        top, fleet_domain, classify_raw)
    for name, values in per_instance.items():
        instances[name] = replace(instances[name], **values)

    cfg = RouterConfig(
        state_dir=state_dir, instances=instances, connector_outcome_ids=tuple(outcome_ids),
        trusted_fleet_hosts=trusted, fleet_hosts=fleet_hosts, egress=egress,
        ingress_quarantine_days=_ingress_quarantine_days(top),
        min_sender_age_s=_min_sender_age_s(top),
        ingress_dedup_horizon_days=_days(top, "ingress_dedup_horizon_days",
                                         INGRESS_DEDUP_HORIZON_DAYS_DEFAULT,
                                         INGRESS_DEDUP_HORIZON_DAYS_MAX),
        attachment_max_bytes=attachment_max_bytes,
        attachment_max_count=attachment_max_count,
        attachment_max_total_bytes=attachment_max_total_bytes,
        fleet_domain=fleet_domain, intake_dir=intake_dir, peer_sent_prune=peer_sent_prune,
        sender_exposure_window_seconds=sender_exposure_window_seconds,
        peer_reply_window_seconds=peer_reply_window_seconds,
        mail_reply_window_seconds=mail_reply_window_seconds,
        discovery=(replace(discovery, inert_edges=inert)
                   if discovery is not None else None),
        selected_json=selected_json,
        transport_plugin=transport_plugin,
        registry_dir=registry_dir,
        hop=hop,
        aliases=_aliases(top, registry_dir, fleet_domain),
    )
    if "delegation" in top:
        cfg = replace(cfg, delegation=_delegation(top["delegation"], cfg))
    if "delivered_domains_file" in top:
        artifact = _require_absolute(top["delivered_domains_file"],
                                     "config.delivered_domains_file")
        for root in agent_reachable_roots(instances):
            if _is_within(artifact, root):
                raise ConfigError(
                    f"config.delivered_domains_file ({artifact}) is inside {root}, which "
                    "an agent can reach")
        cfg = replace(cfg, delivered_domains_file=artifact,
                      delivered_drift=_delivered_domains(artifact, fleet_hosts))

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


logger = logging.getLogger("amap_router_local.config")

#: The largest delivered-domain artifact read; a larger one is refused unread.
DELIVERED_DOMAINS_MAX_BYTES = 1 << 20


def _delivered_domains_uids() -> Tuple[int, ...]:
    """Who may own the delivered-domain artifact: root, or this process."""
    return (0, os.geteuid())


def delivered_domains_hash(domains: Iterable[str]) -> str:
    """The artifact's `sha256`: the hex digest of its domains lowercased,
    sorted, each followed by a newline."""
    text = "".join(d + "\n" for d in sorted(d.lower() for d in domains))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _delivered_domains(path: Path, fleet_hosts: Iterable[str]) -> Optional[Tuple[int, int]]:
    """Read the delivered-domain artifact the hub link delivers to, and
    compare its set with `fleet_hosts`. The artifact is the deployment's:
    `{"delivered_domains": [...], "sha256": delivered_domains_hash(...), "attestation":
    {...}}`, and `attestation` is not read. PROVISIONAL: the deployment's
    layout for it is not yet frozen.

    Refused (`ConfigError`): a path that is a symlink, not a regular file,
    owned by anyone but root or this process, writable by group or others,
    over `DELIVERED_DOMAINS_MAX_BYTES`, not the JSON object above, or whose hash
    does not match its own domains. A set that differs is NOT a refusal:
    mail keeps flowing, every bound reply is held, and the counts are
    returned (None when the sets agree) and logged as an ERROR, never the
    domains."""
    where = f"config.delivered_domains_file ({path})"
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        why = "is a symlink" if e.errno == errno.ELOOP else (e.strerror or str(e))
        raise ConfigError(f"{where}: {why}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{where}: not a regular file")
        if st.st_uid not in _delivered_domains_uids():
            raise ConfigError(f"{where}: owned by uid {st.st_uid}, not root or this process")
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise ConfigError(f"{where}: writable by group or others "
                              f"(mode {oct(stat.S_IMODE(st.st_mode))})")
        raw = os.read(fd, DELIVERED_DOMAINS_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > DELIVERED_DOMAINS_MAX_BYTES:
        raise ConfigError(f"{where}: over {DELIVERED_DOMAINS_MAX_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ConfigError(f"{where}: not JSON ({e})") from None
    domains = doc.get("delivered_domains") if isinstance(doc, dict) else None
    if not (isinstance(domains, list) and all(isinstance(d, str) and d for d in domains)):
        raise ConfigError(f"{where}: delivered_domains is not a list of non-empty strings")
    claimed = doc.get("sha256")
    if not (isinstance(claimed, str) and _SHA256_HEX_RE.fullmatch(claimed)):
        raise ConfigError(f"{where}: sha256 is not 64 lowercase hex")
    if delivered_domains_hash(domains) != claimed:
        raise ConfigError(f"{where}: sha256 does not match its delivered_domains")
    delivered = {d.lower() for d in domains}
    ours = {h.lower() for h in fleet_hosts}
    if delivered == ours:
        return None
    drift = (len(delivered - ours), len(ours - delivered))
    logger.error(
        "%s: the delivered-domain set differs from config.fleet_hosts (%d delivered "
        "but not a fleet host, %d fleet hosts not delivered); every bound reply is "
        "held until they agree, and mail is unaffected", where, *drift)
    return drift


@dataclass(frozen=True)
class DelegationRuntime:
    """One configured peer runtime (`delegation.runtimes[]`): its name, its
    runtime address, its domains and its keys, as written (each key a
    mapping of `key_id`, `public_key` and optional `not_before` /
    `not_after`). The key gate is the plugin's, at activation."""
    name: str
    runtime: str
    domains: Tuple[str, ...]
    keys: Tuple[Mapping[str, str], ...]


@dataclass(frozen=True)
class DelegationConfig:
    """`delegation` as configured (`_delegation`)."""
    partition_verified: str
    signing_key_path: str
    signing_key_id: str
    signing_public_key: str
    runtimes: Tuple[DelegationRuntime, ...]
    crypto_backend: str
    openssl_path: Optional[str] = None
    #: Every directory the signing key must not be inside: as configured and
    #: as resolved (realpath) at load, compared by path components.
    forbidden_roots: Tuple[str, ...] = ()
    #: The deployment's basis for asserting `clean` on a signed peer task's
    #: attachments: None (absent: every one is `unscanned`, no bytes) or
    #: `ATTACHMENT_BASIS_CLOSED_FLEET`. A signature is never the basis.
    attachment_basis: Optional[str] = None
    #: Inbound peer intake: taking signed candidates at all. Opt-in per
    #: host, False when absent; only with it does a poll run the inbound pass.
    inbound: bool = False
    #: The receiver's window: P (past) and F (future skew), in seconds.
    window_p: int = 3600
    window_f: int = 300
    #: The candidate journal's retention sweeper; off unless configured.
    retention_sweep: bool = False

    def crypto_settings(self) -> Dict[str, str]:
        """The signer's and verifier's settings, exactly."""
        out = {"crypto_backend": self.crypto_backend}
        if self.openssl_path is not None:
            out["openssl_path"] = self.openssl_path
        return out

    def key_table_input(self) -> List[Dict[str, Any]]:
        """The peer table in the shape the plugin's key gate takes."""
        return [{"name": r.name, "runtime": r.runtime, "domains": list(r.domains),
                 "keys": [dict(k) for k in r.keys]} for r in self.runtimes]


_DELEGATION_KEYS = frozenset({"partition_verified", "signing_key", "runtimes", "crypto"})
_DELEGATION_OPTIONAL = frozenset({"attachment_basis", "inbound", "windows", "retention"})
#: Any delegation key naming the exposure or sender-age overlay: refused. The
#: top-level `min_sender_age_s` is the ONLY configuration that may change the
#: sender-age duration, and nothing may weaken the exposure policy (contract
#: §8.8, consequential to E30).
_OVERLAY_TOKENS = ("exposure", "sender_age", "sender_since", "age_policy", "min_age",
                   "quarantine")
#: The peer-origin profile's window bounds: P in [300, 86400], F at most 900.
WINDOW_P_BOUNDS, WINDOW_F_MAX = (300, 86400), 900
#: `delegation.attachment_basis`'s one value: every trusted fleet host is
#: operator-supervised and no external sender reaches the peer lane.
ATTACHMENT_BASIS_CLOSED_FLEET = "closed_fleet"
_SIGNING_KEY_KEYS = frozenset({"path", "key_id", "public_key"})
_RUNTIME_KEYS = frozenset({"name", "runtime", "domains", "keys"})
_PEER_KEY_REQUIRED = frozenset({"key_id", "public_key"})
_PEER_KEY_OPTIONAL = frozenset({"not_before", "not_after"})
_HEX64_LOWER_RE = re.compile(r"[0-9a-f]{64}\Z")
CRYPTO_BACKENDS = ("pyca", "openssl")


def _normal_form_problem(path: Any) -> Optional[str]:
    """Why `path` is not an absolute path in normal form, or None: no empty,
    `.` or `..` component, no repeated or trailing `/`."""
    if not isinstance(path, str) or not path:
        return "not a non-empty string"
    if not os.path.isabs(path):
        return "not absolute"
    if path != "/" and (path.endswith("/") or "//" in path):
        return "a repeated or trailing '/'"
    if any(c in (".", "..") for c in path.split("/")[1:]):
        return "a '.' or '..' component"
    if os.path.normpath(path) != path:
        return "not in normal form"
    return None


def _components_within(path: str, root: str) -> bool:
    """`path` is `root` or inside it, compared by path COMPONENTS."""
    p, r = Path(path).parts, Path(root).parts
    return len(p) >= len(r) and p[:len(r)] == r


def _delegation(raw_value: Any, cfg: "RouterConfig") -> "DelegationConfig":
    """`delegation` (module docstring). Everything here is lexical: the key
    file is opened, walked and proved at activation, not at load."""
    where = "config.delegation"
    if cfg.transport_plugin is None or cfg.hop is None:
        raise ConfigError(f"{where}: requires config.transport_plugin and config.hop: "
                          "a signed peer task travels over the hop")
    raw = _require_object(raw_value, where)
    overlays = sorted(k for k in raw if isinstance(k, str) and any(
        t in k.lower() for t in _OVERLAY_TOKENS))
    if overlays:
        raise ConfigError(f"{where}: {overlays}: the exposure and sender-age policy is not "
                          "configurable here; the sender-age duration is set only by the "
                          "top-level min_sender_age_s")
    if not (_DELEGATION_KEYS <= set(raw) <= _DELEGATION_KEYS | _DELEGATION_OPTIONAL):
        raise ConfigError(f"{where}: needs exactly {sorted(_DELEGATION_KEYS)}, and may have "
                          f"{sorted(_DELEGATION_OPTIONAL)}; got {sorted(raw)}")
    basis = raw.get("attachment_basis")
    if "attachment_basis" in raw and basis != ATTACHMENT_BASIS_CLOSED_FLEET:
        raise ConfigError(f"{where}.attachment_basis: absent, or "
                          f"{ATTACHMENT_BASIS_CLOSED_FLEET!r}; got {basis!r}")
    partition = raw["partition_verified"]
    if not (isinstance(partition, str) and partition.strip()):
        raise ConfigError(f"{where}.partition_verified: the deploy's partition evidence is "
                          "required (a non-empty string); without it delegation is refused")
    sk = _require_object(raw["signing_key"], f"{where}.signing_key")
    if set(sk) != _SIGNING_KEY_KEYS:
        raise ConfigError(f"{where}.signing_key: needs exactly {sorted(_SIGNING_KEY_KEYS)}; "
                          f"got {sorted(sk)}")
    why = _normal_form_problem(sk["path"])
    if why is not None:
        raise ConfigError(f"{where}.signing_key.path: {why}")
    if not isinstance(sk["key_id"], str) or not sk["key_id"]:
        raise ConfigError(f"{where}.signing_key.key_id: expected a non-empty string")
    if not (isinstance(sk["public_key"], str) and _HEX64_LOWER_RE.fullmatch(sk["public_key"])):
        raise ConfigError(f"{where}.signing_key.public_key: expected 64 lower-case hex digits")
    lexical = [str(cfg.state_dir), cfg.hop.root]
    lexical += [str(r) for r in agent_reachable_roots(cfg.instances)]
    if cfg.registry_dir is not None:
        lexical.append(str(cfg.registry_dir))
    if cfg.intake_dir is not None:
        lexical.append(str(cfg.intake_dir))
    roots = tuple(sorted(set(lexical) | {os.path.realpath(r) for r in lexical}))
    for root in roots:
        if _components_within(sk["path"], root):
            raise ConfigError(f"{where}.signing_key.path ({sk['path']}) is inside {root}, "
                              "which the signing key must stay outside")
    from . import classify as classify_mod  # local: classify imports this module
    runtimes = raw["runtimes"]
    if not isinstance(runtimes, list):
        raise ConfigError(f"{where}.runtimes: expected an array")
    own = cfg.fleet_domain or ""
    trusted = set(cfg.trusted_fleet_hosts)
    parsed = []
    owner: Dict[str, str] = {}      # domain -> the runtime that lists it
    for i, r in enumerate(runtimes):
        rw = f"{where}.runtimes[{i}]"
        if not isinstance(r, dict) or set(r) != _RUNTIME_KEYS:
            raise ConfigError(f"{rw}: needs exactly {sorted(_RUNTIME_KEYS)} (key_malformed)")
        if not isinstance(r["name"], str) or not _NAME_RE.fullmatch(r["name"]):
            raise ConfigError(f"{rw}.name: not a name (key_malformed)")
        domains = _canonical_list(r["domains"], f"{rw}.domains", classify_mod.canonical_host)
        if not domains:
            raise ConfigError(f"{rw}.domains: at least one domain")
        for d in domains:
            if d == own:
                raise ConfigError(f"{rw}.domains: names this router's own domain {own!r}")
            if d not in trusted:
                raise ConfigError(f"{rw}.domains: {d!r} is not in config.trusted_fleet_hosts; "
                                  "a runtime this router verifies for is a trusted fleet host")
            # A peer domain belongs to exactly one configured runtime: a key
            # vouches only for its own runtime's domains, so a domain two
            # runtimes list would let either one's key speak for it.
            if d in owner:
                raise ConfigError(f"{rw}.domains: {d!r} is also listed by runtime "
                                  f"{owner[d]!r}; a peer domain belongs to exactly one runtime "
                                  "(domain_shared)")
            owner[d] = r["name"]
        rt = r["runtime"]
        if not (isinstance(rt, str) and rt.startswith(ROUTER_LOCAL_PART + "@")
                and rt.split("@", 1)[1] in domains):
            raise ConfigError(f"{rw}.runtime: must be {ROUTER_LOCAL_PART}@<one of its domains>")
        keys = r["keys"]
        if not isinstance(keys, list):
            raise ConfigError(f"{rw}.keys: expected an array (key_malformed)")
        kept = []
        for j, k in enumerate(keys):
            if not (isinstance(k, dict) and _PEER_KEY_REQUIRED <= set(k)
                    <= _PEER_KEY_REQUIRED | _PEER_KEY_OPTIONAL
                    and all(isinstance(v, str) for v in k.values())):
                raise ConfigError(f"{rw}.keys[{j}]: needs key_id and public_key, and may have "
                                  "not_before and not_after, all strings (key_malformed)")
            kept.append(MappingProxyType(dict(k)))
        parsed.append(DelegationRuntime(name=r["name"], runtime=rt, domains=domains,
                                        keys=tuple(kept)))
    crypto = _require_object(raw["crypto"], f"{where}.crypto")
    if not ({"crypto_backend"} <= set(crypto) <= {"crypto_backend", "openssl_path"}):
        raise ConfigError(f"{where}.crypto: needs crypto_backend, and may have openssl_path")
    backend = crypto["crypto_backend"]
    if backend not in CRYPTO_BACKENDS:
        raise ConfigError(f"{where}.crypto.crypto_backend: one of {list(CRYPTO_BACKENDS)}")
    openssl = crypto.get("openssl_path")
    if backend == "openssl" or openssl is not None:
        why = _normal_form_problem(openssl)
        if why is not None:
            raise ConfigError(f"{where}.crypto.openssl_path: {why}")
    inbound = raw.get("inbound", False)
    if type(inbound) is not bool:
        raise ConfigError(f"{where}.inbound: absent, or true or false")
    window_p, window_f = 3600, 300
    if "windows" in raw:
        win = _require_object(raw["windows"], f"{where}.windows")
        if set(win) != {"p", "f"} or not all(type(win[k]) is int for k in ("p", "f")):
            raise ConfigError(f"{where}.windows: needs exactly p and f, integers (seconds)")
        if not (WINDOW_P_BOUNDS[0] <= win["p"] <= WINDOW_P_BOUNDS[1]
                and 0 <= win["f"] <= WINDOW_F_MAX):
            raise ConfigError(f"{where}.windows: p in {list(WINDOW_P_BOUNDS)} and f in "
                              f"[0, {WINDOW_F_MAX}], the profile's bounds")
        window_p, window_f = win["p"], win["f"]
    sweep = False
    if "retention" in raw:
        ret = _require_object(raw["retention"], f"{where}.retention")
        if set(ret) != {"sweep"} or type(ret["sweep"]) is not bool:
            raise ConfigError(f"{where}.retention: needs exactly sweep, true or false")
        sweep = ret["sweep"]
        if sweep and not _peer_store_present(cfg.state_dir):
            raise ConfigError(f"{where}.retention.sweep: refused while the peer store has no "
                              "settled-through frontier (run `router peer-store init` first)")
    return DelegationConfig(
        partition_verified=partition, signing_key_path=sk["path"], signing_key_id=sk["key_id"],
        signing_public_key=sk["public_key"], runtimes=tuple(parsed), crypto_backend=backend,
        openssl_path=openssl, forbidden_roots=roots, attachment_basis=basis, inbound=inbound,
        window_p=window_p, window_f=window_f, retention_sweep=sweep)


def _peer_store_present(state_dir: Path) -> bool:
    """Whether `peer-clock.json` carries the candidate journal's bookkeeping
    (its settled-through frontier among it). Read only to gate the sweep."""
    try:
        doc = json.loads((Path(state_dir) / "peer-clock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and isinstance(doc.get("store"), dict)


_CLASSIFY_INSTANCE_KEYS = ("task_deny", "send_to", "remote_fleet")


def _days(top: Dict[str, Any], key: str, default: int, maximum: int) -> int:
    if key not in top:
        return default
    v = top[key]
    if isinstance(v, bool) or not isinstance(v, int) or not (1 <= v <= maximum):
        raise ConfigError(f"config.{key}: expected an integer from 1 to {maximum}, got {v!r}")
    return v


def _min_sender_age_s(top: Dict[str, Any]) -> int:
    """`min_sender_age_s`: absent is the default; otherwise an exact int from
    0 to the maximum. A bool is refused BEFORE the int test (a bool is an
    int in Python), and so is every float, integral or not: the contract
    says a whole number of seconds, and `86400.0` is a different JSON
    value."""
    if "min_sender_age_s" not in top:
        return MIN_SENDER_AGE_S_DEFAULT
    v = top["min_sender_age_s"]
    if isinstance(v, bool) or type(v) is not int or not (0 <= v <= MIN_SENDER_AGE_S_MAX):
        raise ConfigError(
            f"config.min_sender_age_s: expected an integer from 0 to "
            f"{MIN_SENDER_AGE_S_MAX}, got {v!r}")
    return v


def sender_age_policy(value: int) -> Dict[str, Any]:
    """The canonical sender-age policy object for `value` (D2, contract §8.6
    as amended by E30): the fleet artifact's content."""
    return {"v": SENDER_AGE_POLICY_VERSION, "min_sender_age_s": value}


def sender_age_policy_digest(value: int) -> str:
    """`"sha256:" + hex` of the canonical sender-age policy object, in the
    pinned canonical form of the policy digest (`classify`'s module
    docstring). A pure function of `value`: each router reports the digest
    of the value it ENFORCES, and the fleet artifact carries the same
    bytes, so equality of digests is equality of values in a form a receipt
    can record. Known answers: `tests/vectors/sender_age_policy_digest.json`."""
    text = json.dumps(sender_age_policy(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ingress_quarantine_days(top: Dict[str, Any]) -> int:
    if "ingress_quarantine_days" not in top:
        return INGRESS_QUARANTINE_DAYS_DEFAULT
    v = top["ingress_quarantine_days"]
    if isinstance(v, bool) or not isinstance(v, int) or not (
            1 <= v <= INGRESS_QUARANTINE_DAYS_MAX):
        raise ConfigError(
            f"config.ingress_quarantine_days: expected an integer from 1 to "
            f"{INGRESS_QUARANTINE_DAYS_MAX}, got {v!r}")
    return v


def _canonical_list(value: Any, where: str, canon) -> Tuple[str, ...]:
    """A list of strings, each canonical per `canon`, no two the same after
    canonicalisation. Returned canonical and sorted."""
    from . import classify as classify_mod  # local: classify imports this module
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: expected an array of strings")
    try:
        dups = classify_mod.duplicates(value, canon)
        out = tuple(sorted({canon(v) for v in value}))
    except classify_mod.Malformed as e:
        raise ConfigError(f"{where}: {e}") from None
    if dups:
        raise ConfigError(f"{where}: duplicate entries after canonicalisation: {dups}")
    return out


def _classification(
    top: Dict[str, Any], fleet_domain: Optional[str], raw: Dict[str, Dict[str, Any]],
) -> Tuple[Tuple[str, ...], Tuple[str, ...], bool, Dict[str, Dict[str, Tuple[str, ...]]]]:
    """The cross-host classification inputs (`router/classify.py`), checked
    with the same canonicaliser the policy digest uses. Every refusal here
    stops startup: a config this router cannot classify under is not run on
    a guess."""
    from . import classify as classify_mod  # local: classify imports this module
    hosts = classify_mod.canonical_host
    entries = classify_mod.canonical_entry
    trusted = _canonical_list(top.get("trusted_fleet_hosts", []),
                              "config.trusted_fleet_hosts", hosts)
    fleet = _canonical_list(top.get("fleet_hosts", []), "config.fleet_hosts", hosts)
    own = fleet_domain or classify_mod.LEGACY_DOMAIN
    for key, values in (("trusted_fleet_hosts", trusted), ("fleet_hosts", fleet)):
        if own in values:
            raise ConfigError(
                f"config.{key}: names this router's own domain {own!r}; its "
                "addresses are local, never a fleet host's")
    missing = sorted(set(trusted) - set(fleet))
    if missing:
        raise ConfigError(
            f"config.trusted_fleet_hosts: {missing} not in config.fleet_hosts; every "
            "trusted host is a fleet host")
    egress = top.get("egress", False)
    if not isinstance(egress, bool):
        raise ConfigError(f"config.egress: expected true or false, got {egress!r}")

    per: Dict[str, Dict[str, Tuple[str, ...]]] = {}
    for name, spec in raw.items():
        where = f"config.instances.{name}"
        values: Dict[str, Tuple[str, ...]] = {}
        if "task_deny" in spec:
            deny = _canonical_list(spec["task_deny"], f"{where}.task_deny", entries)
            outside = [e for e in deny if classify_mod.entry_domain(e) not in trusted]
            if outside:
                raise ConfigError(
                    f"{where}.task_deny: {outside} not at a trusted fleet host; "
                    "task_deny only removes trusted-host edges")
            values["task_deny"] = deny
        if "send_to" in spec:
            send_to = _canonical_list(spec["send_to"], f"{where}.send_to", entries)
            named = [e for e in send_to if classify_mod.entry_domain(e) in trusted]
            if named:
                raise ConfigError(
                    f"{where}.send_to: {named} name a trusted fleet host, which is "
                    "reached only on the peer lane")
            values["send_to"] = send_to
        if "remote_fleet" in spec:
            remote = _canonical_list(spec["remote_fleet"], f"{where}.remote_fleet", hosts)
            named = [h for h in remote if h in trusted]
            if named:
                raise ConfigError(
                    f"{where}.remote_fleet: {named} are trusted fleet hosts, which "
                    "are reached only on the peer lane")
            unknown = [h for h in remote if h not in fleet]
            if unknown:
                raise ConfigError(
                    f"{where}.remote_fleet: {unknown} not in config.fleet_hosts")
            values["remote_fleet"] = remote
        if values:
            per[name] = values
    return trusted, fleet, egress, per


@dataclass(frozen=True)
class AliasEntry:
    """One row of the alias table: exact `old` address, canonical `new`
    address (`<name>@<fleet_domain>`), and when it stops (`expires`, a UTC
    timestamp string as written)."""
    old: str
    new: str
    expires: str


_ALIAS_KEYS = frozenset({"old", "new", "expires"})


def _alias_parts(addr: Any, where: str) -> Tuple[str, str]:
    """`(local, domain)` of an exact, normalised address: the local part a
    valid instance name (ASCII, `_NAME_RE`), the domain a lowercase label
    sequence. Anything else is a ConfigError."""
    if not isinstance(addr, str) or addr.count("@") != 1:
        raise ConfigError(f"{where}: expected one exact address, got {addr!r}")
    local, domain = addr.split("@")
    if not _NAME_RE.fullmatch(local):
        raise ConfigError(f"{where}: the local part {local!r} is not a valid name "
                          "(ASCII letters, digits, '.', '_' and '-')")
    if not _FLEET_DOMAIN_RE.fullmatch(domain):
        raise ConfigError(f"{where}: the domain {domain!r} is not a normalised "
                          "(lowercase) domain")
    return local, domain


def _aliases(top: Dict[str, Any], registry_dir: Optional[Path],
             fleet_domain: Optional[str]) -> Tuple[AliasEntry, ...]:
    """`aliases`: a list of `{old, new, expires}` (contract §2.3). Checked
    here, once, for everything that does not depend on the registry: the
    shapes; `new` a canonical address in this fleet's domain; a parseable
    `expires`; no `old` twice; no chain or cycle (no `new` is any `old`);
    `old` never `new`; `old`'s local part never a reserved name's skeleton;
    and a same-domain alias whose local part has its own target's skeleton
    (a case or confusable variant, which the registry would refuse as a
    name). Everything that depends on the registry is decided per poll
    (`router/aliases.py`). Needs a registry and a fleet domain."""
    from .registry import RESERVED_LOCAL_PARTS, skeleton
    from .util import parse_utc_ts
    if "aliases" not in top:
        return ()
    raw = top["aliases"]
    if registry_dir is None or not fleet_domain:
        raise ConfigError("config.aliases: needs registry_dir and fleet_domain (an alias "
                          "maps to an identity's current canonical address)")
    if not isinstance(raw, list):
        raise ConfigError("config.aliases: expected a list of {old, new, expires}")
    out: List[AliasEntry] = []
    reserved = {skeleton(r) for r in RESERVED_LOCAL_PARTS}
    for i, e in enumerate(raw):
        where = f"config.aliases[{i}]"
        if not isinstance(e, dict) or set(e) != _ALIAS_KEYS:
            raise ConfigError(f"{where}: expected exactly {{old, new, expires}}")
        old_local, old_domain = _alias_parts(e["old"], f"{where}.old")
        new_local, new_domain = _alias_parts(e["new"], f"{where}.new")
        if new_domain != fleet_domain:
            raise ConfigError(f"{where}.new: must be a canonical address in "
                              f"{fleet_domain!r}, got {e['new']!r}")
        if not isinstance(e["expires"], str) or parse_utc_ts(e["expires"]) is None:
            raise ConfigError(f"{where}.expires: expected a UTC timestamp, got "
                              f"{e['expires']!r}")
        if e["old"] == e["new"]:
            raise ConfigError(f"{where}: old and new are the same address")
        if skeleton(old_local) in reserved:
            raise ConfigError(f"{where}.old: {old_local!r} collides with a reserved name")
        if old_domain == new_domain and skeleton(old_local) == skeleton(new_local):
            raise ConfigError(f"{where}: {e['old']!r} is a variant of its own target "
                              f"{e['new']!r} in the same domain")
        out.append(AliasEntry(e["old"], e["new"], e["expires"]))
    olds = [a.old for a in out]
    dup = sorted({o for o in olds if olds.count(o) > 1})
    if dup:
        raise ConfigError(f"config.aliases: {dup} listed more than once")
    chained = sorted({a.new for a in out} & set(olds))
    if chained:
        raise ConfigError(f"config.aliases: {chained} is both a target and an old address "
                          "(no chains or cycles)")
    return tuple(out)


def _connector_outcome_ids(top: Dict[str, Any]) -> Tuple[str, ...]:
    """`config.connector_outcome_ids`, validated: a non-empty list of distinct
    connector ids, each matching `_CONNECTOR_ID_RE`. Absent means
    `DEFAULT_CONNECTOR_OUTCOME_IDS`.

    THIS LOADER REFUSES UNKNOWN KEYS, so this key forces a rollout order: a
    router that understands it must be running before any deployment renders
    it, or that deployment's whole config is refused and nothing drains.

    DISTINCT BY CASEFOLD, not by equality, for the reason `_check_casefold`
    gives for instance names: on a case-insensitive filesystem `Codex` and
    `codex` are one directory. Scanned twice it would cost nothing but budget
    (the dedup key holds) — but a config that names one directory twice is a
    mistake worth refusing, and naming both spellings says which."""
    raw = top.get("connector_outcome_ids", list(DEFAULT_CONNECTOR_OUTCOME_IDS))
    if not isinstance(raw, list) or not raw:
        raise ConfigError(
            f"config.connector_outcome_ids: expected a non-empty list of connector "
            f"ids, got {raw!r}")
    seen: Dict[str, str] = {}
    for cid in raw:
        if not isinstance(cid, str) or not _CONNECTOR_ID_RE.fullmatch(cid):
            raise ConfigError(
                f"config.connector_outcome_ids: {cid!r} is not a connector id — "
                f"it becomes a path segment under outbound/ext/, so it must match "
                f"{_CONNECTOR_ID_RE.pattern}")
        folded = cid.casefold()
        if folded in seen:
            raise ConfigError(
                f"config.connector_outcome_ids: {seen[folded]!r} and {cid!r} name "
                f"the same directory (equal, or equal ignoring case)")
        seen[folded] = cid
    return tuple(raw)


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
