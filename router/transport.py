"""router/transport.py — the seam to an optional transport plugin.

This router carries no transport. A deployment that hands requests to a
second runtime does it through an optional plugin, loaded from a file the
operator names by PATH and SHA-256, never by import name. This module is
the whole public side of that seam, and nothing else:

  * the Protocols a plugin's objects satisfy: `TransportPort` (the
    in-flight state machine's view of the transport, `router/inflight.py`)
    and `InboundPort` (what comes back from it);
  * `PLUGIN_API`, the `(major, minor)` version the two sides agree on;
  * `NullTransport`, the plugin in force when none is configured;
  * `load_plugin`, the loader, and `PluginRefused`, its one failure.

IT IMPORTS NO PLUGIN. There is no `import` of plugin code anywhere in this
package and the loader never calls `importlib`: it reads the pinned file's
bytes once, checks their hash, and executes THOSE bytes. An import would
resolve a name through `sys.path` at the moment of import, and the file
executed would be whichever one won that race, not the one that was
hashed. `router/tests/test_transport.py` pins the absence of any import.

NULL, NOT ABSENT. `NullTransport` is the null PLUGIN: its factories return
`None`, so a router with no plugin configured passes `transport=None` to
the drain exactly as it did before this module existed, and an external
route settles `queued_for_human`/`transport_anomaly` ("the external leg is
not configured"). A null object that accepted writes would turn that
visible refusal into requests written nowhere.

THE LOADER (each step is a refusal with a fixed reason, `PluginRefused.reason`):

  1. the path is absolute and canonical (`path_not_absolute`,
     `path_not_canonical`): the string AS CONFIGURED equals its own
     `os.path.realpath`. Nothing normalises it first. That one equality
     refuses a symlinked component anywhere, and every lexical spelling
     (`..`, `.`, `//`, a trailing `/`): `realpath` always returns a
     normalised path, so equality with it implies `path ==
     os.path.normpath(path)` as well. Normalising first would check a
     DIFFERENT path from the one the kernel opens: with `b` a symlink,
     `/a/b/../c/p.py` names `c/p.py` beside `b`'s TARGET, while its
     lexical normal form `/a/c/p.py` names another file;
  2. it is not inside any directory an agent can reach (`agent_reachable`);
  3. every directory from its parent up to `/` is owned by a trusted uid
     and is not writable by anyone else, unless it is sticky
     (`parent_owner`, `parent_writable`);
  4. it is opened `O_NOFOLLOW` (`missing`, `symlink`) and fstat'd: a
     regular file (`not_regular`), owned by a trusted uid (`owner`), mode
     exactly 0444 or 0644 (`mode`), no larger than `MAX_PLUGIN_BYTES`
     (`too_large`);
  5. its bytes are read ONCE from that descriptor and their SHA-256 is
     compared with `hmac.compare_digest` (`hash_mismatch`);
  6. those bytes, and only those, are compiled and executed in a fresh
     namespace (`exec_failed`);
  7. its `PLUGIN_API` has our major and at least our minor (`api_mismatch`);
  8. every factory this runtime needs is present and callable
     (`missing_factory`).

Trusted uids are `(0,)`: a plugin runs with the router's authority, so only
root may own it or any directory above it. The parameter exists for the
test suite, which cannot create root-owned files. It is loaded once, at
startup (`router/service.py`), and never hot-swapped.

A sibling runtime has its own loader with the same reasons; one attack
suite covers both.

API 3.0 (AMENDMENT E8). `(3, 0)` adds, for this runtime: `HopFsOps.list_pinned`
and the `ListingTooLarge` attribute; a paged, fill-or-exhaust
`InboundPort.list_entries` and the `NoticeRefused` attribute; the
`amap-hop-notice-entry/2` bundle with its REQUIRED `hop` member; the
upstream retirement marker store (`make_upstream_marker_store`,
`UpstreamMarkers`); `TransportPort.withdraw_request`; `close()` on every
plugin object; and `TRANSPORT_REASONS`.

MIGRATION, (2, 0) -> (3, 0): a `(3, x)` runtime refuses every `(2, x)`
plugin at load, and a `(2, x)` runtime every `(3, x)` plugin, before any
factory is called (step 7). Nothing at `(2, x)` was ever deployed (no
activation existed), so there is no live migration: plugin and runtime move
together, in one release, readers first (contract §4.4) where a tree exists.
No tree written under `(2, x)` is read under `(3, x)`.

ORDER IS NEVER TAKEN FROM A LISTING. Listings are sorted by NAME, and an
entry id's order is not its name's order (a notice's name is
`notice-<id>.json`): nothing may compare entry ids to page. An outbound
request's claim order is `int(n)`, never its name, since `n` grows from 8 to
18 digits and code-point order is wrong across lengths.

CLASSIFYING WHAT A PLUGIN RAISES (`classify`). The plugin is executed, not
imported, so this runtime holds no class object of the plugin's own
exceptions, and message text is not a contract. In order:

  1. the captured VERDICT classes (`InboundPort.NoticeRefused`,
     `UpstreamMarkers.GenerationAbsent`), each with its own reasons;
  2. the RUNTIME's own classes, from its `HopFsOps` (`UnsafeRead`,
     `ListingTooLarge`), by class: their `.reason` is never compared with
     `TRANSPORT_REASONS`;
  3. a plugin `.reason` in `TRANSPORT_REASONS`;
  4. `OSError` (after `.reason`, so a plugin exception deriving from it is
     still classified by its reason);
  5. anything else, including a missing or unknown `.reason`: no verdict.

API 3.1: THE OPTIONAL INTAKE REMOVER, by the owner's decision (an optional
factory, not a required one). `make_intake_remover(settings, fsops)` returns
an `IntakeRemover`, whose `remove_entry(kind, entry_id)` removes one
committed inbound entry, crash-resumably, sentinel first. It is listed in
`OPTIONAL_FACTORIES` with the minor that introduces it, never in
`REQUIRED_FACTORIES` or `FACTORY_PORTS`, and `HopFsOps.stat_group_pinned`
(`HOPFSOPS_OPTIONAL_METHODS`) arrives with it, used by nothing else. A
plugin below that minor has the name IGNORED whatever it is; at or above
it, absent means the capability is OFF, callable means ON, and present but
not callable is refused (`missing_factory`). The rule that makes this a
MINOR change: adding an optional factory, with its object Protocol, its
result vocabulary and the `HopFsOps` behaviour only that factory's objects
rely on, is minor; adding a required factory, or changing anything a
`(3, 0)` caller relies on, is major.

API 3.3: THE PEER SEAM, for cross-host signed peer traffic (`router/
peerlane.py`). Two more OPTIONAL factories, `make_peer_codec(settings)` (the
peer header and statement codec and the key gate, `settings` exactly `{}`)
and `make_peer_errors()` (the exact exception classes the peer layers
raise, as a closed mapping). With `delegation` configured, `check_delegation`
requires them, and `make_signer` and `make_verifier`, all callable at a
PLUGIN_API of at least `DELEGATION_MINOR`, with the plugin's own
`OPTIONAL_FACTORIES` declaring both new names at that minor or later; any
shortfall is `delegation_capability_missing`. Without `delegation` nothing
here is consulted, so an older compatible plugin still loads.

API 3.4: THE CANDIDATE VIEW, one additive minor with no port change. The
peer codec gains an OPTIONAL method, `candidate_view(raw)` (the verifier's
candidate form from a candidate's bytes: a view, or the plugin's
`CodecError` with a reason in `CANDIDATE_REASONS` and nothing else), and an
OPTIONAL attribute, `CANDIDATE_REASONS` (`CODEC_OPTIONAL_METHODS`,
`CODEC_OPTIONAL_ATTRIBUTES`). The same gate as an optional factory: below
the minor the names are ignored; at or above it, absent is OFF (signed
candidates are held, `candidate_view_unavailable`); a method present but
not callable, or `CANDIDATE_REASONS` present but not exactly
`CANDIDATE_REASONS_3_4`, refuses delegation: exactly that set, at every
minor, until this runtime handles more.
"""

from __future__ import annotations

import builtins
import errno
import hashlib
import hmac
import logging
import os
import re
import stat
import types
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import (Any, Callable, Iterable, List, Literal, Mapping, Optional, Protocol,
                    Sequence, Tuple, Union, runtime_checkable)

_logger = logging.getLogger("amap_router_local.transport")

#: `(major, minor)`. A plugin must have the same major and at least this
#: minor. The MAJOR covers every interface in this module that crosses the
#: seam: `TransportPort`, `InboundPort`, `HopFsOps`, `KeyOps`, `Signer`,
#: `Verifier` and the factory signatures. Changing any of them (a method,
#: a parameter, a return vocabulary) is a major bump; adding an optional
#: factory is a minor one. `(2, 0)` is amendment E5: `HopFsOps` gained
#: `open_private_stage_dir`, `commit_durable`'s keyword-only `deps` and the
#: `UnsafeRead` attribute, so a `(1, x)` plugin is refused here and a
#: `(2, x)` plugin by a `(1, x)` runtime, before any factory is called.
#: `(3, 0)` is amendment E8 (module docstring, API 3.0).
PLUGIN_API: Tuple[int, int] = (3, 4)

#: The lowest minor this runtime LOADS. Optional factories never raise it: a
#: plugin with the same major and a minor of at least this loads, and the
#: runtime uses only what it and the plugin both know.
REQUIRED_MINOR = 0

#: Optional factories: name -> (the `(major, minor)` that introduces it, the
#: port it receives). Below that minor the name is ignored; at or above it,
#: absent is OFF, callable is ON, and anything else is `missing_factory`. The
#: port is `"HopFsOps"` (called with settings and this runtime's `HopFsOps`),
#: `None` (called with settings only) or `NO_ARGUMENTS` (called with none).
NO_ARGUMENTS = "()"
OPTIONAL_FACTORIES: Mapping[str, Tuple[Tuple[int, int], Optional[str]]] = {
    "make_intake_remover": ((3, 1), "HopFsOps"),
    "make_peer_codec": ((3, 3), None),
    "make_peer_errors": ((3, 3), NO_ARGUMENTS),
    "make_runtime_sender": ((3, 5), "HopFsOps"),
    "make_runtime_lister": ((3, 5), "HopFsOps"),
}

#: THE RUNTIME CAPABILITY, in its frozen PLUGIN_API (3, 5) shape: every name
#: this router calls to reach its own runtime control tree
#: (`router/peercontrol.py`), in this one table.
#: - `factory`: bound to one generation, closed settings {hop_root,
#:   generation, peer_uid, address, version_write, caps}; construction never
#:   admits; `admit(admitted_at)` ("admitted" | "exists"), called before the
#:   first transport method in the generation; the sender protocol (a NEW
#:   request in a retired generation raises reason `generation_retired`,
#:   only when no part of it exists); `retire(retired_at)` (never admits;
#:   "absent" for an absent tree), `retired()`, `retired_at()`, `identity()`.
#: - `lister`: READ-ONLY, closed settings {hop_root, peer_uid};
#:   `generations()` -> [(generation, "live" | "retired" | "unreadable")],
#:   an absent runtime tree listing empty.
#: Both are optional factories at `RUNTIME_MINOR`; a plugin declaring
#: neither leaves the runtime tree unavailable.
RUNTIME_MINOR: Tuple[int, int] = (3, 5)
RUNTIME_CAPABILITY: Mapping[str, str] = {
    "factory": "make_runtime_sender",
    "lister": "make_runtime_lister",
    "generations": "generations",
    "retire": "retire",
    "retired": "retired",
    "retired_at": "retired_at",
    "identity": "identity",
    "admit": "admit",
}


def runtime_capability_declared(plugin: Any) -> bool:
    """Whether `plugin` offers the runtime capability: BOTH factories among
    the optional capabilities this runtime will call (loaded at or above
    `RUNTIME_MINOR`, declared, callable)."""
    caps = getattr(plugin, "optional_capabilities", frozenset())
    return (RUNTIME_CAPABILITY["factory"] in caps and RUNTIME_CAPABILITY["lister"] in caps)


def runtime_factory(plugin: Any, role: str) -> Callable[..., Any]:
    """The plugin's `role` factory ("factory" or "lister") from its own
    namespace; `AttributeError` when the capability is off."""
    if not runtime_capability_declared(plugin):
        raise AttributeError("the transport plugin offers no runtime capability")
    return plugin.namespace[RUNTIME_CAPABILITY[role]]

#: The minor delegation needs, and the four factories it needs callable.
DELEGATION_MINOR: Tuple[int, int] = (3, 3)
DELEGATION_FACTORIES: Tuple[str, ...] = (
    "make_signer", "make_verifier", "make_peer_codec", "make_peer_errors")
#: Optional methods and attributes of the peer codec, by name, with the minor
#: introducing each (module docstring, API 3.4).
CODEC_OPTIONAL_METHODS: Mapping[str, Tuple[int, int]] = {"candidate_view": (3, 4)}
CODEC_OPTIONAL_ATTRIBUTES: Mapping[str, Tuple[int, int]] = {"CANDIDATE_REASONS": (3, 4)}
#: `candidate_view`'s vocabulary at (3, 4), exactly: a strict-decode refusal,
#: a schema refusal, and a candidate withheld at write time.
CANDIDATE_REASONS_3_4 = frozenset({"candidate_json", "candidate_schema", "over_cap"})
#: `make_peer_errors()`'s keys, exactly.
PEER_ERROR_NAMES: Tuple[str, ...] = ("CodecError", "KeyConfigError", "BackendError", "ConfigError")

#: The factories this runtime calls. A plugin may define more; it must
#: define these. `make_sender(settings, fsops) -> TransportPort`,
#: `make_intake_reader(settings, fsops) -> InboundPort` and
#: `make_upstream_marker_store(settings, fsops) -> UpstreamMarkers`.
REQUIRED_FACTORIES: Tuple[str, ...] = (
    "make_sender", "make_intake_reader", "make_upstream_marker_store")

#: Uids that may own the plugin file and every directory above it.
TRUSTED_UIDS: Tuple[int, ...] = (0,)

#: A larger file is refused before it is hashed.
MAX_PLUGIN_BYTES = 4 * 1024 * 1024

#: Every reason `PluginRefused` carries. Fixed so that operators, logs and
#: a sibling runtime's loader all say the same thing for the same refusal.
REFUSAL_REASONS = (
    "path_not_absolute", "path_not_canonical", "agent_reachable",
    "parent_owner", "parent_writable",
    "missing", "symlink", "not_regular", "owner", "mode", "too_large",
    "hash_mismatch", "exec_failed", "api_mismatch", "missing_factory",
    "fsops_unavailable", "role_mismatch", "delegation_capability_missing",
)
# `role_mismatch` is the sibling runtime's: its link role and its plugin pin
# disagree, in either direction. This router has no link role and never
# raises it; the reason is listed so both loaders share one vocabulary.
# `fsops_unavailable` likewise: this router raised it for every plugin until
# its filesystem port was activated (`service.start_transport`), and no
# longer does.


class PluginRefused(Exception):
    """The plugin was not loaded. `reason` is one of `REFUSAL_REASONS`.
    Startup stops: there is no degraded mode in either direction."""

    def __init__(self, reason: str, detail: str):
        assert reason in REFUSAL_REASONS, reason
        super().__init__(f"transport plugin refused ({reason}): {detail}")
        self.reason = reason
        self.detail = detail


@runtime_checkable
class TransportPort(Protocol):
    """The transport, as the in-flight state machine needs it
    (`router/inflight.py`, its module docstring's table). Every method takes
    the transport req_id `n` this router allocated.

    `has_pending(n)` is true while request `n` has been handed over and the
    downstream runtime has neither archived it nor written its result,
    WHETHER OR NOT the downstream runtime has claimed it. A claimed request
    is still pending: the in-flight step must not read "claimed" as gone,
    or it would hand the request over again or settle it as an anomaly.
    It is true ONLY for a COMMITTED handover. A publication still in flight,
    or left partial by a crash, reads as NOT pending: it is not yet
    claimable, and the caller must not wait on it, since its retry (below)
    is what completes it.

    `write_request(n, data)` hands request `n` over, and never overwrites or
    replaces anything. A correct caller calls it once per `n`, with one
    exception: after a restart, when `has_result`, `has_pending` and
    `has_archived` are all false for `n`, it calls it again with a document
    carrying the same request, envelope and attachments, and the
    implementation then completes the interrupted publication. The same
    request, envelope and attachments already handed over (pending, claimed or processed) is a success that
    writes nothing. A request under `n` that was withdrawn, or whose bytes
    differ, raises with nothing written; the caller's record then stays in
    flight.

    `data` is the hop handover document, which the hop codec's
    specification defines, not this module: a CLOSED, VERSIONED JSON object
    with exactly the members `schema`, `request` (the submit-request),
    `envelope`, `attachments` (each standard base64, without newlines) and
    `settled_through`, in canonical encoding (sorted keys, compact
    separators). Unknown members are refused. The implementation validates
    the whole document before writing anything: the request's descriptors
    match the attachments one for one by size and sha256, and the caps
    apply to the decoded sizes. `settled_through` is an `n'` below `n` such
    that every request at or below it is settled by this router or was
    allocated and never written; it never decreases, and it is the one
    member a retry may change.

    `withdraw_request(n)` takes a published, UNCLAIMED request back, and is
    decided by the no-replace rename of `outbound/req-<n>.json` itself,
    never by a pre-check: the receiver's claim renames the same source, so
    exactly one side wins. `"withdrawn"`: this call's rename moved it, or
    the JSON is already in `withdrawn/` (a repeat after a crash completes
    the `hop.json` and attachment moves; until then `has_archived(n)` is
    true and `write_request(n)` raises). `"too_late"`: the JSON is in
    `claimed/` or `processed/`, or `results/<n>.json` exists, checked even
    while the JSON is still in `outbound/`; the caller waits for the
    Result. A source gone with none of those, or a destination conflict,
    RAISES (an anomaly), never either verdict. `FileNotFoundError` in two
    separate cases: (i) never published; (ii) a request at link count 2
    (a publication in flight or partial), which is never withdrawn half
    made, and nothing moves. Allowed on a retired generation, alike.

    `close()` releases exactly the descriptors the object itself obtained
    from `open_root_nofollow`, `descend_pinned`, `mkdir_and_pin` or
    `stage_tree`. Stage descriptors from `open_stage_dir` /
    `open_private_stage_dir` belong to the `HopFsOps` instance and are never
    closed by a plugin object, which re-requests a stage descriptor rather
    than retaining it across calls. Idempotent: a second call is a no-op
    and never raises. After it, every other method raises
    `ValueError("closed")`, carrying `.reason` `"closed"`, before any
    `HopFsOps` call. The same holds for `InboundPort` and `UpstreamMarkers`.

    THE FACTORY CLEANUP RULE: a factory that RAISES has released every
    descriptor it opened, so a caller never holds anything from a failed
    construction.

    Every exception a plugin object or factory raises deliberately carries
    `.reason`, one of `TRANSPORT_REASONS`; the caller classifies on it
    (module docstring, CLASSIFYING)."""

    def has_result(self, n: str) -> bool: ...
    def has_pending(self, n: str) -> bool: ...
    def has_archived(self, n: str) -> bool: ...
    def read_result(self, n: str) -> bytes: ...
    def write_request(self, n: str, data: bytes) -> None: ...
    def withdraw_request(self, n: str) -> WithdrawResult: ...
    def close(self) -> None: ...


@runtime_checkable
class InboundPort(Protocol):
    """What arrives from the transport for this router to place: notices,
    signed candidates, and entries no live tree could be found for.
    `kind` is one of `INBOUND_KINDS`. `read_entry(kind, entry_id)` returns
    one entry's bytes, which are HOSTILE input to the caller.
    `entry_id`s are opaque to this router and unique within a kind.

    `list_entries(kind, *, limit, after=None) -> (entry_ids, truncated)`
    pages over the COMMITTED entries of `kind`. The order and the cursor are
    over each entry's underlying NAME in its directory (`notice-<id>.json`
    for a notice; the id itself for a candidate or an unresolved entry), in
    code-point order, never over the id: `after` is an entry id of `kind`
    (it must pass the kind's grammar, else `ValueError`), and the entries
    returned are those whose NAME sorts strictly after `after`'s name.
    `limit` is the caller's keyword (`check_list_args`). It returns fewer
    than `limit` entries only when `truncated` is False; `truncated` is True
    iff at least one further committed entry exists after the last one
    returned. Internally it repeats `HopFsOps.list_pinned`, each call with
    `limit=LIST_LIMIT_MAX` and `after` = the last NAME it saw (an entry or
    not), until it holds `limit + 1` committed entries or the directory is
    exhausted, and returns the first `limit`: the extra one is only the
    lookahead. Time is O(directory) per inner call, so at most
    ceil((J + limit + 1) / LIST_LIMIT_MAX) + 1 scans for `J` non-entry names
    passed (a BOUND, not an exact count), and every scan stops at
    `LIST_SCAN_MAX` names; memory is O(limit + LIST_LIMIT_MAX). The
    `HopFsOps` instance's `ListingTooLarge` propagates UNCHANGED: it is the
    runtime's class, never caught, wrapped or re-raised as anything else.
    The caller keeps one cursor per (port, kind) and restarts from `None`
    when `truncated` is False, so every committed entry is returned within
    ceil(N / limit) + 1 calls, whatever the held set or the junk names.

    `NoticeRefused` is this object's refusal class for a notice (an
    exception class, like `HopFsOps.UnsafeRead`). `read_entry("notice", id)`
    raises it, with `.reason` one of `NOTICE_REFUSAL_REASONS`, for a
    COMMITTED notice whose facts, spool or sidecars are missing
    (`notice_incomplete`) or invalid (`notice_invalid`: the facts by any
    codec layer, or a malformed descriptor or `content_ref`). Such an entry IS listed,
    never hidden; an uncommitted notice is not listed. The caller captures
    the class once, at construction (`capture_verdict_class`: two-way
    disjoint from `OSError` and both of the runtime's own classes,
    `UnsafeRead` and `ListingTooLarge`), and dispatches on the captured
    class for kind `"notice"` only. An `OSError`, `UnsafeRead` or
    `ListingTooLarge` raised while reading or listing notices propagates as
    itself and is never a verdict.

    A `"notice"` entry's bytes are the hop inbound bundle, which the hop
    codec's specification defines, not this module: a CLOSED, VERSIONED
    JSON object, `NOTICE_BUNDLE_SCHEMA`, with exactly the members `schema`,
    `notice`, `spool`, `attachments` and `hop`, in canonical encoding. `hop`
    is REQUIRED and never null: the standard base64 (no newlines) of the
    EXACT bytes of the notice's facts file
    (`inbound/notice-facts/notice-<id>.json`), at most `HOP_FACTS_MAX`
    decoded. A `/1` bundle is refused. `attachments` is POSITIONAL, as
    AMAP binds a sidecar to its descriptor's array index: entry `k` belongs
    to the notice's `message.attachments[k]`, and is the standard base64 of
    sidecar `k` if and only if that descriptor carries `content_ref` (which
    AMAP permits only for a `"clean"` descriptor, and which must equal
    `<notice_id>.attachments/<k>`). Every other position is null: a gap,
    never a renumbering. A notice with no `message.attachments` has none.
    An entry is listed only once its notice, written last, is committed.
    The caller validates every part (the notice and spool against their
    schemas, each attachment against descriptor `k`'s size and sha256) and
    refuses the entry on any mismatch; the caps apply per part, to decoded
    sizes. `close()` is `TransportPort.close`'s, alike."""

    #: This object's refusal class for a committed notice (above).
    NoticeRefused: type

    def list_entries(self, kind: str, *, limit: int,
                     after: Optional[str] = None) -> Tuple[List[str], bool]: ...
    def read_entry(self, kind: str, entry_id: str) -> bytes: ...
    def close(self) -> None: ...


#: The kinds an `InboundPort` serves.
INBOUND_KINDS = ("notice", "candidate", "unresolved")


RemoveResult = Literal["removed", "absent"]
#: `IntakeRemover.remove_entry`'s results, exactly. `"absent"` is shared with
#: `RETIRE_RESULTS` on purpose, with the same meaning: owner-checked, durably
#: not there. Any other return is a protocol error to the caller.
REMOVE_RESULTS: Tuple[str, ...] = ("removed", "absent")
#: The most entries a per-item directory part may hold before removal refuses
#: it (`layout`): `LIST_LIMIT_MAX`, far above any legitimate sidecar count.
REMOVE_DIR_ENTRIES_MAX = 1024
#: The kinds an `IntakeRemover` removes. Host intakes are never its.
_REMOVE_KINDS = ("notice", "candidate")


@runtime_checkable
class IntakeRemover(Protocol):
    """The OPTIONAL `(3, 1)` remover: one committed inbound entry of one
    generation's tree, removed crash-resumably.

    `remove_entry(kind, entry_id) -> RemoveResult`: `kind` is "notice" or
    "candidate" (never a host intake's) and `entry_id` must pass that kind's grammar (a bare
    `ValueError`, before any `HopFsOps` call, otherwise). The parts are
    derived from the id ALONE, never from reading the entry, so an entry the
    reader refused is still removable. The SENTINEL goes first (a notice's
    `notices/notice-<id>.json`; a candidate's `candidates/<id>/candidate.json`),
    then the other parts in order. Every required parent missing, or with
    the wrong owner or kind, raises `HopAnomaly("layout")` / `("owner")`,
    never "absent". A per-item directory part must be flat, owned by the peer,
    group-writable and searchable, setgid, not sticky, with its parent's gid
    and a setgid parent, all checked BEFORE anything is renamed.
    `"removed"`: at least one part was observed present and removed;
    `"absent"`: none was. Either way every part, and every aside of a
    directory part, is durably gone on return. An `OSError`, `UnsafeRead` or
    `ListingTooLarge` from a `HopFsOps` call propagates UNCHANGED; the parts
    before it stay removed and nothing after it is attempted.

    `close()`: as every `(3, 0)` object's (idempotent, never raises; any
    call afterwards raises the closed `ValueError` before any `HopFsOps`
    call)."""

    def remove_entry(self, kind: str, entry_id: str) -> RemoveResult: ...
    def close(self) -> None: ...
#: `InboundPort`'s non-method members.
INBOUNDPORT_ATTRIBUTES = ("NoticeRefused",)
#: `InboundPort.NoticeRefused.reason`: exactly one of these.
NOTICE_REFUSAL_REASONS = ("notice_incomplete", "notice_invalid")
#: The notice bundle's schema at `(3, 0)`. Any other value is refused.
NOTICE_BUNDLE_SCHEMA = "amap-hop-notice-entry/2"
#: The decoded cap on a bundle's `hop` member. Equal to the hop codec's
#: facts `MAX_BYTES`; the plugin is private, so this runtime cannot import
#: it, and the plugin's conformance suite asserts the two are equal at this
#: runtime's pin.
HOP_FACTS_MAX = 64 * 1024

#: `list_pinned` / `list_entries`: the largest `limit` a caller may pass.
#: A larger one is refused, never clamped.
LIST_LIMIT_MAX = 1024
#: `list_pinned` stops after visiting this many names and raises the
#: `HopFsOps` instance's `ListingTooLarge`.
LIST_SCAN_MAX = 65536

#: `withdraw_request`'s results.
WithdrawResult = Literal["withdrawn", "too_late"]
WITHDRAW_RESULTS = ("withdrawn", "too_late")
#: `UpstreamMarkers.retire`'s results.
RetireResult = Literal["created", "exists_same", "exists", "absent"]
RETIRE_RESULTS = ("created", "exists_same", "exists", "absent")

#: `.reason` on every exception a plugin object or factory raises
#: deliberately (module docstring, CLASSIFYING). A missing or unknown
#: `.reason` is "anything else": no verdict.
TRANSPORT_REASONS = (
    "request_exists_different", "request_exists_withdrawn", "request_exists_settled",
    "handover_invalid", "below_frontier",
    "layout", "owner", "version",
    "exists_different", "reconcile", "sidecars", "sidecars_orphaned", "heal_state",
    "protocol_violation", "marker_unreadable",
    "settings_invalid", "closed",
    "generation_retired",
)


@runtime_checkable
class UpstreamMarkers(Protocol):
    """The upstream side's retirement marker for ONE generation tree
    (`make_upstream_marker_store`, settings exactly the four-key core:
    `hop_root`, `logical_id`, `generation`, `peer_uid`). Construction calls
    no `HopFsOps` writer method and never admits (contrast the sender, whose
    construction admits).

    `retire(retired_at)` writes `up/retired.json` durably (`commit_durable`
    through `up/stage`); it is immutable once written. `retired_at` must
    pass `check_retired_at`, BEFORE any `HopFsOps` call. Results:
    `"created"`; `"exists_same"`; `"exists"` (retired already at another
    instant: not an error); `"absent"` ONLY on an owner-checked ENOENT of
    `<logical_id>/<gen>/` or `<logical_id>/`, creating nothing. A repeat
    after a crash part-way through (`up/retired.json` at link count 2) completes
    the commit and returns `"created"` or `"exists_same"`. Any failed
    barrier raises.

    `retired()`: `True` for a valid marker; `False` only for an
    owner-checked ENOENT of `up/retired.json` in an EXISTING tree whose `up/` is
    intact. An absent tree raises this object's `GenerationAbsent`, never
    `False` (`False` means "the tree exists and is not retired"). The caller
    captures `GenerationAbsent` once, at construction
    (`capture_verdict_class`: two-way disjoint from `OSError` and both of the
    runtime's own classes, `UnsafeRead` and `ListingTooLarge`). Every
    other condition RAISES ("cannot decide", so the caller holds): a wrong
    owner, not a regular file, a link count of 2 or more, a missing or
    damaged `up/`, or content other than EXACTLY the canonical
    `{"retired_at": <utc_ts>}`.

    `close()` is `TransportPort.close`'s, alike."""

    #: This object's refusal class for an absent generation tree (above).
    GenerationAbsent: type

    def retire(self, retired_at: str) -> RetireResult: ...
    def retired(self) -> bool: ...
    def close(self) -> None: ...


#: `UpstreamMarkers`'s non-method members.
UPSTREAM_MARKER_ATTRIBUTES = ("GenerationAbsent",)
#: The `retired_at` grammar: this router's `utc_ts` form, ASCII digits only
#: (`\d` would also match non-ASCII digits).
RETIRED_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


# --------------------------------------------------------------------------
# The ports a plugin's factories RECEIVE. Interface only: no implementation
# lives in this module. A plugin makes no filesystem call of its own; every
# one goes through `HopFsOps`, and the signer never opens a path (`KeyOps`).
# --------------------------------------------------------------------------

#: `commit_durable`'s results.
CommitResult = Literal["created", "exists_same", "exists_different"]
#: `rename_noreplace`'s results.
RenameResult = Literal["moved", "src_gone", "dst_exists"]
#: `stat_owner_pinned`'s kinds, from a NON-following stat (`O_NOFOLLOW` /
#: lstat semantics): `"file"` is a regular file only (`S_ISREG`), `"dir"` is
#: `S_ISDIR`, and everything else (symlink, FIFO, socket, device) is
#: `"other"`. The uid and mode come from that same stat. A missing name
#: raises `FileNotFoundError`; any other failure propagates as its own
#: `OSError` and is never folded into a kind.
EntryKind = Literal["file", "dir", "other"]
#: `open_stage_dir`'s sides: the writer-private, 0700 stage directory of
#: `"up"` (the upstream writer, `<gen>/up/stage/`) or `"down"` (the
#: downstream writer, `<gen>/down/stage/`), where `tree_fd` is a generation
#: tree; or `"intake"`, where `tree_fd` is one host intake directory and the
#: stage is its `.stage/`. One `"intake"` value serves every host intake:
#: each has its own `.stage/`, and the binding tells them apart.
#:
#: Checked BEFORE anything is opened, each raising `ValueError`: an unknown
#: side, and a side that disagrees with `tree_fd`'s binding (`"up"`/`"down"`
#: need a registered generation tree, `"intake"` a registered host intake).
#: Otherwise `"intake"` on a generation tree would quietly create
#: `<gen>/.stage/`, a stage no writer recovers from.
#:
#: A missing stage directory is created 0700 through the durable mkdir
#: (unconditional parent fsync). An existing one must pass a non-following
#: fstat: a real directory, owned by the calling writer's uid, mode exactly
#: 0700. Anything else raises and is never repaired or chmodded. The
#: intermediate `<gen>/up/` or `<gen>/down/` (the single-owner 0750 marker
#: directory) and the deploy-created 2750 intake directory already exist;
#: `open_stage_dir` creates neither. The fd is pinned once and reused for
#: the writer's lifetime: a second call for the same (tree, side) returns an
#: fd to the same inode.
StageSide = Literal["up", "down", "intake"]
#: One dependency of a `commit_durable` sentinel: `(dir_fd, name, size,
#: sha256)`, the sha256 as lowercase hex (`HopFsOps`, DEPENDENCIES).
Dependency = Tuple[int, str, int, str]
#: `fsops.UnsafeRead.reason`: exactly one of these (`HopFsOps`, READS), for
#: every runtime that implements `HopFsOps`. Each implementation's own set
#: must be a subset (the plugin's conformance suite checks it), and the
#: classifier never compares these with `TRANSPORT_REASONS` (module
#: docstring, CLASSIFYING).
UNSAFE_READ_REASONS = ("not_regular", "link_count", "too_large")


@runtime_checkable
class HopFsOps(Protocol):
    """Every filesystem operation a plugin may perform, on descriptors the
    implementation pinned. The method list, parameters and result
    vocabularies are exactly the contract's (B §e.2); changing them bumps
    `PLUGIN_API`'s major. Every failed barrier RAISES, and the caller's
    dependent step does not run.

    `commit_durable(stage_dirfd, dest_dirfd, name, data, mode, *, deps=())`
    publishes `data` (the writer's FROZEN bytes, journalled before the call) under
    `name` in `dest_dirfd`, by writing a deterministic stage in the
    writer-private `stage_dirfd`, fsyncing it, linking it in, fsyncing the
    destination and unlinking the stage. Equality is byte equality.
    `exists_same` is returned for identical existing bytes or for this
    writer's own interrupted commit, recovered with the stage still present
    until everything is durable. `exists_different` is an anomaly; the
    existing file is never replaced.

    THE DESTINATION TAG IS THE IMPLEMENTATION'S, AND IT IS AN INVARIANT,
    NOT A PARAMETER. The stage name is `<dest-tag>.<name>`, and the call
    does not carry the tag. The implementation derives it from a canonical
    BINDING it holds for `dest_dirfd`:

      * every destination is registered through the implementation's own
        trusted opening paths (`open_root_nofollow` when the root is itself
        a destination, as for private ledgers; `descend_pinned`;
        `mkdir_and_pin`; and `stage_tree` for an admitted subtree), with
        its writer, tree and stage scope and its directory identity;
      * a bare descriptor number is never the binding: after a close and
        fd-number reuse the binding is stale, so the live descriptor is
        verified against the recorded identity (device and inode, plus the
        directory, owner and mode checks);
      * the tag is a canonical layout role in its tree scope (`outbound`,
        `results` and `notices` are examples, not the list): stable across
        restarts and reopening, never derived from fd numbers, random
        traversal ids or an opening's spelling, and unique among
        destinations sharing one stage directory;
      * a destination that is one of many per-item directories (a
        request's attachment directory, a per-candidate directory, a
        notice's attachment directory) has a tag that INCLUDES THE ITEM'S
        IDENTITY. A fixed tag shared by such directories would let one
        item's stale-stage cleanup unlink another item's interrupted
        commit, so it looked committed without its recovery ever running;
      * tags match `[A-Za-z0-9._-]+`, never contain `/`, and
        `<tag>.<name>` fits in NAME_MAX;
      * an admitted tree keeps its FINAL role: the role of each directory
        in it is derived RELATIVE TO THE `stage_tree` ROOT (the tree's own
        layout), so the temporary parent name never enters it and the
        implementation never needs to learn the final name;
      * an unknown, closed, mismatched, conflicting or ambiguous binding
        RAISES before anything is staged or published. Ambiguous means two
        bindings resolving to the same directory (`st_dev`, `st_ino`) with
        different tags. There is no best-effort fallback to a basename;
      * the binding registry belongs to the `HopFsOps` instance and never
        outlives the process. Restart stability comes from deriving the
        tag from the binding's role and path, never from registration
        order, so recovery in a fresh instance derives the same stage name.

    DEPENDENCIES (`deps`, on a publication's sentinel only). Each
    `(dir_fd, name, size, sha256)` is an earlier commit of the same
    publication, in commit order; its directory may differ from the
    sentinel's but is in the SAME TREE as the destination and never inside
    a stage directory. A dependency outside that scope raises before
    anything is staged. For each one the implementation checks:

      * the binding guard: `dir_fd`'s directory is still at its recorded
        path in its tree, by a fresh `O_NOFOLLOW` walk from the tree root,
        with the same (`st_dev`, `st_ino`);
      * the content: through that walk, `name` is a regular file at link
        count 1 (count 2 is an anomaly here, never NOT_YET: the
        dependency's own commit already returned), read pinned and bounded
        to `size + 1` bytes, with exactly `size` bytes whose SHA-256 is
        `sha256`.

    They are checked BEFORE any stage, compare, recovery or `exists_*`
    answer, and AGAIN after the link or the compare, before the barrier or
    the result, on every path, `exists_different` included. A failure RAISES the implementation's
    dependency anomaly, naming its cause (binding moved, missing, not
    regular, link count, size, digest); it is never `created` or
    `exists_same`, and the stage is kept. These are point-in-time
    observations, not a guarantee through the commit point: `created` and
    `exists_same` mean the sentinel is physically committed and both
    observations passed. Whether a publication is complete is for its
    READER to establish, on the immutable snapshot it consumes.

    `open_private_stage_dir(root_fd)` returns the writer-private stage of a
    configured PRIVATE root: `<private_root>/.stage/`. `root_fd` must be
    the private root itself (not a directory inside one, and never a hop
    tree or intake): anything else raises before anything is created. A
    missing `.stage/` is created 0700 (`fchmod` after `mkdir`, so the umask
    cannot widen it); an existing one must be a real directory owned by the
    calling writer's uid with mode exactly 0700, and is otherwise refused,
    never repaired. The private root is fsynced before the descriptor is
    returned, whether this call created `.stage/` or found it. The
    descriptor is pinned once. `commit_durable` accepts as `stage_dirfd`
    only a directory THIS instance validated through `open_stage_dir` or
    `open_private_stage_dir`, identified by `(st_dev, st_ino)` while the
    instance's pinned stage descriptor holds it, and bound at that stage's
    canonical path; another descriptor of that same directory at that path,
    including one reached through `descend_pinned`, is the same stage. A
    directory this instance never validated, one created in its place, or
    the validated directory reached at any other path, is refused. The
    same-tree rule then confines a private stage to its own private tree.
    `.stage/` is never a destination and must never be swept
    while the writer runs. An implementation is constructed with its hop
    root and private roots, which must be pairwise disjoint (none equal to
    or containing another); otherwise construction raises.

    `open_regular_pinned` returns the file's bytes (`bytes`, exactly) once
    it is committed (link count 1), and `self.NOT_YET` for a commit still
    in flight (link count 2), ON A HOP-TREE OR HOST-INTAKE BINDING ONLY:
    both are written only by trusted runtimes (a generation tree's sides,
    and a host intake's `.stage/` publications), so a link count of 2 there
    is a commit in flight. On any other binding (an agent-writable source,
    or a writer's private tree), a link count of 2 raises like any other
    count but 1. Any other link count raises. `NOT_YET` is one
    object per implementation, never a `bytes` instance and identical
    across calls; the two runtimes do not import each other, so there is
    no shared sentinel. Callers dispatch three ways, and the third is a
    protocol violation, never a skip:

        r = fsops.open_regular_pinned(dir_fd, name, max_bytes=cap)
        if r is fsops.NOT_YET:   # in flight: skip, retry on a later pump
            ...
        elif type(r) is bytes:   # committed
            ...
        else:                    # an implementation bug: raise
            ...

    Reading anything else as "not yet" would turn a bug (a `None`, a `str`,
    a forgotten return) into a silent retry forever.

    READS: WHAT A REFUSAL IS. `open_regular_pinned` raises `self.UnsafeRead`
    (an exception class, one per implementation, defined the way `NOT_YET`
    is) for a deterministic finding about the file, with `.reason` exactly
    one of `UNSAFE_READ_REASONS`:

      * `"not_regular"`: not a regular file after the `fstat`, or ELOOP or
        ENXIO from the single-component `O_NOFOLLOW | O_NONBLOCK` open (a
        symlink gives ELOOP and a socket ENXIO; a FIFO or a device opens,
        and fails the regular-file check), with the `OSError` kept as
        `__cause__`;
      * `"link_count"`: a count other than 1 on a binding without trusted
        links, or other than 1 or 2 on a generation tree or host intake
        (including 0: the name unlinked after the open);
      * `"too_large"`: more than `max_bytes`.

    A missing name raises a raw `FileNotFoundError`, never `UnsafeRead`.
    Anything else (EACCES, EIO, EMFILE, ...) propagates as itself, and
    means no verdict. Callers dispatch on `isinstance(e, fsops.UnsafeRead)`
    and `e.reason` only, never on a class name or module. The reason
    classifies the error; the CALLER's contract decides whether it is
    terminal.

    THE BARRIER EACH METHOD OWES before it returns (a failed barrier raises):

      * `mkdir_and_pin`: fsyncs the parent, whether or not this call created
        the directory (an earlier creator's fsync may have failed). Before
        it returns, the FINAL `fstat` of the descriptor it pins must show a
        directory owned by the writer's uid, permission bits equal to
        `mode & 0o777`, no setuid or sticky bit, and a setgid bit equal to
        the pinned parent's (from `fstat` of the parent descriptor; a
        requested setgid bit means nothing). A new directory is made with
        `mode & 0o777`; only if the umask removed bits is it `fchmod`ed to
        `(its setgid bit) | (mode & 0o777)`. An existing directory is
        checked the same way and never repaired. A failure raises;
      * `stage_tree`: creates the staging subtree under `staging_name`,
        fsyncs it bottom-up and the parent, and returns its root fd
        UNPUBLISHED. It never renames. The caller commits what must exist
        before publication inside it (the identity marker), then publishes
        it with `rename_noreplace` (both directories fsynced). A failure
        before that rename leaves only a staging name that no reader treats
        as a tree;
      * `commit_durable`: the stage file and stage dir, then the
        destination dir, then the stage dir again after the unlink (above);
      * `replace_durable`: the file before its rename, the directory after:
        durable on return;
      * `rename_noreplace`: both directories, destination first; there is
        no fallback to link-then-unlink;
      * `remove_pinned`: the directory, even when the name was already
        missing (an earlier remover's fsync may have failed), so the removal
        is durable on return;
      * `fsync_file`, `fsync_dir`: exactly what they say.

    LISTING. `list_pinned(dir_fd, *, limit, after=None) -> (names, truncated)`
    lists the directory `dir_fd` pins, which must be a descriptor this
    instance bound (the stale-binding check applies). It returns the `limit`
    smallest names strictly greater than `after` in code-point order,
    sorted; `truncated` is True iff more names exist beyond the last one
    returned. `limit` and `after` are checked first (`check_list_args`).
    Names are `str` as the kernel's bytes decode with `surrogateescape`, so
    an undecodable name is returned for the caller's grammar check, never
    dropped and never raised; `.` and `..` are excluded; names are returned
    as listed, and validating them (grammar, kind, owner) is the CALLER's.
    The scan streams a FRESH open description of that directory
    (`os.open(".", dir_fd=...)`, never a dup, which would share the pinned
    descriptor's offset), so the pinned descriptor's offset and state are
    unchanged; memory is O(limit), a bounded heap, never a full listing.
    The scan visits at most `LIST_SCAN_MAX` names: on visiting one more it
    stops at once and raises this instance's `ListingTooLarge`, so no scan
    is longer than that whatever the directory holds. A failure raises; it
    never returns an empty list for an error.

    OPTIONAL AT (3, 1), used only by the optional remover's objects
    (`HOPFSOPS_OPTIONAL_METHODS`): `stat_group_pinned(dir_fd, name) -> (uid,
    gid, mode, kind)`, EXACTLY `stat_owner_pinned`'s semantics (one
    NON-following stat of `name` in the bound `dir_fd`, the stale-binding
    check applying; `mode` the `S_IMODE`, so setuid, setgid and sticky are
    included; `kind` "file" / "dir" / "other"; a missing name a raw
    `FileNotFoundError`; any other failure its own `OSError`) plus that same
    stat's `st_gid`. It is not in `HOPFSOPS_METHODS`, and adding it is minor:
    only a `(3, 1)` runtime constructs a remover, handing it its own `(3, 1)`
    filesystem port. The `(3, 1)` postcondition on `remove_pinned` travels
    with it: before acting on `name` it sweeps every aside of THAT name (the
    exact pattern its own rename-aside gives one), emptying each in place,
    so a call that returns has left neither `name` nor any aside."""

    #: This implementation's "committed not yet" result (above).
    NOT_YET: object
    #: This implementation's refusal class for `open_regular_pinned` (READS).
    UnsafeRead: type
    #: This implementation's refusal class for a directory `list_pinned`
    #: refuses to scan to the end (LISTING). Two-way disjoint from `OSError`
    #: and `UnsafeRead`.
    ListingTooLarge: type

    def open_root_nofollow(self, path: str) -> int: ...
    def descend_pinned(self, root_fd: int, rel: str) -> Optional[int]: ...
    def mkdir_and_pin(self, parent_fd: int, name: str, mode: int) -> int: ...
    def stage_tree(self, parent_fd: int, staging_name: str) -> int: ...
    def commit_durable(self, stage_dirfd: int, dest_dirfd: int, name: str,
                       data: bytes, mode: int, *,
                       deps: Sequence[Dependency] = ()) -> CommitResult: ...
    def open_stage_dir(self, tree_fd: int, side: StageSide) -> int: ...
    def open_private_stage_dir(self, root_fd: int) -> int: ...
    def replace_durable(self, dir_fd: int, name: str, data: bytes, mode: int) -> None: ...
    def rename_noreplace(self, src_fd: int, src: str,
                         dst_fd: int, dst: str) -> RenameResult: ...
    def open_regular_pinned(self, dir_fd: int, name: str, *,
                            max_bytes: int) -> Union[bytes, object]: ...  # bytes or self.NOT_YET
    def stat_owner_pinned(self, dir_fd: int, name: str) -> Tuple[int, int, EntryKind]: ...
    def remove_pinned(self, dir_fd: int, name: str) -> None: ...
    def fsync_file(self, fd: int) -> None: ...
    def fsync_dir(self, fd: int) -> None: ...
    def list_pinned(self, dir_fd: int, *, limit: int,
                    after: Optional[str] = None) -> Tuple[List[str], bool]: ...


#: `HopFsOps`'s methods, in the contract's order (B §e.2, as amended by E5
#: and E8). Methods only: its attributes are `HOPFSOPS_ATTRIBUTES`.
HOPFSOPS_METHODS = (
    "open_root_nofollow", "descend_pinned", "mkdir_and_pin", "stage_tree",
    "commit_durable", "open_stage_dir", "open_private_stage_dir",
    "replace_durable", "rename_noreplace",
    "open_regular_pinned", "stat_owner_pinned", "remove_pinned",
    "fsync_file", "fsync_dir", "list_pinned",
)
#: `HopFsOps`'s non-method members.
HOPFSOPS_ATTRIBUTES = ("NOT_YET", "UnsafeRead", "ListingTooLarge")
#: `HopFsOps` methods an optional factory's objects rely on, with the minor
#: that introduces each. `HOPFSOPS_METHODS` (the `(3, 0)` set) is unchanged.
#: `stat_group_pinned(dir_fd, name) -> (uid, gid, mode, kind)`: exactly
#: `stat_owner_pinned`'s semantics (one NON-following stat of `name` in the
#: bound `dir_fd`, `mode` the `S_IMODE`, `kind` "file" / "dir" / "other", a
#: missing name a raw `FileNotFoundError`), plus that same stat's `st_gid`.
HOPFSOPS_OPTIONAL_METHODS: Mapping[str, Tuple[int, int]] = {"stat_group_pinned": (3, 1)}


@runtime_checkable
class KeyOps(Protocol):
    """The signing key, as the signer receives it. The implementation reads
    the key through a pinned, owner-checked read (mode 0400, owned by this
    runtime's uid) and hands over BYTES; the signer never opens a path, and
    an out-of-process signer receives the key over a pipe descriptor, never
    a path. One Ed25519 key per host.

    `signing_key()` is the 32-byte Ed25519 private seed. `key_id()` is the
    key's identifier, fingerprint-derived and so globally unique."""

    def signing_key(self) -> bytes: ...
    def key_id(self) -> str: ...


@runtime_checkable
class Signer(Protocol):
    """`sign(msg)` is a 64-byte Ed25519 signature over exactly `msg`.
    `key_id` names the key it signs with."""

    key_id: str

    def sign(self, msg: bytes) -> bytes: ...


@runtime_checkable
class Verifier(Protocol):
    """`verify(pub, msg, sig)` is strict RFC 8032 Ed25519 verification: it
    rejects S >= L and non-canonical point encodings, and never raises for
    a bad signature (it returns False). Key-table validation (canonical,
    not small order, unique key ids, ordered validity) happens when the
    table is LOADED, not here."""

    def verify(self, pub: bytes, msg: bytes, sig: bytes) -> bool: ...


#: The plugin's settings: what the runtime chooses to hand a factory.
Settings = Mapping[str, Any]

# The factory signatures (contract §6.2 P4). Each takes only the settings
# and the one port it needs.
MakeSender = Callable[[Settings, HopFsOps], TransportPort]
MakeIntakeReader = Callable[[Settings, HopFsOps], InboundPort]
MakeUpstreamMarkerStore = Callable[[Settings, HopFsOps], UpstreamMarkers]
MakeSigner = Callable[[Settings, KeyOps], Signer]
MakeVerifier = Callable[[Settings], Verifier]
#: The sibling runtime's factories. What they return is that runtime's
#: concern, so this module types the call, not the result.
MakeHopReceiver = Callable[[Settings, HopFsOps], Any]
MakeIntakeWriter = Callable[[Settings, HopFsOps], Any]
MakeMarkerStore = Callable[[Settings, HopFsOps], Any]
MakeHopSender = Callable[[Settings, HopFsOps], Any]

#: Every factory a plugin may define, with the port it receives (None for
#: settings only). This runtime calls the first five; the sibling runtime
#: calls the rest.
FACTORY_PORTS: Mapping[str, Optional[str]] = {
    "make_sender": "HopFsOps",
    "make_intake_reader": "HopFsOps",
    "make_upstream_marker_store": "HopFsOps",
    "make_signer": "KeyOps",
    "make_verifier": None,
    "make_hop_receiver": "HopFsOps",
    "make_intake_writer": "HopFsOps",
    "make_marker_store": "HopFsOps",
    "make_hop_sender": "HopFsOps",
}


class NullTransport:
    """The plugin in force when none is configured: every factory returns
    `None`, so the drain runs with `transport=None` exactly as it did before
    plugins existed (module docstring, NULL, NOT ABSENT)."""

    path: Optional[str] = None
    sha256: Optional[str] = None
    api: Tuple[int, int] = PLUGIN_API
    #: No optional capability: a null transport removes nothing.
    optional_capabilities: frozenset = frozenset()

    def make_sender(self, settings: Settings, fsops: Optional[HopFsOps]) -> None:
        return None

    def make_intake_reader(self, settings: Settings, fsops: Optional[HopFsOps]) -> None:
        return None

    def make_upstream_marker_store(self, settings: Settings,
                                   fsops: Optional[HopFsOps]) -> None:
        return None


@dataclass(frozen=True)
class LoadedPlugin:
    """A plugin that passed every check. Its factories are the callables
    its pinned bytes defined; nothing else of it is reachable."""

    path: str
    sha256: str
    api: Tuple[int, int]
    namespace: Mapping[str, Any]
    #: The optional factories this plugin offers and this runtime will call.
    optional_capabilities: frozenset = frozenset()

    def _factory(self, name: str) -> Callable[..., Any]:
        return self.namespace[name]

    def make_intake_remover(self, settings: Settings, fsops: HopFsOps) -> "IntakeRemover":
        """The optional remover. Raises `AttributeError` when the capability
        is off: the plugin is below `(3, 1)`, or does not define it."""
        if "make_intake_remover" not in self.optional_capabilities:
            raise AttributeError("the transport plugin offers no make_intake_remover")
        return self._factory("make_intake_remover")(settings, fsops)

    def make_sender(self, settings: Settings, fsops: HopFsOps) -> TransportPort:
        return self._factory("make_sender")(settings, fsops)

    def make_intake_reader(self, settings: Settings, fsops: HopFsOps) -> InboundPort:
        return self._factory("make_intake_reader")(settings, fsops)

    def make_upstream_marker_store(self, settings: Settings,
                                   fsops: HopFsOps) -> UpstreamMarkers:
        return self._factory("make_upstream_marker_store")(settings, fsops)


# --------------------------------------------------------------------------
# This runtime's side of the 3.0 rules: the checks a caller runs on what a
# plugin hands it, and the one classifier for what a plugin raises.
# --------------------------------------------------------------------------

#: Why a plugin object's vocabulary was refused at construction.
SEAM_REFUSAL_REASONS = ("reader_vocabulary", "marker_vocabulary", "fsops_vocabulary")


class SeamRefused(Exception):
    """A plugin object (or a `HopFsOps`) offered a refusal class that breaks
    the disjointness rule. `reason` is one of `SEAM_REFUSAL_REASONS`. The
    object is not used and nothing is cached."""

    def __init__(self, reason: str, detail: str):
        assert reason in SEAM_REFUSAL_REASONS, reason
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def check_list_args(limit: Any, after: Any) -> None:
    """`limit` an int (never a bool) with 1 <= limit <= LIST_LIMIT_MAX, and
    `after` None or a str; anything else is `ValueError`. Refused, never
    clamped."""
    if type(limit) is not int or not 1 <= limit <= LIST_LIMIT_MAX:
        raise ValueError(f"limit must be an int in 1..{LIST_LIMIT_MAX}, not {limit!r}")
    if after is not None and type(after) is not str:
        raise ValueError(f"after must be None or a str, not {type(after).__name__}")


def check_retired_at(value: Any) -> str:
    """`value` if it is this router's `utc_ts` form (`RETIRED_AT_RE`, ASCII
    digits only) and a real instant; else `ValueError`."""
    if type(value) is not str or not RETIRED_AT_RE.fullmatch(value):
        raise ValueError(f"retired_at {value!r} is not a utc_ts (YYYY-MM-DDTHH:MM:SSZ)")
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return value


def check_disjoint(cls: Any, bases: Sequence[type]) -> type:
    """`cls` if it is a proper subclass of `Exception` and, for EACH base,
    neither a subclass nor a superclass of it (two-way disjoint), so a
    verdict can never also be an I/O failure, whatever the catch order.
    Otherwise `TypeError`."""
    if not (isinstance(cls, type) and issubclass(cls, Exception) and cls is not Exception):
        raise TypeError(f"{cls!r} is not a proper subclass of Exception")
    for base in bases:
        if issubclass(cls, base) or issubclass(base, cls):
            raise TypeError(f"{cls.__name__} is not disjoint from {base.__name__}")
    return cls


def capture_verdict_class(obj: Any, attribute: str, fsops: Any, reason: str) -> type:
    """The refusal class `obj.<attribute>`, checked ONCE and returned for the
    caller to keep: later dispatch uses the captured class, never a fresh
    lookup, so a class swapped onto the object afterwards changes nothing.
    The check is `check_disjoint` against the COMPLETE set the classifier
    tells it apart from: `OSError` and both of the runtime's own classes
    (`fsops.UnsafeRead`, `fsops.ListingTooLarge`), so no runtime exception
    can ever be read as this verdict, nor this verdict as a runtime one. A
    missing or non-disjoint class raises `SeamRefused(reason)`."""
    try:
        bases = (OSError, fsops.UnsafeRead, fsops.ListingTooLarge)
        return check_disjoint(getattr(obj, attribute), bases)
    except (AttributeError, TypeError) as e:
        raise SeamRefused(reason, f"{attribute}: {e}") from None


#: The ROLES of the runtime's own classes, as `classify` reports them. The
#: Protocol fixes the attribute's role, not the implementation class's name,
#: so a conforming `HopFsOps` may call its class anything.
RUNTIME_ROLES = ("unsafe_read", "listing_too_large")


def check_fsops_classes(fsops: Any) -> Tuple[Tuple[type, str], Tuple[type, str]]:
    """The runtime's own classes with their roles, `((UnsafeRead,
    "unsafe_read"), (ListingTooLarge, "listing_too_large"))`, ready for
    `classify(runtime=...)`; `ListingTooLarge` two-way disjoint from
    `OSError` and `UnsafeRead`."""
    try:
        unsafe = fsops.UnsafeRead
        too_large = check_disjoint(fsops.ListingTooLarge, (OSError, unsafe))
    except (AttributeError, TypeError) as e:
        raise SeamRefused("fsops_vocabulary", str(e)) from None
    return (unsafe, "unsafe_read"), (too_large, "listing_too_large")


def is_current_bundle_schema(value: Any) -> bool:
    """A notice bundle's `schema` is accepted only at `NOTICE_BUNDLE_SCHEMA`."""
    return value == NOTICE_BUNDLE_SCHEMA


#: `classify`'s kinds, in the order it tries them (module docstring).
CLASSES = ("verdict", "runtime", "reason", "oserror", "other")


def classify(exc: BaseException, *,
             verdicts: Sequence[Tuple[type, Optional[Sequence[str]]]] = (),
             runtime: Sequence[Tuple[type, str]] = ()) -> Tuple[str, Optional[str]]:
    """What `exc`, raised by a plugin object, IS, as `(kind, detail)`:

      * `("verdict", reason)` for an instance of a captured verdict class
        whose `.reason` is in that class's reasons (or any reason, when the
        class has none: `None`); a verdict class with an unknown reason is
        `("other", None)`, never a verdict;
      * `("runtime", role)` for an instance of one of the runtime's own
        classes, `role` from `RUNTIME_ROLES` as `check_fsops_classes` pairs
        them (never the class's own name), whatever its `.reason`;
      * `("reason", reason)` for a `.reason` in `TRANSPORT_REASONS`;
      * `("oserror", errno name or None)` for an `OSError`;
      * `("other", None)` for anything else."""
    for cls, reasons in verdicts:
        if isinstance(exc, cls):
            reason = getattr(exc, "reason", None)
            if reasons is None or reason in reasons:
                return "verdict", reason
            return "other", None
    for cls, role in runtime:
        if isinstance(exc, cls):
            return "runtime", role
    reason = getattr(exc, "reason", None)
    if type(reason) is str and reason in TRANSPORT_REASONS:
        return "reason", reason
    if isinstance(exc, OSError):
        return "oserror", errno.errorcode.get(exc.errno) if exc.errno else None
    return "other", None


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _check_path(path: str, forbidden_roots: Iterable[Path],
                trusted_uids: Tuple[int, ...]) -> Path:
    if not os.path.isabs(path):
        raise PluginRefused("path_not_absolute", f"{path!r} is not absolute")
    # The RAW string, never a normalised copy (module docstring, step 1).
    if os.path.realpath(path) != path:
        raise PluginRefused("path_not_canonical",
                            f"{path!r} is not its own realpath: a symlinked component, "
                            "or a spelling such as '..', '.', '//' or a trailing '/'")
    p = Path(path)
    for root in forbidden_roots:
        r = Path(os.path.realpath(root))
        if _is_within(p, r):
            raise PluginRefused("agent_reachable", f"{path!r} is inside {str(r)!r}")
    d = p.parent
    while True:
        try:
            st = os.lstat(d)
        except OSError as e:
            raise PluginRefused("missing", f"{str(d)!r}: {e.strerror}") from e
        if st.st_uid not in trusted_uids:
            raise PluginRefused("parent_owner", f"{str(d)!r} is owned by uid {st.st_uid}")
        if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
            raise PluginRefused("parent_writable",
                                f"{str(d)!r} is writable by others (mode {oct(st.st_mode & 0o7777)})")
        if d.parent == d:
            break
        d = d.parent
    return p


def _read_pinned(p: Path, trusted_uids: Tuple[int, ...]) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(p), flags)
    except FileNotFoundError as e:
        raise PluginRefused("missing", f"{str(p)!r} does not exist") from e
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise PluginRefused("symlink", f"{str(p)!r} is a symlink") from e
        raise PluginRefused("missing", f"{str(p)!r}: {e.strerror}") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PluginRefused("not_regular", f"{str(p)!r} is not a regular file")
        if st.st_uid not in trusted_uids:
            raise PluginRefused("owner", f"{str(p)!r} is owned by uid {st.st_uid}")
        if stat.S_IMODE(st.st_mode) not in (0o444, 0o644):
            raise PluginRefused("mode", f"{str(p)!r} has mode {oct(stat.S_IMODE(st.st_mode))}; "
                                "0444 or 0644 required")
        if st.st_size > MAX_PLUGIN_BYTES:
            raise PluginRefused("too_large", f"{str(p)!r} is {st.st_size} bytes")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PLUGIN_BYTES:
                raise PluginRefused("too_large", f"{str(p)!r} grew past {MAX_PLUGIN_BYTES} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_plugin(
    path: str, sha256: str, *,
    forbidden_roots: Iterable[Path] = (),
    required_factories: Sequence[str] = REQUIRED_FACTORIES,
    api: Tuple[int, int] = PLUGIN_API,
    trusted_uids: Tuple[int, ...] = TRUSTED_UIDS,
    required_minor: int = REQUIRED_MINOR,
    optional_factories: Mapping[str, Tuple[Tuple[int, int], Optional[str]]] = OPTIONAL_FACTORIES,
) -> LoadedPlugin:
    """Load the plugin at `path`, whose bytes must hash to `sha256`
    (lowercase hex). Every check in the module docstring, in that order;
    the first failure raises `PluginRefused`. `forbidden_roots` are the
    directories an agent can reach (every instance root)."""
    p = _check_path(path, forbidden_roots, trusted_uids)
    data = _read_pinned(p, trusted_uids)
    digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(digest, sha256.lower()):
        raise PluginRefused("hash_mismatch", f"{str(p)!r} hashes to {digest}, not the pinned value")
    namespace: dict = {"__name__": "amap_transport_plugin", "__file__": str(p)}
    try:
        code = compile(data, str(p), "exec", dont_inherit=True)
        exec(code, namespace)  # noqa: S102 -- the pinned, hashed bytes, by design
    except Exception as e:  # noqa: BLE001 -- any failure is a refusal
        raise PluginRefused("exec_failed", f"{type(e).__name__}: {e}") from e
    got = namespace.get("PLUGIN_API")
    if not (isinstance(got, tuple) and len(got) == 2
            and all(isinstance(x, int) and not isinstance(x, bool) for x in got)):
        raise PluginRefused("api_mismatch", f"PLUGIN_API is {got!r}, not a (major, minor) pair")
    if got[0] != api[0] or got[1] < required_minor:
        raise PluginRefused("api_mismatch", f"PLUGIN_API {got} is incompatible with {api} "
                                            f"(major {api[0]}, minor at least {required_minor})")
    for name in required_factories:
        if not callable(namespace.get(name)):
            raise PluginRefused("missing_factory", f"the plugin defines no callable {name!r}")
    capabilities = set()
    for name, (since, _port) in sorted(optional_factories.items()):
        if got < since:
            # Below the factory's minor the name is IGNORED, whatever it is:
            # never type-checked and never called.
            if name in namespace:
                _logger.info("transport plugin: %s is ignored below PLUGIN_API %s (the "
                            "plugin is %s)", name, since, got)
            continue
        if name not in namespace:
            continue
        if not callable(namespace[name]):
            raise PluginRefused("missing_factory", f"the plugin's {name!r} is not callable")
        capabilities.add(name)
    return LoadedPlugin(path=str(p), sha256=digest, api=got,
                        namespace=types.MappingProxyType(namespace),
                        optional_capabilities=frozenset(capabilities))


@dataclass(frozen=True)
class DelegationCapabilities:
    """What `check_delegation` proved a plugin offers: the four factories,
    and the exact exception classes, validated, as a read-only mapping."""
    make_signer: Callable[..., Any]
    make_verifier: Callable[..., Any]
    make_peer_codec: Callable[..., Any]
    errors: Mapping[str, type]


def _builtin_classes() -> frozenset:
    return frozenset(v for v in vars(builtins).values() if isinstance(v, type))


def check_delegation(plugin: "LoadedPlugin") -> DelegationCapabilities:
    """The delegation load rule (module docstring, API 3.3), or
    `PluginRefused("delegation_capability_missing")` naming the check that
    failed. Called only with `delegation` configured. Calls
    `make_peer_errors()`, with no arguments, exactly once."""
    def refuse(why: str) -> PluginRefused:
        return PluginRefused("delegation_capability_missing", why)

    api = tuple(plugin.api)
    if api < DELEGATION_MINOR:
        raise refuse(f"PLUGIN_API {api} is below {DELEGATION_MINOR}")
    ns = plugin.namespace
    for name in DELEGATION_FACTORIES:
        if not callable(ns.get(name)):
            raise refuse(f"the plugin defines no callable {name!r}")
    meta = ns.get("OPTIONAL_FACTORIES")
    if type(meta) is not dict:
        raise refuse("the plugin's OPTIONAL_FACTORIES is not a dict")
    for name in ("make_peer_codec", "make_peer_errors"):
        since = meta.get(name)
        if not (type(since) is tuple and len(since) == 2
                and all(type(x) is int for x in since)):
            raise refuse(f"the plugin's OPTIONAL_FACTORIES does not declare {name!r} "
                         "as a (major, minor) pair")
        if since < DELEGATION_MINOR:
            raise refuse(f"the plugin's OPTIONAL_FACTORIES declares {name!r} at {since}, "
                         f"below {DELEGATION_MINOR}")
    try:
        errors = ns["make_peer_errors"]()
    except Exception as e:  # noqa: BLE001 -- any failure is a refusal
        raise refuse(f"make_peer_errors() raised {type(e).__name__}") from None
    if not isinstance(errors, Mapping) or set(errors) != set(PEER_ERROR_NAMES):
        raise refuse(f"make_peer_errors() does not return exactly {list(PEER_ERROR_NAMES)}")
    classes = [errors[n] for n in PEER_ERROR_NAMES]
    builtin = _builtin_classes()
    for n, cls in zip(PEER_ERROR_NAMES, classes):
        if not (isinstance(cls, type) and issubclass(cls, Exception)):
            raise refuse(f"make_peer_errors()[{n!r}] is not an exception class")
        if cls in builtin:
            raise refuse(f"make_peer_errors()[{n!r}] is a built-in exception class")
    for i, a in enumerate(classes):
        for b in classes[i + 1:]:
            if a is b or issubclass(a, b) or issubclass(b, a):
                raise refuse("make_peer_errors()'s classes are not pairwise distinct and "
                             "unrelated")
    return DelegationCapabilities(
        make_signer=ns["make_signer"], make_verifier=ns["make_verifier"],
        make_peer_codec=ns["make_peer_codec"],
        errors=types.MappingProxyType(dict(zip(PEER_ERROR_NAMES, classes))))
