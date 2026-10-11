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
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import stat
import types
from dataclasses import dataclass
from pathlib import Path
from typing import (Any, Callable, Iterable, Literal, Mapping, Optional, Protocol,
                    Sequence, Tuple, Union, runtime_checkable)

#: `(major, minor)`. A plugin must have the same major and at least this
#: minor. The MAJOR covers every interface in this module that crosses the
#: seam: `TransportPort`, `InboundPort`, `HopFsOps`, `KeyOps`, `Signer`,
#: `Verifier` and the factory signatures. Changing any of them (a method,
#: a parameter, a return vocabulary) is a major bump; adding an optional
#: factory is a minor one. `(2, 0)` is amendment E5: `HopFsOps` gained
#: `open_private_stage_dir`, `commit_durable`'s keyword-only `deps` and the
#: `UnsafeRead` attribute, so a `(1, x)` plugin is refused here and a
#: `(2, x)` plugin by a `(1, x)` runtime, before any factory is called.
PLUGIN_API: Tuple[int, int] = (2, 0)

#: The factories this runtime calls. A plugin may define more; it must
#: define these. `make_sender(settings, fsops) -> TransportPort` and
#: `make_intake_reader(settings, fsops) -> InboundPort`.
REQUIRED_FACTORIES: Tuple[str, ...] = ("make_sender", "make_intake_reader")

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
    "fsops_unavailable", "role_mismatch",
)
# `role_mismatch` is the sibling runtime's: its link role and its plugin pin
# disagree, in either direction. This router has no link role and never
# raises it; the reason is listed so both loaders share one vocabulary.


class PluginRefused(Exception):
    """The plugin was not loaded. `reason` is one of `REFUSAL_REASONS`.
    Startup stops: there is no degraded mode in either direction."""

    def __init__(self, reason: str, detail: str):
        assert reason in REFUSAL_REASONS, reason
        super().__init__(f"transport plugin refused ({reason}): {detail}")
        self.reason = reason
        self.detail = detail


class TransportPort(Protocol):
    """The transport, as the in-flight state machine needs it
    (`router/inflight.py`, its module docstring's table). Every method takes
    the transport req_id `n` this router allocated.

    `has_pending(n)` is true while request `n` has been handed over and the
    downstream runtime has neither archived it nor written its result,
    WHETHER OR NOT the downstream runtime has claimed it. A claimed request
    is still pending: the in-flight step must not read "claimed" as gone,
    or it would hand the request over again or settle it as an anomaly.

    `write_request(n, data)` hands request `n` over. It is called at most
    once per `n` by a correct caller and must never overwrite: a request
    already present under `n`, in any state, is an error."""

    def has_result(self, n: str) -> bool: ...
    def has_pending(self, n: str) -> bool: ...
    def has_archived(self, n: str) -> bool: ...
    def read_result(self, n: str) -> bytes: ...
    def write_request(self, n: str, data: bytes) -> None: ...


class InboundPort(Protocol):
    """What arrives from the transport for this router to place: notices,
    signed candidates, and entries no live tree could be found for.
    `kind` is one of `INBOUND_KINDS`. `list_entries(kind)` names the entries
    ready to read, in arrival order; `read_entry(kind, entry_id)` returns
    one entry's bytes, which are HOSTILE input to the caller.
    `entry_id`s are opaque to this router and unique within a kind."""

    def list_entries(self, kind: str) -> Sequence[str]: ...
    def read_entry(self, kind: str, entry_id: str) -> bytes: ...


#: The kinds an `InboundPort` serves.
INBOUND_KINDS = ("notice", "candidate", "unresolved")


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
#: `fsops.UnsafeRead.reason`: exactly one of these (`HopFsOps`, READS).
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
    sentinel's. For each one the implementation checks:

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
    the result, on every path. A failure RAISES the implementation's
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
    descriptor is pinned once; only a stage opened this way is accepted by
    `commit_durable`, whose same-tree rule then confines it to its own
    private tree. `.stage/` is never a destination and must never be swept
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
      * `fsync_file`, `fsync_dir`: exactly what they say."""

    #: This implementation's "committed not yet" result (above).
    NOT_YET: object
    #: This implementation's refusal class for `open_regular_pinned` (READS).
    UnsafeRead: type

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


#: `HopFsOps`'s methods, in the contract's order (B §e.2, as amended by E5).
#: Methods only: its attributes are `HOPFSOPS_ATTRIBUTES`.
HOPFSOPS_METHODS = (
    "open_root_nofollow", "descend_pinned", "mkdir_and_pin", "stage_tree",
    "commit_durable", "open_stage_dir", "open_private_stage_dir",
    "replace_durable", "rename_noreplace",
    "open_regular_pinned", "stat_owner_pinned", "remove_pinned",
    "fsync_file", "fsync_dir",
)
#: `HopFsOps`'s non-method members.
HOPFSOPS_ATTRIBUTES = ("NOT_YET", "UnsafeRead")


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
MakeSigner = Callable[[Settings, KeyOps], Signer]
MakeVerifier = Callable[[Settings], Verifier]
#: The sibling runtime's factories. What they return is that runtime's
#: concern, so this module types the call, not the result.
MakeHopReceiver = Callable[[Settings, HopFsOps], Any]
MakeIntakeWriter = Callable[[Settings, HopFsOps], Any]
MakeMarkerStore = Callable[[Settings, HopFsOps], Any]
MakeHopSender = Callable[[Settings, HopFsOps], Any]

#: Every factory a plugin may define, with the port it receives (None for
#: settings only). This runtime calls the first four; the sibling runtime
#: calls the rest.
FACTORY_PORTS: Mapping[str, Optional[str]] = {
    "make_sender": "HopFsOps",
    "make_intake_reader": "HopFsOps",
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

    def make_sender(self, settings: Settings, fsops: Optional[HopFsOps]) -> None:
        return None

    def make_intake_reader(self, settings: Settings, fsops: Optional[HopFsOps]) -> None:
        return None


@dataclass(frozen=True)
class LoadedPlugin:
    """A plugin that passed every check. Its factories are the callables
    its pinned bytes defined; nothing else of it is reachable."""

    path: str
    sha256: str
    api: Tuple[int, int]
    namespace: Mapping[str, Any]

    def _factory(self, name: str) -> Callable[..., Any]:
        return self.namespace[name]

    def make_sender(self, settings: Settings, fsops: HopFsOps) -> TransportPort:
        return self._factory("make_sender")(settings, fsops)

    def make_intake_reader(self, settings: Settings, fsops: HopFsOps) -> InboundPort:
        return self._factory("make_intake_reader")(settings, fsops)


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
    if got[0] != api[0] or got[1] < api[1]:
        raise PluginRefused("api_mismatch", f"PLUGIN_API {got} is incompatible with {api}")
    for name in required_factories:
        if not callable(namespace.get(name)):
            raise PluginRefused("missing_factory", f"the plugin defines no callable {name!r}")
    return LoadedPlugin(path=str(p), sha256=digest, api=got,
                        namespace=types.MappingProxyType(namespace))
