"""router/fsops.py — this router's implementation of `transport.HopFsOps`.

Every filesystem operation a transport plugin may perform goes through an
instance of `FsOps`, on descriptors it pinned. The Protocol, its result
vocabularies and the invariants owed are in `router/transport.py`; this
module keeps them. `service.start_transport` builds one per process, for
the configured hop root, and hands it to the plugin's factories.

ROOTS. An `FsOps` knows the directories it may open, by kind:

  * `hop_root`: the hop tree (contract §4.1). Under it, `.unresolved/` and
    `.control/` are host intakes, `<logical_id>/<gen>/` and
    `.runtime/<gen>/` are generation trees, and a staging subtree made by
    `stage_tree` is a generation tree that is not yet published;
  * `private_roots`: this writer's own state directories, each one tree.
    Each has one writer-private stage, `<root>/.stage/`, from
    `open_private_stage_dir`, so `commit_durable` publishes into a private
    tree exactly as into a hop tree (contract amendment E5). A link count
    of 2 in a private tree still RAISES on read: NOT_YET stays on hop trees
    and host intakes, and a private writer completes its recovery before it
    reads.

The roots must be pairwise disjoint (none equal to or containing another),
or construction raises: a nested root's `.stage/` would otherwise be an
ordinary path inside the outer tree. `open_root_nofollow` refuses any other
path. There is no "anywhere" mode.

BINDINGS, AND THE DESTINATION TAG. Every directory descriptor this module
returns is registered with a binding: the tree it is in (identified by the
tree root's device and inode, never by a path), its path RELATIVE TO THAT
TREE ROOT, and its own device, inode and owner. A descriptor not handed out
by this instance has no binding and is refused; so is one whose live
`fstat` no longer matches (closed, and the number reused for another
directory). Two bindings resolving to one directory with different
relative paths are ambiguous and refused.

`commit_durable`'s stage name is `<dest-tag>.<name>`, and the tag is
derived from the destination's relative path alone: each component as
`<length>-<component>`, joined by `.`. So the tag:

  * is the same after a restart and through any equivalent opening (it
    depends on nothing but the tree's own layout);
  * differs for every distinct destination in one tree, per-item
    directories included (`outbound/req-00000001.attachments` and
    `outbound/req-00000002.attachments` differ), and the length prefixes
    make the encoding unambiguous although names may contain `.`;
  * keeps an admitted tree's roles: paths are relative to the tree root,
    and the staging root IS the tree root, so publishing it by a rename
    changes no tag.

DURABILITY. Every barrier the Protocol states is taken here, and a failed
barrier raises. These are the barriers this process owes; whether a power
loss preserves them also depends on the filesystem honouring fsync, which
the startup capability probe (`probe`) checks only as far as a running
process can. Nothing here claims more.

LIMITS. `rename_noreplace` needs `renameat2` (Linux, glibc 2.28 or later)
and a filesystem that honours `RENAME_NOREPLACE`. There is no fallback:
link-then-unlink would let a concurrent claim and withdraw both succeed.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import heapq
import re
import fcntl
import logging
import os
import secrets
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from . import transport as transport_mod

logger = logging.getLogger("amap_router_local.fsops")

#: Directory components never valid as a single path component.
_BAD_NAMES = {"", ".", ".."}

#: NAME_MAX for the filesystems this runs on.
NAME_MAX = 255

#: The host intakes under the hop root (contract §4.1).
INTAKES = (".unresolved", ".control")
#: The runtime's own generation trees live under this name instead of a
#: logical_id.
RUNTIME_DIR = ".runtime"

_RENAME_NOREPLACE = 1  # <linux/fs.h>


class FsOpsError(Exception):
    """A refusal by this module: an unknown, stale or ambiguous binding, a
    bad name, or an invariant the caller broke. Never a partial success."""


class BindingError(FsOpsError):
    """The descriptor has no binding, a stale one, or an ambiguous one."""


class NoReplaceUnsupported(OSError):
    """`RENAME_NOREPLACE` cannot be honoured here. No fallback exists."""


class CapabilityError(Exception):
    """The startup probe found a guarantee missing. Refuse to start."""


#: `UnsafeRead.reason` values (`transport.UNSAFE_READ_REASONS`).
UNSAFE_READ_REASONS = ("not_regular", "link_count", "too_large")


class UnsafeRead(FsOpsError):
    """`open_regular_pinned` refused the file for what it IS: `.reason` is
    exactly one of `UNSAFE_READ_REASONS`. Exposed as `FsOps.UnsafeRead`, the
    Protocol attribute, so a caller dispatches on `isinstance` and `.reason`
    and never on this module's name. Any other failure of the read is not
    this class: a missing name is a raw `FileNotFoundError`, and anything
    else (EACCES, EIO, ...) propagates as itself."""

    def __init__(self, reason: str, detail: str):
        if reason not in UNSAFE_READ_REASONS:
            raise ValueError(f"unknown UnsafeRead reason {reason!r}")
        super().__init__(detail)
        self.reason = reason


#: Errnos from the single-component `O_NOFOLLOW | O_NONBLOCK` open that name
#: what the entry is: ELOOP for a symlink, ENXIO for a socket.
_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO})


#: Errnos on the canonical walk that mean the binding is no longer at its
#: path (gone, a symlink, not a directory). Anything else propagates.
_WALK_MOVED = frozenset({errno.ENOENT, errno.ELOOP, errno.ENOTDIR})


#: `DependencyAnomaly.cause` values (`transport.HopFsOps`, DEPENDENCIES).
DEPENDENCY_CAUSES = ("binding_moved", "missing", "not_regular", "link_count",
                     "size", "digest")


class ListingTooLarge(Exception):
    """`list_pinned` visited more than `transport.LIST_SCAN_MAX` names and
    stopped. Exposed as `FsOps.ListingTooLarge`, the Protocol attribute. It
    is deliberately NOT an `OSError` and not related to `UnsafeRead` either
    way, so a caller can never mistake it for an I/O failure or a refused
    read (`transport.check_fsops_classes`)."""


class _Larger:
    """A max-heap key for `str`: `heapq` keeps the SMALLEST names by holding
    the largest on top, so a scan keeps at most `k` of them."""

    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name

    def __lt__(self, other: "_Larger") -> bool:
        return self.name > other.name


class DependencyAnomaly(FsOpsError):
    """A `commit_durable` dependency failed its check: `.cause` is one of
    `DEPENDENCY_CAUSES`, `.index` its position in `deps`. Raised instead of
    any result; the stage is kept."""

    def __init__(self, cause: str, index: int, name: str, detail: str):
        if cause not in DEPENDENCY_CAUSES:
            raise ValueError(f"unknown dependency anomaly cause {cause!r}")
        super().__init__(f"dependency {index} ({name!r}): {cause}: {detail}")
        self.cause = cause
        self.index = index
        self.name = name


class MkdirRefused(FsOpsError):
    """`mkdir_and_pin`'s final-`fstat` predicate failed (`transport.HopFsOps`,
    `mkdir_and_pin`). The directory is left as it is, never repaired."""


class _NotYet:
    __slots__ = ()

    def __repr__(self) -> str:
        return "NOT_YET"


#: The one NOT_YET object this implementation returns.
NOT_YET = _NotYet()


# ---------------------------------------------------------------------------
# renameat2
# ---------------------------------------------------------------------------

_renameat2 = None
_renameat2_looked_up = False


def _libc_renameat2():
    global _renameat2, _renameat2_looked_up
    if not _renameat2_looked_up:
        _renameat2_looked_up = True
        try:
            fn = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
        except OSError:
            fn = None
        if fn is not None:
            fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint]
            fn.restype = ctypes.c_int
        _renameat2 = fn
    return _renameat2


def _sys_renameat2(src_fd: int, src: str, dst_fd: int, dst: str, flags: int) -> None:
    fn = _libc_renameat2()
    if fn is None:
        raise OSError(errno.ENOSYS, "renameat2 is not available in this C library")
    if fn(src_fd, os.fsencode(src), dst_fd, os.fsencode(dst), flags) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------

#: Kinds of tree a binding can be in.
HOP_ROOT = "hop-root"            # the hop root itself, and `<logical_id>/` dirs
GENERATION = "generation"        # a generation tree, published or staging
INTAKE = "intake"                # a host intake
PRIVATE = "private"              # one of this writer's private roots


@dataclass(frozen=True)
class Binding:
    """Where a pinned directory is. `tree` is the tree root's (dev, ino);
    `rel` the path from it. `dev`, `ino` and `uid` are the directory's
    own, as registered."""
    kind: str
    tree: Tuple[int, int]
    rel: Tuple[str, ...]
    dev: int
    ino: int
    uid: int

    @property
    def tag(self) -> str:
        return dest_tag(self.rel)

    @property
    def is_stage(self) -> bool:
        if self.kind == GENERATION:
            return self.rel in (("up", "stage"), ("down", "stage"))
        if self.kind in (INTAKE, PRIVATE):
            return self.rel == (".stage",)
        return False

    @property
    def trusted_links(self) -> bool:
        """Whether a link count of 2 is a commit in flight (NOT_YET) here."""
        return self.kind in (GENERATION, INTAKE)


#: What a destination-tag component may contain (the Protocol's tag grammar).
_TAG_COMPONENT = re.compile(r"[A-Za-z0-9._-]+\Z")


def dest_tag(rel: Sequence[str]) -> str:
    """The destination tag for a relative path: each component as
    `<length in bytes>-<component>`, joined by `.`; the tree root itself is
    `0-`. Components must match `[A-Za-z0-9._-]+` (BindingError otherwise),
    so the tag does too, and the length prefixes keep it unambiguous though
    components may contain `.`."""
    if not rel:
        return "0-"
    for c in rel:
        if not _TAG_COMPONENT.fullmatch(c):
            raise BindingError(f"directory name {c!r} is outside the tag charset [A-Za-z0-9._-]")
    return ".".join(f"{len(c.encode('ascii'))}-{c}" for c in rel)


def _check_name(name: str) -> str:
    if (not isinstance(name, str) or name in _BAD_NAMES or "/" in name
            or "\0" in name or len(name.encode("utf-8", "surrogateescape")) > NAME_MAX):
        raise FsOpsError(f"not a single safe path component: {name!r}")
    return name


def _split_rel(rel: str) -> Tuple[str, ...]:
    parts = tuple(p for p in rel.split("/") if p != "")
    for p in parts:
        _check_name(p)
    return parts


class FsOps:
    """`transport.HopFsOps`, for this router. One instance per writer
    process; its bindings never outlive it, and a fresh instance derives
    the same tags (module docstring)."""

    NOT_YET = NOT_YET
    UnsafeRead = UnsafeRead
    ListingTooLarge = ListingTooLarge

    def __init__(self, *, hop_root: Optional[Union[str, Path]] = None,
                 private_roots: Iterable[Union[str, Path]] = ()):
        def canon(p) -> str:
            s = os.path.normpath(os.fspath(p))
            if not os.path.isabs(s):
                raise FsOpsError(f"root {s!r} is not absolute")
            return s

        self._hop_root = canon(hop_root) if hop_root is not None else None
        self._private_roots = tuple(canon(p) for p in private_roots)
        _check_disjoint(([self._hop_root] if self._hop_root is not None else [])
                        + list(self._private_roots))
        self._by_fd: Dict[int, Binding] = {}
        self._by_dir: Dict[Tuple[int, int], Binding] = {}
        self._stage_cache: Dict[Tuple[Tuple[int, int], str], int] = {}
        #: (dev, ino) of every stage directory `open_stage_dir` validated.
        #: Only those are accepted as `stage_dirfd`: a stage reached any other
        #: way (`descend_pinned` to `up/stage`) skipped the owner and 0700 check.
        self._validated_stages: set = set()
        self._lock = threading.RLock()
        self._dest_locks: Dict[Tuple[int, int], threading.Lock] = {}

    # -- the step seam ------------------------------------------------------

    def _step(self, label: str, **ctx) -> None:
        """Called at every recovery-relevant boundary. Does nothing; tests
        override it to crash or to look at the tree at that moment."""

    # -- registry -----------------------------------------------------------

    def _register(self, fd: int, kind: str, tree: Tuple[int, int],
                  rel: Tuple[str, ...]) -> Binding:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise BindingError("a binding must be a directory")
        b = Binding(kind, tree, rel, st.st_dev, st.st_ino, st.st_uid)
        # The tag is derived, and its charset and length checked, only when a
        # commit uses this directory as a destination (`commit_durable`), so
        # a stray out-of-charset directory blocks commits into it and never a
        # read-only walk past it.
        with self._lock:
            prior = self._by_dir.get((b.dev, b.ino))
            if prior is not None and (prior.kind, prior.tree, prior.rel) != (kind, tree, rel):
                if self._live(prior, exclude_fd=fd):
                    raise BindingError(
                        f"ambiguous binding: one directory as {'/'.join(prior.rel) or '.'} "
                        f"and as {'/'.join(rel) or '.'}")
                # No descriptor still holds the prior directory, so its inode
                # may have been freed and reused (ordinary per-item churn on
                # ext4 and xfs): the prior binding proves nothing. Drop it.
                self._forget(prior)
            self._by_dir[(b.dev, b.ino)] = b
            self._by_fd[fd] = b
        return b

    def _live(self, b: Binding, exclude_fd: int) -> bool:
        """Whether some descriptor still holds `b`'s directory. While one
        does, its inode cannot be freed, so a second binding to the same
        (dev, ino) really is the same directory under another path.
        `exclude_fd` is the descriptor being registered: if its number was
        recorded for `b` before, that record is stale (the number was closed
        and reused), so it cannot show `b` is still held."""
        for fd, other in list(self._by_fd.items()):
            # Every holder of the same directory counts, including an older,
            # equivalent Binding object from an earlier opening (Codex F3).
            if (other.dev, other.ino) != (b.dev, b.ino) or fd == exclude_fd:
                continue
            try:
                st = os.fstat(fd)
            except OSError:
                continue
            if (st.st_dev, st.st_ino) == (b.dev, b.ino) and st.st_nlink > 0:
                return True
        return False

    def _forget(self, b: Binding) -> None:
        """Drop every record of `b`'s directory: the canonical binding and
        every descriptor bound to it through any equivalent opening."""
        key = (b.dev, b.ino)
        self._by_dir.pop(key, None)
        for fd in [fd for fd, other in self._by_fd.items() if (other.dev, other.ino) == key]:
            del self._by_fd[fd]
        self._validated_stages.discard(key)

    def _forget_under(self, parent: Binding, name: str) -> None:
        """Drop every binding at or under `name` in `parent` (it is being
        removed)."""
        prefix = parent.rel + (name,)
        with self._lock:
            for b in [b for b in self._by_dir.values()
                      if b.kind == parent.kind and b.tree == parent.tree
                      and b.rel[:len(prefix)] == prefix]:
                self._forget(b)

    def binding(self, fd: int) -> Binding:
        """The live binding for `fd`, or BindingError. The live descriptor
        must still be the registered directory: same device and inode, a
        directory, the same owner."""
        with self._lock:
            b = self._by_fd.get(fd)
        if b is None:
            raise BindingError(f"fd {fd} was not opened through this FsOps")
        try:
            st = os.fstat(fd)
        except OSError as e:
            raise BindingError(f"fd {fd} is closed") from e
        if (st.st_dev, st.st_ino) != (b.dev, b.ino) or not stat.S_ISDIR(st.st_mode) \
                or st.st_uid != b.uid:
            raise BindingError(f"fd {fd} no longer refers to the directory it was bound to")
        return b

    def _classify_hop(self, parts: Tuple[str, ...], idents: List[Tuple[int, int]]
                      ) -> Tuple[str, Tuple[int, int], Tuple[str, ...]]:
        """(kind, tree, rel) for a path under the hop root, given the
        (dev, ino) of the root and each component walked."""
        if not parts:
            return HOP_ROOT, idents[0], ()
        if parts[0] in INTAKES:
            return INTAKE, idents[1], parts[1:]
        if len(parts) == 1:
            return HOP_ROOT, idents[0], parts
        return GENERATION, idents[2], parts[2:]

    def _child(self, parent: Binding, name: str, fd: int) -> Binding:
        """Register `fd`, the directory `name` under `parent`."""
        st = os.fstat(fd)
        here = (st.st_dev, st.st_ino)
        if parent.kind == HOP_ROOT:
            parts = parent.rel + (name,)
            if parts[0] in INTAKES and len(parts) == 1:
                return self._register(fd, INTAKE, here, ())
            if len(parts) == 1:
                return self._register(fd, HOP_ROOT, parent.tree, parts)
            return self._register(fd, GENERATION, here, ())
        return self._register(fd, parent.kind, parent.tree, parent.rel + (name,))

    # -- opening ------------------------------------------------------------

    def open_root_nofollow(self, path: str) -> int:
        """Open a configured root, or a directory under one, never following
        a symlink in the part below the root. Anything outside every
        configured root is refused."""
        p = os.path.normpath(os.fspath(path))
        roots = []
        if self._hop_root is not None:
            roots.append((self._hop_root, "hop"))
        roots.extend((r, "private") for r in self._private_roots)
        for root, kind in roots:
            if p == root or p.startswith(root.rstrip("/") + "/"):
                rel = _split_rel(p[len(root):])
                break
        else:
            raise BindingError(f"{p!r} is under no configured root")
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            idents = [(st.st_dev, st.st_ino)]
            for part in rel:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nfd
                st = os.fstat(fd)
                idents.append((st.st_dev, st.st_ino))
            if kind == "private":
                self._register(fd, PRIVATE, idents[0], rel)
            else:
                self._register(fd, *self._classify_hop(rel, idents))
        except BaseException:
            os.close(fd)
            raise
        return fd

    def descend_pinned(self, root_fd: int, rel: str) -> Optional[int]:
        """Walk `rel` from `root_fd`, `O_NOFOLLOW` at every component. None
        when a component is missing; a symlink or non-directory raises."""
        b = self.binding(root_fd)
        parts = _split_rel(rel)
        fd = os.dup(root_fd)
        cur = b
        try:
            for part in parts:
                try:
                    nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    os.close(fd)
                    return None
                os.close(fd)
                fd = nfd
                cur = self._child(cur, part, fd)
            if not parts:
                self._register(fd, b.kind, b.tree, b.rel)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        return fd

    def mkdir_and_pin(self, parent_fd: int, name: str, mode: int) -> int:
        """Create `name` if missing, pin it, check the final `fstat` of the
        pinned descriptor against one predicate, and fsync the parent either
        way (an earlier creator's fsync may have failed).

        A new directory is made with `mode & 0o777`. Only if the umask
        removed bits is it `fchmod`ed to `(its setgid bit) | (mode & 0o777)`,
        so an inherited setgid bit survives an ordinary umask. Then the
        FINAL `fstat` must show (`_mkdir_predicate`): a directory owned by
        this writer's uid, permission bits `mode & 0o777`, no setuid or
        sticky bit, and the pinned parent's own setgid bit. An existing
        directory is checked the same way and never repaired. The check is
        on the descriptor this call returns, never a by-name lookup, so a
        directory swapped in at the name cannot pass it for the one pinned."""
        parent = self.binding(parent_fd)
        _check_name(name)
        want = mode & 0o777
        created = True
        try:
            os.mkdir(name, want, dir_fd=parent_fd)
        except FileExistsError:
            created = False
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            if created:
                st = os.fstat(fd)
                if stat.S_IMODE(st.st_mode) & 0o777 != want:
                    os.fchmod(fd, (st.st_mode & stat.S_ISGID) | want)
            _mkdir_predicate(os.fstat(fd), want, os.fstat(parent_fd), name)
            os.fsync(parent_fd)
            self._child(parent, name, fd)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def stage_tree(self, parent_fd: int, staging_name: str) -> int:
        """Create a staging generation tree (its root, `up/` 0750 and
        `up/stage/` 0700) under a `<logical_id>/` directory, fsync it
        bottom-up and the parent, and return its root UNPUBLISHED. It never
        renames: the caller commits the identity marker inside, then
        publishes with `rename_noreplace`."""
        parent = self.binding(parent_fd)
        if parent.kind != HOP_ROOT or len(parent.rel) != 1 or parent.rel[0] in INTAKES:
            raise FsOpsError("stage_tree needs a <logical_id>/ directory under the hop root")
        _check_name(staging_name)
        os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
        root = os.open(staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                       dir_fd=parent_fd)
        try:
            os.mkdir("up", 0o750, dir_fd=root)
            up = os.open("up", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                os.chmod("up", 0o750, dir_fd=root)
                os.mkdir("stage", 0o700, dir_fd=up)
                os.chmod("stage", 0o700, dir_fd=up)
                sfd = os.open("stage", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=up)
                try:
                    os.fsync(sfd)  # its mode, after the chmod
                finally:
                    os.close(sfd)
                os.fsync(up)
            finally:
                os.close(up)
            os.fchmod(root, 0o3770)
            os.fsync(root)
            os.fsync(parent_fd)
            self._child(parent, staging_name, root)
        except BaseException:
            os.close(root)
            raise
        return root

    def open_stage_dir(self, tree_fd: int, side: str) -> int:
        """The writer-private 0700 stage directory for `side`
        (`transport.StageSide`), created durably if missing, validated
        otherwise, pinned once."""
        if side not in ("up", "down", "intake"):
            raise ValueError(f"unknown stage side {side!r}")
        tree = self.binding(tree_fd)
        if side in ("up", "down"):
            if tree.kind != GENERATION or tree.rel != ():
                raise ValueError(f"side {side!r} needs a generation tree root")
            marker, stage_name = side, "stage"
        else:
            if tree.kind != INTAKE or tree.rel != ():
                raise ValueError("side 'intake' needs a host intake directory")
            marker, stage_name = None, ".stage"
        key = (tree.tree, side)
        with self._lock:
            cached = self._stage_cache.get(key)
        if cached is not None:
            try:
                self.binding(cached)
                return cached
            except BindingError:
                pass
        if marker is not None:
            parent_fd = os.open(marker, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=tree_fd)
        else:
            parent_fd = os.dup(tree_fd)
        try:
            try:
                os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
                created = True
            except FileExistsError:
                created = False
            fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent_fd)
            try:
                st = os.fstat(fd)
                if created:
                    os.fchmod(fd, 0o700)
                    st = os.fstat(fd)
                if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                    raise FsOpsError(
                        f"stage directory is not this writer's 0700 directory "
                        f"(uid {st.st_uid}, mode {oct(stat.S_IMODE(st.st_mode))}); "
                        "refusing, never repairing")
                os.fsync(parent_fd)
                rel = (marker, stage_name) if marker is not None else (stage_name,)
                self._register(fd, tree.kind, tree.tree, rel)
            except BaseException:
                os.close(fd)
                raise
        finally:
            os.close(parent_fd)
        with self._lock:
            self._stage_cache[key] = fd
            st = os.fstat(fd)
            self._validated_stages.add((st.st_dev, st.st_ino))
        return fd

    def open_private_stage_dir(self, root_fd: int) -> int:
        """The writer-private 0700 `.stage/` of a configured private root
        (`transport.HopFsOps`). `root_fd` must be the private root itself;
        anything else raises before anything is created. Created durably if
        missing, validated otherwise and never repaired; the private root is
        fsynced whether or not this call created it; pinned once."""
        root = self.binding(root_fd)
        if root.kind != PRIVATE or root.rel != ():
            raise ValueError("open_private_stage_dir needs a configured private root itself")
        key = (root.tree, "private")
        with self._lock:
            cached = self._stage_cache.get(key)
        if cached is not None:
            try:
                self.binding(cached)
                return cached
            except BindingError:
                pass
        try:
            os.mkdir(".stage", 0o700, dir_fd=root_fd)
            created = True
        except FileExistsError:
            created = False
        fd = os.open(".stage", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            if created:
                os.fchmod(fd, 0o700)
            st = os.fstat(fd)
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise BindingError(
                    f"private stage directory is not this writer's 0700 directory "
                    f"(uid {st.st_uid}, mode {oct(stat.S_IMODE(st.st_mode))}); "
                    "refusing, never repairing")
            os.fsync(root_fd)
            self._register(fd, PRIVATE, root.tree, (".stage",))
        except BaseException:
            os.close(fd)
            raise
        with self._lock:
            self._stage_cache[key] = fd
            self._validated_stages.add((st.st_dev, st.st_ino))
        return fd

    # -- the commit -----------------------------------------------------------

    def _dest_lock(self, stage: Binding) -> threading.Lock:
        with self._lock:
            return self._dest_locks.setdefault((stage.dev, stage.ino), threading.Lock())

    def commit_durable(self, stage_dirfd: int, dest_dirfd: int, name: str,
                       data: bytes, mode: int, *,
                       deps: Sequence[Tuple[int, str, int, str]] = ()) -> str:
        """Contract §4.3's one rule, with the dependency checks of E5. See
        `transport.HopFsOps`."""
        stage = self.binding(stage_dirfd)
        dest = self.binding(dest_dirfd)
        _check_name(name)
        if not isinstance(data, bytes):
            raise FsOpsError("data must be the frozen bytes")
        deps = _check_deps_shape(deps)
        for i, (dep_fd, dep_name, _size, _digest) in enumerate(deps):
            d = self.binding(dep_fd)
            # The same publication: a dependency lives in the destination's
            # own tree, never in a stage directory. Refused before anything
            # is staged.
            if d.kind != dest.kind or d.tree != dest.tree:
                raise BindingError(f"dependency {i} ({dep_name!r}) is in another tree")
            if _inside_stage(d):
                raise BindingError(f"dependency {i} ({dep_name!r}) is inside a stage directory")
        if not stage.is_stage or (stage.dev, stage.ino) not in self._validated_stages:
            raise BindingError("stage_dirfd is not a stage directory opened by open_stage_dir")
        if _inside_stage(dest):
            raise BindingError("a stage directory is never a destination")
        if stage.tree != dest.tree or stage.kind != dest.kind:
            raise BindingError("the stage and the destination are in different trees")
        tag = dest.tag  # BindingError for a name outside the tag charset
        stage_name = f"{tag}.{name}"
        if len(stage_name.encode("utf-8", "surrogateescape")) > NAME_MAX:
            raise BindingError(f"the stage name for {name!r} in {'/'.join(dest.rel)!r} "
                               "exceeds NAME_MAX")
        _check_name(stage_name)
        lock = self._dest_lock(stage)
        with lock:
            fcntl.flock(stage_dirfd, fcntl.LOCK_EX)
            try:
                return self._commit_locked(stage_dirfd, dest_dirfd, name, stage_name,
                                           data, mode, deps)
            finally:
                fcntl.flock(stage_dirfd, fcntl.LOCK_UN)

    def _commit_locked(self, sfd: int, dfd: int, name: str, sname: str,
                       data: bytes, mode: int, deps=()) -> str:
        # The entry observation, before any stage, compare, recovery or
        # exists_* answer, so a broken publication never reports a result
        # for the wrong reason.
        self._check_deps(deps)
        if self._exists(dfd, name):
            return self._on_exists(sfd, dfd, name, sname, data, mode, deps)
        # A stale own stage with no final: unlink it, durably.
        if self._exists(sfd, sname):
            os.unlink(sname, dir_fd=sfd)
            os.fsync(sfd)
        fd = os.open(sname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                     dir_fd=sfd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fchmod(fd, mode)
            os.fsync(fd)
            frozen = os.fstat(fd)
            os.fsync(sfd)
            self._step("staged", stage_fd=sfd, stage_name=sname)
            try:
                os.link(sname, name, src_dir_fd=sfd, dst_dir_fd=dfd, follow_symlinks=False)
            except FileExistsError:
                # Raced: a final appeared. Judge it before touching our stage.
                os.close(fd)
                fd = -1
                return self._on_exists(sfd, dfd, name, sname, data, mode, deps)
            linked = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (linked.st_dev, linked.st_ino) != (frozen.st_dev, frozen.st_ino):
                # The stage pathname was substituted after we froze it. The
                # final is at link count 2, so no reader has taken it as
                # committed: remove it, and refuse.
                os.unlink(name, dir_fd=dfd)
                os.fsync(dfd)
                raise FsOpsError("the stage was substituted before the link; nothing published")
        finally:
            if fd >= 0:
                os.close(fd)
        self._step("linked")
        self._check_deps(deps)     # after the link, before the barrier
        os.fsync(dfd)
        self._step("dest_synced")
        os.unlink(sname, dir_fd=sfd)
        self._step("unlinked")
        os.fsync(sfd)
        return "created"

    def _check_deps(self, deps) -> None:
        for i, (dir_fd, name, size, digest) in enumerate(deps):
            self._check_dep(i, dir_fd, name, size, digest)

    def _check_dep(self, i: int, dir_fd: int, name: str, size: int, digest: str) -> None:
        """One dependency (`transport.HopFsOps`, DEPENDENCIES): the binding
        guard by a FRESH canonical walk, then the bounded content check
        through that walk. Raises `DependencyAnomaly`."""
        b = self.binding(dir_fd)
        here = self._canonical_dir(b)
        if here is None:
            raise DependencyAnomaly("binding_moved", i, name,
                                    f"{'/'.join(b.rel) or '.'} is no longer at its path")
        try:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=here)
            except FileNotFoundError:
                raise DependencyAnomaly("missing", i, name, "absent") from None
            except OSError as e:
                if e.errno in _KIND_ERRNOS:
                    raise DependencyAnomaly("not_regular", i, name, os.strerror(e.errno)) from e
                raise
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise DependencyAnomaly("not_regular", i, name, "not a regular file")
                if st.st_nlink != 1:
                    raise DependencyAnomaly("link_count", i, name, f"link count {st.st_nlink}")
                got = self._read_all(fd, size)
            finally:
                os.close(fd)
        finally:
            os.close(here)
        if len(got) != size:
            raise DependencyAnomaly("size", i, name, f"{len(got)} bytes, declared {size}")
        if hashlib.sha256(got).hexdigest() != digest:
            raise DependencyAnomaly("digest", i, name, "sha256 differs from the declared one")

    def _canonical_dir(self, b: Binding) -> Optional[int]:
        """A FRESH descriptor for `b`'s directory reached from its tree root
        by `O_NOFOLLOW` steps, or None when what is at `b`'s path in its tree
        is not `b`'s directory (moved, replaced, gone). The tree root is
        found by walking up `len(b.rel)` levels from the live directory and
        must be `b.tree`; the walk back down uses the recorded names only."""
        live = self._live_fd(b)
        if live is None:
            return None
        fd = live
        try:
            for part in [".."] * len(b.rel) + [None] + list(b.rel):
                if part is None:     # at the top: it must be b's own tree root
                    st = os.fstat(fd)
                    if (st.st_dev, st.st_ino) != b.tree:
                        os.close(fd)
                        return None
                    continue
                try:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except OSError as e:
                    # What is (or is not) at a path says the binding moved;
                    # any other fault (EIO, EACCES, ...) says nothing and
                    # propagates. The same on the way up and the way down.
                    if e.errno in _WALK_MOVED:
                        os.close(fd)
                        return None
                    raise
                os.close(fd)
                fd = nxt
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != (b.dev, b.ino):
                os.close(fd)
                return None
            return fd
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _live_fd(self, b: Binding) -> Optional[int]:
        """A dup of some live descriptor registered for `b`'s directory."""
        with self._lock:
            fds = [fd for fd, other in self._by_fd.items() if (other.dev, other.ino) == (b.dev, b.ino)]
        for fd in fds:
            try:
                st = os.fstat(fd)
            except OSError:
                continue
            if (st.st_dev, st.st_ino) == (b.dev, b.ino):
                return os.dup(fd)
        return None

    @staticmethod
    def _exists(dir_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _different(self, dfd: int, name: str, why: str, fd: Optional[int] = None,
                   deps=()) -> str:
        """The anomaly. The dependencies are observed again first (E5: on
        EVERY result path, so a broken publication is reported as such, not
        as `exists_different`); a caller that has just checked them after
        its own compare passes none. Before it is returned, the existing
        file (when it is a regular file we opened) and the destination are
        fsynced, as for every exists_* result; any own stage is KEPT as
        evidence."""
        self._check_deps(deps)
        if fd is not None:
            os.fsync(fd)
        os.fsync(dfd)
        logger.error("commit_durable: %r exists and is not this commit (%s); "
                     "the existing file is never replaced", name, why)
        return "exists_different"

    def _on_exists(self, sfd: int, dfd: int, name: str, sname: str,
                   data: bytes, mode: int, deps=()) -> str:
        """`name` exists. Establish what it is, and make it durable, BEFORE
        any cleanup: an own stage is removed only once the final is known to
        be this commit and its barriers are taken, and is kept as evidence
        otherwise. Every exists_same also fsyncs the stage directory, so a
        stage-dir barrier that failed on an earlier attempt is repaired."""
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                return self._different(dfd, name, "a symlink", deps=deps)
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return self._different(dfd, name, "not a regular file", deps=deps)
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != mode:
                return self._different(dfd, name, "owner or mode", fd, deps=deps)
            if st.st_nlink == 1:
                same = self._read_all(fd, len(data)) == data
                self._check_deps(deps)     # after the compare, before the barrier
                if not same:
                    return self._different(dfd, name, "different bytes", fd)
                os.fsync(fd)
                os.fsync(dfd)
                self._step("same_synced")
                if self._exists(sfd, sname):
                    # Our own stage, linked nowhere (the final is at link
                    # count 1): stale, and safe to drop now the match is
                    # established and durable.
                    os.unlink(sname, dir_fd=sfd)
                os.fsync(sfd)
                return "exists_same"
            if st.st_nlink == 2:
                try:
                    sst = os.stat(sname, dir_fd=sfd, follow_symlinks=False)
                except FileNotFoundError:
                    return self._different(dfd, name, "a second link that is not our stage", fd,
                                           deps=deps)
                if (sst.st_dev, sst.st_ino) != (st.st_dev, st.st_ino):
                    return self._different(dfd, name, "our stage is a different inode", fd,
                                           deps=deps)
                # Our interrupted commit (F1). Everything is established with
                # the stage still present, so readers keep seeing NOT_YET (H1).
                self._step("recover_before_compare")
                same = self._read_all(fd, len(data)) == data
                self._check_deps(deps)     # after the compare, before the barrier
                if not same:
                    return self._different(dfd, name, "interrupted commit with different bytes",
                                           fd)
                self._step("recover_after_compare")
                os.fsync(fd)
                os.fsync(dfd)
                self._step("recover_after_barrier")
                os.unlink(sname, dir_fd=sfd)
                os.fsync(sfd)
                if os.fstat(fd).st_nlink != 1:
                    raise FsOpsError(f"{name!r} is not at link count 1 after recovery")
                return "exists_same"
            return self._different(dfd, name, f"link count {st.st_nlink}", fd, deps=deps)
        finally:
            os.close(fd)

    @staticmethod
    def _read_all(fd: int, expect: int) -> bytes:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks, got = [], 0
        while got <= expect:
            chunk = os.read(fd, min(1 << 20, expect + 1 - got))
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    # -- other mutations ------------------------------------------------------

    def replace_durable(self, dir_fd: int, name: str, data: bytes, mode: int) -> None:
        """Replace a mutable single-owner marker: temp, fsync, rename, dir
        fsync. Durable on return."""
        self.binding(dir_fd)
        _check_name(name)
        tmp = f".{name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
        _check_name(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                     dir_fd=dir_fd)
        renamed = False
        try:
            try:
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    view = view[n:]
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            renamed = True
            os.fsync(dir_fd)
        except BaseException:
            if not renamed:
                try:
                    os.unlink(tmp, dir_fd=dir_fd)
                except OSError:
                    pass
            raise

    def rename_noreplace(self, src_fd: int, src: str, dst_fd: int, dst: str) -> str:
        """`renameat2(RENAME_NOREPLACE)`, then fsync both directories,
        destination first. No fallback."""
        self.binding(src_fd)
        self.binding(dst_fd)
        _check_name(src)
        _check_name(dst)
        try:
            _sys_renameat2(src_fd, src, dst_fd, dst, _RENAME_NOREPLACE)
        except OSError as e:
            if e.errno == errno.EEXIST:
                return "dst_exists"
            if e.errno == errno.ENOENT:
                return "src_gone"
            if e.errno in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP):
                raise NoReplaceUnsupported(
                    e.errno, "RENAME_NOREPLACE refused: unsupported here, or an invalid "
                    "move such as a directory into its own subtree") from e
            raise
        os.fsync(dst_fd)
        if src_fd != dst_fd:
            os.fsync(src_fd)
        return "moved"

    def remove_pinned(self, dir_fd: int, name: str) -> None:
        """Remove `name` (a directory is renamed aside first, then emptied),
        and fsync `dir_fd` even when the name was already missing.

        CRASH-RESUMABLE (the `(3, 1)` postcondition the optional remover
        relies on): before acting on `name` it sweeps every ASIDE of THAT
        name in `dir_fd`, an entry matching exactly
        `^\\.<escaped name>\\.old\\.tmp\\.[0-9]+\\.[0-9a-f]{16}\\Z` (the name this
        method's own rename gives one). An aside is emptied IN PLACE, never
        renamed a second time, so asides never nest; one that is not a
        directory is unlinked. The sweep pages the bounded listing over that
        prefix (`ListingTooLarge` propagates). A call that returns has left
        neither `name` nor any aside of it."""
        self.binding(dir_fd)
        _check_name(name)
        for aside in self._asides(dir_fd, name):
            try:
                st = os.stat(aside, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(st.st_mode):
                _remove_tree(dir_fd, aside)
            else:
                os.unlink(aside, dir_fd=dir_fd)
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.fsync(dir_fd)
            return
        if stat.S_ISDIR(st.st_mode):
            self._forget_under(self.binding(dir_fd), name)
            aside = f".{name}.old.tmp.{os.getpid()}.{secrets.token_hex(8)}"
            os.rename(name, aside, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
            _remove_tree(dir_fd, aside)
        else:
            try:
                os.unlink(name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        os.fsync(dir_fd)

    def _asides(self, dir_fd: int, name: str) -> List[str]:
        """The asides of `name` in `dir_fd`: the names in the prefix's range
        that match the aside pattern exactly. Pages the bounded listing and
        stops at the first name past the prefix."""
        prefix = f".{name}.old.tmp."
        pattern = re.compile(re.escape(prefix) + r"[0-9]+\.[0-9a-f]{16}\Z")
        found: List[str] = []
        after: Optional[str] = prefix
        while True:
            names, more = self.list_pinned(dir_fd, limit=transport_mod.LIST_LIMIT_MAX,
                                           after=after)
            for n in names:
                if not n.startswith(prefix):
                    return found
                if pattern.fullmatch(n):
                    found.append(n)
            if not more or not names:
                return found
            after = names[-1]

    # -- reads ----------------------------------------------------------------

    def open_regular_pinned(self, dir_fd: int, name: str, *, max_bytes: int):
        """Committed bytes, or NOT_YET for a commit in flight on a hop-tree
        or host-intake binding; anything else raises.

        It checks the file is regular and its link count; it does NOT check
        the owner. A reader that needs an owner rule (contract §4.2 markers)
        calls `stat_owner_pinned` as well, which is a separate lookup and so
        is sound only in a single-owner directory, where nothing else can
        replace the name between the two."""
        b = self.binding(dir_fd)
        _check_name(name)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except FileNotFoundError:
            raise
        except OSError as e:
            if e.errno in _KIND_ERRNOS:
                raise UnsafeRead("not_regular", f"{name!r}: {os.strerror(e.errno)}") from e
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeRead("not_regular", f"{name!r} is not a regular file")
            if st.st_nlink == 2 and b.trusted_links:
                return NOT_YET
            if st.st_nlink != 1:
                raise UnsafeRead("link_count", f"{name!r} has link count {st.st_nlink}")
            if st.st_size > max_bytes:
                raise UnsafeRead("too_large", f"{name!r} exceeds {max_bytes} bytes")
            data = self._read_all(fd, max_bytes)
            if len(data) > max_bytes:
                raise UnsafeRead("too_large", f"{name!r} exceeds {max_bytes} bytes")
            return data
        finally:
            os.close(fd)

    def stat_group_pinned(self, dir_fd: int, name: str) -> Tuple[int, int, int, str]:
        """(uid, gid, permission bits, kind) from ONE non-following stat:
        exactly `stat_owner_pinned`'s semantics plus that stat's `st_gid`
        (`transport.HOPFSOPS_OPTIONAL_METHODS`, at `(3, 1)`)."""
        self.binding(dir_fd)
        _check_name(name)
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        kind = "file" if stat.S_ISREG(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) \
            else "other"
        return st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), kind

    def stat_owner_pinned(self, dir_fd: int, name: str) -> Tuple[int, int, str]:
        """(uid, permission bits, kind) from a non-following stat."""
        self.binding(dir_fd)
        _check_name(name)
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        kind = "file" if stat.S_ISREG(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) \
            else "other"
        return st.st_uid, stat.S_IMODE(st.st_mode), kind

    @staticmethod
    def fsync_file(fd: int) -> None:
        os.fsync(fd)

    @staticmethod
    def fsync_dir(fd: int) -> None:
        os.fsync(fd)

    def list_pinned(self, dir_fd: int, *, limit: int,
                    after: Optional[str] = None) -> Tuple[List[str], bool]:
        """`transport.HopFsOps.list_pinned`: the `limit` smallest names
        strictly greater than `after`, sorted, and whether more exist.

        The arguments are checked first, then `dir_fd`'s binding. The scan
        streams a FRESH open description of that directory (`os.open(".",
        dir_fd=...)`), never a dup: a dup shares the pinned descriptor's
        offset, and reading it would move the caller's position. The fresh
        descriptor is checked to be the same directory before it is read,
        and closed afterwards. At most `limit + 1` names are held (a bounded
        heap), so memory is O(limit) whatever the directory holds; on
        visiting name `transport.LIST_SCAN_MAX + 1` the scan stops at once
        and raises `ListingTooLarge`. Names are `str` as the kernel's bytes
        decode with `surrogateescape`; `.` and `..` never appear. A failure
        raises; it never returns an empty list for an error."""
        transport_mod.check_list_args(limit, after)
        b = self.binding(dir_fd)
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=dir_fd)
        try:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != (b.dev, b.ino):
                raise BindingError(f"fd {dir_fd}'s directory changed under the listing")
            keep = limit + 1
            heap: List[_Larger] = []
            visited = 0
            with os.scandir(fd) as it:
                for entry in it:
                    visited += 1
                    if visited > transport_mod.LIST_SCAN_MAX:
                        raise ListingTooLarge(
                            f"more than {transport_mod.LIST_SCAN_MAX} names; the scan stopped")
                    name = entry.name
                    if after is not None and name <= after:
                        continue
                    if len(heap) < keep:
                        heapq.heappush(heap, _Larger(name))
                    elif name < heap[0].name:
                        heapq.heapreplace(heap, _Larger(name))
        finally:
            os.close(fd)
        names = sorted(h.name for h in heap)
        return names[:limit], len(names) > limit


def _inside_stage(b: Binding) -> bool:
    if b.kind == GENERATION:
        return b.rel[:2] in (("up", "stage"), ("down", "stage"))
    if b.kind in (INTAKE, PRIVATE):
        return b.rel[:1] == (".stage",)
    return False


def _check_disjoint(roots: Sequence[str]) -> None:
    """No root equals or contains another (paths already normalised and
    absolute). Raises `FsOpsError` before anything is opened."""
    for i, a in enumerate(roots):
        for b in roots[i + 1:]:
            if a == b or b.startswith(a.rstrip("/") + "/") or a.startswith(b.rstrip("/") + "/"):
                raise FsOpsError(f"roots {a!r} and {b!r} are not disjoint")


def _mkdir_predicate(final: os.stat_result, want: int, parent: os.stat_result,
                     name: str) -> None:
    """`mkdir_and_pin`'s predicate on the FINAL fstat (`transport.HopFsOps`)."""
    why = None
    if not stat.S_ISDIR(final.st_mode):
        why = "not a directory"
    elif final.st_uid != os.geteuid():
        why = f"owned by uid {final.st_uid}"
    elif stat.S_IMODE(final.st_mode) & 0o777 != want:
        why = f"permission bits {oct(stat.S_IMODE(final.st_mode) & 0o777)}, wanted {oct(want)}"
    elif final.st_mode & (stat.S_ISUID | stat.S_ISVTX):
        why = "setuid or sticky bit set"
    elif (final.st_mode & stat.S_ISGID) != (parent.st_mode & stat.S_ISGID):
        why = "setgid bit differs from the parent's"
    if why is not None:
        raise MkdirRefused(f"{name!r}: {why}; refusing, never repairing")


def _check_deps_shape(deps) -> Tuple[Tuple[int, str, int, str], ...]:
    out = []
    for d in deps:
        if not (isinstance(d, tuple) and len(d) == 4):
            raise FsOpsError(f"a dependency is (dir_fd, name, size, sha256), not {d!r}")
        dir_fd, name, size, digest = d
        if not isinstance(dir_fd, int) or isinstance(dir_fd, bool):
            raise FsOpsError(f"dependency dir_fd {dir_fd!r} is not a descriptor")
        _check_name(name)
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise FsOpsError(f"dependency size {size!r} is not a non-negative int")
        if not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise FsOpsError(f"dependency sha256 {digest!r} is not lowercase hex")
        out.append((dir_fd, name, size, digest))
    return tuple(out)


#: The deepest nesting `_remove_tree` empties: deeper raises `ELOOP`.
REMOVE_TREE_DEPTH_MAX = 8
#: How many names `_remove_tree` holds at once while emptying a directory.
_REMOVE_BATCH = 1024


def _remove_tree(parent_fd: int, name: str, depth: int = 1) -> None:
    """Empty and remove a privately named directory. Its entries are not
    synced one by one: only its disappearance is ordered against.

    BOUNDED: each directory is first counted through a streaming scan that
    stops at `transport.LIST_SCAN_MAX + 1` names (`ListingTooLarge`, before
    anything in it is removed), then emptied in batches of at most
    `_REMOVE_BATCH` names, never a full in-memory listing. Nesting deeper
    than `REMOVE_TREE_DEPTH_MAX` raises `OSError(ELOOP)`. Every entry is
    stat'd without following: a symlink, a FIFO or any other non-directory
    is unlinked, its target never touched."""
    if depth > REMOVE_TREE_DEPTH_MAX:
        raise OSError(errno.ELOOP, f"nesting deeper than {REMOVE_TREE_DEPTH_MAX} under removal",
                      name)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        counted = 0
        with os.scandir(fd) as it:
            for _entry in it:
                counted += 1
                if counted > transport_mod.LIST_SCAN_MAX:
                    raise ListingTooLarge(
                        f"more than {transport_mod.LIST_SCAN_MAX} names under removal; "
                        "nothing in it was removed")
        while True:
            batch: List[str] = []
            with os.scandir(fd) as it:
                for entry in it:
                    batch.append(entry.name)
                    if len(batch) >= _REMOVE_BATCH:
                        break
            if not batch:
                break
            for entry in batch:
                st = os.stat(entry, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    _remove_tree(fd, entry, depth + 1)
                else:
                    os.unlink(entry, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


# ---------------------------------------------------------------------------
# The startup capability probe
# ---------------------------------------------------------------------------

def probe(directory: Union[str, Path]) -> dict:
    """Check, in a private subdirectory of `directory` (removed afterwards),
    every guarantee the primitives depend on: a directory fsync;
    `RENAME_NOREPLACE` moving to a free name, refusing an existing one with
    both files untouched, and reporting a missing source; `link` refusing
    an existing name. Raises `CapabilityError` naming the first failure; a
    caller refuses to start on it. Returns the reported (not enforced)
    `protected_hardlinks` value, or None when unreadable."""
    base = os.open(os.fspath(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = f".fsops-probe.{os.getpid()}.{secrets.token_hex(8)}"
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=base)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base)
        except OSError as e:
            raise CapabilityError(f"cannot create the probe directory: {e.strerror}") from e
        try:
            def write(n: str, data: bytes) -> None:
                f = os.open(n, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                            dir_fd=fd)
                try:
                    os.write(f, data)
                    os.fsync(f)
                finally:
                    os.close(f)

            def read(n: str) -> bytes:
                f = os.open(n, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    return os.read(f, 64)
                finally:
                    os.close(f)

            def noreplace(src: str, dst: str) -> str:
                try:
                    _sys_renameat2(fd, src, fd, dst, _RENAME_NOREPLACE)
                    return "moved"
                except OSError as e:
                    if e.errno == errno.EEXIST:
                        return "dst_exists"
                    if e.errno == errno.ENOENT:
                        return "src_gone"
                    raise CapabilityError(
                        f"RENAME_NOREPLACE is not supported: {os.strerror(e.errno)}") from e

            try:
                os.fsync(fd)
            except OSError as e:
                raise CapabilityError(f"directory fsync failed: {e.strerror}") from e
            write("a", b"a")
            if noreplace("a", "b") != "moved":
                raise CapabilityError("RENAME_NOREPLACE did not move to a free name")
            write("a", b"a2")
            if noreplace("a", "b") != "dst_exists":
                raise CapabilityError("RENAME_NOREPLACE replaced an existing name")
            if read("b") != b"a" or read("a") != b"a2":
                raise CapabilityError("RENAME_NOREPLACE onto an existing name changed a file")
            if noreplace("missing", "c") != "src_gone":
                raise CapabilityError("RENAME_NOREPLACE misreported a missing source")
            try:
                os.link("a", "b", src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                raise CapabilityError("link onto an existing name succeeded")
            except FileExistsError:
                pass
        finally:
            os.close(fd)
            try:
                _remove_tree(base, name)
                os.fsync(base)
            except OSError:
                pass
    finally:
        os.close(base)
    try:
        with open("/proc/sys/fs/protected_hardlinks", "rb") as f:
            value = f.read(8).strip().decode("ascii")
        hardlinks = value if value in ("0", "1") else None
    except (OSError, UnicodeDecodeError):
        hardlinks = None
    return {"protected_hardlinks": hardlinks}
