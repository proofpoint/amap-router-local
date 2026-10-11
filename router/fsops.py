"""router/fsops.py — this router's implementation of `transport.HopFsOps`.

Every filesystem operation a transport plugin may perform goes through an
instance of `FsOps`, on descriptors it pinned. The Protocol, its result
vocabularies and the invariants owed are in `router/transport.py`; this
module keeps them. It is not activated: nothing in this package hands an
`FsOps` to a plugin yet (`service.start_transport` still refuses every
plugin with `fsops_unavailable`).

ROOTS. An `FsOps` knows the directories it may open, by kind:

  * `hop_root`: the hop tree (contract §4.1). Under it, `.unresolved/` and
    `.control/` are host intakes, `<logical_id>/<gen>/` and
    `.runtime/<gen>/` are generation trees, and a staging subtree made by
    `stage_tree` is a generation tree that is not yet published;
  * `private_roots`: this writer's own state directories, each one tree.
    They are opened, read and `replace_durable`d here, but they have no
    stage directory, so `commit_durable` is for hop trees and host intakes
    only (this router's private writes use `util.atomic_write`).

`open_root_nofollow` refuses any other path. There is no "anywhere" mode.

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


class UnsafeRead(FsOpsError):
    """`open_regular_pinned` refused the file (not regular, wrong link count,
    too large)."""


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
        if self.kind == INTAKE:
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

    def __init__(self, *, hop_root: Optional[Union[str, Path]] = None,
                 private_roots: Iterable[Union[str, Path]] = ()):
        def canon(p) -> str:
            s = os.path.normpath(os.fspath(p))
            if not os.path.isabs(s):
                raise FsOpsError(f"root {s!r} is not absolute")
            return s

        self._hop_root = canon(hop_root) if hop_root is not None else None
        self._private_roots = tuple(canon(p) for p in private_roots)
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
        """Create `name` if missing, pin it, and fsync the parent either way
        (an earlier creator's fsync may have failed). `mode` is subject to
        the process umask, as `mkdir(2)` is; an existing directory's mode is
        left as it is. Where a mode must be exact (stage directories), the
        caller that owns it sets and checks it (`open_stage_dir`)."""
        parent = self.binding(parent_fd)
        _check_name(name)
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
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

    # -- the commit -----------------------------------------------------------

    def _dest_lock(self, stage: Binding) -> threading.Lock:
        with self._lock:
            return self._dest_locks.setdefault((stage.dev, stage.ino), threading.Lock())

    def commit_durable(self, stage_dirfd: int, dest_dirfd: int, name: str,
                       data: bytes, mode: int) -> str:
        """Contract §4.3's one rule. See `transport.HopFsOps`."""
        stage = self.binding(stage_dirfd)
        dest = self.binding(dest_dirfd)
        _check_name(name)
        if not isinstance(data, bytes):
            raise FsOpsError("data must be the frozen bytes")
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
                                           data, mode)
            finally:
                fcntl.flock(stage_dirfd, fcntl.LOCK_UN)

    def _commit_locked(self, sfd: int, dfd: int, name: str, sname: str,
                       data: bytes, mode: int) -> str:
        if self._exists(dfd, name):
            return self._on_exists(sfd, dfd, name, sname, data, mode)
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
                return self._on_exists(sfd, dfd, name, sname, data, mode)
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
        os.fsync(dfd)
        self._step("dest_synced")
        os.unlink(sname, dir_fd=sfd)
        self._step("unlinked")
        os.fsync(sfd)
        return "created"

    @staticmethod
    def _exists(dir_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _different(self, dfd: int, name: str, why: str, fd: Optional[int] = None) -> str:
        """The anomaly. Before it is returned, the existing file (when it is
        a regular file we opened) and the destination are fsynced, as for
        every exists_* result; any own stage is KEPT as evidence."""
        if fd is not None:
            os.fsync(fd)
        os.fsync(dfd)
        logger.error("commit_durable: %r exists and is not this commit (%s); "
                     "the existing file is never replaced", name, why)
        return "exists_different"

    def _on_exists(self, sfd: int, dfd: int, name: str, sname: str,
                   data: bytes, mode: int) -> str:
        """`name` exists. Establish what it is, and make it durable, BEFORE
        any cleanup: an own stage is removed only once the final is known to
        be this commit and its barriers are taken, and is kept as evidence
        otherwise. Every exists_same also fsyncs the stage directory, so a
        stage-dir barrier that failed on an earlier attempt is repaired."""
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                return self._different(dfd, name, "a symlink")
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return self._different(dfd, name, "not a regular file")
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != mode:
                return self._different(dfd, name, "owner or mode", fd)
            if st.st_nlink == 1:
                if self._read_all(fd, len(data)) != data:
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
                    return self._different(dfd, name, "a second link that is not our stage", fd)
                if (sst.st_dev, sst.st_ino) != (st.st_dev, st.st_ino):
                    return self._different(dfd, name, "our stage is a different inode", fd)
                # Our interrupted commit (F1). Everything is established with
                # the stage still present, so readers keep seeing NOT_YET (H1).
                self._step("recover_before_compare")
                if self._read_all(fd, len(data)) != data:
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
            return self._different(dfd, name, f"link count {st.st_nlink}", fd)
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
        and fsync `dir_fd` even when the name was already missing."""
        self.binding(dir_fd)
        _check_name(name)
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
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeRead(f"{name!r} is not a regular file")
            if st.st_nlink == 2 and b.trusted_links:
                return NOT_YET
            if st.st_nlink != 1:
                raise UnsafeRead(f"{name!r} has link count {st.st_nlink}")
            if st.st_size > max_bytes:
                raise UnsafeRead(f"{name!r} exceeds {max_bytes} bytes")
            data = self._read_all(fd, max_bytes)
            if len(data) > max_bytes:
                raise UnsafeRead(f"{name!r} exceeds {max_bytes} bytes")
            return data
        finally:
            os.close(fd)

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


def _inside_stage(b: Binding) -> bool:
    if b.kind == GENERATION:
        return b.rel[:2] in (("up", "stage"), ("down", "stage"))
    if b.kind == INTAKE:
        return b.rel[:1] == (".stage",)
    return False


def _remove_tree(parent_fd: int, name: str) -> None:
    """Empty and remove a privately named directory. Its entries are not
    synced one by one: only its disappearance is ordered against."""
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        for entry in os.listdir(fd):
            st = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                _remove_tree(fd, entry)
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
