"""router/util.py — small shared primitives with no policy content.

- `atomic_write`: `.tmp` + fsync + `os.replace` + directory fsync, in
  spirit from an equivalent helper in a second connector implementation —
  every protocol artifact this router produces (result, message spool,
  notice) goes through this so a reader never observes a partial file, and
  each write is fsynced (file, then directory) before it returns.
  `fsync_dir` is the directory half on its own, for a rename or unlink made
  elsewhere.
- `verify_namespace_containment`: an agent owns its own namespace and can
  replace any subdirectory of it (`inbound/`, `outbound/results/`, ...)
  with a symlink pointing anywhere the router process can write — including
  a HOST path outside every namespace, or a DIFFERENT instance's namespace.
  Every write this router makes INTO a namespace must be preceded by this
  check (see `deliver.py`, `outbound.py`); it refuses rather than follows.
- `mint_notice_id`: 128-bit unguessable id (AMAP §6 / review finding
  H2), and importantly restricted to hex so it always satisfies the
  connector's `safe_id` charset (`inbox-mcp-vol`: `[A-Za-z0-9_][A-Za-z0-9_.-]
  {0,199}`) — `secrets.token_urlsafe` can start with `-`, which that charset
  rejects outright, so hex is picked deliberately over urlsafe base64.
- `utc_ts`: ISO-8601 UTC timestamp, second precision, `Z` suffix.
  `parse_utc_ts` is its strict inverse (`None` on anything else) and
  `format_utc_ts` renders a datetime back into the same shape, so window
  arithmetic in `exposure.py`/`outbound.py` never grows a second format.
- `read_capped`: the outbox is untrusted input (SCOPE.md "Trust story") —
  never slurp an agent-controlled file of unbounded size.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from . import clock

DEFAULT_READ_CAP = 1 * 1024 * 1024  # 1 MiB


class ReadTooLargeError(Exception):
    """Raised by `read_capped` when a file exceeds its byte cap."""


class NamespaceEscapeError(Exception):
    """Raised by `verify_namespace_containment` when a namespace
    subdirectory has been replaced by (or is only reachable via) a symlink
    that resolves outside the namespace's own resolved location. The
    caller must refuse the write, not follow it."""


def verify_namespace_containment(namespace: Union[str, Path], target: Union[str, Path]) -> None:
    """Refuse (raise `NamespaceEscapeError`) if `target`'s containing
    directory does not resolve (`os.path.realpath`) to somewhere inside
    `namespace`'s own resolved location.

    This is the belt against an agent replacing a namespace subdirectory —
    e.g. `<ns>/inbound` — with a symlink to redirect the router's writes
    elsewhere: a host path outside every namespace, or worse, a DIFFERENT
    instance's namespace (cross-instance notice injection). `os.path.
    realpath` follows symlinks at every component that currently exists and
    passes nonexistent trailing components through literally, so this is
    safe to call whether or not `target`'s parent tree has been created yet
    — `atomic_write`'s own `mkdir(parents=True, exist_ok=True)` only ever
    runs after this check has already refused an escaping path. Call this
    BEFORE every write (or `os.replace`) whose destination lives inside an
    instance namespace; it is not needed for `state_dir` writes, which are
    never agent-reachable (`config.py` enforces that at load time)."""
    namespace = Path(namespace)
    target = Path(target)
    real_namespace = os.path.realpath(str(namespace))
    real_target_dir = os.path.realpath(str(target.parent))
    if real_target_dir != real_namespace and not real_target_dir.startswith(
        real_namespace + os.sep
    ):
        raise NamespaceEscapeError(
            f"refusing to write {target}: containing directory resolves to "
            f"{real_target_dir!r}, which is outside namespace {str(namespace)!r} "
            f"(-> {real_namespace!r})"
        )


def fsync_dir(path: Union[str, Path]) -> None:
    """Make `path`'s entries durable: a rename, create or unlink inside a
    directory is not durable until the DIRECTORY is fsynced, whatever was
    done to the file. Errors propagate: a barrier that failed is not one."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir_durable(path: Path, durable_root: Optional[Path] = None) -> None:
    """`mkdir -p`, then make the directory entries durable.

    With `durable_root` (a directory the caller knows is durable, such as a
    deployment-created `state_dir`): EVERY directory from `durable_root` down
    to `path` is fsynced into its parent, on every call. Whether this call
    created them does not matter. An earlier attempt whose fsync failed left
    directories that exist but may not be durable, at any depth, and only
    re-establishing the whole chain from a known-durable root repairs that.
    `path` must be `durable_root` or under it (ValueError otherwise).

    Without it: the parent of every directory this call created, and of
    `path` itself, is fsynced. That does NOT repair a failed barrier higher
    up the chain from an earlier attempt; callers that need that pass
    `durable_root`."""
    if durable_root is not None:
        root = Path(os.path.abspath(durable_root))
        target = Path(os.path.abspath(path))
        rel = target.relative_to(root)  # ValueError when outside the root
        target.mkdir(parents=True, exist_ok=True)
        d = root
        for part in rel.parts:
            fsync_dir(d)
            d = d / part
        return
    missing = []
    p = path
    while not p.exists():
        missing.append(p)
        if p.parent == p:
            break
        p = p.parent
    path.mkdir(parents=True, exist_ok=True)
    parents = [d.parent for d in reversed(missing)]
    if path.parent not in parents:
        parents.append(path.parent)
    for d in parents:
        fsync_dir(d)


def atomic_write(path: Union[str, Path], data: bytes, *,
                 make_parents: bool = True, mode: Optional[int] = None,
                 durable_root: Optional[Union[str, Path]] = None) -> None:
    """Write `data` to `path` atomically, with fsync barriers:
    `tempfile.mkstemp` in the destination directory, write, fsync the file,
    `os.replace`, then fsync the directory. A reader can never observe a
    partial file at `path`.

    The barriers are what a durable write needs from THIS process; whether a
    power loss then preserves the write also depends on the filesystem and
    the storage under it honouring fsync, which nothing here can check. So
    this is necessary for durability, and no claim of power-loss safety is
    made on its strength alone. Without the barriers a crash could roll a
    completed write back after something else had acted on it: the in-flight
    counter (`inflight.allocate_transport_req_id`) could return an id that
    the counter then handed out AGAIN. Order: file
    fsync BEFORE the rename (else the rename can be durable over an empty
    file), directory fsync AFTER it (else the rename itself can be lost).
    Any failure raises; nothing here reports success it did not get. A
    failure before the rename leaves `path` untouched and removes the temp;
    a failure of the directory fsync AFTER the rename leaves the new
    contents in place and still raises, because they are not yet durable.

    Does NOT itself check namespace containment — callers writing into an
    instance namespace must call `verify_namespace_containment` first (see
    that function's docstring); this primitive is also used for
    `state_dir` writes, which have no namespace to check against.

    Two keyword-only options, both defaulting to the behaviour every caller
    before them relied on — this module has an out-of-package dependent, so
    the positional signature does not move:

    `make_parents=False` refuses to create the destination directory: a
    missing one raises `FileNotFoundError` from `mkstemp` itself, with no
    check-then-create window. For a directory that belongs to someone else,
    whose absence is THEIR failure to report — creating it here would hide
    that, and would put the file somewhere nothing reads. Directories it
    does create are made durable too (`_mkdir_durable`).

    `durable_root` names a directory the caller knows is durable; every
    directory between it and `path` is then re-established on every write,
    so a directory barrier that failed on an earlier attempt is repaired by
    the next one (`_mkdir_durable`). Without it, only the directories this
    call creates, and the destination's parent, are fsynced into their
    parents. Requires `make_parents`.

    `mode` is applied to the temp file BEFORE the rename, so the file never
    exists at `path` with any other mode. It matters because `mkstemp`
    creates `0600`: right for router-private `state_dir` files, and exactly
    wrong for a file another uid must read — the write succeeds, the content
    is correct, and the reader gets EACCES."""
    dest = Path(path)
    if durable_root is not None and not make_parents:
        raise ValueError("durable_root requires make_parents")
    if make_parents:
        _mkdir_durable(dest.parent, None if durable_root is None else Path(durable_root))
    fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent), prefix=dest.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            if mode is not None:
                os.fchmod(f.fileno(), mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    fsync_dir(dest.parent)


def mint_notice_id() -> str:
    """128-bit unguessable id, lowercase hex (32 chars) — always inside the
    connector's `safe_id` charset (unlike `secrets.token_urlsafe`, which can
    start with `-`)."""
    return secrets.token_hex(16)


_UTC_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_ts() -> str:
    """ISO-8601 UTC timestamp, second precision, `Z` suffix."""
    return format_utc_ts(clock.now())


def format_utc_ts(dt: datetime) -> str:
    """`dt` (aware, any zone) in exactly `utc_ts`'s shape."""
    return dt.astimezone(timezone.utc).strftime(_UTC_TS_FORMAT)


def parse_utc_ts(value: object) -> Optional[datetime]:
    """Strict inverse of `utc_ts`: an aware UTC datetime, or `None` for
    anything that is not exactly that shape — never raises. Strict on
    purpose: the strings this parses (ledger `ts`, the first-sight `first_seen_ts`)
    were all written by `utc_ts`, so a different shape is a corrupt or
    foreign record and the caller must fail closed rather than guess."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, _UTC_TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def read_capped(path: Union[str, Path], cap: int = DEFAULT_READ_CAP) -> bytes:
    """Read `path` fully only if it is no larger than `cap` bytes. The
    outbox is untrusted input to the host (SCOPE.md) — never slurp an
    unbounded agent-controlled file. Raises `ReadTooLargeError` (not a
    silent truncation) if the file is over the cap; propagates `OSError`
    for anything else (missing file, permission, ...)."""
    p = Path(path)
    size = p.stat().st_size
    if size > cap:
        raise ReadTooLargeError(f"{p}: {size} bytes exceeds cap of {cap}")
    return p.read_bytes()


def open_child_pinned(parent_fd: int, name: str) -> Tuple[str, Optional[int]]:
    """Attempt to open `name`, relative to `parent_fd`, as a directory,
    refusing (`O_NOFOLLOW`) to follow it if the final component is a
    symlink. This single syscall is the atomic pin: if it succeeds, the
    returned fd refers to `name`'s CURRENT target inode, and nothing that
    happens to the path afterward (a `rename()` of `name`, of `parent_fd`'s
    own directory entry, anything) can change what that fd refers to.

    Returns one of:
      `("dir", fd)`      — `name` is currently a real, non-symlink
                            directory; `fd` is now pinned to it.
      `("other", None)`  — `name` exists but is not a followable real
                            directory (a symlink, a plain file, or
                            anything else `O_NOFOLLOW`+`O_DIRECTORY`
                            refuses) — never descended into.
      `("missing", None)` — `name` does not currently exist.

    IT LIVES HERE, not in the module that first needed it, because it is a
    security primitive with more than one caller and a near-copy of it is a
    hole rather than a duplicate. An `lstat` followed by an `open`, or the
    same `open` without `O_NOFOLLOW`, both LOOK like this and both follow a
    symlink planted between the two calls — in a tree the agent can write.
    Anything walking an agent-adjacent directory imports this; nothing
    reimplements it. It was `reset._open_child` until a host adapter
    imported it across a repo boundary and made the question unavoidable:
    a reusable pin should not be a private function of the destructive-wipe
    module. `reset._open_child` remains as an alias to this object.
    """
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        return "dir", fd
    except FileNotFoundError:
        return "missing", None
    except OSError:
        # ELOOP (symlink), ENOTDIR (a file), or anything else opening a
        # single already-named component can raise — all mean the same
        # thing here: not a real directory this may safely descend into.
        return "other", None
