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

  1. the path is absolute and canonical: no symlinked component anywhere
     (`path_not_absolute`, `path_not_canonical`);
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
from typing import (Any, Callable, Iterable, Mapping, Optional, Protocol, Sequence,
                    Tuple)

#: `(major, minor)`. A plugin must have the same major and at least this
#: minor. The interfaces the factories receive (the filesystem and key
#: ports) are part of the major.
PLUGIN_API: Tuple[int, int] = (1, 0)

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


class NullTransport:
    """The plugin in force when none is configured: every factory returns
    `None`, so the drain runs with `transport=None` exactly as it did before
    plugins existed (module docstring, NULL, NOT ABSENT)."""

    path: Optional[str] = None
    sha256: Optional[str] = None
    api: Tuple[int, int] = PLUGIN_API

    def make_sender(self, settings: Mapping[str, Any], fsops: Any) -> None:
        return None

    def make_intake_reader(self, settings: Mapping[str, Any], fsops: Any) -> None:
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

    def make_sender(self, settings: Mapping[str, Any], fsops: Any) -> TransportPort:
        return self._factory("make_sender")(settings, fsops)

    def make_intake_reader(self, settings: Mapping[str, Any], fsops: Any) -> InboundPort:
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
    p = Path(os.path.normpath(path))
    if os.path.realpath(p) != str(p):
        raise PluginRefused("path_not_canonical",
                            f"{path!r} has a symlinked or non-canonical component")
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
