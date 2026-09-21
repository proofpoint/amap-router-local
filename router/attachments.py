"""router/attachments.py — attachment transport primitives, AMAP v2.3.0.

Shared by `outbound.py` (agent -> runtime ingest, §3) and `deliver.py`
(runtime -> agent publication, §5). Nothing in this module makes a POLICY
decision (that's `outbound.py`'s job, same split as `validate.py`); this
module verifies bytes and moves them, fail-closed on any disagreement
between what an agent declared and what is actually on disk.

## Conformance basis — what `clean` asserts here

This router asserts `disposition: "clean"` on the basis AMAP §5 names as
its second example — "a closed operator-supervised topology": one machine,
one operator, a closed peer matrix, no external sender, no mail provider.
It is NEVER a scanner verdict. This runtime runs no AV, no DLP, no content
inspection, and no type sniffing, and nothing here should be read as
implying otherwise. A deployment that cannot make that determination MUST
NOT assert `clean` (AMAP §5) — it emits `unscanned` and publishes no bytes. `filename`/`media_type`
are attacker-controlled untrusted display strings on BOTH sides of this
module (§5) and are never treated as anything else here: they are
sanitized for display (`_sanitize_display`) and are NEVER a path component
— the blob path is always `<req-id or notice-id> + array index`, the sole
binding authority (§2).

## The two directions, and why each needs different machinery

- **Outbound ingest** (`ingest_attachments`, §3): the sidecar dir
  (`outbox_root/req-<id>.attachments/`) is AGENT-OWNED and writable while
  the router reads it — the exact TOCTOU class `router/reset.py` found and
  fixed for deletions (see that module's docstring), except here a winning
  race redirects a READ: an attacker who wins gets some file the router
  process can read copied into another agent's inbox. Every filesystem
  lookup below the pin is `dir_fd`-relative and `O_NOFOLLOW`-guarded,
  exactly like `reset.py`'s removal engine (`reset._open_child`, reused
  here rather than re-implemented) — the fd is the boundary; every path
  string above it is advisory only.
- **Inbound publication** (`publish_attachment_blobs`, §5): the bytes
  being written are already verified (they came from `ingest_attachments`
  on the SENDER's side); what's untrusted here is the DESTINATION
  directory — under `namespace` mode (posture A) a recipient owns its own
  `inbox_root` in principle, so the same pinned-fd discipline governs the
  write side too ("namespace containment on both sides", not just path
  checks before the write).

## Verification order (outbound), caps strictly before any read

1. Count cap (`attachment_max_count`) — before any sidecar is opened.
2. Declared-size caps, per-file then total (`attachment_max_bytes`,
   `attachment_max_total_bytes`) — before any sidecar is opened.
3. Pin the sidecar dir, fd-chain from the instance's declared `root` (the
   containment ANCHOR — see `config.InstanceConfig.root`'s docstring).
4. Exact ordinal set: `{e.name for e in scandir} == {str(i) for i in
   range(n)}` — STRING equality against `str(i)`, deliberately not
   `str.isdigit()`, which admits `"01"`, non-ASCII digits, and superscript
   digit glyphs.
5. Per ordinal, `dir_fd`-relative: open (`O_NOFOLLOW`) -> fstat (regular
   file, `st_nlink == 1`) -> bounded read+hash -> compare size+sha256
   against the descriptor. Any single failure rejects the WHOLE request —
   never a partial send (§4).

Verified bytes are held in memory only for the span of one ingest call
(bounded by `attachment_max_total_bytes`) and are the ONLY copy the
runtime ever delivers — each ordinal's fd is opened, read, hashed, and
closed exactly once; there is no verify-then-reread window to race.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import reset as reset_mod
from .util import open_child_pinned
from .config import RouterConfig
from .util import NamespaceEscapeError

REASON_ATTACHMENT_MISMATCH = "attachment_mismatch"
REASON_ATTACHMENT_TOO_LARGE = "attachment_too_large"
REASON_ATTACHMENT_COUNT_EXCEEDED = "attachment_count_exceeded"

# result.schema.json's attachments[].outcome enum (AMAP v2.3.0) is
# enum-locked to exactly these four values — never invent a fifth here.
ATTACH_OUTCOME_ACCEPTED = "accepted"
ATTACH_OUTCOME_REJECTED_TYPE = "rejected_type"
ATTACH_OUTCOME_TOO_LARGE = "too_large"

_READ_CHUNK = 256 * 1024


@dataclass(frozen=True)
class VerifiedAttachment:
    """One outbound attachment, verified against sidecar bytes the router
    read and hashed itself — `size_bytes`/`sha256` here are
    ROUTER-VERIFIED, not merely the agent's declaration (the asymmetry
    AMAP §5 notes: inbound `size_bytes` is normally provider-declared and
    advisory; this runtime has no provider, so what it publishes is stronger).
    `filename`/`media_type` are already display-sanitized."""

    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    data: bytes


class AttachmentIngestError(Exception):
    """Raised by `ingest_attachments` for a whole-request outcome. `outcome`
    is `"rejected"` (malformed/mismatched — §4's first path: never a
    partial send) or `"queued_for_human"` (a policy cap on an HONEST
    declaration — §4's second path, never conflated with the first).
    `index`/`attachment_outcome`, when both given, let the caller attach
    one diagnostic entry to the result's optional `attachments[]` array
    (§4); omitted when the failure doesn't name a single offending index
    (e.g. a whole-array count-cap breach, or a sidecar-dir shape
    violation)."""

    def __init__(
        self, outcome: str, reason_code: str, detail: str,
        *, index: Optional[int] = None, attachment_outcome: Optional[str] = None,
    ) -> None:
        super().__init__(detail)
        self.outcome = outcome
        self.reason_code = reason_code
        self.detail = detail
        self.index = index
        self.attachment_outcome = attachment_outcome


def _sanitize_display(raw: Any, limit: int, fallback: str) -> str:
    """`filename`/`media_type` are attacker-controlled untrusted display
    strings end to end (§5) — collapse control/newline characters to a
    space and cap length, same defensive posture as `deliver.py`'s
    `_collapse_control`. NEVER a path component on either side: the blob
    path is always `<req-id|notice-id>.attachments/<index>`; this string
    appears nowhere in any path this module builds. Falls back to a
    synthesized name if cleaning empties the string (an all-control-char
    filename must still render as something, not vanish silently)."""
    s = "" if raw is None else str(raw)
    cleaned = "".join(c if (c.isprintable() and c not in "\r\n") else " " for c in s)
    cleaned = cleaned.strip()[:limit]
    return cleaned or fallback


def _descend_pinned(root_fd: int, rel: Path) -> Optional[int]:
    """Descend from `root_fd` one path component at a time, each opened
    `O_NOFOLLOW`-pinned as a real, non-symlink directory (`reset.py`'s
    `_open_child` discipline, reused verbatim rather than re-implemented).
    Closes every intermediate fd along the way; returns the fd of the
    final component, or `None` the moment any component isn't currently a
    real directory (caller decides what that means — a fast, structural
    "not there," never an exception for an ordinary missing path)."""
    cur = root_fd
    owns_cur = False
    for part in rel.parts:
        kind, fd = open_child_pinned(cur, part)
        if owns_cur:
            os.close(cur)
        if kind != "dir":
            return None
        cur = fd
        owns_cur = True
    if not owns_cur:
        return os.dup(root_fd)
    return cur


def _refuse_if_sidecar_present(root: Path, outbox_root: Path, side_dir_name: str) -> None:
    """§3: `attachments: []` (or the field absent) is equivalent, and the
    sidecar dir MUST then be absent. Pinned the same way as the populated
    case — an absence check is still a check-then-act on a name an agent
    controls, so it goes through the same `O_NOFOLLOW` discipline rather
    than a bare `Path.exists()`."""
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        outbox_fd = _descend_pinned(root_fd, outbox_root.relative_to(root))
        if outbox_fd is None:
            return  # outbox root itself isn't there — nothing to violate
        try:
            kind, fd = open_child_pinned(outbox_fd, side_dir_name)
            if kind == "missing":
                return
            if kind == "dir":
                os.close(fd)
            raise AttachmentIngestError(
                "rejected", REASON_ATTACHMENT_MISMATCH,
                f"{side_dir_name}: sidecar dir present but no attachments were "
                f"declared (§3: draft.attachments absent/[] requires an absent "
                f"sidecar dir)",
            )
        finally:
            os.close(outbox_fd)
    finally:
        os.close(root_fd)


def _read_capped(fd: int, expected_size: int) -> bytes:
    """Read at most `expected_size + 1` bytes from `fd` (already pinned,
    opened `O_NOFOLLOW` and `dir_fd`-relative by the caller) — bounded
    regardless of the file's real size, so an ordinal that grew past its
    declared size is detected (`len(data) != expected_size`, below)
    without the read itself ever being unbounded. Reads in bounded chunks
    to avoid one huge `read()` even for a file at the size cap."""
    limit = expected_size + 1
    chunks: List[bytes] = []
    got = 0
    while got < limit:
        chunk = os.read(fd, min(_READ_CHUNK, limit - got))
        if not chunk:
            break
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _verify_one(side_fd: int, index: int, descriptor: Dict[str, Any]) -> VerifiedAttachment:
    declared_size = descriptor["size_bytes"]
    declared_sha = descriptor["sha256"]
    name = str(index)
    try:
        # O_NONBLOCK: `name` is inside the agent-owned sidecar dir, so it
        # can be ANYTHING an agent can create with no privilege — including
        # a FIFO (`os.mkfifo`). Without this flag, opening a FIFO for
        # O_RDONLY with no writer present BLOCKS THE OPEN CALL ITSELF,
        # before the `stat.S_ISREG` guard below ever runs — a deterministic
        # DoS that wedges this single router process (and therefore every
        # instance's delivery/first-sight/reset) on the very first drain that
        # touches it, no race required. O_NONBLOCK makes the open on a
        # FIFO-with-no-writer return immediately instead; the fstat check
        # right below then rejects it as "not a regular file," same path a
        # dir-as-ordinal entry already takes. O_NONBLOCK is a documented
        # no-op for regular-file opens/reads, so the happy path (and every
        # other rejection shape) is unaffected. Do NOT pre-stat by name to
        # "detect" a FIFO before opening — that reintroduces exactly the
        # check-then-act TOCTOU this module's fd-pinning discipline exists
        # to avoid; the flag lets the SAME open-then-fstat sequence handle
        # it safely instead.
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=side_fd
        )
    except OSError as e:
        raise AttachmentIngestError(
            "rejected", REASON_ATTACHMENT_MISMATCH,
            f"attachments[{index}]: cannot open sidecar ordinal {name!r}: {e}",
            index=index, attachment_outcome=ATTACH_OUTCOME_REJECTED_TYPE,
        )
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AttachmentIngestError(
                "rejected", REASON_ATTACHMENT_MISMATCH,
                f"attachments[{index}]: sidecar ordinal {name!r} is not a "
                f"regular file",
                index=index, attachment_outcome=ATTACH_OUTCOME_REJECTED_TYPE,
            )
        if st.st_nlink != 1:
            # A genuine agent-written sidecar is always nlink==1 (write +
            # rename into a fresh dir). A hardlink (nlink>=2) is a regular
            # file whose inode is shared with a name OUTSIDE this sidecar
            # dir — reading it would copy bytes the agent never wrote HERE
            # (mirrors the deployed connector's identical Q5 refusal,
            # `inbox-mcp-vol`'s `read_attachment`).
            raise AttachmentIngestError(
                "rejected", REASON_ATTACHMENT_MISMATCH,
                f"attachments[{index}]: sidecar ordinal {name!r} is a hard "
                f"link (nlink={st.st_nlink}) — refusing",
                index=index, attachment_outcome=ATTACH_OUTCOME_REJECTED_TYPE,
            )
        data = _read_capped(fd, declared_size)
        if len(data) != declared_size:
            raise AttachmentIngestError(
                "rejected", REASON_ATTACHMENT_MISMATCH,
                f"attachments[{index}]: descriptor declares size_bytes="
                f"{declared_size} but the sidecar is a different size",
                index=index, attachment_outcome=ATTACH_OUTCOME_REJECTED_TYPE,
            )
        digest = hashlib.sha256(data).hexdigest()
        if digest != declared_sha:
            raise AttachmentIngestError(
                "rejected", REASON_ATTACHMENT_MISMATCH,
                f"attachments[{index}]: sha256 mismatch (descriptor declares "
                f"{declared_sha}, computed {digest} over the sidecar bytes)",
                index=index, attachment_outcome=ATTACH_OUTCOME_REJECTED_TYPE,
            )
    finally:
        os.close(fd)

    filename = _sanitize_display(descriptor.get("filename"), 300, f"attachment-{index}")
    media_type = _sanitize_display(
        descriptor.get("media_type"), 200, "application/octet-stream"
    )
    return VerifiedAttachment(
        filename=filename, media_type=media_type,
        size_bytes=declared_size, sha256=digest, data=data,
    )


def ingest_attachments(
    cfg: RouterConfig, name: str, req_id: str, descriptors: List[Dict[str, Any]],
) -> List[VerifiedAttachment]:
    """§3 outbound ingest. Call unconditionally with `descriptors =
    draft.get("attachments") or []` — even an empty/absent list must run
    the dir-shape check (§3: the sidecar dir MUST be absent when
    `attachments` is absent/`[]`). Returns the verified attachments in
    array order (== ordinal order); raises `AttachmentIngestError` for
    anything that fails (see that class's docstring for the two outcome
    shapes)."""
    inst = cfg.instances[name]
    root = inst.root
    outbox_root = inst.outbox_root
    side_dir_name = f"req-{req_id}.attachments"
    n = len(descriptors)

    if n == 0:
        _refuse_if_sidecar_present(root, outbox_root, side_dir_name)
        return []

    if n > cfg.attachment_max_count:
        raise AttachmentIngestError(
            "queued_for_human", REASON_ATTACHMENT_COUNT_EXCEEDED,
            f"{n} attachments exceeds the {cfg.attachment_max_count}-count cap",
        )

    total = 0
    for i, d in enumerate(descriptors):
        size = d["size_bytes"]
        if size > cfg.attachment_max_bytes:
            raise AttachmentIngestError(
                "queued_for_human", REASON_ATTACHMENT_TOO_LARGE,
                f"attachments[{i}]: {size} bytes exceeds the "
                f"{cfg.attachment_max_bytes}-byte per-file cap",
                index=i, attachment_outcome=ATTACH_OUTCOME_TOO_LARGE,
            )
        total += size
    if total > cfg.attachment_max_total_bytes:
        raise AttachmentIngestError(
            "queued_for_human", REASON_ATTACHMENT_TOO_LARGE,
            f"total {total} bytes across {n} attachment(s) exceeds the "
            f"{cfg.attachment_max_total_bytes}-byte combined cap",
        )

    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        outbox_fd = _descend_pinned(root_fd, outbox_root.relative_to(root))
        if outbox_fd is None:
            raise AttachmentIngestError(
                "rejected", REASON_ATTACHMENT_MISMATCH,
                "outbox root is not currently a real directory",
            )
        try:
            kind, side_fd = open_child_pinned(outbox_fd, side_dir_name)
            if kind == "missing":
                raise AttachmentIngestError(
                    "rejected", REASON_ATTACHMENT_MISMATCH,
                    f"{side_dir_name}: sidecar dir missing for {n} declared "
                    f"attachment(s)",
                )
            if kind != "dir":
                raise AttachmentIngestError(
                    "rejected", REASON_ATTACHMENT_MISMATCH,
                    f"{side_dir_name}: not a real directory (symlink or a "
                    f"plain file)",
                )
            try:
                actual = {e.name for e in os.scandir(side_fd)}
                expected = {str(i) for i in range(n)}
                if actual != expected:
                    raise AttachmentIngestError(
                        "rejected", REASON_ATTACHMENT_MISMATCH,
                        f"{side_dir_name}: entries {sorted(actual)} != expected "
                        f"ordinals {sorted(expected)}",
                    )
                return [_verify_one(side_fd, i, d) for i, d in enumerate(descriptors)]
            finally:
                os.close(side_fd)
        finally:
            os.close(outbox_fd)
    finally:
        os.close(root_fd)


def remove_outbound_sidecar_dir(cfg: RouterConfig, name: str, req_id: str) -> None:
    """Best-effort removal of a consumed (or never-populated)
    `req-<id>.attachments/` sidecar dir, called once a request has been
    answered and archived (`outbound.py`'s `_publish_result_and_archive`)
    — via the SAME pinned-fd removal engine `reset.py` uses (`reset.
    _open_child`/`_remove_one`), never a path-based branch. Absence is not
    an error; any failure here is swallowed — it must never affect the
    result already written, and the request is answered/archived either
    way."""
    inst = cfg.instances[name]
    root = inst.root
    side_dir_name = f"req-{req_id}.attachments"
    try:
        root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        outbox_fd = _descend_pinned(root_fd, inst.outbox_root.relative_to(root))
        if outbox_fd is None:
            return
        try:
            reset_mod._remove_one(outbox_fd, side_dir_name)
        finally:
            os.close(outbox_fd)
    finally:
        os.close(root_fd)


# --------------------------------------------------------------------
# Inbound publication (§5) — write side. See module docstring: the
# destination namespace may, under `namespace` mode, be agent-writable in
# principle, so this uses the same pinned-fd discipline as the outbound
# read side rather than a path-check-then-write.
# --------------------------------------------------------------------


def _mkdir_and_pin(parent_fd: int, name: str) -> int:
    """Create `name` as a directory under `parent_fd` if it doesn't
    already exist (tolerating a concurrent/repeat creator — a crash-and-
    resume of the SAME delivery is a real, expected case even though a
    fresh `notice_id` collision is not), then return a freshly
    `O_NOFOLLOW`-pinned fd to it. Refuses (`NamespaceEscapeError`) if
    `name` exists but is not currently a real, non-symlink directory —
    never descended into."""
    try:
        os.mkdir(name, dir_fd=parent_fd)
    except FileExistsError:
        pass
    kind, fd = open_child_pinned(parent_fd, name)
    if kind != "dir":
        raise NamespaceEscapeError(
            f"refusing to publish attachments into {name!r}: exists but is "
            f"not a real directory"
        )
    return fd


def _mkdir_descend_pinned(root_fd: int, rel: Path) -> int:
    """Like `_descend_pinned`, but CREATES each missing component along
    the way (`_mkdir_and_pin`) rather than refusing on absence — the
    recipient's `messages/` leaf (and, in principle, `inbox_root` itself)
    may not exist yet at first delivery (`deliver.py`'s message-spool
    write has always relied on `atomic_write`'s own `mkdir(parents=True)`
    for this; this is that same laziness, pinned). Still refuses
    (`NamespaceEscapeError`, via `_mkdir_and_pin`) the moment a component
    exists but is not currently a real, non-symlink directory."""
    cur = root_fd
    owns_cur = False
    for part in rel.parts:
        fd = _mkdir_and_pin(cur, part)
        if owns_cur:
            os.close(cur)
        cur = fd
        owns_cur = True
    if not owns_cur:
        return os.dup(root_fd)
    return cur


def _write_blob_pinned(dir_fd: int, name: Any, data: bytes) -> None:
    """Write `data` at `str(name)`, `dir_fd`-relative: a fresh,
    exclusively-created temp name, written, then renamed into place — both
    `dir_fd`-relative, so a reader can never observe a partial blob (a
    crash mid-write leaves only the unreferenced temp name behind, never a
    truncated file). `name` is an ordinal (`int`, sidecar blobs) or an
    arbitrary filename (`str`, `write_agent_visible` below) — either way
    it is NEVER used to build a path string; it is only ever the bare
    final component of a `dir_fd`-relative syscall, matching every other
    write in this module (leg (c) of the contract's write-side
    discipline: a fresh `O_EXCL` create, never `O_TRUNC` in its place)."""
    tmp_name = f".{name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    fd = os.open(
        tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.rename(tmp_name, str(name), src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise


def write_agent_visible(root: Path, target_path: Path, data: bytes) -> None:
    """Pinned equivalent of `util.atomic_write`, for any write whose
    destination lives inside an agent-owned namespace — `deliver.py`'s
    message-spool doc and deliver-notice (v3.0.0 write-side path
    discipline, contract sec 2, lines 89-162; ROUTER-SECURITY.md Finding
    2). Supersedes the old `util.verify_namespace_containment(root, path)`
    + `util.atomic_write(path, data)` pair everywhere it replaces it —
    that pair was a RACE, not a check: the containment check resolves
    `target_path.parent` as a path string, and the write that follows
    resolves the SAME path string again, independently; an agent that
    swaps the parent directory for a symlink in the gap between those two
    resolutions is checked against one filesystem object and written
    through a different one (this is exactly how ROUTER-SECURITY.md's
    Finding 2 moved bytes into a directory `verify_namespace_containment`
    had just certified was safe). This function performs exactly ONE
    resolution instead of two: a `dir_fd` descent pinned `O_NOFOLLOW` at
    every component from `root` (legs (a)+(b)), then an `O_EXCL`-tmp +
    `renameat` off THAT descriptor (leg (c)) — there is no window between
    "checked" and "acted on" for anything to race, because there is no
    longer a separate check. It creates every missing parent directory
    along the way and refuses (`NamespaceEscapeError`, via
    `_mkdir_descend_pinned`/`_mkdir_and_pin`) the instant a component
    exists but is not currently a real, non-symlink directory — the same
    refusal `verify_namespace_containment` gave callers, just detected
    structurally (a failed pinned open) instead of by comparing two
    `realpath()` strings computed at different times.

    Does NOT remove `util.verify_namespace_containment` itself or
    `util.atomic_write` — both remain correct and in use for `state_dir`
    writes (never agent-reachable; `config.py` enforces that at load, so
    no pinning is needed there — see e.g. `binding.record_delivery`'s
    ledger write). This function is for the agent-reachable case only."""
    rel_dir = target_path.parent.relative_to(root)
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        dir_fd = _mkdir_descend_pinned(root_fd, rel_dir)
        try:
            _write_blob_pinned(dir_fd, target_path.name, data)
        finally:
            os.close(dir_fd)
    finally:
        os.close(root_fd)


def sidecar_dir_name(notice_id: str) -> str:
    """The published sidecar directory's name: `<notice_id>.attachments`.

    **BARE `notice_id`, no `notice-` prefix.** The spool FILE is
    `notice-<id>.json`, so anything derived from that filename's stem
    carries the prefix and the directory does not — contract.md §2
    (v3.0.0): bytes are published only at
    `<tree>/notices/<notice-id>.attachments/<index>`, "the single sidecar
    directory named in the layout tree above", and there is no second,
    message-specific sidecar directory.

    This function exists so the DIRECTORY this module creates and the
    `content_ref` STRING `deliver.py` emits cannot drift: both derive from
    here, rather than each formatting the name from the same parts. They
    drifted once. Until v3.0.0 this router published under `messages/`
    with the prefix, keyed on the spool stem, and the deliver-notice
    omitted `content_ref` entirely, so nothing ever compared the two.
    `content_ref_for` below is the only other formatter, and it calls
    this one."""
    return f"{notice_id}.attachments"


def content_ref_for(notice_id: str, index: int) -> str:
    """The `content_ref` a descriptor at array position `index` must carry.

    §5 binds BOTH ends: the trailing `<index>` MUST equal the descriptor's
    own 0-based array index, and the leading prefix is the enclosing
    document's own `notice_id` (so a descriptor cannot point at another
    notice's sidecar). `amap-spec`'s `fixtures/validate.py`
    `_check_content_ref_index_binding` enforces exactly this equality;
    neither half is expressible in JSON Schema."""
    return f"{sidecar_dir_name(notice_id)}/{index}"


def publish_attachment_blobs(
    root: Path, tree_root: Path, notice_id: str, attachments: List[VerifiedAttachment],
) -> None:
    """§5 inbound publication. Writes every verified attachment's bytes to
    `tree_root/notices/<notice_id>.attachments/<index>`,
    `dir_fd`-pinned from `root` (the containment ANCHOR) all the way down
    — see the module docstring for why the write side gets the same
    discipline as the read side. A no-op for an empty `attachments` list
    (no dir is created at all, matching the outbound-side rule that an
    empty set means an absent sidecar dir). Called BEFORE the message
    spool write (`deliver.py`'s commit-sentinel ordering: all blobs ->
    message spool -> ledger -> notice LAST) — bytes always precede the
    notice that announces them."""
    if not attachments:
        return
    # `notices/`, not `messages/`, and on EVERY tree -- `tree_root` is the
    # mail lane's `inbox_root` or the peer lane's `peer_root` depending on
    # the caller, and peer-origin.md 1d makes the confinement per tree:
    # "Bytes resolve only within the `notices/` directory of the tree the
    # enclosing document was read from ... A peer notice cannot point into
    # the mail sidecar directory or vice versa." One line, both lanes.
    notices_rel = (tree_root / "notices").relative_to(root)
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        notices_fd = _mkdir_descend_pinned(root_fd, notices_rel)
        try:
            side_dir_name = sidecar_dir_name(notice_id)
            side_fd = _mkdir_and_pin(notices_fd, side_dir_name)
            try:
                for i, att in enumerate(attachments):
                    _write_blob_pinned(side_fd, i, att.data)
            finally:
                os.close(side_fd)
        finally:
            os.close(notices_fd)
    finally:
        os.close(root_fd)
