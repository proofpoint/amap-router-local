"""router/reset.py — operator command: wipe one instance's mailbox AND its
router-private state to a clean slate, between live bring-up runs.

WHY THIS IS ONE OPERATION, NOT TWO (the whole reason this module exists
instead of a two-line `rm -rf`):

  - **req_id reuse.** The connector derives its next `req_id` from
    `max(pending, processed, results) + 1` over the AGENT-VISIBLE outbox
    (`inbox-submit`). Wipe only the mailbox and the next request lands back
    at `req-00000000.json` — but `state_dir/<name>/results/00000000.json`
    (the router-private idempotency anchor, `outbound.py`'s
    `_private_result_path`) still holds the OLD digest for that id. The
    drain path then compares a fresh sha256 of the new pending bytes
    against that stale digest, sees a mismatch under a reused id, and trips
    `REASON_REQ_ID_REUSED` (`outbound.py`, pinned by
    `router/tests/test_req_id_reuse.py`) — a legitimate first post-reset
    send gets refused as if it were an attack.
  - **Stale first-sight snapshot.** `state_dir/<name>/first-seen.json`
    carries an `outbox_snapshot` of the filenames that were already in the
    outbox when this router first saw the instance
    (`router/firstsight.py`) — `outbound.drain_instance` quarantines any
    fresh request whose filename is a member of that snapshot, name only.
    Wipe only the mailbox and keep this file, and a legitimately NEW
    post-reset file that happens to collide with an old snapshot name (the
    connector's req_id counter restarts at 0 after a wipe, so a collision
    is the COMMON case, not a corner case) is quarantined instead of sent.

  Clearing state alongside the mailbox fixes both: an empty `results/`
  means no stale digest to collide with, and deleting `first-seen.json` is
  documented (`firstsight.py`'s module docstring) as the supported remedy
  for a stale snapshot — the next poll is a first sight again and snapshots
  the now-empty outbox, which names nothing. **This is why a reset always
  returns the instance to never-seen** — there is no way to clear the
  poisoned snapshot without also clearing the marker it lives inside, and
  reusing the OLD marker after a mailbox wipe is exactly the bug this module
  exists to avoid.

WHAT GETS TOUCHED, PER INSTANCE:

  Router-private (`state_dir/<name>`, never agent-reachable — no
  containment check needed, `config.py` already enforces this at load):
    - `first-seen.json`   — removed FIRST (the back-to-never-seen commit
      point),
      regardless of its current shape (a directory or a dangling symlink
      counts as "present" here too — only a REGULAR-FILE check would miss
      those and leave them behind)
    - everything else under `state_dir/<name>` (`results/`, `delivered/`,
      `held/`, `quarantine/`, `outcomes/`) — removed after — EXCEPT
      `audit/`, the append-only audit log (`router/audit.py`), which is
      the one piece of router-private state a reset preserves. It is the
      record of what the router did, and the one evidence-destroying
      command must not destroy the evidence; instead `reset_instance`
      APPENDS a `reset` line to it (what was removed, whether the instance
      had been seen). Nothing else reads `audit/`, so keeping it poisons no
      later send: the two traps this module exists for are `results/` and
      `first-seen.json`, both still cleared.
    - this happens TWICE per `reset_instance` call, live each time (see
      "ORDERING" below) — not once from a plan computed at the start.
    - `state_dir/<name>` itself being a symlink is a refusal, not a
      descent: `_clear_state` treats that as "nothing here" rather than
      following it and clearing whatever it points at.

  Agent-visible mailbox (containment-checked; CONTENTS only, never the
  roots or the skeleton leaves themselves; `inbox_root`, `outbox_root` and
  — on the peer lane — `peer_root` are probed and emptied INDEPENDENTLY of
  each other — an agent that has deleted or replaced just one of them,
  e.g. its own `outbox_root` under `namespace` mode posture A, must not
  cause the OTHER, still-present sides to be silently skipped too):
    - `inbox_root`'s direct entries other than `notices/`, `messages/` —
      anything an agent or an earlier router version left at the top of the
      inbox. (One such thing was `APPROVED.json`, a mirror this router wrote
      so the agent could see it had been approved; it is not written any
      more, and sweeping the directory's strays is what removes a leftover
      copy from a deployment that predates the change.)
    - the CONTENTS of `inbox_root/notices/` and `inbox_root/messages/`
      (AMAP v3.0.0: this includes any `<notice-id>.attachments/`
      published-bytes sidecar dir under `notices/` — swept as ordinary
      content of that leaf via `_remove_all_in`, no special-casing needed;
      see `router/attachments.py`. It was under `messages/` with a
      `notice-` prefix until 2026-09-20, and this comment needed no
      behavioural change when it moved BECAUSE both leaves' contents are
      swept identically — a property worth not breaking.)
    - `outbox_root`'s direct entries other than `results/`, `processed/` —
      `req-*.json`, any `req-<id>.attachments/` sidecar dir (AMAP v2.3.0
      outbound sidecars — same story: an ordinary non-keep direct entry,
      also independently swept by `attachments.
      remove_outbound_sidecar_dir` once a request is consumed), strays
    - the CONTENTS of `outbox_root/results/` and `outbox_root/processed/`
    - `peer_root` (`InstanceConfig.peer_root`, handoff mode in a fleet with
      a `fleet_domain`): its direct entries other than `notices/`,
      `messages/`, and the CONTENTS of those two — the peer tree is emptied
      exactly as the inbox tree is, never removed. The adapter mounts
      `peer/` read-only into the container, so its root is a live mount
      source too.

  NEVER touched: `inbox_root`, `outbox_root`, `peer_root`, and the skeleton
  leaves themselves (`notices/`, `messages/`, `results/`, `processed/`)
  stay in place as directories. In `handoff_dir` mode those two roots are the host's
  own live bind-mount SOURCES (`router/README.md` "Layout") — `rm -rf`-ing
  the root out from under a running container strands its mount on a
  deleted inode, and the agent then sees an empty tree that never recovers
  until the sandbox relaunches. Emptying contents in place needs no
  session downtime and keeps every mount valid. It also means `reset`
  creates NOTHING, ever — `provision.py`'s `ProvisionRefusesToCreateHostOwned
  DirsTest` exists because the host, not this code, must create and mount the
  handoff pair; a reset that recreated an emptied root would silently
  reintroduce exactly the failure mode that guard was written to prevent.
  `inbox_root/notices/processed/` is likewise never created here (v2.2.0
  §2 makes it optional and this router never depends on it existing — see
  `provision.py`'s `_INBOX_SKELETON_LEAVES`).

  `state_dir/status.json` (process-lifetime observability, one level above
  `state_dir/<name>`) is never touched by a reset — it isn't a source of
  record for any instance's ground truth (`status.py`'s module docstring).

  DE-ENROLMENT LEAVES ORPHAN STATE, AND `reset` CANNOT CLEAN IT UP. An
  instance that is removed from the config simply stops being mentioned;
  nothing sweeps `state_dir/<name>`, so its first-sight marker, ledger and
  audit log stay on disk indefinitely. `reset` refuses a name the config
  does not know (`plan_reset`), so the obvious remedy is the one thing that
  will not work — that refusal is deliberate (a typo must not be able to
  destroy an instance's state) and is not being weakened for this.

  So the supported order is RESET THEN DE-ENROL, and the consequence for
  anyone auditing `state_dir` is that "a marker exists for a name that is
  not a configured instance" is NOT evidence of a defect. It is the
  expected result of removing an instance, and a check that fails on it
  will fail on any fleet that has ever retired a sandbox. Warn, name the
  directory, and leave it: deleting it by hand is an operator's call, and
  it discards an audit log this command would have preserved.

ORDERING — state, THEN mailbox, THEN state again (why a plain "state
first" is not enough on its own):

  The only genuinely dangerous half-state is mailbox-emptied-while-state-
  survives (the req_id-reuse trap and the stale-snapshot trap, above, in
  their most exact form: the mailbox already looks clean, so an operator
  would trust it, while the private anchors that would poison the next
  send are still sitting there). Clearing state FIRST closes off a
  mid-reset CRASH: if the process dies between the two halves, the
  first-sight marker is already gone, so the next `drain_instance` takes a
  fresh snapshot and quarantines whatever is in the outbox rather than
  draining
  against half-cleared private state. That alone does not close off a
  concurrent DRAIN, though — a `router run` poll running in parallel
  (RUNBOOK §8 says to stop it first, but nothing enforces that) can read
  the first-sight marker a moment before the first state-clear removes it,
  keep going, and write a brand-new `state_dir/<name>/results/<id>.json`
  WHILE `_empty_mailboxes` is running. A single state-clear-then-mailbox-
  empty pass would never see that write and it would survive the reset —
  a private anchor with no mailbox entry to match it, which poisons the
  next send under that id exactly like the trap this module exists to
  prevent, just approached from the other direction. `reset_instance`
  closes this by re-running `_clear_state` a SECOND time, live (a fresh
  `state_dir/<name>` listing, never a snapshot computed earlier), after
  `_empty_mailboxes` returns — anything written to `state_dir/<name>`
  during the mailbox half is caught by this second pass. Both state-clear
  calls and the mailbox-empty call are separate module-level functions
  specifically so tests can patch one to fail, or to inject a write
  between calls, and pin this ordering and its fail-closed midpoint
  (`router/tests/test_reset.py`).

SAFETY — pin, then act, never re-resolve a path for the actual removal:
every mailbox removal goes through a directory file descriptor opened
with `O_NOFOLLOW`, one path component at a time, from the instance's
declared `root` (the containment ANCHOR — see `InstanceConfig.root`'s
docstring) all the way down to whichever leaf is being emptied
(`inbox_root`/`outbox_root` themselves, then `notices`/`messages`/
`results`/`processed` beneath them). Each `O_NOFOLLOW` open is a single
atomic syscall: it succeeds only if that exact path component is, AT THAT
INSTANT, a real (non-symlink) directory, and once it succeeds the
returned file descriptor stays pinned to THAT inode for the rest of this
leaf's removal — every subsequent `os.scandir`/`os.unlink`/`os.rmdir`
call is `dir_fd`-relative, resolving a bare filename as a single
component INSIDE the fd's own directory, never by re-walking a path
string. A `rename()` of any component, by the agent or anything else, at
any point after that fd was opened, cannot redirect a single one of these
removals: the fd already refers to the original directory's inode,
regardless of what name currently points at it, or what a swapped-in
symlink under that name might now resolve to.

This closes a gap a plain path-based implementation has and this module
once had: enumerating `leaf.iterdir()` once and then calling
`os.unlink`/`shutil.rmtree` on `leaf / entry_name` for each result
re-resolves the FULL PATH at every single removal, so a leaf swapped for
a symlink to an outside directory AFTER enumeration but BEFORE the last
entry is removed silently redirects every remaining removal through that
symlink — proven exploitable both deterministically (swap the leaf
mid-loop, in a scratch tree) and as a live race against a SEPARATE
process (won on the first of 20 attempts). Pinning removes the gap
structurally rather than narrowing the window: there is no window between
"verified real directory" and "acted on that directory," because they
are the same syscall (`router/tests/test_reset.py`'s
`test_leaf_swapped_to_symlink_mid_removal_never_touches_the_swap_target`
reproduces the deterministic case and asserts nothing outside the
instance root is ever touched).

When an `O_NOFOLLOW` open fails because the component turned out to be a
symlink, `reset` still has to decide whether to ABORT the whole call for
this instance (this is where `plan_reset`'s upfront `_verify_containment`
probe, and `reset_instances`' batch-wide pre-probe over every named
instance before any of them is touched, both matter too — they give a
fast, early refusal for the common case where the escape already existed
before `reset` was even invoked) or simply remove the symlink as an
ordinary stray entry. That decision is made by resolving where the
symlink currently points (`verify_namespace_containment`): outside the
instance root, and the whole reset aborts (`NamespaceEscapeError`),
touching nothing further for that instance; inside it (or the component
turns out to be a stray FILE, not a symlink at all), it's removed as an
ordinary entry. This judgment call is itself a best-effort, racy path
check — but it is a courtesy (turning what would otherwise be a
confusing, silently-empty mailbox into a loud abort), never the safety
boundary: the safety boundary is that every removal this module performs
is `dir_fd`-scoped and can therefore never reach outside the directory
whose fd it's using, no matter how that judgment call turns out or how
many times a path gets renamed underneath it. `unlink()` on a symlink
never touches its target regardless of where that target resolves.

Router-private state (`state_dir/<name>`) needs none of this machinery —
it is never agent-reachable (`config.py` enforces that at load) — except
one hardening check: if `state_dir/<name>` has itself been replaced by a
symlink, `_clear_state` refuses to descend through it at all (treats it
as if nothing were there), rather than trusting `Path.is_dir()`, which
follows symlinks transparently and would otherwise clear out whatever the
symlink points at.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import logging

from . import firstsight
from . import audit as audit_mod
from . import lock as lock_mod
from .config import RouterConfig
from .util import (
    NamespaceEscapeError, open_child_pinned, verify_namespace_containment,
)

logger = logging.getLogger("amap_router_local.reset")

# Skeleton leaves reset must never delete (only empty) — verbatim in
# spirit from `provision.py`'s `_INBOX_SKELETON_LEAVES`/
# `_OUTBOX_SKELETON_LEAVES`/`_PEER_SKELETON_LEAVES`, but named here since
# reset walks them directly rather than just `mkdir`-ing them.
_INBOX_KEEP = ("notices", "messages")
_OUTBOX_KEEP = ("results", "processed")
_PEER_KEEP = ("notices", "messages")

# The one `state_dir/<name>` entry a reset preserves (module docstring).
_STATE_KEEP = (audit_mod.AUDIT_DIR,)


class ResetError(Exception):
    """Raised when `plan_reset`/`plan_resets`/`reset_instance`/
    `reset_instances` is asked for one or more instance names this config
    doesn't know. Naming the offending name(s) and the known set, same
    idiom as `ProvisionError`/`ApprovalError`."""


@dataclass
class ResetPlan:
    """Pure inspection result for one instance — what a reset WOULD
    remove, computed with no side effects. Drives `--dry-run` output.

    `inbox_available`/`outbox_available` are reported SEPARATELY —
    `mailbox_available` (a plain `and` of the two) is kept only as a
    back-compat convenience; prefer the per-root fields, since an agent
    can delete or replace just one of the two roots (`namespace` mode
    posture A) and a caller that only looked at the combined flag would
    never learn which side actually went missing.

    This preview and `reset_instance`'s real removal are independent
    implementations that are each expected to agree with the other on the
    common (non-adversarial) case — NOT one driving the other by replaying
    a precomputed path list, which is exactly the check-then-act gap the
    real removal's `O_NOFOLLOW`-pinned engine exists to avoid (see the
    module docstring's SAFETY section). A `--dry-run` is inherently
    non-destructive, so the ordinary path-based enumeration used here is
    fine for preview purposes even though it would not be safe to drive
    an actual deletion."""

    name: str
    was_seen: bool
    inbox_available: bool
    outbox_available: bool
    # `False` both when the instance has no peer tree at all (not on the
    # peer lane) and when it has one that is not currently a real
    # directory; `has_peer_tree` tells the two apart for rendering.
    peer_available: bool = False
    has_peer_tree: bool = False
    state_paths: List[Path] = field(default_factory=list)
    mailbox_paths: List[Path] = field(default_factory=list)

    @property
    def mailbox_available(self) -> bool:
        return self.inbox_available and self.outbox_available

    def is_empty(self) -> bool:
        return not self.state_paths and not self.mailbox_paths


def _verify_containment(cfg: RouterConfig, name: str) -> None:
    """Probe every agent-visible mailbox leaf of instance `name` for
    namespace containment. Raises `NamespaceEscapeError` (never caught
    here — the caller aborts) on the first escape. A missing mailbox pair
    (handoff mode, the host hasn't created it yet) has nothing to probe and
    is silently fine — `reset` never creates it either, so there is
    nothing here for an escape to hide behind.

    This is a FAST, EARLY, path-based check only — it gives an immediate,
    clean refusal for the common case where an escaping symlink already
    exists before `reset` is even invoked, and it is what makes
    `reset_instances`' batch-wide pre-probe possible (every named instance
    is checked this way before any of them is touched). It is NOT what
    makes the actual removal safe against a symlink swap that happens
    AFTER this probe runs — that is `_empty_mailboxes`'s job, via
    `O_NOFOLLOW`-pinned file descriptors (see the module docstring's
    SAFETY section); `plan_reset`/`reset_instance` call this probe first
    as a convenience, then `_empty_mailboxes` independently re-verifies
    containment as an inherent, atomic part of actually removing
    anything."""
    inst = cfg.instances[name]
    inbox_root, outbox_root = inst.inbox_root, inst.outbox_root
    root = inst.root  # containment ANCHOR — see InstanceConfig.root's docstring
    if inbox_root.is_dir() and outbox_root.is_dir():
        for leaf in (
            inbox_root, inbox_root / "notices", inbox_root / "messages",
            outbox_root, outbox_root / "results", outbox_root / "processed",
        ):
            verify_namespace_containment(root, leaf / "._containment_probe")
    peer_root = inst.peer_root
    if peer_root is not None and peer_root.is_dir():
        for leaf in (peer_root, peer_root / "notices", peer_root / "messages"):
            verify_namespace_containment(root, leaf / "._containment_probe")


def _enumerate_mailbox_removals(
    inbox_root: Optional[Path], outbox_root: Optional[Path],
    peer_root: Optional[Path] = None,
) -> List[Path]:
    """Every mailbox path a reset would remove for one instance, for
    PREVIEW purposes: direct entries of each given root other than its
    two skeleton leaves, plus the direct entries INSIDE each of those
    skeleton leaves (their contents, never the leaf directories
    themselves). Pass `None` for a root that isn't currently available
    (missing, or replaced by a symlink) — it contributes nothing, and the
    other root (if given) is still enumerated independently. A would-be
    skeleton leaf that isn't currently a plain, non-symlink directory
    (replaced by a file, a symlink, or simply absent) is treated as a
    stray top-level entry instead — removed outright rather than
    descended into, since there is nothing safe to "empty contents of."
    """
    paths: List[Path] = []
    for root, keep in (
        (inbox_root, _INBOX_KEEP), (outbox_root, _OUTBOX_KEEP), (peer_root, _PEER_KEEP),
    ):
        if root is None:
            continue
        try:
            entries = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError:
            entries = []
        for p in entries:
            if p.name in keep and p.is_dir() and not p.is_symlink():
                continue  # a real skeleton leaf — kept; its contents are below
            paths.append(p)
        for leaf_name in keep:
            leaf = root / leaf_name
            if leaf.is_dir() and not leaf.is_symlink():
                try:
                    paths.extend(sorted(leaf.iterdir(), key=lambda p: p.name))
                except OSError:
                    pass
    return paths


def plan_reset(cfg: RouterConfig, name: str) -> ResetPlan:
    """Inspect (never mutate) what a reset of instance `name` would
    remove. Verifies namespace containment as part of inspection — a
    `--dry-run` must fail exactly the way a real run would, never report a
    clean plan for a namespace it couldn't actually have reset safely.

    Refuses (`ResetError`) if `name` doesn't name a configured instance.
    Raises `NamespaceEscapeError` (propagated, not caught) if any
    mailbox leaf has been replaced by an escaping symlink."""
    if name not in cfg.instances:
        raise ResetError(
            f"reset: {name!r} names no configured instance (known: {sorted(cfg.instances)})"
        )
    _verify_containment(cfg, name)

    inst = cfg.instances[name]
    first_seen_marker = firstsight.marker_path(cfg.state_dir, name)
    was_seen = first_seen_marker.is_file()

    state_paths: List[Path] = []
    # Present in ANY shape (regular file, directory, or dangling symlink)
    # counts — a stale check that only recognized `.is_file()` would leave
    # a non-file `first-seen.json` (a directory, say) out of this list AND
    # out of the "rest of state_dir" listing below (since the exclusion
    # used to be by path identity regardless of whether this branch had
    # actually included it) — surviving the reset entirely.
    if first_seen_marker.is_symlink() or first_seen_marker.exists():
        state_paths.append(first_seen_marker)
    inst_state_dir = cfg.state_dir / name
    if inst_state_dir.is_dir() and not inst_state_dir.is_symlink():
        try:
            rest = sorted(inst_state_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            rest = []
        # Exclude by MEMBERSHIP in what's already listed, not by identity
        # with `first_seen_marker` alone — the two are only the same set
        # when the marker was actually appended above. `audit/` is never
        # listed: a reset preserves it (module docstring).
        state_paths.extend(
            p for p in rest if p not in state_paths and p.name not in _STATE_KEEP
        )

    inbox_root, outbox_root = inst.inbox_root, inst.outbox_root
    inbox_available = inbox_root.is_dir() and not inbox_root.is_symlink()
    outbox_available = outbox_root.is_dir() and not outbox_root.is_symlink()
    peer_root = inst.peer_root
    peer_available = (
        peer_root is not None and peer_root.is_dir() and not peer_root.is_symlink()
    )
    mailbox_paths = _enumerate_mailbox_removals(
        inbox_root if inbox_available else None,
        outbox_root if outbox_available else None,
        peer_root if peer_available else None,
    )

    return ResetPlan(
        name=name, was_seen=was_seen,
        inbox_available=inbox_available, outbox_available=outbox_available,
        peer_available=peer_available, has_peer_tree=peer_root is not None,
        state_paths=state_paths, mailbox_paths=mailbox_paths,
    )


def plan_resets(cfg: RouterConfig, names: Iterable[str]) -> List[ResetPlan]:
    """`plan_reset` for every name in `names`. Validates the FULL set of
    names before planning any of them (`ResetError` names every unknown
    one at once, matching `provision`'s "name the known set"
    idiom) — a typo in a batch must never silently plan-and-report on the
    valid ones while staying quiet about the invalid one."""
    names = list(names)
    unknown = sorted(n for n in names if n not in cfg.instances)
    if unknown:
        raise ResetError(
            f"reset: {unknown} names no configured instance (known: {sorted(cfg.instances)})"
        )
    return [plan_reset(cfg, name) for name in names]


# --------------------------------------------------------------------
# Secure removal engine (mailbox side) — see the module docstring's
# SAFETY section. Every function below that takes a `dir_fd` performs
# ALL of its filesystem lookups relative to that fd; none of them ever
# builds or resolves a path string for the actual removal.
# --------------------------------------------------------------------

#: THE PIN, now `util.open_child_pinned` — an alias, not a wrapper, so
#: `reset._open_child is util.open_child_pinned` and there is exactly one
#: implementation to audit. Kept because a host adapter imports this name
#: across a repo boundary (`router/__init__.py` records why that import is
#: correct) and because `attachments` still reaches here for `_remove_one`.
#: No expiry: removing it is a cross-repo change and owes that caller notice
#: BEFORE the commit.
_open_child = open_child_pinned


def _pin_or_abort(
    parent_fd: int, name: str, *, root: Path, current_path: Path
) -> Tuple[str, Optional[int]]:
    """`_open_child`, plus the ABORT-vs-stray judgment call described in
    the module docstring's SAFETY section: when `name` turns out to be
    something other than a real directory, and it currently looks like a
    symlink at its full path (`current_path` — used ONLY for this
    judgment, never for the actual removal, which always goes through
    `parent_fd`+`name`), resolve where it points. Outside `root`, raise
    `NamespaceEscapeError` (propagated, aborting the whole reset for this
    instance). Inside `root` — or not a symlink at all, just a stray file
    — return normally; the caller removes it as an ordinary entry.

    A race on `current_path.is_symlink()` itself (the entry changes AGAIN
    between `_open_child`'s failure and this check) can only make this
    judgment call wrong, never unsafe: whatever the caller does next is
    still exactly one `dir_fd`-scoped removal of `name` inside
    `parent_fd`'s own directory."""
    kind, fd = _open_child(parent_fd, name)
    if kind == "other" and current_path.is_symlink():
        verify_namespace_containment(root, current_path / "._containment_probe")
    return kind, fd


def _remove_all_in(dir_fd: int) -> int:
    """Remove every entry directly inside the directory `dir_fd` refers
    to (never the directory itself). Returns the count removed. Every
    removal is `dir_fd`-relative (see `_remove_one`) — immune to whatever
    happens to the PATH that used to lead to this directory while this
    runs."""
    try:
        names = sorted(e.name for e in os.scandir(dir_fd))
    except OSError:
        return 0
    for name in names:
        _remove_one(dir_fd, name)
    return len(names)


def _remove_one(dir_fd: int, name: str) -> None:
    """Remove `name` from the directory `dir_fd` refers to, entirely: a
    symlink or a plain file is `unlink()`-ed; a real (non-symlink)
    directory is emptied recursively (through a freshly `O_NOFOLLOW`
    -pinned fd, exactly like the top level) and then `rmdir()`-ed.
    `unlink()`/`rmdir()` never dereference a symlink — whatever `name`
    currently is, removing it only ever touches the dentry inside
    `dir_fd`'s own directory, never a symlink's target, however that
    target resolves. Idempotent: a concurrent remover racing this one is
    tolerated silently, matching `_remove_path`'s contract for the
    (non-racy) state side."""
    kind, sub_fd = _open_child(dir_fd, name)
    if kind == "missing":
        return
    if kind == "dir":
        try:
            _remove_all_in(sub_fd)
        finally:
            os.close(sub_fd)
        try:
            os.rmdir(name, dir_fd=dir_fd)
        except OSError:
            pass
        return
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except IsADirectoryError:
        # Raced TO a directory since `_open_child`'s failed open, above
        # (rare) — `rmdir` still only ever touches `dir_fd`'s own entry.
        try:
            os.rmdir(name, dir_fd=dir_fd)
        except OSError:
            pass


def _empty_root(
    root: Path, root_fd: int, base_dir: Path, keep: Tuple[str, ...]
) -> Tuple[bool, int]:
    """Empty the CONTENTS of one mailbox root (`inbox_root` or
    `outbox_root`, `base_dir`), in place: every direct entry other than
    the names in `keep` is removed outright; each name in `keep` that is
    currently a real, non-symlink directory has its CONTENTS purged (kept
    as a directory); a `keep` name that is not currently a real directory
    is removed outright instead.

    Returns `(available, removed_count)`. `available=False` (nothing
    removed) if `base_dir` (looked up by name, relative to `root_fd`)
    doesn't currently exist as a real, non-symlink directory — reset
    never creates or otherwise touches the root itself, only empties what
    is already there. Raises `NamespaceEscapeError` (propagated) if
    `base_dir`, or any `keep` leaf beneath it, has been replaced by a
    symlink resolving OUTSIDE `root` (see `_pin_or_abort`)."""
    rel_name = base_dir.name
    kind, base_fd = _pin_or_abort(root_fd, rel_name, root=root, current_path=base_dir)
    if kind != "dir":
        return False, 0
    try:
        try:
            names = sorted(e.name for e in os.scandir(base_fd))
        except OSError:
            names = []
        removed = 0
        for entry_name in names:
            if entry_name in keep:
                continue
            _remove_one(base_fd, entry_name)
            removed += 1
        for leaf_name in keep:
            leaf_kind, leaf_fd = _pin_or_abort(
                base_fd, leaf_name, root=root, current_path=base_dir / leaf_name,
            )
            if leaf_kind == "missing":
                continue
            if leaf_kind == "dir":
                try:
                    removed += _remove_all_in(leaf_fd)
                finally:
                    os.close(leaf_fd)
            else:
                _remove_one(base_fd, leaf_name)
                removed += 1
        return True, removed
    finally:
        os.close(base_fd)


def _empty_mailboxes(cfg: RouterConfig, name: str) -> Dict[str, Any]:
    """Empty BOTH of instance `name`'s mailbox roots' contents, live and
    securely (see the module docstring's SAFETY section) — `inbox_root`
    and `outbox_root` are probed and emptied INDEPENDENTLY of each other,
    so a half-present mailbox (one root missing or replaced, the other
    intact) still gets its surviving side emptied, and both sides'
    availability is reported rather than one flag hiding which side was
    actually skipped.

    Returns `{"inbox_available", "outbox_available", "removed"}`. Raises
    `NamespaceEscapeError` (propagated) if either root, or any of its two
    skeleton leaves, has been replaced by a symlink resolving outside the
    instance's declared root — the whole reset for THIS instance aborts;
    a batch caller (`reset_instances`) already pre-probed every named
    instance before touching any of them, but this call independently
    re-verifies containment as an atomic, inherent part of the removal
    itself (`O_NOFOLLOW`-pinned file descriptors), never by trusting an
    earlier path-based probe to still be true."""
    inst = cfg.instances[name]
    root = inst.root
    peer_available, peer_removed = False, 0
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        inbox_available, inbox_removed = _empty_root(root, root_fd, inst.inbox_root, _INBOX_KEEP)
        outbox_available, outbox_removed = _empty_root(root, root_fd, inst.outbox_root, _OUTBOX_KEEP)
        if inst.peer_root is not None:
            peer_available, peer_removed = _empty_root(root, root_fd, inst.peer_root, _PEER_KEEP)
    finally:
        os.close(root_fd)
    return {
        "inbox_available": inbox_available,
        "outbox_available": outbox_available,
        "peer_available": peer_available,
        "removed": inbox_removed + outbox_removed + peer_removed,
    }


# --------------------------------------------------------------------
# Router-private state side — never agent-reachable, no dir_fd pinning
# needed; plain path operations are fine here.
# --------------------------------------------------------------------

def _remove_path(p: Path) -> None:
    """Remove one state entry. A symlink is `unlink()`-ed regardless of
    what it points at — its TARGET is never touched, only the link
    itself. A real (non-symlink) directory is `shutil.rmtree`-d.
    Anything else (a regular file) is `unlink()`-ed. Tolerates a
    concurrent remover: a `FileNotFoundError` for either operation is not
    an error here — reset is idempotent."""
    try:
        if p.is_symlink() or not p.is_dir():
            p.unlink()
        else:
            shutil.rmtree(p)
    except FileNotFoundError:
        pass


def _clear_state(cfg: RouterConfig, name: str) -> int:
    """Live, unconditional wipe of `state_dir/<name>`'s CONTENTS:
    `first-seen.json` FIRST, in whatever shape it currently has (regular
    file, directory, or dangling symlink — `.is_file()` alone would miss
    the latter two and leave them behind), then everything else. Always
    re-lists `state_dir/<name>` fresh from disk on every call rather than
    replaying a plan computed earlier — `reset_instance` calls this
    TWICE, before and after the mailbox half, specifically so anything
    written to `state_dir/<name>` DURING the mailbox half (a concurrent
    drain that read the first-sight marker just before this function's
    first call removed it — see the module docstring's ORDERING section)
    is still caught by the second call.

    If `state_dir/<name>` has itself been replaced by a symlink, this
    refuses to descend through it at all — treated as if nothing were
    there, never followed and never cleared. `state_dir` is never
    agent-reachable (`config.py` enforces this at load), so this is
    hardening rather than a live exposure, but a destructive command
    should not trust `Path.is_dir()`'s symlink-following here either.

    `audit/` is skipped by name — the audit log survives a reset (module
    docstring).

    Returns the count of entries removed (0 on an already-clean or
    symlinked instance dir — idempotent)."""
    inst_state_dir = cfg.state_dir / name
    if inst_state_dir.is_symlink() or not inst_state_dir.is_dir():
        return 0
    removed = 0
    first_seen_marker = firstsight.marker_path(cfg.state_dir, name)
    if first_seen_marker.is_symlink() or first_seen_marker.exists():
        _remove_path(first_seen_marker)
        removed += 1
    try:
        rest = sorted(inst_state_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        rest = []
    for p in rest:
        if p.name in _STATE_KEEP:
            continue
        _remove_path(p)
        removed += 1
    return removed


def reset_instance(cfg: RouterConfig, name: str) -> Dict[str, Any]:
    """Reset one instance to a clean slate: state, THEN mailbox, THEN
    state again (see the module docstring's ORDERING section for why the
    re-sweep at the end is needed, not just the first pass). Returns a
    summary dict: `{"name", "was_seen", "mailbox_available",
    "inbox_available", "outbox_available", "state_removed",
    "mailbox_removed"}` — counts, not paths.

    Refuses (`ResetError`) if `name` doesn't name a configured instance;
    raises `NamespaceEscapeError` (propagated) on an escaping mailbox
    leaf, in both cases before anything is removed."""
    plan = plan_reset(cfg, name)  # validates name; fast, early containment probe
    state_removed = _clear_state(cfg, name)
    mailbox = _empty_mailboxes(cfg, name)
    # Re-sweep, LIVE (not `plan.state_paths`, computed before any of this
    # ran) — catches anything a concurrent drain wrote to
    # `state_dir/<name>` while `_empty_mailboxes` was running.
    state_removed += _clear_state(cfg, name)
    summary = {
        "name": name,
        "was_seen": plan.was_seen,
        "mailbox_available": mailbox["inbox_available"] and mailbox["outbox_available"],
        "inbox_available": mailbox["inbox_available"],
        "outbox_available": mailbox["outbox_available"],
        "peer_available": mailbox["peer_available"],
        "state_removed": state_removed,
        "mailbox_removed": mailbox["removed"],
        "audit_preserved": False,
    }
    # The evidence this command spares records the command itself. Written
    # LAST, after both sweeps, so the line describes what actually happened;
    # never fatal — a reset that succeeded is not undone by a log failure.
    try:
        audit_mod.append(
            cfg.state_dir, name, audit_mod.EVENT_RESET,
            was_seen=plan.was_seen,
            state_removed=state_removed,
            mailbox_removed=mailbox["removed"],
            inbox_available=mailbox["inbox_available"],
            outbox_available=mailbox["outbox_available"],
            peer_available=mailbox["peer_available"],
        )
        summary["audit_preserved"] = True
    except (audit_mod.AuditError, OSError) as e:
        logger.warning(
            "instance %r: reset completed but its audit line could not be "
            "appended (%s: %s)", name, type(e).__name__, e,
        )
    return summary


def reset_instances(cfg: RouterConfig, names: Iterable[str]) -> List[Dict[str, Any]]:
    """Reset every name in `names`. All-or-nothing at the batch level:
    every name is validated, and every instance's mailbox leaves are
    containment-probed, BEFORE anything is removed for ANY of them — an
    unknown name or a `NamespaceEscapeError` anywhere aborts the whole
    call with nothing deleted anywhere (matching `provision()`'s existing
    all-or-nothing refusal). This holds regardless of WHERE in the list
    the escaping instance is named — the probe loop below runs over the
    full list first, so an instance named earlier is never touched just
    because it was processed before the escaping one would have been
    reached (`router/tests/test_reset.py`'s
    `TestResetContainmentAbort` pins this for both the first- and
    second-listed positions). Instances are then reset one at a time, in
    the given order; `reset_instance` (via `_empty_mailboxes`)
    independently re-verifies each instance's own containment again,
    atomically, immediately before touching it — this loop's pre-probe is
    a fast up-front check, not the thing that makes the per-instance
    removal itself safe.

    Single-drainer (contract v3.0.0 section 2): acquires the same
    process-wide `state_dir` lock `once`/`run` hold (`router/lock.py`)
    immediately before the removal loop below -- after every name is
    validated and containment-probed above (validation needs no
    exclusivity), but before anything is actually deleted. `reset.py`'s
    own module docstring names the danger this closes: a `router run`
    poll left running during a reset (RUNBOOK section 8 says to stop it
    first; nothing used to enforce that) can write a brand-new private
    result WHILE `_empty_mailboxes` is racing it, surviving as an anchor
    with no matching mailbox entry -- the second `_clear_state` sweep
    narrows that window, the lock now closes it. Raises `ResetError` (not
    `lock.LockHeldError` -- this module's own exception vocabulary, so
    `__main__.py`'s existing `except ResetError` handling covers it with
    no new branch) if another process already holds it; nothing is
    removed in that case."""
    names = list(names)
    unknown = sorted(n for n in names if n not in cfg.instances)
    if unknown:
        raise ResetError(
            f"reset: {unknown} names no configured instance (known: {sorted(cfg.instances)})"
        )
    for name in names:
        _verify_containment(cfg, name)
    try:
        lk = lock_mod.acquire(cfg.state_dir)
    except lock_mod.LockHeldError as e:
        raise ResetError(f"reset: {e}") from e
    try:
        return [reset_instance(cfg, name) for name in names]
    finally:
        lk.release()
