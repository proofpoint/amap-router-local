"""router/lock.py — single-writer, single-drainer mutual exclusion
(contract v3.0.0 §2, lines 74-85; ROUTER-RELIABILITY.md RR-F1, reproduced
15/15 with no attacker needed).

**The gap this closes.** Nothing in this router enforced single-instance
operation before this module existed: no lockfile, pidfile, `flock`, or
`O_EXCL` claim anywhere. Two `once`/`run` processes against the same
`state_dir` — or a `reset` overlapping a live drain, the exact case
`reset.py`'s module docstring names but never enforced ("RUNBOOK §8 says
to stop it first, but nothing enforces that") — duplicate every message
in flight and can publish a false `rejected` verdict for a request that
was, in fact, delivered by the OTHER process. Every atomicity guarantee
this contract makes (`.tmp` + rename, the commit-sentinel write order,
`req_id` derivation from `max(pending, processed, results)+1`) is sound
only under the assumption of one writer / one drainer per namespace; none
of it provides mutual exclusion on its own (contract §2, "Single writer,
single drainer").

**Mechanism: `fcntl.flock`, deliberately not a pidfile.** An `flock` is
bound to the OPEN FILE DESCRIPTION, not to a PID recorded in the file's
bytes — so the kernel releases it automatically the moment the holding
process's fd is closed, whether that happens via a clean `release()` or
because the process was `kill -9`'d and the OS tore down its file table.
There is therefore no stale-lock state to reap and no liveness check
(`kill -0`, PID reuse, ...) to get wrong: a fresh process that calls
`acquire()` after a crash simply succeeds, immediately, with no operator
intervention. A pidfile is strictly worse here — it needs a liveness
probe, is racy on PID reuse, and leaves a turd behind after a hard kill.
The PID is still written into the lock file's bytes (`_write_pid`), but
ONLY as a diagnostic for a human reading `LockHeldError`'s message or the
file directly; nothing in this module ever reads it back to decide
whether the lock is actually held — that question is answered by the
`flock` call itself, exclusively.

**A PROBE FOR "IS ANYTHING RUNNING" CAN ITSELF STOP SOMETHING RUNNING.**
Recorded because a host adapter asked to gate a migration on this lock, and
the obvious use of it is harmful. `acquire` fails FAST rather than queueing,
so a `run`/`once` that starts DURING somebody's probe does not wait — it
raises `LockHeldError` and exits. The prober has then refused a router that
was doing nothing wrong, and the operator sees a router that would not start
with no mention of the prober in the message.

Two consequences worth stating, because the second is counter-intuitive:
acquiring and releasing IMMEDIATELY is safe for a router starting after the
release (the kernel drops the lock when the fd closes, so it acquires
normally) and unsafe only for one starting inside the window. And SUCCESS is
not evidence that nothing is running, beyond that instant — nothing stops a
router starting a moment later. Only HOLDING the lock for the duration of
the work gives that, at the price of making a concurrent `run` fail loudly,
which is the correct outcome and worth an operator recognising.

`LockHeldError` is the positive evidence in either design. Nothing should
read the PID from the file's bytes to answer the question — see above.

**Where the lock file lives.** `state_dir` is never agent-reachable
(`config.py` enforces that at load, independent of this module) — plain
`os.open`/`fcntl.flock` on a path is safe here with no `O_NOFOLLOW`
pinning; a hostile symlink swap on the lock path itself is not a threat
this file exists to defend against (nothing agent-controlled ever
resolves this path). The lock file sits directly under `state_dir`,
alongside `status.json` and each instance's `state_dir/<name>` — never
inside any instance's own subtree, so `reset.py`'s per-instance
`_clear_state` (which only ever lists `state_dir/<name>`) never touches
it.

**One process-wide lock, not one per instance.** `run_once`/`drain_
instance` iterates every configured instance in a single call
(`service.run_once`), so a single lock covering the whole `state_dir` is
the right granularity: it is exactly the boundary within which `service.
run_once`/`reset.reset_instances` promise not to be re-entered
concurrently. A caller that wants to run one drain loop per namespace
still needs a distinct `state_dir` per namespace to get a distinct lock
— that's already the deployment shape a per-instance `state_dir/<name>`
implies.

**Where it is acquired, deliberately NOT inside `run_once`/`drain_
instance`.** `service.run_once` is the unit the test suite drives
directly, dozens of times, with no threading and no process boundary
(`service.py`'s own module docstring) — locking inside it would force
every existing behavior test to also manage this lock for no behavioral
reason of its own. The lock is acquired at the actual process/operation
boundary instead: `__main__.main()` for the `once` and `run` subcommands
(held for that whole subcommand's duration — the whole process lifetime,
for `run`), and inside `reset.reset_instances` immediately before its
removal loop (after every instance name has been validated and
containment-probed, but before anything is actually deleted) — see that
function's docstring for why validation itself does not need the lock."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import Optional, Union

LOCK_NAME = ".router.lock"


class LockHeldError(Exception):
    """Raised by `acquire` when another process already holds the
    namespace-wide drain/reset lock (`fcntl.flock(..., LOCK_NB)` returned
    `EWOULDBLOCK`/`EAGAIN`). `holder_pid`, if available, is read from the
    lock file's contents for a human-readable message ONLY — it is never
    consulted to decide whether the lock is held; the failed `flock` call
    already answered that authoritatively."""

    def __init__(self, lock_path: Path, holder_pid: Optional[str]) -> None:
        who = f"pid {holder_pid}" if holder_pid else "an unknown process"
        # NAMES BOTH KINDS OF HOLDER, because the message used to say
        # "another drainer" and that is now sometimes false. A host adapter
        # holds this lock for the DURATION of a migration — deliberately, so
        # that a router starting mid-move exits here rather than draining a
        # tree being moved under it — and an operator reading "another
        # drainer" would go hunting for a second router that does not exist.
        #
        # The lock cannot say WHICH: `flock` carries no label and the file's
        # bytes hold only a diagnostic pid. So the message says the pid is
        # the only thread to pull, rather than implying a drainer.
        super().__init__(
            f"{lock_path} is held by {who} — refusing to run concurrently "
            f"(contract v3.0.0 §2: single writer, single drainer). The holder "
            f"is a drainer (`run`/`once`/`reset`) OR a host adapter holding "
            f"this lock across a migration; the lock itself does not say "
            f"which, and {who} is the only way to tell them apart"
        )
        self.lock_path = lock_path
        self.holder_pid = holder_pid


class DrainLock:
    """A held lock, returned by `acquire`. Call `release()` when done (or
    use as a context manager); `release()` is idempotent. Closing the fd
    is what actually drops the kernel `flock` — there is nothing else to
    clean up, by design (see the module docstring's "stale lock" section)."""

    def __init__(self, fd: int, path: Path) -> None:
        self._fd: Optional[int] = fd
        self.path = path

    def release(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __enter__(self) -> "DrainLock":
        return self

    def __exit__(self, *exc_info) -> None:
        self.release()


def acquire(state_dir: Union[str, Path]) -> DrainLock:
    """Acquire the process-lifetime drain/reset lock for `state_dir`,
    non-blocking. Raises `LockHeldError` immediately if another process
    already holds it — NEVER blocks waiting for it (a blocking acquire
    here would just turn "two drainers" into "one drainer, badly
    serialized," and would wedge a batch `reset` behind a long-running
    `run` for no benefit; failing fast is the contract-correct behavior:
    "a runtime MUST NOT run two concurrent drains of one namespace," not
    "must queue them"). Creates `state_dir` if it doesn't exist yet (the
    lock can be the very first thing written there, e.g. `once` before
    any instance has ever been seen or drained)."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / LOCK_NAME
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        holder_pid = _read_pid(fd)
        os.close(fd)
        raise LockHeldError(lock_path, holder_pid)
    _write_pid(fd)
    return DrainLock(fd, lock_path)


def _read_pid(fd: int) -> Optional[str]:
    """Best-effort diagnostic read of whatever PID text is currently in
    the lock file — via `os.pread` at offset 0, genuinely independent of
    (never disturbing) the caller's own fd/offset, and never raising: this
    is a nicety for a human-readable error message, not something the
    lock's correctness depends on.

    `os.dup(fd)` (the old approach) does NOT achieve that: a dup'd fd
    shares the same OPEN FILE DESCRIPTION as `fd`, including its file
    *offset* — reading through the dup still advances `fd`'s own offset,
    exactly as if `fd` had been read directly. Harmless today (the only
    caller closes `fd` immediately afterward on the failure path, never
    reads through it again), but wrong for a module whose whole value is
    exact reasoning about file descriptions — see the module docstring.
    `pread` reads at an explicit offset without touching the description's
    offset at all, which is what "never disturbing the caller's own
    fd/offset" actually requires."""
    try:
        data = os.pread(fd, 64, 0)
    except OSError:
        return None
    text = data.decode("ascii", errors="replace").strip()
    return text or None


def _write_pid(fd: int) -> None:
    """Best-effort: write this process's PID into the now-held lock file,
    for a human `cat`-ing it or reading a future `LockHeldError`'s
    message. Never consulted for correctness — see the module docstring."""
    try:
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode("ascii"))
    except OSError:
        pass
