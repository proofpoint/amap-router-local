"""router/audit.py — the append-only audit log, `state_dir/<instance>/audit/log.jsonl`.

The peer-origin profile's retention answer is "the audit log, not the spool":
the seam is where notices travel, this file is the record of what the router
did. One JSON object per line, one file per instance, filed under the
instance WHOSE TREE WAS WRITTEN (a peer notice placed in B's tree is a line in
B's log; the DSN that lands in A's inbox is a line in A's log; a refusal that
wrote nothing is a line in the refused sender's log, since its outbox is what
was drained).

Why under `state_dir` and not under the agent's handoff root: `state_dir` is
the one place the loader PROVES no agent uid can reach (`config.py`), and an
audit record an agent could edit is not one. The spec names an
`<agent-id>/audit/` location as a MAY; it is not exercised until something
reads it.

Every line carries `ts` (`util.utc_ts`, the moment of writing), `event` and
`instance`, then the event's own fields. Events written today, and by whom:

    peer_notice_placed   deliver.deliver_peer     the notice's id, from/to (addresses
                                                  and instance names), req_id, in_reply_to
                                                  (null on a fresh task), reply_basis
                                                  ("edge" | "reply_window" | null), the
                                                  sender_exposure stamp verbatim, origin
                                                  ("local"), signature_verdict and
                                                  demotion_cause (both null same-host;
                                                  reserved for the cross-host verifier)
    peer_refused         outbound                 a peer-lane refusal: req_id, reason_code,
                                                  the instance names involved
    outcome_consumed     outcomes                 one daemon outcome recorded once per
                                                  (tree, notice_id, outcome): the daemon's
                                                  ts, its `detail` (logged here, NEVER
                                                  forwarded), the sender it concerns
    outcome_discarded    outcomes                 an outcome file read and discarded, with
                                                  `cause` (malformed | unknown_notice_id |
                                                  duplicate)
    dsn_sent             deliver.deliver_router_notice
                                                  a router-authored DSN placed in a
                                                  sender's inbox: its own notice_id, the
                                                  peer id it answers, the outcome
    reset                reset                    the one evidence-destroying command,
                                                  recorded in the evidence it spares

Write discipline: parents created as needed; the file opened `O_APPEND |
O_CREAT | O_NOFOLLOW` and one line written per call — a single `write(2)`
of a line far below any page size, so concurrent appenders (a `reset` racing
a `run`, both legitimately holding nothing against each other on this file)
interleave whole lines, never characters. A symlinked `state_dir/<instance>`
is refused rather than followed (`AuditError`), the same hardening `reset.py`
applies to that directory; `state_dir` is never agent-reachable, so this is
posture, not a live exposure. Nothing here ever rewrites or truncates the
file — `reset` is the one command that clears `state_dir/<instance>`, and it
skips `audit/` by name.

`read_events` exists for tests and operators; the router never reads its own
audit log to decide anything.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from .util import utc_ts

AUDIT_DIR = "audit"
AUDIT_FILENAME = "log.jsonl"

EVENT_PEER_NOTICE_PLACED = "peer_notice_placed"
EVENT_PEER_REFUSED = "peer_refused"
EVENT_OUTCOME_CONSUMED = "outcome_consumed"
EVENT_OUTCOME_DISCARDED = "outcome_discarded"
EVENT_DSN_SENT = "dsn_sent"
EVENT_RESET = "reset"


class AuditError(Exception):
    """Raised when the log cannot be appended to safely — today only when
    `state_dir/<instance>` has been replaced by a symlink. Callers decide
    whether that aborts their operation (a peer delivery: yes, before the
    notice is written) or is logged and skipped (a reset line)."""


def audit_dir(state_dir: Path, instance: str) -> Path:
    return Path(state_dir) / instance / AUDIT_DIR


def log_path(state_dir: Path, instance: str) -> Path:
    return audit_dir(state_dir, instance) / AUDIT_FILENAME


def build_line(event: str, instance: str, fields: Dict[str, Any]) -> bytes:
    """The bytes of one audit line — `ts`, `event`, `instance`, then
    `fields`, keys sorted, one trailing newline. Split from `append` so a
    caller that must write the line as part of its own commit ordering can
    build it first and write it at the right moment."""
    doc: Dict[str, Any] = {"ts": utc_ts(), "event": event, "instance": instance}
    for k, v in fields.items():
        if k in doc:
            raise ValueError(f"audit field {k!r} collides with the envelope")
        doc[k] = v
    return (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8")


def append(state_dir: Path, instance: str, event: str, **fields: Any) -> None:
    """Append one line for `event` to `instance`'s log. See the module
    docstring for the write discipline and the symlink refusal."""
    append_bytes(state_dir, instance, build_line(event, instance, fields))


def append_bytes(state_dir: Path, instance: str, line: bytes) -> None:
    """`append` for a line already built by `build_line` — the form
    `deliver.py` uses so the line is composed before the commit sequence
    and written at its place in it."""
    inst_dir = Path(state_dir) / instance
    if inst_dir.is_symlink():
        raise AuditError(
            f"refusing to append to the audit log: {inst_dir} is a symlink"
        )
    d = audit_dir(state_dir, instance)
    d.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(d / AUDIT_FILENAME),
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def read_events(state_dir: Path, instance: str) -> List[Dict[str, Any]]:
    """Every line of `instance`'s log, parsed, in file order. `[]` when
    there is no log yet. A line that does not parse is returned as
    `{"_unparsed": "<text>"}` rather than dropped — a reader of an audit log
    must never be shown fewer records than exist."""
    path = log_path(state_dir, instance)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            out.append({"_unparsed": raw})
            continue
        out.append(doc if isinstance(doc, dict) else {"_unparsed": raw})
    return out
