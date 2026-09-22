"""router/outcomes.py — consume the delivery outcomes a receiving daemon writes.

The in-sandbox delivery daemon performs the last hop of every peer notice —
the UDS injection this router never speaks — and reports what happened
through the spec's connector-owned side channel, `outbox/ext/<name>/outcomes/`,
one file per outcome, named `peer-<notice_id>.json`:

    {"outcome": "delivered" | "held" | "denied" | "refused" |
                "ambiguous_target" | "inject_failed",
     "ts": "<ISO 8601 UTC, seconds>", "tree": "peer",
     "notice_id": "<32 hex, = the filename's>",
     "detail": "<optional free text>"}                      # no other keys

`<name>` is `claude-code` — the id the spec pins, which does not change when
the connector's repository is renamed and is opaque to this router
(`CONNECTOR_ID`). A compatibility path under the old repo-tracking spelling
was scanned alongside it for one release and was RETIRED on 2026-09-22; see
that commit for the decision and for what was not established when it was
made.

Outcomes are INFORMATIONAL, NOT PROOF. They are written by the workspace
uid — the agent's uid — so the receiving agent can forge `delivered` or
suppress `refused` for delegations addressed to itself. They change what a
SENDER is told and what an OPERATOR sees; they never change what the ledger
or the audit log records as fact, and nothing security-relevant is built on
them (the spec's rule for `outbound/ext/`). Which is also why `detail` — the
receiver's free text — is logged and NEVER forwarded: a DSN that quoted it
would put one agent's prose in front of another under this router's framing.

Read with the outbox discipline, because it is the agent's directory:
pinned `O_NOFOLLOW` descent from the instance root, filename hygiene
(`^peer-[a-f0-9]{32}\\.json$` — the daemon's `.peer-<id>.json.tmp` staging
name fails it, so a partial file is never read), `O_NOFOLLOW|O_NONBLOCK`
open, `fstat`-verified regular file with `nlink == 1`, a bounded read, and a
cap on how many files one poll will look at. The shape is checked exactly:
the closed key set, the vocabulary, `tree == "peer"`, `notice_id` equal to
the filename's. Then the router's own ledger under the RECIPIENT is the
judge of whether this router ever issued that id to that recipient on the
peer tree; an outcome for an id it did not is logged and discarded.

Each outcome is recorded ONCE per `(tree, notice_id, outcome)` at
`state_dir/<recipient>/outcomes/<tree>-<notice_id>.<outcome>.json` — the
record is the dedup key, so a re-read is idempotent and a sender is never
DSN'd twice for one transition — and the outcome file is then UNLINKED, in
every case where it was read (recorded, duplicate, unknown, malformed): the
daemon re-creates the same name for a later transition (`held`, then
`delivered`) and tolerates the file being gone at any time. The binding
record is never annotated: the outcome record beside it IS the annotation,
keyed by the same id, and the reply-binding record stays written-once.

    outcome            router's response
    delivered          audit; counter. Nothing to the sender.
    held               audit; counter; OPERATOR ALERT (`peer_alerts` in the poll
                       summary -> `status` banner). Not a failure, no timeout,
                       nothing to the sender. A later delivered/denied is handled as
                       such — it is an alert, not a state machine.
    denied             audit; counter; DSN to the sender.
    refused            audit; counter; DSN to the sender; OPERATOR ALERT naming
                       sender and recipient. The alert is the point: the
                       daemon rejected something THIS ROUTER authorised, and
                       the two disagree about a delegation the policy allows.
                       Since ruling 16 the daemon holds no allowlist, so the
                       disagreement is no longer "two renderings of one
                       policy" — it is an integrity check of the daemon's own
                       failing, and only the daemon knows which.
    ambiguous_target   audit; counter; alert (status banners it when it recurs).
                       Nothing to the sender; the spool holds.
    inject_failed      audit; counter. Nothing to the sender; the daemon retries.
    (none)             nothing. Silence is never inferred from, and no notice is
                       ever re-written.

The DSN (`deliver.deliver_router_notice`) is mail from the router's own
address into the SENDER's `inbox/`: `in_reply_to` = the peer message id,
subject `Not delivered: <outcome>`, body router-authored only — the reported
outcome, the peer id, the recipient's address, the daemon's timestamp, one
sentence of meaning. Every sentence of it, like every `status` banner, is
worded as the receiving sandbox's CLAIM ("the recipient's sandbox reported
that ..."), never as a fact the router established — it did not, and cannot
(see "INFORMATIONAL, NOT PROOF" above). Order: record -> DSN -> unlink. A DSN that fails to write is
logged and counted (`peer_dsn_failed`); the transition stays recorded and is
not retried — at-most-once for the DSN, so a sender is never told twice.

The summary this returns is merged into the instance's per-poll drain
summary by `service.run_once` ONLY for instances on the peer lane
(`InstanceConfig.peer_root` set), so a fleet without one sees exactly the
summary it always did. Counter keys are listed in `status.TOTAL_KEYS`;
`peer_alerts` is a list of dicts `status` renders as banners.

`peer_placed_denied` (`placed_but_denied`) is the one shape a receiver's
deniability takes, and it is visible only from here, where the ledger and
the outcome records sit together: per receiver, every peer notice whose
ledger record says THIS ROUTER placed it (`tree: "peer"`) and whose LATEST
recorded outcome is `denied` or `refused`. It is recomputed from disk every
poll — it is state, not a per-process counter — so it survives a router
restart and drops a notice the moment a later `delivered` is recorded. A
receiver that reports "a human declined it" for everything a particular
sender places shows up here as a list, not as a scatter of DSNs in someone
else's inbox.

THE GAP IS THE MAIL LANE, AND IT IS NOT THIS MODULE'S TO CLOSE. Every
signal here is driven by an outcome record EXISTING, and there is no
detection for a notice this router placed that is never answered at all — no
staleness check, no unanswered list, nothing separating "answered silently
never" from "still in flight". That blindness is REAL but it is confined to
the mail lane, and the scoping was corrected by the connector rather than
reasoned out here.

  PEER LANE — COVERED. A receiving sandbox that refuses cross-session
  messages writes `held`, with a `detail` naming the setting and the fix,
  and re-offers hourly; the same notice goes `held` -> `delivered` on its
  own once the setting changes. Not silent, not terminal, and deliberately
  NOT `refused` — the daemon reserves that for its own gate, which is
  exactly the reading of `refused` this module states. An earlier draft of
  this paragraph assumed a silent drop was possible here. It is not.

  AND ONE CAUSE THAT IS NOBODY'S LANE. The connector creates
  `ext/<name>/outcomes/` with `makedirs(exist_ok=True)` ON EVERY WRITE, not
  at startup — so a clean sandbox correctly has no such directory and its
  absence must never be asserted against. But that creation failing is
  NON-FATAL there and logs one line nothing watches, so an outbox lane
  mounted read-only, or owned by the wrong uid, produces exactly the silence
  above with no bug in any of the three repos: the agent submits, delivery
  happens, the outcome cannot be written, and every surface looks healthy.
  Traced by the host adapter, which now probes the inverse of its EROFS
  check — a write from the agent uid INSIDE the outbox lane that must
  succeed. Recorded here because the symptom surfaces on this side and the
  cause does not.

  MAIL LANE — BLIND, BY DESIGN AND NOT BY OVERSIGHT. The mail notice is a
  content-free doorbell and the outcome channel does not exist for it, so
  the daemon writes NO outcome ever. On a refusing receiver it simply
  retries hourly and records nothing. From this side a `deliver` notice sits
  placed with no outcome and no signal, and ANY condition that keeps the
  doorbell from landing looks identical to one that landed.

So the honest statement is narrower than the one this paragraph first made,
and is not fixable here: a lane with no outcome channel cannot be observed
through the outcome channel. Whatever closes it lives with the ledger, which
knows what was placed and when, not with the outcomes reader, which can only
report what someone wrote.

One thing that is NOT observable on either lane, and that nothing should be
built to need: `delivered` means the frame was ACCEPTED, not that the
session read it. Under `accept` the receiver emits no receipt at all, so
silence within the window is inferred delivery. Whether it was ever acted on
is not visible from here and never will be.

It is computable from data already on disk: the ledger record carries the
placement and its timestamp; the outcomes directory answers or does not. Not
built, because what to DO about it — a banner, a DSN, after how long — is a
policy question, and guessing it is how a good signal becomes noise.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import attachments as attachments_mod
from . import audit as audit_mod
from . import binding
from . import deliver as deliver_mod
from .config import RouterConfig, address_for
from .util import atomic_write, utc_ts

logger = logging.getLogger("amap_router_local.outcomes")

#: The connector id in `outbound/ext/<name>/`. The spec pins it
#: (AMAP core §2, the commit pinning `outbound/ext/<name>` as a stable
#: connector id — v3.1.0 DRAFT): `<name>` MUST NOT change when the
#: connector's repository is renamed, and MUST be treated as opaque. So this
#: is a CONSTANT, not a repo name that happens to be current — it survives
#: `amp-connector-claude-code` -> `amap-connector-claude` untouched, and
#: nothing here may parse it.
CONNECTOR_ID = "claude-code"


def outcomes_rel(connector_id: str) -> Path:
    """`ext/<connector_id>/outcomes`, relative to `outbox_root`."""
    return Path("ext") / connector_id / "outcomes"


#: Where the daemon writes, relative to `outbox_root` (spec `outbound/ext/<name>/`).
OUTCOMES_REL = outcomes_rel(CONNECTOR_ID)
#: The directories scanned each poll. A TUPLE with one member, not a bare
#: path: `_consume_dir` iterates it and shares one file budget across
#: whatever it holds, and a second entry has been in here before. Keeping the
#: shape means re-adding one is a one-line change rather than a reshaping of
#: the consumption loop.
OUTCOMES_RELS = (OUTCOMES_REL,)

OUTCOME_NAME_RE = re.compile(r"^peer-([a-f0-9]{32})\.json$")

OUTCOME_DELIVERED = "delivered"
OUTCOME_HELD = "held"
OUTCOME_DENIED = "denied"
OUTCOME_REFUSED = "refused"
OUTCOME_AMBIGUOUS_TARGET = "ambiguous_target"
OUTCOME_INJECT_FAILED = "inject_failed"
OUTCOMES = (
    OUTCOME_DELIVERED, OUTCOME_HELD, OUTCOME_DENIED, OUTCOME_REFUSED,
    OUTCOME_AMBIGUOUS_TARGET, OUTCOME_INJECT_FAILED,
)
#: Terminal failures: the sender is told, by DSN.
DSN_OUTCOMES = frozenset({OUTCOME_DENIED, OUTCOME_REFUSED})
#: Operator alerts (`peer_alerts` entries).
ALERT_OUTCOMES = frozenset({OUTCOME_HELD, OUTCOME_REFUSED, OUTCOME_AMBIGUOUS_TARGET})

_REQUIRED_KEYS = frozenset({"outcome", "ts", "tree", "notice_id"})
_ALLOWED_KEYS = _REQUIRED_KEYS | {"detail"}

#: One outcome file is a few hundred bytes; anything near this is not one.
OUTCOME_READ_CAP = 64 * 1024
#: Files examined per instance per poll. The directory is agent-writable.
MAX_FILES_PER_POLL = 1000

#: Every counter this module can put in a summary (mirrored in `status.TOTAL_KEYS`).
COUNTER_KEYS = (
    "peer_outcomes_seen",
    "peer_delivered", "peer_held", "peer_denied", "peer_refused",
    "peer_ambiguous_target", "peer_inject_failed",
    "peer_outcome_discarded", "peer_outcome_errored",
    "peer_dsn_sent", "peer_dsn_failed",
)

#: One sentence of meaning per terminal outcome — the whole of what a
#: sender learns beyond the mechanical facts. Router-authored, never `detail`.
#:
#: Phrased as the RECEIVER'S CLAIM, never as fact: an outcome file is
#: written by the receiving sandbox's own uid (module docstring), so the
#: router cannot vouch that a human really reviewed anything or that a daemon
#: really refused. A sending agent that read "a human declined it" would be
#: reading a fact the router does not have. Every sentence here, and every
#: `status` banner (`status._peer_banners`), attributes the outcome to the
#: recipient's sandbox as something it REPORTED.
_DSN_MEANING = {
    OUTCOME_DENIED: (
        "The recipient's sandbox reported that a human reviewed this message and "
        "declined it."
    ),
    OUTCOME_REFUSED: (
        # NO CAUSE IS STATED, because this router does not have one. The
        # daemon's `detail` is read and logged and deliberately never
        # forwarded (module docstring: a DSN quoting it would put one agent's
        # prose in front of another under this router's framing). The previous
        # text named a cause anyway — "your address is not in its
        # allowed-senders list" — which was a guess even when daemons had an
        # allowlist, and became simply false when ruling 16 removed it. It
        # cost an operator a real debugging session: the daemon was refusing
        # every notice for an unrelated reason, and the DSN sent them hunting
        # for a list that no longer exists.
        "The recipient's sandbox reported that its delivery daemon refused this "
        "message. It did not say why, and this router does not forward the "
        "daemon's own reason — the cause is in the recipient sandbox's daemon "
        "log, not in this notice. The operator has been alerted."
    ),
}

DSN_SUBJECT_PREFIX = "Not delivered: "


def record_path(state_dir: Path, recipient: str, tree: str, notice_id: str, outcome: str) -> Path:
    return state_dir / recipient / "outcomes" / f"{tree}-{notice_id}.{outcome}.json"


class _Discard(Exception):
    """An outcome file that was read and must be logged and unlinked, not
    acted on. `cause` is the audit line's."""

    def __init__(self, cause: str, detail: str = ""):
        super().__init__(f"{cause}: {detail}" if detail else cause)
        self.cause = cause
        self.detail = detail


def _read_outcome_pinned(dir_fd: int, filename: str) -> bytes:
    """The outbox read discipline (`outbound._read_request_pinned`), on one
    outcome file: `O_NOFOLLOW|O_NONBLOCK`, `fstat` regular + `nlink == 1`,
    bounded read. Raises `OSError` (a natural subtype where one applies)."""
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{filename!r} is not a regular file")
        if st.st_nlink != 1:
            raise OSError(f"{filename!r} has nlink={st.st_nlink} (expected 1)")
        chunks: List[bytes] = []
        got = 0
        limit = OUTCOME_READ_CAP + 1
        while got < limit:
            chunk = os.read(fd, min(attachments_mod._READ_CHUNK, limit - got))
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        data = b"".join(chunks)
        if len(data) > OUTCOME_READ_CAP:
            raise OSError(f"{filename!r} exceeds the outcome read cap")
        return data
    finally:
        os.close(fd)


def _parse_outcome(raw: bytes, notice_id: str) -> Dict[str, Any]:
    """The agreed shape, exactly. Anything else is `_Discard("malformed")`."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise _Discard("malformed", f"invalid JSON: {type(e).__name__}")
    if not isinstance(doc, dict):
        raise _Discard("malformed", "not an object")
    keys = set(doc)
    if not _REQUIRED_KEYS <= keys or not keys <= _ALLOWED_KEYS:
        raise _Discard("malformed", f"keys {sorted(keys)}")
    if doc["outcome"] not in OUTCOMES:
        raise _Discard("malformed", f"outcome {doc['outcome']!r}")
    if doc["tree"] != deliver_mod.TREE_PEER:
        raise _Discard("malformed", f"tree {doc['tree']!r}")
    if doc["notice_id"] != notice_id:
        raise _Discard("malformed", "notice_id differs from the filename's")
    if not isinstance(doc["ts"], str) or not doc["ts"]:
        raise _Discard("malformed", "ts")
    if "detail" in doc and not isinstance(doc["detail"], str):
        raise _Discard("malformed", "detail is not a string")
    return doc


def _dsn(
    cfg: RouterConfig, sender: str, recipient: str, notice_id: str, outcome: Dict[str, Any],
) -> Dict[str, str]:
    """Author and place the DSN in `sender`'s inbox (module docstring).
    Body is router-authored only; `detail` is not consulted."""
    kind = outcome["outcome"]
    recipient_address = address_for(recipient, cfg.fleet_domain)
    # Every sentence attributes the outcome to the recipient's sandbox as a
    # claim (see `_DSN_MEANING`); the mechanical lines are labelled
    # "reported" for the same reason. The one fact the router states on its
    # own authority is that it placed no delivery — which it did not.
    body = (
        f"The sandbox at {recipient_address} reported that it did not deliver "
        f"your peer message.\n"
        f"\n"
        f"reported outcome: {kind}\n"
        f"peer message id: {notice_id}\n"
        f"recipient: {recipient_address}\n"
        f"reported at: {outcome['ts']}\n"
        f"\n"
        f"{_DSN_MEANING[kind]}\n"
    )
    return deliver_mod.deliver_router_notice(
        cfg, cfg.state_dir, sender,
        subject=f"{DSN_SUBJECT_PREFIX}{kind}",
        body_text=body,
        in_reply_to=notice_id,
        audit_fields={
            "outcome": kind,
            "peer_notice_id": notice_id,
            "peer_recipient": recipient,
        },
    )


def _consume_one(
    cfg: RouterConfig, name: str, dir_fd: int, filename: str, notice_id: str,
    summary: Dict[str, Any],
) -> None:
    """Read, judge, record, act, unlink — one outcome file for recipient
    `name`. Every path that READ the file ends in an unlink (module
    docstring); a file that could not be read is left alone and counted
    `peer_outcome_errored`."""
    try:
        raw = _read_outcome_pinned(dir_fd, filename)
    except FileNotFoundError:
        return  # gone between listing and open — the daemon's, or a concurrent poll's
    except OSError as e:
        logger.warning(
            "instance %r: could not read outcome %r (%s: %s) — left in place",
            name, filename, type(e).__name__, e,
        )
        summary["peer_outcome_errored"] += 1
        return

    try:
        doc = _parse_outcome(raw, notice_id)
        record = binding.read_ledger_record(cfg.state_dir, name, notice_id)
        if record is None or record.get("tree") != deliver_mod.TREE_PEER:
            raise _Discard("unknown_notice_id",
                           "no peer notice with this id was ever issued to this instance")
        outcome = doc["outcome"]
        rec_path = record_path(cfg.state_dir, name, deliver_mod.TREE_PEER, notice_id, outcome)
        if rec_path.exists():
            raise _Discard("duplicate", f"{outcome} already recorded for this notice")

        sender = record.get("from_instance")
        stored = {
            "tree": deliver_mod.TREE_PEER,
            "notice_id": notice_id,
            "outcome": outcome,
            "outcome_ts": doc["ts"],
            "detail": doc.get("detail"),
            "recorded_ts": utc_ts(),
            "from_instance": sender,
            "to_instance": name,
            "req_id": record.get("req_id"),
        }
        atomic_write(rec_path, json.dumps(stored, sort_keys=True).encode("utf-8"))
        audit_mod.append(
            cfg.state_dir, name, audit_mod.EVENT_OUTCOME_CONSUMED,
            tree=deliver_mod.TREE_PEER, notice_id=notice_id, outcome=outcome,
            outcome_ts=doc["ts"], detail=doc.get("detail"),
            from_instance=sender, to_instance=name,
        )
        summary[f"peer_{outcome}"] += 1

        if outcome in ALERT_OUTCOMES:
            summary["peer_alerts"].append({
                "kind": outcome, "notice_id": notice_id,
                "sender": sender, "recipient": name, "ts": doc["ts"],
            })

        if outcome in DSN_OUTCOMES:
            if isinstance(sender, str) and sender in cfg.instances:
                try:
                    _dsn(cfg, sender, name, notice_id, doc)
                    summary["peer_dsn_sent"] += 1
                except Exception as e:  # noqa: BLE001 — recorded; never retried
                    logger.warning(
                        "instance %r: DSN to %r for peer notice %s failed (%s: %s)",
                        name, sender, notice_id, type(e).__name__, e,
                    )
                    summary["peer_dsn_failed"] += 1
            else:
                logger.warning(
                    "instance %r: peer notice %s has no configured sender to DSN (%r)",
                    name, notice_id, sender,
                )
                summary["peer_dsn_failed"] += 1
    except _Discard as d:
        summary["peer_outcome_discarded"] += 1
        logger.info("instance %r: outcome %r discarded: %s", name, filename, d)
        try:
            audit_mod.append(
                cfg.state_dir, name, audit_mod.EVENT_OUTCOME_DISCARDED,
                tree=deliver_mod.TREE_PEER, notice_id=notice_id,
                cause=d.cause, detail=d.detail,
            )
        except (audit_mod.AuditError, OSError) as e:
            logger.warning("instance %r: could not audit the discard (%s: %s)",
                           name, type(e).__name__, e)
    finally:
        # Consumed, in every sense that reached here: the daemon re-creates
        # the name on a later transition and never assumes it is still there.
        try:
            os.unlink(filename, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("instance %r: could not unlink outcome %r (%s: %s)",
                           name, filename, type(e).__name__, e)


def empty_summary() -> Dict[str, Any]:
    d: Dict[str, Any] = {k: 0 for k in COUNTER_KEYS}
    d["peer_alerts"] = []
    d["peer_placed_denied"] = []
    return d


#: The record files `_consume_one` writes: `<tree>-<notice_id>.<outcome>.json`.
_RECORD_NAME_RE = re.compile(
    r"^(?P<tree>[a-z]+)-(?P<notice_id>[a-f0-9]{32})\.(?P<outcome>[a-z_]+)\.json$"
)


def placed_but_denied(cfg: RouterConfig, name: str) -> List[Dict[str, Any]]:
    """The placed-but-denied list for receiver `name` (module docstring):
    every peer notice this router's ledger says it placed in `name`'s peer
    tree whose LATEST recorded outcome is `denied` or `refused`.

    "Latest" is the most recently WRITTEN record for that notice id —
    ordered by `recorded_ts`, then by the record file's mtime (nanoseconds)
    for two transitions recorded within one second, e.g. `held` then
    `denied` in the same poll. A notice whose latest record is `delivered`,
    `held`, `ambiguous_target` or `inject_failed` is not listed, whatever
    came before it. Records this router did not write the way it writes
    them (name hygiene fails, unparseable, not an object, tree not `peer`)
    are skipped, not fatal; a missing ledger record, or one that does not
    say `tree: "peer"`, drops the notice — the router placed nothing it can
    be told was denied. Read from router-private state only; nothing here
    touches an agent-writable directory."""
    rec_dir = cfg.state_dir / name / "outcomes"
    try:
        entries = list(os.scandir(rec_dir))
    except FileNotFoundError:
        return []
    latest: Dict[str, tuple] = {}
    for entry in entries:
        m = _RECORD_NAME_RE.match(entry.name)
        if not m or m.group("tree") != deliver_mod.TREE_PEER:
            continue
        try:
            st = entry.stat()
            if not stat.S_ISREG(st.st_mode):
                continue
            doc = json.loads(Path(entry.path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict) or doc.get("outcome") != m.group("outcome"):
            continue
        nid = m.group("notice_id")
        key = (str(doc.get("recorded_ts") or ""), st.st_mtime_ns)
        prior = latest.get(nid)
        if prior is None or key > prior[0]:
            latest[nid] = (key, doc)
    out: List[Dict[str, Any]] = []
    for nid in sorted(latest):
        doc = latest[nid][1]
        if doc.get("outcome") not in DSN_OUTCOMES:
            continue
        ledger = binding.read_ledger_record(cfg.state_dir, name, nid)
        if ledger is None or ledger.get("tree") != deliver_mod.TREE_PEER:
            continue
        out.append({
            "notice_id": nid,
            "sender": ledger.get("from_instance"),
            "recipient": name,
            "outcome": doc.get("outcome"),
            "outcome_ts": doc.get("outcome_ts"),
            "recorded_ts": doc.get("recorded_ts"),
            "req_id": ledger.get("req_id"),
        })
    return out


def consume_instance(cfg: RouterConfig, name: str) -> Dict[str, Any]:
    """Consume every outcome file in `name`'s outcomes directory once
    (module docstring), then recompute `peer_placed_denied` from the
    records on disk. Returns the counters + `peer_alerts` +
    `peer_placed_denied`. A missing directory (no daemon has written yet)
    consumes nothing but still reports the list — the records it is built
    from are router-private and outlive the daemon's files. An instance
    with no peer tree gets the empty summary. Never raises for a per-file
    surprise; a listing-level surprise propagates to `service.run_once`'s
    per-instance isolation."""
    summary = empty_summary()
    inst = cfg.instances[name]
    if inst.peer_root is None:
        return summary
    _consume_dir(cfg, name, inst, summary)
    summary["peer_placed_denied"] = placed_but_denied(cfg, name)
    return summary


def _consume_dir(cfg: RouterConfig, name: str, inst: Any, summary: Dict[str, Any]) -> None:
    """The consumption half of `consume_instance`: the pinned descent into
    each of the agent's outcomes directories (`OUTCOMES_RELS`, preferred
    first) and one `_consume_one` per file.

    BOTH ids are scanned, not whichever exists: the compatibility window is
    for a daemon that has not been re-provisioned yet, and that daemon keeps
    writing under the old id whether or not the new directory has appeared.
    Scanning only the preferred one when it exists would strand exactly the
    outcomes the window is for — silently, since unread outcomes are silence.

    `MAX_FILES_PER_POLL` is a bound on work per instance per poll, so it is
    shared ACROSS the directories rather than applied to each: these are
    agent-writable, and two directories must not buy twice the budget."""
    root = inst.root
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        examined = 0
        for rel_base in OUTCOMES_RELS:
            if examined >= MAX_FILES_PER_POLL:
                break
            rel = (inst.outbox_root / rel_base).relative_to(root)
            dir_fd = attachments_mod._descend_pinned(root_fd, rel)
            if dir_fd is None:
                continue  # this id has no directory — the ordinary case for one of them
            try:
                examined = _consume_names(cfg, name, dir_fd, summary, examined)
            finally:
                os.close(dir_fd)
    finally:
        os.close(root_fd)


def _consume_names(
    cfg: RouterConfig, name: str, dir_fd: int, summary: Dict[str, Any], examined: int,
) -> int:
    """One pinned outcomes directory: hygiene, budget, `_consume_one` each.
    Returns the running `examined` count, which `_consume_dir` carries from
    one directory to the next."""
    for filename in sorted(e.name for e in os.scandir(dir_fd)):
        m = OUTCOME_NAME_RE.match(filename)
        if not m:
            # Never opened: the daemon's `.tmp` staging names land
            # here legitimately, so this is not even a warning.
            logger.debug("instance %r: outcomes entry %r skipped (name hygiene)",
                         name, filename)
            continue
        if examined >= MAX_FILES_PER_POLL:
            logger.warning(
                "instance %r: more than %d outcome files; the rest wait for "
                "the next poll", name, MAX_FILES_PER_POLL,
            )
            break
        examined += 1
        summary["peer_outcomes_seen"] += 1
        try:
            _consume_one(cfg, name, dir_fd, filename, m.group(1), summary)
        except Exception:  # noqa: BLE001 — one file must not sink the rest
            logger.exception(
                "instance %r: error consuming outcome %r — isolated, continuing",
                name, filename,
            )
            summary["peer_outcome_errored"] += 1
    return examined
