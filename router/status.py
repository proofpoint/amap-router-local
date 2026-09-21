"""router/status.py — "/health"-style observability as a file, not a socket.

`StatusTracker` folds each poll's `service.poll_once`-shaped summary
(`{instance_name: drain_summary}`, the same shape `service.run_once`
returns) into cumulative per-process-lifetime totals, and `write()`s them
atomically to `state_dir/status.json` via `util.atomic_write`. Pure
aggregation — no policy, no namespace access, no filesystem reads beyond
what the caller already produced.

Why a file instead of a listening socket: stdlib-only, zero new listener
surface on a security-sensitive host process, and fully testable with temp
dirs — no threads, no ports (SCOPE.md "Test strategy"). `status.json` lives
at the root of the router-PRIVATE `state_dir` — never agent-reachable
(`config.load_obj` already enforces `state_dir` is unreachable from every
instance namespace, so this file needs no containment check of its own).

Peer lane (`outcomes.py`): an instance with a peer tree also carries the
`peer_*` counters in `totals`, and `peer_alerts` — the most recent
`MAX_ALERTS` alert dicts (`held`, `refused`, `ambiguous_target`) accumulated
across polls, newest last — which `render` turns into banners: `held` is
loud because it means a receiving session's `crossSessionInbound` is not
what the adapter intended; `refused` names sender and recipient because the
two renderings of one fleet policy disagree; `ambiguous_target` is bannered
only when it RECURS for one recipient (a sandbox running more agents than
the topology says). Alerts, like counters, are per process lifetime.

Every peer banner is worded as the receiving sandbox's CLAIM — "<name>'s
sandbox reported ..." — never as a fact: outcomes are written by the
agent's own uid and prove nothing (`outcomes.py`, "INFORMATIONAL, NOT
PROOF"). The one exception is what the router itself did ("the sender was
DSN'd"), which it can state.

`placed_but_denied` is the third peer-lane key and the one that is NOT per
process lifetime: `outcomes.placed_but_denied`'s list for the receiver,
recomputed from router-private state on every poll and REPLACED (never
accumulated) here — the notices this router's ledger says it placed in
that receiver's peer tree whose latest recorded outcome is `denied` or
`refused`. It is the one shape a receiver's deniability takes, and only
this side can see it. `render` banners it whenever non-empty, listing up
to `MAX_PLACED_DENIED_LINES` notices and counting the rest. A summary that
does not carry the key (an errored poll, an instance without a peer tree)
leaves the last known list in place — absent is not empty.

Counters are per-PROCESS-LIFETIME, not a ledger: they reset to zero on
every restart (`started_ts` marks the window). The ledger/anchors under
`state_dir/<name>/{results,delivered,held}` already persist the ground
truth this observability layer summarizes; `status.json` is a convenience
view, not a source of record.

Schema (schema=1)::

    {
      "schema": 1,
      "pid": 1234,
      "started_ts": "2026-08-13T00:00:00Z",
      "last_poll_ts": "2026-08-13T00:00:10Z",
      "polls": 17,
      "admitted": ["alice", "bob"],   # the set the loader accepted THIS poll,
                                      #   replaced wholesale; NOT `instances`
                                      #   below, which never shrinks
      "interval_s": 5.0,              # as the loop sleeps it; absent when
                                      #   unknown, never defaulted
      "instances": {
        "alice": {
          "last_summary": {...drain_instance's summary dict, verbatim...},
          "totals": {"drained": 12, "accepted": 9, "rejected": 2,
                     "queued_for_human": 1, "outbound_errored": 0,
                     "outbound_skipped_bad_name": 0, "outbound_resumed": 0,
                     "outbound_req_id_reused": 0, "instance_errored": 0},
          "last_error_ts": null,
          "peer_alerts": [...peer lane only; see above...],
          "placed_but_denied": [{"notice_id": "<32 hex>", "sender": "alice",
                                 "recipient": "bob", "outcome": "denied",
                                 "outcome_ts": "...", "recorded_ts": "...",
                                 "req_id": "00000001"}, ...]   # peer lane only
        }
      }
    }
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from .util import atomic_write, utc_ts

SCHEMA = 1

STATUS_FILENAME = "status.json"

# Every key `drain_instance`/`service.run_once` can ever put in a per-
# instance summary dict — fixed so `totals` is always fully zero-filled,
# never sparse, regardless of which keys any given poll's summary happened
# to carry.
TOTAL_KEYS = (
    "drained",
    "accepted",
    "rejected",
    "queued_for_human",
    "outbound_errored",
    "outbound_skipped_bad_name",
    "outbound_resumed",
    "outbound_req_id_reused",
    "instance_errored",
    "quarantined",
    "first_sight",
    # Peer lane — `outcomes.COUNTER_KEYS`, spelled out so this tuple stays a
    # literal an operator can read without chasing an import.
    "peer_outcomes_seen",
    "peer_delivered",
    "peer_held",
    "peer_denied",
    "peer_refused",
    "peer_ambiguous_target",
    "peer_inject_failed",
    "peer_outcome_discarded",
    "peer_outcome_errored",
    "peer_dsn_sent",
    "peer_dsn_failed",
)

#: Alerts kept per instance; older ones fall off the front.
MAX_ALERTS = 50
#: `ambiguous_target` banners once it has happened this many times.
AMBIGUOUS_TARGET_BANNER_AT = 2
#: Notices listed under a PLACED BUT DENIED banner before "... and N more".
MAX_PLACED_DENIED_LINES = 10

NOT_WRITTEN_MSG = (
    "router has not written status yet — is it running with this config's "
    "state_dir?"
)


def _empty_totals() -> Dict[str, int]:
    return {k: 0 for k in TOTAL_KEYS}


class StatusTracker:
    """Accumulates `record_poll` calls into cumulative per-instance totals
    for the lifetime of this process; `write()` persists the current state.
    Construct one at process start (before the first poll) so `started_ts`
    marks the true window start."""

    def __init__(self, interval_s: Optional[float] = None) -> None:
        self.pid = os.getpid()
        self.started_ts = utc_ts()
        self.last_poll_ts: Optional[str] = None
        self.polls = 0
        self.instances: Dict[str, Dict[str, Any]] = {}
        #: The poll interval as the loop actually sleeps it — the float
        #: `--interval` became, not the argv string, and the same number
        #: `run_forever`'s startup line prints. `None` for a tracker that is
        #: not a `run` loop, and then OMITTED from the document rather than
        #: defaulted: a consumer computes a freshness bound from this (3x, on
        #: the peer side), so a made-up value is a wrong bound asserted
        #: confidently. Absent means "this document cannot answer".
        self.interval_s = interval_s
        #: The ADMITTED set: instances the loader accepted on the most recent
        #: poll, REPLACED WHOLESALE each time.
        #:
        #: Deliberately NOT `instances` below, which is a different thing and
        #: was nearly used for this. That map is built with `setdefault` and
        #: has no removal path, so it is the union of every instance seen
        #: since process start — monotonic. On a de-enrolment it keeps the
        #: departed instance for ever, and a consumer reading it as "the set
        #: now" gets a stale answer with nothing in the document admitting
        #: it. The peer that asked for this was about to do exactly that.
        self.admitted: Optional[List[str]] = None

    def record_admitted(self, names: Iterable[str]) -> None:
        """Replace the admitted set. Called every poll, INCLUDING a poll that
        errored — the set the loader accepted is known even when draining it
        did not work, and those two facts are answered by different checks."""
        self.admitted = sorted(names)

    def record_poll(self, summary: Dict[str, Dict[str, int]]) -> None:
        """Fold one `service.run_once`/`poll_once`-shaped summary into the
        cumulative totals. Every key present in a per-instance summary that
        is also one of `TOTAL_KEYS` is added into that instance's running
        total; `last_summary` is replaced (not accumulated) with this
        poll's summary verbatim, so an operator can see both "right now"
        and "since start" at a glance."""
        self.polls += 1
        self.last_poll_ts = utc_ts()
        for name, s in summary.items():
            inst = self.instances.setdefault(
                name, {"last_summary": {}, "totals": _empty_totals(), "last_error_ts": None}
            )
            inst["last_summary"] = dict(s)
            totals = inst["totals"]
            for k, v in s.items():
                if k in totals:
                    totals[k] += v
            if s.get("instance_errored") or s.get("outbound_errored"):
                inst["last_error_ts"] = self.last_poll_ts
            alerts = s.get("peer_alerts")
            if alerts:
                kept = inst.setdefault("peer_alerts", [])
                kept.extend(a for a in alerts if isinstance(a, dict))
                del kept[:-MAX_ALERTS]
            # State, not a counter: replaced wholesale when the poll
            # answered, left alone when it did not (absent is not empty).
            placed_denied = s.get("peer_placed_denied")
            if isinstance(placed_denied, list):
                inst["placed_but_denied"] = [d for d in placed_denied if isinstance(d, dict)]

    def to_doc(self) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "schema": SCHEMA,
            "pid": self.pid,
            "started_ts": self.started_ts,
            "last_poll_ts": self.last_poll_ts,
            "polls": self.polls,
            "instances": self.instances,
        }
        # Omitted, never defaulted, when this tracker cannot answer. A
        # consumer distinguishes "a router older than this field" from a
        # wrong value only if the absence is real.
        if self.admitted is not None:
            doc["admitted"] = list(self.admitted)
        if self.interval_s is not None:
            doc["interval_s"] = self.interval_s
        return doc

    def write(self, state_dir: Union[str, Path]) -> None:
        """Atomically write the current cumulative status to
        `state_dir/status.json`. `state_dir` is router-private (never
        agent-reachable), so no containment check is needed here — only
        instance-namespace writes require `verify_namespace_containment`."""
        doc = self.to_doc()
        path = Path(state_dir) / STATUS_FILENAME
        atomic_write(path, json.dumps(doc, sort_keys=True).encode("utf-8"))


def read(state_dir: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Read + parse `state_dir/status.json`. Returns `None` (never raises
    for the ordinary "not written yet" case) if the file doesn't exist;
    callers wanting an operator-facing message should use `NOT_WRITTEN_MSG`.
    Propagates nothing for a malformed file either — corrupt JSON also
    returns `None`, since `atomic_write` means a genuinely partial file
    should never be observable, so any parse failure here is exactly as
    uninformative as "not written yet" from the caller's point of view."""
    path = Path(state_dir) / STATUS_FILENAME
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def _age_seconds(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    from datetime import datetime, timezone

    try:
        then = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - then).total_seconds()


def render_discovery(report) -> List[str]:
    """Operator-facing lines for a `DiscoveryReport`, or `[]` when it is
    clean.

    THE REPORT IS THE WHOLE POINT OF ADMISSION-NOT-VALIDATION. Discovery
    skips rather than refuses so one bad directory cannot stop a running
    fleet — and a skip that nothing prints is indistinguishable from a
    fleet with nothing wrong. Every line here exists because the alternative
    was silence.

    Derived state, never persisted: it is recomputed from the tree at every
    load, so it belongs in what an operator ASKS for and in the log of the
    process that read it, not in `status.json` where it would become a
    stale record of a directory listing.

    THE HEADING AND THE `** ` MARKER ARE WIRE. A host adapter's bringup greps
    this: a `** `-wrapped line under `discovery:` is a FAIL whose remedy
    names the line, a plain line is a warning, and the heading's ABSENCE is
    how it recognises an authored config. Renaming either is a cross-repo
    change owing notice before the commit — and a COSMETIC rename is the
    dangerous one, because their check would not break, it would go
    permanently green with nothing to say it had stopped working.
    `test_discovery.py::DiscoveryOutputIsWireTests` pins both by name.
    """
    if report is None or report.is_clean():
        return []
    out = ["discovery:"]
    if report.verdict_unavailable:
        out.append(
            "    ** VERDICT UNAVAILABLE: the host's selected.json is missing "
            "or unreadable — NOBODY is admitted and nothing will drain. This "
            "is not 'the host selected nobody'; it is 'the host has not "
            "answered' **"
        )
    for slug, reason in sorted(report.skipped.items()):
        out.append(f"    SKIPPED  {slug}: {reason}")
    for slug in report.no_verdict:
        out.append(
            f"    NO VERDICT  {slug}: a directory with no entry in the host's "
            f"selected.json — not drained, NOT deleted (every workspace "
            f"rename produces one)"
        )
    for slug in report.verdict_without_directory:
        out.append(
            f"    ** NO DIRECTORY  {slug}: the host selected it and its tree "
            f"does not exist. A verdict follows a launch and a launch creates "
            f"the tree, so this is broken state rather than a pending one **"
        )
    for slug, reason in sorted(report.inert_edges.items()):
        loud = "**" if "typo" in reason else "  "
        out.append(f"    {loud} INERT EDGE  {slug}: {reason} {loud}".rstrip())
    return out


def render(doc: Dict[str, Any]) -> str:
    """Human-readable status table. No staleness heuristic is baked in
    (PICKED: unknowable from the file alone what interval the router is
    running at) — the age is printed plainly and the operator judges."""
    lines = []
    age = _age_seconds(doc.get("last_poll_ts"))
    age_str = f"{age:.0f}s ago" if age is not None else "unknown"
    lines.append(
        f"last poll {age_str} ({doc.get('polls', 0)} polls since {doc.get('started_ts', '?')}, "
        f"pid {doc.get('pid', '?')})"
    )
    instances = doc.get("instances") or {}
    for name in sorted(instances):
        totals = instances[name].get("totals") or {}
        last_summary = instances[name].get("last_summary") or {}
        errors = totals.get("outbound_errored", 0) + totals.get("instance_errored", 0)
        last_error_ts = instances[name].get("last_error_ts")
        line = (
            f"{name}  drained={totals.get('drained', 0)} "
            f"accepted={totals.get('accepted', 0)} "
            f"rejected={totals.get('rejected', 0)} "
            # `for_human=`, NOT `held=`. The peer lane has an outcome
            # literally called `held` (AMAP's vocabulary: delivered / held /
            # denied / refused) and it renders as a PEER HELD banner on the
            # very next line. The two count OPPOSITE DIRECTIONS: this is
            # what THIS instance tried to SEND and a human must release
            # (`state_dir/<name>/held/`); that is what someone sent TO this
            # instance and its own daemon declined to inject. Disjoint sets,
            # one word, adjacent lines — an operator reads "3 held, 2 of
            # them peer" and the arithmetic they just did is meaningless.
            # The spec's word wins for the spec's concept, so the banner
            # keeps `held` and this label, which was only ever a shortening
            # of `queued_for_human`, gives way.
            f"for_human={totals.get('queued_for_human', 0)} "
            f"quarantined={totals.get('quarantined', 0)} "
            f"errors={errors}"
        )
        if last_error_ts:
            line += f"  (last error {last_error_ts})"
        # Loudly not-idle, never merely quiet: on first sight everything
        # already staged is quarantined rather than drained
        # (router/firstsight.py), and that must never look the same as an
        # instance that's simply caught up.
        #
        # TWO TEXTS, because one of them would be a lie half the time. A
        # first sight with an EMPTY outbox quarantines nothing, and on a
        # fresh fleet that is every instance at once — a banner announcing
        # quarantined requests there is false, and a banner an operator
        # learns to scroll past is worse than none. So the loud one is
        # earned by `quarantined`, not by `first_sight`, and the quiet one
        # still records that the boundary was drawn this poll.
        if last_summary.get("first_sight"):
            quarantined = last_summary.get("quarantined", 0)
            if quarantined:
                # The quarantined requests are never delivered, so an
                # operator who expected them to go needs to see this once.
                line += (f"  ** FIRST SIGHT — {quarantined} staged request(s) "
                         f"quarantined, never delivered **")
            else:
                line += "  (first sight — outbox was empty, nothing quarantined)"
        lines.append(line)
        lines.extend(_peer_banners(
            name, totals, instances[name].get("peer_alerts") or [],
            instances[name].get("placed_but_denied") or [],
        ))
    if not instances:
        lines.append("(no instances polled yet)")
    return "\n".join(lines)


def _peer_banners(name: str, totals: Dict[str, Any], alerts: list,
                  placed_but_denied: list = ()) -> list:
    """The peer-lane banners under one instance's line (module docstring).
    Indented so they read as belonging to the line above. Each one
    attributes the outcome to `name`'s sandbox as its report, never as
    fact — the router only ever saw a file the receiving uid wrote."""
    out = []
    held = totals.get("peer_held", 0)
    if held:
        # NO CAUSE IS STATED, for the reason `outcomes.py` already records
        # against the `refused` DSN: naming one is a guess, and a guess in an
        # operator-facing line costs a debugging session when it is wrong.
        # `held` has (at least) TWO causes that this router cannot tell apart
        # — a human reviewed and parked it, and the receiving sandbox has
        # `crossSessionInbound` not set to accept, which is a CONFIG state and
        # no human's decision. The daemon distinguishes them in the outcome
        # record's `detail`; this router does not read prose to decide
        # anything, so it says where the answer is rather than choosing one.
        # Recovery differs too: the config case resolves itself when the
        # setting is fixed (the daemon re-offers), while a human hold waits
        # for a human, so "what should I do" has no single answer either.
        out.append(
            f"    ** PEER HELD ({held}): {name}'s sandbox reported that it held peer "
            f"message(s) rather than delivering them; nothing was told to the sender. "
            f"Cause not stated here — see `detail` in state_dir/{name}/outcomes/ **"
        )
    for a in alerts:
        if a.get("kind") == "refused":
            out.append(
                f"    ** PEER REFUSED: {name}'s sandbox reported that its daemon refused a "
                f"peer notice from {a.get('sender')!r} (notice {a.get('notice_id')}) — "
                f"a daemon refuses only a notice not addressed to itself or one from the router's own address (it holds no allowlist since ruling 16), so this is a routing fault; the "
                f"sender was DSN'd **"
            )
    ambiguous = totals.get("peer_ambiguous_target", 0)
    if ambiguous >= AMBIGUOUS_TARGET_BANNER_AT:
        out.append(
            f"    ** AMBIGUOUS TARGET recurring ({ambiguous}): {name}'s sandbox reported "
            f"more than one live session; peer notices stay in the spool until it "
            f"reports exactly one **"
        )
    if placed_but_denied:
        n = len(placed_but_denied)
        out.append(
            f"    ** PLACED BUT DENIED ({n}): this router placed {n} peer notice(s) in "
            f"{name}'s tree whose latest reported outcome is denied/refused — {name}'s "
            f"sandbox says it did not deliver them **"
        )
        for d in placed_but_denied[:MAX_PLACED_DENIED_LINES]:
            out.append(
                f"       notice {d.get('notice_id')} from {d.get('sender')!r}: reported "
                f"{d.get('outcome')} at {d.get('outcome_ts')}"
            )
        if n > MAX_PLACED_DENIED_LINES:
            out.append(f"       ... and {n - MAX_PLACED_DENIED_LINES} more (status --json)")
    return out
