"""router/console.py — the operator console: one page, rendered, never served.

Answers the four things an operator asks of a running fleet — is it healthy,
how much traffic is there, is anyone excluded, and what was actually said —
from router-private state, as a single self-contained HTML file.

WHY THIS IS A RENDERER AND NOT A SERVER. `status.json` is a file rather than
a socket deliberately: zero new listener surface on a security-sensitive host
process. The container runs `--network none`, asserted by `test_docker.py`,
and `dependencies = []` is machine-readable policy. A web server here would
break three stated properties at once. So this module writes a page; serving
it, if anyone wants that, is somebody else's process and somebody else's
trust posture. `peers.render_peers_html` set the precedent and this follows
it exactly: self-contained, no stylesheet, no font, no script, nothing that
turns opening a review artifact into a network request.

DISPLAY ONLY. Everything here is recomputed from `config` and from state on
disk at render time and nothing is stored. There is no cache anyone could
later mistake for a ledger — the same rule `peers.py` runs on.

WHERE THE DATA COMES FROM, AND HOW FAR EACH PART IS TRUSTED. This is the
whole design, so it is written down rather than left to the reader:

  ROUTER-PRIVATE, under `state_dir`, unreachable from every agent namespace
  (enforced at config load). Trustworthy: this router wrote all of it.
    - `status.json`         poll freshness, counters, alerts
    - `<name>/first-seen.json` whether this router has ever polled the
                             instance, and what was in its outbox when it did
    - `<name>/delivered/`    the reply-binding ledger: who sent what to whom,
                             on which tree, when. THE ROUTING METADATA COMES
                             FROM HERE, never from a message document.
    - `<name>/audit/`        placements, refusals, outcomes, DSNs
    - `<name>/outcomes/`     the recorded delivery outcome per transition

  AGENT-ADJACENT, under each instance's own root. The message spool document
  supplies `subject` and `body_text` and NOTHING ELSE this page relies on:
    - `<inbox|peer>/messages/notice-<id>.json`
  Under `handoff` mode this router wrote that file and the agent's mount of
  it is read-only, so the envelope is ours and only `body_text` is the
  sender's words. Under `namespace` mode the whole tree is agent-writable and
  the document may have been rewritten wholesale; the page says so per
  instance rather than quietly presenting the two as equivalent.

BODIES, AND THE HAZARD THEY CARRY. A peer body is, on a delegation-only
fleet, by construction one agent instructing another. Rendering it in a page
an operator trusts, beside this router's own assertions, points a prompt
injection at the HUMAN — the risk is not that the markup runs, it is that the
text reads as though the console were saying it. So:

  - metadata and the router's control-collapsed `preview` are what the page
    shows by default;
  - a body is behind an explicit `<details>` click, and the summary says
    whose words are inside before they are opened;
  - a body is rendered as TEXT inside `<pre>`, escaped, never as markup;
  - the page declares `default-src 'none'` and carries no script at all, so
    there is nothing for injected markup to reach even if escaping failed;
  - every body sits inside a block that states its author, so attribution is
    structural rather than a caption someone can scroll past.

Retention is the operator's, and the page says which window it is showing:
bodies live until `reset`, so this makes them browsable for as long as they
are on disk.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import firstsight as firstsight_mod
from . import attachments as attachments_mod
from . import audit as audit_mod
from . import binding
from . import status as status_mod
from .config import MODE_NAMESPACE, RouterConfig, address_for, derive_matrix
from .util import utc_ts

#: One message body, for display. Larger bodies render truncated with a note
#: rather than being withheld — an operator looking at a 2 MiB body still
#: wants to see what it starts with.
BODY_DISPLAY_CAP = 256 * 1024

#: A spool document is small; anything near this is not one.
SPOOL_READ_CAP = 8 * 1024 * 1024

#: How stale a fact may be before the page calls it stale rather than current.
#: Poll age: `run --interval N` is typically seconds, so a minute is generous.
POLL_STALE_SECONDS = 60
#: Host facts come from a separate `amap-sandy.py verify` run, which an operator
#: or a cron drives at their own cadence; an hour is the honest default.
HOST_FACTS_STALE_SECONDS = 3600

#: The `--host-facts` document shape this console understands. A different
#: number is refused rather than read with these meanings.
#:
#: Bumped 1 -> 2 on 2026-09-21, when the adapter retired `bringup.py` and
#: `amap-sandy.py verify` became the only producer on the fleet. Between the
#: retirement and this bump every document this page could be pointed at was
#: refused: the page was BLIND to a live fleet, not merely behind it. The
#: refusal was correct and is the designed loud-once event; it is the state it
#: leaves that has a cost, and that cost is the argument for adopting promptly
#: rather than at leisure.
#:
#: Adopted against FOUR captured documents from the operator's host — healthy,
#: router stopped, docker unreachable, and sandy absent — covering every
#: `exit_meaning` schema 2 can emit and both states of `not_enrolled`. Not
#: against a description of them; see `test_console.py`'s schema-2 class for
#: what each one proved.
HOST_FACTS_SCHEMA = 2

#: The adapter's own word for a whole run, so this console never has to know
#: their exit integers. `cannot_run` is a first-class state: the read produced
#: no verdict, which is neither healthy nor broken.
#: `declined` HAS NO PRODUCER under schema 2 and is kept deliberately.
#: `verify` never prompts, so it cannot decline; `ok`/`failed`/`cannot_run`
#: are the three it emits. The word stays because this vocabulary is the
#: CONSOLE's, not the adapter's — a fifth producer may need it, and a closed
#: set that refuses everything else is doing work. Its two rendering branches
#: (the pill and the banner) are unreachable today; see the note at each.
HOST_FACTS_MEANINGS = ("ok", "failed", "cannot_run", "declined")

#: The boundary between the two failure words, agreed with the producer and
#: worth not re-deriving: `failed` means "something is wrong and the checks
#: say what" — INCLUDING a document whose checks are all UNKNOWN, because
#: "could not tell" is not a clean bill. `cannot_run` means "this read
#: produced no verdict at all", and arrives with `phases: []` and no
#: `not_enrolled` key, because the lookups never happened. An all-UNKNOWN
#: document is the FIRST of those, never the second.

#: Phase ids this page names directly. Everything else in the document
#: renders generically, so a phase the adapter adds appears here without this
#: module learning about it.
#:
#: These were "8.1" and "8.2" under schema 1 — positions in `bringup.py`'s
#: numbered run. That program is deleted, and an id that outlives its program
#: is stable and meaningless at once, so schema 2 names them for what they
#: ARE. The rename is the whole of this module's cost for the bump.
PHASE_CONTAINER = "router-container"   # running, network none, restart policy, mounts
PHASE_ROUTER_HEALTH = "router-health"  # status.json freshness, from their side


def _parse_ts(value: Any) -> Optional[datetime]:
    """An ISO-8601 `...Z` timestamp, or `None` for anything unparseable —
    every timestamp on this page came off disk and none of them are trusted
    to be well formed."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def _age_seconds(value: Any) -> Optional[float]:
    parsed = _parse_ts(value)
    if parsed is None:
        return None
    return (datetime.now(timezone.utc) - parsed).total_seconds()


def _human_age(seconds: Optional[float]) -> str:
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    if seconds < 0:
        return "in the future"
    if seconds < 90:
        return f"{seconds}s ago"
    if seconds < 5400:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


# --- gathering ---------------------------------------------------------------

def _read_spool_doc(
    cfg: RouterConfig, recipient: str, tree: str, notice_id: str
) -> Optional[Dict[str, Any]]:
    """The message spool document for one delivered notice, or `None`.

    Read with the discipline every agent-adjacent read in this router uses
    (`outbound._read_request_pinned`, `outcomes._read_outcome_pinned`): a
    pinned `O_NOFOLLOW` descent from the instance's declared root, an
    `fstat`-verified regular file, a bounded read. The tree is agent-owned
    under `namespace` mode and its `messages/` directory could be a symlink
    to anywhere this process can read; a display page is not a reason to
    relax that.

    Returns `None` — never raises — for every failure. A body that cannot be
    read is a body the page reports as unavailable; it is not an error that
    should take a console down."""
    inst = cfg.instances.get(recipient)
    if inst is None:
        return None
    base = inst.peer_root if tree == "peer" else inst.inbox_root
    if base is None:
        return None
    try:
        rel = (base / "messages").relative_to(inst.root)
    except ValueError:
        return None

    root_fd = os.open(str(inst.root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        dir_fd = attachments_mod._descend_pinned(root_fd, rel)
        if dir_fd is None:
            return None
        try:
            fd = os.open(
                f"notice-{notice_id}.json",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd,
            )
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_size > SPOOL_READ_CAP:
                    return None
                raw = os.read(fd, SPOOL_READ_CAP)
            finally:
                os.close(fd)
        finally:
            os.close(dir_fd)
    except OSError:
        return None
    finally:
        os.close(root_fd)

    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _ledger_records(cfg: RouterConfig, recipient: str) -> List[Dict[str, Any]]:
    """Every ledger record filed under `recipient`, newest first. Router-
    private and therefore the authority for who sent what to whom."""
    out: List[Dict[str, Any]] = []
    d = binding.ledger_dir(cfg.state_dir, recipient)
    try:
        entries = sorted(p.name for p in os.scandir(d))
    except OSError:
        return out
    for name in entries:
        if not (name.startswith("notice-") and name.endswith(".json")):
            continue
        try:
            doc = json.loads((d / name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(doc, dict):
            doc["_recipient"] = recipient
            out.append(doc)
    out.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
    return out


def _outcome_for(cfg: RouterConfig, recipient: str, notice_id: str) -> Optional[str]:
    """The latest recorded outcome for one notice, or `None` if none was
    recorded. Router-private; the outcome FILE the daemon wrote is long
    unlinked by the time this runs."""
    d = cfg.state_dir / recipient / "outcomes"
    latest: Tuple[str, str] = ("", "")
    try:
        entries = list(os.scandir(d))
    except OSError:
        return None
    for e in entries:
        if notice_id not in e.name or not e.name.endswith(".json"):
            continue
        try:
            doc = json.loads(Path(e.path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict) or doc.get("notice_id") != notice_id:
            continue
        stamp = str(doc.get("recorded_ts") or "")
        if stamp >= latest[0]:
            latest = (stamp, str(doc.get("outcome") or ""))
    return latest[1] or None


def phase_verdict(phase: Dict[str, Any]) -> str:
    """One phase's verdict, from its own checks: `pass`, `fail`, `unknown`,
    `unrunnable` or `skipped`.

    `unrunnable` — the phase could not be read at all — is deliberately NOT
    folded into `unknown`. A check that ran and returned UNKNOWN examined
    something and could not tell; a phase that is unrunnable examined
    nothing. They call for different operator action and the page shows
    them differently.

    This aggregates the adapter's verdicts and does not recompute any of
    them. The adapter's container phase stays the only place that knows what a
    healthy container is; a second implementation here would drift from it,
    which is the failure the adapter's own console has a name for."""
    if not isinstance(phase, dict):
        return "unknown"
    if phase.get("unrunnable"):
        return "unrunnable"
    if phase.get("skipped"):
        return "skipped"
    checks = phase.get("checks")
    if not isinstance(checks, list) or not checks:
        return "unknown"
    results = [c.get("result") for c in checks if isinstance(c, dict)]
    if any(r == "FAIL" for r in results):
        return "fail"
    if any(r != "PASS" for r in results):
        return "unknown"
    return "pass"


def find_phase(host: Dict[str, Any], phase_id: str) -> Optional[Dict[str, Any]]:
    for phase in host.get("phases") or []:
        if isinstance(phase, dict) and phase.get("id") == phase_id:
            return phase
    return None


def load_host_facts(path: Optional[Path]) -> Dict[str, Any]:
    """The adapter's `amap-sandy.py verify --host-facts` document, or the
    UNKNOWN state.

    ABSENCE IS A FACT AND IS RENDERED AS ONE. A page that simply omits the
    container row when this file is missing leaves poll age looking like a
    clean bill of health, which is the failure this shape exists to prevent.
    So every return carries `available`, and the renderer says "not
    available" rather than saying nothing.

    Staleness is checked, not presence — the same lesson `status.json`
    taught the adapter's phase 8.2 in the other direction. A `--check` that
    ran an hour ago describes a container that may since have died, so
    `generated_ts` is required and its age is shown beside every fact drawn
    from here.

    **THIS PAGE IS NO LONGER SAFE-TO-PASTE BY CONSTRUCTION.** Every other
    value it renders is a slug, a count or a timestamp. Schema 2's `reason`
    is the producer's verbatim words about why a check could not tell, and a
    real captured one carried an absolute host path including a username. The
    producer is right to pass errors through rather than paraphrase them —
    paraphrasing a daemon error is how a console starts lying about what a
    tool said — so the exposure belongs here, stated, rather than being
    sanitised away upstream. Read a generated page before putting it in a
    ticket.

    `exit_meaning` is the adapter's own word for the run as a whole, so this
    console never has to know their exit integers: `ok`, `failed`,
    `cannot_run` or `declined`. **`cannot_run` is its own state and is not
    folded into either neighbour** — it means the read produced no verdict,
    and rendering that as either healthy or broken is precisely the false
    report the whole arrangement exists to refuse.

    An unrecognised `schema` is refused rather than guessed at: the field
    names here carry meaning, and a console that reads a future document by
    assuming this one's meanings is a console that reports confidently about
    something it does not understand."""
    if path is None:
        return {"available": False, "reason": "no --host-facts file was given"}
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        return {"available": False, "reason": f"could not read {path}: {e.__class__.__name__}"}
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        # Also the shape a reader sees if it opens the file mid-write. The
        # adapter writes atomically so this should not happen; treating it as
        # absent is the safe direction either way.
        return {"available": False, "reason": f"{path} is not valid JSON"}
    if not isinstance(doc, dict):
        return {"available": False, "reason": f"{path} is not an object"}

    schema = doc.get("schema")
    if schema != HOST_FACTS_SCHEMA:
        return {"available": False,
                "reason": f"{path} declares schema {schema!r}; this console "
                          f"understands {HOST_FACTS_SCHEMA}"}

    age = _age_seconds(doc.get("generated_ts"))
    if age is None:
        # No usable generation time means nothing here can be dated, and an
        # undated container fact is exactly the "existence alone is worthless"
        # case. Refuse it rather than render it as current.
        return {"available": False,
                "reason": f"{path} carries no usable generated_ts, so its facts cannot be dated"}

    meaning = doc.get("exit_meaning")
    doc["available"] = True
    doc["age_seconds"] = age
    doc["stale"] = age > HOST_FACTS_STALE_SECONDS
    doc["exit_meaning"] = meaning if meaning in HOST_FACTS_MEANINGS else "unknown"
    return doc


def gather(
    cfg: RouterConfig, *, host_facts_path: Optional[Path] = None,
    body_cap: int = BODY_DISPLAY_CAP,
) -> Dict[str, Any]:
    """Everything the page shows, read fresh. Stores nothing."""
    names = sorted(cfg.instances)
    status_doc = status_mod.read(cfg.state_dir) or {}
    host = load_host_facts(host_facts_path)

    per_instance: Dict[str, Dict[str, Any]] = {}
    for name in names:
        inst = cfg.instances[name]
        per_instance[name] = {
            "seen": firstsight_mod.read_marker(cfg.state_dir, name) is not None,
            "mode": inst.mode,
            "peer_lane": inst.peer_root is not None,
            "address": address_for(name, cfg.fleet_domain),
            "status": (status_doc.get("instances") or {}).get(name) or {},
            "events": audit_mod.read_events(cfg.state_dir, name),
        }

    # Traffic and messages both come off the ledger, which is router-private
    # and therefore the authority for routing metadata. The spool document is
    # consulted only for subject and body.
    messages: List[Dict[str, Any]] = []
    pairs: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for recipient in names:
        for rec in _ledger_records(cfg, recipient):
            notice_id = str(rec.get("notice_id") or "")
            if not notice_id:
                continue
            tree = "peer" if rec.get("tree") == "peer" else "inbox"
            sender = rec.get("from_instance")
            if rec.get("authored_by") == "router":
                sender_label = "the router (DSN)"
            elif isinstance(sender, str) and sender:
                sender_label = sender
            else:
                sender_label = "unknown"

            spool = _read_spool_doc(cfg, recipient, tree, notice_id) or {}
            body = spool.get("body_text")
            body_text = body if isinstance(body, str) else None
            truncated = False
            if body_text is not None and len(body_text) > body_cap:
                body_text, truncated = body_text[:body_cap], True

            messages.append({
                "notice_id": notice_id,
                "ts": rec.get("ts"),
                "tree": tree,
                "sender": sender_label,
                "sender_instance": sender if isinstance(sender, str) else None,
                "recipient": recipient,
                "router_authored": rec.get("authored_by") == "router",
                "req_id": rec.get("req_id"),
                # Sender-authored, from the spool document:
                "subject": spool.get("subject"),
                "body_text": body_text,
                "body_truncated": truncated,
                "body_available": body_text is not None,
                # Whether the document itself could have been rewritten:
                "spool_agent_writable":
                    cfg.instances[recipient].mode == MODE_NAMESPACE,
                "outcome": _outcome_for(cfg, recipient, notice_id),
            })

            key = (sender_label, recipient, tree)
            slot = pairs.setdefault(
                key, {"sender": sender_label, "recipient": recipient,
                      "tree": tree, "count": 0, "last_ts": ""})
            slot["count"] += 1
            stamp = str(rec.get("ts") or "")
            if stamp > slot["last_ts"]:
                slot["last_ts"] = stamp

    messages.sort(key=lambda m: str(m.get("ts") or ""), reverse=True)

    # The discovery report travels with the page. See `_discovery_section`.

    return {
        "discovery": cfg.discovery,
        "generated_ts": utc_ts(),
        "fleet_domain": cfg.fleet_domain,
        "status": status_doc,
        "poll_age_seconds": _age_seconds(status_doc.get("last_poll_ts")),
        "host": host,
        "instances": per_instance,
        "messages": messages,
        "traffic": sorted(pairs.values(),
                          key=lambda p: (-p["count"], p["sender"], p["recipient"])),
        "excluded": _excluded(cfg, per_instance, host),
    }


def _excluded(
    cfg: RouterConfig, per_instance: Dict[str, Dict[str, Any]], host: Dict[str, Any]
) -> Dict[str, Any]:
    """The three senses of "excluded", kept apart because they have three
    different remedies and a page that blends them sends an operator to the
    wrong one.

      1. NOT ENROLLED — the host's own verdict that this sandbox is not
         selected. Lives in fleet policy, which this router cannot see AT
         ALL: a sandbox that was never enrolled appears in no config of
         mine, so this is not partially visible here, it is invisible. It
         comes from the adapter's host facts or it is unanswered, and
         "unanswered" is rendered as such. The nasty case it covers is a
         rule that matches nothing: that enrols nobody and is
         indistinguishable from a deliberate decision not to enrol.

         THE WIRE KEY IS STABLE AND ITS MEANING IS NOT. `not_enrolled` has
         always carried host SLUGS and still does — same key, same type —
         but since the host adapter moved to a feature manifest it means the
         host's recorded `not_selected` verdicts rather than "matched no
         profile". No schema bump, deliberately, because nothing about the
         shape changed. Read that as a warning rather than a reassurance: a
         field whose meaning moves under a stable name is invisible to every
         check that looks at shape, which is the same hazard the host's own
         `features` field carries across its schema bump.

         THERE IS A THIRD STATE AND IT IS NOT RENDERED HERE. A sandbox with
         no verdict yet — never launched since the manifest was written — is
         in NEITHER list. It is PENDING, not excluded, and this page cannot
         show it: it has no instance of mine and no verdict of theirs, so it
         is absent from every column by construction. That is correct (there
         is genuinely nothing to report) and it is worth stating, because
         "absent from this page" must not be read as "enrolled and fine".
      2. NO EDGE — configured here, but no counterpart on either lane. Mine,
         and this is the rendered result rather than the policy's intent.
      3. NEVER POLLED — configured, with edges, and yet this router has no
         first-sight marker for it, so no poll has ever reached its root.
         Router-private. This used to read NOT APPROVED and meant a missing
         operator command; `approve` is retired, so the same absence now
         means the drainer is not running, is pointed at a different config,
         or has never come up. Kept as its own sense because the remedy is
         still nothing to do with edges or policy.
    """
    matrix = derive_matrix(cfg)
    names = sorted(cfg.instances)

    no_edge: List[str] = []
    for name in names:
        mail = any(matrix[name][other] or matrix[other][name]
                   for other in names if other != name)
        peer_in = bool(cfg.instances[name].peer_senders)
        peer_out = any(name in cfg.instances[other].peer_senders
                       for other in names if other != name)
        if not (mail or peer_in or peer_out):
            no_edge.append(name)

    not_enrolled = host.get("not_enrolled") if host.get("available") else None
    return {
        "not_enrolled": not_enrolled if isinstance(not_enrolled, list) else None,
        "not_enrolled_known": host.get("available") and isinstance(not_enrolled, list),
        "no_edge": no_edge,
        "never_polled": [n for n in names if not per_instance[n]["seen"]],
    }


# --- rendering ---------------------------------------------------------------
#
# A LOCAL FILE, like `peers.render_peers_html`: it carries real instance
# names, real addresses and real message bodies, and it is written to a path
# the operator names and published nowhere. Self-contained for the same
# reason — no external stylesheet, no font, no script src, nothing that turns
# opening it into a network request. It goes further than `peers.py` in one
# way: NO SCRIPT AT ALL, and a CSP of `default-src 'none'`, because this page
# renders agent-authored text and a page with no script is a page with
# nothing for injected markup to reach.

_CSS = """
:root { --bg:#fbfbfd; --fg:#1b2430; --dim:#6b7686; --line:#e2e6ec; --card:#fff;
        --ok:#1f7a4d; --okbg:#e6f4ec; --warn:#b03a3a; --warnbg:#fdeaea;
        --unk:#8a6d1f; --unkbg:#fdf6e3; --accent:#12365c; --quote:#f3f5f8; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#12151a; --fg:#e6e9ee; --dim:#8790a0; --line:#262c36; --card:#171b21;
          --ok:#5fd39b; --okbg:#122a1f; --warn:#e08585; --warnbg:#2b1618;
          --unk:#d8c07a; --unkbg:#2a2412; --accent:#7fb0e8; --quote:#1b2029; } }
* { box-sizing:border-box } body { margin:0; background:var(--bg); color:var(--fg);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
.wrap { padding:26px 30px 60px; max-width:1180px; }
h1 { font-size:20px; margin:0 0 3px; color:var(--accent); }
h2 { font-size:15px; margin:30px 0 10px; color:var(--accent);
     border-bottom:1px solid var(--line); padding-bottom:5px; }
.sub { color:var(--dim); font-size:12.5px; margin:0 0 18px; }
.cards { display:flex; flex-wrap:wrap; gap:12px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:7px;
        padding:12px 15px; min-width:210px; }
.card .k { color:var(--dim); font-size:11.5px; text-transform:uppercase;
           letter-spacing:.04em; }
.card .v { font-size:17px; margin-top:3px; }
.pill { display:inline-block; padding:1px 8px; border-radius:11px; font-size:11.5px;
        font-weight:600; }
.pill.ok { color:var(--ok); background:var(--okbg); }
.pill.warn { color:var(--warn); background:var(--warnbg); }
.pill.unk { color:var(--unk); background:var(--unkbg); }
table { border-collapse:collapse; width:100%; font-size:13px; margin-top:4px; }
th,td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line);
        vertical-align:top; }
th { color:var(--dim); font-weight:600; font-size:11.5px; text-transform:uppercase;
     letter-spacing:.04em; }
td.mono,.mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
.note { color:var(--dim); font-size:12.5px; margin:8px 0 0; max-width:74em; }
/* `reason` is the producer's verbatim words and can be multi-line. pre-wrap,
   because HTML collapses the newline and the structure IS the information. */
.reason { white-space:pre-wrap; word-wrap:break-word; margin:4px 0 0;
          padding-left:10px; border-left:2px solid var(--line); }
.banner { border-left:3px solid var(--warn); background:var(--warnbg); color:var(--warn);
          padding:9px 13px; margin:0 0 14px; border-radius:0 4px 4px 0; font-size:13px; }
.banner.unk { border-left-color:var(--unk); background:var(--unkbg); color:var(--unk); }
details { margin:6px 0 0; }
summary { cursor:pointer; font-size:12.5px; color:var(--accent); }
.body { margin:8px 0 2px; border:1px solid var(--line); border-radius:6px;
        background:var(--quote); overflow:hidden; }
.body .who { background:var(--warnbg); color:var(--warn); font-size:11.5px;
             font-weight:600; padding:6px 11px; border-bottom:1px solid var(--line); }
.body pre { margin:0; padding:11px 13px; white-space:pre-wrap; word-wrap:break-word;
            font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
.empty { color:var(--dim); font-style:italic; padding:8px 0; }
.kind { color:var(--dim); font-size:11px; text-transform:uppercase;
        letter-spacing:.04em; margin-bottom:3px; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
th.num { text-align:right; }
.unobs { color:var(--dim); }
"""


def _esc(text: Any) -> str:
    """Every value on this page goes through here. Bodies, subjects and
    instance names alike — the first two are agent-authored and the third is
    config, and distinguishing them at each call site is how one gets
    missed."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _pill(kind: str, text: str) -> str:
    return f'<span class="pill {kind}">{_esc(text)}</span>'


def _health_section(data: Dict[str, Any]) -> str:
    status = data["status"]
    age = data["poll_age_seconds"]
    host = data["host"]

    if not status:
        router_pill = _pill("unk", "no status.json")
    elif age is None:
        router_pill = _pill("unk", "no readable poll time")
    elif age > POLL_STALE_SECONDS:
        router_pill = _pill("warn", f"stale — {_human_age(age)}")
    else:
        router_pill = _pill("ok", f"polling — {_human_age(age)}")

    # The two halves are shown as two facts and never blended into one light:
    # poll age says the drain loop is running; only the adapter's docker check
    # can say the container is. Neither substitutes for the other.
    #
    # The container pill AGGREGATES the adapter's verdicts for phase 8.1 and
    # recomputes none of them — 8.1 remains the only place that knows what a
    # healthy container is.
    if not host.get("available"):
        host_pill = _pill("unk", "unknown")
        host_detail = _esc(host.get("reason") or "not available")
    elif host.get("exit_meaning") == "cannot_run":
        # Its own state, never folded into ok or failed: the run produced no
        # verdict, so there is nothing here to be reassured or alarmed by.
        host_pill = _pill("unk", "check could not run")
        host_detail = "the host check produced no verdict — nothing was examined"
    elif host.get("exit_meaning") == "declined":
        # UNREACHABLE UNDER SCHEMA 2: `verify` never prompts, so it cannot
        # decline. Kept with the word itself — see HOST_FACTS_MEANINGS.
        host_pill = _pill("unk", "check declined")
        host_detail = "the host check declined to run"
    else:
        phase = find_phase(host, PHASE_CONTAINER)
        verdict = phase_verdict(phase) if phase else "unknown"
        pill_for = {
            "pass": ("ok", "container healthy"),
            "fail": ("warn", "container NOT healthy"),
            "unknown": ("unk", "container state unknown"),
            "unrunnable": ("unk", "container check unrunnable"),
            "skipped": ("unk", "container check skipped"),
        }
        kind, label = pill_for.get(verdict, ("unk", "container state unknown"))
        if verdict == "pass" and host.get("stale"):
            kind, label = "unk", "container was healthy"
        host_pill = _pill(kind, label)
        host_detail = (
            f'checked {_esc(_human_age(host.get("age_seconds")))}'
            f'{" — STALE" if host.get("stale") else ""}')

    def count(totals: Dict[str, Any], key: str, observed: bool) -> str:
        """One counter cell: the number, blank for zero, a marker for a
        counter that does not exist yet.

        BLANK FOR ZERO because a fleet of fifty agents where three are
        talking renders as a wall of zeros, and the three rows that carry
        every bit of the signal are lost in it. Zero is not news here; a
        number is. Suppressing it is what lets the eye find the four cells
        that matter without reading two hundred.

        BUT BLANK MUST MEAN ZERO AND NOTHING ELSE, which is why the third
        state exists. `totals.get(key, 0)` rendered 0 for an instance that
        has never been polled — indistinguishable from one polled a thousand
        times that did nothing, and when `status.json` is missing entirely it
        rendered a whole table of zeros that read as "all quiet" when the
        truth was "nothing has been observed". That is the same false report
        this page refuses everywhere else, and it was hiding in a default
        argument."""
        if not observed:
            return "<span class='unobs' title='not polled yet'>·</span>"
        value = totals.get(key, 0)
        return "" if value in (0, None) else _esc(value)

    rows = []
    for name, inst in sorted(data["instances"].items()):
        totals = (inst["status"].get("totals") or {})
        # "Observed" means THERE ARE COUNTERS, not merely that a key exists.
        # For every document this router writes the two are the same —
        # `status.record_poll` always emits a full `totals` — but they differ
        # for a status.json from an older writer or a hand edit, and there
        # the right answer is a dot: an entry with no counters has nothing to
        # report, which is not the same as counters that are zero.
        observed = bool(totals)
        flags = []
        if not inst["seen"]:
            flags.append(_pill("warn", "NEVER POLLED"))
        if inst["mode"] == MODE_NAMESPACE:
            flags.append(_pill("unk", "namespace mode"))
        if not inst["peer_lane"]:
            flags.append(_pill("unk", "no peer tree"))
        alerts = inst["status"].get("peer_alerts") or []
        if alerts:
            flags.append(_pill("warn", f"{len(alerts)} alert(s)"))
        rows.append(
            f"<tr><td class='mono'>{_esc(name)}</td>"
            f"<td class='mono'>{_esc(inst['address'])}</td>"
            f"<td class='num'>{count(totals, 'accepted', observed)}</td>"
            f"<td class='num'>{count(totals, 'rejected', observed)}</td>"
            f"<td class='num'>{count(totals, 'queued_for_human', observed)}</td>"
            f"<td class='num'>{count(totals, 'peer_delivered', observed)}</td>"
            f"<td>{' '.join(flags)}</td></tr>")

    return f"""
<h2>Health</h2>
<div class="cards">
  <div class="card"><div class="k">Drain loop</div><div class="v">{router_pill}</div>
    <div class="k" style="text-transform:none;margin-top:5px">
      {_esc(f"{status.get('polls', 0)} polls, pid {status.get('pid', '?')}")}</div></div>
  <div class="card"><div class="k">Container</div><div class="v">{host_pill}</div>
    <div class="k" style="text-transform:none;margin-top:5px">{host_detail}</div></div>
</div>
<p class="note"><b>These are two facts, not one light.</b> The drain loop's age
says this router polled recently; only the adapter's docker check can say the
container is running, on the correct mount set, and newer than its config.
Poll age cannot tell a hung router from an idle one, and a container check
cannot tell whether the loop inside it is doing anything.</p>
<table><thead><tr><th>instance</th><th>address</th><th class="num">accepted</th>
<th class="num">rejected</th><th class="num">held</th>
<th class="num">peer delivered</th><th></th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="7" class="empty">no instances</td></tr>'}</tbody></table>
<p class="note"><b>A blank counter is zero</b>, left empty so the numbers
that exist are findable — on a fleet this size the quiet agents are the
majority and their zeros are not news. <b>A dot (·) is not zero</b>: that
instance has not been polled since this router started, so there is nothing
to report about it rather than nothing to report. Counters are
per-process-lifetime and reset when the router restarts — they are not a
ledger. Volume over time is the Traffic section, which is built from the
audit log and the reply ledger.</p>
{_host_phases(host)}
"""


def _host_phases(host: Dict[str, Any]) -> str:
    """The adapter's phases, as it reported them.

    Claims and remedies are operator-facing prose the adapter wrote for
    exactly this purpose. Expected/actual VALUES are deliberately not in the
    document — they are mount tables and absolute host paths, and this page
    is a browser page — so what an operator gets here is "which claim failed
    and what to do", with the values a terminal away. That is the right
    default and it is the adapter's call, not this console's."""
    if not host.get("available"):
        return ""
    meaning = host.get("exit_meaning")
    banner = ""
    if meaning == "cannot_run":
        banner = ("<div class='banner unk'>The host check could not run, so it "
                  "returned no verdict about this host. This is neither a pass "
                  "nor a failure — nothing was examined.</div>")
    elif meaning == "declined":
        # UNREACHABLE UNDER SCHEMA 2 — see HOST_FACTS_MEANINGS.
        banner = "<div class='banner unk'>The host check declined to run.</div>"
    elif host.get("stale"):
        banner = (f"<div class='banner unk'>These host facts are "
                  f"{_esc(_human_age(host.get('age_seconds')))} and may no longer "
                  f"describe the running host.</div>")


    phases = [p for p in (host.get("phases") or []) if isinstance(p, dict)]
    if not phases:
        # THE BANNER IS EMITTED HERE TOO, and this line is the reason the
        # computation moved above this return. `cannot_run` arrives with
        # `phases: []` — that IS its shape — so the early return used to skip
        # the banner for the one document on which it matters most: nothing
        # was read, no phase was reached, and the page said only "reported no
        # phases", losing the sentence written for exactly this case.
        #
        # Found by rendering a captured `cannot_run` document, not by reading
        # this function. The empty-phases path and the banner path were
        # written for different reasons and nothing connected them.
        return (banner + "<p class='note'>The host check reported no phases — nothing "
                "was examined.</p>")

    kind_for = {"pass": "ok", "fail": "warn", "unknown": "unk",
                "unrunnable": "unk", "skipped": "unk"}
    rows = []
    for phase in phases:
        verdict = phase_verdict(phase)
        detail = ""
        if verdict == "unrunnable":
            # UNREACHABLE UNDER SCHEMA 2, deliberately kept. Schema 1 had
            # `unrunnable` (a phase whose probe never ran) and `skipped` as
            # phase-level keys; schema 2 has neither, because an unanswerable
            # check is now an UNKNOWN in the list WITH ITS REASON — which is
            # the better design: an absent phase tells a reader nothing about
            # why it is absent.
            #
            # Kept rather than deleted because a branch with no producer is
            # not the same as a branch that is wrong, and deleting a state is
            # how a console loses the ability to say something it may need
            # again. If either word returns it arrives with a schema bump.
            detail = (f"<div class='note'>could not be read: "
                      f"{_esc(phase.get('unrunnable'))}</div>")
        elif verdict == "skipped":
            # Also unreachable under schema 2 — see above.
            detail = f"<div class='note'>skipped: {_esc(phase.get('skipped'))}</div>"
        else:
            bad = [c for c in (phase.get("checks") or [])
                   if isinstance(c, dict) and c.get("result") != "PASS"]
            for check in bad:
                remedy = check.get("remedy")
                # `reason` (schema 2) is on UNKNOWN checks and is the whole
                # content of the answer: the producer's own sentence about why
                # it could not tell. It is FREE TEXT, may be MULTI-LINE, and
                # may carry a host path — the only field in the document that
                # can. So it gets `.reason`, which is `pre-wrap`; a plain
                # `.note` collapses the newline and a two-line reason renders
                # as one run-on sentence that reads as a single confused
                # statement from a single speaker. Found by rendering a real
                # captured document rather than the shape of one.
                reason = check.get("reason")
                detail += (
                    f"<div class='note'><b>{_esc(check.get('result') or '?')}</b> "
                    f"{_esc(check.get('claim'))}"
                    + (f"<br>{_esc(remedy)}" if remedy else "")
                    + (f"<div class='reason'>{_esc(reason)}</div>" if reason else "")
                    + "</div>")
        rows.append(
            f"<tr><td class='mono'>{_esc(phase.get('id') or '?')}</td>"
            f"<td>{_esc(phase.get('title') or '')}{detail}</td>"
            f"<td>{_pill(kind_for.get(verdict, 'unk'), verdict)}</td></tr>")

    return f"""
<h2>Host checks <span class="note">— reported by the adapter's
<code>amap-sandy.py verify</code>, {_esc(_human_age(host.get("age_seconds")))}</span></h2>
{banner}
<table><thead><tr><th>phase</th><th>claim</th><th>verdict</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="note">These are the adapter's verdicts, reported not recomputed —
the adapter's <code>{PHASE_CONTAINER}</code> phase is the only place that
knows what a healthy container is, and a second implementation here would
drift from it. <b>UNKNOWN</b> is a check that RAN and could not tell; its
<i>reason</i> is the producer's own sentence about why, shown verbatim
beneath the claim. Only non-passing checks are listed: a true-but-worthless
PASS beside a FAIL is how a page grows past the point anyone reads it.</p>
"""


def _discovery_section(data) -> str:
    """What discovery SAW and did not admit — on the page, not only in a log.

    THE CONSOLE IS THE SURFACE MOST ABLE TO LIE HERE. With no readable
    verdict nothing is admitted, so every other section renders correctly and
    says nothing: an empty instance table, an empty traffic table, no
    excluded agents, no alerts. A healthy-looking page for a fleet with real
    sandboxes on disk that is delivering nothing.

    That is the same defect `peers --json` had — a CORRECT rendering of an
    unknown input — found on this surface by generalising it rather than by a
    test, because no test of a renderer catches a renderer that is right.
    """
    report = data.get("discovery")
    if report is None:
        # An authored fleet. Absent, not empty: there is nothing to report
        # because discovery did not happen, and a section saying "clean"
        # would be a claim about a process that never ran.
        return ""
    from .status import render_discovery
    if not render_discovery(report):
        return ""

    # GROUPED BY CONDITION, NOT ONE ROW PER SLUG.
    #
    # `render_discovery` emits one line per slug because it is WIRE: a host
    # adapter greps it, a `** `-wrapped line under `discovery:` is a FAIL, and
    # that format is not this module's to change. **Nothing here touches it.**
    # This builds from the REPORT OBJECT instead, so the page can group and
    # the grep keeps its line-per-slug.
    #
    # Why group: on a real fleet the same condition holds for many slugs at
    # once — a rename produces a NO VERDICT per workspace, a missing manifest
    # entry produces an INERT EDGE per endpoint — and a column of near-
    # identical sentences is where an operator stops reading. The CONDITION is
    # the thing to act on and there are only ever a handful; the slugs are the
    # scope of that one action.
    groups = []   # (loud, tag, reason, [slugs])
    if report.verdict_unavailable:
        groups.append((True, "VERDICT UNAVAILABLE",
                       "the host's selected.json is missing or unreadable, so "
                       "nothing is admitted — this is UNANSWERED, not "
                       "'the host answered none'", []))
    by_reason = {}
    for slug, reason in sorted(report.skipped.items()):
        by_reason.setdefault(reason, []).append(slug)
    for reason, slugs in sorted(by_reason.items()):
        groups.append((False, "SKIPPED", reason, slugs))
    if report.no_verdict:
        groups.append((False, "NO VERDICT",
                       "a directory with no entry in the host's selected.json "
                       "— NOT DRAINED and NOT deleted; every workspace rename "
                       "produces one", sorted(report.no_verdict)))
    if report.verdict_without_directory:
        groups.append((True, "NO DIRECTORY",
                       "the host selected it and its tree does not exist. A "
                       "verdict follows a launch and a launch creates the tree, "
                       "so this is broken state rather than a pending one",
                       sorted(report.verdict_without_directory)))
    by_reason = {}
    for slug, reason in sorted(report.inert_edges.items()):
        by_reason.setdefault(reason, []).append(slug)
    for reason, slugs in sorted(by_reason.items()):
        # Same two tiers the wire format marks: a reason naming a typo is the
        # loud one. Read from the reason rather than recomputed, so the page
        # and the log cannot disagree about which edges need a human.
        groups.append(("typo" in reason, "INERT EDGE", reason, slugs))

    # LOUD FIRST. The wire format cannot reorder — its consumer greps line by
    # line and the order is the report's — but a page can, and a condition
    # needing a human should not be below three that do not. Stable within
    # each half, so the grouping order above still holds inside it.
    groups.sort(key=lambda g: not g[0])

    rows = ""
    for loud, tag, reason, slugs in groups:
        who = ("".join(f"<span class='mono'>{_esc(s)}</span> " for s in slugs)
               if slugs else "<span class='empty'>—</span>")
        count = (f"<span class='kind'>{len(slugs)} workspace"
                 f"{'' if len(slugs) == 1 else 's'}</span>") if slugs else ""
        rows += (f"<tr><td class=\"{'bad' if loud else 'warn'}\">"
                 f"<b>{_esc(tag)}</b><div class='note'>{_esc(reason)}</div></td>"
                 f"<td>{count}{who}</td></tr>")

    return f"""
<h2>Discovery</h2>
<p class="note">Instances are DIRECTORIES admitted by the host's verdict.
Everything below was seen and not admitted, or admitted with something
unresolved. An empty fleet with lines here is not an idle fleet — it is a
fleet this router could not assemble.</p>
<table><thead><tr><th>condition</th><th>workspaces it applies to</th></tr>
</thead><tbody>{rows}</tbody></table>"""


def _excluded_section(data: Dict[str, Any]) -> str:
    ex = data["excluded"]

    # The REMEDY column always states the remedy, even when the "who" is
    # unanswered: an operator reading this section is learning that three
    # different fixes exist, and hiding one of them behind the availability
    # of a file would teach the wrong shape. What changes when the facts are
    # missing is the "who", which says so and says how to answer it.
    def listing(names: List[Any], kind: str) -> str:
        """A list of identifiers, LABELLED WITH WHICH NAMESPACE THEY ARE IN.

        Two different kinds of name land in this one column and they are not
        interchangeable: a sandy SLUG (`name-<hash>`, whatever characters the
        workspace path produced) and a router INSTANCE NAME (derived from a
        slug by lowercasing and replacing everything outside `[a-z0-9-]`).
        They coincide for most sandboxes and diverge for any slug carrying
        uppercase, `_` or `.` — on the operator's own box, 9 slugs of 42.

        Rendering both unlabelled in one column is how an operator comes to
        believe `My_Repo-1a2b3c4d` and `my-repo-1a2b3c4d` are the same row of
        the same table, and they are not.

        The examples here and in the rendered page are SYNTHETIC on purpose.
        A slug's 8-hex suffix is a hash of a real workspace path, so it
        identifies that workspace whatever name precedes it — an example
        built by putting an invented word in front of a real digest is not
        sanitised, it only reads as though it were."""
        # The label is emitted even for an empty list. It describes what the
        # cell holds, not what happens to be in it today, and dropping it
        # when a row is empty removes the namespace claim exactly when the
        # row has nothing to disambiguate it — which is the moment a reader
        # is most likely to carry the previous row's reading downward.
        label = f"<div class='kind'>{_esc(kind)}</div>"
        if not names:
            return f"{label}<span class='empty'>none</span>"
        # Sorted case-insensitively here rather than taking the document's
        # order: the adapter emits `sorted()`, which puts capitalised slugs
        # ahead of lowercase ones, and it said explicitly that the order is
        # not part of the contract and to sort our own way.
        rendered = ", ".join(
            f"<span class='mono'>{_esc(n)}</span>"
            for n in sorted((str(n) for n in names), key=str.lower))
        return f"{label}{rendered}"

    if ex["not_enrolled_known"]:
        # SLUGS, VERBATIM, AND NEVER DERIVED INTO INSTANCE NAMES. A sandbox
        # that was never enrolled has no router instance at all — no entry in
        # router.json, no `state_dir/<name>/` — so the slug is not merely the
        # identifier the adapter happened to pick, it is the only identifier
        # that exists. Deriving one would also be unsound in principle:
        # `instance_name_for_slug` does not disambiguate, so two slugs can
        # derive to one name and a derived match can land on the wrong row.
        who = listing(ex["not_enrolled"] or [], "sandy slugs — no router instance exists")
    else:
        who = (_pill("unk", "UNANSWERED") +
               " — this router cannot see fleet policy at all. Supply "
               "<code>--host-facts</code> from the adapter's "
               "<code>amap-sandy.py verify</code> to answer it.")
    enrolled_row = f"<td>{who}</td><td>edit the fleet policy and re-sync</td>"

    return f"""
<h2>Excluded agents</h2>
<p class="note">An agent can be excluded in three different ways with three
different remedies, so they are kept apart. A console that answered only the
middle one would send you to re-render a config when the real problem was a
drainer that never came up, or a glob that matched nothing.</p>
<table><thead><tr><th>sense</th><th>who</th><th>remedy</th></tr></thead><tbody>
<tr><td><b>Not enrolled</b><br><span class="note">denied by policy, or matched
no profile — including a profile whose glob matches nothing, which enrols
nobody and looks exactly like a deliberate choice</span></td>{enrolled_row}</tr>
<tr><td><b>No edge</b><br><span class="note">configured here, but no
counterpart on either lane</span></td>
<td>{listing(ex['no_edge'], 'router instance names')}</td>
<td>declare a <code>peer_senders</code> edge or a mutual <code>peers</code> pair</td></tr>
<tr><td><b>Never polled</b><br><span class="note">configured, with edges,
but this router has never seen its root — no first-sight marker exists</span></td>
<td>{listing(ex['never_polled'], 'router instance names')}</td>
<td>start the drainer, or check it is pointed at this config:
<code>python3 -m router --config C once</code></td></tr>
</tbody></table>
<p class="note"><b>Two namespaces share that column, so it says which is
which.</b> The first row lists <i>sandy slugs</i> — <code>name-&lt;hash&gt;</code>,
carrying whatever characters the workspace path produced. The other two list
<i>router instance names</i>, which since the name charset was widened to
the slug alphabet are the slug, spelled the same way: <code>My_Repo-1a2b3c4d</code>
is the instance name, not a source for deriving one. Nothing here maps
between the two columns, and nothing should start: the reason the columns are
labelled is that a sandbox can appear in one and not the other. A not-enrolled
sandbox has <b>no instance name at all</b>: nothing in
<code>router.json</code>, nothing under <code>state_dir/</code>. This page
never invents one, because there is nothing to invent it for: an unenrolled
sandbox is absent from this router's world entirely, and a name placed in that
column would claim otherwise.</p>
"""


def _traffic_section(data: Dict[str, Any]) -> str:
    rows = []
    for pair in data["traffic"]:
        lane = "peer" if pair["tree"] == "peer" else "mail"
        rows.append(
            f"<tr><td class='mono'>{_esc(pair['sender'])}</td>"
            f"<td class='mono'>{_esc(pair['recipient'])}</td>"
            f"<td>{_esc(lane)}</td><td>{pair['count']}</td>"
            f"<td class='mono'>{_esc(pair['last_ts'] or '—')}</td></tr>")

    refusals = []
    for name, inst in sorted(data["instances"].items()):
        for event in inst["events"]:
            if event.get("event") == audit_mod.EVENT_PEER_REFUSED:
                refusals.append(
                    f"<tr><td class='mono'>{_esc(event.get('ts', '—'))}</td>"
                    f"<td class='mono'>{_esc(event.get('instance', name))}</td>"
                    f"<td>{_esc(event.get('cause') or event.get('reason_code') or '—')}</td></tr>")

    refusal_table = (
        f"<table><thead><tr><th>when</th><th>instance</th><th>cause</th></tr>"
        f"</thead><tbody>{''.join(refusals)}</tbody></table>"
        if refusals else "<p class='empty'>no refusals recorded</p>")

    return f"""
<h2>Traffic</h2>
<table><thead><tr><th>from</th><th>to</th><th>lane</th><th>messages</th>
<th>most recent</th></tr></thead><tbody>
{''.join(rows) or '<tr><td colspan="5" class="empty">nothing delivered yet</td></tr>'}
</tbody></table>
<p class="note">Counted from the reply-binding ledger, which this router wrote
and no agent can reach — so who sent what to whom is router-asserted, not
taken from any message.</p>
<h2>Refused</h2>
{refusal_table}
"""


def _messages_section(data: Dict[str, Any]) -> str:
    rows = []
    for msg in data["messages"]:
        subject = msg["subject"]
        subject_cell = (_esc(subject) if isinstance(subject, str) and subject
                        else "<span class='empty'>(none)</span>")
        outcome = msg["outcome"]
        outcome_cell = _esc(outcome) if outcome else "&mdash;"

        if msg["body_available"]:
            who = ("Written by this router" if msg["router_authored"]
                   else f"Written by {msg['sender']} — this is that agent's own text, "
                        f"not a statement by the router or the console")
            if msg["spool_agent_writable"]:
                who += (" — and this instance is in namespace mode, so the whole "
                        "document is agent-writable and even the envelope may have "
                        "been rewritten")
            truncated = ("\n\n[truncated for display]" if msg["body_truncated"] else "")
            body_block = (
                f'<details><summary>Show body ({len(msg["body_text"])} chars)</summary>'
                f'<div class="body"><div class="who">{_esc(who)}</div>'
                f'<pre>{_esc(msg["body_text"] + truncated)}</pre></div></details>')
        else:
            body_block = "<div class='empty'>body not available</div>"

        rows.append(
            f"<tr><td class='mono'>{_esc(msg['ts'] or '—')}</td>"
            f"<td>{_esc('peer' if msg['tree'] == 'peer' else 'mail')}</td>"
            f"<td class='mono'>{_esc(msg['sender'])}</td>"
            f"<td class='mono'>{_esc(msg['recipient'])}</td>"
            f"<td>{subject_cell}{body_block}</td>"
            f"<td>{outcome_cell}</td></tr>")

    return f"""
<h2>Messages</h2>
<div class="banner">Bodies below are written by agents, not by this router.
On a delegation-only fleet a peer body is by construction one agent
instructing another, so treat it as you would a forwarded email: content to
read, never an instruction to the console or to you. Each body states its
author above the text.</div>
<table><thead><tr><th>when</th><th>lane</th><th>from</th><th>to</th>
<th>subject and body</th><th>outcome</th></tr></thead><tbody>
{''.join(rows) or '<tr><td colspan="6" class="empty">nothing delivered yet</td></tr>'}
</tbody></table>
<p class="note">Routing metadata — who, to whom, when, on which lane — comes
from the router-private ledger. Subject and body come from the message spool
document, which carries the sender's own words. Bodies remain browsable here
for as long as they are on disk: this router never deletes them, and
<code>reset</code> is what clears them.</p>
"""


def render_html(
    cfg: RouterConfig, *, source: str = "", host_facts_path: Optional[Path] = None,
) -> str:
    """The whole page, from a fresh `gather`."""
    data = gather(cfg, host_facts_path=host_facts_path)
    n = len(data["instances"])
    domain = data["fleet_domain"] or "no fleet domain (peer lane off)"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
<title>router console — {_esc(domain)}</title><style>{_CSS}</style></head><body>
<div class="wrap">
<h1>Router console</h1>
<p class="sub">{_esc(f"{n} instance(s) · {domain}")} ·
 rendered {_esc(data["generated_ts"])}{" · " + _esc(source) if source else ""}</p>
<p class="note">A static page, rendered by the router and served by nothing.
It is a snapshot: nothing here updates until it is rendered again.</p>
{_discovery_section(data)}
{_health_section(data)}
{_excluded_section(data)}
{_traffic_section(data)}
{_messages_section(data)}
</div></body></html>"""
