#!/usr/bin/env python3
"""Reply depth over a run window: every peer-lane reply placed in the window
is a FIRST-LEVEL reply (it answers a fresh task), never a reply to a reply.

An offline analyser of COPIED router records. It never opens a live
`state_dir`, writes nothing, sends nothing, and imports nothing from the
router package: it reads the files it is given and prints.

THE SOURCE: the router's audit log, `state_dir/<state key>/audit/log.jsonl`
(`router/audit.py`, `log_path`), one per hosted instance, from EVERY host in
the run. Its `peer_notice_placed` event is written by both placement paths,
and is the only router record that carries `in_reply_to`:

  * same host, `origin: "local"`: `router/deliver.py`, `deliver_peer`;
  * cross host, `origin: "fleet"`: `router/deliver.py`, `deliver_signed_peer`.

The ledgers cannot answer depth: a binding record has no `in_reply_to`
(`binding.record_delivery`), and the peer ledger's members are closed
(`peerlane.LEDGER_MEMBERS`) without one.

Why the audit log is complete for a window, and when it is not: the
placement commit order is spool, ledger, audit, notice LAST
(`deliver._commit`), so while every host stays up, every notice an agent
could see has its line. A crash between audit and notice leaves a line for
a notice never shown; the replay places it again under the same notice id
with a later `ts` (deduplicated below, and a STOP if the two straddle a
window edge). The audit append is NOT fsynced (`audit.append_bytes`,
`durable=False`), so after a power loss or kernel crash a visible notice
can lack its line, and a lost depth-2 line would read as a PASS. This tool
therefore does not take the log's completeness on trust: it RECONCILES the
log against copies of the peer notice trees, in both directions, every run.
A notice with no audit line is an undercount and a STOP; an audit line whose
notice is absent (a placement that crashed and was never replayed, or a tree
copied short) is an overcount and a STOP. Only `deliver_peer` and
`deliver_signed_peer` write into a peer tree, and the agent's mount of it is
read-only, so the two sets must agree. The one sanctioned removal is
`reset`, which empties the peer tree and keeps the audit log, recording
itself there (`router/reset.py`): placements before an instance's last
`reset` line are exempt from the overcount check, and a `reset` at or after
the window start is a STOP (it emptied the tree the window's lines must be
checked against; copy before any reset). The log is append-only and `reset` skips it
(`router/audit.py` module docstring), and it lives under `state_dir`, which
no agent uid reaches. A host records only what it PLACED, so a cross-host
chain spans two hosts' logs: hence every host, and the domain checks below.

What remains on the operator: an instance whose audit log AND peer tree are
both left out of the copies is invisible (one whose log is read needs its
tree, or a `--no-peer-tree` declaration, which is printed). The output lists
every log, tree and declaration, so that can be checked against the hosts'
configs. And the copies must be taken before any `reset` of a run instance:
a reset at or after the window start is a STOP.

DEPTH. A placed message is a TASK when `in_reply_to` is null. Otherwise its
parent is the placed message whose `message_id` equals its `in_reply_to`
(same host: the reply's `in_reply_to` is the ledger record's `message_id`,
`deliver._in_reply_to_from`; cross host: the statement's `in_reply_to`, the
id the parent was placed under). A reply whose parent is a task is
FIRST-LEVEL; a reply whose parent is itself a reply is DEPTH 2+. Parents are
looked up in every supplied log, whatever their `ts`; only the CHILDREN are
filtered by the window.

INPUT.

    check_reply_depth.py --since 2026-11-15T15:00:00Z --until 2026-11-15T16:00:00Z \\
        --host <host domain>=<copy of that host's state_dir> [--host ...] \\
        --peer-tree <host domain>/<instance>=<copy of that instance's peer/> [...] \\
        [--no-peer-tree <host domain>/<instance> ...]

Each `--host` names one host by the domain its agents' addresses carry and a
directory holding a copy of its `state_dir` (only `*/audit/log.jsonl` is
read). Each `--peer-tree` names one hosted instance by its NAME (the audit
line's `to_instance`) and a copy of its peer tree, `<root>/peer`
(`config.PEER_TREE`); only `notices/` is read. Every instance named in any
log read (its lines' `instance`) needs its tree, unless the operator declares
it with `--no-peer-tree` (an instance with no peer lane); an instance that any
line places to needs its tree regardless. The window is `[since, until)` on the line's
`ts`. The router has no notion of a run id: the operator maps a run to its
window.

OUTPUT. First, one line per log read, `read <host> <dir> lines=N
peer_notice_placed=M` (`<dir>` is the state directory: the instance name, or
its state key on a registry host), and one per tree, `tree <host> <instance>
notices=N leftovers=K`, and one per `--no-peer-tree` declaration, so the
operator can check that every hosted instance of every host was supplied.
Then the window, what was reconciled, and per lane (`local`, `fleet`):
tasks, first-level replies and depth-2+ replies in the window, each with its
message ids. Then EXACTLY ONE line beginning `RESULT `, and it is the last
line:

  * `RESULT PASS` -- first-level >= 1 (both lanes together) and depth-2+ = 0;
  * `RESULT FAIL` -- the records are sound and the assertion does not hold;
  * `RESULT STOP` -- the records cannot support a verdict.

The exit status mirrors it (0, 1, 2), but the RESULT line is the verdict:
rc 0 without `RESULT PASS` is not a pass. Output is ASCII: anything else in
an id or a path is printed escaped.

STOP, never PASS, on: a bad argument; a host directory with no audit log; a
symlink anywhere on a log's or a tree's path; an unreadable or non-regular
log or notice; a log not ending in a newline (a truncated copy); a line that
is not UTF-8 JSON with a string `event` and a valid UTC `ts`; a
`peer_notice_placed` line missing a field or with an unknown `origin`; one
`message_id` placed twice with different contents; identical lines for one
`message_id` on both sides of a window edge; a `to` outside the host it was
logged on; an address on a host that was not supplied; two `--host` with one
domain; a peer tree for a host not supplied, or supplied twice; an instance
placed to with no tree; a notice with no audit line, or one that disagrees
with its line; two audit lines for one notice; an audit line with no notice
(after the instance's last `reset`); a write leftover in `notices/` with no
audit line (a lost append); an instance whose log was read with neither a
tree nor a `--no-peer-tree`; a line without an `instance` name; a `reset` at
or after `since`; an unknown entry in `notices/`; a reply whose parent is in
no supplied log, or does not run the reverse direction; an empty window.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

EVENT = "peer_notice_placed"
RESET = "reset"
LANES = ("local", "fleet")
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DOMAIN_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
#: An instance name: `config._NAME_RE`.
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
#: In `notices/`: a notice (`deliver._commit`), its sidecar directory
#: (`attachments.sidecar_dir_name`), and the temp name a crash mid-write
#: leaves behind (`attachments._write_blob_pinned`).
NOTICE_RE = re.compile(r"notice-([A-Za-z0-9_][A-Za-z0-9_.-]*)\.json\Z")
SIDECAR_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.attachments\Z")
LEFTOVER_RE = re.compile(
    r"\.notice-([A-Za-z0-9_][A-Za-z0-9_.-]*)\.json\.tmp\.[0-9]+\.[0-9a-f]{16}\Z")
#: The members a placed message is compared on when it appears twice.
IDENTITY = ("notice_id", "from", "to", "to_instance", "in_reply_to", "origin", "tree")

PASS, FAIL, STOP = "PASS", "FAIL", "STOP"
RC = {PASS: 0, FAIL: 1, STOP: 2}


class Stop(Exception):
    """The records cannot support a verdict."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Stop(f"usage: {message}")


def valid_ts(value) -> bool:
    """A real UTC instant in exactly `YYYY-MM-DDTHH:MM:SSZ` (`util.utc_ts`):
    parsed strictly and required to round-trip, so a shape-valid but
    impossible value (month 99, 30 February, 25:00) is refused."""
    if not isinstance(value, str):
        return False
    try:
        return datetime.strptime(value, TS_FORMAT).strftime(TS_FORMAT) == value
    except ValueError:
        return False


def _domain(address, where: str) -> str:
    if not isinstance(address, str) or address.count("@") != 1:
        raise Stop(f"{where}: {address!r} is not an address")
    local, domain = address.split("@")
    if not local or not domain.isascii() or not DOMAIN_RE.fullmatch(domain):
        raise Stop(f"{where}: {address!r} is not an address")
    return domain.lower()


def _canonical(address: str) -> str:
    local, domain = address.split("@")
    return f"{local}@{domain.lower()}"


def _no_symlink(path: Path, root: Path) -> None:
    p = root
    if p.is_symlink():
        raise Stop(f"{p}: a symlink, refused")
    for part in path.relative_to(root).parts:
        p = p / part
        if p.is_symlink():
            raise Stop(f"{p}: a symlink, refused")


def _read_file(path: Path, root: Path) -> bytes:
    _no_symlink(path, root)
    try:
        # O_NONBLOCK: a FIFO opens at once and is then refused as not regular.
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise Stop(f"{path}: unreadable ({type(e).__name__})") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Stop(f"{path}: not a regular file")
        chunks = []
        while True:
            b = os.read(fd, 1 << 16)
            if not b:
                break
            chunks.append(b)
    except OSError as e:
        raise Stop(f"{path}: unreadable ({type(e).__name__})") from None
    finally:
        os.close(fd)
    return b"".join(chunks)


def _lines(path: Path, data: bytes) -> List[Tuple[int, dict]]:
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise Stop(f"{path}: does not end in a newline (a truncated copy?)")
    out = []
    for n, raw in enumerate(data.split(b"\n")[:-1], start=1):
        where = f"{path}:{n}"
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Stop(f"{where}: not a UTF-8 JSON line") from None
        if not isinstance(doc, dict):
            raise Stop(f"{where}: not a JSON object")
        if not isinstance(doc.get("event"), str) or not doc["event"]:
            raise Stop(f"{where}: no event")
        if not valid_ts(doc.get("ts")):
            raise Stop(f"{where}: ts {doc.get('ts')!r} is not a valid UTC timestamp")
        out.append((n, doc))
    return out


def _placed(doc: dict, where: str, host: str) -> dict:
    for k in ("message_id", "notice_id"):
        if not isinstance(doc.get(k), str) or not doc[k]:
            raise Stop(f"{where}: {k} missing or empty")
    if not isinstance(doc.get("to_instance"), str) or not NAME_RE.fullmatch(doc["to_instance"]):
        raise Stop(f"{where}: to_instance {doc.get('to_instance')!r} is not an instance name")
    if "in_reply_to" not in doc:
        raise Stop(f"{where}: in_reply_to missing (null on a task, never absent)")
    irt = doc["in_reply_to"]
    if irt is not None and (not isinstance(irt, str) or not irt):
        raise Stop(f"{where}: in_reply_to {irt!r} is neither null nor an id")
    if doc.get("origin") not in LANES:
        raise Stop(f"{where}: origin {doc.get('origin')!r} is not one of {LANES}")
    if doc.get("tree") != "peer":
        raise Stop(f"{where}: tree {doc.get('tree')!r} is not 'peer'")
    if _domain(doc.get("to"), where + " to") != host:
        raise Stop(f"{where}: to {doc.get('to')!r} is not on host {host!r}, where it was logged")
    _domain(doc.get("from"), where + " from")
    return {**{k: doc[k] for k in IDENTITY}, "message_id": doc["message_id"],
            "ts": doc["ts"], "all_ts": [doc["ts"]], "host": host, "where": where}


class Records:
    def __init__(self):
        self.placed: Dict[str, dict] = {}
        #: (host, instance name) -> the ts of every `reset` line.
        self.resets: Dict[Tuple[str, str], List[str]] = {}
        #: (host, instance name) -> {notice_id: notice doc}
        self.trees: Dict[Tuple[str, str], Dict[str, dict]] = {}
        #: (host, instance name) -> the notice id of every write leftover
        self.leftovers: Dict[Tuple[str, str], List[str]] = {}
        #: (host, instance name) of every log read (the `instance` of its lines)
        self.logged: set = set()
        self.read: List[str] = []


def load(hosts: List[Tuple[str, Path]], trees: List[Tuple[str, str, Path]],
         recs: Optional[Records] = None,
         no_tree: Optional[List[Tuple[str, str]]] = None) -> Records:
    """Every placed message in every supplied log, keyed by `message_id`,
    every `reset` line, and every notice in every supplied tree."""
    domains = [d for d, _ in hosts]
    if len(set(domains)) != len(domains):
        raise Stop("two --host entries name one domain: hosts must be told apart by domain")
    recs = recs if recs is not None else Records()
    for host, root in hosts:
        if root.is_symlink() or not root.is_dir():
            raise Stop(f"{root}: not a directory")
        logs = sorted(root.glob("*/audit/log.jsonl"))
        if not logs:
            raise Stop(f"{root}: no */audit/log.jsonl for host {host!r}")
        for path in logs:
            docs = _lines(path, _read_file(path, root))
            n_placed = 0
            for n, doc in docs:
                inst = doc.get("instance")
                if not isinstance(inst, str) or not NAME_RE.fullmatch(inst):
                    raise Stop(f"{path}:{n}: line without an instance name")
                recs.logged.add((host, inst))
                if doc["event"] == RESET:
                    recs.resets.setdefault((host, inst), []).append(doc["ts"])
                    continue
                if doc["event"] != EVENT:
                    continue
                n_placed += 1
                rec = _placed(doc, f"{path}:{n}", host)
                prior = recs.placed.get(rec["message_id"])
                if prior is None:
                    recs.placed[rec["message_id"]] = rec
                elif any(prior[k] != rec[k] for k in IDENTITY) or prior["host"] != host:
                    raise Stop(f"message_id {rec['message_id']} placed twice with different "
                               f"contents ({prior['where']}, {rec['where']})")
                else:
                    prior["all_ts"].append(rec["ts"])
            recs.read.append(f"read {host} {path.relative_to(root).parts[0]} "
                             f"lines={len(docs)} peer_notice_placed={n_placed}")
    supplied = set(domains)
    for rec in recs.placed.values():
        for k in ("from", "to"):
            d = _domain(rec[k], rec["where"])
            if d not in supplied:
                raise Stop(f"{rec['where']}: {k} {rec[k]!r} is on host {d!r}, "
                           f"whose logs were not supplied")
    for host, inst, root in trees:
        if host not in supplied:
            raise Stop(f"--peer-tree {host}/{inst}: host {host!r} has no --host")
        if (host, inst) in recs.trees:
            raise Stop(f"--peer-tree {host}/{inst} supplied twice")
        recs.trees[(host, inst)], recs.leftovers[(host, inst)] = _read_tree(
            host, inst, root, recs.read)
    declared = set()
    for host, inst in no_tree or []:
        if host not in supplied:
            raise Stop(f"--no-peer-tree {host}/{inst}: host {host!r} has no --host")
        if (host, inst) in recs.trees or (host, inst) in declared:
            raise Stop(f"{host}/{inst} is given a --peer-tree and a --no-peer-tree, or "
                       f"--no-peer-tree twice")
        declared.add((host, inst))
        recs.read.append(f"declared {host} {inst} has no peer tree")
    for host, inst in sorted(recs.logged - set(recs.trees) - declared):
        raise Stop(f"instance {inst} on host {host} has an audit log but no --peer-tree "
                   f"(declare --no-peer-tree {host}/{inst} if it has no peer lane)")
    return recs


def _read_tree(host: str, inst: str, root: Path,
               read: List[str]) -> Tuple[Dict[str, dict], List[str]]:
    notices = root / "notices"
    _no_symlink(notices, root)
    if not notices.is_dir():
        raise Stop(f"{notices}: not a directory")
    found: Dict[str, dict] = {}
    leftovers: List[str] = []
    for entry in sorted(notices.iterdir()):
        name = entry.name
        m = NOTICE_RE.fullmatch(name)
        if m:
            raw = _read_file(entry, root)
            try:
                doc = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise Stop(f"{entry}: not a UTF-8 JSON notice") from None
            msg = doc.get("message") if isinstance(doc, dict) else None
            if (not isinstance(msg, dict) or doc.get("notice_id") != m.group(1)
                    or doc.get("kind") != "peer" or not isinstance(msg.get("id"), str)
                    or not isinstance(msg.get("from"), str)
                    or not isinstance(msg.get("in_reply_to", ""), str)):
                raise Stop(f"{entry}: not a peer notice named for its own notice_id")
            found[m.group(1)] = doc
        elif SIDECAR_RE.fullmatch(name) and entry.is_dir() and not entry.is_symlink():
            continue
        elif LEFTOVER_RE.fullmatch(name) and not entry.is_symlink():
            leftovers.append(LEFTOVER_RE.fullmatch(name).group(1))
        else:
            raise Stop(f"{entry}: not a notice, a sidecar or a write leftover")
    read.append(f"tree {host} {inst} notices={len(found)} leftovers={len(leftovers)}")
    return found, leftovers


def reconcile(recs: Records, since: str, until: str) -> str:
    """The audit set against the notice trees, both directions."""
    for (host, inst), stamps in sorted(recs.resets.items()):
        after = sorted(t for t in stamps if t >= since)
        if after:
            raise Stop(f"instance {inst} on host {host} was reset at or after the window start "
                       f"({after[0]}): its window notices cannot be reconciled")
    by_notice: Dict[Tuple[str, str], Dict[str, dict]] = {}
    for rec in recs.placed.values():
        key = (rec["host"], rec["to_instance"])
        if key not in recs.trees:
            raise Stop(f"{rec['where']}: no --peer-tree {key[0]}/{key[1]} for the instance it "
                       f"places to")
        other = by_notice.setdefault(key, {}).get(rec["notice_id"])
        if other is not None:
            raise Stop(f"notice {rec['notice_id']} in {key[0]}/{key[1]} has two audit lines with "
                       f"different message ids ({other['where']}, {rec['where']})")
        by_notice[key][rec["notice_id"]] = rec
    lines = 0
    for key, recs_by_notice in sorted(by_notice.items()):
        last_reset = max(recs.resets.get(key, []), default=None)
        tree = recs.trees[key]
        for nid, rec in sorted(recs_by_notice.items()):
            if nid in tree:
                continue
            if last_reset is not None and max(rec["all_ts"]) < last_reset:
                continue        # emptied by the reset recorded after it
            raise Stop(f"{rec['where']}: audit line for notice {nid} but no notice in "
                       f"{key[0]}/{key[1]} (an overcount: a placement never completed?)")
        lines += len(recs_by_notice)
    for key, ids in sorted(recs.leftovers.items()):
        for nid in ids:
            # The audit append precedes the notice write, and a page-cache
            # append survives a process crash: a leftover with no line
            # implies a power loss or kernel crash.
            if nid not in by_notice.get(key, {}):
                raise Stop(f"a write leftover for notice {nid} in {key[0]}/{key[1]} has no "
                           f"audit line (a lost audit append: power loss?)")
    notices = 0
    for key, tree in sorted(recs.trees.items()):
        known = by_notice.get(key, {})
        for nid, doc in sorted(tree.items()):
            rec = known.get(nid)
            if rec is None:
                raise Stop(f"notice {nid} in {key[0]}/{key[1]} has no audit line "
                           f"(an undercount: a lost audit append?)")
            msg = doc["message"]
            if (msg["id"], _canonical(msg["from"]) if msg["from"].count("@") == 1 else None,
                    msg.get("in_reply_to")) != (
                    rec["message_id"], _canonical(rec["from"]), rec["in_reply_to"]):
                raise Stop(f"notice {nid} in {key[0]}/{key[1]} disagrees with its audit line "
                           f"{rec['where']}")
            notices += 1
    return (f"reconciled: {notices} notices against {lines} placed messages in "
            f"{len(recs.trees)} peer trees, both directions")


def analyse(recs: Records, since: str, until: str) -> Tuple[str, List[str]]:
    placed = recs.placed
    for r in placed.values():
        if len({since <= t < until for t in r["all_ts"]}) > 1:
            raise Stop(f"{r['where']}: message_id {r['message_id']} has identical lines on both "
                       f"sides of a window edge ({', '.join(sorted(r['all_ts']))})")
    reconciled = reconcile(recs, since, until)
    window = sorted((r for r in placed.values() if since <= r["ts"] < until),
                    key=lambda r: (r["ts"], r["message_id"]))
    if not window:
        raise Stop(f"no peer_notice_placed in [{since}, {until})")
    lanes = {lane: {"tasks": [], "first": [], "deep": []} for lane in LANES}
    replies_per_parent: Dict[str, int] = {}
    for r in window:
        bucket = lanes[r["origin"]]
        if r["in_reply_to"] is None:
            bucket["tasks"].append(r["message_id"])
            continue
        parent = placed.get(r["in_reply_to"])
        if parent is None:
            raise Stop(f"{r['where']}: in_reply_to {r['in_reply_to']} is in no supplied log "
                       f"(depth unknown)")
        if (_canonical(r["from"]), _canonical(r["to"])) != (
                _canonical(parent["to"]), _canonical(parent["from"])):
            raise Stop(f"{r['where']}: reply {r['message_id']} does not run the reverse "
                       f"direction of its parent {parent['message_id']}")
        if parent["in_reply_to"] is None:
            bucket["first"].append(r["message_id"])
            replies_per_parent[parent["message_id"]] = (
                replies_per_parent.get(parent["message_id"], 0) + 1)
        else:
            bucket["deep"].append(f"{r['message_id']} (answers reply {parent['message_id']})")
    out = [f"window [{since}, {until}): {len(window)} peer_notice_placed",
           f"assumes: every hosted instance of every host is in the copies above; "
           f"{reconciled}"]
    for lane in LANES:
        b = lanes[lane]
        out.append(f"lane {lane}: tasks={len(b['tasks'])} first_level={len(b['first'])} "
                   f"depth2plus={len(b['deep'])}")
        for name, key in (("task", "tasks"), ("first_level", "first"), ("depth2plus", "deep")):
            for i in b[key]:
                out.append(f"  {lane} {name} {i}")
    for parent, n in sorted(replies_per_parent.items()):
        if n > 1:
            out.append(f"info: task {parent} has {n} first-level replies")
    first = sum(len(lanes[lane]["first"]) for lane in LANES)
    deep = sum(len(lanes[lane]["deep"]) for lane in LANES)
    if deep:
        return FAIL, out + [f"RESULT FAIL depth2plus={deep} first_level={first}"]
    if first < 1:
        return FAIL, out + ["RESULT FAIL first_level=0 depth2plus=0"]
    return PASS, out + [f"RESULT PASS first_level={first} depth2plus=0"]


def _host(value: str) -> Tuple[str, Path]:
    domain, sep, path = value.partition("=")
    if not sep or not path:
        raise Stop(f"--host {value!r}: expected <domain>=<state_dir copy>")
    if not domain.isascii() or not DOMAIN_RE.fullmatch(domain):
        raise Stop(f"--host {value!r}: {domain!r} is not a domain")
    return domain.lower(), Path(path)


def _tree(value: str) -> Tuple[str, str, Path]:
    key, sep, path = value.partition("=")
    host, slash, inst = key.partition("/")
    if not sep or not path or not slash:
        raise Stop(f"--peer-tree {value!r}: expected <domain>/<instance>=<peer tree copy>")
    if not host.isascii() or not DOMAIN_RE.fullmatch(host) or not NAME_RE.fullmatch(inst):
        raise Stop(f"--peer-tree {value!r}: bad domain or instance name")
    return host.lower(), inst, Path(path)


def _no_tree(value: str) -> Tuple[str, str]:
    host, slash, inst = value.partition("/")
    if (not slash or not host.isascii() or not DOMAIN_RE.fullmatch(host)
            or not NAME_RE.fullmatch(inst)):
        raise Stop(f"--no-peer-tree {value!r}: expected <domain>/<instance>")
    return host.lower(), inst


def _ascii(line: str) -> str:
    # Ids and paths come from the copied records: escape anything that could
    # start a second line or fail to encode, so the RESULT line is always
    # printed and stays the only one.
    return "".join(c if c.isascii() and c.isprintable()
                   else c.encode("unicode_escape").decode("ascii") for c in line)


def main(argv: Optional[List[str]] = None) -> int:
    recs = Records()     # filled as it reads, so a STOP still lists what was read
    try:
        p = _Parser(prog="check_reply_depth.py", add_help=False)
        p.add_argument("--since", required=True)
        p.add_argument("--until", required=True)
        p.add_argument("--host", action="append", required=True)
        p.add_argument("--peer-tree", action="append", required=True)
        p.add_argument("--no-peer-tree", action="append", default=[])
        a = p.parse_args(argv)
        for name in ("since", "until"):
            if not valid_ts(getattr(a, name)):
                raise Stop(f"--{name} {getattr(a, name)!r}: expected a valid "
                           f"YYYY-MM-DDTHH:MM:SSZ")
        if not a.since < a.until:
            raise Stop("--since must be before --until")
        load([_host(h) for h in a.host], [_tree(t) for t in a.peer_tree], recs,
             [_no_tree(t) for t in a.no_peer_tree])
        verdict, lines = analyse(recs, a.since, a.until)
    except Stop as e:
        verdict, lines = STOP, [f"RESULT STOP {e}"]
    except Exception as e:  # noqa: BLE001 -- anything unforeseen is STOP, never PASS
        verdict, lines = STOP, [f"RESULT STOP unexpected {type(e).__name__}: {e}"]
    for line in recs.read + lines:
        print(_ascii(line))
    return RC[verdict]


if __name__ == "__main__":
    sys.exit(main())
