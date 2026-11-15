#!/usr/bin/env python3
"""Reply depth over a run window: every peer-lane reply placed in the window
is a FIRST-LEVEL reply (it answers a fresh task), never a reply to a reply.

An offline analyser of COPIED router records. It never opens a live
`state_dir`, writes nothing, sends nothing, and imports nothing from the
router package: it reads the files it is given and prints.

THE SOURCE: the router's audit log, `state_dir/<state key>/audit/log.jsonl`
(`router/audit.py`, `log_path`), one per hosted instance, from EVERY host in
the run. Its `peer_notice_placed` event is written by both placement paths,
and is the only record that carries `in_reply_to`:

  * same host, `origin: "local"`: `router/deliver.py`, `deliver_peer`;
  * cross host, `origin: "fleet"`: `router/deliver.py`, `deliver_signed_peer`.

The ledgers cannot answer depth: a binding record has no `in_reply_to`
(`binding.record_delivery`), and the peer ledger's members are closed
(`peerlane.LEDGER_MEMBERS`) without one.

Why the audit log is COMPLETE for a window: the placement commit order is
spool, ledger, audit, notice LAST (`deliver._commit`), so every notice an
agent could see has its line, and a crash leaves at worst an extra line
(deduplicated here, below). The log is append-only and `reset` skips it
(`router/audit.py` module docstring), and it lives under `state_dir`, which
no agent uid reaches. A host records only what it PLACED, so a cross-host
chain spans two hosts' logs: hence every host, and the domain checks below.

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
        --host <host domain>=<copy of that host's state_dir> [--host ...]

Each `--host` names one host by the domain its agents' addresses carry and a
directory holding a copy of its `state_dir` (only `*/audit/log.jsonl` is
read). The window is `[since, until)` on the line's `ts`. The router has no
notion of a run id: the operator maps a run to its window.

OUTPUT. Per lane (`local`, `fleet`): tasks, first-level replies and depth-2+
replies in the window, each with its message ids. Then EXACTLY ONE line
beginning `RESULT `, and it is the last line:

  * `RESULT PASS` -- first-level >= 1 (both lanes together) and depth-2+ = 0;
  * `RESULT FAIL` -- the records are sound and the assertion does not hold;
  * `RESULT STOP` -- the records cannot support a verdict.

The exit status mirrors it (0, 1, 2), but the RESULT line is the verdict:
rc 0 without `RESULT PASS` is not a pass.

STOP, never PASS, on: a bad argument; a host directory with no audit log; a
symlink anywhere on a log's path; an unreadable log; a log not ending in a
newline (a truncated copy); a line that is not UTF-8 JSON with a string
`event` and a well-formed `ts`; a `peer_notice_placed` line missing a field
or with an unknown `origin`; one `message_id` placed twice with different
contents; a `to` outside the host it was logged on; an address on a host
that was not supplied; two `--host` with one domain; a reply whose parent is
in no supplied log, or does not run the reverse direction; an empty window.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

EVENT = "peer_notice_placed"
LANES = ("local", "fleet")
TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
DOMAIN_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
#: The members a placed message is compared on when it appears twice.
IDENTITY = ("notice_id", "from", "to", "in_reply_to", "origin", "tree")

PASS, FAIL, STOP = "PASS", "FAIL", "STOP"
RC = {PASS: 0, FAIL: 1, STOP: 2}


class Stop(Exception):
    """The records cannot support a verdict."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Stop(f"usage: {message}")


def _domain(address: str, where: str) -> str:
    if not isinstance(address, str) or address.count("@") != 1:
        raise Stop(f"{where}: {address!r} is not an address")
    local, domain = address.split("@")
    if not local or not domain.isascii() or not DOMAIN_RE.fullmatch(domain):
        raise Stop(f"{where}: {address!r} is not an address")
    return domain.lower()


def _canonical(address: str) -> str:
    local, domain = address.split("@")
    return f"{local}@{domain.lower()}"


def _read_log(path: Path, root: Path) -> bytes:
    rel = path.relative_to(root)
    p = root
    for part in rel.parts:
        p = p / part
        if p.is_symlink():
            raise Stop(f"{p}: a symlink, refused")
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
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
        if not isinstance(doc.get("ts"), str) or not TS_RE.fullmatch(doc["ts"]):
            raise Stop(f"{where}: ts {doc.get('ts')!r} is not a UTC timestamp")
        out.append((n, doc))
    return out


def _placed(doc: dict, where: str, host: str) -> dict:
    for k in ("message_id", "notice_id"):
        if not isinstance(doc.get(k), str) or not doc[k]:
            raise Stop(f"{where}: {k} missing or empty")
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
            "ts": doc["ts"], "where": where}


def load(hosts: List[Tuple[str, Path]]) -> Dict[str, dict]:
    """Every placed message in every supplied log, keyed by `message_id`."""
    domains = [d for d, _ in hosts]
    if len(set(domains)) != len(domains):
        raise Stop("two --host entries name one domain: hosts must be told apart by domain")
    placed: Dict[str, dict] = {}
    for host, root in hosts:
        if root.is_symlink() or not root.is_dir():
            raise Stop(f"{root}: not a directory")
        logs = sorted(root.glob("*/audit/log.jsonl"))
        if not logs:
            raise Stop(f"{root}: no */audit/log.jsonl for host {host!r}")
        for path in logs:
            for n, doc in _lines(path, _read_log(path, root)):
                if doc["event"] != EVENT:
                    continue
                rec = _placed(doc, f"{path}:{n}", host)
                prior = placed.get(rec["message_id"])
                if prior is None:
                    placed[rec["message_id"]] = rec
                elif any(prior[k] != rec[k] for k in IDENTITY):
                    raise Stop(f"message_id {rec['message_id']} placed twice with different "
                               f"contents ({prior['where']}, {rec['where']})")
    supplied = set(domains)
    for rec in placed.values():
        for k in ("from", "to"):
            d = _domain(rec[k], rec["where"])
            if d not in supplied:
                raise Stop(f"{rec['where']}: {k} {rec[k]!r} is on host {d!r}, "
                           f"whose logs were not supplied")
    return placed


def analyse(placed: Dict[str, dict], since: str, until: str) -> Tuple[str, List[str]]:
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
    out = [f"window [{since}, {until}): {len(window)} peer_notice_placed"]
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
        return FAIL, out + [f"RESULT FAIL first_level=0 depth2plus=0"]
    return PASS, out + [f"RESULT PASS first_level={first} depth2plus=0"]


def _host(value: str) -> Tuple[str, Path]:
    domain, sep, path = value.partition("=")
    if not sep or not path:
        raise Stop(f"--host {value!r}: expected <domain>=<state_dir copy>")
    if not domain.isascii() or not DOMAIN_RE.fullmatch(domain):
        raise Stop(f"--host {value!r}: {domain!r} is not a domain")
    return domain.lower(), Path(path)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        p = _Parser(prog="check_reply_depth.py", add_help=False)
        p.add_argument("--since", required=True)
        p.add_argument("--until", required=True)
        p.add_argument("--host", action="append", required=True)
        a = p.parse_args(argv)
        for name in ("since", "until"):
            if not TS_RE.fullmatch(getattr(a, name)):
                raise Stop(f"--{name} {getattr(a, name)!r}: expected YYYY-MM-DDTHH:MM:SSZ")
        if not a.since < a.until:
            raise Stop("--since must be before --until")
        verdict, lines = analyse(load([_host(h) for h in a.host]), a.since, a.until)
    except Stop as e:
        verdict, lines = STOP, [f"RESULT STOP {e}"]
    except Exception as e:  # noqa: BLE001 -- anything unforeseen is STOP, never PASS
        verdict, lines = STOP, [f"RESULT STOP unexpected {type(e).__name__}: {e}"]
    for line in lines:
        # Ids and paths come from the copied records: escape anything that
        # could start a second line, so the RESULT line stays the only one.
        print("".join(c if c.isprintable() else repr(c)[1:-1] for c in line))
    return RC[verdict]


if __name__ == "__main__":
    sys.exit(main())
