"""`tools/check_reply_depth.py`: over a run window, at least one first-level
peer reply and no reply to a reply, from copies of the routers' audit logs.

WHERE EVERY FIXTURE'S SHAPE COMES FROM. No audit line here is typed out by
hand. Each one is written by the router's real producer, in this process,
into a real `state_dir`:

  * `origin: "local"` lines: `deliver.deliver_peer`, reached through
    `outbound.drain_instance` on a submitted request, exactly as on a host;
  * `origin: "fleet"` lines: `deliver.deliver_signed_peer`, reached through
    the decided chain `test_peerbind._Chain` already builds (authorise,
    confirm, decision record, `peerbind.resume`).

A test that needs a broken or foreign record takes a REAL line and changes
one thing in it, and says which. So a change to the producer's line shape
reaches these tests; a hand-typed fixture would keep passing against a
format the router no longer writes.

The verdict is asserted on the RESULT line, which only `analyse`/`main`
write, and every STOP test also asserts its own cause in that line, so a
STOP for a different reason cannot pass it.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
from pathlib import Path

from router import outbound
from router.tests import test_peerbind as tpb
from router.tests.helpers import RouterTestCase, read_json, result_path, write_request
from router.tests.peer_helpers import FLEET_DOMAIN, addr, make_peer_config

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "check_reply_depth.py"

_spec = importlib.util.spec_from_file_location("check_reply_depth", TOOL)
crd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crd)

SINCE, UNTIL = "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"


def run(*hosts, since=SINCE, until=UNTIL, argv=None):
    if argv is None:
        argv = ["--since", since, "--until", until]
        for domain, path in hosts:
            argv += ["--host", f"{domain}={path}"]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = crd.main(argv)
    lines = out.getvalue().splitlines()
    return rc, lines


def log_of(state_dir: Path, name: str) -> Path:
    return Path(state_dir) / name / "audit" / "log.jsonl"


def read_lines(path: Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def write_lines(path: Path, docs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(d, sort_keys=True) + "\n" for d in docs), encoding="utf-8")


class _Verdicts:
    def assertResult(self, got, verdict, *needles):
        rc, lines = got
        self.assertTrue(lines, "no output at all")
        self.assertEqual([x for x in lines if x.startswith("RESULT")], [lines[-1]],
                         "exactly one RESULT line, and it is the last")
        self.assertTrue(lines[-1].startswith(f"RESULT {verdict}"), lines)
        for n in needles:
            self.assertIn(n, lines[-1])
        self.assertEqual(rc, {"PASS": 0, "FAIL": 1, "STOP": 2}[verdict])
        return lines


class SameHostTests(_Verdicts, RouterTestCase):
    """The `local` lane, from `outbound.drain_instance` -> `deliver_peer`."""

    def setUp(self):
        super().setUp()
        # Edges both ways: a reply to a reply is then permitted by the router
        # (outbound._drain_peer_reply), so the depth-2 case is reachable.
        self.cfg = make_peer_config(self, {"a": {"peer_senders": ["b"]},
                                           "b": {"peer_senders": ["a"]}})
        self.n = 0

    def send(self, sender, recipient, in_reply_to=None):
        self.n += 1
        req = f"{self.n:08d}"
        kw = {"in_reply_to": in_reply_to} if in_reply_to else {}
        write_request(self.cfg, sender, req, to=[addr(recipient)], body_text="x", **kw)
        outbound.drain_instance(self.cfg, sender)
        result = read_json(result_path(self.cfg, sender, req))
        self.assertEqual(result["reason_code"], "peer_routed", result)
        return result["message_id"]

    def host(self):
        return (FLEET_DOMAIN, self.state_dir)

    def test_task_and_one_reply_passes(self):
        task = self.send("a", "b")
        reply = self.send("b", "a", in_reply_to=task)
        lines = self.assertResult(run(self.host()), "PASS", "first_level=1", "depth2plus=0")
        self.assertIn(f"  local task {task}", lines)
        self.assertIn(f"  local first_level {reply}", lines)
        self.assertIn("lane local: tasks=1 first_level=1 depth2plus=0", lines)
        self.assertIn("lane fleet: tasks=0 first_level=0 depth2plus=0", lines)

    def test_zero_replies_fails(self):
        self.send("a", "b")
        self.assertResult(run(self.host()), "FAIL", "first_level=0")

    def test_a_reply_to_a_reply_fails(self):
        task = self.send("a", "b")
        first = self.send("b", "a", in_reply_to=task)
        second = self.send("a", "b", in_reply_to=first)
        lines = self.assertResult(run(self.host()), "FAIL", "depth2plus=1", "first_level=1")
        self.assertIn(f"  local depth2plus {second} (answers reply {first})", lines)

    def test_two_replies_to_one_task_pass_with_a_note(self):
        task = self.send("a", "b")
        self.send("b", "a", in_reply_to=task)
        self.send("b", "a", in_reply_to=task)
        lines = self.assertResult(run(self.host()), "PASS", "first_level=2")
        self.assertIn(f"info: task {task} has 2 first-level replies", lines)

    def test_the_window_filters_children_not_parents(self):
        task = self.send("a", "b")
        reply = self.send("b", "a", in_reply_to=task)
        path = log_of(self.state_dir, "b")
        docs = read_lines(path)                       # the task, placed in b's tree
        for d in docs:
            d["ts"] = "2001-01-01T00:00:00Z"          # moved before the window
        write_lines(path, docs)
        lines = self.assertResult(run(self.host(), since="2002-01-01T00:00:00Z"), "PASS")
        self.assertIn(f"  local first_level {reply}", lines)
        self.assertNotIn(f"  local task {task}", lines)

    def test_an_empty_window_stops(self):
        self.send("a", "b")
        self.assertResult(run(self.host(), since="2099-01-01T00:00:00Z"), "STOP",
                          "no peer_notice_placed")

    # -- malformed and incomplete records: each a REAL line, one change ----

    def _one_change(self, name, change):
        path = log_of(self.state_dir, name)
        docs = read_lines(path)
        change(docs)
        write_lines(path, docs)

    def _chain(self):
        task = self.send("a", "b")
        reply = self.send("b", "a", in_reply_to=task)
        return task, reply

    def test_an_unparseable_line_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        path.write_bytes(path.read_bytes() + b"{not json\n")
        self.assertResult(run(self.host()), "STOP", "not a UTF-8 JSON line")

    def test_a_truncated_copy_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        path.write_bytes(path.read_bytes()[:-1])
        self.assertResult(run(self.host()), "STOP", "does not end in a newline")

    def test_a_missing_in_reply_to_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].pop("in_reply_to"))
        self.assertResult(run(self.host()), "STOP", "in_reply_to missing")

    def test_a_bad_ts_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].update(ts="yesterday"))
        self.assertResult(run(self.host()), "STOP", "not a UTC timestamp")

    def test_an_unknown_origin_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].update(origin="elsewhere"))
        self.assertResult(run(self.host()), "STOP", "origin 'elsewhere'")

    def test_a_missing_parent_stops(self):
        self._chain()
        log_of(self.state_dir, "b").unlink()          # the task's line, gone
        self.assertResult(run(self.host()), "STOP", "in no supplied log")

    def test_a_reply_in_the_wrong_direction_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].update(**{"from": addr("c")}))
        self.assertResult(run(self.host()), "STOP", "reverse direction")

    def test_one_id_placed_twice_differently_stops(self):
        task, reply = self._chain()
        path = log_of(self.state_dir, "a")
        docs = read_lines(path)
        twin = dict(docs[0], in_reply_to=None)
        write_lines(path, docs + [twin])
        self.assertResult(run(self.host()), "STOP", "placed twice with different contents")

    def test_an_identical_retry_line_is_one_message(self):
        task, reply = self._chain()
        path = log_of(self.state_dir, "a")
        docs = read_lines(path)
        write_lines(path, docs + [dict(docs[0], ts="2050-01-01T00:00:00Z")])
        self.assertResult(run(self.host()), "PASS", "first_level=1")

    def test_a_line_logged_on_the_wrong_host_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].update(to="a@other.example"))
        self.assertResult(run(self.host()), "STOP", "is not on host")

    def test_a_host_with_no_logs_stops(self):
        self._chain()
        empty = Path(tempfile.mkdtemp(dir=self.tmp))
        self.assertResult(run(self.host(), ("other.example", empty)), "STOP", "no */audit/log.jsonl")

    def test_a_symlinked_log_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        real = path.with_name("real.jsonl")
        path.rename(real)
        os.symlink(real.name, path)
        self.assertResult(run(self.host()), "STOP", "a symlink")

    def test_an_unreadable_log_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        os.chmod(path, 0)
        try:
            if os.access(path, os.R_OK):
                self.skipTest("running as a user that can read mode-0 files")
            self.assertResult(run(self.host()), "STOP", "unreadable")
        finally:
            os.chmod(path, 0o600)

    def test_a_hostile_id_cannot_forge_a_result_line(self):
        task = self.send("a", "b")
        self._one_change("b", lambda docs: docs[0].update(message_id=task + "\nRESULT PASS x"))
        rc, lines = run(self.host())
        self.assertEqual([x for x in lines if x.startswith("RESULT")], [lines[-1]])
        self.assertTrue(lines[-1].startswith("RESULT FAIL"), lines)

    def test_bad_arguments_stop(self):
        here = f"{FLEET_DOMAIN}={self.state_dir}"
        for argv, cause in (
                ([], "usage:"),
                (["--since", SINCE, "--until", UNTIL], "usage:"),
                (["--since", "x", "--until", UNTIL, "--host", here], "--since 'x'"),
                (["--since", UNTIL, "--until", SINCE, "--host", here], "before --until"),
                (["--since", SINCE, "--until", UNTIL, "--host", "nodomain"], "expected <domain>="),
                (["--since", SINCE, "--until", UNTIL, "--host", f"{FLEET_DOMAIN}=/nonexistent"],
                 "not a directory")):
            with self.subTest(argv=argv):
                self.assertResult(run(argv=argv), "STOP", cause)

    def test_two_hosts_with_one_domain_stop(self):
        # Both directories real and readable, so only the domain rule can stop it.
        self._chain()
        self.assertResult(run(self.host(), (FLEET_DOMAIN.upper(), self.state_dir)), "STOP",
                          "two --host entries name one domain")

    def test_reads_nothing_it_was_not_given_and_writes_nothing(self):
        self._chain()
        before = sorted((str(p), p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else b"")
                        for p in self.state_dir.rglob("*"))
        self.assertResult(run(self.host()), "PASS")
        after = sorted((str(p), p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else b"")
                       for p in self.state_dir.rglob("*"))
        self.assertEqual(before, after)


class CrossHostTests(_Verdicts, tpb._Chain):
    """The `fleet` lane. bob@FD's line is written by `deliver_signed_peer`
    (test_peerbind's decided chain); the parent it answers lives on host T1,
    and is the same producer's line for the opposite direction: a real line
    from this chain with its from/to swapped and its ids replaced, the one
    change the test names."""

    PARENT = "orig0123456789abcdefghij"

    def place_reply(self):
        auth, snap = self.fresh(in_reply_to=self.PARENT)
        _rec, rcp = self.decide(auth)
        d = tpb.peerbind.resume(rcp, snap, state_dir=self.state_dir)
        tpb.deliver.deliver_signed_peer(self.cfg, self.state_dir, d,
                                        in_reply_to_resolved=self.PARENT)
        [line] = [x for x in read_lines(log_of(self.state_dir, "bob"))
                  if x["event"] == "peer_notice_placed"]
        self.assertEqual((line["origin"], line["in_reply_to"]), ("fleet", self.PARENT))
        return line

    def t1_host(self, line, grandparent=None):
        """Host T1's state_dir copy holding the PARENT: bob -> planner,
        placed on T1, i.e. the real line with from/to swapped and its ids
        replaced. With `grandparent`, the parent is itself a reply to it, and
        the grandparent (planner -> bob, the real line's own direction, with
        its ids replaced) is placed on FD, in bob's log."""
        t1 = Path(tempfile.mkdtemp(dir=self.tmp))
        parent = dict(line, **{"from": line["to"], "to": line["from"],
                               "message_id": self.PARENT, "notice_id": "f" * 32,
                               "to_instance": "planner", "in_reply_to": grandparent})
        write_lines(log_of(t1, "planner"), [parent])
        if grandparent is not None:
            fd_log = log_of(self.state_dir, "bob")
            gp = dict(line, message_id=grandparent, notice_id="e" * 32, in_reply_to=None)
            write_lines(fd_log, read_lines(fd_log) + [gp])
        return t1

    def test_a_cross_host_first_level_reply_passes(self):
        line = self.place_reply()
        t1 = self.t1_host(line)
        lines = self.assertResult(run((tpb.FD, self.state_dir), (tpb.T1, t1)), "PASS",
                                  "first_level=1")
        self.assertIn(f"  fleet first_level {line['message_id']}", lines)
        self.assertIn(f"  fleet task {self.PARENT}", lines)

    def test_a_cross_host_reply_to_a_reply_fails(self):
        line = self.place_reply()
        t1 = self.t1_host(line, grandparent="gp0123456789abcdefghijk")
        lines = self.assertResult(run((tpb.FD, self.state_dir), (tpb.T1, t1)), "FAIL",
                                  "depth2plus=1")
        self.assertIn(f"  fleet depth2plus {line['message_id']} (answers reply {self.PARENT})",
                      lines)

    def test_the_other_hosts_logs_are_required(self):
        line = self.place_reply()
        self.t1_host(line)
        self.assertResult(run((tpb.FD, self.state_dir)), "STOP", "whose logs were not supplied")

    def test_the_real_fleet_line_has_every_member_the_tool_reads(self):
        line = self.place_reply()
        for k in crd.IDENTITY + ("message_id", "ts", "event"):
            self.assertIn(k, line)


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
