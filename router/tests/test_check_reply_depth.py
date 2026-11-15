"""`tools/check_reply_depth.py`: over a run window, at least one first-level
peer reply and no reply to a reply, from copies of the routers' audit logs,
reconciled against copies of the peer notice trees.

WHERE EVERY FIXTURE'S SHAPE COMES FROM. No audit line and no notice here is
typed out by hand. Each is written by the router's real producer, in this
process, into a real `state_dir` and a real peer tree:

  * `origin: "local"` lines and their notices: `deliver.deliver_peer`,
    reached through `outbound.drain_instance` on a submitted request, as on
    a host;
  * `origin: "fleet"` lines and their notices: `deliver.deliver_signed_peer`,
    reached through the decided chain `test_peerbind._Chain` already builds
    (authorise, confirm, decision record, `peerbind.resume`);
  * `reset` lines: `audit.append` with `audit.EVENT_RESET`, the call
    `reset.py` makes.

A same-host test that needs a broken record takes a REAL line or notice and
changes one thing in it, and says which. The cross-host PARENT (and
grandparent) on the other host is DERIVED, not produced: the real fleet line
and notice with from/to swapped and their ids and recipient replaced,
several fields at once, as `CrossHostTests.t1_host` states. So a change to
the producer's shape reaches these tests; a hand-typed fixture would keep
passing against a format the router no longer writes.

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
import subprocess
import sys
import tempfile
from pathlib import Path

from router import audit, outbound
from router.tests import test_peerbind as tpb
from router.tests.helpers import RouterTestCase, read_json, result_path, write_request
from router.tests.peer_helpers import FLEET_DOMAIN, addr, make_peer_config

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "check_reply_depth.py"

_spec = importlib.util.spec_from_file_location("check_reply_depth", TOOL)
crd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crd)

SINCE, UNTIL = "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"


def argv_for(hosts, trees, since=SINCE, until=UNTIL):
    argv = ["--since", since, "--until", until]
    for domain, path in hosts:
        argv += ["--host", f"{domain}={path}"]
    for domain, inst, path in trees:
        argv += ["--peer-tree", f"{domain}/{inst}={path}"]
    return argv


def run(hosts=(), trees=(), since=SINCE, until=UNTIL, argv=None):
    if argv is None:
        argv = argv_for(hosts, trees, since, until)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = crd.main(argv)
    return rc, out.getvalue().splitlines()


def log_of(state_dir: Path, name: str) -> Path:
    return Path(state_dir) / name / "audit" / "log.jsonl"


def read_lines(path: Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def write_lines(path: Path, docs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(d, sort_keys=True) + "\n" for d in docs), encoding="utf-8")


def notice_file(tree: Path, notice_id: str) -> Path:
    return Path(tree) / "notices" / f"notice-{notice_id}.json"


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

    def tree(self, name):
        return self.cfg.instances[name].peer_root

    def hosts(self):
        return [(FLEET_DOMAIN, self.state_dir)]

    def trees(self, *names):
        return [(FLEET_DOMAIN, n, self.tree(n)) for n in (names or ("a", "b"))]

    def check(self, **kw):
        return run(self.hosts(), self.trees(), **kw)

    def _chain(self):
        task = self.send("a", "b")
        reply = self.send("b", "a", in_reply_to=task)
        return task, reply

    def _one_change(self, name, change):
        path = log_of(self.state_dir, name)
        docs = read_lines(path)
        change(docs)
        write_lines(path, docs)

    # -- the verdicts ------------------------------------------------------

    def test_task_and_one_reply_passes(self):
        task, reply = self._chain()
        lines = self.assertResult(self.check(), "PASS", "first_level=1", "depth2plus=0")
        self.assertIn(f"  local task {task}", lines)
        self.assertIn(f"  local first_level {reply}", lines)
        self.assertIn("lane local: tasks=1 first_level=1 depth2plus=0", lines)
        self.assertIn("lane fleet: tasks=0 first_level=0 depth2plus=0", lines)
        for inst in ("a", "b"):
            self.assertIn(f"read {FLEET_DOMAIN} {inst} lines=1 peer_notice_placed=1", lines)
            self.assertIn(f"tree {FLEET_DOMAIN} {inst} notices=1 leftovers=0", lines)
        self.assertTrue(any(x.startswith("assumes: ") and "reconciled: 2 notices against 2 "
                            "placed messages in 2 peer trees, both directions" in x
                            for x in lines), lines)

    def test_zero_replies_fails(self):
        self.send("a", "b")
        self.assertResult(self.check(), "FAIL", "first_level=0")

    def test_a_reply_to_a_reply_fails(self):
        task, first = self._chain()
        second = self.send("a", "b", in_reply_to=first)
        lines = self.assertResult(self.check(), "FAIL", "depth2plus=1", "first_level=1")
        self.assertIn(f"  local depth2plus {second} (answers reply {first})", lines)

    def test_two_replies_to_one_task_pass_with_a_note(self):
        task = self.send("a", "b")
        self.send("b", "a", in_reply_to=task)
        self.send("b", "a", in_reply_to=task)
        lines = self.assertResult(self.check(), "PASS", "first_level=2")
        self.assertIn(f"info: task {task} has 2 first-level replies", lines)

    def test_the_window_filters_children_not_parents(self):
        task, reply = self._chain()
        self._one_change("b", lambda docs: [d.update(ts="2001-01-01T00:00:00Z") for d in docs])
        lines = self.assertResult(self.check(since="2002-01-01T00:00:00Z"), "PASS")
        self.assertIn(f"  local first_level {reply}", lines)
        self.assertNotIn(f"  local task {task}", lines)

    def test_an_empty_window_stops(self):
        self.send("a", "b")
        self.assertResult(self.check(since="2099-01-01T00:00:00Z"), "STOP",
                          "no peer_notice_placed")

    # -- reconciliation: audit set against the notice trees ----------------

    def test_a_notice_without_its_audit_line_stops(self):
        # The lost-append case: the reply's notice survives, its line does not.
        self._chain()
        write_lines(log_of(self.state_dir, "a"), [])
        self.assertResult(self.check(), "STOP", "has no audit line", "undercount")

    def test_a_lost_depth2_line_cannot_pass(self):
        # The false PASS this reconciliation exists for: a depth-2 reply was
        # placed, its notice is visible, its audit line was lost.
        task, first = self._chain()
        self.send("a", "b", in_reply_to=first)
        self._one_change("b", lambda docs: docs.pop())
        self.assertResult(self.check(), "STOP", "has no audit line")

    def test_an_audit_line_without_its_notice_stops(self):
        task, reply = self._chain()
        notice_file(self.tree("a"), reply).unlink()
        self.assertResult(self.check(), "STOP", "no notice in", "overcount")

    def test_a_notice_that_disagrees_with_its_line_stops(self):
        task, reply = self._chain()
        path = notice_file(self.tree("a"), reply)
        doc = json.loads(path.read_text())
        doc["message"].pop("in_reply_to")
        path.write_text(json.dumps(doc))
        self.assertResult(self.check(), "STOP", "disagrees with its audit line")

    def test_an_instance_without_its_tree_stops(self):
        self._chain()
        self.assertResult(run(self.hosts(), self.trees("a")), "STOP", "no --peer-tree")

    def test_a_tree_for_an_unsupplied_host_stops(self):
        self._chain()
        trees = self.trees() + [("other.example", "c", self.tree("a"))]
        self.assertResult(run(self.hosts(), trees), "STOP", "has no --host")

    def test_a_tree_supplied_twice_stops(self):
        self._chain()
        self.assertResult(run(self.hosts(), self.trees("a", "b", "a")), "STOP", "supplied twice")

    def test_an_unknown_entry_in_notices_stops(self):
        self._chain()
        (self.tree("a") / "notices" / "stray.txt").write_text("x")
        self.assertResult(self.check(), "STOP", "not a notice, a sidecar or a write leftover")

    def test_a_write_leftover_is_counted_not_fatal(self):
        self._chain()
        (self.tree("a") / "notices" / ".notice-abc.json.tmp.123.0123456789abcdef").write_text("")
        lines = self.assertResult(self.check(), "PASS")
        self.assertIn(f"tree {FLEET_DOMAIN} a notices=1 leftovers=1", lines)

    def _reset_line(self, name):
        # The producer reset.py calls; it stamps the line with the clock.
        audit.append(self.state_dir, name, audit.EVENT_RESET, was_seen=True)

    def test_a_reset_in_the_window_stops(self):
        self._chain()
        self._reset_line("a")
        self.assertResult(self.check(), "STOP", "was reset in the window")

    def test_lines_before_a_reset_need_no_notice(self):
        task, reply = self._chain()
        notice_file(self.tree("a"), reply).unlink()          # what the reset emptied
        self._reset_line("a")
        self._one_change("a", lambda docs: [
            d.update(ts="2001-01-01T00:00:00Z" if d["event"] == "peer_notice_placed"
                     else "2001-06-01T00:00:00Z") for d in docs])
        # Reconciliation passes; only the task is left in the window.
        self.assertResult(self.check(since="2002-01-01T00:00:00Z"), "FAIL", "first_level=0")

    # -- malformed and incomplete records: each a REAL line, one change ----

    def test_an_unparseable_line_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        path.write_bytes(path.read_bytes() + b"{not json\n")
        self.assertResult(self.check(), "STOP", "not a UTF-8 JSON line")

    def test_a_truncated_copy_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        path.write_bytes(path.read_bytes()[:-1])
        self.assertResult(self.check(), "STOP", "does not end in a newline")

    def test_a_missing_in_reply_to_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].pop("in_reply_to"))
        self.assertResult(self.check(), "STOP", "in_reply_to missing")

    def test_a_shape_valid_but_impossible_ts_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        good = path.read_bytes()
        for bad in ("yesterday", "2026-02-30T12:00:00Z", "2026-99-99T99:99:99Z",
                    "2026-11-15T25:00:00Z", "2026-11-15T12:60:00Z", "2026-1-15T12:00:00Z"):
            with self.subTest(ts=bad):
                self._one_change("a", lambda docs: docs[0].update(ts=bad))
                self.assertResult(self.check(), "STOP", "not a valid UTC timestamp")
                path.write_bytes(good)
        self.assertResult(self.check(), "PASS")

    def test_an_impossible_window_bound_stops(self):
        self._chain()
        for since, until in (("2026-02-30T00:00:00Z", UNTIL), (SINCE, "2026-13-01T00:00:00Z"),
                             (SINCE, "2026-11-15T24:00:00Z")):
            with self.subTest(since=since, until=until):
                self.assertResult(self.check(since=since, until=until), "STOP",
                                  "expected a valid")

    def test_an_unknown_origin_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].update(origin="elsewhere"))
        self.assertResult(self.check(), "STOP", "origin 'elsewhere'")

    def test_a_missing_parent_stops(self):
        # The task's line AND its notice gone: reconciliation is satisfied,
        # so only the parent lookup can stop it.
        task, reply = self._chain()
        write_lines(log_of(self.state_dir, "b"), [])
        notice_file(self.tree("b"), task).unlink()
        self.assertResult(self.check(), "STOP", "in no supplied log")

    def test_a_reply_in_the_wrong_direction_stops(self):
        task, reply = self._chain()
        self._one_change("a", lambda docs: docs[0].update(**{"from": addr("c")}))
        path = notice_file(self.tree("a"), reply)       # the notice agrees with the line
        doc = json.loads(path.read_text())
        doc["message"]["from"] = addr("c")
        path.write_text(json.dumps(doc))
        self.assertResult(self.check(), "STOP", "reverse direction")

    def test_one_id_placed_twice_differently_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        docs = read_lines(path)
        write_lines(path, docs + [dict(docs[0], in_reply_to=None)])
        self.assertResult(self.check(), "STOP", "placed twice with different contents")

    def test_an_identical_retry_line_is_one_message(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        docs = read_lines(path)
        write_lines(path, docs + [dict(docs[0], ts="2050-01-01T00:00:00Z")])
        self.assertResult(self.check(), "PASS", "first_level=1")

    def test_an_identical_retry_across_a_window_edge_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        docs = read_lines(path)
        write_lines(path, [dict(docs[0], ts="2001-01-01T00:00:00Z")] + docs)
        self.assertResult(self.check(since="2002-01-01T00:00:00Z"), "STOP",
                          "both sides of a window edge")

    def test_a_line_logged_on_the_wrong_host_stops(self):
        self._chain()
        self._one_change("a", lambda docs: docs[0].update(to="a@other.example"))
        self.assertResult(self.check(), "STOP", "is not on host")

    def test_a_host_with_no_logs_stops(self):
        self._chain()
        empty = Path(tempfile.mkdtemp(dir=self.tmp))
        self.assertResult(run(self.hosts() + [("other.example", empty)], self.trees()), "STOP",
                          "no */audit/log.jsonl")

    def test_two_hosts_with_one_domain_stop(self):
        # Both directories real and readable, so only the domain rule can stop it.
        self._chain()
        self.assertResult(run(self.hosts() + [(FLEET_DOMAIN.upper(), self.state_dir)],
                              self.trees()), "STOP", "two --host entries name one domain")

    def test_a_symlinked_log_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        real = path.with_name("real.jsonl")
        path.rename(real)
        os.symlink(real.name, path)
        self.assertResult(self.check(), "STOP", "a symlink")

    def test_a_symlinked_notice_stops(self):
        task, reply = self._chain()
        path = notice_file(self.tree("a"), reply)
        real = path.with_name("real.json")
        path.rename(real)
        os.symlink(real.name, path)
        self.assertResult(self.check(), "STOP", "a symlink")

    def test_an_unreadable_log_stops(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        os.chmod(path, 0)
        try:
            if os.access(path, os.R_OK):
                self.skipTest("running as a user that can read mode-0 files")
            self.assertResult(self.check(), "STOP", "unreadable")
        finally:
            os.chmod(path, 0o600)

    def test_a_fifo_log_stops_and_does_not_hang(self):
        self._chain()
        path = log_of(self.state_dir, "a")
        path.unlink()
        os.mkfifo(path)
        try:
            p = subprocess.run([sys.executable, "-B", str(TOOL)]
                               + argv_for(self.hosts(), self.trees()),
                               capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("the tool blocked opening a FIFO log")
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("not a regular file", p.stdout.splitlines()[-1])

    def test_a_hostile_id_cannot_forge_a_result_line(self):
        task = self.send("a", "b")
        hostile = task + "\nRESULT PASS x"
        self._one_change("b", lambda docs: docs[0].update(message_id=hostile))
        path = notice_file(self.tree("b"), task)
        doc = json.loads(path.read_text())
        doc["message"]["id"] = hostile
        path.write_text(json.dumps(doc))
        rc, lines = self.check()
        self.assertEqual([x for x in lines if x.startswith("RESULT")], [lines[-1]])
        self.assertTrue(lines[-1].startswith("RESULT FAIL"), lines)

    def test_a_non_ascii_id_keeps_the_result_line_on_an_ascii_stdout(self):
        task = self.send("a", "b")
        odd = task + "é "
        self._one_change("b", lambda docs: docs[0].update(message_id=odd))
        path = notice_file(self.tree("b"), task)
        doc = json.loads(path.read_text())
        doc["message"]["id"] = odd
        path.write_text(json.dumps(doc))
        env = dict(os.environ, PYTHONIOENCODING="ascii")
        p = subprocess.run([sys.executable, "-B", str(TOOL)] + argv_for(self.hosts(), self.trees()),
                           capture_output=True, text=True, timeout=60, env=env)
        out = p.stdout.splitlines()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual([x for x in out if x.startswith("RESULT")], [out[-1]])
        self.assertTrue(out[-1].startswith("RESULT FAIL first_level=0"), out)
        self.assertIn(f"  local task {task}\\xe9\\u2028", out)

    def test_bad_arguments_stop(self):
        here = f"{FLEET_DOMAIN}={self.state_dir}"
        tree = f"{FLEET_DOMAIN}/a={self.tree('a')}"
        for argv, cause in (
                ([], "usage:"),
                (["--since", SINCE, "--until", UNTIL, "--host", here], "usage:"),
                (["--since", "x", "--until", UNTIL, "--host", here, "--peer-tree", tree],
                 "--since 'x'"),
                (["--since", UNTIL, "--until", SINCE, "--host", here, "--peer-tree", tree],
                 "before --until"),
                (["--since", SINCE, "--until", UNTIL, "--host", "nodomain", "--peer-tree", tree],
                 "expected <domain>="),
                (["--since", SINCE, "--until", UNTIL, "--host", here, "--peer-tree", "a=/x"],
                 "expected <domain>/<instance>="),
                (["--since", SINCE, "--until", UNTIL, "--host",
                  f"{FLEET_DOMAIN}=/nonexistent", "--peer-tree", tree], "not a directory")):
            with self.subTest(argv=argv):
                self.assertResult(run(argv=argv), "STOP", cause)

    def test_reads_nothing_it_was_not_given_and_writes_nothing(self):
        self._chain()

        def snap():
            return sorted((str(p), p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else b"")
                          for p in self.tmp.rglob("*") if not p.is_symlink())
        before = snap()
        self.assertResult(self.check(), "PASS")
        self.assertEqual(before, snap())


class CrossHostTests(_Verdicts, tpb._Chain):
    """The `fleet` lane. bob@FD's line and notice are written by
    `deliver_signed_peer` (test_peerbind's decided chain); the parent it
    answers lives on host T1 and is DERIVED from them (see the module
    docstring)."""

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

    def bob_tree(self):
        return self.cfg.instances["bob"].peer_root

    def derived(self, line, *, message_id, notice_id, frm, to, to_instance, in_reply_to):
        """The real line and notice, with these fields replaced."""
        doc = dict(line, **{"from": frm, "to": to, "message_id": message_id,
                            "notice_id": notice_id, "to_instance": to_instance,
                            "in_reply_to": in_reply_to})
        notice = json.loads(notice_file(self.bob_tree(), line["notice_id"]).read_text())
        notice["notice_id"] = notice_id
        notice["message"] = dict(notice["message"], id=message_id, **{"from": frm})
        notice["message"].pop("in_reply_to", None)
        if in_reply_to is not None:
            notice["message"]["in_reply_to"] = in_reply_to
        return doc, notice

    def t1_host(self, line, grandparent=None):
        """Host T1's state_dir copy and planner's peer tree, holding the
        PARENT: bob -> planner, placed on T1. With `grandparent`, the parent
        is itself a reply to it, and the grandparent (planner -> bob, the real
        line's own direction) is placed on FD, in bob's log and tree."""
        t1 = Path(tempfile.mkdtemp(dir=self.tmp))
        tree = Path(tempfile.mkdtemp(dir=self.tmp))
        (tree / "notices").mkdir()
        parent, pnotice = self.derived(line, message_id=self.PARENT, notice_id="f" * 32,
                                       frm=line["to"], to=line["from"], to_instance="planner",
                                       in_reply_to=grandparent)
        write_lines(log_of(t1, "planner"), [parent])
        notice_file(tree, "f" * 32).write_text(json.dumps(pnotice))
        if grandparent is not None:
            gp, gnotice = self.derived(line, message_id=grandparent, notice_id="e" * 32,
                                       frm=line["from"], to=line["to"], to_instance="bob",
                                       in_reply_to=None)
            fd_log = log_of(self.state_dir, "bob")
            write_lines(fd_log, read_lines(fd_log) + [gp])
            notice_file(self.bob_tree(), "e" * 32).write_text(json.dumps(gnotice))
        return t1, tree

    def check(self, t1=None, tree=None):
        hosts = [(tpb.FD, self.state_dir)] + ([(tpb.T1, t1)] if t1 else [])
        trees = [(tpb.FD, "bob", self.bob_tree())] + ([(tpb.T1, "planner", tree)] if tree else [])
        return run(hosts, trees)

    def test_a_cross_host_first_level_reply_passes(self):
        line = self.place_reply()
        lines = self.assertResult(self.check(*self.t1_host(line)), "PASS", "first_level=1")
        self.assertIn(f"  fleet first_level {line['message_id']}", lines)
        self.assertIn(f"  fleet task {self.PARENT}", lines)

    def test_a_cross_host_reply_to_a_reply_fails(self):
        line = self.place_reply()
        t1, tree = self.t1_host(line, grandparent="gp0123456789abcdefghijk")
        lines = self.assertResult(self.check(t1, tree), "FAIL", "depth2plus=1")
        self.assertIn(f"  fleet depth2plus {line['message_id']} (answers reply {self.PARENT})",
                      lines)

    def test_the_other_hosts_logs_are_required(self):
        line = self.place_reply()
        self.t1_host(line)
        self.assertResult(self.check(), "STOP", "whose logs were not supplied")

    def test_the_real_fleet_line_and_notice_carry_what_the_tool_reads(self):
        line = self.place_reply()
        for k in crd.IDENTITY + ("message_id", "ts", "event"):
            self.assertIn(k, line)
        notice = json.loads(notice_file(self.bob_tree(), line["notice_id"]).read_text())
        self.assertEqual((notice["notice_id"], notice["kind"], notice["message"]["id"],
                          notice["message"]["in_reply_to"]),
                         (line["notice_id"], "peer", line["message_id"], self.PARENT))


if __name__ == "__main__":  # pragma: no cover
    import unittest
    unittest.main()
