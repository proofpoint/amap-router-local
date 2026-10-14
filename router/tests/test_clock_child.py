"""The clock's child-process witness: an installed source is what the driven
production paths observe.

A child interpreter (`-B`, an empty HOME, TMPDIR and cwd) installs a strict
`clock.Stepper` and then, IN THAT SAME interpreter, runs
`router/tests/clock_child_flows.py`: `router once` and `router status` through
the CLI's `main`, a service poll that writes `status.json`, a peer send whose
exposure comes from a file time set with `os.utime`, one ingress pump, and the
peer-store verbs. An install does not survive `exec`, so nothing here launches
a further process.

Every timestamp those operations newly wrote must be one the Stepper emitted
(an operator's B is data, and so is H after a bound raises it to B), the
values must not go backwards from one operation to the next, nor from one
write to the next inside an operation (an fsync-ordered trace), and at least
two must be distinct, which a cached read would collapse. A companion run with no
source writes none in the Stepper's year. And the lifecycle: `clock.reset()`
takes the source away, while `hoplink.reset_process_state()`, a modelled
restart, keeps it.

That the installed source is the ONLY time the package reads is
`test_one_clock.py`'s claim; this one proves the source is what those reads
return."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

INSTALL = (
    "from datetime import datetime, timezone\n"
    "from router import clock\n"
    "clock.install(clock.Stepper(datetime(2001, 2, 3, 4, 5, 6, tzinfo=timezone.utc)),"
    " strict=True)\n")
RUN_FLOWS = (
    "from router.tests import clock_child_flows as f\n"
    "raise SystemExit(f.main())\n")

#: Members every installed run must show at least once, by member path.
REQUIRED = {"ts", "result/ts", "date", "sender_exposure/window_end", "last_poll_ts",
            "started_ts", "first_seen_ts", "received_at", "state_ts", "H",
            "bound_b/recorded_at"}


def run_child(script: str, out: Path = None):
    with tempfile.TemporaryDirectory() as empty:
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "AMAP_SPEC_REPO")}
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(REPO), HOME=empty,
                   TMPDIR=empty)
        if out is not None:
            env["CLOCK_W2_OUT"] = str(out)
        return subprocess.run([sys.executable, "-B", "-c", script], cwd=empty, env=env,
                              capture_output=True, text=True, timeout=300)


class InstalledSourceTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name) / "w2.json"
        cls.proc = run_child(INSTALL + RUN_FLOWS, out)
        cls.doc = json.loads(out.read_text()) if out.exists() else None

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.assertIsNotNone(self.doc, self.proc.stderr[-4000:])
        self.assertTrue(self.doc["ok"], self.proc.stderr[-4000:])

    def ops(self):
        return [r for r in self.doc["records"] if "values" in r]

    def data(self):
        return {v for r in self.doc["records"] for v in r.get("data", ())}

    def test_every_written_time_is_one_the_source_emitted(self):
        emitted, data = set(self.doc["emitted"]), self.data()
        seen = [v for r in self.ops() for v in r["values"]]
        self.assertGreater(len(seen), 10, "the flows wrote almost nothing: not observing")
        bad = [v for v in seen if v[2] not in emitted and v[2] not in data]
        self.assertEqual(bad, [], "a written time the installed source never emitted")

    def test_each_kind_of_time_is_present(self):
        members = {v[1] for r in self.ops() for v in r["values"]}
        tails = {m for m in members} | {m.split("/", 1)[1] for m in members if "/" in m}
        self.assertEqual(REQUIRED - tails, set(), "a driven path wrote no time of this kind")

    def test_times_never_go_backwards_and_more_than_one_is_seen(self):
        data = self.data()
        flows = {}
        for r in self.ops():
            flows.setdefault(r["flow"], []).append(r)
        distinct = set()
        for flow, ops in flows.items():
            high = ""
            for r in sorted(ops, key=lambda r: r["op"]):
                vals = [v[2] for v in r["values"] if v[2] not in data]
                distinct.update(vals)
                if vals:
                    with self.subTest(flow=flow, op=r["label"]):
                        self.assertGreaterEqual(min(vals), high, "an earlier time written later")
                    high = max(high, max(vals))
        self.assertGreaterEqual(len(distinct), 2, "one value everywhere: a cached read")

    def test_writes_within_an_operation_never_go_backwards(self):
        """In the order writes became visible, inside each operation, no
        stamp is earlier than the latest stamp of any earlier write, except
        a declared reuse site (`backwards`, `DECLARED_REUSE`): a
        value read early and written after a later one shows here, where
        the operation-level check cannot see it."""
        emitted, data = self.doc["emitted"], self.data()
        events, log_high = 0, {}
        for r in sorted(self.ops(), key=lambda r: (r["flow"], r["op"])):
            bad = backwards(r["trace"], set(emitted) - data, set(emitted[:r["pre"]]), log_high,
                            op=(r["flow"], r["label"]))
            events += sum(1 for e in r["trace"] if e[1])
            with self.subTest(flow=r["flow"], op=r["label"]):
                self.assertEqual(bad, [], "a write stamped a time earlier than an earlier write")
        self.assertGreater(events, 10, "the write trace saw almost nothing: not tracing")

    def test_every_declared_site_is_used_by_the_real_flows(self):
        """A declared site that no real write matches is a stale exemption."""
        doc, used = self.doc, set()
        for r in doc["records"]:
            for _kind, stamps, path in r.get("trace", ()):
                for m, _v in stamps:
                    for site in DECLARED_REUSE:
                        flow, label, pattern, member, _why = site
                        import re
                        if (flow, label) == (r["flow"], r["label"]) and member == m \
                                and re.search(pattern, path):
                            used.add(site)
        self.assertEqual(set(DECLARED_REUSE) - used, set())

    def test_the_exposure_follows_the_file_time_set_from_the_installed_clock(self):
        [rec] = [r for r in self.doc["records"] if "exposure" in r]
        self.assertIs(rec["exposure"]["external_mail_delivered"], True)
        self.assertEqual(rec["exposure"]["last_external_delivery_ts"], rec["written"])


#: The declared reuse sites: where production DELIBERATELY writes one
#: reading after a fresher stamp of the same operation. Each is
#: (flow, operation, path pattern, member, reason). A repeat of an earlier
#: reading is exempt from the high-water rule only where it matches one.
DECLARED_REUSE = (
    ("ingress", "pump", r"/inbox/notices/notice-[0-9a-f]{32}\.json$", "ts",
     "the pump reads Pump.now once per pass; it is the placed notice's time"),
    ("ingress", "pump", r"/delivered/notice-[0-9a-f]{32}\.json$", "ts",
     "the same Pump.now on the notice's delivered-ledger record"),
    ("ingress", "pump", r"/delivered/notice-[0-9a-f]{32}\.json$", "received_at",
     "the same Pump.now as the ledger record's receipt time"),
    ("peer_send", "drain", r"/peer/notices/notice-[0-9a-f]{32}\.json$", "ts",
     "deliver's one placement time; the notice, the commit sentinel, is "
     "written last, after the audit line took a fresh stamp"),
    ("peer_send", "drain", r"/peer/notices/notice-[0-9a-f]{32}\.json$",
     "message/sender_exposure/window_end",
     "the exposure window ends at that same placement time"),
)


def _declared(op, path, member) -> bool:
    import re
    return any((flow, label) == op and re.search(pattern, path) and m == member
               for flow, label, pattern, m, _why in DECLARED_REUSE)


def backwards(trace, valid, before, log_high=None, op=None):
    """The stamps in `trace` that step back. `trace` is `[kind, stamps,
    path]` per write, in the order writes became visible; each stamp is
    `[member, value]`; `op` is the operation's `(flow, label)`.

    Only values the source emitted count (`valid`). A document value the
    source emitted before the operation began (`before`) was carried from
    earlier state, not stamped now; an appended line's values always count.

    Rule 1, across the operation: a stamp is backwards when it is earlier
    than the HIGHEST stamp of any earlier write in the operation. The one
    exception is a declared reuse site (`DECLARED_REUSE`): there, a value an
    earlier write of the operation already stamped is the same reading
    written again, by design. Anywhere else, a repeat of an earlier value
    after a later stamp is backwards, and so is a value read early, held
    back, and written after a later one.

    Rule 2, on one append-only path: a line stamped earlier than an earlier
    line of that path is backwards, with no exception. Pass the same
    `log_high` to successive operations and it holds over the log's life."""
    bad, high, stamped = [], None, set()
    log_high = {} if log_high is None else log_high
    for kind, stamps, path in trace:
        pairs = [(m, v) for m, v in stamps if v in valid and (kind == "jsonl" or v not in before)]
        vals = [v for _m, v in pairs]
        if high is not None:
            bad += [v for m, v in pairs if v < high
                    and not (v in stamped and _declared(op, path, m))]
        if kind == "jsonl":
            last = log_high.get(path)
            bad += [v for v in vals if last is not None and v < last and v not in bad]
            if vals:
                log_high[path] = max([last] + vals) if last else max(vals)
        if vals:
            high = max(vals) if high is None else max(high, max(vals))
            stamped.update(vals)
    return bad


NOTICE = "/t/instances/bravo/inbox/notices/notice-" + "a" * 32 + ".json"
JOURNAL = "/t/state/l/gen-g/ingress/notice/" + "b" * 64 + ".json"


class BackwardsTests(unittest.TestCase):
    """The order judge on traces built by hand, through the same
    `stamps_added` the child uses."""

    def setUp(self):
        from router.tests import clock_child_flows as f
        self.f = f

    def test_a_multi_valued_write_then_an_earlier_one_is_backwards(self):
        trace = [["json", [["a", "t1"], ["b", "t5"]], "/a.json"], ["json", [["c", "t3"]], "/b.json"]]
        self.assertEqual(backwards(trace, {"t1", "t3", "t5"}, set()), ["t3"])

    def test_an_undeclared_repeat_across_paths_after_a_later_stamp_is_backwards(self):
        trace = [["json", [["ts", "t1"]], "/a.json"], ["json", [["ts", "t5"]], "/b.json"],
                 ["json", [["ts", "t1"]], "/c.json"]]
        self.assertEqual(backwards(trace, {"t1", "t5"}, set()), ["t1"])

    def test_a_first_append_repeating_another_paths_earlier_value_is_backwards(self):
        """A new log has no high-water of its own yet; rule 1 still catches
        it, because the line is not a declared site."""
        trace = [["json", [["ts", "t1"]], "/a.json"], ["json", [["ts", "t5"]], "/b.json"],
                 ["jsonl", [["ts", "t1"]], "/new-log.jsonl"]]
        self.assertEqual(backwards(trace, {"t1", "t5"}, set()), ["t1"])

    def test_the_declared_pump_reuse_passes_and_only_there(self):
        trace = [["json", [["ts", "t1"], ["first_seen_ts", "t2"]], JOURNAL],
                 ["json", [["state_ts", "t3"]], JOURNAL],
                 ["json", [["ts", "t1"]], NOTICE]]
        valid = {"t1", "t2", "t3"}
        self.assertEqual(backwards(trace, valid, set(), op=("ingress", "pump")), [])
        # The same shape in another operation, or on another member, is backwards.
        self.assertEqual(backwards(trace, valid, set(), op=("mail_once", "once")), ["t1"])
        # An UNDECLARED member of a declared file reusing it is backwards...
        other = trace[:2] + [["json", [["date", "t1"]], NOTICE]]
        self.assertEqual(backwards(other, valid, set(), op=("ingress", "pump")), ["t1"])
        # ...and so is an undeclared file reusing the declared site's value.
        elsewhere = trace + [["json", [["ts", "t1"]], "/t/state/l/elsewhere.json"]]
        self.assertEqual(backwards(elsewhere, valid, set(), op=("ingress", "pump")), ["t1"])

    def test_in_order_writes_pass_and_carried_values_do_not_count(self):
        trace = [["json", [["a", "t2"]], "/a.json"], ["json", [["a", "t1"], ["b", "t3"]], "/b.json"],
                 ["jsonl", [["ts", "t3"]], "/c.jsonl"]]
        self.assertEqual(backwards(trace, {"t1", "t2", "t3"}, {"t1"}), [])

    def test_an_append_repeating_an_older_stamp_on_the_same_path_is_backwards(self):
        first = json.dumps({"ts": "2001-02-03T04:05:06Z"})
        later = json.dumps({"ts": "2001-02-03T04:05:09Z"})
        state, s1 = self.f.stamps_added(None, first + "\n", True)
        state, s2 = self.f.stamps_added(state, first + "\n" + later + "\n", True)
        state, s3 = self.f.stamps_added(state, first + "\n" + later + "\n" + first + "\n", True)
        self.assertEqual((s1, s2, s3), ([["ts", "2001-02-03T04:05:06Z"]],
                                        [["ts", "2001-02-03T04:05:09Z"]],
                                        [["ts", "2001-02-03T04:05:06Z"]]))
        valid = {"2001-02-03T04:05:06Z", "2001-02-03T04:05:09Z"}
        log = "/x/audit.jsonl"
        # The repeat on the same path is backwards even inside one operation...
        self.assertEqual(backwards([["jsonl", s1, log], ["jsonl", s2, log], ["jsonl", s3, log]],
                                   valid, set()), ["2001-02-03T04:05:06Z"])
        # ...and when the repeated stamp is from an earlier operation.
        highs: dict = {}
        self.assertEqual(backwards([["jsonl", s1, log], ["jsonl", s2, log]], valid, set(), highs),
                         [])
        self.assertEqual(backwards([["jsonl", s3, log]], valid,
                                   {"2001-02-03T04:05:06Z", "2001-02-03T04:05:09Z"}, highs),
                         ["2001-02-03T04:05:06Z"])

    def test_a_document_rewrite_carrying_a_member_is_not_a_new_stamp(self):
        a = json.dumps({"first_seen_ts": "2001-02-03T04:05:06Z", "state_ts": "2001-02-03T04:05:07Z"})
        b = json.dumps({"first_seen_ts": "2001-02-03T04:05:06Z", "state_ts": "2001-02-03T04:05:09Z"})
        state, _ = self.f.stamps_added(None, a, False)
        _state, stamps = self.f.stamps_added(state, b, False)
        self.assertEqual(stamps, [["state_ts", "2001-02-03T04:05:09Z"]])

class CompanionTests(unittest.TestCase):

    def test_with_no_source_nothing_lands_in_the_sources_year(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "w2.json"
            proc = run_child(RUN_FLOWS, out)
            self.assertTrue(out.exists(), proc.stderr[-4000:])
            doc = json.loads(out.read_text())
        self.assertTrue(doc["ok"], proc.stderr[-4000:])
        seen = [v for r in doc["records"] for v in r.get("values", ())]
        self.assertGreater(len(seen), 10)
        self.assertEqual([v for v in seen if v[2].startswith("2001-")], [])


LIFECYCLE = INSTALL + (
    "import sys, json, tempfile\n"
    "from router import hoplink, status\n"
    "def written():\n"
    "    d = tempfile.mkdtemp()\n"
    "    status.StatusTracker(interval_s=5).write(d)\n"
    "    return json.load(open(d + '/status.json'))['started_ts']\n"
    "hoplink.reset_process_state()\n"
    "after_restart = written()\n"
    "clock.reset()\n"
    "after_reset = written()\n"
    "print(json.dumps([after_restart, after_reset]))\n")


class LifecycleTests(unittest.TestCase):

    def test_a_modelled_restart_keeps_the_source_and_reset_removes_it(self):
        proc = run_child(LIFECYCLE)
        self.assertEqual(proc.returncode, 0, proc.stderr[-4000:])
        after_restart, after_reset = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertTrue(after_restart.startswith("2001-02-03T"), after_restart)
        self.assertFalse(after_reset.startswith("2001-"), after_reset)


if __name__ == "__main__":
    unittest.main()
