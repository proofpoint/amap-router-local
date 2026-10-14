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
values must not go backwards from one operation to the next, and at least two
must be distinct, which a cached read would collapse. A companion run with no
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

    def test_the_exposure_follows_the_file_time_set_from_the_installed_clock(self):
        [rec] = [r for r in self.doc["records"] if "exposure" in r]
        self.assertIs(rec["exposure"]["external_mail_delivered"], True)
        self.assertEqual(rec["exposure"]["last_external_delivery_ts"], rec["written"])


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
