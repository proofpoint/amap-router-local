"""Step 6 of the peer-lane build, the container half: `derive-mounts.py`
mounts `intake_dir` read-write when the config names one, and requires it
to exist like every other path — `provision` creates it, so a missing one
means provision has not run, which is the same "silent non-delivery" class
the refusal exists for."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "derive-mounts.py"


class DeriveMountsIntakeTests(unittest.TestCase):
    def _run(self, make_intake: bool):
        with TemporaryDirectory() as d:
            root = Path(d)
            (root / "alice").mkdir()
            (root / "state").mkdir()
            intake = root / "router-intake"
            if make_intake:
                intake.mkdir()
            cfg = {"state_dir": str(root / "state"), "fleet_domain": "example.invalid",
                   "intake_dir": str(intake),
                   "instances": {"alice": {"handoff_dir": str(root / "alice")}}}
            f = root / "r.json"
            f.write_text(json.dumps(cfg))
            r = subprocess.run([sys.executable, str(SCRIPT), str(f)], capture_output=True, text=True)
            return r, str(intake)

    def test_intake_dir_is_one_rw_mount(self):
        r, intake = self._run(make_intake=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = dict(l.split("\t") for l in r.stdout.splitlines() if l.strip())
        self.assertEqual(lines[intake], "rw")
        self.assertEqual(len(lines), 3)  # state_dir, alice, intake

    def test_missing_intake_dir_is_refused(self):
        r, intake = self._run(make_intake=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("intake_dir", r.stderr)

    def test_no_intake_dir_means_no_extra_mount(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            (root / "alice").mkdir()
            (root / "state").mkdir()
            f = root / "r.json"
            f.write_text(json.dumps({"state_dir": str(root / "state"),
                                     "instances": {"alice": {"handoff_dir": str(root / "alice")}}}))
            r = subprocess.run([sys.executable, str(SCRIPT), str(f)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len([l for l in r.stdout.splitlines() if l.strip()]), 2)


if __name__ == "__main__":
    unittest.main()
