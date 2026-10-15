"""`docker/derive-mounts.py` with a `delegation` section: the directory of
`delegation.signing_key.path` (KEY_DIR) is mounted read-only, exactly it,
never the key file, never a symlinked spelling, and never nested with a
read-write mount either way. Gated on `delegation` alone, not on `hop`.
EXECUTED, like `test_docker_hop_mounts.py`: the script imports nothing from
the router, so only running it proves what it emits."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "derive-mounts.py"


class KeyMountTests(unittest.TestCase):
    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        # Resolved: every identity-mounted path must be its own realpath.
        self.t = Path(os.path.realpath(td.name))
        for d in ("alice", "state", "keys"):
            (self.t / d).mkdir()
        (self.t / "keys" / "peer.key").write_text("seed")

    def p(self, rel):
        return str(self.t / rel)

    def cfg(self, key="keys/peer.key", **over):
        doc = {"state_dir": self.p("state"),
               "instances": {"alice": {"handoff_dir": self.p("alice")}},
               "delegation": {"signing_key": {"path": self.p(key) if key else None}}}
        for k, v in over.items():
            if v is None:
                doc.pop(k, None)
            else:
                doc[k] = v
        return doc

    def run_script(self, doc):
        f = self.t / "router.json"
        f.write_text(json.dumps(doc))
        return subprocess.run([sys.executable, "-B", str(SCRIPT), str(f)],
                              capture_output=True, text=True)

    def mounts(self, doc):
        r = self.run_script(doc)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [l.split("\t") for l in r.stdout.splitlines() if l.strip()]
        return dict(lines), len(lines)

    def refused(self, doc, *needles):
        r = self.run_script(doc)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        for n in needles:
            self.assertIn(n, r.stderr)
        self.assertEqual(r.stdout, "")
        return r.stderr

    def test_delegation_adds_exactly_the_key_directory_read_only(self):
        m, n = self.mounts(self.cfg())
        self.assertEqual(m, {self.p("state"): "rw", self.p("alice"): "rw",
                             self.p("keys"): "ro"})
        self.assertEqual(n, 3)

    def test_the_key_file_itself_is_never_a_bind_line(self):
        m, _ = self.mounts(self.cfg())
        self.assertNotIn(self.p("keys/peer.key"), m)
        self.assertEqual(m.get(self.p("keys")), "ro")

    def test_without_delegation_there_is_no_key_mount(self):
        m, n = self.mounts(self.cfg(delegation=None))
        self.assertEqual(m, {self.p("state"): "rw", self.p("alice"): "rw"})
        self.assertEqual(n, 2)

    def test_the_bind_needs_delegation_alone_not_hop(self):
        doc = self.cfg()
        self.assertNotIn("hop", doc)
        m, _ = self.mounts(doc)
        self.assertEqual(m.get(self.p("keys")), "ro")

    def test_a_symlinked_component_is_refused_never_mounted_where_it_points(self):
        os.symlink(self.p("keys"), self.p("keylink"))
        err = self.refused(self.cfg(key="keylink/peer.key"), "key mount", "realpath")
        self.assertNotIn(self.p("keys") + "\t", err)

    def test_a_symlinked_key_file_is_refused(self):
        os.symlink(self.p("keys/peer.key"), self.p("keys/link.key"))
        self.refused(self.cfg(key="keys/link.key"), "key mount", "is a symlink")

    def test_a_missing_key_file_is_refused(self):
        self.refused(self.cfg(key="keys/absent.key"), "do not exist", "absent.key")

    def test_a_key_directory_inside_a_read_write_mount_is_refused(self):
        (self.t / "state" / "keys").mkdir()
        (self.t / "state" / "keys" / "peer.key").write_text("seed")
        self.refused(self.cfg(key="state/keys/peer.key"), "key mount",
                     "a read-only path is nested with no read-write one")

    def test_a_key_directory_containing_a_read_write_mount_is_refused(self):
        (self.t / "keys" / "inner").mkdir()
        doc = self.cfg(instances={"alice": {"handoff_dir": self.p("keys/inner")}})
        self.refused(doc, "key mount", "a read-only path is nested with no read-write one")

    def test_the_key_directory_holds_only_the_key(self):
        for extra, make in (("peer.key.pub", lambda p: p.write_text("pub")),
                            (".hidden", lambda p: p.write_text("x")),
                            ("backup", lambda p: p.mkdir())):
            with self.subTest(extra=extra):
                make(self.t / "keys" / extra)
                self.refused(self.cfg(), "key mount", "must hold only the key", repr(extra))
                p = self.t / "keys" / extra
                p.rmdir() if p.is_dir() else p.unlink()
        m, _ = self.mounts(self.cfg())
        self.assertEqual(m.get(self.p("keys")), "ro", "the companion: the key alone mounts")

    def test_a_delegation_without_a_signing_key_is_refused(self):
        self.refused(self.cfg(delegation={"partition_verified": True}), "key mount",
                     "signing_key")


if __name__ == "__main__":
    unittest.main()
