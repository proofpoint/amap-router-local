"""`docker/derive-mounts.py` on a host with a hop link: a config with a
`hop` section gains identity mounts for `hop.root` (rw), `registry_dir`
(ro), the directory of `delivered_domains_file` (ro) and the directory of
`transport_plugin.path` (ro); a config without one derives exactly what it
did before. EXECUTED, like `test_docker_intake.py`: the script imports
nothing from the router, so only running it proves what it emits."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "derive-mounts.py"


class HopMountsTests(unittest.TestCase):
    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        # Resolved: every hop path must be its own realpath.
        self.t = Path(os.path.realpath(td.name))
        for d in ("alice", "state", "hop", "registry", "d7", "plugins"):
            (self.t / d).mkdir()
        (self.t / "d7" / "delivered.json").write_text("{}")
        (self.t / "plugins" / "hop_plugin.py").write_text("")

    def p(self, rel):
        return str(self.t / rel)

    def cfg(self, **over):
        doc = {"state_dir": self.p("state"), "fleet_domain": "example.invalid",
               "instances": {"alice": {"handoff_dir": self.p("alice")}},
               "registry_dir": self.p("registry"),
               "delivered_domains_file": self.p("d7/delivered.json"),
               "transport_plugin": {"path": self.p("plugins/hop_plugin.py"), "sha256": "0" * 64},
               "hop": {"root": self.p("hop"), "peer_uid": 1001, "version_write": 1,
                       "caps": {"document": 1, "request": 1, "attachment": 1, "total": 1}}}
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

    # --- each mount, each mode -------------------------------------------

    def test_the_full_hop_mount_set(self):
        m, n = self.mounts(self.cfg())
        self.assertEqual(m, {self.p("state"): "rw", self.p("alice"): "rw",
                             self.p("hop"): "rw", self.p("registry"): "ro",
                             self.p("d7"): "ro", self.p("plugins"): "ro"})
        self.assertEqual(n, 6)

    def test_hop_root_is_mounted_read_write(self):
        m, _ = self.mounts(self.cfg())
        self.assertEqual(m.get(self.p("hop")), "rw")

    def test_registry_dir_is_mounted_read_only(self):
        m, _ = self.mounts(self.cfg())
        self.assertEqual(m.get(self.p("registry")), "ro")

    def test_the_plugin_files_directory_is_mounted_read_only(self):
        m, _ = self.mounts(self.cfg())
        self.assertEqual(m.get(self.p("plugins")), "ro")
        self.assertNotIn(self.p("plugins/hop_plugin.py"), m)

    def test_the_delivered_domains_files_directory_is_mounted_read_only(self):
        m, _ = self.mounts(self.cfg())
        self.assertEqual(m.get(self.p("d7")), "ro")
        self.assertNotIn(self.p("d7/delivered.json"), m)

    def test_no_delivered_domains_file_means_no_d7_mount(self):
        m, n = self.mounts(self.cfg(delivered_domains_file=None))
        self.assertNotIn(self.p("d7"), m)
        self.assertEqual(n, 5)

    def test_a_shared_read_only_directory_is_mounted_once(self):
        os.rename(self.p("plugins/hop_plugin.py"), self.p("registry/hop_plugin.py"))
        doc = self.cfg(transport_plugin={"path": self.p("registry/hop_plugin.py"),
                                         "sha256": "0" * 64})
        m, n = self.mounts(doc)
        self.assertEqual(m.get(self.p("registry")), "ro")
        self.assertEqual(n, 5)

    def test_a_read_only_path_may_nest_in_another_read_only_one(self):
        (self.t / "registry" / "plugins").mkdir()
        os.rename(self.p("plugins/hop_plugin.py"), self.p("registry/plugins/hop_plugin.py"))
        doc = self.cfg(transport_plugin={"path": self.p("registry/plugins/hop_plugin.py"),
                                         "sha256": "0" * 64})
        m, _ = self.mounts(doc)
        self.assertEqual((m.get(self.p("registry")), m.get(self.p("registry/plugins"))),
                         ("ro", "ro"))

    # --- nothing new without a hop section -------------------------------

    def test_without_hop_the_mount_list_is_byte_identical(self):
        # The D7 key is present and its directory exists, so only the `hop`
        # gate keeps it out: the companion to the full set above, where the
        # same key DOES mount. (registry_dir is the one key mounted without
        # `hop`: the rows below.)
        bare = self.cfg(hop=None, transport_plugin=None, registry_dir=None,
                        delivered_domains_file=None)
        keys = self.cfg(hop=None, transport_plugin=None, registry_dir=None)
        a, b = self.run_script(bare), self.run_script(keys)
        self.assertEqual((a.returncode, b.returncode), (0, 0), a.stderr + b.stderr)
        self.assertEqual(b.stdout, a.stdout)
        self.assertEqual(a.stdout, f"{self.p('state')}\trw\n{self.p('alice')}\trw\n")

    # --- the registry without a hop section -------------------------------

    def no_hop(self, **over):
        return self.cfg(hop=None, transport_plugin=None, delivered_domains_file=None, **over)

    def test_registry_dir_without_hop_is_mounted_read_only(self):
        # The loader reads registry_dir with or without hop; run.sh's
        # container must see it, or every instance is held.
        m, n = self.mounts(self.no_hop())
        self.assertEqual(m, {self.p("state"): "rw", self.p("alice"): "rw",
                             self.p("registry"): "ro"})
        self.assertEqual(n, 3)

    def test_registry_dir_without_hop_keeps_the_hop_paths_rules(self):
        (self.t / "reglink").symlink_to(self.t / "registry")
        for value, needle in (("registry", "must be an absolute path"),
                              (self.p("registry") + "/", "not in normal form"),
                              (self.p("reglink"), "not its own realpath"),
                              ("/usr/share/registry", "container system path")):
            with self.subTest(value=value):
                self.refused(self.no_hop(registry_dir=value), "registry mount: registry_dir", needle)

    def test_registry_dir_without_hop_inside_a_read_write_mount_is_refused(self):
        (self.t / "state" / "registry").mkdir()
        self.refused(self.no_hop(registry_dir=self.p("state/registry")),
                     "registry mount: registry_dir", "a read-only path is nested with no read-write one")

    def test_a_missing_registry_dir_without_hop_is_refused(self):
        r = self.run_script(self.no_hop(registry_dir=self.p("absent")))
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn(f"registry_dir: {self.p('absent')}", r.stderr)
        self.assertEqual(r.stdout, "")

    # --- refusals, each named --------------------------------------------

    def hop(self, root):
        return dict(self.cfg()["hop"], root=root)

    def test_a_relative_hop_root_is_refused(self):
        self.refused(self.cfg(hop=self.hop("srv/hop")), "hop.root must be an absolute path")

    def test_a_hop_root_not_in_normal_form_is_refused(self):
        self.refused(self.cfg(hop=self.hop(self.p("hop") + "/")), "hop.root", "normal form")

    def test_a_symlinked_hop_root_is_refused(self):
        os.symlink(self.p("hop"), self.p("hoplink"))
        self.refused(self.cfg(hop=self.hop(self.p("hoplink"))),
                     "hop.root", "not its own realpath")

    def test_a_symlinked_component_of_registry_dir_is_refused(self):
        os.symlink(self.t, self.p("via"))
        self.refused(self.cfg(registry_dir=self.p("via/registry")),
                     "registry_dir", "not its own realpath")

    def test_a_symlinked_plugin_file_is_refused(self):
        os.symlink(self.p("plugins/hop_plugin.py"), self.p("plugins/link.py"))
        self.refused(self.cfg(transport_plugin={"path": self.p("plugins/link.py"),
                                                "sha256": "0" * 64}),
                     "transport_plugin.path", "is a symlink")

    def test_a_symlinked_delivered_domains_file_is_refused(self):
        os.symlink(self.p("d7/delivered.json"), self.p("d7/link.json"))
        self.refused(self.cfg(delivered_domains_file=self.p("d7/link.json")),
                     "delivered_domains_file", "is a symlink")

    def test_a_plugin_under_a_container_system_tree_is_refused(self):
        self.refused(self.cfg(transport_plugin={"path": "/usr/local/lib/hop_plugin.py",
                                                "sha256": "0" * 64}),
                     "transport_plugin.path's directory", "container system path")

    def test_a_container_system_directory_itself_is_refused(self):
        self.refused(self.cfg(registry_dir="/etc"), "registry_dir", "container system path")

    def test_hop_root_inside_state_dir_is_refused(self):
        (self.t / "state" / "hop").mkdir()
        self.refused(self.cfg(hop=self.hop(self.p("state/hop"))),
                     "hop.root", "overlaps", "hop.root is nested with no other mount")

    def test_hop_root_containing_a_read_only_path_is_refused(self):
        (self.t / "hop" / "registry").mkdir()
        self.refused(self.cfg(registry_dir=self.p("hop/registry")),
                     "overlaps", "hop.root is nested with no other mount")

    def test_a_read_only_path_inside_a_read_write_mount_is_refused(self):
        (self.t / "alice" / "registry").mkdir()
        self.refused(self.cfg(registry_dir=self.p("alice/registry")),
                     "registry_dir", "overlaps", "a read-only path is nested with no read-write one")

    def test_a_read_only_path_containing_a_read_write_mount_is_refused(self):
        # The D7 directory holds an instance root and nothing else mounted, so
        # only the read-only/read-write rule can refuse it.
        (self.t / "wrap").mkdir()
        os.rename(self.p("alice"), self.p("wrap/alice"))
        os.rename(self.p("d7/delivered.json"), self.p("wrap/delivered.json"))
        self.refused(self.cfg(delivered_domains_file=self.p("wrap/delivered.json"),
                              instances={"alice": {"handoff_dir": self.p("wrap/alice")}}),
                     "delivered_domains_file's directory", "overlaps",
                     "a read-only path is nested with no read-write one")

    def test_hop_root_inside_a_symlinked_state_dir_is_refused(self):
        # state_dir named through a link: only the RESOLVED comparison sees
        # that hop.root sits inside it.
        (self.t / "state" / "hop").mkdir()
        os.symlink(self.p("state"), self.p("statelink"))
        self.refused(self.cfg(state_dir=self.p("statelink"), hop=self.hop(self.p("state/hop"))),
                     "overlaps", f"an existing mount ({self.p('state')}, rw)")

    def test_a_sibling_sharing_a_name_prefix_is_not_nested(self):
        (self.t / "hop-registry").mkdir()
        m, _ = self.mounts(self.cfg(registry_dir=self.p("hop-registry")))
        self.assertEqual((m.get(self.p("hop")), m.get(self.p("hop-registry"))), ("rw", "ro"))

    def test_a_config_file_inside_hop_root_is_refused(self):
        # run.sh mounts the config by itself; only this comparison sees it.
        f = self.t / "hop" / "router.json"
        f.write_text(json.dumps(self.cfg()))
        r = subprocess.run([sys.executable, "-B", str(SCRIPT), str(f)],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn(f"overlaps the config file ({f}, ro)", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_a_config_file_beside_a_read_only_path_is_accepted(self):
        f = self.t / "registry" / "router.json"
        f.write_text(json.dumps(self.cfg()))
        r = subprocess.run([sys.executable, "-B", str(SCRIPT), str(f)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_missing_hop_root_is_refused(self):
        os.rmdir(self.p("hop"))
        self.refused(self.cfg(), "do not exist", f"hop.root: {self.p('hop')}")

    def test_a_missing_plugin_file_is_refused(self):
        os.unlink(self.p("plugins/hop_plugin.py"))
        self.refused(self.cfg(), "do not exist",
                     f"transport_plugin.path: {self.p('plugins/hop_plugin.py')}")

    def test_hop_without_a_plugin_or_a_registry_is_refused(self):
        self.refused(self.cfg(transport_plugin=None), "needs 'transport_plugin'")
        self.refused(self.cfg(registry_dir=None), "needs 'registry_dir'")


if __name__ == "__main__":
    unittest.main()
