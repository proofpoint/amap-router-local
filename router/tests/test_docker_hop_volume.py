"""`--volume <path>=<name>`: one of the `hop` section's identity mounts
(hop.root, registry_dir, the plugin's or the delivered-domain file's
directory) mounted from a NAMED VOLUME instead of bound from the host, for an
engine whose bind mounts keep no uid boundary (a macOS share shows every
container user as the owner). EXECUTED, like `test_docker_hop_mounts.py`:
`derive-mounts.py` imports nothing from the router, and `run.sh` runs against
a fake `docker` that records its argv and answers `volume inspect`. Without
`--volume` nothing changes, which the existing modules pin and the
`*_without_volume_*` rows here re-pin."""

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "docker" / "derive-mounts.py"
RUN_SH = REPO / "docker" / "run.sh"
# Container-side paths: a volume's destination is never made on this host.
HOP = "/private/var/amap/hop"
PLUGIN_DIR = "/private/var/amap/plugin"
D7_DIR = "/private/var/amap/d7"


class Lab:
    """A hop config: host paths that exist (resolved), and the hop.root, the
    plugin and the D7 file at container-side paths that do not."""

    def __init__(self, t: Path):
        self.t = t
        for d in ("alice", "state", "registry"):
            (t / d).mkdir()

    def p(self, rel):
        return str(self.t / rel)

    def cfg(self, **over):
        doc = {"state_dir": self.p("state"), "fleet_domain": "example.invalid",
               "instances": {"alice": {"handoff_dir": self.p("alice")}},
               "registry_dir": self.p("registry"),
               "delivered_domains_file": D7_DIR + "/delivered.json",
               "transport_plugin": {"path": PLUGIN_DIR + "/hop_plugin.py", "sha256": "0" * 64},
               "hop": {"root": HOP, "peer_uid": 2102, "version_write": 1,
                       "caps": {"document": 1, "request": 1, "attachment": 1, "total": 1}}}
        for k, v in over.items():
            if v is None:
                doc.pop(k, None)
            else:
                doc[k] = v
        return doc

    def hop(self, **over):
        return dict(self.cfg()["hop"], **over)

    def write(self, doc, name="router.json"):
        f = self.t / name
        f.write_text(json.dumps(doc))
        return f


ALL3 = ("--volume", HOP, "--volume", PLUGIN_DIR, "--volume", D7_DIR)


class DeriveTests(unittest.TestCase):
    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.lab = Lab(Path(os.path.realpath(td.name)))
        self.p = self.lab.p

    def run_script(self, doc, *args, cfg_name="router.json"):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), str(self.lab.write(doc, cfg_name)), *args],
                              capture_output=True, text=True)

    def lines(self, doc, *args):
        r = self.run_script(doc, *args)
        self.assertEqual(r.returncode, 0, r.stderr)
        return [tuple(l.split("\t")) for l in r.stdout.splitlines()]

    def refused(self, doc, *args, needle=""):
        r = self.run_script(doc, *args)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual(r.stdout, "")
        self.assertIn(needle, r.stderr)
        return r.stderr

    def host_tree(self):
        """The same config with every hop path on the host, as binds."""
        for d in ("hop", "plugins", "d7"):
            (self.lab.t / d).mkdir()
        (self.lab.t / "plugins" / "hop_plugin.py").write_text("")
        (self.lab.t / "d7" / "delivered.json").write_text("{}")
        return self.lab.cfg(hop=self.lab.hop(root=self.p("hop")),
                            transport_plugin={"path": self.p("plugins/hop_plugin.py"), "sha256": "0" * 64},
                            delivered_domains_file=self.p("d7/delivered.json"))

    # --- each mount, by its role -----------------------------------------

    def test_each_named_path_becomes_a_volume_line_by_its_role(self):
        got = self.lines(self.lab.cfg(), *ALL3)
        self.assertEqual(len(got), 6)
        self.assertEqual(dict(got), {self.p("state"): "rw", self.p("alice"): "rw", D7_DIR: "volume-ro",
                                     HOP: "volume-rw", PLUGIN_DIR: "volume-ro", self.p("registry"): "ro"})

    def test_hop_root_as_a_volume_is_read_write(self):
        self.assertIn((HOP, "volume-rw"), self.lines(self.lab.cfg(), *ALL3))

    def test_the_plugin_and_d7_directories_as_volumes_are_read_only(self):
        got = dict(self.lines(self.lab.cfg(), *ALL3))
        self.assertEqual((got[PLUGIN_DIR], got[D7_DIR]), ("volume-ro", "volume-ro"))

    def test_registry_dir_as_a_volume_is_read_only(self):
        doc = self.lab.cfg(registry_dir="/private/var/amap/registry")
        got = dict(self.lines(doc, *ALL3, "--volume", "/private/var/amap/registry"))
        self.assertEqual(got["/private/var/amap/registry"], "volume-ro")

    def test_a_volume_replaces_its_bind_and_nothing_else(self):
        doc = self.host_tree()
        binds = self.lines(doc)
        vol = self.lines(doc, "--volume", self.p("hop"))
        self.assertEqual(vol, [(p, "volume-rw" if p == self.p("hop") else m) for p, m in binds])

    def test_a_volume_path_is_never_looked_for_on_the_host(self):
        for p in (HOP, PLUGIN_DIR, D7_DIR):
            self.assertFalse(os.path.exists(p))
        self.lines(self.lab.cfg(), *ALL3)
        # The same paths as binds: refused, because they do not exist here.
        self.refused(self.lab.cfg(), needle="do not exist")
        # A host symlink at the written path means nothing to a volume's
        # destination: it is the container's path. As a bind it is refused.
        (self.lab.t / "hoplink").symlink_to(self.lab.t / "registry")
        doc = self.lab.cfg(hop=self.lab.hop(root=self.p("hoplink")))
        self.assertIn((self.p("hoplink"), "volume-rw"),
                      self.lines(doc, "--volume", self.p("hoplink"), "--volume", PLUGIN_DIR, "--volume", D7_DIR))
        self.refused(doc, "--volume", PLUGIN_DIR, "--volume", D7_DIR, needle="not its own realpath")

    def test_without_volume_the_output_is_as_before(self):
        self.assertEqual(self.lines(self.host_tree()),
                         [(self.p("state"), "rw"), (self.p("alice"), "rw"), (self.p("hop"), "rw"),
                          (self.p("registry"), "ro"), (self.p("plugins"), "ro"), (self.p("d7"), "ro")])

    # --- the lexical rules still apply -------------------------------------

    def test_a_volume_hop_root_keeps_the_lexical_rules(self):
        for value, needle in ((HOP + "/", "not in normal form"), ("/usr/local/hop", "container system path"),
                              ("/var", "container system path")):
            with self.subTest(value=value):
                self.refused(self.lab.cfg(hop=self.lab.hop(root=value)), "--volume", value,
                             "--volume", PLUGIN_DIR, "--volume", D7_DIR, needle=needle)

    def test_a_volume_file_directory_keeps_the_lexical_rules(self):
        for value, needle in (("/usr/lib/hop_plugin.py", "container system path"),
                              ("/opt/hop_plugin.py", "container system path")):
            with self.subTest(value=value):
                self.refused(self.lab.cfg(transport_plugin={"path": value, "sha256": "0" * 64}),
                             "--volume", HOP, "--volume", os.path.dirname(value), "--volume", D7_DIR,
                             needle=needle)

    def test_mount_syntax_in_a_volume_path_is_refused(self):
        for value in (HOP + ",readonly", '/private/var/a"mp', "/private/var/amap/a=b"):
            with self.subTest(value=value):
                self.refused(self.lab.cfg(hop=self.lab.hop(root=value)), "--volume", value,
                             "--volume", PLUGIN_DIR, "--volume", D7_DIR, needle="would read as syntax")

    # --- nesting -----------------------------------------------------------

    def test_a_volume_hop_root_is_nested_with_no_other_mount(self):
        inside = self.lab.cfg(hop=self.lab.hop(root=self.p("state") + "/hop"))
        self.refused(inside, "--volume", self.p("state") + "/hop", "--volume", PLUGIN_DIR, "--volume", D7_DIR,
                     needle="hop.root is nested with no other mount")
        # A read-only volume inside it is refused too.
        in_vol = self.lab.cfg(delivered_domains_file=HOP + "/d7/delivered.json")
        self.refused(in_vol, "--volume", HOP, "--volume", PLUGIN_DIR, "--volume", HOP + "/d7",
                     needle="hop.root is nested with no other mount")

    def test_a_volume_is_compared_with_each_mount_as_written(self):
        # state_dir spelled through a symlink: its bind is made at the written
        # path, so a volume inside THAT spelling overlaps it in the container
        # although the resolved paths do not nest.
        (self.lab.t / "stlink").symlink_to(self.lab.t / "state")
        hop = self.p("stlink") + "/hop"
        doc = self.lab.cfg(state_dir=self.p("stlink"), hop=self.lab.hop(root=hop))
        self.refused(doc, "--volume", hop, "--volume", PLUGIN_DIR, "--volume", D7_DIR,
                     needle="hop.root is nested with no other mount")

    def test_a_config_file_inside_a_volume_is_refused(self):
        (self.lab.t / "conf").mkdir()
        doc = self.lab.cfg(hop=self.lab.hop(root=self.p("conf")))
        r = self.run_script(doc, "--volume", self.p("conf"), "--volume", PLUGIN_DIR, "--volume", D7_DIR,
                            cfg_name="conf/router.json")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("the config file", r.stderr)

    def test_a_config_file_inside_a_volume_as_written_is_refused(self):
        # The config reached through a symlinked directory: run.sh binds it at
        # the written path, inside the volume, although its resolved path is not.
        (self.lab.t / "realconf").mkdir()
        (self.lab.t / "conflink").symlink_to(self.lab.t / "realconf")
        doc = self.lab.cfg(hop=self.lab.hop(root=self.p("conflink")))
        r = self.run_script(doc, "--volume", self.p("conflink"), "--volume", PLUGIN_DIR, "--volume", D7_DIR,
                            cfg_name="conflink/router.json")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("the config file", r.stderr)

    def test_a_later_bind_inside_a_volume_is_refused(self):
        key = self.lab.t / "keys"
        key.mkdir()
        (key / "seed").write_text("")
        doc = self.lab.cfg(hop=self.lab.hop(root=str(key)), delegation={"signing_key": {"path": str(key / "seed")}})
        self.refused(doc, "--volume", str(key), "--volume", PLUGIN_DIR, "--volume", D7_DIR, needle="overlaps")

    def test_two_read_only_volumes_may_share_one_path(self):
        doc = self.lab.cfg(delivered_domains_file=PLUGIN_DIR + "/delivered.json")
        self.assertEqual(dict(self.lines(doc, "--volume", HOP, "--volume", PLUGIN_DIR))[PLUGIN_DIR], "volume-ro")

    # --- a volume and a bind never share a path ---------------------------
    # One output line per path: a volume and a bind at one path would leave
    # ONE of them, silently. Each direction, and each --volume order.

    def refused_in_each_order(self, doc, vols, needle):
        for order in (vols, vols[::-1]):
            with self.subTest(order=order):
                self.refused(doc, *[a for v in order for a in ("--volume", v)], needle=needle)

    def test_a_volume_never_replaces_the_signing_key_bind(self):
        """The volume first (a hop path), the bind after it (the key): the key
        rules would have run against the host directory, and the router would
        read whatever the volume holds."""
        kv = self.lab.t / "kv"
        kv.mkdir()
        (kv / "seed").write_text("k")
        doc = self.lab.cfg(transport_plugin={"path": self.p("kv/hop_plugin.py"), "sha256": "0" * 64},
                           delegation={"signing_key": {"path": self.p("kv/seed")}})
        self.refused_in_each_order(doc, [HOP, self.p("kv"), D7_DIR],
                                   needle="a volume shares no path with a bind")

    def test_a_volume_is_never_dropped_for_a_bind_at_its_path(self):
        """The bind first (the verdict's directory), the volume after it: the
        volume was counted as used and the host bind mounted in its place."""
        for d in ("instances", "verdict"):
            (self.lab.t / d).mkdir()
        doc = self.lab.cfg(instances=None, instances_dir=self.p("instances"),
                           selected_json=self.p("verdict/selected.json"),
                           transport_plugin={"path": self.p("verdict/hop_plugin.py"), "sha256": "0" * 64})
        self.refused_in_each_order(doc, [HOP, self.p("verdict"), D7_DIR],
                                   needle="a volume shares no path with a bind")

    def test_a_volume_nested_in_a_read_only_bind_is_refused(self):
        doc = self.lab.cfg(transport_plugin={"path": self.p("registry/plug/p.py"), "sha256": "0" * 64})
        self.refused_in_each_order(doc, [HOP, self.p("registry/plug"), D7_DIR],
                                   needle="a volume is nested with no other mount")

    def test_a_bind_nested_in_a_read_only_volume_is_refused(self):
        (self.lab.t / "pv" / "k").mkdir(parents=True)
        (self.lab.t / "pv" / "k" / "seed").write_text("k")
        doc = self.lab.cfg(transport_plugin={"path": self.p("pv/hop_plugin.py"), "sha256": "0" * 64},
                           delegation={"signing_key": {"path": self.p("pv/k/seed")}})
        self.refused_in_each_order(doc, [HOP, self.p("pv"), D7_DIR],
                                   needle="a volume is nested with no other mount")

    def test_two_read_only_volumes_nested_are_refused(self):
        reg = "/private/var/amap/registry"
        doc = self.lab.cfg(registry_dir=reg,
                           transport_plugin={"path": reg + "/plug/p.py", "sha256": "0" * 64})
        self.refused_in_each_order(doc, [HOP, reg, reg + "/plug", D7_DIR],
                                   needle="a volume is nested with no other mount")

    # --- what --volume may name -------------------------------------------

    def test_a_path_this_config_does_not_mount_from_its_hop_section_is_refused(self):
        for value in (self.p("state"), self.p("alice"), "/private/var/amap/other", HOP + "/x"):
            with self.subTest(value=value):
                self.refused(self.lab.cfg(), *ALL3, "--volume", value, needle="not one of this config's hop mounts")

    def test_a_named_plugin_or_d7_file_rather_than_its_directory_is_refused(self):
        self.refused(self.lab.cfg(), "--volume", HOP, "--volume", PLUGIN_DIR + "/hop_plugin.py",
                     "--volume", D7_DIR, needle="not one of this config's hop mounts")

    def test_volume_needs_a_hop_section(self):
        bare = self.lab.cfg(hop=None, transport_plugin=None, delivered_domains_file=None)
        self.refused(bare, "--volume", self.p("registry"), needle="needs a 'hop' section")

    def test_a_bad_or_repeated_argument_is_refused(self):
        for args, needle in ((["--volum", HOP], "unexpected argument"), (["--volume"], "unexpected argument"),
                             (["x"], "unexpected argument"), (["--volume", HOP, "--volume", HOP], "given twice")):
            with self.subTest(args=args):
                self.refused(self.lab.cfg(), *args, needle=needle)


class RunShTests(unittest.TestCase):
    """run.sh with a fake docker: `volume inspect NAME` answers from the
    VOL_<NAME> variable (absent: no such volume); every other call records
    its argv."""

    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.lab = Lab(Path(os.path.realpath(td.name)))
        self.p = self.lab.p
        self.bin = self.lab.t / "bin"
        self.bin.mkdir()
        fake = self.bin / "docker"
        fake.write_text("#!/usr/bin/env bash\n"
                        'for a in "$@"; do printf "%s\\n" "$a"; done >> "$FAKE_LOG"\n'
                        'printf -- "--END--\\n" >> "$FAKE_LOG"\n'
                        'if [ "$1 $2" = "volume inspect" ]; then\n'
                        '  n="${@: -1}"; var="VOL_${n//[^A-Za-z0-9]/_}"\n'
                        '  [ -n "${!var-}" ] || { echo "Error response from daemon: get $n: no such volume" >&2; exit 1; }\n'
                        '  case "${!var}" in "!"*) echo "${!var#!}" >&2; exit 1 ;; esac\n'
                        '  printf "%s\\n" "${!var}"\n'
                        "fi\n"
                        "exit 0\n")
        fake.chmod(0o755)
        self.log = self.lab.t / "docker.log"

    def stand_in(self, manifest):
        """run.sh copied beside a STAND-IN derive-mounts.py printing
        `manifest`: the one way to hand run.sh a manifest the real script
        never prints, which is what its own check on it is for."""
        d = self.lab.t / "dk"
        d.mkdir(exist_ok=True)
        shutil.copy(RUN_SH, d / "run.sh")
        (d / "manifest").write_text(manifest)
        (d / "derive-mounts.py").write_text(f"#!/bin/sh\ncat '{d / 'manifest'}'\n")
        (d / "check-stale.py").write_text("#!/bin/sh\nexit 0\n")
        for f in ("run.sh", "derive-mounts.py", "check-stale.py"):
            (d / f).chmod(0o755)
        return d / "run.sh"

    def run_sh(self, doc, *args, vols=None, script=RUN_SH):
        vols = {"amap-hop": "amap-hop local null", "amap-plugin": "amap-plugin local null",
                "amap-d7": "amap-d7 local {}"} if vols is None else vols
        cfg = self.lab.write(doc)
        self.log.write_text("")
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FAKE_LOG=str(self.log))
        env.update({"VOL_" + "".join(c if c.isalnum() else "_" for c in k): v for k, v in vols.items()})
        p = subprocess.run([str(script), "--config", str(cfg), "--name", "amp-test", "--detach", *args],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
        blocks = [b.splitlines() for b in self.log.read_text().split("--END--\n") if b.strip()]
        return (p, cfg, [b for b in blocks if b[0] == "run"],
                [b[-1] for b in blocks if b[:2] == ["volume", "inspect"]])

    def want(self, cfg, mounts):
        return (["run", "-d", "--restart", "unless-stopped", "--name", "amp-test",
                 "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                 "-e", f"ROUTER_CONFIG={cfg}", "-e", "ROUTER_INTERVAL=5"]
                + mounts + ["-v", f"{cfg}:{cfg}:ro", "amap-router-local"])

    ARGS = ("--volume", f"{HOP}=amap-hop", "--volume", f"{PLUGIN_DIR}=amap-plugin", "--volume", f"{D7_DIR}=amap-d7")

    def test_each_volume_is_mounted_by_name_with_its_role(self):
        p, cfg, runs, inspects = self.run_sh(self.lab.cfg(), *self.ARGS)
        self.assertEqual(p.returncode, 0, p.stderr)
        b = lambda x: ("-v", f"{self.p(x)}:{self.p(x)}:{'ro' if x == 'registry' else 'rw'}")
        want = self.want(cfg, [])
        head, tail = want[:-3], want[-3:]
        self.assertEqual(len(runs), 1)
        argv = runs[0]
        self.assertEqual((argv[:len(head)], argv[-3:]), (head, tail))
        mid = argv[len(head):-3]
        pairs = sorted(zip(mid[0::2], mid[1::2]))
        self.assertEqual(pairs, sorted([b("state"), b("alice"), b("registry"),
                                        ("--mount", f"type=volume,src=amap-d7,dst={D7_DIR},readonly,volume-nocopy"),
                                        ("--mount", f"type=volume,src=amap-hop,dst={HOP},volume-nocopy"),
                                        ("--mount", f"type=volume,src=amap-plugin,dst={PLUGIN_DIR},readonly,"
                                                    "volume-nocopy")]))
        self.assertEqual(sorted(inspects), ["amap-d7", "amap-hop", "amap-plugin"])

    def test_without_volume_no_volume_is_asked_about(self):
        for d in ("hop", "plugins", "d7"):
            (self.lab.t / d).mkdir()
        (self.lab.t / "plugins" / "p.py").write_text("")
        (self.lab.t / "d7" / "x.json").write_text("{}")
        doc = self.lab.cfg(hop=self.lab.hop(root=self.p("hop")),
                           transport_plugin={"path": self.p("plugins/p.py"), "sha256": "0" * 64},
                           delivered_domains_file=self.p("d7/x.json"))
        p, cfg, runs, inspects = self.run_sh(doc)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(inspects, [])
        self.assertNotIn("--mount", runs[0])

    def test_a_missing_volume_is_refused_before_docker_run(self):
        p, _, runs, inspects = self.run_sh(self.lab.cfg(), *self.ARGS,
                                           vols={"amap-hop": "amap-hop local null", "amap-d7": "amap-d7 local null"})
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("amap-plugin: docker volume inspect failed: Error response from daemon: "
                      "get amap-plugin: no such volume", p.stderr)
        self.assertIn("amap-plugin", inspects)
        self.assertEqual(runs, [], "docker run would create it, empty and root's")

    def test_a_failed_inspect_says_what_docker_said(self):
        """Not every failure is a missing volume: an operator told "no such
        volume" when the daemon refused the call would go and make one."""
        p, _, runs, _ = self.run_sh(self.lab.cfg(), *self.ARGS,
                                    vols={"amap-hop": "amap-hop local null", "amap-d7": "amap-d7 local null",
                                          "amap-plugin": "!permission denied while trying to connect "
                                                         "to the docker daemon socket"})
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("inspect failed: permission denied while trying to connect", p.stderr)
        self.assertNotIn("no such volume", p.stderr)
        self.assertEqual(runs, [])

    def test_every_volume_becomes_exactly_one_mount(self):
        st, al, reg = self.p("state"), self.p("alice"), self.p("registry")
        base = f"{st}\trw\n{al}\trw\n{reg}\tro\n"
        for manifest, n in ((base, 0), (base + f"{HOP}\tvolume-rw\n{HOP}\tvolume-rw\n", 2)):
            with self.subTest(n=n):
                p, _, runs, _ = self.run_sh(self.lab.cfg(), "--volume", f"{HOP}=amap-hop",
                                            script=self.stand_in(manifest))
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn(f"run.sh: --volume {HOP}=amap-hop became {n} mount(s), not one", p.stderr)
                self.assertEqual(runs, [])
        # The control: the same stand-in printing the volume once starts.
        p, _, runs, _ = self.run_sh(self.lab.cfg(), "--volume", f"{HOP}=amap-hop",
                                    script=self.stand_in(base + f"{HOP}\tvolume-rw\n"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(runs), 1)
        self.assertIn(f"type=volume,src=amap-hop,dst={HOP},volume-nocopy", runs[0])

    def test_a_volume_with_driver_options_or_another_driver_is_refused(self):
        for info in ('amap-hop local {"device":"/x","o":"bind","type":"none"}', "amap-hop nfs null",
                     "other local null", "amap-hop local null extra"):
            with self.subTest(info=info):
                p, _, runs, _ = self.run_sh(self.lab.cfg(), *self.ARGS,
                                            vols={"amap-hop": info, "amap-plugin": "amap-plugin local null",
                                                  "amap-d7": "amap-d7 local null"})
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("not a plain local volume", p.stderr)
                self.assertEqual(runs, [])

    def test_a_bad_volume_argument_is_refused_before_any_docker_call(self):
        for bad in (["amap-hop"], [f"{HOP}="], [f"{HOP}=a"], [f"{HOP}=a,readonly"], [f"{HOP}=-x"], [f"{HOP}=_x"],
                    [f"{HOP}=a/b"], [f"{HOP}=a b"], [f"{HOP}=" + "v" * 129], ["relative=amap-hop"], [""],
                    [f"{HOP}=amap-hop", "--volume", f"{HOP}=amap-hop2"],
                    [f"{HOP}=amap-hop", "--volume", f"{PLUGIN_DIR}=amap-hop"]):
            with self.subTest(bad=bad):
                p, _, runs, inspects = self.run_sh(self.lab.cfg(), "--volume", *bad)
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("run.sh: --volume", p.stderr)
                self.assertEqual((runs, inspects), ([], []))

    def test_a_derive_refusal_stops_run_sh_before_any_docker_call(self):
        p, _, runs, inspects = self.run_sh(self.lab.cfg(), *self.ARGS, "--volume", f"{self.p('state')}=amap-st")
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("not one of this config's hop mounts", p.stderr)
        self.assertEqual((runs, inspects), ([], []))

    def test_the_help_text_shows_the_volume_line_and_stops_before_the_code(self):
        p = subprocess.run([str(RUN_SH), "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("--volume /var/lib/amap/hop=amap-hop", p.stdout)
        self.assertIn("set -euo pipefail", p.stdout)
        self.assertNotIn("HERE=", p.stdout)


if __name__ == "__main__":
    unittest.main()
