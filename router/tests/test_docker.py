"""docker/ — the container definition, guarded by assertion rather than by care.

These tests do not build an image and do not need docker. They pin the
properties that, when they drift, produce a container that starts cleanly and
is silently wrong — which is the only failure mode worth writing a test for
here. A broken build announces itself; a router that runs happily while never
draining one instance does not.

The manifest rule is the load-bearing one. The sibling amp-simple-email-router
lists each module in its Dockerfile individually, and that is precisely how
this family shipped an image that could not start: `fs_safety.py` was added to
the code and not to the COPY list. A directory copy has no list to forget, so
these tests keep it a directory copy.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

# The mount derivation moved out of run.sh into its own file — see
# DeriveMountsActuallyRunsTest for why. Assertions about its CONTENT follow
# it; the assertions that matter now execute it.
DERIVE_TEXT = (Path(__file__).resolve().parents[2]
               / "docker" / "derive-mounts.py").read_text()

_REPO = Path(__file__).absolute().parents[2]
_DOCKER = _REPO / "docker"


def _read(name: str) -> str:
    p = _DOCKER / name
    if not p.is_file():
        raise unittest.SkipTest(f"{p} not present")
    return p.read_text(encoding="utf-8")


def _code(name: str) -> str:
    """`_read` with comment lines removed. A flag NAMED in a comment — often
    to say it is deliberately absent — is not a flag USED, and asserting
    against the raw text makes the comment explaining an absence fail the test
    that checks for it."""
    return "\n".join(ln for ln in _read(name).splitlines()
                     if not ln.lstrip().startswith("#"))


class DockerfileManifestTests(unittest.TestCase):
    def test_router_package_is_copied_as_a_directory(self):
        """The anti-manifest guard. `COPY router/ /app/router/` cannot omit a
        module; a per-file list can, and did, in the sibling repo."""
        text = _read("Dockerfile")
        self.assertRegex(
            text, r"(?m)^COPY\s+router/\s+/app/router/\s*$",
            msg="the Dockerfile must copy the router package as a DIRECTORY")

    def test_no_per_module_copy_lines(self):
        """Catches a well-meaning 'be explicit' refactor that reintroduces the
        exact defect the directory copy exists to prevent."""
        text = _read("Dockerfile")
        per_module = re.findall(r"^COPY\s+router/\S+\.py\b.*$", text, re.M)
        self.assertEqual(
            per_module, [],
            msg="per-module COPY lines reintroduce the manifest that can be "
                "forgotten; copy the package directory instead")

    def test_every_router_module_reaches_the_image(self):
        """A directory copy is only sufficient if .dockerignore does not carve
        modules back out of it."""
        ignore = _read(".dockerignore")
        excluded = [ln.strip() for ln in ignore.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]
        modules = sorted(p.name for p in (_REPO / "router").glob("*.py"))
        self.assertIn("__main__.py", modules)          # sanity: we found the package
        for pattern in excluded:
            for mod in modules:
                self.assertFalse(
                    pattern == f"router/{mod}",
                    msg=f".dockerignore excludes router/{mod} from the image")

    def test_tests_are_kept_out_of_the_image(self):
        ignore = _read(".dockerignore")
        self.assertIn("router/tests/", ignore)

    def test_user_is_not_pinned(self):
        """Every mount is a bind mount of host directories owned by the host
        user, and the agent side runs as that same uid. A pinned USER would
        write root-owned notices into the operator's home directory."""
        text = _read("Dockerfile")
        self.assertNotRegex(text, r"(?m)^USER\s+\S")


class NoCredentialsNoNetworkTests(unittest.TestCase):
    """The two properties that distinguish this runtime from a mail-carrying
    one. Both are claims the README makes; these keep the container honest
    about them."""

    def test_run_sh_disables_networking(self):
        self.assertIn("--network none", _code("run.sh"))

    def test_run_sh_takes_no_env_file(self):
        """No secrets exist to pass. An --env-file appearing here means the
        provider-free property has quietly stopped being true."""
        self.assertNotIn("--env-file", _code("run.sh"))

    def test_dockerfile_bakes_no_credentials(self):
        text = _read("Dockerfile").lower()
        for token in ("password", "secret", "token", "smtp_", "imap_", "api_key"):
            self.assertNotIn(
                f"env {token}", text,
                msg=f"{token!r} looks like a credential baked into the image")

    def test_run_sh_runs_as_the_invoking_user(self):
        self.assertIn('--user "$(id -u):$(id -g)"', _code("run.sh"))


class WhatTheEntrypointMayRunTests(unittest.TestCase):
    """The entrypoint used to carry a REFUSAL case for `approve`, because a
    restart policy could re-run it and silently retake the snapshot that gate
    hung off. `approve` is retired and the snapshot is taken by the drain
    itself and persisted, so the refusal is gone with the command — and the
    mention has to go with it, or the file advertises a subcommand the CLI
    would reject."""

    def test_no_dispatchable_mode_names_the_retired_command(self):
        """Scoped to the SCRIPT BODY, not the whole file: the header comment
        says why the refusal was removed and has to keep saying `approve` to
        say it. A whole-file assertion would fail on that sentence, and the
        obvious repair — deleting the sentence — loses the only record of why
        the case went away."""
        body = _read("entrypoint.sh").split("set -euo pipefail", 1)[1]
        self.assertNotIn("approve", body,
                         msg="entrypoint.sh still dispatches or names `approve`")

    def test_entrypoint_modes_are_read_only_or_drain(self):
        text = _read("entrypoint.sh")
        for mode in ("run)", "once)", "peers)", "status)"):
            self.assertIn(mode, text)
        for forbidden in ("reset)",):
            self.assertNotIn(
                forbidden, text,
                msg="reset is destructive and evidence-destroying; keep it on the host")


class MountDerivationTests(unittest.TestCase):
    """run.sh computes mounts from the config rather than taking a hand-written
    list. A missing instance mount does not crash the router — it starts, looks
    healthy, and never drains that agent."""

    def test_mounts_are_derived_from_the_config(self):
        text = _read("run.sh")
        self.assertIn("--config", text)
        self.assertIn("instances", DERIVE_TEXT)
        self.assertIn("state_dir", text)

    def test_missing_paths_fail_before_docker_run(self):
        text = _read("run.sh")
        self.assertIn("do not exist", DERIVE_TEXT)

    def test_config_is_mounted_read_only(self):
        self.assertIn(':ro"', _read("run.sh"))


if __name__ == "__main__":
    unittest.main()


class DeriveMountsActuallyRunsTest(unittest.TestCase):
    """`docker/derive-mounts.py`, EXECUTED — not asserted about as text.

    Every other test in this file reads file contents. That is why run.sh
    shipped broken and stayed broken until the first real execution: its mount
    derivation lived in a heredoc inside `$( ... )`, the refusal message gained
    backticks, and a backtick inside a command substitution sends the shell
    looking for a closing backtick instead of the closing paren. `bash -n`
    passes it. Only running it fails.
    """

    SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "derive-mounts.py"

    def _run(self, cfg: dict):
        with TemporaryDirectory() as d:
            for name, spec in (cfg.get("instances") or {}).items():
                root = spec.get("handoff_dir") or spec.get("namespace")
                if root and root.startswith("MAKE:"):
                    real = Path(d) / name
                    real.mkdir(parents=True, exist_ok=True)
                    spec[("handoff_dir" if "handoff_dir" in spec else "namespace")] = str(real)
            sd = Path(d) / "state"
            sd.mkdir(exist_ok=True)
            if cfg.get("state_dir") == "MAKE:":
                cfg["state_dir"] = str(sd)
            f = Path(d) / "r.json"
            f.write_text(json.dumps(cfg))
            return subprocess.run([sys.executable, str(self.SCRIPT), str(f)],
                                  capture_output=True, text=True)

    def test_it_emits_one_tab_separated_line_per_mount(self):
        r = self._run({"state_dir": "MAKE:", "instances": {
            "alice": {"handoff_dir": "MAKE:alice"}, "bob": {"handoff_dir": "MAKE:bob"}}})
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        self.assertEqual(len(lines), 3, lines)          # state_dir + two instances
        for l in lines:
            path, mode = l.split("\t")
            self.assertTrue(path.startswith("/"), path)
            self.assertIn(mode, ("rw", "ro"))

    def test_a_missing_path_is_refused_with_the_operator_message(self):
        r = self._run({"state_dir": "MAKE:",
                       "instances": {"alice": {"handoff_dir": "/nope/does/not/exist"}}})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("do not exist", r.stderr)
        self.assertIn("launch-enrolled-once.py", r.stderr)   # the backticked prose

    def test_no_instances_is_refused(self):
        r = self._run({"state_dir": "MAKE:", "instances": {}})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("drain nothing", r.stderr)

    def test_run_sh_invokes_the_script_rather_than_a_heredoc(self):
        """The structural guard. A heredoc here would reintroduce the bug the
        moment someone adds a backtick to a message."""
        run_sh = (Path(__file__).resolve().parents[2] / "docker" / "run.sh").read_text()
        self.assertIn("derive-mounts.py", run_sh)
        self.assertNotIn("python3 - \"$CONFIG_ABS\" <<", run_sh)


class RunShDetachedActuallyRunsTest(unittest.TestCase):
    """`docker/run.sh --detach`, EXECUTED, with a fake `docker` on PATH.

    Same lesson as DeriveMountsActuallyRunsTest, one shell construct along.
    The detached path expanded `"${MODE_ARGS[@]}"` on an array that is empty in
    exactly that mode — detached is the mode with no trailing args, the
    entrypoint's own default being the point. Bash before 4.4 calls expanding
    an empty array under `set -u` an unbound variable; declaring it is not
    enough, and macOS still ships 3.2.57 as /bin/bash. So the one path an
    operator runs once and leaves running was the only path that could not
    start on a stock mac, while `-- once` filled the array and passed all day.
    `bash -n` is silent on it. On bash 4.4+ so is execution — which is why the
    static assertion below carries the regression guard and this test carries
    the argv contract.

    `TTY` is the same shape: empty whenever stdin is not a terminal, so cron,
    CI and any harness that redirects hit it on the foreground path.
    """

    RUN_SH = Path(__file__).resolve().parents[2] / "docker" / "run.sh"

    def _lab(self, d):
        root, state = Path(d) / "alice", Path(d) / "state"
        root.mkdir(), state.mkdir()
        cfg = Path(d) / "router.json"
        cfg.write_text(json.dumps({"state_dir": str(state),
                                   "instances": {"alice": {"handoff_dir": str(root)}}}))
        return cfg, root, state

    def _fake_docker(self, d):
        """Records every invocation; `check-stale.py` calls docker too."""
        bin_dir, out = Path(d) / "bin", Path(d) / "argv"
        bin_dir.mkdir()
        fake = bin_dir / "docker"
        fake.write_text("#!/usr/bin/env bash\n"
                        'for a in "$@"; do printf "%s\\n" "$a"; done\n'
                        'printf -- "--END--\\n"\n'
                        "exit 0\n")
        fake.chmod(0o755)
        return bin_dir, out

    def _argv(self, *args, stdin=subprocess.DEVNULL):
        with TemporaryDirectory() as d:
            cfg, _, _ = self._lab(d)
            bin_dir, out = self._fake_docker(d)
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
            p = subprocess.run([str(self.RUN_SH), "--config", str(cfg), *args],
                               capture_output=True, text=True, stdin=stdin, env=env)
            blocks = [b.splitlines() for b in p.stdout.split("--END--\n") if b.strip()]
            runs = [b for b in blocks if b and b[0] == "run"]
            return p, runs

    def test_detached_reaches_docker_at_all(self):
        """The bug this pins: run.sh died before `docker run` was ever built."""
        p, runs = self._argv("--name", "amp-test", "--detach")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("unbound variable", p.stderr)
        self.assertEqual(len(runs), 1, p.stderr)
        # `-d`, or this passes on the foreground path and says nothing about
        # the mode it is named for.
        self.assertIn("-d", runs[0])

    def test_detached_passes_no_mode_args_after_the_image(self):
        """Detached means the entrypoint's default. A stray empty string here
        would reach the entrypoint as an unknown mode."""
        _, runs = self._argv("--name", "amp-test", "--detach")
        argv = runs[0]
        self.assertEqual(argv[-1], "amap-router-local",
                         "the image must be the last argument, with nothing after it")
        for flag in ("-d", "--restart", "unless-stopped", "--network", "none"):
            self.assertIn(flag, argv)

    def test_the_foreground_path_survives_a_non_terminal_stdin(self):
        """TTY is empty whenever stdin is not a terminal — the cron/CI shape."""
        p, runs = self._argv("--name", "amp-test", "--", "once")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("unbound variable", p.stderr)
        self.assertEqual(runs[0][-1], "once")
        self.assertNotIn("-t", runs[0])

    def test_mode_args_still_reach_the_container(self):
        """The guard must not silently swallow what it is guarding."""
        _, runs = self._argv("--name", "amp-test", "--", "peers")
        self.assertEqual(runs[0][-1], "peers")

    def test_the_empty_array_guard_is_spelled_out_in_the_source(self):
        """The behavioural tests above pass on bash 4.4+ WITH OR WITHOUT the
        fix — the failure only appears on the older bash the operator has. So
        the regression guard has to be textual, or a revert rides through CI
        and breaks exactly one class of host."""
        code = _code("run.sh")
        for var in ("MODE_ARGS", "TTY"):
            with self.subTest(var=var):
                guarded = "${%s[@]+\"${%s[@]}\"}" % (var, var)
                self.assertIn(guarded, code,
                              f"{var} is legitimately empty; expand it with the "
                              f"${{arr[@]+...}} guard so `set -u` on bash 3.2 survives it")
                # The guard CONTAINS the bare form, so strip every guarded
                # occurrence before asking whether a bare one survives.
                # Asserting against the raw text passes trivially and would
                # have said nothing about a half-applied fix.
                self.assertNotIn('"${%s[@]}"' % var, code.replace(guarded, ""),
                                 f"the unguarded expansion of {var} is the macOS bug")


class StalenessWarningTest(unittest.TestCase):
    """The image BAKES the source (`COPY router/ /app/router/`), so a container
    can run code that predates the operator's edits — correctly, silently, and
    identically to a working system. This is the advisory that says so."""

    SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "check-stale.py"

    def _run(self, image="amap-router-local", created=None, newest=None):
        """Drive the two pure functions directly; `docker` is not available in
        this environment and mocking it would test the mock."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("_cs", self.SCRIPT)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_source_newer_than_image_warns_and_exits_1(self):
        m = self._run()
        m.image_created = lambda image: 1000.0
        m.newest_source = lambda root: (2000.0, Path(__file__))
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = m.main(["check-stale.py", "amap-router-local"])
        self.assertEqual(rc, 1)
        self.assertIn("BAKES the source", buf.getvalue())
        self.assertIn("docker/build.sh", buf.getvalue())

    def test_image_newer_than_source_is_silent(self):
        m = self._run()
        m.image_created = lambda image: 9000.0
        m.newest_source = lambda root: (1000.0, Path(__file__))
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = m.main(["check-stale.py", "amap-router-local"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue(), "")

    def test_unknown_answer_is_never_a_gate(self):
        """No docker, no such image, unparseable timestamp — all exit 0. An
        advisory that blocks on its own uncertainty is worse than none."""
        m = self._run()
        m.newest_source = lambda root: (2000.0, Path(__file__))
        for created in (None,):
            m.image_created = lambda image: created
            self.assertEqual(m.main(["check-stale.py", "x"]), 0)

    def test_nanosecond_timestamps_parse(self):
        """Docker emits RFC3339 with nanoseconds, which `fromisoformat` rejects
        on older Pythons. Truncation is why this is not version-dependent."""
        m = self._run()
        import subprocess as sp
        real = sp.run
        m.subprocess.run = lambda *a, **k: type(
            "R", (), {"returncode": 0, "stdout": "2026-08-24T19:39:05.123456789Z"})()
        try:
            self.assertIsNotNone(m.image_created("x"))
        finally:
            m.subprocess.run = real

    def test_run_sh_consults_it_without_gating(self):
        run_sh = (Path(__file__).resolve().parents[2] / "docker" / "run.sh").read_text()
        self.assertIn("check-stale.py", run_sh)
        self.assertIn('"$HERE/check-stale.py" "$IMAGE" || true', run_sh)


class DeriveMountsUnderDiscoveryTests(unittest.TestCase):
    """`derive-mounts.py` under a discovery sibling.

    The container's mount set is FIXED at `docker run`, so what this derives
    decides whether a fleet can gain an instance without a restart — which is
    the entire point of discovery.
    """

    def _derive(self, doc):
        import json as _json
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for rel in ("state", "features/amap/instances", "intake"):
                (tmp / rel).mkdir(parents=True, exist_ok=True)
            (tmp / "features/amap/selected.json").write_text("{}")
            rendered = _json.dumps({k: (str(tmp / v) if k.endswith(("_dir", "_json"))
                                        else v)
                                    for k, v in doc.items()})
            cfg = tmp / "router.json"
            cfg.write_text(rendered)
            out = subprocess.run([str(_REPO / "docker" / "derive-mounts.py"), str(cfg)],
                                 capture_output=True, text=True)
            return out.returncode, [l.split("\t") for l in out.stdout.splitlines()], out.stderr

    def test_a_discovery_config_derives_mounts_at_all(self):
        """It used to exit with "config has no instances" — `run.sh` could not
        start a container against a sibling at all."""
        rc, mounts, err = self._derive({
            "state_dir": "state", "instances_dir": "features/amap/instances",
            "selected_json": "features/amap/selected.json"})
        self.assertEqual(rc, 0, err)
        self.assertTrue(mounts)

    def test_the_instance_tree_is_ONE_mount_not_one_per_instance(self):
        """Per-instance mounts would put the restart back: a container's
        mount set is fixed at `docker run`, so a new sandbox would need a
        re-render and a restart — exactly what discovery removes."""
        rc, mounts, err = self._derive({
            "state_dir": "state", "instances_dir": "features/amap/instances",
            "selected_json": "features/amap/selected.json"})
        trees = [p for p, _m in mounts if p.endswith("/instances")]
        self.assertEqual(len(trees), 1)

    def test_the_verdict_is_mounted_BY_DIRECTORY_never_as_a_file(self):
        """The host publishes `selected.json` with temp-file + rename, so the
        path gets a NEW INODE on every write. A file bind-mount binds the
        inode it found at `docker run`: after the first rename the container
        reads the ORIGINAL file forever — a stale verdict that parses, admits
        the membership of an hour ago, and looks healthy."""
        rc, mounts, err = self._derive({
            "state_dir": "state", "instances_dir": "features/amap/instances",
            "selected_json": "features/amap/selected.json"})
        paths = [p for p, _m in mounts]
        self.assertNotIn(
            [p for p in paths if p.endswith("selected.json")], [[p] for p in paths],
            "selected.json must not be mounted as a file")
        self.assertTrue(any(p.endswith("/features/amap") for p in paths),
                        "its directory must be mounted instead")

    def test_a_parent_is_always_emitted_BEFORE_its_children(self):
        """run.sh emits these as `-v` flags in order and docker applies them
        in order. A parent mounted AFTER its child SHADOWS it — the rw
        instance tree would vanish behind a ro mount of its own parent and
        every delivery would fail on a read-only filesystem.

        The first version of the discovery branch emitted the child first,
        because that was the order the code read in."""
        rc, mounts, err = self._derive({
            "state_dir": "state", "instances_dir": "features/amap/instances",
            "selected_json": "features/amap/selected.json",
            "intake_dir": "intake"})
        paths = [p for p, _m in mounts]
        for i, child in enumerate(paths):
            for j, parent in enumerate(paths):
                if child != parent and child.startswith(parent.rstrip("/") + "/"):
                    with self.subTest(parent=parent, child=child):
                        self.assertLess(j, i,
                                        f"{parent} is mounted after its child {child} "
                                        f"and would shadow it")

    def test_instances_dir_without_a_verdict_is_refused(self):
        rc, mounts, err = self._derive({
            "state_dir": "state", "instances_dir": "features/amap/instances"})
        self.assertNotEqual(rc, 0)
        self.assertIn("selected_json", err + "".join(p for p, _ in mounts))

    def test_both_sources_together_is_refused(self):
        rc, mounts, err = self._derive({
            "state_dir": "state", "instances_dir": "features/amap/instances",
            "selected_json": "features/amap/selected.json",
            "instances": {"a-deadbeef": {"handoff_dir": "/tmp/nope"}}})
        self.assertNotEqual(rc, 0)
