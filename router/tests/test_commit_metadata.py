"""`tools/check_commit_metadata.py`: every commit reachable from HEAD carries
a no-reply author and committer.

Each test builds a throwaway repository with exact identities, so the
checker is proved against histories it can be wrong about, not only against
this repository's own. Every planted address is synthetic (assembled at
run time so this file contains none whole).
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "check_commit_metadata.py"

_spec = importlib.util.spec_from_file_location("check_commit_metadata", TOOL)
cm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm)

CLEAN = ("Someone", "12345+someone" + "@" + "users.noreply.github.com")
WEB = ("GitHub", "noreply" + "@" + "github.com")
PLANTED = "jane.doe" + "@" + "mail.example-isp.net"


@unittest.skipUnless(shutil.which("git"), "git is required")
class CheckerTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = self._tmp.name
        self.git("init", "-q", "-b", "main")

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args, author=CLEAN, committer=None):
        committer = committer or author
        env = dict(os.environ,
                   GIT_AUTHOR_NAME=author[0], GIT_AUTHOR_EMAIL=author[1],
                   GIT_COMMITTER_NAME=committer[0], GIT_COMMITTER_EMAIL=committer[1],
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        return subprocess.run(["git", "-C", self.repo, *args], env=env,
                              capture_output=True, check=True).stdout.decode()

    def commit(self, msg, **kw):
        Path(self.repo, msg).write_text(msg)
        self.git("add", msg, **kw)
        self.git("commit", "-q", "-m", msg, **kw)
        return self.git("rev-parse", "HEAD").strip()

    def run_tool(self):
        return subprocess.run([sys.executable, str(TOOL), self.repo],
                              capture_output=True, text=True)

    # -- the twin every failure is measured against ----------------------

    def test_noreply_author_and_github_web_committer_pass(self):
        self.commit("one")
        self.commit("two", author=CLEAN, committer=WEB)
        out = self.run_tool()
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("2 commit(s) checked, 0 finding(s)", out.stdout)

    # -- planted identities ------------------------------------------------

    def test_a_personal_author_fails_and_is_redacted(self):
        self.commit("one")
        sha = self.commit("two", author=("Jane", PLANTED), committer=CLEAN)
        out = self.run_tool()
        self.assertEqual(out.returncode, 1)
        self.assertIn(f"commit {sha[:12]} author", out.stdout)
        self.assertNotIn(PLANTED, out.stdout + out.stderr)
        self.assertIn("value redacted", out.stdout)

    def test_a_personal_committer_fails_and_is_redacted(self):
        sha = self.commit("one", author=CLEAN, committer=("Jane", PLANTED))
        out = self.run_tool()
        self.assertEqual(out.returncode, 1)
        self.assertIn(f"commit {sha[:12]} committer", out.stdout)
        self.assertNotIn(PLANTED, out.stdout + out.stderr)

    def test_an_old_commit_deep_in_history_is_caught(self):
        self.commit("one", author=("Jane", PLANTED))
        for i in range(5):
            self.commit(f"later{i}")
        self.assertEqual(self.run_tool().returncode, 1)

    def test_a_merge_commits_own_identity_is_checked(self):
        """CI's HEAD on a pull request is a merge commit nobody wrote by
        hand; its identity is reachable from HEAD and checked like any."""
        self.commit("base")
        self.git("checkout", "-q", "-b", "side")
        self.commit("side")
        self.git("checkout", "-q", "main")
        self.commit("main2")
        self.git("merge", "-q", "--no-ff", "-m", "merge", "side",
                 author=("Jane", PLANTED), committer=WEB)
        merge = self.git("rev-parse", "HEAD").strip()
        out = self.run_tool()
        self.assertEqual(out.returncode, 1)
        self.assertIn(f"commit {merge[:12]} author", out.stdout)

    def test_lookalike_domains_are_refused(self):
        for bad in ("x" + "@" + "users.noreply.github.com.example-isp.net",
                    "x" + "@" + "sub.users.noreply.github.com",
                    "noreply" + "@" + "github.com.example-isp.net",
                    "@" + "users.noreply.github.com",
                    ""):
            with self.subTest(email=bad):
                self.assertFalse(cm.email_allowed(bad))

    # -- the empty answer is not a clean one ------------------------------

    def test_a_repository_with_no_commits_fails_loudly(self):
        out = self.run_tool()
        self.assertEqual(out.returncode, 2)

    def test_an_empty_history_is_not_clean(self):
        """The second producer of exit 2 above is git refusing `HEAD`; this
        pins the checker's own refusal of an empty answer."""
        from unittest import mock
        with mock.patch.object(cm, "identities", return_value=[]):
            self.assertEqual(cm.main([self.repo]), 2)

    def test_the_exception_list_is_exact(self):
        """Only the one decided exception, as a full sha; the hook matches
        whole shas only."""
        self.assertEqual(cm.EXCEPTED_SHAS,
                         frozenset({"a6d03d918369d33f25c01cba46726549fd17456c"}))
        for sha in cm.EXCEPTED_SHAS:
            self.assertRegex(sha, r"^[0-9a-f]{40}$")
        sha = self.commit("one", author=("Jane", PLANTED), committer=CLEAN)
        rows = cm.identities(self.repo)
        self.assertEqual(len(cm.findings(rows)), 1)
        original = cm.EXCEPTED_SHAS
        try:
            cm.EXCEPTED_SHAS = frozenset({sha[:12]})
            self.assertEqual(len(cm.findings(rows)), 1, "a prefix must not exempt")
            cm.EXCEPTED_SHAS = frozenset({sha})
            self.assertEqual(cm.findings(rows), [])
        finally:
            cm.EXCEPTED_SHAS = original


if __name__ == "__main__":
    unittest.main()
