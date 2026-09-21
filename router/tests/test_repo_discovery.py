"""The two by-name sibling-checkout probes, pinned.

`helpers._spec_root()` locates the spec checkout and
`test_provision._connector_bin()` locates the connector's `bin/`. Both accept
two spellings, because the family renames `agent-mailbox-protocol` ->
`amap-spec` and `amp-connector-claude-code` -> `amap-connector-claude` in one
flag day and the repos must be able to rename independently.

WHY THIS FILE EXISTS. The comment in `test_provision.py` records what happened
the last time one of these probes carried a single hardcoded name: the name
changed, the probe stopped finding anything, and it SKIPPED. The suite stayed
green while the one check that compares against the real connector had quietly
stopped running. Nothing failed, because a probe that cannot find its target
is indistinguishable from one whose target is legitimately absent.

That is the inverse of the mutation-testing rule the repo runs on: not a guard
that cannot fail, but a check that cannot pass, silently. The only defence is
to test the RESOLVER rather than the thing it resolves — which is what this
file does, in-process, against a scratch tree. It needs no checkout of
anything, so unlike the probes themselves it runs identically in a bare
sandbox and beside a full workbench.

`_spec_root()` reads the module global `__file__` at call time, so pointing
`helpers.__file__` at a fabricated path relocates its depth-3 lookup into a
temporary directory. Nothing here reads, writes, or depends on a real sibling
checkout.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from router.tests import helpers
from router.tests import test_provision

# Every environment variable either resolver consults. Cleared for each test:
# an operator who really has one of these exported must not change what these
# tests prove, in either direction.
_DISCOVERY_VARS = (
    "AMAP_SPEC_REPO", "AMP_SPEC_REPO",
    "AMAP_CONNECTOR_REPO", "AMP_CONNECTOR_REPO",
)


class _DiscoveryTestCase(unittest.TestCase):
    """A scratch siblings directory, plus env and module-global isolation."""

    def setUp(self) -> None:
        ctx = tempfile.TemporaryDirectory()
        self.addCleanup(ctx.cleanup)
        #: stands in for the directory that holds the sibling checkouts
        self.siblings = Path(ctx.name) / "dev"
        self.siblings.mkdir()
        self.env()

    def env(self, **values: str) -> None:
        """Replace `os.environ` with one carrying none of `_DISCOVERY_VARS`
        except those given. Restored on cleanup."""
        env = {k: v for k, v in os.environ.items() if k not in _DISCOVERY_VARS}
        env.update(values)
        patch = mock.patch.dict(os.environ, env, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def checkout(self, *parts: str) -> Path:
        """Create (and return) a directory under the scratch siblings dir."""
        path = self.siblings.joinpath(*parts)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def at_depth(self, repo_dir_name: str = "amp-local-router") -> None:
        """Point `helpers.__file__` at `<siblings>/<repo>/router/tests/
        helpers.py`, so `_spec_root()`'s `parents[3]` lands on the scratch
        siblings dir. Restored on cleanup."""
        fake = self.siblings / repo_dir_name / "router" / "tests" / "helpers.py"
        patch = mock.patch.object(helpers, "__file__", str(fake))
        patch.start()
        self.addCleanup(patch.stop)


class SpecRootTests(_DiscoveryTestCase):
    """`helpers._spec_root()` — the resolver behind `AMP_ROOT`."""

    def setUp(self) -> None:
        super().setUp()
        self.at_depth()

    def test_new_name_wins_when_both_are_present(self):
        self.checkout("agent-mailbox-protocol")
        self.checkout("amap-spec")
        self.assertEqual(helpers._spec_root(), self.siblings / "amap-spec")

    def test_old_name_is_found_when_only_it_is_present(self):
        """The two repos rename independently; this is the whole point of
        accepting both. Before the flag day only this name exists."""
        self.checkout("agent-mailbox-protocol")
        self.assertEqual(
            helpers._spec_root(), self.siblings / "agent-mailbox-protocol")

    def test_new_name_is_found_when_only_it_is_present(self):
        """And after the flag day, only this one does."""
        self.checkout("amap-spec")
        self.assertEqual(helpers._spec_root(), self.siblings / "amap-spec")

    def test_neither_present_falls_back_to_the_post_rename_name(self):
        """Fires only when the spec checkout is absent ENTIRELY, so the
        failure it produces should name what a checkout will be called from
        the flag day on — that is the actionable message."""
        self.assertEqual(helpers._spec_root(), self.siblings / "amap-spec")

    def test_absent_spec_still_yields_a_path_so_callers_FAIL_not_skip(self):
        """`test_validate_fixtures` asserts the fixtures directory exists. A
        resolver returning `None` (or raising) on absence would turn that
        assertion into an error about the resolver, or tempt a caller into
        skipping. It must return a path that simply is not there."""
        root = helpers._spec_root()
        self.assertIsInstance(root, Path)
        self.assertFalse(root.exists())

    def test_amp_spec_repo_env_beats_the_by_name_lookup(self):
        self.checkout("amap-spec")
        elsewhere = self.checkout("somewhere-else")
        self.env(AMP_SPEC_REPO=str(elsewhere))
        self.assertEqual(helpers._spec_root(), elsewhere)

    def test_amap_spec_repo_env_beats_amp_spec_repo(self):
        new = self.checkout("new-env")
        old = self.checkout("old-env")
        self.env(AMAP_SPEC_REPO=str(new), AMP_SPEC_REPO=str(old))
        self.assertEqual(helpers._spec_root(), new)

    def test_lookup_is_keyed_on_depth_not_on_this_repo_s_own_name(self):
        """This repo is itself renamed in the same flag day
        (`amp-local-router` -> `amap-router-local`), and is also reached
        through a workspace symlink under a third name. The depth-3
        arithmetic must not care which."""
        self.checkout("amap-spec")
        for repo_dir in ("amp-local-router", "amap-router-local", "checkout"):
            with self.subTest(repo_dir=repo_dir):
                self.at_depth(repo_dir)
                self.assertEqual(
                    helpers._spec_root(), self.siblings / "amap-spec")


class ConnectorBinTests(_DiscoveryTestCase):
    """`test_provision._connector_bin()` — the optional cross-checkout probe
    whose ancestor is the one that skipped silently."""

    def setUp(self) -> None:
        super().setUp()
        # `_connector_bin` reads its module's `AMP_ROOT` and uses `.parent`,
        # so any child of the scratch siblings dir puts the search there.
        patch = mock.patch.object(
            test_provision, "AMP_ROOT", self.siblings / "amap-spec")
        patch.start()
        self.addCleanup(patch.stop)

    def test_new_name_wins_when_both_are_present(self):
        self.checkout("amp-connector-claude-code", "bin")
        expected = self.checkout("amap-connector-claude", "bin")
        self.assertEqual(test_provision._connector_bin(), expected)

    def test_old_name_is_found_when_only_it_is_present(self):
        expected = self.checkout("amp-connector-claude-code", "bin")
        self.assertEqual(test_provision._connector_bin(), expected)

    def test_neither_present_falls_back_to_the_post_rename_repo(self):
        self.assertEqual(
            test_provision._connector_bin(),
            self.siblings / "amap-connector-claude" / "bin")

    def test_amp_connector_repo_env_is_still_honoured(self):
        self.checkout("amap-connector-claude", "bin")
        root = self.checkout("elsewhere", "bin").parent
        self.env(AMP_CONNECTOR_REPO=str(root))
        self.assertEqual(test_provision._connector_bin(), root / "bin")

    def test_amap_connector_repo_env_beats_amp_connector_repo(self):
        new = self.checkout("new-env", "bin").parent
        old = self.checkout("old-env", "bin").parent
        self.env(AMAP_CONNECTOR_REPO=str(new), AMP_CONNECTOR_REPO=str(old))
        self.assertEqual(test_provision._connector_bin(), new / "bin")

    def test_env_override_accepts_either_repo_shape(self):
        """A checkout given by env may be the connector repo itself (`bin/`)
        or the multi-connector layout (`claude-code/bin/`)."""
        flat = self.checkout("flat", "bin").parent
        nested = self.checkout("nested", "claude-code", "bin").parents[1]
        self.env(AMAP_CONNECTOR_REPO=str(flat))
        self.assertEqual(test_provision._connector_bin(), flat / "bin")
        self.env(AMAP_CONNECTOR_REPO=str(nested))
        self.assertEqual(
            test_provision._connector_bin(), nested / "claude-code" / "bin")


if __name__ == "__main__":
    unittest.main()
