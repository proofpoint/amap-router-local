"""`provision.provision` writes only inside the target instance's own
namespace and returns exactly the four env vars the connector's three
tools resolve — see `provision.py`'s module docstring for the names
verified against the real binaries."""

import os
import re
import unittest
from pathlib import Path

from router.provision import (
    ENV_AGENT_ID, ENV_DROPBOX_DIR, ENV_MSG_DIR, ENV_NOTICE_DIR,
    ProvisionError, format_env, provision,
)
from router.tests.helpers import AMP_ROOT, RouterTestCase
from router.util import NamespaceEscapeError

# The connector checkout (sibling to agent-mailbox-protocol, per AMP_ROOT)
# — the three unmodified binaries provision's env vars must match.
# OPTIONAL cross-checkout probe: if a connector package happens to sit
# alongside this repo, verify against its real binaries. Skipped when it
# isn't there, so this suite stands alone.
#
# Resolved by trying each known name in turn rather than hardcoding one, NEWEST
# FIRST: the family renames `amp-connector-claude-code` -> `amap-connector-claude`
# in one flag day, and accepting both means this repo and the connector repo can
# rename independently instead of having to land together. Drop the old name
# once no checkout carries it. `$AMAP_CONNECTOR_REPO`, else `$AMP_CONNECTOR_REPO`,
# overrides for a checkout that lives somewhere else.
#
# Hardcoding one name alone is what made this probe skip silently after the last
# split — the suite stayed green while the one check that compares against the
# real connector stopped running (see `amap-conformance-harness/tests/harness.py`,
# same pattern). So the tuple is EXTENDED for a rename, never swapped.
#
# `amp-connectors` and `connector-reference` were the two pre-split spellings and
# are gone: no checkout has carried either for two splits, so trying them bought
# nothing but the impression of coverage.
def _connector_bin() -> Path:
    for var in ("AMAP_CONNECTOR_REPO", "AMP_CONNECTOR_REPO"):
        env = os.environ.get(var)
        if env:
            root = Path(env).absolute()
            for tail in (("bin",), ("claude-code", "bin")):
                if root.joinpath(*tail).is_dir():
                    return root.joinpath(*tail)
            return root / "bin"
    for name, tail in (("amap-connector-claude", ("bin",)),
                       ("amp-connector-claude-code", ("bin",))):
        cand = AMP_ROOT.parent.joinpath(name, *tail)
        if cand.is_dir():
            return cand
    return AMP_ROOT.parent / "amap-connector-claude" / "bin"


_CONNECTOR_BIN = _connector_bin()


class TestProvision(RouterTestCase):
    def test_env_dict_and_skeleton(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        inbox_root = cfg.instances["alice"].inbox_root
        outbox_root = cfg.instances["alice"].outbox_root

        env = provision(cfg, "alice", create=True)

        # Pin all four env var NAMES to bare literals (not the module's own
        # ENV_* constants) — a rename of a constant's value must fail this
        # test, since matching the names the three unmodified connector
        # binaries actually resolve is the entire point of `provision`.
        self.assertEqual(env, {
            "INBOX_NOTICE_DIR": str(inbox_root / "notices"),
            "INBOX_MESSAGE_DIR": str(inbox_root / "messages"),
            "OUTBOX_DIR": str(outbox_root),
            "MAILBOX_AGENT_ID": "alice",
        })
        # Same result via the module's constants, so both views agree.
        self.assertEqual(env, {
            ENV_NOTICE_DIR: str(inbox_root / "notices"),
            ENV_MSG_DIR: str(inbox_root / "messages"),
            ENV_DROPBOX_DIR: str(outbox_root),
            ENV_AGENT_ID: "alice",
        })

        for leaf in (inbox_root / "notices", inbox_root / "messages",
                     outbox_root, outbox_root / "results", outbox_root / "processed"):
            self.assertTrue(leaf.is_dir(), f"{leaf} missing")

        # v2.2.0: `inbound/notices/processed/` is an OPTIONAL,
        # writable-inbound-only convention — provisioning must never
        # manufacture it, since `inbox_root` is (under `handoff_dir` mode)
        # the host's real `:ro` mount and nothing on either side may depend
        # on this directory's existence.
        self.assertFalse((inbox_root / "notices" / "processed").exists())

    def test_env_names_match_the_live_connector_binaries(self):
        """Stronger than pinning literals in-repo: grep the three unmodified
        connector binaries directly, so a connector-side rename of one of
        these vars breaks the router's test suite rather than silently
        landing in the flatter $MAILBOX_ROOT_DIR/{notices,messages,dropbox}
        fallback (or dying) the first time a real instance is provisioned."""
        if not _CONNECTOR_BIN.is_dir():
            self.skipTest(f"no connector checkout alongside this repo at {_CONNECTOR_BIN}")

        sources = {
            # INBOX_NOTICE_DIR has no connector binary to check against since
            # `inbox-channel` was retired (2026-09-15): the daemon receives the
            # notice dir as AMAP_DELIVERY_MAIL_NOTICE_DIR via the adapter's wrapper.
            "INBOX_MESSAGE_DIR": _CONNECTOR_BIN / "inbox-mcp-vol",
            "OUTBOX_DIR": _CONNECTOR_BIN / "inbox-submit",
            "MAILBOX_AGENT_ID": _CONNECTOR_BIN / "inbox-submit",
        }
        for env_name, binary in sources.items():
            self.assertTrue(binary.is_file(), f"missing connector binary: {binary}")
            text = binary.read_text(encoding="utf-8")
            self.assertIsNotNone(
                re.search(rf'\b{re.escape(env_name)}\b', text),
                f"{env_name!r} not found in {binary.name} — provision()'s env "
                f"var name has drifted from what the connector actually resolves",
            )

    def test_idempotent_second_call(self):
        cfg = self.make_config({"alice": []})
        env1 = provision(cfg, "alice", create=True)
        env2 = provision(cfg, "alice", create=True)
        self.assertEqual(env1, env2)

    def test_unknown_instance_refused(self):
        cfg = self.make_config({"alice": []})
        with self.assertRaises(ProvisionError):
            provision(cfg, "mallory", create=True)

    def test_symlinked_inbound_refused_nothing_created_at_target(self):
        cfg = self.make_config({"alice": []})
        inbox_root = cfg.instances["alice"].inbox_root
        outside = self.tmp / "outside-the-namespace"
        outside.mkdir()

        os.symlink(outside, inbox_root)

        with self.assertRaises(NamespaceEscapeError):
            provision(cfg, "alice", create=True)

        self.assertEqual(list(outside.iterdir()), [])

    def test_no_create_leaves_filesystem_untouched(self):
        cfg = self.make_config({"alice": []})
        inbox_root = cfg.instances["alice"].inbox_root
        outbox_root = cfg.instances["alice"].outbox_root

        env = provision(cfg, "alice", create=False)

        self.assertEqual(env[ENV_AGENT_ID], "alice")
        self.assertFalse(inbox_root.exists())
        self.assertFalse(outbox_root.exists())

    def test_format_env(self):
        cfg = self.make_config({"alice": []})
        env = provision(cfg, "alice", create=False)

        env_text = format_env(env, "env")
        lines = env_text.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith(f"{ENV_NOTICE_DIR}="))
        self.assertTrue(lines[-1].startswith(f"{ENV_AGENT_ID}=alice"))

        json_text = format_env(env, "json")
        import json
        parsed = json.loads(json_text)
        self.assertEqual(parsed, env)

        with self.assertRaises(ValueError):
            format_env(env, "xml")


class TestProvisionHandoffMode(RouterTestCase):
    """The split-root mode: `handoff_dir` -> `inbox_root = P/"inbox"`,
    `outbox_root = P/"outbox"` — must provision, skeleton, and containment-
    check identically to `namespace` mode, just under different leaf names."""

    def test_env_dict_and_skeleton(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]}, mode="handoff")
        inbox_root = cfg.instances["alice"].inbox_root
        outbox_root = cfg.instances["alice"].outbox_root
        root = cfg.instances["alice"].root

        self.assertEqual(inbox_root, root / "inbox")
        self.assertEqual(outbox_root, root / "outbox")

        env = provision(cfg, "alice", create=True)
        self.assertEqual(env, {
            "INBOX_NOTICE_DIR": str(inbox_root / "notices"),
            "INBOX_MESSAGE_DIR": str(inbox_root / "messages"),
            "OUTBOX_DIR": str(outbox_root),
            "MAILBOX_AGENT_ID": "alice",
        })

        for leaf in (inbox_root / "notices", inbox_root / "messages",
                     outbox_root, outbox_root / "results", outbox_root / "processed"):
            self.assertTrue(leaf.is_dir(), f"{leaf} missing")

        # v2.2.0: same non-creation guarantee under handoff mode, where
        # `inbox_root` is the host's real `:ro` mount — a `mkdir` here would
        # fail loud (EROFS) on a live box, but must not even be attempted.
        self.assertFalse((inbox_root / "notices" / "processed").exists())

    def test_symlinked_inbox_refused_nothing_created_at_target(self):
        cfg = self.make_config({"alice": []}, mode="handoff")
        inbox_root = cfg.instances["alice"].inbox_root
        outside = self.tmp / "outside-the-handoff-dir"
        outside.mkdir()

        # The fixture pre-creates this root the way the host does at launch;
        # the attack being modeled is the agent REPLACING it with a symlink.
        inbox_root.rmdir()
        os.symlink(outside, inbox_root)

        with self.assertRaises(NamespaceEscapeError):
            provision(cfg, "alice", create=True)

        self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_outbox_refused_nothing_created_at_target(self):
        """The outbox side is agent-writable in EVERY mode (the host's own
        `outbox` mount is `rw`) — a symlinked `outbox_root` itself, not
        just a leaf beneath it, must be caught too."""
        cfg = self.make_config({"alice": []}, mode="handoff")
        root = cfg.instances["alice"].root
        outbox_root = cfg.instances["alice"].outbox_root
        root.mkdir(parents=True, exist_ok=True)
        outside = self.tmp / "outside-the-handoff-dir-outbox"
        outside.mkdir()

        # The fixture pre-creates this root the way the host does at launch;
        # the attack being modeled is the agent REPLACING it with a symlink.
        outbox_root.rmdir()
        os.symlink(outside, outbox_root)

        with self.assertRaises(NamespaceEscapeError):
            provision(cfg, "alice", create=True)

        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()


class ProvisionRefusesToCreateHostOwnedDirsTest(RouterTestCase):
    """In handoff mode THE HOST owns the two roots — it creates and mounts them at
    launch, only when the host's split-root mode is enabled. Creating them ourselves yields host
    directories that are NOT mounted into the container, so the connector reads
    and writes a tree no agent can ever see: the wiring silently does nothing.
    The host maintainer's guidance says plainly "do not create the directories yourself."
    """

    def _handoff_cfg(self):
        cfg = self.make_config({"alice": []}, mode="handoff")
        return cfg, cfg.instances["alice"]

    def test_missing_inbox_root_refuses_rather_than_creating_it(self):
        cfg, inst = self._handoff_cfg()
        inst.inbox_root.rmdir()          # as if the host had never created the pair
        with self.assertRaises(ProvisionError) as ctx:
            provision(cfg, "alice", create=True)
        msg = str(ctx.exception)
        self.assertIn("the host's split-root mode", msg)
        self.assertIn("RUNBOOK", msg)
        self.assertFalse(inst.inbox_root.exists(), "provision created a dir the host owns")

    def test_missing_outbox_root_refuses(self):
        cfg, inst = self._handoff_cfg()
        inst.outbox_root.rmdir()
        with self.assertRaises(ProvisionError):
            provision(cfg, "alice", create=True)
        self.assertFalse(inst.outbox_root.exists())

    def test_namespace_mode_still_creates_its_own_tree(self):
        """We own the namespace-mode tree, so provision must still build it."""
        cfg = self.make_config({"alice": []})
        inst = cfg.instances["alice"]
        self.assertFalse(inst.inbox_root.exists())
        provision(cfg, "alice", create=True)
        self.assertTrue((inst.inbox_root / "notices").is_dir())
        self.assertTrue((inst.outbox_root / "results").is_dir())

    def test_present_roots_provision_normally(self):
        cfg, inst = self._handoff_cfg()   # fixture pre-creates, as the host does
        env = provision(cfg, "alice", create=True)
        self.assertTrue((inst.inbox_root / "notices").is_dir())
        self.assertTrue((inst.outbox_root / "results").is_dir())
        self.assertEqual(env["MAILBOX_AGENT_ID"], "alice")
