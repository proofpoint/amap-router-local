"""router/provision.py — provisioning helper: env vars + skeleton dirs for
wiring a configured instance's two roots to the connector.

Writes ONLY inside the instance's own declared root (`handoff_dir` or
`namespace` — the AMAP §2-canonical skeleton, split across the two derived
roots) and prints/returns the four env vars the connector side resolves
independently — `INBOX_NOTICE_DIR` (the notice directory; under sandy the
adapter's wrapper hands it to `inbox-delivery` as `AMAP_DELIVERY_MAIL_NOTICE_DIR`),
`inbox-mcp-vol` (`INBOX_MESSAGE_DIR`), `inbox-submit` (`OUTBOX_DIR`,
`MAILBOX_AGENT_ID`) — see each binary's own resolution order, cited in
`router/README.md`'s "Layout" table. `MAILBOX_ROOT_DIR` is deliberately never
set: the explicit vars override it anyway, and leaving it unset
means a missing explicit var fails loud (the connector's own behavior)
instead of silently landing in the flatter `$MAILBOX_ROOT_DIR/{notices,messages,
dropbox}` layout.

Since the peer lane (AMAP 3.1.0 peer-origin profile), provisioning a
handoff-mode instance in a fleet with a `fleet_domain` ALSO creates the peer
tree, `<handoff_dir>/peer/{notices,messages}` — and, unlike the host's
`inbox`/`outbox` pair, creates `peer/` ITSELF: it is router-owned, not a
host mount source, so the "refuse to create host-owned dirs" rule does not
apply to it

**UNDER DISCOVERY THAT SENTENCE IS FALSE AND THIS COMMAND CREATES NOTHING
IN THE INSTANCE TREE.** A feature manifest declares `peer` as a mount
alongside `inbox` and `outbox` and creates all three itself, so `peer/` IS a
host mount source there and creating it here would produce exactly what the
rule below warns about for the other two: a directory not mounted into the
container, which this router fills with peer notices no agent can ever see.
The rule did not gain an exception — the exception lost its reason. Only
creation retires; the env-var report stays, because nothing else answers
"what do I wire into this sandbox (the adapter mounts it read-only into the container AFTER this
runs, which is why the adapter runs `provision` between sandy launch and
enrolment). When `intake_dir` is configured, `<intake_dir>/<instance>/` is
created too. Neither is in the four env vars — the daemon does not read
them — so `report()` carries them, and `--format json` prints the report:

    {
      "INBOX_NOTICE_DIR": ..., "INBOX_MESSAGE_DIR": ..., "OUTBOX_DIR": ...,
      "MAILBOX_AGENT_ID": "<name>",              # the four env vars, as before
      "address":        "<name>@<fleet_domain>"  | "agent.<name>@local",
      "router_address": "amap.router@<fleet_domain>" | null,
      "peer":   {"root": ..., "notices": ..., "messages": ...} | null,
      "intake": "<intake_dir>/<name>" | null
    }

`peer` is null for a namespace-mode instance (never a peer target) and for
a fleet without a domain; `intake` is null without `intake_dir`. The `env`
format stays exactly the four connector variables.

This module never touches the host's own state directory, `~/.claude*`, or any host-side
file. The host placement facts below are DOCUMENTATION ONLY (verified,
SCOPE.md "Provisioning facts") — provisioning around them, by hand, is
left to the operator:

  - The per-sandbox user config is a SIBLING file,
    `<sandbox-dir>.claude.json` (mounted at a fixed point) —
    NOT inside the sandbox directory tree itself.
  - The host strips the `projects` key on first seed and re-applies
    `tipsDisabled`/`installMethod`/trust entries on every launch —
    provision AROUND those keys when hand-editing that file, don't fight
    them.
  - `~/.claude/plugins/` is inside the mounted `claude/` dir, so a plugin
    dropped host-side at `<sandbox-dir>/claude/plugins/` is
    picked up without touching the workspace.
  - `.claude/{commands,agents,plugins}` are writable overlays, not `:ro`
    — don't assume everything under `.claude/` is protected.

This tool intentionally writes none of the above.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from .config import LANE_INBOX, LANE_LEAVES, LANE_OUTBOX, LANE_PEER, LANES, InstanceConfig, RouterConfig, address_for, router_address
from .util import verify_namespace_containment

ENV_NOTICE_DIR = "INBOX_NOTICE_DIR"
ENV_MSG_DIR = "INBOX_MESSAGE_DIR"
ENV_DROPBOX_DIR = "OUTBOX_DIR"
ENV_AGENT_ID = "MAILBOX_AGENT_ID"

# Fixed order the four vars are documented and printed in.
ENV_KEYS = (ENV_NOTICE_DIR, ENV_MSG_DIR, ENV_DROPBOX_DIR, ENV_AGENT_ID)

# AMAP §2-canonical skeleton, relative to `inbox_root`/`outbox_root`
# respectively (in EITHER mode — see `config.py`'s `_derive_roots`).
# Listed leaves only (not their ancestors) — each entry is checked and
# created via `Path.mkdir(parents=True, exist_ok=True)`, which also
# creates any missing ancestor WITHIN the instance's declared root
# (`outbox_root` before `outbox_root/results/`, etc.); the containment
# check below still catches an ancestor that already exists as an
# escaping symlink. Checked against `root` (the declared `handoff_dir`/
# `namespace`), never against `inbox_root`/`outbox_root` themselves — see
# `InstanceConfig.root`'s docstring.
#
# `inbox_root/notices/processed/` is deliberately ABSENT from this list.
# AMAP v2.2.0 §2 makes it an OPTIONAL, writable-inbound-only convention —
# never something a connector or runtime may depend on existing — and
# `inbox_root` (under `handoff_dir` mode) is the host's REAL `:ro` mount, so
# creating a subdirectory there for the connector to archive into would
# be provisioning a write surface the deployment's whole point is to deny.
# Consumption-tracking is connector-private per v2.2.0 (the daemon's
# delivered ledger lives on its private mount, outside this volume).
# DERIVED, never re-listed. `config.LANE_LEAVES` is the single source these
# three and the host adapter's `create` block all read; a second copy here
# would agree right up until one of them changed.
#
# The outbox keeps its `Path(".")` entry — the lane ROOT itself, created
# here because under `namespace` mode nothing else makes it. That is a
# creation detail of this module and deliberately NOT in the exported
# constant: a `create` block rendered from it would carry `outbox/.`.
_INBOX_SKELETON_LEAVES = tuple(Path(x) for x in LANE_LEAVES[LANE_INBOX])
_OUTBOX_SKELETON_LEAVES = (Path("."),) + tuple(
    Path(x) for x in LANE_LEAVES[LANE_OUTBOX])
_PEER_SKELETON_LEAVES = tuple(Path(x) for x in LANE_LEAVES[LANE_PEER])


class ProvisionError(Exception):
    """Raised when `provision()` is asked for an instance name this
    config doesn't know."""


def provision(cfg: RouterConfig, name: str, *, create: bool = True) -> Dict[str, str]:
    """Return the four connector env vars for instance `name`. Unless
    `create=False`, also creates its AMAP §2-canonical skeleton
    directories, idempotently, INSIDE the instance's declared root only
    (whichever mode it's in — `handoff_dir` or `namespace`).

    Each skeleton leaf is checked with `verify_namespace_containment`
    BEFORE `mkdir`, anchored on the instance's declared `root` (never on
    `inbox_root`/`outbox_root` themselves — see `InstanceConfig.root`'s
    docstring) — passing a would-be file path one level under the leaf
    (matching `deliver.py`/`outbound.py`'s own call convention) makes the
    check resolve the LEAF ITSELF (following a symlink if the leaf, or any
    ancestor up to the first nonexistent component, already is one), not
    just its parent. A `NamespaceEscapeError` aborts the whole call
    immediately — no partial skeleton, nothing created at an escaping
    target — never silently creates the rest and skips just the bad one.

    Refuses (`ProvisionError`) if `name` doesn't name a configured
    instance, naming the known set."""
    if name not in cfg.instances:
        raise ProvisionError(
            f"provision: {name!r} names no configured instance "
            f"(known: {sorted(cfg.instances)})"
        )
    inst = cfg.instances[name]
    root, inbox_root, outbox_root = inst.root, inst.inbox_root, inst.outbox_root

    if create and cfg.discovery is not None:
        # DISCOVERY: THE HOST OWNS THE WHOLE INSTANCE TREE, `peer/` INCLUDED,
        # and this command creates nothing inside it.
        #
        # The module docstring above says `peer/` is router-owned because it
        # is "not a sandy mount source". THAT SENTENCE IS WHAT CHANGED. Under
        # a feature manifest the host declares `peer` as a mount alongside
        # `inbox` and `outbox` and creates all three from its `create` list,
        # so creating `peer/` here now yields exactly what the handoff rule
        # below warns about for the other two: a directory that is NOT
        # mounted into the container, which this router writes peer notices
        # into and no agent can ever see. The wiring would look perfect and
        # deliver nothing.
        #
        # So the rule did not get an exception — the exception lost its
        # reason. Refuse, name every missing lane at once, and create
        # nothing.
        # CHECKED TO THE LEAF, NOT THE LANE, and the first version stopped at
        # the lane. A real cutover hit exactly the difference: on a 2.0
        # sandbox reset the host PRESERVED the relay shim and DESTROYED the
        # tree, so the daemon started before the leaves existed and refused
        # with "mail notice dir ... is not a directory", exit 2, failing the
        # launch. The lane directories were there; `notices/` and `messages/`
        # were not.
        #
        # So a lane-only check passes precisely when the failure happens.
        # Everything the daemon opens is a leaf, so every leaf is what this
        # has to name — and naming them ALL at once matters, because the
        # operator's fix is one edit to the manifest's `create` block and a
        # relaunch, not six.
        expected = (
            [inst.inbox_root / rel for rel in _INBOX_SKELETON_LEAVES]
            + [inst.outbox_root / rel for rel in _OUTBOX_SKELETON_LEAVES]
            + ([inst.peer_root / rel for rel in _PEER_SKELETON_LEAVES]
               if inst.peer_root is not None else [])
        )
        missing = [str(p) for p in expected if not p.is_dir()]
        if missing:
            raise ProvisionError(
                f"provision: instance {name!r} is discovered, so the host owns "
                f"its whole tree and has not created {', '.join(sorted(missing))}. "
                f"Creating them here would produce directories that are not "
                f"mounted into the container — the connector would read and "
                f"write a tree no agent can see, and a daemon that starts "
                f"before a leaf exists refuses the launch outright. Check that "
                f"the feature manifest lists every LEAF in its `create` block "
                f"(not just the three lanes) and that this sandbox has been "
                f"launched since."
            )
        # Nothing under the instance root is ours to make. Router-private
        # state below still is.
        create_instance_tree = False
    else:
        create_instance_tree = True

    # NOT gated on `create_instance_tree`, deliberately, and the first draft
    # gated it. Under discovery this check cannot behave differently: the
    # block above has already refused every missing lane, so by the time
    # control reaches here `inbox` and `outbox` both exist and it passes.
    # Mutation showed the condition had no effect on any test — an inert
    # condition that reads as load-bearing, which is the same defect as a
    # test that cannot fail, one layer down.
    if create and inst.mode == "handoff":
        # In handoff mode THE HOST owns these two roots: it creates and mounts them
        # at launch, when configured to do so. Creating them here is explicitly
        # what such a host warns against — the result is directories
        # that are NOT mounted into the container, so the connector reads and
        # writes a tree no agent can see and the whole wiring silently does
        # nothing. Missing roots mean one of: split-root mode is off, the
        # workspace collided with the mount point, the host does not support it,
        # or that sandbox has
        # never been launched. All four are operator problems, and all four are
        # cheaper to hear about now than to debug as "mail just never arrives."
        missing = [str(p) for p in (inbox_root, outbox_root) if not p.is_dir()]
        if missing:
            raise ProvisionError(
                f"provision: instance {name!r} is in handoff mode but the host has not "
                f"created {', '.join(missing)}. The host creates and mounts this pair at "
                "launch (only where the host is configured to create them) — creating it by hand "
                "yields an unmounted directory the agent can never see. Check, in "
                "order: (1) the host's split-root mode is enabled for that workspace, (2) the "
                "sandbox has been launched at least once since, (3) the host is new "
                "enough to provide it ("
                "--print-schema | grep the host's split-root mode`), (4) the workspace does "
                "not sit at or under ~/.handoff, which makes some hosts disable the pair "
                "and warn. See RUNBOOK.md §0."
            )

    if create and create_instance_tree:
        for rel in _INBOX_SKELETON_LEAVES:
            leaf = inbox_root / rel
            verify_namespace_containment(root, leaf / "._containment_probe")
            leaf.mkdir(parents=True, exist_ok=True)
        for rel in _OUTBOX_SKELETON_LEAVES:
            leaf = outbox_root / rel
            verify_namespace_containment(root, leaf / "._containment_probe")
            leaf.mkdir(parents=True, exist_ok=True)
        # Router-owned, so created here even though sandy's pair is not
        # (module docstring). Same containment discipline, anchored on `root`.
        if inst.peer_root is not None:
            for rel in _PEER_SKELETON_LEAVES:
                leaf = inst.peer_root / rel
                verify_namespace_containment(root, leaf / "._containment_probe")
                leaf.mkdir(parents=True, exist_ok=True)
    if create:
        # Router-private (the loader proves it is outside every instance
        # root and outside state_dir), so no containment anchor applies —
        # and so it is created under discovery too. `intake_dir` is not a
        # mount source and not the host's to make; the reason the instance
        # tree is now hands-off does not reach it.
        intake = intake_path(cfg, inst)
        if intake is not None:
            intake.mkdir(parents=True, exist_ok=True)

    return {
        ENV_NOTICE_DIR: str(inbox_root / "notices"),
        ENV_MSG_DIR: str(inbox_root / "messages"),
        ENV_DROPBOX_DIR: str(outbox_root),
        ENV_AGENT_ID: name,
    }


def peer_paths(inst: InstanceConfig) -> Optional[Dict[str, str]]:
    """Host-side paths of the peer tree — `{"root", "notices", "messages"}`
    — or `None` when the instance has no peer tree (namespace mode, or no
    `fleet_domain`). `root` is what the adapter mounts read-only at
    `~/.handoff/peer/`."""
    if inst.peer_root is None:
        return None
    return {
        "root": str(inst.peer_root),
        "notices": str(inst.peer_root / "notices"),
        "messages": str(inst.peer_root / "messages"),
    }


def intake_path(cfg: RouterConfig, inst: InstanceConfig) -> Optional[Path]:
    """`<intake_dir>/<instance>/` — derived from the instance name, never
    configured per instance — or `None` without `intake_dir`."""
    if cfg.intake_dir is None:
        return None
    return cfg.intake_dir / inst.name


def report(cfg: RouterConfig, name: str, env: Dict[str, str]) -> Dict[str, Any]:
    """The `--format json` document (module docstring): the four env vars
    from `provision()` plus the instance's address, the router's, the peer
    tree and the intake directory. A pure function of config — call
    `provision()` first if the directories should exist."""
    inst = cfg.instances[name]
    intake = intake_path(cfg, inst)
    doc: Dict[str, Any] = {k: env[k] for k in ENV_KEYS}
    doc["address"] = address_for(name, cfg.fleet_domain)
    doc["router_address"] = router_address(cfg.fleet_domain)
    doc["peer"] = peer_paths(inst)
    doc["intake"] = str(intake) if intake is not None else None
    return doc


def format_env(env: Dict[str, str], fmt: str = "env") -> str:
    """`fmt="env"` (default): `KEY=value` lines, shell/dotenv-pasteable,
    in the fixed `ENV_KEYS` order. `fmt="json"`: a `{"KEY": "value"}`
    object of the same four keys. The CLI's `--format json` prints
    `report()` instead, which carries these four keys at its top level plus
    the peer-lane paths; this function stays the env-only rendering."""
    if fmt == "env":
        return "\n".join(f"{k}={env[k]}" for k in ENV_KEYS)
    if fmt == "json":
        return json.dumps({k: env[k] for k in ENV_KEYS}, indent=2)
    raise ValueError(f"format_env: unknown fmt {fmt!r} (expected 'env' or 'json')")


def format_report(doc: Dict[str, Any]) -> str:
    """`report()` as the JSON `provision --format json` prints: two-space
    indent, insertion order (the four env vars first, then the peer-lane
    fields), so the top of the output is byte-identical to what it was
    before the peer lane for a fleet without one."""
    return json.dumps(doc, indent=2)
