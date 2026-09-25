"""router/roster.py — the fleet roster: who EXISTS, published for agents.

One file, `roster.json`, written every poll into a directory the host adapter
mounts READ-ONLY into every sandbox. It exists because an agent cannot derive
a peer's address — a sandy slug carries a suffix nothing can compute — and
without a list it can task only someone who has already written to it.

WHAT IT IS NOT, and each of these is a decision rather than an omission:

  * NOT AN ALLOWLIST. It carries no edges: no `may_task`, no `peer_senders`,
    nothing about who may address whom. A list of who exists grants nothing.
    Authorisation is decided at submit time by `binding`, and the result is
    the only report of what happened. This is what separates it from the
    retired `peers.json` and from `directory.json` (spec §10), which DOES
    carry a projection of the graph and is a different artifact.
  * NOT EVIDENCE. `members[].state` is only ever `admitted`, and there is no
    delivery evidence in it. The router's first-hand record (the delivery
    ledger) is not published; the outcome records are NEVER published,
    because they come from `outbound/ext/`, which is agent-writable, and a
    document in a read-only runtime-written tree reads as the runtime's
    signature. Publishing an outcome here would launder an agent's claim
    into something that looks router-attested, fleet-wide.
  * NEVER READ BACK, FOR ANY PURPOSE. Write-only from this side. Nothing in
    this router opens `roster.json` — not as a cache, not to recover the
    admitted set after losing state, not to cross-check. The set derives
    from discovery; the file is a projection of it; nothing derives the set
    from the file. The prohibition is on the DIRECTION, not the purpose, for
    the reason spec §10 gives for `directory.json`: every way this rots has
    innocent intent, and the last two make a projection into a source.
    `test_roster.py::NeverReadBackTests` pins it.

WHERE: `dirname(selected_json) / "roster" / "roster.json"`. Derived, with no
config key — the one agreed exception to this repo's rule against deriving a
location from another location (`config.load` refuses to derive
`selected_json` from `instances_dir` for exactly that reason). It is an
exception because it is not a guess: it is a convention agreed with the host
adapter and PINNED FROM BOTH ENDS — the adapter's test asserts the directory
its install creates and its manifest mounts is `dirname(selected_json)/roster`,
and `test_roster.py::LocationConventionTests` asserts this side targets the
same. A config key was the alternative and was rejected because this loader
refuses unknown keys, so adding one forces a rollout order in which getting
it backwards takes the whole config down.

WHEN IT IS NOT WRITTEN, and why each is a skip rather than an error:

  * an authored `instances` config — it has no `selected_json`, so there is
    no location to derive. Discovery only.
  * no `fleet_domain` — members would have no fleet address to publish.
  * the host's verdict is UNAVAILABLE (missing or corrupt `selected.json`).
    The admitted set is then empty, but empty-because-unknown is not
    empty-because-nobody, and `members: []` would tell every agent the fleet
    is empty. Skipping leaves the previous roster to age past its freshness
    bound, where a reader treats it as UNKNOWN — which is the true state.
  * the roster directory is ABSENT. It is the adapter's directory, created
    at its install. This module never creates it: doing so would hide the
    adapter's failure, and put the file somewhere no manifest mounts.
  * the roster directory is NOT WRITABLE by this process (EROFS, EACCES,
    EPERM). The location is designated but was not bound read-write for the
    router — found on the first real deploy, where the directory sat inside
    the read-only mount of its parent. Any OTHER write error is a fault and
    propagates.

WRITTEN AT THE END OF THE POLL, after the drain, never before. A newly
admitted instance's first-sight snapshot is taken during the drain, so by
the time it appears in the roster the router has adopted it. The rule
transfers from spec §10: no agent may be told about an address the runtime
cannot yet route to.

Mode `0644`, applied before the rename. `mkstemp` creates `0600`, which for
this file is the failure spec §10 names: the write succeeds, the content is
correct, and no agent can read it.

Shape — `schemas/roster.schema.json`, the draft's "The Fleet Roster"::

    {
      "contract_version": "2",
      "router": "amap.router@agents.internal",
      "written_at": "2026-09-24T12:00:00Z",
      "interval_s": 5.0,                  # OMITTED when unknown, never
                                          #   defaulted — readers judge
                                          #   written_at against it
      "members": [
        {"address": "alice-deadbeef@agents.internal", "state": "admitted"}
      ]
    }

`members` is exactly the admitted set of this poll, SORTED BY ADDRESS as the
schema requires — which is not the same as sorted by slug: `-` sorts before
`@`, so `alice-deadbeef@…` precedes `alice@…`. Nothing else is emitted. The
envelope is open so CONSUMERS tolerate members they do not know; EMITTING an
undefined one is still producer non-conformance, which is why the slug and
the fleet domain that v1 of this writer carried are gone: the slug is the
address's local part, and the domain is `router`'s.

Specified in amap-spec PR #5 (draft section "The Fleet Roster", a separate
artifact from §10's peer directory). Validated against that schema, and its
invalid fixtures proved rejected, by `test_roster_conformance.py`.
"""

from __future__ import annotations

import errno
import json
from pathlib import Path
from typing import Any, Dict, Optional

from .config import RouterConfig, address_for, router_address
from .util import atomic_write, utc_ts

#: Every AMAP artifact carries it; a consumer refuses an unknown major.
CONTRACT_VERSION = "2"
ROSTER_DIRNAME = "roster"
ROSTER_FILENAME = "roster.json"
STATE_ADMITTED = "admitted"
#: World-readable: the reader is an agent's uid, not this router's.
FILE_MODE = 0o644

WRITTEN = "written"
SKIP_AUTHORED = "skipped: authored instances config (no selected_json to derive a location from)"
SKIP_NO_DOMAIN = "skipped: no fleet_domain (members would have no fleet address)"
SKIP_VERDICT_UNAVAILABLE = ("skipped: host verdict unavailable (the admitted set is "
                            "UNKNOWN, not empty; the previous roster ages out)")


def roster_dir(cfg: RouterConfig) -> Optional[Path]:
    """`dirname(selected_json)/roster`, or `None` for an authored config.

    The convention the host adapter pins from its side. Changing this without
    changing the adapter publishes into a directory nothing mounts."""
    if cfg.selected_json is None:
        return None
    return cfg.selected_json.parent / ROSTER_DIRNAME


def build(cfg: RouterConfig, interval_s: Optional[float],
          written_at: str) -> Dict[str, Any]:
    """The roster document. Pure: no filesystem, no clock."""
    doc: Dict[str, Any] = {
        "contract_version": CONTRACT_VERSION,
        "router": router_address(cfg.fleet_domain),
        "written_at": written_at,
    }
    if interval_s is not None:
        doc["interval_s"] = interval_s
    doc["members"] = sorted(
        ({"address": address_for(name, cfg.fleet_domain), "state": STATE_ADMITTED}
         for name in cfg.instances),
        key=lambda m: m["address"],
    )
    return doc


def publish(cfg: RouterConfig, interval_s: Optional[float]) -> str:
    """Write the roster if this config can have one. Returns `WRITTEN` or a
    `skipped: ...` reason; the caller logs when the outcome CHANGES.

    Any error other than an absent directory propagates: a read-only or
    wrong-owner roster directory is a real fault, not a configuration."""
    target_dir = roster_dir(cfg)
    if target_dir is None:
        return SKIP_AUTHORED
    if not cfg.fleet_domain:
        return SKIP_NO_DOMAIN
    if cfg.discovery is not None and cfg.discovery.verdict_unavailable:
        return SKIP_VERDICT_UNAVAILABLE
    data = (json.dumps(build(cfg, interval_s, utc_ts()), indent=2) + "\n").encode("utf-8")
    try:
        atomic_write(target_dir / ROSTER_FILENAME, data,
                     make_parents=False, mode=FILE_MODE)
    except FileNotFoundError:
        return f"skipped: roster directory absent ({target_dir}) — the host adapter creates it"
    except OSError as e:
        # PRESENT BUT NOT WRITABLE is a deployment state, like absent: the
        # location is designated, and this process was not given write access
        # to it. Found on the first real deploy — the directory sat inside a
        # read-only bind — where it logged a full traceback every poll. A
        # standing state is logged once, when it starts, like every other
        # skip here. ONLY these errnos: anything else (a full disk, an I/O
        # error) is a fault, and still propagates to `poll_once`'s belt.
        if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
            return (f"skipped: roster directory not writable ({target_dir}: "
                    f"{e.strerror}) — the deployment must bind it read-write "
                    f"for the router")
        raise
    return WRITTEN
