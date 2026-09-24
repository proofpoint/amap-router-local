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

WRITTEN AT THE END OF THE POLL, after the drain, never before. A newly
admitted instance's first-sight snapshot is taken during the drain, so by
the time it appears in the roster the router has adopted it. The rule
transfers from spec §10: no agent may be told about an address the runtime
cannot yet route to.

Mode `0644`, applied before the rename. `mkstemp` creates `0600`, which for
this file is the failure spec §10 names: the write succeeds, the content is
correct, and no agent can read it.

Schema (schema=1)::

    {
      "schema": 1,
      "generated_ts": "2026-09-24T12:00:00Z",
      "interval_s": 5.0,                  # OMITTED when unknown, never
                                          #   defaulted — readers compute a
                                          #   freshness bound from it
      "fleet_domain": "agents.internal",
      "router": "amap.router@agents.internal",
      "members": [
        {"slug": "alice-deadbeef",
         "address": "alice-deadbeef@agents.internal",
         "state": "admitted"}
      ]
    }

`members` is sorted by slug and is exactly the admitted set of this poll.
There is no basename or human name: splitting a slug at its last hyphen is
how two nonexistent directories once got into a sibling's docs. A reader
matches a slug by prefix.

This schema is v1 and is NOT a spec artifact yet: whether it belongs beside
§10 in amap-spec is that repo's ruling, and has been asked for.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from .config import RouterConfig, address_for, router_address
from .util import atomic_write, utc_ts

SCHEMA = 1
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
          generated_ts: str) -> Dict[str, Any]:
    """The roster document. Pure: no filesystem, no clock."""
    doc: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated_ts": generated_ts,
    }
    if interval_s is not None:
        doc["interval_s"] = interval_s
    doc["fleet_domain"] = cfg.fleet_domain
    doc["router"] = router_address(cfg.fleet_domain)
    doc["members"] = [
        {"slug": name,
         "address": address_for(name, cfg.fleet_domain),
         "state": STATE_ADMITTED}
        for name in sorted(cfg.instances)
    ]
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
    return WRITTEN
