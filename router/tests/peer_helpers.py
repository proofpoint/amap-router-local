"""router/tests/peer_helpers.py — scaffolding for the peer lane.

`helpers.make_config` builds the pre-peer-lane shape (`peers` only, one mode
for every instance) and every test written against it must keep testing
exactly that, so the peer lane gets its own builder rather than a widened
signature: `make_peer_config` takes a per-instance spec (`peers`,
`peer_senders`, `mode`), a `fleet_domain`, and runs `provision` so the peer
tree exists the way it does on a real box — the adapter runs `provision`
between sandy launch and enrolment for exactly that reason.

The daemon's side of the seam is stood in for by `write_outcome`, which
writes one outcome file in the agreed shape (`.tmp` + rename, like the real
daemon) into an instance's `outbox/ext/claude-code/outcomes/` — or, with
`legacy=True`, into the old connector id the router still reads for one
release.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from router import outcomes as outcomes_mod
from router import provision as provision_mod
from router.config import RouterConfig, load_obj
from router.tests.helpers import AMP_ROOT, RouterTestCase, _mark_seen

FLEET_DOMAIN = "example.invalid"


def make_peer_config(
    tc: RouterTestCase,
    instances: Dict[str, Dict[str, Any]],
    *,
    fleet_domain: Optional[str] = FLEET_DOMAIN,
    seen: bool = True,
    provision: bool = True,
    intake_dir: Optional[Path] = None,
    top: Optional[Dict[str, Any]] = None,
) -> RouterConfig:
    """`instances`: `{name: {"peers": [...], "peer_senders": [...],
    "mode": "handoff" | "namespace"}}`, every key optional (`mode` defaults
    to `handoff`, the peer lane's mode). Creates each declared root (and,
    for handoff mode, the sandy pair) under `tc.tmp`, loads through
    `config.load_obj` so validation runs for real, marks seen like
    `helpers.make_config`, and — unless `provision=False` — provisions every
    instance so `peer/{notices,messages}` exists."""
    doc: Dict[str, Any] = {"state_dir": str(tc.state_dir), "instances": {}}
    if fleet_domain is not None:
        doc["fleet_domain"] = fleet_domain
    if intake_dir is not None:
        doc["intake_dir"] = str(intake_dir)
    if top:
        doc.update(top)
    for name, spec in instances.items():
        mode = spec.get("mode", "handoff")
        root_key = "handoff_dir" if mode == "handoff" else "namespace"
        entry: Dict[str, Any] = {root_key: str(tc.tmp / "instances" / name)}
        if "peers" in spec:
            entry["peers"] = list(spec["peers"])
        if "peer_senders" in spec:
            entry["peer_senders"] = list(spec["peer_senders"])
        doc["instances"][name] = entry
        declared = tc.tmp / "instances" / name
        declared.mkdir(parents=True, exist_ok=True)
        if mode == "handoff":
            (declared / "inbox").mkdir(exist_ok=True)
            (declared / "outbox").mkdir(exist_ok=True)
    cfg = load_obj(doc)
    if seen:
        _mark_seen(cfg)
    if provision:
        for name in instances:
            provision_mod.provision(cfg, name, create=True)
    return cfg


def addr(name: str, fleet_domain: str = FLEET_DOMAIN) -> str:
    return f"{name}@{fleet_domain}"


def peer_notices_dir(cfg: RouterConfig, name: str) -> Path:
    return cfg.instances[name].peer_root / "notices"


def peer_messages_dir(cfg: RouterConfig, name: str) -> Path:
    return cfg.instances[name].peer_root / "messages"


def list_peer_notices(cfg: RouterConfig, name: str) -> List[str]:
    d = cfg.instances[name].peer_root
    if d is None or not (d / "notices").is_dir():
        return []
    return sorted(p.name for p in (d / "notices").glob("notice-*.json"))


def notice_id_of(filename: str) -> str:
    return filename[len("notice-"):-len(".json")]


def outcomes_dir(cfg: RouterConfig, name: str, *, legacy: bool = False) -> Path:
    """The outcomes directory under the spec-pinned connector id, or under
    the old repo-tracking id with `legacy=True` (the compatibility path the
    router scans for one release — `outcomes.LEGACY_CONNECTOR_ID`)."""
    rel = outcomes_mod.LEGACY_OUTCOMES_REL if legacy else outcomes_mod.OUTCOMES_REL
    return cfg.instances[name].outbox_root / rel


def write_outcome(
    cfg: RouterConfig, name: str, notice_id: str, outcome: str, *,
    ts: str = "2026-09-03T12:00:00Z", detail: Optional[str] = None,
    doc_override: Optional[Dict[str, Any]] = None, filename: Optional[str] = None,
    raw_override: Optional[bytes] = None, legacy: bool = False,
) -> Path:
    """The daemon's write, as agreed: `.peer-<id>.json.tmp` + rename into
    `outbox/ext/<connector-id>/outcomes/peer-<id>.json`. Returns the final
    path. `legacy=True` writes under the old connector id instead, standing
    in for a daemon that has not been re-provisioned. `doc_override`
    replaces the document wholesale (for shape tests); `raw_override` writes
    arbitrary bytes."""
    d = outcomes_dir(cfg, name, legacy=legacy)
    d.mkdir(parents=True, exist_ok=True)
    final = d / (filename or f"peer-{notice_id}.json")
    tmp = d / f".{final.name}.tmp"
    if raw_override is not None:
        data = raw_override
    else:
        doc: Dict[str, Any] = {"outcome": outcome, "ts": ts, "tree": "peer", "notice_id": notice_id}
        if detail is not None:
            doc["detail"] = detail
        if doc_override is not None:
            doc = doc_override
        data = json.dumps(doc).encode("utf-8")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o644)
    os.rename(tmp, final)
    return final


def load_amp_validate():
    """The AMAP fixtures engine, by path (the same pattern
    `test_happy_path.py` uses)."""
    module_path = AMP_ROOT / "fixtures" / "validate.py"
    spec = importlib.util.spec_from_file_location("amp_fixtures_validate_peer", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def peer_schema_present() -> bool:
    return (AMP_ROOT / "schemas" / "peer-notice.schema.json").is_file()


def events(cfg: RouterConfig, name: str, event: Optional[str] = None) -> List[Dict[str, Any]]:
    from router import audit
    out = audit.read_events(cfg.state_dir, name)
    return [e for e in out if event is None or e.get("event") == event]
