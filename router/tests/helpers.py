"""router/tests/helpers.py — shared test scaffolding.

Two temp dirs stand in for two (or more) agent sandbox roots, plus a
third for `state_dir` — the same shape SCOPE.md's "Test strategy" section
describes. Nothing here imports a host tool, `docker`, or any real connector
binary; requests are written directly in the shape `inbox-submit` would
produce, and notices/messages are read back directly in the shape
the connector (`inbox-delivery`/`inbox-mcp-vol`) would read them.

`make_config` defaults to `mode="namespace"` (the pre-existing single-tree
layout) so every test written before the two-root model keeps testing
exactly what it tested; pass `mode="handoff"` to build a split-root pair
instead. It also marks every instance ALREADY SEEN by
default (`seen=True`) — writing the router-private first-sight marker
directly with an EMPTY snapshot, not by calling
`router.firstsight.record_first_sight` and inventorying a not-yet-populated
outbox — so the ~100 pre-existing behavior tests, none of which are about
first sight itself, don't all have to learn about it. Tests that ARE about
first sight or the staged-request quarantine (`test_first_sight.py`,
`test_quarantine.py`) pass `seen=False` and let the real drain take the
snapshot at the point in the scenario that matters.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Iterable, Optional

from router import firstsight as firstsight_mod
from router.config import RouterConfig, load_obj
from router.util import atomic_write, utc_ts

#: Spec-checkout directory names, NEWEST FIRST. The family renames
#: `agent-mailbox-protocol` -> `amap-spec` in one flag day; both names are
#: accepted so this repo and the spec repo can rename independently instead of
#: having to land together. Drop the old name once no checkout carries it.
SPEC_REPO_NAMES = ("amap-spec", "agent-mailbox-protocol")

#: Environment overrides for a spec checkout that lives somewhere else, newest
#: first. Same two-era rule as `SPEC_REPO_NAMES`.
SPEC_REPO_ENV_VARS = ("AMAP_SPEC_REPO", "AMP_SPEC_REPO")


def _spec_root() -> Path:
    """The spec checkout this suite validates against: `$AMAP_SPEC_REPO`, else
    `$AMP_SPEC_REPO`, else a by-name lookup beside this repo.

    NOT `.resolve()` — this repo is reached through a symlink from the
    integration workspace, and resolving would land path arithmetic somewhere
    unexpected; `.absolute()` only normalizes cwd-relativeness.

    Depth 3 = the directory holding the sibling checkouts, which works both
    from the real path (.../dev/amap-router-local/router/tests) and through a
    workspace symlink (.../<workspace>/amap-router-local/router/tests). That
    arithmetic is keyed on DEPTH, not on this repo's own directory name, so it
    survives this repo being renamed too.

    When neither name is present the POST-rename spelling is returned, so the
    resulting failure names what a checkout should be called from the flag day
    on. It must stay a path that does not exist rather than `None`: callers
    assert the fixtures directory is there and MUST fail on absence
    (`test_validate_fixtures.py`) — a spec checkout that has gone missing is
    never allowed to turn the conformance tests into a silent skip.
    """
    for var in SPEC_REPO_ENV_VARS:
        override = os.environ.get(var)
        if override:
            return Path(override).absolute()
    siblings = Path(__file__).absolute().parents[3]
    for name in SPEC_REPO_NAMES:
        candidate = siblings / name
        if candidate.is_dir():
            return candidate
    return siblings / SPEC_REPO_NAMES[0]


AMP_ROOT = _spec_root()


def _mark_seen(cfg: RouterConfig) -> None:
    """Write an empty-snapshot first-sight marker directly for every
    instance in `cfg` — bypassing `firstsight.record_first_sight`'s outbox
    inventory (there's nothing in the outbox yet at config-build time in the
    normal case, but writing the marker directly rather than calling that
    function keeps this helper independent of its own behavior, which is
    exactly what `test_first_sight.py`/`test_quarantine.py` exist to pin
    instead)."""
    for name, inst in cfg.instances.items():
        doc = {
            "schema": firstsight_mod.SCHEMA,
            "instance": name,
            "first_seen_ts": utc_ts(),
            "mode": inst.mode,
            "declared_root": str(inst.root),
            "outbox_snapshot": [],
        }
        atomic_write(
            firstsight_mod.marker_path(cfg.state_dir, name),
            json.dumps(doc, sort_keys=True).encode("utf-8"),
        )


class ClockMixin:
    """`install_clock(source)` installs a test clock (strict by default: a
    lost source raises rather than reading real time) and registers
    `clock.reset()` as a cleanup, so no installed source outlives its test.
    `reset_process_state` does NOT clear it (the clock is environment), so
    every test that installs one goes through here or resets it itself."""

    def install_clock(self, source, *, strict: bool = True):
        from router import clock
        clock.install(source, strict=strict)
        self.addCleanup(clock.reset)
        return source


class RouterTestCase(unittest.TestCase):
    """Base class: sets up `self.tmp` (a `TemporaryDirectory`), `self.state_dir`,
    and a `make_config(instances)` helper that creates each instance's
    declared root under `self.tmp` and returns a loaded `RouterConfig`."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.state_dir = self.tmp / "state"

    def tearDown(self) -> None:
        self._tmp_ctx.cleanup()

    def make_config(
        self,
        instances: Dict[str, Iterable[str]],
        *,
        mode: str = "namespace",
        seen: bool = True,
    ) -> RouterConfig:
        """`instances`: `{name: [peer, ...]}`. Creates each instance's
        declared root (empty) under `self.tmp` and returns a
        `RouterConfig` built via `config.load_obj` (so config validation
        runs for real, same as production).

        `mode="namespace"` (default): `config.instances.*.namespace`, the
        pre-existing single-tree layout. `mode="handoff"`: `config.
        instances.*.handoff_dir`, the host's split-root pair.

        `seen=True` (default): every instance is marked already-seen with
        an EMPTY outbox snapshot before this returns, so `outbound.
        drain_instance` drains normally — matching every test written
        before first sight existed. Pass `seen=False` to get a config this
        router has never seen (for `test_first_sight.py`), or to control
        exactly what is already staged when the first drain takes the
        snapshot (for `test_quarantine.py`)."""
        root_key = "handoff_dir" if mode == "handoff" else "namespace"
        doc = {
            "state_dir": str(self.state_dir),
            "instances": {
                name: {
                    root_key: str(self.tmp / "instances" / name),
                    "peers": list(peers),
                }
                for name, peers in instances.items()
            },
        }
        for name in instances:
            declared = self.tmp / "instances" / name
            declared.mkdir(parents=True, exist_ok=True)
            if mode == "handoff":
                # Stand in for what the host does at launch when
                # the host's split-root mode is enabled: it creates and mounts the pair.
                # `provision()` REFUSES to create these itself in handoff
                # mode (an unmounted directory the agent can never see is
                # worse than a loud failure), so a fixture that omitted
                # them would be testing a state that cannot occur once
                # the host has run — and would mask the guard.
                (declared / "inbox").mkdir(exist_ok=True)
                (declared / "outbox").mkdir(exist_ok=True)
        cfg = load_obj(doc)
        if seen:
            _mark_seen(cfg)
        return cfg


#: Hop caps every test config with a transport plugin uses: large enough
#: for the document floor at the default attachment limits.
TEST_HOP_CAPS = {"document": 1 << 30, "request": 1 << 20,
                 "attachment": 8 << 20, "total": 32 << 20}


def with_hop(doc: Dict, base: Path, *, peer_uid: int = 0) -> Dict:
    """`doc` plus what a configured transport plugin requires: a `hop`
    object (its root a sibling of everything else under `base`) and a
    `registry_dir`, unless the doc already names one."""
    out = dict(doc)
    out.setdefault("registry_dir", str(base / "registry"))
    out["hop"] = {"root": str(base / "hop"), "peer_uid": peer_uid, "version_write": 1,
                  "caps": dict(TEST_HOP_CAPS)}
    return out


def write_request(
    cfg: RouterConfig,
    name: str,
    req_id: str,
    *,
    to: Optional[list] = None,
    cc: Optional[list] = None,
    subject: str = "subject",
    body_text: str = "body",
    in_reply_to: Optional[str] = None,
    agent_id: Optional[str] = None,
    attachments: Optional[list] = None,
    raw_override: Optional[bytes] = None,
    filename: Optional[str] = None,
) -> Path:
    """Write `req-<req_id>.json` directly into instance `name`'s
    `outbox_root` — the shape `inbox-submit` would produce. `raw_override`
    writes arbitrary bytes instead (for malformed-input tests).
    `filename`, if given, overrides the derived `req-<req_id>.json` name
    (for hostile-filename tests)."""
    outbox_root = cfg.instances[name].outbox_root
    outbox_root.mkdir(parents=True, exist_ok=True)
    path = outbox_root / (filename or f"req-{req_id}.json")
    if raw_override is not None:
        path.write_bytes(raw_override)
        return path
    draft: Dict = {
        "to": to if to is not None else ["nobody@example.org"],
        "subject": subject,
        "body_text": body_text,
    }
    if cc is not None:
        draft["cc"] = cc
    if attachments is not None:
        draft["attachments"] = attachments
    doc: Dict = {"contract_version": "2", "req_id": req_id, "draft": draft}
    if in_reply_to is not None:
        doc["in_reply_to"] = in_reply_to
    if agent_id is not None:
        doc["agent_id"] = agent_id
    path.write_bytes(json.dumps(doc).encode("utf-8"))
    return path


def read_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8"))


def result_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return cfg.instances[name].outbox_root / "results" / f"{req_id}.json"


def processed_path(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return cfg.instances[name].outbox_root / "processed" / f"req-{req_id}.json"


def notices_dir(cfg: RouterConfig, name: str) -> Path:
    return cfg.instances[name].inbox_root / "notices"


def messages_dir(cfg: RouterConfig, name: str) -> Path:
    return cfg.instances[name].inbox_root / "messages"


def list_notices(cfg: RouterConfig, name: str) -> list:
    d = notices_dir(cfg, name)
    if not d.is_dir():
        return []
    return sorted(p.name for p in d.glob("notice-*.json"))


# --- attachment transport (AMAP v2.3.0 §3/§5) ---------------------------

def attachment_descriptor(
    data: bytes, *, filename: str = "file.bin", media_type: str = "application/octet-stream",
) -> Dict:
    """A well-formed `draft.attachments[]` descriptor for `data` — sha256/
    size computed over the DECODED bytes, exactly as §3 requires of a real
    sender."""
    import hashlib

    return {
        "filename": filename,
        "media_type": media_type,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def outbound_sidecar_dir(cfg: RouterConfig, name: str, req_id: str) -> Path:
    return cfg.instances[name].outbox_root / f"req-{req_id}.attachments"


def stage_outbound_sidecars(
    cfg: RouterConfig, name: str, req_id: str, contents: Iterable[bytes],
) -> Path:
    """Write `outbox_root/req-<req_id>.attachments/<i>` for each ordinal in
    `contents`, in order — the shape `inbox-submit --attach` produces
    (minus the streaming/chunking; tests write the whole file at once).
    Returns the sidecar dir path. Callers needing a MISMATCHED descriptor
    (a wrong sha/size to test rejection) pair this with a hand-built
    `attachments=[...]` list passed to `write_request` separately — this
    helper only ever writes exactly what it's given."""
    side_dir = outbound_sidecar_dir(cfg, name, req_id)
    side_dir.mkdir(parents=True, exist_ok=True)
    for i, data in enumerate(contents):
        (side_dir / str(i)).write_bytes(data)
    return side_dir


def inbound_sidecar_dir(cfg: RouterConfig, name: str, notice_id: str) -> Path:
    return notices_dir(cfg, name) / f"{notice_id}.attachments"


# --- generations (router/generations.py) ---------------------------------

def gen_state(state_dir: Path, logical_id: str) -> Path:
    """`state_dir/<logical_id>/gen-<current>/`: where an identity's
    generation-scoped state lives under a registry, after its first poll."""
    from router import generations
    doc = generations.read_doc(Path(state_dir), logical_id)
    assert doc is not None, f"{logical_id} has no generations yet (no poll has run)"
    return generations.gen_dir(Path(state_dir), logical_id, doc["current"])


def keyed_for_poll(cfg: RouterConfig):
    """`cfg` keyed exactly as a poll keys it: a fresh registry report, the
    generation pre-pass applied (it may begin a generation), then both the
    state keys and the generation keys attached. For tests that drive
    `drain_instance` directly under a registry."""
    from router import generations, registry
    report = registry.report_for(cfg.registry_dir, cfg.state_dir, cfg.instances)
    report, keys = generations.apply(cfg, report)
    return generations.keyed(registry.keyed_config(cfg, report), keys)


def adopt_test_markers(cfg: RouterConfig) -> None:
    """Move each resolved identity's pre-made first-sight marker (written by
    the config helpers, in the pre-generation layout) into a first
    generation begun for it, as an operator's adoption would. Test setup
    only: it lets a fixture keep its "already first-sighted" instances under
    the generation layout."""
    import os
    from router import generations, registry
    report = registry.report_for(cfg.registry_dir, cfg.state_dir, cfg.instances,
                                 persist=False)
    for name, entry in (report.resolved or {}).items():
        lid = entry.logical_id
        marker = cfg.state_dir / lid / "first-seen.json"
        if not marker.exists() or generations.read_doc(cfg.state_dir, lid) is not None:
            continue
        gen = generations.begin(cfg.state_dir, name, lid, generations.binding_of(entry),
                                generations.root_identity(cfg.instances[name].root),
                                generations.REASON_FIRST)
        gdir = generations.gen_dir(cfg.state_dir, lid, gen)
        gdir.mkdir(parents=True, exist_ok=True)
        (gdir / "first-sight.taken").write_text("adopted")
        os.rename(marker, gdir / "first-seen.json")
