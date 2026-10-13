"""router/service.py — the drain loop.

`run_once(cfg)` drains every configured instance's `outbound/` exactly
once — this is the unit the test suite drives directly (no threads, no
sleeps) — and, for every instance ON THE PEER LANE (`InstanceConfig.
peer_root` set), consumes the delivery outcomes its daemon wrote
(`outcomes.consume_instance`), merging those counters and `peer_alerts` into
the same per-instance summary. An instance without a peer tree gets exactly
the drain summary it always did, so nothing downstream of `status` changes
shape for a fleet that has no peer lane. Outcomes are consumed whether or
not the instance has been seen before: first sight gates what the instance
may SEND, and an outcome is the daemon reporting on something this router
already
delivered to it. `poll_once(cfg, tracker)` is exactly what one iteration of
`run_forever`'s loop runs: `run_once` (itself wrapped in a belt-and-braces
`try/except` — a status-write failure or an `iterdir` surprise must never
kill the loop, on top of `run_once`'s own per-instance isolation), then
`tracker.record_poll(summary)`, then `tracker.write(cfg.state_dir)`.
Extracting it lets `test_status.py` drive precisely what the loop runs,
still with no threads or sleeps (mirrors L1's `run_once`-as-test-unit
discipline). `run_forever(cfg, interval)` is a thin polling wrapper for
actual deployment; it is not otherwise exercised by the test suite.

No wake, no watcher, no thread: the router's whole job is writing files —
the connector's own watcher (`inbox-delivery`) (already running, unmodified) does the rest
(SCOPE.md "No wake to build").
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import aliases as aliases_mod
from . import ingress as ingress_mod
from . import inflight as inflight_mod, quarantine as quarantine_mod
from . import generations, hoplink, outbound, outcomes, registry as registry_mod, roster, transport as transport_mod
from .config import RouterConfig
from .config import ConfigError, load
from .status import StatusTracker, render_discovery
from .util import parse_utc_ts, utc_ts

logger = logging.getLogger("amap_router_local")

#: The last poll's inbound counts (`ingress.pump_all`), for status: process
#: state, replaced each poll that pumped.
LAST_INGRESS: Dict[str, Dict[str, int]] = {}


#: `run_once`'s default: load the configured plugin for this one call.
_LOAD = object()


@dataclass(frozen=True)
class HopRuntime:
    """What `start_transport` hands the drain when a transport plugin is
    configured: the loaded plugin (or a same-shaped stand-in), this router's
    filesystem port for the hop tree, and the hop config. Exactly these
    three fields, in this order: the hop fixture builds one directly. The
    drain resolves it to one sender per (logical_id, generation)
    (`router/hoplink.py`)."""
    plugin: Any
    fsops: Any
    hop: Any


def _agent_reachable_roots(cfg: RouterConfig) -> List[Path]:
    """Every directory an agent can reach: no plugin may live inside one."""
    roots: List[Path] = []
    for inst in cfg.instances.values():
        for p in (inst.root, inst.inbox_root, inst.outbox_root, inst.peer_root):
            if p is not None:
                roots.append(p)
    return roots


def start_transport(cfg: RouterConfig) -> Optional["HopRuntime"]:
    """The transport the drain uses, loaded ONCE per process (`run_forever`)
    and never hot-swapped. With no `transport_plugin` configured this is
    `NullTransport`'s sender, `None`, and the drain behaves exactly as it
    did before plugins existed. With one configured, `transport.load_plugin`
    checks the file and raises `PluginRefused` on any failure, which stops
    startup: a configured hand-off with no usable plugin never starts in a
    degraded mode. Then this router's filesystem port for the configured
    hop root is built, its own refusal classes checked
    (`transport.check_fsops_classes`), and a `HopRuntime` returned. Nothing
    is constructed against the hop tree yet: each generation's sender is,
    on first use, by the drain."""
    pin = cfg.transport_plugin
    if pin is None:
        return transport_mod.NullTransport().make_sender({}, None)
    plugin = transport_mod.load_plugin(
        pin.path, pin.sha256, forbidden_roots=_agent_reachable_roots(cfg))
    from . import fsops as fsops_mod  # local: only a configured plugin needs it
    fsops = fsops_mod.FsOps(hop_root=cfg.hop.root)
    transport_mod.check_fsops_classes(fsops)
    logger.info("transport plugin activated: %s (sha256 %s, PLUGIN_API %s), hop root %s",
                plugin.path, plugin.sha256, plugin.api, cfg.hop.root)
    if cfg.hop.peer_uid == os.geteuid():
        # Accepted (single-uid deployments, unprivileged fixtures), and said
        # once: the hop tree's owner rules compare the two sides' uids.
        logger.warning("hop.peer_uid equals this router's uid: owner checks cannot "
                       "distinguish the two sides")
    return HopRuntime(plugin=plugin, fsops=fsops, hop=cfg.hop)


#: What this process last logged about the registry, so a standing hold is
#: logged when it changes, not every poll.
_REGISTRY_LOGGED: Dict[str, Any] = {}


def registry_report(cfg: RouterConfig) -> "registry_mod.Report":
    """This poll's reading of the registry (`registry.report_for`), logged
    when its state or its held set changes."""
    report = registry_mod.report_for(cfg.registry_dir, cfg.state_dir, cfg.instances)
    if report.state != "off":
        key = (report.state, report.code, tuple(sorted(report.held.items())))
        if _REGISTRY_LOGGED.get(str(cfg.state_dir)) != key:
            _REGISTRY_LOGGED[str(cfg.state_dir)] = key
            if report.state == "ok":
                (logger.warning if report.held else logger.info)(
                    "registry: seq %s; drained %s; held %s", report.seq,
                    sorted(report.resolved), dict(sorted(report.held.items())))
            else:
                logger.error("registry %s (%s): %s; HOLDING every instance %s",
                             report.state, report.code, report.detail, sorted(report.held))
    return report


def run_once(cfg: RouterConfig, transport: Any = _LOAD,
             report: Optional["registry_mod.Report"] = None,
             gen_keys: Optional[Dict[str, str]] = None) -> Dict[str, Dict[str, int]]:
    """Drain every configured instance's outbound/ once. Returns
    `{instance_name: drain_summary}` for logging/tests.

    Each instance's `drain_instance` call is isolated in its own `try/
    except Exception`: `drain_instance` already isolates per-REQUEST
    failures internally, but an instance-level surprise (e.g. its whole
    `outbound/` directory replaced by something `iterdir()` chokes on)
    must still never stop the OTHER instances in this loop from draining.

    GAP, RECORDED NOT FIXED: this function RETURNS the per-instance summary
    and `__main__`'s `once` subcommand throws it away. `once` writes no
    `status.json` either — only `poll_once`, which `run_forever` drives,
    does that. So the documented "drain once, exit, useful in a cron-style
    invocation" produces NOTHING machine-readable: no exit-code detail, no
    stdout, no file. Its only artifact is the log line in `run_all` above,
    whose summary is a dict repr.

    That is why a host adapter greps a log prefix, and it is the honest
    reason rather than a shortcut on their part. The fix is small and is
    not being done here because it is out of scope for the work in hand:
    give `once` a `--json` that prints the summary it already has, or have
    it write `status.json` like a poll does. Either turns a log-scrape into
    a supported read. Whoever takes it owes the adapter notice, because the
    log line stops being the only option but does not stop being what they
    parse today.
    """
    if transport is _LOAD:
        transport = start_transport(cfg)
    if report is None:
        report = registry_report(cfg)
    if gen_keys is None:
        # Every instance's generation is resolved (begun, fenced or held)
        # BEFORE any instance drains, so a sender drained first never places
        # into a recipient root that has been replaced this poll.
        report, gen_keys = generations.apply(cfg, report)
    # Under a registry every resolved instance's private state is keyed by
    # its logical_id from here on (`registry.keyed_config`), and its
    # generation-scoped state by its current generation.
    cfg = generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys)
    # The alias table's decisions for this poll, store settled and expired
    # entries tombstoned, BEFORE any drain (router/aliases.py).
    cfg = aliases_mod.attach(cfg, report)
    summary: Dict[str, Dict[str, int]] = {}
    for name in sorted(cfg.instances):
        if report.state != "off" and name not in report.resolved:
            continue  # held by the registry (`registry_report` says why)
        root_held = False
        try:
            result = outbound.drain_instance(cfg, name, transport=transport)
        except generations.GenerationHeld as e:
            # The instance's root no longer checks out against its
            # generation: NOTHING more is done on its side this poll, the
            # outcome consume included. The next pre-pass decides.
            logger.warning("instance %r held for this poll: %s", name, e)
            result = {"instance_errored": 1}
            root_held = True
        except Exception:
            logger.exception(
                "error draining instance %r — isolated, continuing with "
                "the next instance", name,
            )
            result = {"instance_errored": 1}
        if cfg.instances[name].peer_root is not None and not root_held:
            try:
                result.update(outbound.with_pinned_root(
                    cfg, name, outcomes.consume_instance))
            except generations.GenerationHeld as e:
                logger.warning("instance %r: outcomes not consumed this poll: %s", name, e)
                result = {**result, "peer_outcome_errored": 1}
            except Exception:
                logger.exception(
                    "error consuming delivery outcomes for instance %r — "
                    "isolated, continuing with the next instance", name,
                )
                result = {**result, "peer_outcome_errored": 1}
        summary[name] = result
        # THIS LINE IS A CROSS-REPO SURFACE. Not "the prefix is" — the LINE
        # is, and it carries more than it looks like. A host adapter's
        # bringup matches the prefix, captures the `{...}` that follows,
        # runs `ast.literal_eval` on it (never `eval`), and asserts that no
        # counter OUTSIDE its allowlist is non-zero. Its "nothing drained"
        # check is that assertion.
        #
        # So what is depended on is: the prefix `drained `; that the summary
        # is a Python dict repr something can `literal_eval`; and THE KEY
        # NAMES of the observation-only counters —
        #     outbound_seen, outbound_skipped_bad_name,
        #     peer_outcomes_seen, first_sight
        # Values matter only by truthiness. Key order and quoting are not
        # depended on, because `literal_eval` does not care.
        #
        # STILL LIVE AFTER `once --json` SHIPPED, and that is the trap.
        # Offering a supported alternative does NOT retire this obligation —
        # the consumer has to actually move, and as of 2026-09-19 it has
        # deliberately not, because its drain phase wants the human lines
        # rather than the document. "There is a JSON flag now, so the log
        # line must be free" is the wrong inference and the likely one.
        #
        # CONSEQUENCE A FUTURE EDITOR MUST NOT MISS: adding a counter to
        # this summary is not a private change. A new key that is ever
        # non-zero fails that adapter's assertion — DELIBERATELY on their
        # side, since a new counter may mean something happened and they
        # would rather fail than ignore it. `first_sight` was added here
        # today and is in their allowlist because they were told. The next
        # one owes the same notice, before the commit.
        #
        # I first recorded this as "nothing should ever parse past the
        # prefix". That was advice stated as fact: they had been parsing
        # past it since the check was written, and said so when they read
        # it. The advice is still right and the rule was already untrue.
        # What follows the prefix is a dict repr (`{'accepted': 2}`), NOT
        # the `accepted=2` tokens the `status` renderer emits — those are a
        # different surface that nobody outside this repo reads.
        logger.info("drained %s: %s", name, result)
    # The inbound pass, after every drain and under the same lock. Its
    # counts go to its own log line and to status, NEVER into `summary`
    # (whose key names are a cross-repo surface, above).
    if hoplink.is_runtime(transport) and report.state != "off":
        try:
            pumped = ingress_mod.pump_all(cfg, transport, report)
            if pumped:
                logger.info("ingress: %s", pumped)
                LAST_INGRESS.clear()
                LAST_INGRESS.update(pumped)
        except Exception:
            logger.exception("error in the inbound pass — isolated")
    return summary


def poll_once(cfg: RouterConfig, tracker: StatusTracker,
              transport: Any = _LOAD) -> Dict[str, Dict[str, int]]:
    """One iteration of `run_forever`'s loop: drain everything, fold the
    result into `tracker`, and persist it to `cfg.state_dir/status.json`.
    `run_once` already isolates per-instance failures; this adds one more
    belt around the whole call (plus the status write itself) so a
    surprise here — e.g. `iterdir()` choking on a hostile `state_dir`
    shape, or the status write itself failing — can never take down the
    poll loop. On that outer failure, `summary` is `{}` for this iteration
    (no drain data to fold) but `tracker.write` still runs, so the age of
    `last_poll_ts` stays meaningful even through an errored iteration."""
    # BEFORE the drain, deliberately. The admitted set is what the loader
    # accepted; whether draining it worked is a different claim with its own
    # counters. An errored poll must still report the set it was working on.
    tracker.record_admitted(cfg.instances)
    if cfg.reload_failed:
        logger.error(
            "the config reload is failing: running on the last good config, and the "
            "external leg is closed (nothing new is published, no revocation is "
            "enacted) until a reload succeeds")
    try:
        # The no-plugin call keeps its exact shape (`run_once(cfg)`), so a
        # router without a plugin runs precisely the code it ran before.
        report = registry_report(cfg)
        report, gen_keys = generations.apply(cfg, report)
        tracker.record_registry(report.to_doc() if report.state != "off" else None)
        if report.state == "off":
            summary = run_once(cfg) if transport is _LOAD else run_once(cfg, transport)
            keyed_cfg = cfg
        else:
            summary = run_once(cfg, transport, report, gen_keys)
            keyed_cfg = generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys)
        try:
            tracker.record_classification(classification_status(
                keyed_cfg, report, None if transport is _LOAD else transport))
        except Exception:
            logger.exception("error reading the cross-host state for status — isolated")
        if hoplink.is_runtime(transport):
            try:
                hop_doc = hoplink.status_doc(keyed_cfg, keyed_cfg.instances)
                try:
                    hop_doc["ingress"] = ingress_mod.status_doc(keyed_cfg, LAST_INGRESS)
                except Exception:
                    logger.exception("error reading the ingress state for status — isolated")
                tracker.record_hop(hop_doc)
            except Exception:
                logger.exception("error reading the hop state for status — isolated")
        if report.state != "off":
            try:
                tracker.record_generations(generations.status_doc(
                    generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys),
                    report))
            except Exception:
                logger.exception("error reading generations for status — isolated")
            try:
                tracker.record_aliases(aliases_mod.status_doc(
                    generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys),
                    report))
            except Exception:
                logger.exception("error reading aliases for status — isolated")
    except Exception:
        logger.exception(
            "error running a full poll — isolated, continuing the loop"
        )
        summary = {}
    tracker.record_poll(summary)
    try:
        tracker.write(cfg.state_dir)
    except Exception:
        logger.exception("error writing status.json — isolated, continuing the loop")
    # The roster, AFTER the drain: a newcomer's first-sight snapshot has been
    # taken by now, so nothing is announced before the router has adopted it
    # (`roster` module docstring). HERE rather than in `run_forever`, so every
    # caller of the loop body publishes — the loop's own docstring records
    # what happened the last time a step lived only in the one caller nothing
    # exercised. Its own belt: a roster failure must not take down the poll,
    # and must not be confused with a status.json failure in the log.
    try:
        outcome = roster.publish(cfg, tracker.interval_s)
    except Exception:
        logger.exception("error writing roster.json — isolated, continuing the loop")
        outcome = "errored"
    # Logged when the outcome CHANGES, not every poll — a standing skip
    # repeated every five seconds is how an operator learns to stop reading
    # the log. `errored` is logged above with its traceback each time.
    if outcome != tracker.roster_outcome and outcome != "errored":
        (logger.info if outcome == roster.WRITTEN else logger.warning)(
            "roster: %s", outcome)
    tracker.roster_outcome = outcome
    return summary


def classification_status(cfg: RouterConfig, report: Any,
                          transport: Any) -> Optional[Dict[str, Any]]:
    """The `classification` section of status.json, or None when it would be
    empty: whether the config reload is failing, every in-flight request
    revoked after it was handed over (with its age; `inflight.revoked`), and,
    under a registry, the ingress quarantine's count per agent."""
    doc: Dict[str, Any] = {}
    if cfg.reload_failed:
        doc["config_reload_failed"] = True
    now = parse_utc_ts(utc_ts())
    revoked: Dict[str, List[Dict[str, Any]]] = {}
    for name in sorted(cfg.instances):
        try:
            rows = inflight_mod.revoked(cfg, name)
        except Exception:  # noqa: BLE001 -- an unkeyed name has no records to show
            continue
        for row in rows:
            since = parse_utc_ts(row["since"])
            row["age_s"] = None if since is None or now is None else int(
                (now - since).total_seconds())
        if rows:
            revoked[name] = rows
    if revoked:
        doc["revocation_unenforceable"] = revoked
        doc["withdraw_capable"] = inflight_mod.withdraw_capable(transport)
    known = getattr(report, "known", None) or {}
    if report is not None and getattr(report, "state", "off") != "off":
        doc["ingress_quarantine"] = {
            name: quarantine_mod.counts(quarantine_mod.list_ingress(
                cfg.state_dir, lid, name, days=cfg.ingress_quarantine_days))
            for name, lid in sorted(known.items())}
    return doc or None


def reload_config(config_path, current: RouterConfig) -> RouterConfig:
    """Re-read the config for the next poll, or keep `current` and say why.

    NEVER RAISES. A config that has become unreadable or invalid is not a
    reason to take down a fleet that is draining correctly on the last good
    one — it is a reason to be loud. The alternative turns a half-written
    file, caught between a renderer's write and its rename, into an outage.

    EVERY FAILED OR REFUSED RELOAD RETURNS `current` WITH `reload_failed`
    SET (`RouterConfig.reload_failed`, process state). The local lane keeps
    running on it unchanged; the external leg fails closed while it is set:
    no new publication, no re-write of a handed-but-unwritten request, and no
    revocation enacted (`inflight.advance`). The next good reload returns a
    fresh config, which clears it.

    REFUSES A CHANGED `state_dir`, and this one is not a style choice. The
    running process holds `state_dir`'s drain lock and its private ledgers,
    markers and quarantine are all under it; adopting a new one mid-run
    would silently strand every one of them and leave the lock held on a
    directory nothing is using. That is a restart, and it should look like
    one.
    """
    try:
        fresh = load(config_path)
    except ConfigError as e:
        logger.error(
            "config reload FAILED — continuing on the last good config, which "
            "may now be stale: %s", e)
        return replace(current, reload_failed=True)
    except OSError as e:
        logger.error(
            "config reload could not READ %s — continuing on the last good "
            "config, which may now be stale: %s", config_path, e)
        return replace(current, reload_failed=True)
    if fresh.state_dir != current.state_dir:
        logger.error(
            "config reload changed state_dir (%s -> %s) — REFUSED and ignored. "
            "This process holds that directory's drain lock and all of its "
            "private state; moving it needs a restart, not a reload.",
            current.state_dir, fresh.state_dir)
        return replace(current, reload_failed=True)
    if fresh.transport_plugin != current.transport_plugin:
        logger.error(
            "config reload changed transport_plugin — REFUSED and ignored. The "
            "plugin is loaded once at startup and never hot-swapped; changing "
            "it needs a restart, not a reload.")
        return replace(current, reload_failed=True)
    if fresh.hop != current.hop:
        logger.error(
            "config reload changed hop — REFUSED and ignored. Each generation is "
            "pinned to the hop binding it was admitted under; changing it needs a "
            "restart, and a changed root holds the generations pinned to the old one.")
        return replace(current, reload_failed=True)
    return fresh


def run_forever(cfg: RouterConfig, interval: float, config_path=None) -> None:
    """Poll every `interval` seconds until interrupted (Ctrl-C / SIGTERM),
    writing `cfg.state_dir/status.json` after every poll.

    THIS FUNCTION IS DRIVEN BY THE SUITE, and that sentence is load-bearing
    because its predecessor was not. It used to say "not used by the test
    suite directly (`poll_once` is the driven unit) — deployment only", and
    that was true, and it is how the reload defect below survived four items
    and six hundred tests: the one caller nothing exercised was the one
    holding the loop the whole design depends on. Testing `reload_config`
    alone would NOT have caught it — a correct helper that nothing calls is
    still a fleet that never rediscovers.

    `test_discovery.py::RunForeverIsActuallyDrivenTests` drives it with a
    patched `sleep`, and its mutation proof re-introduces the ORIGINAL defect
    (ignore `config_path`) rather than a synthetic one.

    RE-READS THE CONFIG BEFORE EVERY POLL when `config_path` is given, and
    that is the whole point of discovery rather than a convenience. The
    instance set is DISCOVERED at load: without a reload it is frozen for
    the process lifetime, so a sandbox launched after the router started is
    never drained until someone restarts it — the restart-per-enrolment
    defect, alive inside the feature built to remove it. It was, until a
    peer asked whether the policy was re-read and the answer turned out to
    be about more than the policy.

    Unconditional, never mtime-compared: the file is small and local, the
    read is free beside a poll, and an mtime check buys nothing while costing
    coarse-timestamp and same-second-rewrite bugs.
    """
    logger.info("router starting: interval=%ss, instances=%s",
                interval, sorted(cfg.instances))
    # Once, before the loop, and allowed to raise: a refused plugin stops
    # startup here (`start_transport`).
    transport = start_transport(cfg)
    tracker = StatusTracker(interval_s=interval)
    seen_report = None
    seen_names = sorted(cfg.instances)
    try:
        while True:
            if config_path is not None:
                cfg = reload_config(config_path, cfg)
                # THE ADMITTED SET IS ANNOUNCED WHEN IT CHANGES. The startup
                # line above names it once, and before this it was the ONLY
                # line that ever did — so a sandbox that appeared was visible
                # only through its own first-sight line (which never recurs)
                # and one that DISAPPEARED was entirely silent. A fleet
                # losing a member with nothing in the log is the shape this
                # repo keeps finding.
                #
                # Added because a peer's bringup wanted to compare "the last
                # logged instance set" against current discovery, and there
                # was no such thing after startup — the check would have
                # failed on every correctly-enrolled fleet.
                names = sorted(cfg.instances)
                if names != seen_names:
                    added = [n for n in names if n not in seen_names]
                    gone = [n for n in seen_names if n not in names]
                    logger.info(
                        "instance set changed: instances=%s (added=%s removed=%s)",
                        names, added, gone)
                    seen_names = names
                # The discovery report is announced when it CHANGES, not
                # every poll — the same reasoning that announces first sight
                # once. A standing orphan repeated every five seconds is how
                # an operator learns to stop reading the log.
                report = cfg.discovery
                current = None if report is None else render_discovery(report)
                if current != seen_report:
                    for line in current or []:
                        logger.warning("%s", line)
                    seen_report = current
            # Without a plugin (`transport` is None) the loop body is called
            # exactly as before; `run_once` then resolves the same None.
            if transport is None:
                poll_once(cfg, tracker)
            else:
                poll_once(cfg, tracker, transport)
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("router stopping (interrupted)")
