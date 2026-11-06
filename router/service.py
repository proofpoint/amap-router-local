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
import dataclasses
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional

from . import aliases as aliases_mod
from . import clock
from . import ingress as ingress_mod
from . import inflight as inflight_mod, quarantine as quarantine_mod
from . import generations, hoplink, outbound, outcomes, registry as registry_mod, roster, transport as transport_mod
from .config import RouterConfig
from .config import ConfigError, load
from .config import MIN_SENDER_AGE_S_DEFAULT, sender_age_policy_digest
from .status import StatusTracker, render_discovery
from .util import format_utc_ts_us, parse_utc_ts, utc_ts

logger = logging.getLogger("amap_router_local")

#: The last poll's inbound counts (`ingress.pump_all`), for status: process
#: state, replaced each poll that pumped.
LAST_INGRESS: Dict[str, Dict[str, int]] = {}
#: PROCESS state: the candidate journal's startup report, per state_dir
#: (`peerjournal.startup`), shown in status's `peer_store`.
PEER_STARTUP: Dict[str, Dict[str, Any]] = {}
#: PROCESS state: the last signed-candidate pass's counts (`peerjournal.poll`).
LAST_PEER_POLL: Dict[str, Any] = {}


#: `run_once`'s default: load the configured plugin for this one call.
_LOAD = object()

#: TEST-ONLY, and `None` in production (nothing in this package assigns it):
#: a callable the hop fence step calls with "fence_recorded" (the new
#: generation's record is durable, no predecessor retired yet) and
#: "retired_written" (every pinned predecessor retired, the successor not yet
#: admitted). The hop fixture stops a poll there by raising; what it raises
#: leaves the poll as `hoplink.FenceStopped` (its `.raised`), which no
#: isolation belt swallows.
FENCE_STOP_AT: Optional[Any] = None


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


def policy_status(cfg: RouterConfig) -> Dict[str, Any]:
    """status.json's `policy` section: the sender-age duration this process
    ENFORCES (`cfg.min_sender_age_s`, the value both enforcing paths read),
    the release default, and the digest of the canonical sender-age policy
    object for the enforced value (`config.sender_age_policy_digest`).
    Never the default in place of the value: a fleet check compares this
    against the fleet artifact."""
    value = cfg.min_sender_age_s
    return {"min_sender_age_s": value, "default": MIN_SENDER_AGE_S_DEFAULT,
            "digest": sender_age_policy_digest(value)}


def log_sender_age_policy(cfg: RouterConfig) -> None:
    """The startup audit line for the sender-age duration (E30: logged at
    startup, INFO), and a WARNING beside it when the value is BELOW the
    release default. The warning says what the gate still does: ages at or
    above the value pass, younger ones are still refused, and every other
    policy check still runs."""
    value = cfg.min_sender_age_s
    logger.info("min_sender_age_s=%d (default %d) policy_digest=%s",
                value, MIN_SENDER_AGE_S_DEFAULT, sender_age_policy_digest(value))
    if value < MIN_SENDER_AGE_S_DEFAULT:
        logger.warning(
            "sender-age gate allows ages >= %ds; this is below the %ds release "
            "default; other policy checks still apply", value, MIN_SENDER_AGE_S_DEFAULT)


def plugin_status(runtime: Any) -> Optional[Dict[str, str]]:
    """status.json's `transport_plugin` for this process: the path
    `transport.load_plugin` opened and the sha256 IT computed from its one
    fd read of the bytes it executed (`LoadedPlugin`), never recomputed from
    the file and never copied from the config. None without a loaded plugin
    (no `transport_plugin` configured, or a stand-in that loaded no bytes)."""
    plugin = getattr(runtime, "plugin", None) if isinstance(runtime, HopRuntime) else None
    if not isinstance(plugin, transport_mod.LoadedPlugin):
        return None
    return {"path": plugin.path, "sha256": plugin.sha256}


def _agent_reachable_roots(cfg: RouterConfig) -> List[Path]:
    """Every directory an agent can reach: no plugin may live inside one.
    The same list `config.load` checks `hop.root` against."""
    from .config import agent_reachable_roots
    return agent_reachable_roots(cfg.instances)


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


class PollInputs(NamedTuple):
    """What `run_once` hands every pass of one poll: the configuration keyed
    for this poll, the registry report, and each instance's generation key."""
    cfg: RouterConfig
    report: "registry_mod.Report"
    gen_keys: Dict[str, str]


def poll_inputs(cfg: RouterConfig, *,
                report: Optional["registry_mod.Report"] = None,
                gen_keys: Optional[Dict[str, str]] = None) -> PollInputs:
    """The (keyed cfg, report, gen_keys) one poll runs on: exactly the four
    steps `run_once` takes before any pass, and nothing else (no outbox
    drain, no ingress pump, no signed-candidate poll). `run_once` calls it,
    so a conformance driver that runs a single pass through it
    (`peerjournal.poll(inputs.cfg, transport, inputs.report, ...)`) gets the
    inputs production gets. No transport is loaded or read: the glue needs
    none. It is NOT read-only: `generations.apply` begins, fences and holds
    generations, and `aliases.attach` settles and tombstones alias entries.
    So, as in production, the caller holds the drain lock, and never calls it
    beside a running router on the same `state_dir`. `report` and `gen_keys` are honoured when given because `run_once`
    is itself handed them (`poll_once` computes both before it calls
    `run_once`); recomputing them would apply generations twice in one poll.

    1. the registry report (`registry_report`), unless one is given;
    2. every instance's generation resolved (begun, fenced or held) BEFORE
       any instance drains, so a sender drained first never places into a
       recipient root that has been replaced this poll (`generations.apply`),
       unless the generation keys are given;
    3. under a registry, every resolved instance's private state keyed by
       its logical_id (`registry.keyed_config`), and its generation-scoped
       state by its current generation (`generations.keyed`);
    4. the alias table's decisions for this poll, store settled and expired
       entries tombstoned, BEFORE any drain (`aliases.attach`)."""
    if report is None:
        report = registry_report(cfg)
    if gen_keys is None:
        report, gen_keys = generations.apply(cfg, report)
    cfg = generations.keyed(registry_mod.keyed_config(cfg, report), gen_keys)
    cfg = aliases_mod.attach(cfg, report)
    return PollInputs(cfg, report, gen_keys)


def send_control_pending(cfg: RouterConfig, transport: Any, *, delegation: Any,
                         now: Any) -> Dict[str, int]:
    """The control-notices-out pass (`peercontrol.send_pending`), called with
    exactly these arguments and its result returned unchanged. `run_once`
    reaches the pass only through here, so a conformance driver calling this
    after `peerjournal.poll` runs what production runs."""
    from . import peercontrol
    return peercontrol.send_pending(cfg, transport, delegation=delegation, now=now)


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
    cfg, report, gen_keys = poll_inputs(cfg, report=report, gen_keys=gen_keys)
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
    # The signed-candidate pass, ONLY with `delegation.inbound` (opt-in per
    # host, off by default): same lock, its own log line and status, never
    # `summary`. Candidates are decided by the production profile
    # (`peerpolicy.production_hooks`): mandatory exposure and the 24 h age.
    if (cfg.delegation is not None and cfg.delegation.inbound
            and hoplink.is_runtime(transport) and report.state != "off"):
        from . import peerjournal, peerlane
        try:
            polled = peerjournal.poll(cfg, transport, report,
                                      delegation=peerlane.current(cfg),
                                      now=clock.now())
            if polled:
                logger.info("signed candidates: %s", polled)
                LAST_PEER_POLL.clear()
                LAST_PEER_POLL.update(polled)
        except Exception:
            logger.exception("error in the signed-candidate pass — isolated")
        # Control notices out: the pending ones, through the runtime tree,
        # which is unavailable (and nothing is attempted) unless the plugin
        # declares the runtime capability.
        try:
            sent = send_control_pending(cfg, transport, delegation=peerlane.current(cfg),
                                        now=clock.now())
            if sent:
                logger.info("control notices: %s", sent)
        except Exception:
            logger.exception("error in the control-notice pass — isolated")
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
            "enacted) until a reload succeeds%s",
            "; delegation key changes in the refused config (a removed key) are NOT "
            "applied" if cfg.delegation is not None else "")
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
        if cfg.delegation is not None:
            from . import peerjournal
            try:
                peer_doc = peerjournal.status_doc(cfg.state_dir, clock.now(),
                                                  PEER_STARTUP.get(str(cfg.state_dir)))
                peer_doc["inbound"] = bool(cfg.delegation.inbound)
                if LAST_PEER_POLL:
                    peer_doc["last_poll"] = dict(LAST_PEER_POLL)
                # Control notices out, and the runtime tree as the loaded
                # plugin's capability shows it (`unavailable` without one).
                try:
                    from . import peercontrol
                    peer_doc["controls"] = peercontrol.status_doc(
                        cfg, None if transport is _LOAD else transport, now=clock.now())
                except Exception:
                    logger.exception("error reading the control notices for status — isolated")
                tracker.record_peer_store(peer_doc)
            except Exception:
                logger.exception("error reading the peer store for status — isolated")
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
        failure = _RELOAD_FAILURE.get(str(cfg.state_dir))
        if failure is not None:
            doc["config_reload_failure"] = dict(failure)
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


def activate_delegation(cfg: RouterConfig, runtime: Any) -> None:
    """With `delegation` configured: activate it against the loaded plugin
    (`peerlane.activate`) and make it the one this process signs and
    verifies with. Raises `peerlane.DelegationRefused` (startup stops).
    Without `delegation`: whatever was active for this state_dir ends."""
    from . import peerlane
    if cfg.delegation is None:
        peerlane.install(cfg, None)
        return
    plugin = getattr(runtime, "plugin", None)
    if plugin is None:
        raise peerlane.DelegationRefused("no_plugin", "delegation needs the loaded transport "
                                                      "plugin")
    fingerprint = peerlane.fingerprint(cfg, plugin)
    current = peerlane.current(cfg)
    if current is not None and fingerprint is not None and current.fingerprint == fingerprint:
        # Nothing activation depends on has changed (the delegation config,
        # the plugin, the seed file's identity, mode and size): keep it, with
        # no seed read, no backend self-test and no probe on every poll.
        peerlane.install(cfg, current)
        return
    delegation = peerlane.activate(cfg, plugin, now=clock.now())
    # The durable decision key a decided signed placement is MAC'd under:
    # created once, made durable before it is accepted (`peerbind`). A key
    # that cannot be established refuses the activation.
    from . import peerbind
    try:
        peerbind.ensure_decision_key(cfg.state_dir)
    except (OSError, peerbind.RecoveryCorrupt) as e:
        raise peerlane.DelegationRefused("decision_key", str(e)) from None
    peerlane.install(cfg, dataclasses.replace(delegation, fingerprint=fingerprint))
    logger.info("delegation activated: signing key %s, %d peer runtime(s)",
                cfg.delegation.signing_key_id, len(cfg.delegation.runtimes))


#: PROCESS state: since when, and why, the config reload has been refused,
#: per state_dir (status.json's `config_reload_failed`). Cleared by a good
#: reload.
_RELOAD_FAILURE: Dict[str, Dict[str, str]] = {}


def peer_startup(cfg: RouterConfig, transport: Any = None) -> Optional[Dict[str, Any]]:
    """Once at start, under the drain lock, with `delegation` configured:
    verify the candidate journal and its clock (`peerjournal.startup`),
    which closes admission or raises the floor and never opens it. A
    failure is logged and recorded, never fatal: admission then stays as it
    is on disk, and without a readable clock that is closed."""
    if cfg.delegation is None:
        return None
    from . import peerjournal
    try:
        peerjournal.apply_window(cfg.state_dir, clock.now(), cfg.delegation)
        rep = peerjournal.startup(cfg.state_dir, clock.now())
    except Exception as e:  # noqa: BLE001 -- isolated, recorded
        logger.exception("peer store startup check failed")
        rep = {"admission": "unknown", "why": "startup_failed",
               "problems": [f"{type(e).__name__}: {e}"], "digests_repaired": 0}
    # The disposal stages, created and checked at start (with inbound
    # intake only): a host-intake candidate is never taken without them.
    if cfg.delegation.inbound and cfg.hop is not None and hoplink.is_runtime(transport):
        for intake in peerjournal.HOST_INTAKES:
            try:
                peerjournal.disposed_dirs(transport.fsops, Path(cfg.hop.root), intake)
            except peerjournal.DisposedUnavailable as e:
                rep.setdefault("problems", []).append(f"disposed: {e}")
                logger.error("peer store: %s", e)
    PEER_STARTUP[str(cfg.state_dir)] = rep
    level = logging.WARNING if rep.get("why") else logging.INFO
    logger.log(level, "peer store: admission %s%s", rep["admission"],
               f" ({rep['why']})" if rep.get("why") else "")
    return rep


def _refuse_reload(current: RouterConfig, why: str) -> RouterConfig:
    """`current`, kept, with `reload_failed` set and the refusal recorded
    (its first sighting kept while it persists)."""
    prior = _RELOAD_FAILURE.get(str(current.state_dir))
    if prior is None or prior["error"] != why:
        _RELOAD_FAILURE[str(current.state_dir)] = {"since": utc_ts(), "error": why}
    return replace(current, reload_failed=True)


def reload_config(config_path, current: RouterConfig, runtime: Any = None) -> RouterConfig:
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
        return _refuse_reload(current, "the config is invalid")
    except OSError as e:
        logger.error(
            "config reload could not READ %s — continuing on the last good "
            "config, which may now be stale: %s", config_path, e)
        return _refuse_reload(current, "the config could not be read")
    if fresh.state_dir != current.state_dir:
        logger.error(
            "config reload changed state_dir (%s -> %s) — REFUSED and ignored. "
            "This process holds that directory's drain lock and all of its "
            "private state; moving it needs a restart, not a reload.",
            current.state_dir, fresh.state_dir)
        return _refuse_reload(current, "state_dir changed")
    if fresh.transport_plugin != current.transport_plugin:
        logger.error(
            "config reload changed transport_plugin — REFUSED and ignored. The "
            "plugin is loaded once at startup and never hot-swapped; changing "
            "it needs a restart, not a reload.")
        return _refuse_reload(current, "transport_plugin changed")
    if fresh.hop != current.hop:
        logger.error(
            "config reload changed hop — REFUSED and ignored. Each generation is "
            "pinned to the hop binding it was admitted under; changing it needs a "
            "restart, and a changed root holds the generations pinned to the old one.")
        return _refuse_reload(current, "hop changed")
    if fresh.min_sender_age_s != current.min_sender_age_s:
        # EFFECTIVE values are compared, so an absent key and an explicit
        # default are the same value and reload cleanly. A change is a
        # restart: the startup audit line and every enforcement stay on the
        # value this process started with (contract §8.6 as amended by E30).
        logger.error(
            "config reload changed min_sender_age_s (%d -> %d) — REFUSED and "
            "ignored; restart required", current.min_sender_age_s,
            fresh.min_sender_age_s)
        return _refuse_reload(current, "min_sender_age_s changed (restart required)")
    if fresh.delegation is not None or current.delegation is not None:
        # Delegation is re-activated against the fresh config BEFORE it is
        # adopted: a key gate, signing-key or probe failure refuses the
        # whole reload, and the last good delegation stays in force.
        from . import peerlane
        try:
            activate_delegation(fresh, runtime)
        except peerlane.DelegationRefused as e:
            logger.error(
                "config reload REFUSED: delegation cannot be activated (%s) — continuing on "
                "the last good config; a key removed in the refused config is NOT applied "
                "until a reload succeeds", e)
            return _refuse_reload(current, "delegation could not be activated")
        except Exception:  # noqa: BLE001 -- NEVER RAISES (docstring): a fault refuses the reload
            logger.exception(
                "config reload REFUSED: delegation activation FAILED unexpectedly — "
                "continuing on the last good config and the last good delegation")
            return _refuse_reload(current, "delegation activation failed unexpectedly")
    _RELOAD_FAILURE.pop(str(current.state_dir), None)
    return fresh


def run_forever(cfg: RouterConfig, interval: float, config_path=None,
                process_started=None) -> None:
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
    # This PROCESS's start, at full resolution: `__main__.main` takes it as its
    # first statement and passes it; a caller that passes none gets it here,
    # still before the plugin is loaded. Taken once, never re-read.
    if process_started is None:
        process_started = clock.now()
    logger.info("router starting: interval=%ss, instances=%s",
                interval, sorted(cfg.instances))
    log_sender_age_policy(cfg)
    # Once, before the loop, and allowed to raise: a refused plugin stops
    # startup here (`start_transport`).
    transport = start_transport(cfg)
    activate_delegation(cfg, transport)
    peer_startup(cfg, transport)
    tracker = StatusTracker(interval_s=interval,
                            process_started_ts=format_utc_ts_us(process_started))
    # The loaded plugin's own digest, recorded once for this process: the
    # reload below can never change it (a changed `transport_plugin` is a
    # refused reload), so nothing records it again.
    tracker.record_transport_plugin(plugin_status(transport))
    tracker.record_policy(policy_status(cfg))
    seen_report = None
    seen_names = sorted(cfg.instances)
    try:
        while True:
            if config_path is not None:
                cfg = reload_config(config_path, cfg, runtime=transport)
                # The policy section always describes the config this poll
                # runs on: a refused reload returns `current`, so a rejected
                # value is never reported.
                tracker.record_policy(policy_status(cfg))
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
