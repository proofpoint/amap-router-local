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
import time
from typing import Dict

from . import outbound, outcomes
from .config import RouterConfig
from .config import ConfigError, load
from .status import StatusTracker, render_discovery

logger = logging.getLogger("amap_router_local")


def run_once(cfg: RouterConfig) -> Dict[str, Dict[str, int]]:
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
    summary: Dict[str, Dict[str, int]] = {}
    for name in sorted(cfg.instances):
        try:
            result = outbound.drain_instance(cfg, name)
        except Exception:
            logger.exception(
                "error draining instance %r — isolated, continuing with "
                "the next instance", name,
            )
            result = {"instance_errored": 1}
        if cfg.instances[name].peer_root is not None:
            try:
                result.update(outcomes.consume_instance(cfg, name))
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
    return summary


def poll_once(cfg: RouterConfig, tracker: StatusTracker) -> Dict[str, Dict[str, int]]:
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
    try:
        summary = run_once(cfg)
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
    return summary


def reload_config(config_path, current: RouterConfig) -> RouterConfig:
    """Re-read the config for the next poll, or keep `current` and say why.

    NEVER RAISES. A config that has become unreadable or invalid is not a
    reason to take down a fleet that is draining correctly on the last good
    one — it is a reason to be loud. The alternative turns a half-written
    file, caught between a renderer's write and its rename, into an outage.

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
        return current
    except OSError as e:
        logger.error(
            "config reload could not READ %s — continuing on the last good "
            "config, which may now be stale: %s", config_path, e)
        return current
    if fresh.state_dir != current.state_dir:
        logger.error(
            "config reload changed state_dir (%s -> %s) — REFUSED and ignored. "
            "This process holds that directory's drain lock and all of its "
            "private state; moving it needs a restart, not a reload.",
            current.state_dir, fresh.state_dir)
        return current
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
            poll_once(cfg, tracker)
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("router stopping (interrupted)")
