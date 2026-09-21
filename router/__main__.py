"""router/__main__.py — CLI entry point:
`python3 -m router --config PATH {once|run|peers|status|provision|reset} ...`

  once [--json]                 drain every configured instance's outbound/ exactly once, then exit.
                                 --json prints the per-instance drain summary to stdout as
                                 {instance: {counter: n}} and quiets INFO logging, so stdout is the
                                 document alone; without it `once` reports nothing a script can read
  run --interval N              drain every N seconds, forever (Ctrl-C to stop); writes status.json after every poll
  peers (alias: matrix) [--json] print the derived n x n "can cold-initiate" matrix, the declared peer lists
                                 and (with a fleet_domain) the directed peer task graph; --json prints ONLY
                                 the graph as {recipient-address: [sender-address, ...]} for the adapter's
                                 --verify to diff against each agent's peers.json
  status [--json]               print (or dump) the last-written state_dir/status.json
  provision NAME [--format env|json] [--no-create]
                                 print the four connector env vars for NAME; creates its skeleton dirs (and, on
                                 the peer lane, <handoff_dir>/peer/{notices,messages} and <intake_dir>/NAME/)
                                 unless --no-create. --format json adds address, router_address, peer and
                                 intake (router/provision.py's module docstring gives the exact shape)
  reset {NAME [NAME...]|--all} [--yes|--dry-run]
                                 empty NAME's (or every instance's) mailbox CONTENTS and clear its
                                 router-private state together (never one without the other — see
                                 router/reset.py); never deletes the mailbox roots themselves, so no
                                 sandbox relaunch is needed. clears the first-sight marker, so the next poll re-snapshots
                                 afterward. Refuses without `--yes`; `--dry-run` previews and removes nothing.

`--config PATH` is required for every subcommand. Logging goes to stderr
only. Stdlib only throughout.

Exit codes: 0 ok; 1 status-missing, provision-refused, or
reset-refused (unknown instance, namespace escape, or missing --yes); 2 config error.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import ConfigError, load
from .lock import LockHeldError, acquire as acquire_lock
from .peers import render_peers, render_peers_json
from .provision import ProvisionError, format_env, format_report, provision, report
from .reset import ResetError, plan_resets, reset_instances
from .service import run_forever, run_once
from .status import render_discovery as status_render_discovery, NOT_WRITTEN_MSG, read as status_read, render as status_render
from .util import NamespaceEscapeError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="router", description="amap-router-local")
    parser.add_argument("--config", required=True, help="path to router config JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p_once = sub.add_parser("once", help="drain every instance once, then exit")
    p_once.add_argument(
        "--json", action="store_true",
        help="print the per-instance drain summary to stdout as JSON",
    )

    p_run = sub.add_parser("run", help="drain every N seconds, forever")
    p_run.add_argument("--interval", type=float, required=True, help="seconds between polls")

    # "matrix" is a hidden alias for "peers" — same handler, kept so
    # nothing documented against the L1 CLI breaks.
    _peers = sub.add_parser("peers", help="print the derived per-instance peer lists and allow matrix")
    _peers.add_argument("--html", metavar="PATH",
                        help="also write the matrix as a self-contained HTML page "
                             "(local file; nothing is published)")
    _peers.add_argument("--json", action="store_true",
                        help="print only the directed peer task graph, as "
                             "{recipient-address: [sender-address, ...]}")
    _matrix = sub.add_parser("matrix", help=argparse.SUPPRESS)
    _matrix.add_argument("--html", metavar="PATH", help=argparse.SUPPRESS)
    _matrix.add_argument("--json", action="store_true", help=argparse.SUPPRESS)

    p_console = sub.add_parser(
        "console", help="render the operator console to a self-contained HTML file")
    p_console.add_argument(
        "--html", metavar="PATH", required=True,
        help="write the page here (a local file; it is served by nothing and "
             "carries real addresses and real message bodies)")
    p_console.add_argument(
        "--host-facts", metavar="PATH", default=None,
        help="the adapter's `bringup.py --check` JSON document. Without it the "
             "page reports container liveness and 'not enrolled' as UNKNOWN "
             "rather than omitting them")

    p_status = sub.add_parser("status", help="print (or dump) the router's last-written status")
    p_status.add_argument("--json", action="store_true", help="dump the raw status.json document")

    p_provision = sub.add_parser("provision", help="print connector env vars for one instance")
    p_provision.add_argument("name", help="instance name, as it appears in config.instances")
    p_provision.add_argument(
        "--format", choices=("env", "json"), default="env",
        help="output shape: KEY=value lines, or a JSON object (default: env)",
    )
    p_provision.add_argument(
        "--no-create", action="store_true",
        help="print env vars only; do not create the instance's skeleton directories",
    )

    p_reset = sub.add_parser(
        "reset",
        help="wipe an instance's mailbox contents + router-private state together (the next poll is a first sight again)",
    )
    p_reset.add_argument(
        "names", nargs="*",
        help="instance name(s), as they appear in config.instances (omit when using --all)",
    )
    p_reset.add_argument("--all", action="store_true", help="reset every configured instance")
    p_reset.add_argument(
        "--yes", action="store_true",
        help="actually perform the reset (required unless --dry-run)",
    )
    p_reset.add_argument(
        "--dry-run", action="store_true",
        help="print exactly what would be removed; remove nothing",
    )

    return parser


def _render_reset_plan(plan) -> str:
    lines = [f"reset {plan.name!r} (dry-run — nothing removed):"]
    if not plan.inbox_available:
        lines.append("  inbox:  not present yet (skipped — reset never creates it)")
    if not plan.outbox_available:
        lines.append("  outbox: not present yet (skipped — reset never creates it)")
    if plan.has_peer_tree and not plan.peer_available:
        lines.append("  peer:   not present yet (skipped — run `provision` to create it)")
    if plan.is_empty():
        lines.append("  (nothing to remove — already a clean slate)")
    else:
        for p in plan.state_paths:
            lines.append(f"  state:   {p}")
        for p in plan.mailbox_paths:
            lines.append(f"  mailbox: {p}")
    if plan.was_seen:
        lines.append(
            f"  NOTE: {plan.name!r} has a first-sight marker — a real reset clears it, "
            f"so the next poll snapshots its outbox again and quarantines whatever is in it"
        )
    lines.append("  audit:   state_dir/<name>/audit/ is preserved; a `reset` line is appended")
    return "\n".join(lines)


def _render_reset_summary(summary) -> str:
    line = (
        f"router: instance {summary['name']!r} reset — "
        f"{summary['state_removed']} router-private path(s), "
        f"{summary['mailbox_removed']} mailbox path(s) removed"
        + (" (audit/ preserved)" if summary.get("audit_preserved") else "")
    )
    if not summary["inbox_available"]:
        line += f"\nrouter: instance {summary['name']!r} inbox not present — skipped, nothing created"
    if not summary["outbox_available"]:
        line += f"\nrouter: instance {summary['name']!r} outbox not present — skipped, nothing created"
    if summary["was_seen"]:
        line += (
            f"\nrouter: instance {summary['name']!r} has no first-sight marker now; the next "
            f"poll will snapshot its outbox and quarantine whatever is already in it"
        )
    return line


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # WARNING rather than INFO when a machine-readable document is asked
    # for. The INFO lines a drain emits — `FIRST SIGHT`, `drained <name>:
    # {...}` — carry EXACTLY the data the document carries, so a `--json`
    # caller loses nothing by not seeing them twice, and stdout stays the
    # document alone even when something merges the streams.
    #
    # `status --json` did not need this: it reads, it does not drain, so it
    # had no INFO of its own once the discovery report was withheld.
    # `once --json` does drain, and the first version of it produced a clean
    # stdout and an unparseable `2>&1` — the same half-fix this repo has now
    # caught three times.
    #
    # WARNING and above still speak. Those are not redundant with the
    # document: a warning during a `--json` drain is a thing the summary
    # does not say, and a caller merging streams and then failing to parse
    # is being told something true.
    logging.basicConfig(
        level=(logging.WARNING if getattr(args, "json", False) else logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = load(args.config)
    except ConfigError as e:
        print(f"router: config error: {e}", file=sys.stderr)
        return 2

    # ONCE PER INVOCATION, not once per poll. The report is recomputed at
    # every load and is identical on every poll until the tree changes, so
    # repeating it would make the poll where something CHANGED
    # indistinguishable from every poll after — the same reasoning that
    # announces first sight once.
    #
    # NOT AT ALL WHEN A MACHINE-READABLE DOCUMENT IS BEING ASKED FOR. The
    # report is a HUMAN surface — `status`'s table, the console, the log of a
    # `run` — and none of those is `--json`'s stdout.
    #
    # This is belt to `run.sh`'s braces rather than a duplicate of it. That
    # script now withholds docker's `-t` unless BOTH streams are terminals,
    # which keeps the container's stderr off its stdout; this keeps the report
    # off stdout even when something else merges the two — a `-t` from a
    # caller that is not run.sh, a harness combining streams, `2>&1`. A
    # document that is only clean while nobody merges the streams is a
    # document that will be dirty eventually, and the consumer obeying the
    # rule is the one who pays.
    #
    # Live fleet, 2026-09-19: 38 discovery lines landed ahead of the JSON and
    # a bringup check read UNKNOWN against a perfectly healthy router.
    if not getattr(args, "json", False):
        for line in status_render_discovery(cfg.discovery):
            logging.getLogger("amap_router_local").warning("%s", line)

    if args.command == "once":
        # Single-drainer (contract v3.0.0 §2): refuse to run at all rather
        # than duplicate delivery against a `run`/`once` already draining
        # this state_dir. Never blocks — see router/lock.py's docstring
        # for why a non-blocking, fail-fast acquire is the contract-
        # correct behavior here, not a queued/serialized wait.
        try:
            lk = acquire_lock(cfg.state_dir)
        except LockHeldError as e:
            print(f"router: refusing to run 'once': {e}", file=sys.stderr)
            return 1
        try:
            summary = run_once(cfg)
        finally:
            lk.release()
        if args.json:
            # THE SUMMARY `run_once` ALREADY COMPUTES, rather than a second
            # rendering of it. Printed verbatim: `{instance: {counter: n}}`,
            # the same shape `status.json` carries per instance as
            # `last_summary`.
            #
            # Exists because without it `once` reports NOTHING a script can
            # read — empty stdout, an exit code that says only whether it
            # crashed, and one log line whose payload is a Python dict repr.
            # A host adapter's bringup was therefore obliged to match that
            # line's prefix and `ast.literal_eval` the rest, which made the
            # prefix, the repr format and four counter NAMES cross-repo wire:
            # adding a counter here stopped being a private change.
            #
            # The log line is unchanged and stays. This is a path off it, not
            # its replacement, and the caller migrates when it suits them.
            #
            # ONE INVOCATION CANNOT HAVE BOTH, AND DO NOT "FIX" THAT. With
            # `--json` you get the document and lose the INFO drain lines;
            # without it you get the lines and parse text. Re-emitting the
            # INFO lines under `--json` would put the SAME FACT on one stream
            # twice — the document already carries every counter those lines
            # report — and would undo the reason the threshold is raised at
            # all.
            #
            # The consumer this was built for asked for it to stay this way,
            # having weighed it: its drain phase exists so an operator
            # WATCHES a real drain happen, so it keeps scraping rather than
            # taking the document. That is a considered choice about which
            # surface it wants, not a gap waiting to be closed.
            #
            # `--json` also routes through the discovery-report suppression
            # above, so stdout is the document alone even when something
            # merges the streams — same rule as `status --json` and
            # `peers --json`.
            print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if args.command == "run":
        # Held for the whole process lifetime (until Ctrl-C/SIGTERM stops
        # the poll loop) — see router/lock.py's docstring.
        try:
            lk = acquire_lock(cfg.state_dir)
        except LockHeldError as e:
            print(f"router: refusing to run 'run': {e}", file=sys.stderr)
            return 1
        try:
            run_forever(cfg, args.interval, config_path=args.config)
        finally:
            lk.release()
        return 0

    if args.command == "console":
        from .console import render_html
        dest = Path(args.html)
        facts = Path(args.host_facts) if args.host_facts else None
        try:
            dest.write_text(
                render_html(cfg, source=str(args.config), host_facts_path=facts),
                encoding="utf-8",
            )
        except OSError as e:
            print(f"could not write {dest}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {dest}", file=sys.stderr)
        if facts is None:
            print("no --host-facts: container liveness and 'not enrolled' "
                  "render as UNKNOWN", file=sys.stderr)
        return 0

    if args.command in ("peers", "matrix"):
        if getattr(args, "json", False):
            # A GRAPH THIS ROUTER CANNOT COMPUTE IS NOT AN EMPTY GRAPH.
            #
            # Under discovery with no readable verdict, NOTHING is admitted —
            # so `render_peers_json` would print `{}`, which is also exactly
            # what a fleet whose verdict admits nobody prints. A consumer
            # reading stdout and discarding stderr (which is every JSON
            # consumer) cannot tell "the host has not answered" from "nobody
            # has a peer", and on the day a fleet legitimately renders an
            # empty graph the comparison PASSES while nothing is admitted and
            # nothing drains.
            #
            # Found by a host adapter's workbench, which hit it as a red test
            # today and would have hit it as a silent pass later.
            #
            # So: print NOTHING and exit non-zero. Deliberately not a wrapper
            # object (`{graph, verdict}`) — that would change the SHAPE every
            # existing consumer diffs element-for-element, to fix a problem an
            # exit code already answers. "stdout is a graph or stdout is
            # nothing" is a stronger contract than "stdout is a graph, check a
            # field", because a consumer that ignores the exit code gets a
            # parse error rather than a wrong answer.
            if cfg.discovery is not None and cfg.discovery.verdict_unavailable:
                print(
                    "router: peers --json: the host's verdict is unavailable, so "
                    "NO instance is admitted and the graph is UNKNOWN rather than "
                    "empty. Refusing to print `{}`, which is what a fleet that "
                    "admits nobody prints. Fix the verdict and re-run.",
                    file=sys.stderr,
                )
                return 1
            print(render_peers_json(cfg))
            return 0
        print(render_peers(cfg))
        out = getattr(args, "html", None)
        if out:
            from .peers import render_peers_html
            dest = Path(out)
            try:
                dest.write_text(render_peers_html(cfg, str(args.config)), encoding="utf-8")
            except OSError as e:
                print(f"could not write {dest}: {e}", file=sys.stderr)
                return 2
            print(f"\nwrote {dest}", file=sys.stderr)
        return 0

    if args.command == "status":
        doc = status_read(cfg.state_dir)
        if doc is None:
            print(f"router: {NOT_WRITTEN_MSG}", file=sys.stderr)
            return 1
        if args.json:
            # `json` is imported at MODULE level. A local `import json` here
            # made the name local to the whole of `main()`, so the `once
            # --json` branch above — which runs earlier — hit
            # UnboundLocalError on a module that was plainly imported at the
            # top of the file. Caught by running it; the traceback names the
            # line that USES it, not the line that shadowed it.
            print(json.dumps(doc, indent=2, sort_keys=True))
        else:
            print(status_render(doc))
            for line in status_render_discovery(cfg.discovery):
                print(line)
        return 0

    if args.command == "provision":
        try:
            env = provision(cfg, args.name, create=not args.no_create)
        except ProvisionError as e:
            print(f"router: {e}", file=sys.stderr)
            return 1
        except NamespaceEscapeError as e:
            print(f"router: refusing to provision {args.name!r}: {e}", file=sys.stderr)
            return 1
        if args.format == "json":
            print(format_report(report(cfg, args.name, env)))
        else:
            print(format_env(env, args.format))
        return 0

    if args.command == "reset":
        if args.all and args.names:
            print("router: reset: pass instance NAME(s) or --all, not both", file=sys.stderr)
            return 1
        if not args.all and not args.names:
            print("router: reset: pass at least one instance NAME, or --all", file=sys.stderr)
            return 1
        names = sorted(cfg.instances) if args.all else args.names

        if args.dry_run:
            try:
                plans = plan_resets(cfg, names)
            except ResetError as e:
                print(f"router: {e}", file=sys.stderr)
                return 1
            except NamespaceEscapeError as e:
                print(f"router: refusing to reset: {e}", file=sys.stderr)
                return 1
            for plan in plans:
                print(_render_reset_plan(plan))
            return 0

        if not args.yes:
            print(
                "router: reset: refusing without --yes (pass --dry-run to preview first, "
                "or --yes to actually remove)",
                file=sys.stderr,
            )
            return 1

        try:
            summaries = reset_instances(cfg, names)
        except ResetError as e:
            print(f"router: {e}", file=sys.stderr)
            return 1
        except NamespaceEscapeError as e:
            print(f"router: refusing to reset: {e}", file=sys.stderr)
            return 1
        for summary in summaries:
            print(_render_reset_summary(summary))
        return 0

    parser.error(f"unknown command {args.command!r}")  # pragma: no cover — argparse prevents this
    return 2


if __name__ == "__main__":
    sys.exit(main())
