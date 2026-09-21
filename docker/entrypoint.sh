#!/usr/bin/env bash
# docker/entrypoint.sh — router-container process dispatcher.
#
# Dispatches on the first arg (default "run"):
#   run     -> python3 -m router --config "$ROUTER_CONFIG" run --interval N
#   once    -> drain every instance a single time, then exit (useful in a
#              cron-style invocation, and for smoke-testing a fresh wiring)
#   peers   -> print the derived peer matrix and exit
#   status  -> print the last-written status document and exit
#   shell   -> exec whatever follows, for debugging
#
# There is no `approve` mode, and there is no longer a command to refuse:
# `approve` was retired. The staged-request snapshot it used to take is now
# taken by the drain itself, the first time it sees an instance root, and
# persisted in `state_dir/<name>/first-seen.json`. A restart policy that
# re-runs `run` therefore changes nothing — the marker is already there and
# is never retaken. That is what made the old refusal necessary and what
# makes it unnecessary now.
#
# WHAT THE CONTAINER MUST STILL GET RIGHT: `state_dir` has to be a PERSISTENT
# mount. On a tmpfs it is a fresh first sight after every restart, so every
# request sitting in an outbox at that moment is quarantined. Fail-closed and
# loud, not silent — but it is a mount bug, and this is where to look for it.
set -euo pipefail

MODE="${1:-run}"
shift || true

: "${ROUTER_CONFIG:?ROUTER_CONFIG must be set (run.sh sets it from --config)}"
INTERVAL="${ROUTER_INTERVAL:-5}"

if [ ! -r "$ROUTER_CONFIG" ]; then
  echo "entrypoint: cannot read config at $ROUTER_CONFIG" >&2
  echo "entrypoint: the config is mounted at its own host path (identity mount);" >&2
  echo "entrypoint: if this is empty the bind mount did not happen." >&2
  exit 2
fi

case "$MODE" in
  run)    exec python3 -m router --config "$ROUTER_CONFIG" run --interval "$INTERVAL" ;;
  once)   exec python3 -m router --config "$ROUTER_CONFIG" once ;;
  peers)  exec python3 -m router --config "$ROUTER_CONFIG" peers ;;
  status) exec python3 -m router --config "$ROUTER_CONFIG" status "$@" ;;
  shell)  exec "$@" ;;
  *)
    echo "entrypoint: unknown mode '$MODE' (run|once|peers|status|shell)" >&2
    exit 2 ;;
esac
