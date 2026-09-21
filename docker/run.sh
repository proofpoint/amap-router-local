#!/usr/bin/env bash
# docker/run.sh — start the router container with mounts derived from the config.
#
# The mount set is COMPUTED FROM THE CONFIG, never hand-written. A router whose
# container is missing one instance's bind mount does not fail: it starts
# cleanly, reports healthy, and silently never drains that agent — requests pile
# up in an outbox nothing reads. Deriving the mounts from the same file the
# router parses makes that state unreachable.
#
# Every path is mounted at ITS OWN HOST PATH inside the container (an identity
# mount). One config is then correct on both sides, nothing is rewritten on the
# way in, and the router's own containment checks — notably that `state_dir` is
# not reachable from any instance root — compute the same answer in the
# container as they do when the operator runs the router directly on the host.
#
#   docker/run.sh --config ~/.sandy/router.json
#   docker/run.sh --config ~/.sandy/router.json --detach
#   docker/run.sh --config ~/.sandy/router.json --interval 10
#   docker/run.sh --config ~/.sandy/router.json -- once      # drain once, exit
#
# NO SECRETS. This container takes no --env-file and needs none: the router is
# provider-free, holds no credential, and runs `--network none`.
set -euo pipefail

# Resolved rather than assumed: run.sh is invoked as docker/run.sh, by absolute
# path, and through a symlink, and derive-mounts.py sits beside it in all three.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="${IMAGE:-amap-router-local}"
CONTAINER="${CONTAINER:-amap-router-local}"
CONFIG=""
INTERVAL="${ROUTER_INTERVAL:-5}"
DETACH=0
MODE_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --config)   CONFIG="${2:?--config needs a path}"; shift 2 ;;
    --interval) INTERVAL="${2:?--interval needs seconds}"; shift 2 ;;
    --detach|-d) DETACH=1; shift ;;
    --image)    IMAGE="${2:?}"; shift 2 ;;
    --name)     CONTAINER="${2:?}"; shift 2 ;;
    --)         shift; MODE_ARGS=("$@"); break ;;
    -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "run.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "run.sh: docker not found on PATH" >&2; exit 2; }
[ -n "$CONFIG" ] || { echo "run.sh: --config is required" >&2; exit 2; }
[ -r "$CONFIG" ] || { echo "run.sh: cannot read config: $CONFIG" >&2; exit 2; }

# Absolute, because a bind mount source must be absolute and because an
# identity mount is meaningless for a relative path.
CONFIG_ABS="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"

# --- derive the mount manifest -------------------------------------------
# All of this runs BEFORE `docker run`, so a bad config fails here with a
# legible message rather than inside a container that then exits 1.
# Advisory, never a gate: the image bakes the source, so a container can
# silently run code that predates the operator's edits.
"$HERE/check-stale.py" "$IMAGE" || true

MANIFEST="$("$HERE/derive-mounts.py" "$CONFIG_ABS")" || { echo "run.sh: $MANIFEST" >&2; exit 2; }

MOUNTS=()
while IFS=$'\t' read -r path mode; do
  [ -n "$path" ] || continue
  MOUNTS+=(-v "$path:$path:$mode")
done <<< "$MANIFEST"
# The config itself, read-only: the router parses it and never writes it.
MOUNTS+=(-v "$CONFIG_ABS:$CONFIG_ABS:ro")

echo "run.sh: $(( ${#MOUNTS[@]} / 2 )) mount(s) derived from $CONFIG_ABS" >&2

# --network none: the router has no provider, no credential and nothing to
# reach. This is the strongest statement available that it is not a network
# service, and it costs nothing because it never was one.
COMMON=(
  --network none
  --user "$(id -u):$(id -g)"
  -e "ROUTER_CONFIG=$CONFIG_ABS"
  -e "ROUTER_INTERVAL=$INTERVAL"
  "${MOUNTS[@]}"
)

# `${arr[@]+"${arr[@]}"}`, not `"${arr[@]}"`, for the two arrays that are
# LEGITIMATELY EMPTY.  Under `set -u`, bash before 4.4 calls expanding an empty
# array an unbound variable — declaring it is not enough — and macOS still
# ships 3.2.57 as /bin/bash.  Both empties are reachable and neither is an
# error:
#
#   MODE_ARGS is empty in exactly one mode: --detach, where the entrypoint's
#   own default (run forever) is the point.  So the detached path, the one an
#   operator runs once and leaves running, was the only path that could not
#   start on a stock mac.  `-- once` filled the array and hid it.
#
#   TTY is empty whenever stdin is not a terminal — cron, CI, a harness that
#   redirects.  Interactively it is (-t) and the bug stays invisible.
#
# The guard expands to nothing when the array is empty and to the quoted
# elements otherwise, and is a no-op on 4.4+.  MOUNTS is deliberately NOT
# guarded: derive-mounts.py exits when the config has no instances and the
# config itself is always appended, so an empty MOUNTS is a bug worth crashing
# on rather than a case worth tolerating.
if [ "$DETACH" = "1" ]; then
  exec docker run -d --restart unless-stopped --name "$CONTAINER" \
    "${COMMON[@]}" "$IMAGE" ${MODE_ARGS[@]+"${MODE_ARGS[@]}"}
fi

# BOTH streams, not just stdin. `-t` allocates a pseudo-terminal, and docker
# then MERGES the container's stderr INTO its stdout — so a caller with a
# terminal on stdin but a pipe on stdout (an operator running this by hand and
# capturing the result, which is the normal way to use `status --json`) gets
# the router's log lines interleaved ahead of the document and
# `json.loads(stdout)` fails.
#
# That is exactly what happened on a live fleet: 38 discovery lines on stdout
# in front of the JSON, and a bringup check read UNKNOWN against a router that
# was perfectly healthy. The log was ALREADY going to stderr — moving it would
# have fixed nothing, because `-t` had merged the two before the consumer saw
# either.
#
# Gating on stdout as well means a redirected or piped stdout never gets a
# TTY, so the streams stay separate and a machine-readable stdout stays
# machine-readable. The interactive case — both a terminal — is unchanged.
TTY=()
[ -t 0 ] && [ -t 1 ] && TTY=(-t)
exec docker run --rm -i ${TTY[@]+"${TTY[@]}"} --name "$CONTAINER" \
  "${COMMON[@]}" "$IMAGE" ${MODE_ARGS[@]+"${MODE_ARGS[@]}"}
