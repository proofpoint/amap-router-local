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
#   docker/run.sh --config ~/.sandy/router.json --detach --group-add 2100
#   docker/run.sh --config C --detach --volume /var/lib/amap/hop=amap-hop
#     (a hop mount as a named volume, for an engine whose binds keep no uid boundary)
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
GROUP_ADD=""
# --volume PATH=NAME, as two parallel lists (bash 3.2 has no associative arrays).
VOL_PATHS=()
VOL_NAMES=()

while [ $# -gt 0 ]; do
  case "$1" in
    --config)   CONFIG="${2:?--config needs a path}"; shift 2 ;;
    --interval) INTERVAL="${2:?--interval needs seconds}"; shift 2 ;;
    --detach|-d) DETACH=1; shift ;;
    --image)    IMAGE="${2:?}"; shift 2 ;;
    --name)     CONTAINER="${2:?}"; shift 2 ;;
    # ONE supplementary group, by number, for a host whose shared tree is
    # group-owned (the hop tree's group): the container keeps the invoking
    # user's uid and primary gid, and gains exactly this one. Decimal, never 0
    # (root's group), never a list, at most once.
    --group-add)
      [ -z "$GROUP_ADD" ] || { echo "run.sh: --group-add given twice" >&2; exit 2; }
      case "${2-}" in
        ''|0*|*[!0-9]*) echo "run.sh: --group-add needs one decimal gid other than 0, got '${2-}'" >&2; exit 2 ;;
      esac
      [ "${#2}" -le 10 ] || { echo "run.sh: --group-add gid '$2' is too long" >&2; exit 2; }
      GROUP_ADD="$2"; shift 2 ;;
    # One of the hop section's identity mounts (hop.root, registry_dir, the
    # plugin's or the delivered-domain file's directory), named exactly as
    # derive-mounts.py derives it, mounted from the NAMED VOLUME instead of
    # bound from the host: for an engine whose bind mounts keep no uid boundary
    # (a macOS share shows every container user as the owner). Repeatable; each
    # path and each volume at most once. The volume must already exist, made
    # and laid out by its owner; run.sh never creates one.
    --volume)
      v="${2-}"
      case "$v" in
        /*=*) ;;
        *) echo "run.sh: --volume needs <absolute container path>=<volume name>, got '$v'" >&2; exit 2 ;;
      esac
      vp="${v%%=*}"; vn="${v#*=}"
      case "$vn" in
        ''|[!A-Za-z0-9]*|*[!A-Za-z0-9_.-]*) echo "run.sh: --volume $vp: a docker volume name ([A-Za-z0-9][A-Za-z0-9_.-]*) is needed, got '$vn'" >&2; exit 2 ;;
      esac
      [ "${#vn}" -le 128 ] || { echo "run.sh: --volume $vp: volume name '$vn' is too long" >&2; exit 2; }
      for i in ${VOL_PATHS[@]+"${!VOL_PATHS[@]}"}; do
        [ "${VOL_PATHS[$i]}" != "$vp" ] || { echo "run.sh: --volume $vp given twice" >&2; exit 2; }
        [ "${VOL_NAMES[$i]}" != "$vn" ] || { echo "run.sh: --volume: volume $vn given twice" >&2; exit 2; }
      done
      VOL_PATHS+=("$vp"); VOL_NAMES+=("$vn"); shift 2 ;;
    --)         shift; MODE_ARGS=("$@"); break ;;
    -h|--help)  sed -n '2,27p' "$0"; exit 0 ;;
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

# The volume paths go to derive-mounts.py, which checks each is one of this
# config's hop mounts and names its role; without --volume its argv is exactly
# what it always was.
DERIVE_ARGS=()
for vp in ${VOL_PATHS[@]+"${VOL_PATHS[@]}"}; do DERIVE_ARGS+=(--volume "$vp"); done
MANIFEST="$("$HERE/derive-mounts.py" "$CONFIG_ABS" ${DERIVE_ARGS[@]+"${DERIVE_ARGS[@]}"})" || { echo "run.sh: $MANIFEST" >&2; exit 2; }

# Each volume must exist BEFORE `docker run`, which would otherwise create an
# empty one, owned by root, and start the router on a tree nobody laid out.
# And it must be a plain local volume: one made with `-o type=none,o=bind` is a
# host directory again, with the boundary this exists to keep lost.
for i in ${VOL_NAMES[@]+"${!VOL_NAMES[@]}"}; do
  vn="${VOL_NAMES[$i]}"
  info="$(docker volume inspect --format '{{.Name}} {{.Driver}} {{json .Options}}' "$vn" 2>/dev/null)" \
    || { echo "run.sh: --volume ${VOL_PATHS[$i]}=$vn: no such volume (run.sh never creates one; its owner makes and lays it out first)" >&2; exit 2; }
  case "$info" in
    "$vn local null"|"$vn local {}") ;;
    *) echo "run.sh: --volume ${VOL_PATHS[$i]}=$vn is not a plain local volume ($info): a driver option can make it a host bind again" >&2; exit 2 ;;
  esac
done

MOUNTS=()
while IFS=$'\t' read -r path mode; do
  [ -n "$path" ] || continue
  case "$mode" in
    volume-rw|volume-ro)
      vn=""
      for i in ${VOL_PATHS[@]+"${!VOL_PATHS[@]}"}; do
        [ "${VOL_PATHS[$i]}" != "$path" ] || vn="${VOL_NAMES[$i]}"
      done
      [ -n "$vn" ] || { echo "run.sh: derive-mounts named a volume at $path that no --volume gave" >&2; exit 2; }
      ro=""; [ "$mode" = volume-rw ] || ro=",readonly"
      MOUNTS+=(--mount "type=volume,src=$vn,dst=$path$ro,volume-nocopy") ;;
    rw|ro) MOUNTS+=(-v "$path:$path:$mode") ;;
    *) echo "run.sh: derive-mounts printed an unknown mode '$mode' for $path" >&2; exit 2 ;;
  esac
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
)
# Directly after --user, and only when asked: without --group-add the argv is
# exactly what it was.
[ -z "$GROUP_ADD" ] || COMMON+=(--group-add "$GROUP_ADD")
COMMON+=(
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
