#!/usr/bin/env bash
# console.sh — render the router's operator console (fleet health, traffic,
# exclusions, the messages actually exchanged) to one self-contained HTML
# file, and open it. Run it on the HOST.
#
# By default it renders INSIDE the running router container (docker/run.sh
# names it amap-router-local), with `docker exec`. That is the only way to be
# sure the page describes the fleet that is actually running:
#   - the config is the container's own ROUTER_CONFIG, not a guess at a path
#     (a stale ~/.sandy/router.json renders a stale fleet, and looks fine);
#   - the code is the image's, the same code that wrote the state it reads;
#   - every path is visible to it, because those are the router's own mounts.
#
#   ./console.sh                                   # render from the live router, open
#   ./console.sh --container NAME                  # a router container not named the default
#   ./console.sh --config path/to/router.json      # no container: render on the host
#   ./console.sh --out /some/private/dir/fleet.html --no-open
#   ./console.sh --host-facts facts.json           # use an existing facts doc
#
# Host facts (container liveness, who is not enrolled) come from the sandy
# adapter: `amap-sandy.py verify --host-facts <file>`. If amap-sandy.py is on
# PATH (or AMAP_SANDY names it) and no --host-facts is given, this runs it
# first; without it those rows render as UNKNOWN.
#
# Environment overrides: AMAP_ROUTER_CONTAINER, AMAP_ROUTER_CONFIG,
# AMAP_CONSOLE_OUT, AMAP_HOST_FACTS, AMAP_SANDY.
#
# The page carries real addresses and real message bodies. It is written
# readable by you alone (umask 077) and served by nothing. Do not publish it
# or attach it anywhere.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

container="${AMAP_ROUTER_CONTAINER:-amap-router-local}"
config="${AMAP_ROUTER_CONFIG:-}"
out="${AMAP_CONSOLE_OUT:-$HOME/.sandy/console.html}"
host_facts="${AMAP_HOST_FACTS:-}"
open_it=1

usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --container)  container="$2"; shift 2 ;;
        --config)     config="$2"; shift 2 ;;
        --out)        out="$2"; shift 2 ;;
        --host-facts) host_facts="$2"; shift 2 ;;
        --no-open)    open_it=0; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "console.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

umask 077
mkdir -p "$(dirname "$out")"

if [ -z "$host_facts" ]; then
    sandy_cli="${AMAP_SANDY:-$(command -v amap-sandy.py || true)}"
    if [ -n "$sandy_cli" ]; then
        host_facts="$(dirname "$out")/host-facts.json"
        # verify exits non-zero when it finds a fault; the document it wrote
        # says so, and the page renders it, so that is not a reason to stop.
        "$sandy_cli" verify --host-facts "$host_facts" >/dev/null || true
        [ -f "$host_facts" ] || { echo "console.sh: $sandy_cli verify wrote no host facts" >&2; host_facts=""; }
    else
        echo "console.sh: amap-sandy.py not found; host facts will render as UNKNOWN" >&2
    fi
elif [ ! -f "$host_facts" ]; then
    echo "console.sh: no host-facts document at $host_facts" >&2
    exit 1
fi

running() {
    command -v docker >/dev/null 2>&1 &&
        [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]
}

tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT

if [ -z "$config" ] && running "$container"; then
    live_config="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container" \
                   | sed -n 's/^ROUTER_CONFIG=//p')"
    [ -n "$live_config" ] || { echo "console.sh: $container has no ROUTER_CONFIG" >&2; exit 1; }
    echo "console: rendering inside $container from $live_config" >&2
    # The page goes to stdout and the host facts come in on stdin: the
    # container's mounts do not include either file, and none are added.
    facts_args=()
    [ -n "$host_facts" ] && facts_args=(--host-facts /dev/stdin)
    if [ -n "$host_facts" ]; then
        docker exec -i "$container" python3 -m router --config "$live_config" \
            console --html /dev/stdout ${facts_args[@]+"${facts_args[@]}"} \
            < "$host_facts" > "$tmp"
    else
        docker exec "$container" python3 -m router --config "$live_config" \
            console --html /dev/stdout > "$tmp"
    fi
else
    if [ -z "$config" ]; then
        echo "console.sh: no running container named $container;" \
             "rendering on the host instead" >&2
        config="$HOME/.sandy/router.json"
        echo "console.sh: WARNING: $config is a guess, and may not be the config" \
             "the router runs with. Pass --config, or --container." >&2
    fi
    [ -f "$config" ] || { echo "console.sh: no router config at $config" >&2; exit 1; }
    args=(--config "$config" console --html "$tmp")
    [ -n "$host_facts" ] && args+=(--host-facts "$host_facts")
    ( cd "$HERE" && python3 -m router "${args[@]}" )
fi

[ -s "$tmp" ] || { echo "console.sh: the router wrote an empty page" >&2; exit 1; }
mv "$tmp" "$out"
trap - EXIT
echo "console: $out"

if [ "$open_it" = 1 ]; then
    if command -v open >/dev/null 2>&1; then
        open "$out"
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$out" >/dev/null 2>&1 &
    fi
fi
