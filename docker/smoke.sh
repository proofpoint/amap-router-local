#!/usr/bin/env bash
# docker/smoke.sh — prove the container works, against nothing that matters.
#
# First run: 2026-08-24, and it earned its keep immediately — run.sh died at the
# mount derivation, on a bug that had been committed days earlier and that every
# test in this repo passed over, because they assert on file CONTENTS (that the
# Dockerfile copies the package as a directory, that run.sh passes
# `--network none`, that the entrypoint has no way to reset) and none of them ran
# Docker. A construct that is only wrong at evaluation is invisible to all of
# them. Had that first run been against the live fleet, it would have meant
# debugging the container and the real wiring at once.
#
# Run this before pointing run.sh at a real config, and after any change to
# run.sh, the Dockerfile or the entrypoint.
#
# This builds the image and drives one full drain against a synthetic
# two-instance layout in a temp directory: no sandy, no enrollment, no real
# sandboxes, nothing under $SANDY_HOME touched. It uses `namespace` mode
# rather than `handoff_dir` precisely because namespace mode needs no sandy —
# see router/config.py's docstring for why both modes exist.
#
#   docker/smoke.sh            # build + drain once + report
#   docker/smoke.sh --keep     # leave the temp fleet for inspection
#
# What a pass proves: the image builds, the entrypoint runs, run.sh's mount
# derivation is right, identity mounts resolve inside the container, the
# router loads a config and completes a drain as the invoking uid, and it does
# all of that with no network. What it does not prove: anything about sandy,
# the connector, or a real agent.
set -euo pipefail

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
command -v docker >/dev/null 2>&1 || { echo "smoke: docker not found on PATH" >&2; exit 2; }

LAB="$(mktemp -d)"
cleanup() { [ "$KEEP" = "1" ] && echo "smoke: kept $LAB" || rm -rf "$LAB"; }
trap cleanup EXIT

# --- a synthetic two-instance fleet ------------------------------------
# `namespace` mode: <ns>/inbound is host-written, <ns>/outbound is
# agent-written. Nothing here is mounted into any container but the router's.
for who in alice bob; do
  mkdir -p "$LAB/boxes/$who/inbound/notices" \
           "$LAB/boxes/$who/inbound/messages" \
           "$LAB/boxes/$who/outbound/results" \
           "$LAB/boxes/$who/outbound/processed"
done
mkdir -p "$LAB/router-state"

cat > "$LAB/router.json" <<JSON
{
  "state_dir": "$LAB/router-state",
  "instances": {
    "alice": { "namespace": "$LAB/boxes/alice", "peers": ["bob"] },
    "bob":   { "namespace": "$LAB/boxes/bob",   "peers": ["alice"] }
  }
}
JSON

echo "== 1. the config loads on the HOST first =="
# If this fails the container has nothing to prove — fail here, where the
# error is legible, rather than inside a container that then exits 1.
( cd "$ROOT" && python3 -m router --config "$LAB/router.json" peers ) | sed 's/^/   /'

echo
echo "== 2. build =="
"$HERE/build.sh" >/dev/null 2>&1 && echo "   image built" || { echo "   BUILD FAILED — rerun docker/build.sh to see why" >&2; exit 1; }

echo
echo "== 3. drain once, in the container — this is also FIRST SIGHT =="
# No operator step precedes this any more. The drain takes the snapshot
# itself and writes state_dir/<name>/first-seen.json before draining anything.
"$HERE/run.sh" --config "$LAB/router.json" -- once 2>&1 | sed 's/^/   /'

echo
echo "== 4. the marker is there, and a second run does not retake it =="
MARKER="$LAB/router-state/alice/first-seen.json"
[ -f "$MARKER" ] || { echo "   *** no first-sight marker for alice — that is a defect ***" >&2; exit 1; }
BEFORE="$(cat "$MARKER")"
"$HERE/run.sh" --config "$LAB/router.json" -- once >/dev/null 2>&1
if [ "$BEFORE" = "$(cat "$MARKER")" ]; then
  echo "   unchanged across a second run, as designed"
else
  echo "   *** the marker was rewritten by a second run — that is a defect ***" >&2
  exit 1
fi

echo
echo "== 5. the container cannot reset =="
if "$HERE/run.sh" --config "$LAB/router.json" -- reset >/dev/null 2>&1; then
  echo "   *** the entrypoint ACCEPTED reset — that is a defect ***" >&2
  exit 1
else
  echo "   refused, as designed"
fi

echo
echo "== 6. state the router wrote =="
find "$LAB/router-state" -type f | sed "s|$LAB|<lab>|" | sed 's/^/   /'
echo
echo "smoke: PASS — image builds, mounts resolve, a drain completes, first sight is recorded once."
