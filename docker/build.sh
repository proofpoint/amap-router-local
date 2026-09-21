#!/usr/bin/env bash
# docker/build.sh — build the router image from the repo root.
#
# Run from anywhere; the build context is always this repo's root, because the
# Dockerfile does `COPY router/` and that path is root-relative.
set -euo pipefail
IMAGE="${IMAGE:-amap-router-local}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
command -v docker >/dev/null 2>&1 || { echo "build.sh: docker not found on PATH" >&2; exit 2; }
exec docker build -f "$HERE/Dockerfile" -t "$IMAGE" "$ROOT" "$@"
