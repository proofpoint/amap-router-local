#!/usr/bin/env python3
"""Warn when the image is older than the source it was built from.

`Dockerfile` does `COPY router/ /app/router/`, so the code is BAKED AT BUILD
TIME. Edit the router, run the container without rebuilding, and it runs the old
code — correctly, silently, and with no indication that what you are watching is
not what you just wrote. That cost a confused comparison the first time
`peers`' output changed: the host printed the new matrix and the container
printed the old one, from the same repository, seconds apart.

Exits 0 when the image is current or the answer cannot be determined (no docker,
no such image, unparseable timestamp) — this is an advisory, never a gate. Exits
1 with a one-line stderr warning when source is newer.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WATCHED = ("router", "docker/entrypoint.sh", "docker/Dockerfile")


def image_created(image: str) -> float | None:
    try:
        out = subprocess.run(["docker", "image", "inspect", "-f", "{{.Created}}", image],
                             capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    raw = out.stdout.strip()
    # Docker emits RFC3339 with nanoseconds, which fromisoformat rejects before
    # 3.11 — truncate to microseconds rather than depending on the version.
    if "." in raw:
        head, _, tail = raw.partition(".")
        frac = "".join(c for c in tail if c.isdigit())[:6]
        raw = f"{head}.{frac}" + ("Z" if tail.endswith("Z") else "")
    raw = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return None


def newest_source(root: Path) -> tuple[float, Path] | None:
    newest = None
    for rel in WATCHED:
        p = root / rel
        if p.is_file():
            candidates = [p]
        elif p.is_dir():
            candidates = [f for f in p.rglob("*.py") if "__pycache__" not in f.parts]
        else:
            continue
        for f in candidates:
            try:
                m = f.stat().st_mtime
            except OSError:
                continue
            if newest is None or m > newest[0]:
                newest = (m, f)
    return newest


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check-stale.py IMAGE", file=sys.stderr)
        return 0
    root = Path(__file__).resolve().parent.parent
    built = image_created(argv[1])
    newest = newest_source(root)
    if built is None or newest is None:
        return 0
    mtime, path = newest
    if mtime <= built:
        return 0
    age = int((mtime - built) // 60)
    print(f"run.sh: WARNING — image {argv[1]!r} was built before "
          f"{path.relative_to(root)} was last changed ({age} min older). "
          f"The image BAKES the source; you are running code that predates your "
          f"edits. Rebuild with docker/build.sh.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
