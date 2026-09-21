# syntax=docker/dockerfile:1
#
# amap-router-local container: the trusted AMAP runtime, in its own container,
# isolated from every agent sandbox.
#
# What makes this image unusual for a mail runtime: it carries NO CREDENTIALS
# AND NEEDS NO NETWORK. There is no SMTP, no IMAP, no provider and no egress —
# the router moves messages between agent namespaces on one machine. So this
# image takes no secrets, no --env-file, and is intended to run
# `--network none`. If a future change makes it want a network, that is a
# design change worth arguing about, not a flag to add.
#
# Build:
#   docker/build.sh                 (or: docker build -f docker/Dockerfile -t amap-router-local .)
#
# Run:  docker/run.sh --config <host-path-to-router.json>
#       run.sh derives the bind mounts from the config itself, so the mount set
#       and the config cannot disagree. See docker/README.md.

FROM python:3.11-slim

# The router is pure stdlib — no pip install, nothing from the network at
# build time beyond the base image itself. Kept deliberately: a runtime whose
# whole claim is "no credentials, no egress" should not acquire a dependency
# tree that could quietly change either.

# COPY THE PACKAGE AS A DIRECTORY, never file-by-file.
#
# The sibling amp-simple-email-router lists each module explicitly, and that
# is exactly how this family shipped a container that could not start: a new
# module (`fs_safety.py`) was added to the code and not to the Dockerfile, so
# the image was missing an import and only failed at runtime. A directory COPY
# has no manifest to forget. `docker/.dockerignore` keeps tests and caches out,
# and `tests/test_docker_manifest.py` asserts this stays a directory copy
# rather than drifting back to a per-file list.
WORKDIR /app
COPY router/ /app/router/
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

# Identity mounts: run.sh bind-mounts every path in the config at THE SAME
# PATH inside the container, so one config file is correct on both sides and
# nothing has to be rewritten on the way in. It also means the router's own
# validation — in particular `state_dir` not being reachable from any
# instance root — computes the same answer inside the container as the
# operator gets running `python3 -m router` on the host.
#
# Consequence: no ENV pointing at container-internal paths, because there are
# none. Everything comes from --config at runtime.

# HOME is set because Python and some stdlib paths want one; /tmp is
# container-private, not bind-mounted, and writable by an arbitrary --user
# uid. Nothing durable is written there — all router state lives in
# `state_dir`, which is an explicit mount.
ENV HOME=/tmp \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# USER is intentionally NOT pinned. Every mount is a bind mount of host
# directories that sandy created as the host user, and the agent side runs as
# that same uid. Run this container as that user too —
# `--user "$(id -u):$(id -g)"`, which run.sh does — so files the router writes
# into an instance's inbox are owned exactly like the ones sandy made. Pinning
# a uid here would produce root-owned notices in the operator's home directory.

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["run"]
