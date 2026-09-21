# Running the router in a container

The router is host-side infrastructure. It is built and started from the host
by the operator, it is not reachable from any agent sandbox, and it is a
different trust domain from the agents it serves.

```
docker/build.sh
docker/run.sh --config ~/.sandy/router.json
```

That is the whole thing. There is no env-file, no secrets file, and no port.

## Why this container is unusually small

A mail-carrying runtime brings provider credentials, TLS trust, egress and a
polling loop against someone else's server. This one brings none of that: it
moves messages between agent namespaces on one machine. So:

- **No credentials.** Nothing to pass at runtime, nothing to bake in, no
  `--env-file`. `test_docker.py` asserts one never appears — if it does, the
  provider-free property has quietly stopped being true and that is a design
  change, not a deployment detail.
- **No network.** `run.sh` passes `--network none`. The router has nothing to
  reach and never did.
- **No dependencies.** The router is pure stdlib, so the image installs
  nothing. A runtime whose claim is "no credentials, no egress" should not
  acquire a dependency tree that could change either.

## Identity mounts, and why the config is not rewritten

Every path in the config is bind-mounted at **its own host path** inside the
container. The config is then correct on both sides and nothing is translated
on the way in.

The reason is not convenience. The router validates that `state_dir` is not
reachable from any instance root — that directory holds the approval markers,
the reply-binding ledger and the quarantine, and an agent able to reach it
could forge the binding that stops it redirecting a reply. Under identity
mounts that check computes the same answer inside the container as it does
when the operator runs `python3 -m router` directly on the host. Under
rewritten paths it would be checking different strings, and the two could
disagree without anyone noticing.

## The mount set is derived, never written by hand

`run.sh` reads the config and computes the mounts from it:

| what | mode | why |
|---|---|---|
| each instance's `handoff_dir` (or `namespace`) | `rw` | the router writes the inbound side (notices, bodies) and writes results back on the outbound side |
| `state_dir` | `rw` | router-private: approval markers, reply ledger, quarantine |
| the config file | `ro` | parsed, never written |

A hand-written mount list has one failure mode worth designing against: omit
one instance and the router **does not fail**. It starts, reports healthy, and
silently never drains that agent while requests pile up in an outbox nothing
reads. Deriving the list from the file the router itself parses makes that
state unreachable.

`run.sh` refuses to start if a path in the config does not exist, naming it.
For a handoff pair that usually means the sandbox has not been launched with
`SANDY_HANDOFF_DIRS=1` yet — do not create those by hand, that produces host
directories mounted into no container and the wiring silently does nothing.

**On `rw` for the handoff root:** the `:ro` that carries the inbound-integrity
property is the one *sandy* applies to the **agent's** view of `inbox`. It is a
property of the agent's mount, not the router's. The router must write there;
mounting it read-only here would break delivery entirely.

## Why the image is not run as a fixed user

`USER` is deliberately not pinned in the Dockerfile, and `run.sh` passes
`--user "$(id -u):$(id -g)"`. Every mount is a bind mount of host directories
that sandy created as the host user, and the agent side runs as that same uid.
Pinning a uid would write root-owned notices into the operator's home
directory.

## Modes

```
docker/run.sh --config C                 # drain forever (default)
docker/run.sh --config C --detach        # same, daemonized, restart unless-stopped
docker/run.sh --config C -- once         # drain every instance once, exit
docker/run.sh --config C -- peers        # print the derived peer matrix
docker/run.sh --config C -- status       # print the last-written status
```

## What the container will not do

**`reset` is absent.** It is destructive and evidence-destroying, and a
container that could run it composes with the next poll's fresh first sight
into a complete laundering cycle for the staged-request quarantine. Reset from
the host, deliberately.

**There is no `approve` mode, and nothing to refuse.** The entrypoint used to
refuse `approve` outright: that command snapshotted the outbox at the instant
it ran, a restart policy could re-run the entrypoint, and re-snapshotting a
different moment would have preserved the write while destroying its meaning.
`approve` is retired. The snapshot is now taken by the drain itself the first
time it sees an instance root, and persisted in
`state_dir/<name>/first-seen.json`, so a restart re-runs `run` and finds the
marker already there. It is never retaken.

**Which puts the weight on one mount:** `state_dir` must be PERSISTENT. On a
tmpfs, every container restart is a fresh first sight, and every `req-*.json`
sitting in an outbox at that moment is quarantined rather than delivered. That
fails closed and says so in the log — but it is a mount bug, and this is the
paragraph to remember when an agent's sends start coming back quarantined
after a restart.

## The manifest rule

The Dockerfile copies `router/` **as a directory**, never file by file. The
sibling `amp-simple-email-router` lists each module individually, and that is
exactly how this family shipped an image that could not start: a module was
added to the code and not to the `COPY` list. A directory copy has no list to
forget. `router/tests/test_docker.py` keeps it that way, including a test that
fails if a well-meaning refactor makes the copies explicit again.
