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
| `hop.root` (only with a `hop` section) | `rw` (a volume with `--volume`) | the hop tree the transport plugin writes and the downstream runtime reads |
| `registry_dir` (with or without a `hop` section) | `ro` | the host registry; without it every instance is held |
| the directory of `delivered_domains_file` (only with a `hop` section) | `ro` | the delivered-domain artifact, by its directory: it is replaced by rename |
| the directory of `transport_plugin.path` (only with a `hop` section) | `ro` | the pinned plugin, by its directory, for the same reason |
| the directory of `delegation.signing_key.path` (only with a `delegation` section, with or without `hop`) | `ro` | the peer signing key, by its directory and never as the file (a rotated key is a rename); the same path rules as the hop paths, and never nested with a read-write mount |

**The hop paths are checked harder than the rest**, because the router uses
them exactly as written: each must be absolute, in normal form and its own
realpath (no symlinked component, and neither file a symlink); none may be a
container system path (`/`, `/etc`, `/var` and the like as a whole, or
anything under `/usr`, `/lib*`, `/bin`, `/sbin`, `/app`, `/proc`, `/sys` or
`/dev`, where an identity mount would replace what the image runs);
`hop.root` may be nested with no other mount, the config file included (it
is mounted by `run.sh` on its own, and inside the tree the downstream
runtime writes it could be replaced before the next start); and a read-only path may be
nested with no read-write one. Each refusal names the path. Without a `hop`
section the list is exactly what it was, whatever else the config carries.

**On a hop host, two things about the container's user matter** beyond the
mounts. The plugin checks its own side's ownership against the process's
uid and the downstream side's against `hop.peer_uid`, both as `stat()` sees
them inside the container: so `run.sh` must be run by the account that owns
this router's existing trees under `hop.root`, and `hop.peer_uid` is correct
only with no user-namespace remapping. A mismatch fails closed. And the
plugin's loader requires every directory above the plugin file to be owned
by root and not group- or world-writable: the identity-mounted directory
itself on the host, and the parents docker creates for it inside the
container (root, 0755).

**A host whose binds keep no uid boundary** (a macOS engine: its bind mounts
are a share that shows every container user as the owner, so `hop.peer_uid`
means nothing there and the plugin loader sees a host plugin owned by the
viewer, never by root) mounts any of the `hop` section's identity mounts from
a NAMED VOLUME instead, with `--volume <path>=<name>` (repeatable):

- `<path>` must be exactly one of hop.root, registry_dir, or the directory of
  transport_plugin.path or of delivered_domains_file, as derived above;
  anything else is refused, as is `--volume` without a `hop` section.
- It is mounted as `--mount type=volume,src=<name>,dst=<path>,volume-nocopy`,
  read-write for hop.root and with `readonly` for the others, and no bind is
  made there.
- The volume must already exist as a plain `local` volume with no driver
  options (one made with `-o type=none,o=bind` is a host directory again),
  made and laid out by its owner: `run.sh` checks it with `docker volume
  inspect` and never creates one. Each path and each volume at most once.
- The path exists only inside the container, so it is checked as written
  (absolute, normal form, not a system path, and nested with no other mount
  as the rules above say, against each other mount both as written and as
  resolved), never against the host, and it may not contain `,`, `"` or `=`.
- A volume shares no path with a bind and nests in no other mount, nor any
  mount in it. One line per path is all the mount list can carry, so a
  volume and a bind at one path would silently leave one of them; nested,
  the engine would have to make a mountpoint inside the outer mount's source.
  Two volumes at ONE path (the plugin's and the delivered-domain file's
  directory) are the same volume and are allowed. `run.sh` also refuses
  unless each `--volume` became exactly one `--mount`.

Without `--volume` the derived mounts and the `docker run` argv are exactly
what they were.

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

`--group-add <gid>` adds exactly ONE supplementary group, by number, directly
after `--user`: for a host whose shared tree is owned by a group the operator's
primary gid is not (the hop tree's group). Decimal, never 0, never a list, at
most once; without it the `docker run` argv is unchanged.

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
