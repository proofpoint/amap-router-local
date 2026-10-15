#!/usr/bin/env python3
"""Derive the container's bind-mount manifest from a router config.

Lives in its own file rather than in a heredoc inside `$( ... )` in run.sh,
which is where it started. That construction broke the first time run.sh was
ever executed: the refusal message contains backticks, and a backtick inside a
command substitution opens legacy command substitution, so the shell hunts for a
closing backtick and never finds the closing paren. `bash -n` does not catch it —
the failure is at evaluation.

Any prose here can now contain backticks, apostrophes and parentheses without
the shell having an opinion, and the derivation is directly testable, which it
was not while embedded.

Prints one `<abspath>\t<rw|ro>` line per mount. Exits non-zero with an
operator-facing message on any problem.
"""
import json, os, sys
cfg_path = sys.argv[1]
try:
    doc = json.loads(open(cfg_path).read())
except json.JSONDecodeError as e:
    sys.exit(f"config is not valid JSON: {e}")

state_dir = doc.get("state_dir")
if not state_dir:
    sys.exit("config has no 'state_dir'")
instances = doc.get("instances") or {}
instances_dir = doc.get("instances_dir")
selected_json = doc.get("selected_json")
if instances and instances_dir:
    sys.exit("config declares both 'instances' and 'instances_dir' — one or the other")
if not instances and not instances_dir:
    sys.exit("config has no instances and no instances_dir — "
             "the router would start and drain nothing")

roots, missing = [], []

def want(path, mode, what):
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(p):
        missing.append(f"{what}: {p}")
    roots.append((p, mode))

# state_dir is router-private: the approval markers, the reply-binding ledger,
# the audit log and the quarantine. Read-write, and mounted nowhere near a sandbox.
want(state_dir, "rw", "state_dir")

# intake_dir (optional): the cross-host intake spool's parent. The router
# creates `<intake_dir>/<instance>/` in `provision` and, when an email router
# exists, reads candidates from it — so the router mounts the PARENT
# read-write, once. The email router's own mount set is one per-instance
# subdirectory each; that set is the adapter's to assert, not this script's.
intake_dir = doc.get("intake_dir")
if intake_dir:
    want(intake_dir, "rw", "intake_dir")

if instances_dir:
    # DISCOVERY: one mount for the whole tree, not one per instance.
    #
    # Per-instance mounts would defeat the entire point. The instance set is
    # found at poll time precisely so a new sandbox needs no re-render and no
    # restart; deriving a mount per instance would put the restart back,
    # because a container's mount set is fixed at `docker run`.
    want(instances_dir, "rw", "instances_dir")

    if not selected_json:
        sys.exit("config has 'instances_dir' but no 'selected_json' — "
                 "discovery finds directories, but only the host's verdict admits them")

    # THE VERDICT IS MOUNTED BY ITS DIRECTORY, NEVER AS A FILE, and this is
    # not a style choice. The host publishes it with temp-file + rename, so
    # the path gets a NEW INODE on every write. A file bind-mount binds the
    # inode it found at `docker run`: after the first rename the container
    # would read the ORIGINAL file forever, and nothing would say so — a
    # stale verdict that parses, admits the membership of an hour ago, and
    # looks entirely healthy. Mounting the directory follows the rename.
    verdict_dir = os.path.dirname(os.path.abspath(os.path.expanduser(selected_json)))
    want(verdict_dir, "ro", "selected_json's directory")

    # THE ROSTER DIRECTORY, READ-WRITE, over its read-only parent — the same
    # shape as `instances_dir`, and for the same reason. `router/roster.py`
    # writes `dirname(selected_json)/roster/roster.json`, which sits INSIDE the
    # `:ro` mount just above. Without its own `rw` bind the writer resolves the
    # right path and gets EROFS on every poll. It shipped that way: the design
    # checked that the router could SEE this directory and never that it
    # could WRITE it, and the first real deploy found it.
    #
    # EMITTED ONLY IF IT EXISTS ON THE HOST. Docker creates a missing bind
    # source rather than refusing, as root — which would make the runtime the
    # creator of the deployment's location, and the spec's roster section says
    # a runtime MUST NOT create it. So absent means no mount, and the writer
    # falls through to its logged "roster directory absent" skip. Not a
    # refusal either: a fleet whose adapter predates the roster is correct,
    # just rosterless — unlike `missing` above, which is silent non-delivery.
    #
    # A SYMLINK IS NOT A DIRECTORY here. A symlinked source would bind wherever
    # it points; the same pinned-directory discipline the router applies to
    # every agent-adjacent path. The literal "roster" is pinned against
    # `roster.ROSTER_DIRNAME` by `test_docker.py`: this script imports nothing
    # from the router, and a rename on one side only would bind a directory
    # the writer never uses.
    roster_dir = os.path.join(verdict_dir, "roster")
    if os.path.isdir(roster_dir) and not os.path.islink(roster_dir):
        roots.append((roster_dir, "rw"))

for name, spec in sorted(instances.items()):
    if not isinstance(spec, dict):
        sys.exit(f"instance {name!r} is not an object")
    root = spec.get("handoff_dir") or spec.get("namespace")
    if not root:
        sys.exit(f"instance {name!r} declares neither handoff_dir nor namespace")
    # Read-write: the router WRITES the inbound side (notices, message bodies)
    # and writes results/processed back on the outbound side. The `:ro` that
    # matters is the one SANDY applies to the AGENT's view of inbox — it is a
    # property of the agent's mount, not of the router's, and mounting this
    # read-only here would break delivery entirely.
    want(root, "rw", f"instance {name}")

# THE PATH RULES every identity mount below shares (hop paths, the key).
# Parents of everything the image itself runs: never mounted over, nor
# under (the interpreter, its library, the router's code, the kernel's
# filesystems).
IMAGE_TREES = ("/app", "/bin", "/dev", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
               "/sbin", "/sys", "/usr")
# Directories the image populates: never mounted over as a whole.
IMAGE_DIRS = ("/", "/boot", "/etc", "/home", "/media", "/mnt", "/opt", "/root", "/run",
              "/srv", "/tmp", "/var")

def within(a, b):
    """Whether `a` is `b` or inside it, by whole components."""
    return a == b or a.startswith(b.rstrip("/") + "/")

def hop_path(value, what, where="hop mounts"):
    if not isinstance(value, str) or not os.path.isabs(value):
        sys.exit(f"{where}: {what} must be an absolute path, got {value!r}")
    if os.path.normpath(value) != value:
        sys.exit(f"{where}: {what} ({value}) is not in normal form (a trailing '/', "
                 "'//', '.' or '..'): the router uses it exactly as written")
    if os.path.realpath(value) != value:
        sys.exit(f"{where}: {what} ({value}) is not its own realpath (a symlinked "
                 "component): it would mount wherever the link points")
    if value in IMAGE_DIRS or any(within(value, t) for t in IMAGE_TREES):
        sys.exit(f"{where}: {what} ({value}) is a container system path: an identity "
                 "mount there would replace what the image needs")
    return value

def hop_file(value, what, where="hop mounts"):
    """A file mounted by its directory: the file must be a regular file,
    never a symlink; its directory goes through `hop_path`."""
    if not isinstance(value, str) or not os.path.isabs(value):
        sys.exit(f"{where}: {what} must be an absolute path, got {value!r}")
    if os.path.islink(value):
        sys.exit(f"{where}: {what} ({value}) is a symlink")
    if not os.path.isfile(value):
        missing.append(f"{what}: {value}")
    return hop_path(os.path.dirname(value), f"{what}'s directory", where)



def check_nesting(new, where):
    """Each new (path, mode, what) against every mount so far, RESOLVED, and the
    config file: hop.root nested with NO other mount, and each read-only path
    nested with no read-write one. Then each joins the list."""
    # Comparing them as written as well would add nothing: each new path is
    # its own realpath, so it can sit inside a spelling only if that spelling
    # resolves to itself.
    others = [(os.path.realpath(p), mode, "an existing mount") for p, mode in roots]
    # The config file too: run.sh mounts it read-only by itself, outside this
    # list. Inside hop.root, the tree the downstream runtime's uid writes, it
    # could be replaced on the host and would be read at the next start,
    # plugin pin, peer uid and all; the read-only bind pins only the inode it
    # found.
    others.append((os.path.realpath(cfg_path), "ro", "the config file"))
    for i, (p, mode, what) in enumerate(new):
        rivals = others + [n for j, n in enumerate(new) if j != i]
        for q, qmode, qwhat in rivals:
            if not (within(p, q) or within(q, p)):
                continue
            if mode == "rw" or qmode == "rw":
                why = ("hop.root is nested with no other mount" if "hop.root" in (what, qwhat)
                       else "a read-only path is nested with no read-write one")
                sys.exit(f"{where}: {what} ({p}) overlaps {qwhat} ({q}, {qmode}): {why}")
        if not os.path.isdir(p):
            missing.append(f"{what}: {p}")
        roots.append((p, mode))


# THE HOP PATHS, only when the config has a `hop` section. A router with a
# transport plugin reads four things outside every path above: the hop tree
# the plugin writes (`hop.root`), the host registry (`registry_dir`), the
# delivered-domain artifact (`delivered_domains_file`) and the plugin file
# itself (`transport_plugin.path`). Without their mounts a run.sh-started
# router cannot see any of them: the plugin is refused at startup, the
# registry is absent so every instance is held, and the hop tree is empty.
#
# IDENTITY MOUNTS, like every mount here, and checked harder than the rest,
# because the loader uses these strings VERBATIM (`hop.root` is handed to the
# plugin as written; the plugin path must be its own realpath):
#   - absolute and already in normal form, never expanded or normalised here:
#     a spelling this script repaired would mount one path and leave the
#     router naming another;
#   - its own realpath: a symlinked component would bind wherever it points
#     on the host while the router names the link inside the container;
#   - existing, as everywhere above (docker would otherwise create it, as
#     root);
#   - never a container system path: an identity mount over a path the image
#     uses replaces it (a plugin in /usr/local/lib would shadow the
#     interpreter's own library);
#   - hop.root (rw, the tree the downstream runtime shares) nested with NO
#     other mount, and each read-only path nested with no read-write one: a
#     read-only path inside a writable mount, or containing one, would no
#     longer be what its mode says.
# The two FILES are mounted by their directory, for the reason the verdict
# above is: a file bind binds the inode it found, and a rename replaces it.
#
# Gated on the `hop` section, not on each key: without `hop` the list is
# exactly what it was, whatever else the config carries.
hop = doc.get("hop")
if hop is not None:
    if not isinstance(hop, dict):
        sys.exit("hop mounts: 'hop' is not an object")
    plugin = doc.get("transport_plugin")
    if not isinstance(plugin, dict) or "path" not in plugin:
        sys.exit("hop mounts: 'hop' needs 'transport_plugin' with a 'path'")
    if not doc.get("registry_dir"):
        sys.exit("hop mounts: 'hop' needs 'registry_dir'")
    new = [(hop_path(hop.get("root"), "hop.root"), "rw", "hop.root"),
           (hop_path(doc["registry_dir"], "registry_dir"), "ro", "registry_dir"),
           (hop_file(plugin["path"], "transport_plugin.path"), "ro",
            "transport_plugin.path's directory")]
    if doc.get("delivered_domains_file") is not None:
        new.append((hop_file(doc["delivered_domains_file"], "delivered_domains_file"), "ro",
                    "delivered_domains_file's directory"))

    check_nesting(new, "hop mounts")

# THE SIGNING KEY'S DIRECTORY (KEY_DIR), READ-ONLY, whenever the config has a
# `delegation` section: the router signs its peer tasks with the key at
# `delegation.signing_key.path`, and without this bind a run.sh-started router
# cannot read it. Gated on `delegation` alone, not on `hop`: the loader needs
# the key readable whenever delegation is configured, whatever else is.
#
# EXACTLY THE DIRECTORY, by the same rules as the hop files above: the key FILE
# is never a bind line (a file bind pins the inode it found, and a rotated key
# is a rename); the path is absolute, in normal form and its own realpath, so a
# symlinked component is refused rather than mounted where it points (the
# identity mount must be the path the router reads); never a container system
# path; and read-only, so it may not sit inside a read-write mount, nor contain
# one. And it holds EXACTLY ONE entry, the key itself, a regular file by lstat:
# the bind exposes the whole directory, so anything else in it (a .pub, a
# backup, a dot-file, a subdirectory) would be mounted into the container
# with the key. The deployment checks the same rule host-side; the public key
# lives in the config's inventory, never beside the seed.
delegation = doc.get("delegation")
if delegation is not None:
    if not isinstance(delegation, dict) or not isinstance(delegation.get("signing_key"), dict):
        sys.exit("key mount: 'delegation' needs 'signing_key' with a 'path'")
    key_path = delegation["signing_key"].get("path")
    key_dir = hop_file(key_path, "delegation.signing_key.path", "key mount")
    # Nesting first: a directory containing a read-write mount is refused for
    # THAT, before its extra entry is ever counted.
    check_nesting([(key_dir, "ro", "the signing key's directory")], "key mount")
    if os.path.isdir(key_dir) and os.path.isfile(key_path):
        extra = sorted(set(os.listdir(key_dir)) - {os.path.basename(key_path)})
        if extra:
            sys.exit(f"key mount: the signing key's directory ({key_dir}) must hold only the key; "
                     f"it also holds {', '.join(repr(e) for e in extra)}")

if missing:
    sys.exit("these paths in the config do not exist:\n  " + "\n  ".join(missing)
             + "\n\nSandy creates a handoff pair AT LAUNCH. Do not mkdir it by hand:"
               "\nthat produces host directories mounted into no container, which is"
               "\nwhy this refuses rather than letting docker -v create them for you."
               "\n\nA partially-wired fleet is normal — sandboxes get their pair the"
               "\nnext time they are launched. This container needs ALL of them at"
               "\nonce because a missing mount is silent non-delivery, not an error."
               "\nEither launch the sandboxes above (amp-sandy-adapter's"
               "\nlaunch-enrolled-once.py does it without disturbing running ones), or"
               "\nrun the router on the host instead — `python3 -m router --config ...`"
               "\ntolerates a not-yet-wired instance and simply drains nothing for it.")

seen = set()
# PARENT BEFORE CHILD. run.sh emits these as `-v` flags in order, and docker
# applies them in order: a parent mounted AFTER its child SHADOWS the child,
# so the rw instances tree would vanish behind a ro mount of its own parent
# and every delivery would fail on a read-only filesystem.
#
# Discovery makes that nesting real for the first time — `instances_dir` sits
# inside the directory holding `selected.json`. Sorting by component count
# puts every ancestor first, which is the only ordering that is correct
# whatever the layout turns out to be.
#
# Written after warning a host adapter about exactly this hazard in ITS mount
# emitter, and then reproducing it here: the first version of the discovery
# branch emitted the child first because that was the order the code read in.
roots.sort(key=lambda pm: len(pm[0].rstrip(os.sep).split(os.sep)))

for p, mode in roots:
    if p in seen:
        continue
    seen.add(p)
    print(f"{p}\t{mode}")
