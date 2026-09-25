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
