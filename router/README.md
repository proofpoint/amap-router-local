# router — the AMAP runtime

A host-side process, outside every sandbox, that moves AMAP artifacts
between two (or more) agent sandboxes on one box — so two agents, each
running the **unmodified, already-running** `claude-code` connector, can
mail each other with **no mail provider at all**. See the deployment that installs a connector against this router for the
design rationale and trust story this package implements; this file is the
operator-facing "how do I run it" doc.

## Layout

Every instance has **two roots with different trust properties** —
`inbox_root` (host-written) and `outbox_root` (agent-written) — derived
from whichever ONE config key the instance declares (`router/config.py`'s
`InstanceConfig`):

| Config key | Mode | `inbox_root` | `outbox_root` | Posture |
|---|---|---|---|---|
| `handoff_dir: P` | `handoff` (**primary**) | `P/inbox` | `P/outbox` | a split-root pair mounted separately by the host — `inbox` is a REAL `:ro` mount, `outbox` is `rw` |
| `namespace: P` | `namespace` (kept working) | `P/inbound` | `P/outbound` | the older single-tree AMAP layout — both sides `rw` (Posture A) |

Exactly one key per instance; giving both, or neither, is a config error
naming the offending instance. See the read-only-inbound posture note in
the deployment notes for why two roots exist even in `namespace` mode (the router
never assumes the mount flag is doing the work, because in that mode
nothing is).

The connector (`inbox-delivery` / `inbox-mcp-vol` / `inbox-submit`) resolves
its three directories independently, and is wired to the derived roots —
never to `$MAILBOX_ROOT_DIR`'s flatter fallback:

| Connector tool | Env var | Fallback (never used here) | What it does there |
|---|---|---|---|
| `inbox-delivery` (the daemon, via the adapter's `relay.sh`) | `INBOX_NOTICE_DIR` → `AMAP_DELIVERY_MAIL_NOTICE_DIR` | `$MAILBOX_ROOT_DIR/notices` | acts on `notice-<id>.json`: a content-free doorbell into the session for mail; records consumption in its private delivered ledger |
| `inbox-mcp-vol` | `INBOX_MESSAGE_DIR` | `$MAILBOX_ROOT_DIR/messages` | reads `notice-<notice_id>.json` for `read_message` |
| `inbox-submit` | `OUTBOX_DIR` | `$MAILBOX_ROOT_DIR/dropbox` | writes `req-<id>.json`; reads `results/<id>.json` |

```
INBOX_NOTICE_DIR=<inbox_root>/notices
INBOX_MESSAGE_DIR=<inbox_root>/messages
OUTBOX_DIR=<outbox_root>
MAILBOX_AGENT_ID=<instance-name>
```

Setting these three explicit env vars per instance, rather than relying on
`$MAILBOX_ROOT_DIR`, makes the connector's dropbox root **be** `outbox_root` —
so `<outbox_root>/results/` and `<outbox_root>/processed/` land exactly on
AMAP §2's canonical layout with zero connector changes. The router then
works entirely in terms of that same tree — shown here for `handoff_dir`
mode (`namespace` mode is identical, with `inbox`/`outbox` read as
`inbound`/`outbound`):

```
<handoff_dir>/
  outbox/
    req-<id>.json            # agent -> router (agent writes)
    req-<id>.attachments/    # agent -> router: sidecar bytes, ordinals 0 1 2 … (agent writes;
                              #   AMAP v2.3.0 §3 — consumed and swept once the request is answered)
    results/<id>.json        # router -> agent (router writes)
    processed/req-<id>.json  # router: courtesy archive, never read back —
                              #   connector-deletable at will (AMAP v2.2.0 §2)
  inbox/
    notices/notice-<id>.json    # router -> agent (router writes)
    messages/notice-<id>.json   # router -> agent (router writes)
    notices/<notice-id>.attachments/    # router -> agent: bytes this router asserts clean,
                                        #   ordinals 0 1 2 … (router writes; AMAP v3.0.0 §2/§5)
                                        #   BARE notice-id — the spool FILE has the
                                        #   `notice-` prefix, this directory does not
```

**Host <-> container mapping:** the router runs on the HOST,
outside every sandbox, so `handoff_dir` in its config is a HOST path —
`<SANDBOX_DIR>/handoff` — and `<SANDBOX_DIR>/handoff/inbox` /
`<SANDBOX_DIR>/handoff/outbox` are two independent bind-mount SOURCES that
the host maps to `~/.handoff/inbox` (`:ro`) and `~/.handoff/outbox` (`rw`)
INSIDE the container. `mcp-servers.json` (the connector's MCP registration,
merged into every sandbox by the host adapter) therefore names the
CONTAINER-side paths — `<container-home>/.handoff/inbox/notices`, etc. —
while `provision NAME` here prints the matching HOST-side paths under
whatever `handoff_dir` that instance's config declares.

**The container home is deliberately not spelled out here.** It is the host
adapter's to choose and it has changed: a sandbox user/home rename is
scheduled on that side, and this paragraph named the old one until someone
thought to check. Nothing in `router/` reads it — this router deals in host
paths only, and `docker/Dockerfile` pins its own `HOME=/tmp` precisely so the
container it runs in has no opinion about the agent's. So the rename costs
this repo nothing, and the way to keep that true is to not write the value
down. `test_layout_agreement.py` pins the two to agree
mechanically: a drift here is the exact class of bug that wastes a live
bring-up. **That test lives in the HOST ADAPTER's repository, not this one**
— it has to, because its claim is that two repos agree, and it imports this
package's declared test surface (`router/tests/__init__.py`,
`PUBLIC_TEST_SURFACE`) to build the fixture from the side that derives the
layout. Citing it as `router/tests/...` here was wrong for as long as this
paragraph has existed.

No code or config in this package hard-codes a volume name — an instance's root is
an explicit config path. A documentation-only example for `namespace`
mode: place it under `<sandbox-dir>/claude/mail/` (a neutral
leaf dir name, picked per SCOPE.md's "operator decision" that it not be
named anything) — outside the workspace, so nothing lands in a git repo.
Router-private state (the delivery ledger, idempotency anchors, held
requests, first-sight markers, quarantine copies) lives in a **separate**
`state_dir`, validated at config-load time to be unreachable from every
instance's declared root, in either mode.

## Config

```json
{
  "state_dir": "/path/to/router-state",
  "instances": {
    "alice": { "handoff_dir": "/path/to/sandboxes/alice/handoff",
               "peers": ["bob"] },
    "bob":   { "namespace": "/path/to/sandboxes/bob/claude/mail",
               "peers": ["ALLOW_ANY"] }
  }
}
```

(A config may freely mix modes across instances, as shown — each is
independent.)

- Three OPTIONAL top-level keys govern attachment transport (AMAP v2.3.0
  §3/§5 — see "Attachment transport" below): `attachment_max_bytes`
  (default 8 MiB, per-file), `attachment_max_count` (default 16),
  `attachment_max_total_bytes` (default 32 MiB, combined). Each must be a
  positive integer if given; `attachment_max_total_bytes` must be >=
  `attachment_max_bytes`. Router-wide, not per-instance.
- `state_dir`, and every instance's declared root (`handoff_dir` or
  `namespace` — exactly one of the two, per instance), MUST be absolute
  paths, and MUST NOT be nested inside one another (in either direction)
  or inside another instance's declared root — checked at load, not
  assumed, and checked over the DECLARED root even across mixed modes
  (a `namespace` nested inside another instance's `handoff_dir` is still
  caught).
- An instance name matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` — the sandy
  slug alphabet, so the slug IS the instance name — and becomes the local-part
  of its synthetic address: `agent.<name>@local`. That address appears as
  `draft.to` on a submit and as `message.from` on a notice. Two names that
  differ only by case are refused at load (they would share one directory
  under `state_dir` on a case-insensitive filesystem), and `amap.router`, the
  router's own local part, is refused as an instance name.
- `mail_graph: "all"` is the OPTIONAL fleet-level shorthand for "every
  instance may cold-initiate to every other". Expanded at load into the same
  per-instance `peers` sets an explicit list produces, so nothing downstream
  knows the word exists. Refused beside any instance that also declares
  `peers` — one source or the other. It needs no `fleet_domain` (the mail
  lane addresses `agent.<name>@local`) and, unlike `task_graph`, it INCLUDES
  `namespace`-mode instances: that exclusion is about whether a peer notice
  can be trusted to have come from this router, and it does not transfer to
  the mail lane. **It is not `ALLOW_ANY`** — that relaxes only the side
  declaring it and still owes mutuality; this declares both directions, so
  mutuality is satisfied by construction.
- `peers` governs **cold initiation only** — the first message in a
  thread. Replies never consult it (see "Reply vs. cold send" below).
  `ALLOW_ANY` is the literal wildcard member (picked over `"*"` for
  greppability). Peers are verified **mutually**: alice can cold-send bob
  only if bob's `peers` also names alice (or `ALLOW_ANY`) — listing a peer
  one-sidedly grants nothing. The full n×n "who can cold-initiate to whom"
  matrix is never stored; it's derived on demand (`peers` / `matrix`, or
  `config.derive_matrix`) from `peers` alone.

## Deployment posture

Two config modes, same router code, same enforcement (see "Layout"
above): `handoff_dir` (the host's `the host's split-root mode` pair — inbound is a
REAL `:ro` mount) and `namespace` (the older single-tree layout — both
sides `rw` — the weaker posture, where the split is conceptual only). Under `namespace` mode an agent
can forge a deliver-notice straight into its own inbox — accepted
prototype delta, not worked around (`tests/test_forged_notice.py` proves
the router doesn't fall for it: a reply to a self-forged notice fails
closed with `unresolved_reply`, because binding only ever reads the
router's own private ledger). Switching an instance to `handoff_dir` mode
changes nothing in this package's enforcement — it's a config change, not
a code change.

In operator terms: the accepted `namespace`-mode delta is that a
compromised or merely buggy agent can lie **to itself** — plant a fake
notice in its own inbox and read it back — but it can never redirect a
real send, in EITHER mode. Binding a reply reads only
`state_dir/<sender>/delivered/notice-<id>.json`, the router's own private
ledger written at delivery time; nothing an agent writes into its own
inbox side is ever consulted for that decision. The forged notice is a
self-inflicted, contained confusion, not an exfil path.

**The outbox side has no integrity property in EITHER mode** — the host's own
`outbox` mount is `rw` by design (the agent must be able to submit), so it
remains untrusted input to the host regardless of config mode. This is
also why the first-sight quarantine exists (see below): `the host's split-root
mode` being passive-tier (no prompt of any kind) means an agent, or a repo it
was pointed at, can stage outbox entries before this router has any business
draining that outbox at all.

## First sight + the staged-request quarantine (before ANY drain)

**There is no operator command before the first drain.** There used to be —
`approve NAME` — and it is retired. The deliberate human act is **enrolment**:
putting the instance in this config at all. That is upstream of the router
seeing the root, so the boundary "nothing that existed before the router first
saw this outbox" sits strictly after it.

What the first poll does instead: the FIRST time `drain_instance` sees an
instance root, before it drains anything from it, it snapshots every
`req-*.json` filename (+ sha256 + size) already sitting in that outbox into a
router-private marker (`state_dir/<name>/first-seen.json` — outside every
sandbox, so the agent can neither forge nor backdate it) and **never delivers
any of them**. `status`/logs say so once, and the loudness is earned by the
count rather than by the event: with something staged the line carries
`** FIRST SIGHT — N staged request(s) quarantined, never delivered **`, and
with an empty outbox a quiet `(first sight — outbox was empty, nothing
quarantined)`. On a fresh fleet every instance has its first sight at once, so
a banner that shouted on all of them would be false on most and ignored on the
rest.

This closes a passive-tier gap: `the host's split-root mode` can be enabled by
a workspace's own config — including one committed to a repository — with no
prompt ever shown, so an outbox can be pre-staged before any delivery
relationship existed.

Any request whose filename is a member of that snapshot is quarantined —
`rejected` / `quarantined_pre_approval` (the reason code kept its old spelling
because it is on the wire), archived, and preserved under router-private
`state_dir/<name>/quarantine/` for the operator — never delivered, no notice
ever sent. A fresh filename appearing afterwards is a perfectly ordinary send.

The snapshot is taken **once** and persisted; later polls read the marker and
never re-snapshot. An existing deployment upgrading across the retirement
adopts its old `approval.json` snapshot rather than taking a fresh one, so a
live outbox is not quarantined by the upgrade itself.

Full design rationale, including exactly what the filename-membership check
does and does not guarantee (it is never an mtime check — mtime is
agent-controllable in every posture), lives in `router/firstsight.py`'s module
docstring.

## Resetting an instance (clean slate)

`reset` gives an operator a way to wipe an instance's handoff mailbox
between live bring-up runs — a **content-only** wipe, and a **combined**
one:

```
python3 -m router --config C reset alice [bob ...] --yes   # or: --all
python3 -m router --config C reset alice --dry-run         # preview only, removes nothing
```

**Content-only, never the roots.** `reset` empties the CONTENTS of
`inbox_root`/`outbox_root` — it never deletes the roots themselves, or the
four skeleton leaves (`notices/`, `messages/`, `results/`, `processed/`).
In `handoff_dir` mode those two roots are the host's own live bind-mount
SOURCES ("Layout" above); deleting one out from under a running container
strands its mount on a deleted inode, and the agent then sees an empty
tree that never recovers until the sandbox relaunches. Emptying in place
needs no session downtime, keeps every mount valid, and means **reset
creates nothing, ever** — the same invariant `provision`'s handoff-mode
refusal protects (see `router/provision.py`'s `ProvisionRefusesToCreateHostOwnedDirsTest`).
Removed: every direct entry of each root other than its two skeleton
leaves (stray `req-*.json`, `.attachments/` sidecar dirs, and anything else
an agent — or a router version that predates this one — left at the top of a
root), plus the CONTENTS of all four skeleton leaves.

**Mailbox and router-private state are wiped in the SAME operation —
never one without the other.** A mailbox-only wipe produces a poisoned
slate, not a clean one:

- **req_id reuse.** The connector derives its next `req_id` from
  `max(pending, processed, results) + 1` over the agent-visible outbox —
  wipe that alone and the next request reuses an id whose router-private
  digest (`state_dir/<name>/results/<id>.json`) still refers to the OLD
  request; the drain path then refuses it as `req_id_reused` (see
  `router/tests/test_req_id_reuse.py`) instead of accepting a perfectly
  legitimate first post-reset send.
- **Stale first-sight snapshot.** `state_dir/<name>/first-seen.json` carries
  the `outbox_snapshot` that gates the staged-request quarantine (above).
  Keep it across a mailbox wipe and a genuinely NEW post-reset file that
  happens to reuse an old filename (common, since the req_id counter also
  restarts at 0) is quarantined instead of delivered.

`reset` closes both by clearing `state_dir/<name>` in full (`first-seen.json`
first, then `results/`, `delivered/`, `held/`, `quarantine/`) in the same
call that empties the mailbox.

**This means a reset returns the instance to NEVER SEEN.** There is no way
to discard a poisoned snapshot without discarding the marker it lives
inside — reusing the old marker after a mailbox wipe is exactly the bug
this command exists to avoid. The next poll is a first sight again, and
`reset`'s own success output says so explicitly, every time.

**Quiesce the agent, not just the poll loop.** The next poll snapshots the
outbox as it finds it — so anything the agent writes into the outbox between
a `reset` and that poll is captured by the fresh snapshot and permanently
quarantined (rejected, never delivered; recoverable only by resubmitting
under a different filename). Stopping the poll loop alone does not help,
because the snapshot happens when it restarts. Quiescing the agent is the
clean way
to avoid hitting this.

**The two mailbox roots are probed and emptied independently.** Under
`namespace` mode the agent owns both `inbox_root` and `outbox_root` and
can delete or replace either one on its own; `reset` never folds "one
side is missing" into skipping the whole mailbox — the summary and
`--dry-run` output report `inbox`/`outbox` availability separately, and
whichever side is actually present still gets emptied.

Safety: every mailbox removal goes through a directory file descriptor
pinned (`O_NOFOLLOW`) at the moment each leaf is opened, and every
subsequent removal from that leaf is `dir_fd`-relative — never by
re-walking a path string — so a rename anywhere in the tree, at any point
after that leaf was pinned, cannot redirect a removal outside it. On top
of that, every named instance is namespace-containment-probed
(`util.verify_namespace_containment`) up front, before ANY of them is
touched, for a fast early refusal — a symlinked leaf pointing outside the
instance root aborts the whole call with nothing deleted anywhere,
matching `provision()`'s existing all-or-nothing refusal. `reset` refuses
to run at all without `--yes`; `--dry-run` prints exactly what would be
removed and removes nothing. Full design rationale (including the
state/mailbox/state ordering that keeps a mid-crash OR mid-drain reset
fail-closed rather than half-poisoned, and the pinned-fd removal
mechanism) lives in `router/reset.py`'s module docstring.

## Commands

```
python3 -m router --config C once [--json]                          # drain every instance once, then exit;
                                                                      # --json prints the per-instance drain summary
                                                                      # to stdout as {instance: {counter: n}} — the
                                                                      # same shape status.json carries as last_summary
python3 -m router --config C run --interval N                       # loop forever, poll every N seconds; writes status.json after every poll
python3 -m router --config C peers [--json]                         # print declared peer lists + the derived allow matrix + the peer task graph (alias: matrix);
                                                                      # --json prints ONLY the graph as {recipient-address: [sender-address, ...]}
python3 -m router --config C status [--json]                        # print (or dump) the last-written status.json
python3 -m router --config C provision NAME [--format env|json] [--no-create]
                                                                      # print the four connector env vars for NAME; creates its skeleton dirs (and, on the
                                                                      # peer lane, peer/{notices,messages} + <intake_dir>/NAME/) unless --no-create;
                                                                      # --format json adds address, router_address, peer, intake — see "Peer lane"
python3 -m router --config C reset {NAME [NAME...]|--all} [--yes|--dry-run]
                                                                      # wipe NAME's (or every instance's) mailbox contents + router-private
                                                                      # state together; returns the instance(s) to NEVER SEEN — see "Resetting an
                                                                      # instance" above
```

`matrix` is kept as an exact alias for `peers` (same output) so nothing
documented against the earlier `--matrix` flag breaks. `once` is what the
test suite drives (`service.run_once`) — there is no wake to build: the
router's whole delivery mechanism is writing the notice file.
The connector's own watcher (`inbox-delivery`, already running, unmodified)
does the rest.

## Status

"`/health`-style" is a **file, not a socket**: `run` writes
`state_dir/status.json` (atomically) after every poll. Deliberately not a
listening endpoint — stdlib-only, zero new listener surface on a
security-sensitive host process, and fully testable with temp dirs (no
threads, no ports). Read it directly, or via `status [--json]`:

```
$ python3 -m router --config C status
last poll 2s ago (17 polls since 2026-08-13T00:00:00Z, pid 4191)
alice  drained=12 accepted=9 rejected=2 for_human=1 quarantined=0 errors=0
bob    drained=1 accepted=0 rejected=1 for_human=0 quarantined=1 errors=0  ** FIRST SIGHT — 1 staged request(s) quarantined, never delivered **
carol  drained=0 accepted=0 rejected=0 for_human=0 quarantined=0 errors=0  (first sight — outbox was empty, nothing quarantined)
```

Field glossary:

| Field | Meaning |
|---|---|
| `pid` | the router process that wrote this file |
| `started_ts` | when THIS process started — the counter window's start |
| `last_poll_ts` | timestamp of the most recent poll (age is what `status` prints; there's no baked-in staleness heuristic — the operator judges) |
| `polls` | number of polls this process has run |
| `instances.<name>.last_summary` | the most recent poll's `drain_instance` summary, verbatim — carries `first_sight: 1` on the poll that snapshotted this instance |
| `instances.<name>.totals` | cumulative per-outcome + per-refusal-path counts, this process lifetime, including `first_sight` and `quarantined`, and on the peer lane the `peer_*` outcome counters (see "Peer lane") |
| `instances.<name>.peer_alerts` | peer lane only: the most recent `held` / `refused` / `ambiguous_target` outcomes (notice id, sender, recipient, ts), rendered as banners by `status` |
| `instances.<name>.placed_but_denied` | peer lane only, and NOT per process lifetime: the notices this router's ledger says it placed in `<name>`'s peer tree whose latest recorded outcome is `denied` or `refused` (`notice_id`, `sender`, `recipient`, `outcome`, `outcome_ts`, `recorded_ts`, `req_id`), recomputed from `state_dir/<name>/outcomes/` every poll and replaced, never accumulated; `status` banners it as `PLACED BUT DENIED` |
| `instances.<name>.last_error_ts` | timestamp of the most recent poll that saw `instance_errored` or any `outbound_errored`, or `null` |

An instance whose most recent poll's `last_summary` carries `first_sight`
says so on its line, in one of two texts: the loud
`** FIRST SIGHT — N staged request(s) quarantined, never delivered **` when
`quarantined` is non-zero, and a parenthesised
`(first sight — outbox was empty, nothing quarantined)` when it is not. The
loud one is the line that explains why an outbox that was full went silent;
it is keyed on the count, not on the event, so it cannot fire on an instance
where nothing was refused.

**Counters are per-process-lifetime, not a ledger.** They reset to zero on
every restart (`started_ts` marks the window). The ledger and idempotency
anchors under `state_dir/<name>/{results,delivered,held,quarantine}` and
the first-sight marker at `state_dir/<name>/first-seen.json` already persist
the ground truth `status.json` summarizes — this file is an observability
convenience, never a source of record.

## Peers review artifact

`peers` (alias `matrix`) is the pre-flight review tool for "who can
cold-initiate to whom" before wiring up a new instance. Sample output with
one `ALLOW_ANY` declarer (NOT a full mesh — alice and carol never mutually
list each other, so that cell stays `-` in both directions) — output
pasted verbatim from a real run against this three-instance config:

```
$ python3 -m router --config C peers
alice   peers: bob
bob     peers: ALLOW_ANY  ** ANY — will accept cold-initiation from EVERY instance that also lists bob **
carol   peers: bob

       alice   bob*  carol
alice      .    yes      -
bob*     yes      .    yes
carol      -    yes      .

* declares ALLOW_ANY; mutuality still required — ALLOW_ANY only relaxes the declaring side

derived from per-instance peers at render time — never stored; governs COLD INITIATION ONLY (replies bind via the private ledger)
```

When every off-diagonal cell is `yes` (which requires at least two
instances — a single-instance config is never a full mesh, since it has no
off-diagonal cells to check), a `!! FULL MESH` banner is printed above the
legend — obvious at a glance rather than something an operator has to
notice by scanning every cell. The banner does not replace the legend:
both print when applicable, independently (a config where every instance
declares `ALLOW_ANY` prints both). The matrix itself is **derived, never
stored** (`config.derive_matrix`, recomputed fresh on every call) and
**governs cold initiation only** — a reply never consults it; recipient
binding for a reply always comes from the private ledger (see "Reply vs.
cold send" below).

## Wiring to a real agent sandbox

1. Add the instance to the router config's `instances` map (see "Config"
   above) — for a real agent sandbox, `handoff_dir: <SANDBOX_DIR>/handoff`
   (the primary mode) — and its `peers`.
2. Run `provision NAME` to get the four env vars and create the AMAP
   §2-canonical skeleton directories inside that instance's two roots
   (idempotent — safe to re-run):

   ```
   $ python3 -m router --config C provision alice
   INBOX_NOTICE_DIR=/path/to/sandboxes/alice/handoff/inbox/notices
   INBOX_MESSAGE_DIR=/path/to/sandboxes/alice/handoff/inbox/messages
   OUTBOX_DIR=/path/to/sandboxes/alice/handoff/outbox
   MAILBOX_AGENT_ID=alice
   ```

   `--format json` emits the same four keys as a JSON object shaped for
   pasting into an `.mcp.json` server entry's `"env"` block. `--no-create`
   prints the env vars without touching the filesystem at all. Provisioning
   writes ONLY inside the instance's own declared root — see the "Layout"
   table above for exactly what each connector tool does with each var,
   and for the host-path/container-path mapping.
3. `mcp-servers.json` (this repo's ONE source of truth for the connector's
   MCP registration, merged into every *enrolled* sandbox by
   `provision-sandboxes.py` — a sandbox must be explicitly enrolled with
   `--enroll <slug>` before it will be touched at all, see that script's
   module docstring) already names the CONTAINER-side equivalents of the
   THREE directory
   vars — nothing to hand-wire for those under `handoff_dir` mode.
   **`MAILBOX_AGENT_ID` is different: it is per-sandbox, not a shared
   constant, so it cannot simply be listed as a fixed value in a file
   merged byte-for-byte into every sandbox.** `provision-sandboxes.py`
   injects it automatically at merge time (`servers_for_slug`), stamping
   in that sandbox's the host slug — which is only correct if you name the
   router instance for that sandbox IDENTICALLY to the slug. If your
   instance name can't match the slug (e.g. the slug contains a character
   the instance-name pattern above forbids), or you're not running
   `provision-sandboxes.py` at all, wire `MAILBOX_AGENT_ID` by hand
   instead — the shipped file's placeholder value,
   `__REPLACE_WITH_SANDBOX_SLUG__`, is deliberately broken so a missed
   wiring fails loud (`agent_id_mismatch`) rather than silently landing on
   `inbox-submit`'s own `"sandbox"` default. Under the older `namespace`
   mode, wire all four env vars into that agent sandbox's MCP server
   config for the `claude-code` connector (`inbox-mcp-vol` / `inbox-submit`;
   the daemon's variables through its wrapper) by hand.
4. **Expect the first poll to quarantine anything already staged** — there is
   no approval step to run, but there is a boundary to know about. See "First
   sight + the staged-request quarantine" above; `status` says so once, and
   the requests are preserved under `state_dir/alice/quarantine/`.

**This tool does not write any host-side file** — the following facts are
documentation only, verified against the real the host behavior (SCOPE.md
"Provisioning facts"), for hand-editing when you get there:

- The per-sandbox user config is a **sibling file**,
  `<sandbox-dir>.claude.json` — *not* inside the sandbox
  directory tree.
- The host strips the `projects` key on first seed and re-applies
  `tipsDisabled`/`installMethod`/trust entries on every launch — provision
  *around* those keys when hand-editing that file.
- `~/.claude/plugins/` is inside the mounted `claude/` dir, so a plugin
  dropped host-side at `<sandbox-dir>/claude/plugins/` is
  picked up without touching the workspace.
- `.claude/{commands,agents,plugins}` are writable overlays, not `:ro` —
  don't assume everything under `.claude/` is protected.

## Reply vs. cold send

- **Reply** (`in_reply_to` present, see "Which field carries the reply
  key" below): the recipient is resolved from the router's own private
  delivery ledger — never from anything an agent wrote. The agent's
  `draft.to`/`draft.cc` are discarded outright (logged, never surfaced as
  if they mattered). A reply key that doesn't resolve to a ledger record
  this router itself wrote for this sender ⇒ `rejected` / `unresolved_reply`.
  This is what makes the exfil test hold: a compromised agent can lie to
  itself, but it cannot redirect a send.
- **Reply to an internet-originated thread** (added 2026-09-03, one branch
  in `outbound._drain_reply`): a ledger record with `from_instance: null`
  binds a reply OUTSIDE the fleet only when all three of
  `transport == "smtp"`, `origin == "external"` and a non-empty
  `from_address` hold on the record. Nothing in this repo writes such a
  record — a combined runtime's inbound SMTP leg does, under the recipient.
  When they hold, the injected `deliver_backend` is called with
  `recipient=None` and the record as `reply_to_record`
  (`deliver.DeliveryBackend`, "THE ONE EXTENSION"); the result is
  `accepted`/`recipient_bound` with the record's `from_address` as its one
  recipient, `draft.to`/`cc` discarded as on the local branch. The default
  local backend has no leg out and raises `deliver.ExternalReplyUnsupported`,
  answered once as `queued_for_human`/`delivery_failed`. A null sender that
  fails the three-part test — a router DSN record — is `unresolved_reply`,
  as before.
- **Cold send** (no reply key present on either field): recipient set =
  `to ∪ cc`. Every address must parse as `agent.<known-instance>@local` and
  pass the mutual allowlist check. One governing outcome for the whole
  request — never a partial delivery.

### Which field carries the reply key (D1)

AMAP §3 names the *top-level* `in_reply_to` field as the binding key for a
reply. But the real, unmodified `inbox-submit` binary — both its CLI
`--reply-to-id` flag and its MCP `submit` tool's `in_reply_to` argument —
only ever writes that value into `draft.reply_to_message_id`
(`make_submit_request` in `inbox-submit`); it never emits the top-level
field at all. Since this router's whole point is driving the connector
*unmodified*, it recognizes both:

- top-level `in_reply_to`, if present and non-empty, wins;
- else `draft.reply_to_message_id`, if present and a non-empty string, is
  used as the reply key;
- if neither is present (or both are empty/null), the request is a cold
  send.

This is sound because `deliver.py` deliberately coincides `message_id ==
notice_id` (see "Known limitation" below) and no external mail provider
exists in this substrate — so every id an agent could legitimately name in
either field is a router-private ledger key, and resolution itself is
**unchanged**: `binding.read_ledger_record` still only ever trusts
`state_dir/<sender>/delivered/notice-<id>.json`, fail-closed
(`rejected`/`unresolved_reply`) on anything that doesn't resolve there,
regardless of which field supplied the candidate id. Only the *intent*
signal ("this is a reply") is being read from a second place; the
*recipient* still never comes from anything the agent wrote.

## Peer lane (AMAP 3.1.0 peer-origin profile)

Work delegation between agents in different sandboxes, same principal:
a second inbound tree, `<handoff_dir>/peer/{notices,messages}`, a sibling of
`inbox/`, holding `kind: "peer"` notices that only this router writes and
that the in-sandbox delivery daemon (the AMAP connector) injects into
the agent's session as a teammate's request. The tree IS the origin
assertion — "authenticated same-principal origin, unscreened content" — so
what goes into it is decided by write authority and declared edges, never by
a field in the message. Design record: `delivery_design.md` and `RULINGS.md`
in the connector's repo; the wire is the spec repo's
`spec/peer-origin.md`; this section is the operator's
view.

**Config.** Five optional top-level keys and one per-instance key:

```json
{
  "state_dir":    "$HOME/.sandy/router-state",
  "fleet_domain": "example.invalid",
  "intake_dir":   "$HOME/.sandy/router-intake",
  "instances": {
    "analyst":     { "handoff_dir": ".../analyst/handoff",     "peer_senders": ["coder"] },
    "mail-reader": { "handoff_dir": ".../mail-reader/handoff", "peer_senders": ["analyst"] },
    "coder":       { "handoff_dir": ".../coder/handoff",       "peer_senders": ["analyst"] }
  }
}
```

- `fleet_domain` (lowercase bare domain) switches addressing on BOTH lanes:
  every agent is `<instance>@<fleet_domain>`, the router is
  `amap.router@<fleet_domain>` (derived; the `.` keeps it out of the
  instance-name charset, so it never parses as an agent and never appears
  in any allowlist). Without it, addressing stays `agent.<name>@local` and
  there is no peer lane. Changing it is a flag day for memorised addresses;
  reply binding survives (the ledger binds on instance names).
- `peer_senders` is the directed task graph, declared on the RECEIVER: who
  may task this instance. No wildcard, no mutuality. Refused without a
  domain; refused when either end is a `namespace`-mode instance (a peer
  notice in an agent-writable tree asserts nothing, and a reply travels the
  reverse edge into the SENDER's tree); refused when the same ordered pair
  is also a mutual `peers` pair — **the lanes are disjoint per ordered pair
  by `ConfigError`**, so nothing a sender writes can pick its lane. In the
  first fleet the adapter renders `peers` empty: the mail lane between
  agents is closed, and a submit with no edge is held
  (`recipient_not_allowlisted`), loudly, on `status`.
- `sender_exposure_window_seconds` (default 86400) and
  `peer_reply_window_seconds` (default 604800) — below.
- `intake_dir` — the cross-host intake spool's parent; `provision` creates
  `<intake_dir>/<instance>/`, `docker/derive-mounts.py` mounts it. Nothing
  reads it until an email router exists.

**Routing is recipient policy on the ordinary submit-request** — no new
shape, no `delegate` tool. A cold submit whose single `draft.to` is on a
declared edge from the drained sender is `accepted`/`peer_routed`, and
`result.message_id` is the peer message id (= `notice_id`, 32 hex,
unguessable, bare in every document). More than one recipient or any `cc`
on such a submit is `rejected`/`peer_single_recipient` — refused whole. No
edge: exactly the mail-lane decision above. A reply whose key resolves to a
peer notice this router placed travels the REVERSE edge as a peer notice
with `in_reply_to` set: always along a declared edge, else within
`peer_reply_window_seconds` of the notice, else
`rejected`/`peer_reply_window_expired`. An unresolvable key stays
`rejected`/`unresolved_reply` on both lanes, never stripped — **a peer
notice carries `in_reply_to` iff this router resolved it from its own
ledger**, the peer-origin profile's invariant (§4).

**What a peer notice carries.** Same shape as a deliver-notice
(`peer-notice.schema.json`): `kind: "peer"`, `message.mailbox: "peer"`,
`message.from` = the sender's address as asserted from the drained outbox
(never from the request), no `provenance`, attachments published under
`peer/notices/<notice-id>.attachments/` — the same SHAPE as the mail lane but
by rule rather than inheritance (`peer-origin.md` §1d: bytes resolve only
within the `notices/` directory of the tree the enclosing document was read
from, so a peer notice cannot point into the mail sidecar dir or vice versa) —
and
`message.sender_exposure` — this router's assertion about the SENDER:

```json
"sender_exposure": {"asserted_by": "amap.router@example.invalid",
                    "external_mail_delivered": false,
                    "window_start": "2026-09-02T12:00:00Z", "window_end": "2026-09-03T12:00:00Z"}
```

"Was external mail written into the sender's mail tree in this window" —
the ledger for the sender first, then a bounded listing of its
`inbox/notices/` for ids this router did not write. In this fleet it is
asserted `false` (not omitted: the router is the only writer and knows).
`window_start` is clamped to the sender's `first_seen_ts` after a reset. A
submit-request carrying `sender_exposure` is `rejected`/`malformed_request`
by the closed envelope before policy runs. Advisory only; nothing here reads
it back. See `router/exposure.py`.

**Delivery outcomes and DSNs.** The daemon reports each notice's last hop
into `outbox/ext/claude-code/outcomes/peer-<id>.json`
(`delivered | held | denied | refused | ambiguous_target | inject_failed`).
`claude-code` is the connector id the spec pins: it does not change when the
connector's repository is renamed, and this router treats it as opaque. It is
the ONLY directory scanned. A compatibility path under the old repo-tracking
spelling was read alongside it for one release and was retired on 2026-09-22;
`ext/` is agent-writable, so an outcome written under any other id sits there
unread. That retirement was a deliberate edit rather than a cleanup, and the
reason generalises to any future change here: an outcome nobody reads is
silence, this router never infers anything from silence, and so nothing it
observes would report the mistake. `router/tests/test_outcomes_ext_path.py`
is what says which directory is scanned, in place of that missing signal.
Every poll reads that directory with the outbox discipline, records each
outcome once per `(tree, notice_id, outcome)` under
`state_dir/<recipient>/outcomes/`, unlinks the file, and acts: `denied` and
`refused` send the SENDER a DSN — a `deliver` notice in its `inbox/` from
`amap.router@<domain>`, subject `Not delivered: <outcome>`, `in_reply_to` the
peer id, router-authored body only (the daemon's free-text `detail` is
audited, never forwarded); `held`, `refused` and a recurring
`ambiguous_target` are operator banners on `status`, and the
placed-but-denied list (above, `status.json` glossary) is a fourth. Outcomes
are informational, written by the agent's uid; they change what a sender is
told and what an operator sees, never what the ledger or audit log records —
which is why every DSN sentence and every banner is worded as the receiving
sandbox's CLAIM ("the recipient's sandbox reported that ..."), never as a
fact the router established. See `router/outcomes.py`.

**Audit log.** `state_dir/<instance>/audit/log.jsonl`, append-only, one
JSON object per line, filed under the instance whose tree was written:
`peer_notice_placed`, `peer_refused`, `outcome_consumed`,
`outcome_discarded`, `dsn_sent`, `reset`. It is the one piece of
router-private state `reset` preserves (it appends a `reset` line
instead). Shapes in `router/audit.py`.

**Bring-up order.** `peer/` must exist before the container that mounts it:
sandy launch → `provision NAME` (creates `peer/{notices,messages}` and
`<intake_dir>/NAME/`; idempotent) → enrolment. `provision NAME --format
json` reports the host paths the adapter mounts:

```json
{
  "INBOX_NOTICE_DIR": ".../handoff/inbox/notices", "INBOX_MESSAGE_DIR": ".../handoff/inbox/messages",
  "OUTBOX_DIR": ".../handoff/outbox", "MAILBOX_AGENT_ID": "analyst",
  "address": "analyst@example.invalid", "router_address": "amap.router@example.invalid",
  "peer": {"root": ".../handoff/peer", "notices": ".../handoff/peer/notices", "messages": ".../handoff/peer/messages"},
  "intake": "$HOME/.sandy/router-intake/analyst"
}
```

`peer` and `intake` are `null` where the instance has no peer tree
(namespace mode, no domain) or no `intake_dir`. `peers --json` prints the
task graph as `{recipient-address: [sender-address, ...]}` for the adapter's
`--verify` to diff against each agent's informational `peers.json`.

**Not built yet, by design:** cross-host peer traffic (signing, the intake
verifier, demotion to mail). It waits for an email router to exist; the
config keys and mounts it needs are already expressible.

## Attachment transport (AMAP v2.3.0, §3/§5)

`router/attachments.py` carries file bytes end to end: the agent's
`draft.attachments[]` descriptor + `req-<id>.attachments/<ordinal>`
sidecars outbound (§3), and this router's own `message.attachments[]` +
published `<ordinal>` blobs inbound (§5). See the deployment's "Attachment
transport — what `clean` asserts here" for the conformance basis
(operator-supervised topology, never a scan) and the router-verified-size/
digest asymmetry; this section is the mechanism.

**Verification order, caps strictly BEFORE any sidecar is opened:**

1. Count cap (`attachment_max_count`, default 16).
2. Declared-size caps: per-file (`attachment_max_bytes`, default 8 MiB)
   and combined total (`attachment_max_total_bytes`, default 32 MiB).
3. Pin the sidecar dir, `O_NOFOLLOW`-`dir_fd` chained from the instance's
   declared root — same discipline as `reset.py`'s removal engine (see
   below).
4. Exact ordinal set: sidecar entries must equal `{"0", "1", ..., "n-1"}`
   by STRING equality — deliberately not `str.isdigit()`, which admits
   `"01"`, non-ASCII digits, and superscript glyphs.
5. Per ordinal, `dir_fd`-relative: open (`O_NOFOLLOW`) → fstat (regular
   file, `nlink == 1`) → bounded read+hash → compare size+sha256 against
   the descriptor.

A cap breach on an otherwise-honest declaration is `queued_for_human`
(policy hold; no sidecar was ever opened to reach that verdict — the held
copy preserved for the operator is the request JSON ONLY, never sidecar
bytes, since copying those would be the very DoS the cap exists to
prevent). Any mismatch discovered once the sidecar IS opened — bad sha,
wrong size, missing/extra ordinal, a symlinked/hardlinked/non-regular
entry, a dir-shape violation — is `rejected`/`attachment_mismatch` for the
**whole request**, never a partial send (AMAP §4's "two paths, never
conflated"). Both are configurable at the top level of the router config
(`router/config.py`): `attachment_max_bytes`, `attachment_max_count`,
`attachment_max_total_bytes`.

**TOCTOU.** The sidecar dir is agent-owned and writable while the router
reads it — the same defect class `reset.py` found and fixed for deletions
(a path-based check-then-act let an agent redirect a removal outside its
root, proven exploitable in a live race). Here the same class would
redirect a READ: a winning attacker gets some file the router process can
read copied into another agent's inbox. `attachments.py` uses the exact
same pinning discipline reset.py's engine does (`reset._open_child`,
reused rather than re-implemented) — every filesystem lookup below the
initial pin is `dir_fd`-relative and `O_NOFOLLOW`-guarded; a path string
above that pin is advisory only. `router/tests/test_attachments_outbound.py`
proves this with a deterministic in-process swap, a genuine live race
against a SEPARATE process, and a path-based control that demonstrates
the race harness itself can detect the bug class (loses at least once
against a deliberately naive, unpinned reader).

**Publication (§5) mirrors the discipline on the write side.** Under
`namespace` mode a recipient's `inbox_root` is agent-writable in
principle (posture A's accepted delta — see "Trust story" in
the deployment notes), so `publish_attachment_blobs` descends from the
instance's declared root via the SAME `dir_fd`-pinned engine (creating
`notices/` and the `<notice-id>.attachments/` leaf on demand, tolerant of
a resumed-after-crash retry) rather than a path-check-then-write.

**Publication path and shape.** Bytes are published once, under
`inbox/notices/<notice-id>.attachments/<ordinal>` — the single sidecar
directory AMAP §2 names, which the deployed connector's `read_attachment`
resolves and verifies
independently (`inbox-mcp-vol`: path recomputed from the notice id +
index, never parsed out of `content_ref`). **Both** the message-spool doc's
`attachments[]` and the deliver-notice's `message.attachments[]` carry
`content_ref: "<notice-id>.attachments/<i>"` + `sha256` +
`disposition: "clean"`, and both resolve to the SAME single sidecar
directory: `<tree>/notices/<notice-id>.attachments/<index>`.

**Bare `notice_id` — no `notice-` prefix.** The spool FILE is
`notice-<id>.json`; the sidecar DIRECTORY is not. `attachments.
sidecar_dir_name` is the single source for the directory name and
`attachments.content_ref_for` for the string, so the grant and the path
cannot drift.

### What this used to say, and why the change is not cosmetic

Until 2026-09-20 this router published bytes under
`messages/notice-<id>.attachments/<i>` and **omitted `content_ref` from the
deliver-notice** — §5 makes emitting it a MAY, and this router would not
assert a byte-grant at a path it did not populate. That made the notice NOT
self-describing: a strict §5-literal reader saw `clean` + a verified
`sha256` with no grant and could misread it as "not published". The
mitigation was that the notice and the spool doc are a self-describing
PAIR, the spool doc carrying the grant and the write order putting it on
disk first.

**AMAP §2 closed that fork the other way at v3.0.0**: bytes are published
only at `inbound/notices/<notice-id>.attachments/<index>`, "the single
sidecar directory named in the layout tree above", and "there is no
second, message-specific sidecar directory" — a prior revision's prose
claiming one was a self-contradiction, corrected there. `peer-origin.md`
§1d makes the confinement per tree, so the peer lane publishes under its
own `peer/notices/`, by rule and not by inheritance.

So the omission's reason expired: it was never a preference for omitting,
only a refusal to point somewhere false. The notice is now self-describing
alone, and the pair argument is retired. **The write order below is
unchanged and stays** — it is correct on its own merits and is what makes
byte-absence the gate; it simply stops being load-bearing for that
argument.

This runtime was non-conformant on both counts for a year, and the
conformance gate was green throughout, because the only documents carrying
`content_ref` were never submitted to it. See
`router/tests/test_attachments_outbound.py`'s `TestHappyPath` for the
assertion that closes that and an honest account, from mutation testing, of
what it does and does not catch.

**Write order — bytes precede everything that could reference them.**
Extending `deliver.py`'s existing commit-sentinel discipline: attachment
blobs → message spool → router-private ledger → notice LAST. Crash-midway
trace: (a) mid-blob — only an unreferenced `.tmp`-shaped temp name, the
ordinal name never appears; (b) blobs done, message doc not yet written —
orphan blobs under an unguessable, never-announced notice-id, unreachable
(the connector only ever resolves a sidecar via a spool doc it can open by
id, and no id was ever handed to any agent); (c) message doc done, notice
not yet written — same as (b): correct and complete, but nothing relays
it (the connector's watcher acts on the NOTICE file); (d) notice written —
fully complete and consistent. At no point is a partially-written
attachment ever visible as complete. Orphaned sidecar dirs from (b)/(c)
are swept the same way any other mailbox content is: `reset` (below).

**Consumption cleanup.** Once a request is answered and archived
(`_publish_result_and_archive`), the sender's now-consumed
`req-<id>.attachments/` dir is swept via the pinned-fd engine
(`attachments.remove_outbound_sidecar_dir`) — this also runs on the D4
resume/reused paths, so it sweeps any leftover dir from a crashed earlier
attempt too.

**Display strings are never paths.** `filename`/`media_type` are
attacker-controlled untrusted display strings on BOTH sides (§5) — the
blob path is always `<req-id or notice-id> + array index`; these strings
appear nowhere in any path this module builds, on either side, ever.
They're sanitized for display (control/newline collapse, length cap,
fallback to a synthesized name if cleaning empties the string).

**§3/§5 ambiguities this router resolved (not spec edits — see the module
docstring for the full reasoning):**
- **Publication location / `content_ref` form**, above.
- **§4's "duplicate index"** malformed case is unproducible on the submit
  side (the ordinal IS the array position; there's no separate index
  field to duplicate) — nothing to check.
- **Size-cap classification:** a cap breach on an HONEST declaration is a
  policy hold (`queued_for_human`); a declared size that DISAGREES with
  the actual bytes is malformed (`rejected`) — §4 draws this line and this
  router follows it exactly.
- **§2 "readers ignore `*.tmp`"** is moot for sidecars: the consumer
  point-opens exact ordinals, never enumerates the dir, so a `.tmp` turd
  left behind by anything is simply an "extra entry" the ingest-side
  ordinal-set check already rejects.

## Reason-code vocabulary

Every result this router writes carries a `reason_code` (AMAP §4:
"recommend a reason on every result, success included"):

| `outcome` | `reason_code` | Meaning |
|---|---|---|
| `accepted` | `recipient_bound` | Reply, resolved via the private ledger — to a fleet instance, or (a record passing the three-part external test, injected backend only) to the record's external `from_address` |
| `accepted` | `allowlisted` | Cold send, all recipients mutually allowlisted, every delivery succeeded |
| `accepted` | `partial_delivery` | Some deliveries succeeded, some raised. `recipients` lists **only those actually delivered to** (AMAP §4 makes it authoritative); failures are named in `detail`. Not retried — a retry would re-deliver to the ones that already have it |
| `queued_for_human` | `delivery_failed` | Every delivery raised. An infrastructure failure, not a policy refusal, so it is held for an operator rather than silently dropped |
| `queued_for_human` | `recipient_not_allowlisted` | Every address is a known instance, but at least one isn't mutual; request held at `state_dir/<name>/held/` — no release mechanism in L1 |
| `rejected` | `unsupported_contract_version` | `contract_version` absent or not `"2"` |
| `rejected` | `malformed_request` | Fails AMAP §3 shape (bad JSON, missing/mistyped fields, empty `to`, bad attachment descriptor, ...) |
| `rejected` | `req_id_mismatch` | Body `req_id` != the filename's id |
| `rejected` | `agent_id_mismatch` | Body `agent_id` present and != the namespace instance |
| `rejected` | `attachment_mismatch` | An attachment descriptor and its sidecar bytes disagree, or the sidecar dir's shape is wrong: sha/size mismatch, missing/extra ordinal, non-ordinal entry name, symlinked/hardlinked/non-regular sidecar, dir present with no attachments declared (or vice versa) — see "Attachment transport" below |
| `rejected` | `recipient_unknown` | Cold send: an address doesn't parse, or names an instance this router doesn't know |
| `rejected` | `unresolved_reply` | Reply: `in_reply_to` doesn't resolve to a ledger record for this sender |
| `rejected` | `self_send` | Recipient resolves to the sender's own instance |
| `rejected` | `req_id_reused` | The filename's `req_id` was already anchored to a DIFFERENT request (agent deleted its own `outbound/{results,processed}` and resubmitted under a reused id) — refused rather than replaying the stale verdict |
| `rejected` | `quarantined_pre_approval` | The filename was already present in the outbox at the moment this router FIRST SAW the instance — staged-request quarantine, never delivered; resubmit under a fresh `req_id`. (The code keeps its old spelling: it is on the wire, and `approve` was retired after it shipped.) |
| `queued_for_human` | `attachment_too_large` | A declared `size_bytes` (per-file or total) exceeds the configured cap — an HONEST declaration, so held rather than rejected; no sidecar was opened to reach this verdict |
| `queued_for_human` | `attachment_count_exceeded` | More attachments than `attachment_max_count` — no sidecar was opened |
| `accepted` | `peer_routed` | Peer lane: placed in the recipient's `peer/` tree along a declared edge (or, for a reply, the reverse edge). `message_id` is the peer message id. Fresh task and reply alike — the code names the TREE |
| `rejected` | `peer_single_recipient` | Peer lane: a submit touching a declared edge named more than one recipient or carried `cc`. Refused whole; a mixed-lane submit is never half-sent |
| `rejected` | `peer_reply_window_expired` | Peer lane: the reply key resolves to a peer notice, no edge exists in the reply's direction, and the notice is older than `peer_reply_window_seconds` |

## Retention / deletion rights (v2.2.0)

AMAP v2.2.0 §2 names, for the first time, who may delete each artifact class
and on what basis. This router's current behavior against that table:

| Artifact | May be deleted by (spec) | This router today |
|---|---|---|
| `outbound/req-<id>.json` (pending) | runtime, on consumption | moved to `processed/` in `_publish_result_and_archive` |
| `outbound/processed/req-<id>.json` | runtime at will; connector after reading the result | never deleted by the router; a courtesy archive it also never reads back — a connector may delete it freely (see `outbound.py`'s module docstring and `test_req_id_reuse.py::test_processed_deletion_alone_is_not_a_durability_concern`) |
| `outbound/results/<id>.json` | connector, once read; runtime by age-based retention | never deleted by the router in this build — no retention sweep exists |
| `inbound/notices/*`, `inbound/messages/*` | runtime only, conservative/age-based | never deleted by the router — the maximally conservative limit of "conservative," and the only one available without inventing GC (Appendix A, non-normative, deliberately unimplemented) |
| `outbound/req-<id>.attachments/` | connector, runtime (consumption) | swept by the router immediately after every request is answered and archived (`attachments.remove_outbound_sidecar_dir`, called from `_publish_result_and_archive`) — also covered generically by `reset` (below) |
| `inbound/notices/<notice-id>.attachments/` | runtime only | same policy as `inbound/notices/*` above — never deleted outside `reset` |

**Nothing here grows unbounded with no owner** — every class above has a
named owner (the router, doing nothing, is still a decision, not a gap) —
but nothing here is *automatically reclaimed* either: an operator who wants
`state_dir` or a namespace's `results`/`processed` trimmed does so by hand
today, or in bulk via `reset` (above) — the operator's hand-trim, scripted
and made safe (containment-checked, and paired with the router-private
state that has to go with it) rather than a raw `rm -rf`. Appendix A
sketches a future connector-written GC signal (`outbound/acks/notice-<id>`)
that would let the runtime reclaim consumed inbound artifacts safely; it is
explicitly **not-yet-specified** and nothing here implements it.

## Known limitation (documented, not a test target)

If the process crashes between a successful `deliver()` call (notice
already written) and the private result write that anchors idempotency,
the next drain re-processes the request and mints a **second**, distinct
notice — `notice_id` is freshly random per delivery (unguessable, AMAP §6 /
H2), not derived from `req_id`, so this narrow window is not currently
made idempotent. Out of scope for L1; flagged for anyone hardening this
further.

## Approved but NOT BUILT: discovery and the published directory

Approved by this repo's operator on 2026-09-18, against the tree as it stood
when `util` gained its pinned-descriptor helper and the two unclassified module
names were declared for another repo to import.
**Nothing below is implemented.** It is recorded here because a plan nobody
can find gets re-derived, and re-derivation is where the reasoning is lost.

The fuller design record — admission-vs-validation rulings, the manifest
grammar, the correspondence that produced each amendment — lived in
`PLAN-discovery.md`, which is not part of this repository: most of its content
described the *host adapter's* internals, which is the adapter's to publish and
not this router's. What follows is the part that IS this router's, extracted so
it stands without the rest.

**The defect it fixes.** Today this router mounts one bind per `handoff_dir`
from a config read once at start, so every enrolment is a re-render of that
config plus a fleet-wide restart.

### The five items

1. **Two mounts, fixed.** `instances/` `:rw`, `feature.json` `:ro`.
   `state_dir`/`intake_dir` unchanged in `docker/run.sh`.
2. **Discovery.** Each subdirectory of `instances/` whose name passes the
   existing name rule is an instance named by the directory. First sight on
   the first poll that finds it — unchanged semantics, and they are what make
   discovery safe.
3. **Policy read from a generated file**, re-read EVERY POLL. Never from the
   operator-authored manifest block, which carries keys with this repo's
   names and the operator's meanings.
4. **`provision` retires FOR CREATION ONLY.** The wiring printout (the four
   connector env vars) stays until something else answers that question.
5. **Publish `directory.json`** at each instance ROOT — `contract_version`,
   `router`, `written_at`, `delegate_to`, `mail_to`. A projection per
   instance, never a shared file; temp + rename; rewritten for every instance
   whose lists changed; for a newcomer only AFTER its first-sight snapshot.

**Sequencing:** 2 and 3 together first — they are one change, and splitting
them ships a router that discovers instances but still needs a restart for a
graph edit, which is the restart this exists to kill. 1 falls out of them. 4
is the adapter's. 5 last.

### The two conditions this repo holds to on item 5

**(a) Refuse to publish into an agent-writable tree.** Same rule and same
reason as the peer lane refusing a `namespace`-mode instance: that tree is
agent-writable end to end, so a document placed there asserts nothing. AMAP
§10 makes this conformance rather than local strictness — a runtime that
publishes MUST ensure the agent can read it, and one that cannot make it
readable MUST NOT publish.

**(b) Ruling 16 — THIS ROUTER NEVER READS `directory.json` BACK, FOR ANY
PURPOSE.** Write-only from this side. The graph derives from policy; the file
is a projection of the graph; nothing derives the graph from the file.
Enforcement stays `binding.check_peer_edge`, on every message, unchanged.

The prohibition is scoped to DIRECTION, not to purpose, and that is the whole
of its strength. An earlier wording — "never read back AS AUTHORISATION" —
asks an implementer to classify their own intent, and every way this decays
passes that test from the inside: as an optimisation ("not in the list, don't
attempt"), as a cache, as recovery (rebuild the graph after losing state), as
a cross-check. The last two are worse than what the ruling forbids, because
they make a projection into a SOURCE. A projection that can be read back
becomes a cache, a cache becomes a record, and a record that disagrees with
policy wins by accident on the day policy is slow to load.

### Item 5 is WAITING, and "off" is a correct terminal state

Item 5 is off pending one measurement the adapter owns: whether nested bind
mounts apply parent-first on a real host. If they do, the root mount goes in,
the sibling lanes become overlays, and publishing switches on — with notice
BEFORE it does. **If they do not, publishing stays off permanently, and that
is §10-conformant rather than a gap to work around.** Publishing is OPTIONAL;
an unreadable directory is indistinguishable from an absent one to a consumer
and worse than an absent one to an operator. Do not read item 5's absence as
unfinished business.
