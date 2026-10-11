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
- `connector_outcome_ids` (OPTIONAL, default `["claude-code"]`): the connector
  ids whose `outbox/ext/<id>/outcomes/` directories are scanned for delivery
  outcomes, in order — `["claude-code", "codex"]` for a fleet mixing Claude
  and Codex connectors. Each id matches `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`
  (it is a path segment under an agent-writable tree), and ids equal ignoring
  case are refused. Router-wide: every id is scanned in every instance. The
  ORDER is the scan order against one shared per-poll budget: the first id is
  scanned first, and a later id gets only what the earlier ones leave, so a
  flooded first directory DEFERS the next one's outcomes to later polls (none
  is dropped; each waits its turn). **Roll
  out the router first:** this loader refuses unknown keys, so a deployment
  that renders this key for an older router has its whole config refused.
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
root), plus the CONTENTS of all four skeleton leaves. **Except the outbox's
`ext/`**, the spec's Connector-owned side channel, over which the spec's
deletion-rights table gives the runtime no right: reset empties only
`ext/<id>/outcomes/` for each configured `connector_outcome_ids` id (the files
this router already consumes) and leaves everything else under `ext/` in
place. Before 2026-10-07 it removed `ext/` whole, as a stray.

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

  Every branch that holds work under an id compares digests before
  answering a file under it. A settled anchor refuses a different request
  as `req_id_reused`. A request still IN FLIGHT settles privately when the
  file under its id is now a different one: the anchor keeps its verdict,
  nothing is published or archived, the new file is held (counted as
  `outbound_req_id_reused_pending`) until then and refused as
  `req_id_reused` after. An anchor with no digest (an original too large to
  read) resumes only while the file under its id is still unreadable for
  what it is; a readable one is `req_id_reused`. A transient read fault
  decides none of these (`router/tests/test_reuse.py`).

  **Residual, accepted:** a request byte-identical to the original under a
  reused id IS the original as far as the router can tell, and resumes
  with the stored verdict without being delivered again. `ts` is optional,
  so a template-like request can repeat exactly. Telling the two apart
  needs a connector incarnation id, which AMAP does not carry.

  **Residual, accepted:** the comparison and the archive are two steps. A
  different file written at the name between the digest check and the
  archive rename still receives the stored verdict and is archived. The
  same window exists on the anchor-resume path. Closing it needs the
  archive to verify what it moves, which is not done here.

  The same rule answers an agent that REWRITES its own request while it is
  in flight: the staged copy was handed over and may well have been sent,
  but the rewritten file is refused as `req_id_reused`. Nothing here can
  tell a rewrite from a reset connector's reuse. An agent that reads that
  refusal as "not sent" and resubmits the content under a new id may send
  it twice.
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

**`status --check`** is the one definition of healthy: exit 0 while the last
poll is within 3x `interval_s` (the same factor the host adapter's
`router_health` uses), else exit 1, with one line saying why — on stdout when
healthy, stderr when not. Anything it cannot establish is unhealthy, never
assumed fine: no readable `status.json`, no `interval_s` (omitted when unknown;
`once` never writes one), or an unparseable `last_poll_ts`. The image's Docker
`HEALTHCHECK` runs it, so `docker ps` shows `healthy`/`unhealthy`. Plain Docker
reports that but does not restart on it — `--restart` acts on exit.

Field glossary:

| Field | Meaning |
|---|---|
| `pid` | the router process that wrote this file |
| `started_ts` | when THIS process started — the counter window's start |
| `last_poll_ts` | timestamp of the most recent poll (age is what `status` prints; `status --check` judges it — see below) |
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

## The fleet roster (`roster.json`)

Who EXISTS in the fleet, written every poll so an agent can find a peer's
address — a sandy slug carries a suffix nothing can derive, so without a list
an agent can task only someone who has already written to it. Full contract:
`router/roster.py`'s docstring.

**Where.** `dirname(selected_json)/roster/roster.json`, with no config key. The
host adapter creates `roster/` at install and mounts it READ-ONLY into every
selected sandbox as `$AMAP_ROSTER_DIR`; this router writes inside it and
nothing else does. The convention is pinned from both ends — the adapter's
test and `test_roster.py::LocationConventionTests` — because a key would force
a rollout order this loader's unknown-key refusal turns into an outage.

**It grants nothing.** No edges, no `may_task`, no delivery evidence. The file
is `{contract_version: "2", router, written_at, interval_s?, members}`, and
members are the admitted set, each exactly `{address, state: "admitted"}`,
sorted by ADDRESS (not by name: `-` sorts before `@`). Authorisation is still
decided at submit time, and the result is still the only report.

**It is never read back** — not as a cache, for recovery, or as a
cross-check. `NeverReadBackTests` watches every read path while publishing.

**Not written**, each logged once when it starts rather than every poll:

| condition | why it is a skip |
|---|---|
| authored `instances` config | no `selected_json`, so no location to derive |
| no `fleet_domain` | members would have no fleet address |
| host verdict unavailable | the set is UNKNOWN, not empty; the old roster ages past its freshness bound instead of announcing an empty fleet |
| `roster/` absent | the adapter's directory; creating it would hide their install failure |
| `roster/` not writable (EROFS, EACCES, EPERM) | designated but not bound read-write for the router; `docker/derive-mounts.py` binds it `rw` over its `ro` parent when it exists. Any other write error is a fault and propagates |

Written at the END of the poll, after the drain, so a newcomer's first-sight
snapshot precedes its announcement; mode `0644`, because `mkstemp`'s `0600` is
a correct file no agent can read.

**Spec: its own section of the draft, "The Fleet Roster"** (amap-spec PR #5,
unmerged at the time of writing), with `schemas/roster.schema.json` and
`roster-*` fixtures. It is a separate artifact from §10's `directory.json`,
which answers who an agent may ADDRESS; the roster answers only who EXISTS.
`test_roster_conformance.py` validates the writer's real output against that
schema — passed explicitly, never selected by filename — after proving the
validator rejects every invalid roster fixture. The draft splits readability
between the parties that can observe it: this router publishes only where the
deployment designates and never creates it; the deployment exposes it. A
roster written where nothing is exposed is inert, not a violation.

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
`claude-code` is the default connector id, and the first the spec names; a
mixed fleet lists more in `connector_outcome_ids` (see "Config"). An id does
not change when a connector's repository is renamed, and this router treats
it as opaque. ONLY the configured directories are scanned: `ext/` is
agent-writable, so an outcome written under any other id sits there unread.
One per-poll budget and one dedup key span all of them, so a second directory
buys no extra work and one transition reported under two ids is acted on —
and DSN'd — once. Directories are scanned in the configured order, so under
budget pressure the first id's outcomes are read first and a later id's wait
for a later poll. A compatibility path under an old repo-tracking spelling was
read for one release and retired on 2026-09-22. Changing the scanned set is a
deliberate edit rather than a cleanup: an outcome nobody reads is silence,
this router never infers anything from silence, and so nothing it observes
would report the mistake. `router/tests/test_outcomes_ext_path.py` is what
says which directories are scanned, in place of that missing signal.
Every poll reads those directories with the outbox discipline, records each
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
| `queued_for_human` | `transport_anomaly` | External leg (not yet reachable from any built-in policy; see "In-flight requests"): the transport request was archived without a result, its result failed validation, no transport is configured, or the request carried attachments (staging to the transport is not built yet). Never resubmitted |

## In-flight requests (external leg, partly built)

`router/inflight.py` holds a request that stays unanswered across polls: one
handed to a second runtime and settled from that runtime's result. Nothing
reaches it yet. No built-in policy returns `outbound.ExternalRoute`, and
no plugin can be activated yet (below); the rest of the external leg
(classification, the transport itself, re-placement) is designed but not
built. The transport is an optional plugin.

* A record per request at `state_dir/<name>/inflight/<req_id>.json`, holding
  the staged copy; the agent's file stays in its outbox, skipped, until settled.
* Transport req_ids come from `state_dir/<name>/transport/next_req_id`,
  persisted before use and never reused. `reset` preserves it.
* No timeout settles a request. The drain summary (and so `status.json`)
  carries `inflight`, `inflight_oldest_age_s` and `inflight_stale` (past one
  hour), with one WARNING per stale request per process. These keys appear
  only for an instance with a transport or with records.
* The downstream verdict passes through verbatim, `detail` prefixed
  `transport:`.

### The transport plugin (`router/transport.py`)

The transport is an optional plugin, named in the config by path and
content hash and never by import name:

```json
"transport_plugin": {"path": "/opt/amap/transport-plugin.py",
                     "sha256": "<64 lowercase hex digits>"}
```

Both members or neither. Absent, the router runs `transport.NullTransport`,
whose factories return `None`: the drain gets no transport, exactly as
before, and an external route settles `queued_for_human`/`transport_anomaly`
("the external leg is not configured").

Present, the router loads it ONCE at startup (`service.start_transport`)
and refuses to start on any failure. A config reload that changes it is
refused; changing the plugin needs a restart. The loader's refusals, each a
fixed `PluginRefused.reason`:

| reason | refused when |
|---|---|
| `path_not_absolute`, `path_not_canonical` | the path is relative, or any component is a symlink |
| `agent_reachable` | the file is inside an instance's root, inbox, outbox or peer tree |
| `parent_owner`, `parent_writable` | a directory between the file and `/` is not root-owned, or is writable by others without the sticky bit |
| `missing`, `symlink`, `not_regular` | the file is absent, is a symlink, or is not a regular file |
| `owner`, `mode` | the file is not root-owned, or its mode is not exactly 0444 or 0644 |
| `too_large` | the file exceeds `transport.MAX_PLUGIN_BYTES` |
| `hash_mismatch` | its bytes, read once from the pinned descriptor, do not hash to `sha256` |
| `exec_failed` | those bytes, the only ones ever executed, fail to run |
| `api_mismatch` | its `PLUGIN_API` is not `(our major, at least our minor)` |
| `missing_factory` | it lacks a callable `make_sender` or `make_intake_reader` |
| `fsops_unavailable` | it passed every check, but the filesystem port its factories need is not built yet |

The last one is deliberate and temporary: until that port exists, any
configured plugin stops startup, so no transport is used before its
durability work is done. `TransportPort.has_pending` is true for a request
the downstream runtime has claimed as well as one it has not.

**The ports a plugin receives** are Protocols in the same module, interface
only: `HopFsOps` (every filesystem operation a plugin may make, on pinned
descriptors; a plugin makes no filesystem call of its own), `KeyOps` (the
signing key as bytes; the signer never opens a path), `Signer` and
`Verifier`, plus the factory signatures (`make_sender`, `make_intake_reader`,
`make_signer`, `make_verifier`, and the sibling runtime's four).
`PLUGIN_API`'s major covers all of them. Two contracts on `HopFsOps` are
worth knowing before implementing it: `commit_durable` derives its stage
name's destination tag from a binding the implementation holds, never from
a parameter or a bare descriptor number; and `open_regular_pinned` returns
`bytes` or the port's own `NOT_YET`, with anything else a protocol
violation that callers raise on, never skip.

**This router's implementation of `HopFsOps`** is `router/fsops.py`
(internal). It is built and tested but NOT activated: nothing hands it to a
plugin, and `start_transport` still refuses every plugin. It needs
`renameat2` with `RENAME_NOREPLACE` (Linux, glibc 2.28+), and a startup
capability probe (`fsops.probe`) refuses a filesystem without it or without
a working directory fsync. Whether a given mount honours those is a
deployment measurement, not something this code can show.

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

## The host registry (`registry_dir`)

With `registry_dir` set to the host registry's directory (a read-only mount
holding `registry.json`), every poll reads the registry and drains only the
instances whose name is an ACTIVE, uncontested registry entry. Every other
configured instance is HELD, not drained, and reported in `status.json`
under `registry.held` with a reason:

| reason | meaning |
|---|---|
| `not_registered` | no active registry entry has this name |
| `skeleton_collision` | two active entries' names fold to the same skeleton; both are held, never guessed between |
| `registry_unavailable` | the snapshot is absent, unreadable, not a regular file, too large, not strict JSON, an unknown schema token, or a field of the wrong shape (`registry.code` says which) |
| `registry_rolled_back` | the snapshot's `seq` is lower than one already accepted |
| `state_not_migrated` | the instance has private state under its name and none under its logical_id (below) |
| `state_conflict` | private state exists under both its name and its logical_id; which is current is not guessed |
| `name_shape` | the name can never key state under a registry: 32 hex digits (either case), or `registry` / `status.json` (this router's own `state_dir` entries) |

Without `registry_dir`, nothing changes. The router never writes the
registry. It checks the schema token, `seq` and the fields it uses, and
relies on the registry writer for the rest (it validates every snapshot
before making it visible).

**A rolled-back registry is an operator event.** The highest `seq` this
router has accepted is kept in `state_dir/registry/seq`. A snapshot with a
lower `seq` means the registry was restored, and adopting it could re-bind
names to older identities, so every instance stays held and `status.json`
shows `registry.state: "rolled_back"`. To accept a deliberate restore, the
operator removes `state_dir/registry/seq`; the next poll accepts the
snapshot's `seq` as the new floor.

**Losing `state_dir` loses the floor.** With `state_dir/registry/seq` gone,
the next snapshot is accepted whatever its `seq`, a rolled-back one
included. Restoring or recreating `state_dir` is therefore an operator
event to check against the registry, not a routine restart.

### Private state is keyed by logical_id

Under a registry, every resolved instance's private state lives under
`state_dir/<logical_id>/`, not `state_dir/<name>/`. The per-identity part
(the reply ledger `delivered/`, outcome records, DSN intents and the audit
log) is directly there; everything that belongs to one life of the
instance's connector (private results, in-flight records and the transport
counter, held local deliveries, held and quarantined requests, the
first-sight marker) is in its current GENERATION, `gen-<g>/` ("Generations",
below). Renaming an identity (an operator override in the registry)
therefore moves none of it. Without `registry_dir`, everything stays keyed
by name, exactly as before, and there are no generations.

**Moving private state under a registry is an operator step, and the router
holds until it is done.** An instance whose `state_dir/<name>` exists (in any
shape) while `state_dir/<logical_id>` does not is held as
`state_not_migrated`: draining it would take a fresh first-sight snapshot and
start an empty reply ledger beside the old one, so earlier notices could no
longer be replied to. To migrate, with the router stopped:

    mv state_dir/<name> state_dir/<logical_id>

(the logical_id is the instance's entry in the registry snapshot). If both
exist, the instance is held as `state_conflict` until the operator removes or
merges one; this router does not choose. An unreadable entry counts as present.

**Nothing is written under a name while a registry is configured.** An
instance the registry holds has no state key at all (`config.state_key`
raises rather than fall back to the name), and a delivery TO a held
recipient HOLDS ("Held local delivery", below): nothing is placed and
nothing is created under `state_dir/<name>/`, which would otherwise come
back as `state_conflict` once the recipient is registered again.

**`reset` follows the same keys, read fresh.** Under a registry, `reset <name>`
reads the registry again under the drain lock, whatever keys a caller
cached, clears the per-identity state under `state_dir/<logical_id>/` and the
mailbox, and then FENCES the current generation and begins the next: it
never deletes a generation, the generations file or a migration journal
(the fenced generation keeps what it held, and the new one carries the
transport counter forward and takes its own first sight). A reset of an
instance still in the pre-generation layout is refused. If any named instance is held
(including a conflict or an unavailable or rolled-back registry since the
keys were cached) the whole batch is refused before anything is removed.
`reset --dry-run` reads it without persisting the seq floor, since it takes no
lock.

**`registry` and `status.json` are never instance names**, with or without a
registry: they are entries this router keeps directly under `state_dir` (the
seq floor's directory and the status file), and an instance's private state
lives beside them. Refused at config load (casefolded) and skipped in
discovery.

**Names shaped like a logical_id cannot run under a registry.** A static
instance named with 32 hex digits (either case, for a case-insensitive
`state_dir`) is refused at config load when `registry_dir` is set, and
discovery skips such a directory (the host keys its own per-identity
directories that way; the registry never issues that shape as a name). The
name rule itself is unchanged without a registry.

### Generations

A GENERATION is one continuous life of an instance's connector state: one
registry binding (adapter, stable_key, binding_seq) and one instance root
(path, st_dev, st_ino). `state_dir/<logical_id>/generations.json` lists them;
exactly one is current, the rest are FENCED and never current again.

**A generation begins only on positive evidence**, checked for every instance
BEFORE any instance of the poll drains (`router/generations.py`):

- the registry binding changed (a rebind), or the root's identity changed
  (re-created, or a new root), read from the descriptor an `O_NOFOLLOW` open
  returns, never from a path stat;
- or the operator says so: `router generation new <name> --reason <text>`
  (needs the router stopped; `--dry-run` writes nothing), or `router reset`.

A same-root connector counter reset is NOT inferred: AMAP gives a connector
no incarnation id. Within a generation a reused id fails closed instead
(`req_id_reused`, or `req_id_reused_pending` while the earlier work is in
flight, shown in `status.json` with its age and a hint). A `name_seq` or
`enrollment_epoch` change never begins one.

**The new generation's transport counter starts at its predecessor's next
unused id**, written durably before it becomes current; a fenced generation
never allocates. A predecessor whose counter is missing although it handed
ids out, or corrupt, holds the instance (`transport_counter_unverified`).

**Holds, never guesses.** An instance is held for the poll, with a reason in
`status.json`'s registry section, when its root cannot be opened
(`connector_state_unverified`), when it has state in the pre-generation
layout (`legacy_state_unadopted`), when its generations file or current
generation is unreadable or inconsistent or a migration is unfinished
(`state_layout_conflict`), or when its current generation has taken first
sight but its marker is gone (`first_sight_marker_lost`; it is never
re-snapshotted, which would move the quarantine line forward). That includes
a crash between first sight's sentinel and its marker; the way out, once the
operator has looked, is `router generation new <name> --reason ...`, whose
fresh generation takes its own first sight. A generations file that is lost
while generation directories remain holds too (`state_layout_conflict`): a
fresh start would reuse their transport ids. Under a registry, a drain opens
its instance's root once, checks that descriptor is the directory its
generation recorded, and does everything else (first sight, the listing,
every read, the publish and the archive) through that descriptor: a root
replaced after the check is never read or written by that drain. The peer
outcome consume that follows a drain runs through the same checked
descriptor, and not at all after a drain held for its root. This pinning
goes through `/proc/self/fd/<fd>`, so registry mode needs Linux `/proc`;
without it every instance is held with that reason. `status.json`'s
generations section is report-only and never feeds a decision. A delivery to
a held instance holds (below), and so does one whose root was replaced after
the poll's check: every placement writes through a root descriptor that must
be the directory the recipient's current generation recorded.

**A fenced generation's work is finished, privately when it must be.** Its
in-flight records keep advancing under their own transport ids (it never
allocates a new one), and its pending records replay from their snapshots
(below). Each publishes its Result only while the root is still the one the
generation recorded and the live outbox entry is still its request;
otherwise the verdict stays in that generation (an anchor, nothing published,
nothing archived). A file such work still owns is neither taken into the new
generation's first sight nor drained by it. What fenced generations still
hold is shown as `generations.<name>.fenced_work`. Ownership is taken
before any of that work runs and is fail-closed: a record that cannot be read,
or whose replay fails, keeps its file owned, and a file is released only once
its work is demonstrably settled or its record is gone. A fenced replay never
delivers from the live entry, but it still READS it, to decide whether the
Result may be published. An anchor whose original could not be read (it has
no digest) owns the live file only while that file still cannot be read for
what it is: the stored verdict then completes it, and a readable file under
the id is a new request, the current generation's. An anchor that cannot
itself be read keeps its file, and is shown with its age under
`generations.<name>.fenced_damaged_anchors`.

**A recipient held mid-pass.** If a recipient's root is replaced between the
poll's check and its write, the request goes pending with what that pass
already did recorded as done. In the rare case that the snapshot cannot then
be taken and some recipients already have the message, it cannot wait: it is
answered once, in a single Result, with the held recipient counted as
failed.

**Pending requests carry a private snapshot.** Before a pending record is
written, the raw request and every verified attachment are written, durably,
into `pending/<req_id>.<nonce>.snap/`; the record names them by digest and
nonce, and every replay re-verifies them (`snapshot_damaged` holds). In the
current generation the live entry is still read every poll: gone, the work
continues and its Result is published; changed (a reused id), the ORIGINAL
request is still the one delivered, it settles privately, and the changed
file is then refused as `req_id_reused`. A version-1 record (no snapshot)
still needs its live entry, and in a fenced generation it holds
(`legacy_snapshot_missing`).

**`recipient_generation_changed`.** A placement begun for a recipient (its
target `delivering`) records the recipient's generation. If that generation
has changed by the replay, the target HOLDS: it is never continued into the
new generation's root, and nothing answers it automatically, so the sender
sees only "not yet". Runbook: look at the recipient's old generation; if the
notice was placed there, the operator decides whether that counts (the
request can be answered by fencing the SENDER's generation, or left held);
if it was not, the request stays held until the operator acts.

**Migrating pre-generation state.** An instance whose state predates
generations (its entries directly under `state_dir/<logical_id>/`) holds as
`legacy_state_unadopted` until the operator, with the router stopped, runs
one of:

```sh
python3 -m router --config C generation adopt NAME --reason TEXT [--dry-run]
python3 -m router --config C generation fence-legacy NAME --reason TEXT [--dry-run]
```

`adopt` attests that the root and binding are unchanged since that state was
written: everything moves, exactly, into the first current generation (the
transport counter included), and each version-1 pending record gains a
snapshot taken from the live request it names, only when those bytes still
match its digest (otherwise it stays version 1 and holds as before).
An adopted generation always records that it took first sight (the
`first-sight.taken` sentinel), and when the legacy layout has only an old
`approval.json` its marker is written FROM that file, as a pre-generation
router's upgrade did: `first_seen_ts` is the `approved_ts`, verbatim, and
`adopted_from` says so. Both are planned in the journal and checked like
every moved path. `fence-legacy` makes the old state a FENCED generation and
begins a fresh current one: that legacy generation recorded only a path for
its root, which vouches for nothing, so its work settles privately, and the
fresh generation's own first sight quarantines whatever is in the outbox (the
agent resubmits). Use it when the origin cannot be vouched for. A generation
that records no root identity (this one, or one begun while its root could
not be opened) claims no live file and publishes nothing; before migration
existed, the root check failed on such a record with a `TypeError`, which the
fenced drain treated as keep-every-claim.

Both are journaled in `state_dir/<logical_id>/migration.json`: every fact the
verb depends on is planned there, durably, before the first rename, and
never recomputed. Each phase is durable before the next; a crash leaves the
instance held (`state_layout_conflict`) and re-running the SAME verb resumes,
deciding each path from what is at its source and destination (both present,
or neither, is a conflict, never a tie-break), and only while the binding
(for adopt, also the root) it recorded still verifies. The other verb is
refused while a journal exists; the same verb once done changes nothing. The
journal is kept when done, and "done" is believed only when the generations
file lists what it made with the same legacy record and its blocker is in
place. The attestation, with `--reason`, the binding and root observed and
the journal's digest, is written durably to the audit log before `done`, once
however many runs it takes.

**The transport counter is preserved, or the verb refuses.** The plan
classifies the legacy state once. A legacy counter moves exactly. Without
one, the verb refuses whenever any transport id is proven allocated (an
in-flight entry, or an anchor recording a transport id, passing a verdict
through from the transport (`detail` beginning `transport: `), or recording
a `transport_anomaly` other than the two refusals made before any id was
allocated), and whenever an anchor is not exactly the shape a
pre-generation router wrote: no flag overrides either. With no anchors at
all it proceeds. With only local anchors it proceeds only on
`--no-transport-history=N`, N being exactly the count it found, which
attests that the instance never had a transport route. **A false
attestation can silently reuse a transport id once the transport has pruned
the old one**, which breaks the rule that an id is never handed out twice;
an attested chain is shown as `generations.<name>.legacy_attested`, and every
later `generation new` and `reset` logs a WARNING naming it. The migrated
generation and the journal carry the same record of all this, and a
successor's counter is taken from it: a migrated counter that is later lost,
or found below the value migrated (a rollback), holds the instance
(`transport_counter_unverified`), as does a migrated generation whose record
is missing or disagrees with the journal, or a record no journal names.

**adopt's evidence.** `adopt` also refuses, pointing to `fence-legacy`, when
the legacy marker is missing (an old `approval.json` stands in only with a
real `approved_ts`; a marker a pre-generation router adopted from one is
trusted only if its `first_seen_ts` is that `approved_ts`), when the marker's
root is not this instance's root (paths compared normalised, never
resolved), when the registry's binding history is malformed or does not end
in the current binding, or when it records a REBIND (any binding after the
initial one) at or after the legacy state's first sight, with a 1 second
margin for clock skew. The initial binding is not compared: a registry
imported after the router first saw an instance records that binding later
than first sight, and the root check and the attestation stand for it.

**What "done" is checked against.** Every reader of the journal first checks
that it is well-formed for its phase and for this identity, and, from
`complete` on, that the digest its attestation commits to is the one
recomputed from its body and that the planned line carries exactly the
body's facts; anything else holds (`state_layout_conflict`). On every poll: the generation chain the
verb made, with the binding and root it recorded; every moved path, with its
type, and the digested files unchanged; the legacy record and every anchor
its manifest lists, unchanged; the counter floor; the blocker. Not on every
poll, but at the verb's own resume and before every `reset` and
`generation new`: exactly one copy of the planned attestation line in the
audit log. That line is planned into the journal (fixed bytes) before
`complete` and written durably once; a torn copy left by a crash is ended
with a newline and the line written whole after it; a malformed line that
mentions this journal, a different line for it, or a second copy holds the
instance; a malformed line about anything else is skipped with a WARNING.

**Rolling back past this version is not supported.** The last step before a
migration completes leaves a DIRECTORY named `first-seen.json` where the
legacy marker was. An older router run against the migrated layout fails at
its first statement, before listing or delivering anything, instead of
taking a fresh first sight and restarting the transport counter. `reset`
leaves it, and the journal, in place.

**Not yet built** (later steps): aliases.

### Held local delivery

Under a registry, a delivery to a LOCAL target that this poll's report does
not resolve HOLDS. One immutable report per poll is attached to the keyed
config (`config.target_hold`), and the mail, peer, reply and router-notice
paths all ask it before reading or writing anything on the recipient's side.
A held target is never reclassified as unknown or external. A registry with
no report attached fails closed (`registry_report_missing`).

**What the sender sees: "not yet".** AMAP gives a Runtime exactly one,
terminal Result per request it consumes, and a closed outcome vocabulary
(draft §6.1), so "held" cannot be a Result. A request with a held target is
NOT consumed and gets NO Result while held; it stays in `outbound/`.
`queued_for_human` is not used for it (that is terminal). A sender-visible
"held" would need a change to AMAP itself.

**What the operator sees.** `status.json` lists, per instance:

- `held_local`: each pending request, its held targets and why (any reason
  in the registry table above, or `identity_changed`), and a request-level
  `block` when the request itself changed, went missing, became unreadable,
  its attachments changed, or fresh policy now routes it differently;
- `dsn_held`: each DSN waiting on a held sender, and why.

Each change of a hold reason is one `delivery_held` / `dsn_held` audit line,
never one per poll. The console shows both counts.

**The pending record.** `state_dir/<sender>/pending/<req_id>.json` holds
the request's sha256, its kind and targets, and for a reply its PINNED
binding. It is written durably (file and directory fsync) at every
transition:

- before ANY placement for a target, the record moves it to `delivering`
  with a pre-minted notice id and ts, the target's logical_id and the
  delivery kind. A crash anywhere after that replays the placement with the
  SAME identity through the full notice-last sequence; the target is
  `delivered` only once the placement returned. The guarantee is one stable
  notice id and ledger path per (request, recipient), offered at least once
  (a crash after the notice can offer the same id again; dedup by id), never
  two ids;
- a target is pinned to a logical_id whenever one is known: for a reply,
  the identity its task was delivered from (ledger records under a registry
  carry `from_lid` / `to_lid`); otherwise the identity the registry knows
  now, held or not (`state_not_migrated`, `state_conflict` and
  `skeleton_collision` names still have one). Only a target never known is
  bound at its first resolution. A name that later resolves to another
  logical_id holds as `identity_changed`; it is never rerouted;
- an error after a placement began is NOT terminal: the target stays
  `delivering` (reason `failing: <error>`) and is replayed with the same
  identity next poll;
- a reply pins its binding at its first ELIGIBLE evaluation (it resolved,
  and passed the reply window then), so a hold cannot age it out. A reply
  already outside its window is refused at once, never pinned;
- fresh policy runs every poll: a refusal is terminal, but only once every
  placement already begun is settled (replayed with its identity), so its
  Result names EVERY recipient whose notice was placed; a changed route
  holds;
- an injected delivery backend gets the pre-minted identity (a `preset`
  keyword); one that cannot take it is held as `backend_no_preset` BEFORE
  any placement;
- targets that resolve go at once; completed ones are never re-delivered;
  when none is pending, the request gets its ONE Result, as an unheld drain
  would have answered, and the record goes;
- a damaged record fails closed: the request holds, listed as damaged.

**DSNs to a held sender.** A DSN is enqueued as a durable intent under the
RECEIVER (`state_dir/<receiver>/dsn-pending/<tree>-<nid>.<outcome>.json`,
with a pre-minted DSN id and the sender's pinned logical_id) BEFORE the
outcome is recorded or its file unlinked; until the record is durably
written the outcome file stays for the next poll. An existing intent is
validated exactly and made durable again before its source is consumed.
Intents are drained after fresh outcomes, under their own budget and a
persisted fair cursor (damaged intents count toward it, and are reported),
armed only on a DURABLE outcome record, rewritten durably before every
placement, and removed only after the DSN is placed. Nothing is dropped, timed out or turned into
`queued_for_human`.

An unavailable or rolled-back registry holds every instance, senders
included, so neither pending requests nor DSN intents advance until it
recovers.

**Removing `registry_dir` with work in flight is unsupported.** Pending
records and DSN intents live under logical_ids, which cannot be mapped back
to instances without the registry. If `registry_dir` is absent and any
`state_dir/<logical_id>/` holds pending records or intents, every instance
is held (`status.json` `registry.state: "stranded"`, reason
`registry_state_without_registry`, and an error in the log) rather than
re-delivering completed targets with new ids. Restore `registry_dir`, let
the work drain, and only then remove it. A state directory that cannot be read is
treated as stranded too (it cannot be shown empty). Only the documented
path is detected: moving logical_id directories back to names by hand and
then removing `registry_dir` is not, and re-delivers. Without `registry_dir` none of this runs: drains, results, DSNs
and `status.json` are as before.

**Known limits, recorded rather than fixed here:**

- Held delivery: a target whose identity was NEVER known (no ledger
  `from_lid`, no registry entry at the time) binds its logical_id at its
  first resolution.

- A name the registry has overridden is `not_registered` until aliases exist:
  the snapshot's `names` history is not read yet.
- The casefold incumbency check during discovery still looks for
  `state_dir/<name>`; under a registry, two registered names that fold
  together are held as `skeleton_collision` instead.
- `binding.ledger_dir`, `ledger_path`, `read_ledger_record` and
  `resolve_binding` (public) take an optional keyword-only `state_key`;
  omitted, they key by the instance name as before.

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
