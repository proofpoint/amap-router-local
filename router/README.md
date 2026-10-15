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
python3 -m router --config C quarantine list [NAME] [--control-dir DIR]   # --control-dir only WITHOUT `hop`
python3 -m router --config C quarantine show NAME SOURCE GEN ID [--control-dir DIR]
                                                                      # read-only inspection of the ingress quarantine — see
                                                                      # "The ingress quarantine" below
python3 -m router --config C inflight list [NAME] [--json]          # read-only: one row per in-flight entry, no lock, safe while
                                                                      # the router runs — see "Listing what is in flight" below
python3 -m router --config C peer-request show ID                   # read-only: a signed peer id's preserved copy, settlement,
                                                                      # claim, retransmits, and each action with why it is refused
python3 -m router --config C peer-request retransmit ID --evidence TEXT [--allow-pending]
                                                                      # the original bytes under a new transport id, never re-signed —
                                                                      # see "Resending a signed peer task" below
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
- `mail_reply_window_seconds` (default 604800, at most 7776000, i.e. 90
  days) — how long after an inbound hop mail is placed its recipient may
  reply to it as a bound reply. Fixed into the mail's ledger record when the
  entry is prepared, so a later change never moves a recorded binding.
- `delivered_domains_file` — optional, an absolute path: the set of domains
  the downstream hub delivers to, as the deployment renders it. Below,
  "Bound replies over the hop".
- `delegation` — optional: cross-host SIGNED peer tasks to trusted fleet
  hosts. Below, "Signed peer tasks (delegation)".
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

**The refusal's `attachments[]`.** AMAP §6.1 gives a Result one diagnostic
entry per SUBMITTED attachment, its `index` equal to its array position, 0
through n-1. Ingest stops at the first failure, so the attachments after it
have no verdict, and §6.1's vocabulary has no word for "not examined". The
array is written only when every submitted attachment has a real verdict,
which on a refusal means exactly one was submitted and it failed a POLICY
cap (`too_large`). Otherwise the optional member is omitted and `detail`
ends with the failing index and its outcome, `(attachment <i>: <outcome>)`.
A MALFORMED attachment (a size or digest mismatch, a sidecar that cannot be
opened, is not a regular file, or is linked) has no §6.1 per-attachment
outcome at all: §6.1 makes it a top-level `rejected`, and `rejected_type` is
the policy verdict for a disallowed type. It is never given an entry, alone
or not, and `detail` ends `(attachment <i>: malformed)`. A verdict is never
invented for an attachment nobody examined.

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
| `queued_for_human` | `recipient_not_allowlisted` | Every address is a known instance, but at least one isn't mutual; or a fleet host outside the trusted list that the sender's `remote_fleet` does not name; or an internet address its `send_to` does not permit. Request held at `state_dir/<name>/held/` — no release mechanism in L1. Also the answer when the policy changed between staging and publication ("policy changed before publication: …", nothing held, nothing sent) |
| `rejected` | `unsupported_contract_version` | `contract_version` absent or not `"2"` |
| `rejected` | `malformed_request` | Fails AMAP §3 shape (bad JSON, missing/mistyped fields, empty `to`, bad attachment descriptor, ...), or a cold-send address outside the one address grammar (`router/classify.py`: a trailing dot, an IP literal, a doubled dot, a U-label, a fleet local part outside the name grammar, ...) |
| `rejected` | `req_id_mismatch` | Body `req_id` != the filename's id |
| `rejected` | `agent_id_mismatch` | Body `agent_id` present and != the namespace instance |
| `rejected` | `attachment_mismatch` | An attachment descriptor and its sidecar bytes disagree, or the sidecar dir's shape is wrong: sha/size mismatch, missing/extra ordinal, non-ordinal entry name, symlinked/hardlinked/non-regular sidecar, dir present with no attachments declared (or vice versa) — see "Attachment transport" below |
| `rejected` | `recipient_unknown` | Cold send: an address at this router's own domain names no instance (classification step 3); or, with no transport plugin, any cross-host address (step 4); or a trusted-host peer task while `delegation` is not configured and activated, so this router cannot sign it (item 5e) |
| `rejected` | `mixed_recipient_classes` | Cold send: `to` ∪ `cc` spans more than one class (local, trusted fleet host, other fleet host, internet). One request, one class |
| `rejected` | `no_route` | Cold send to the internet, and this host has no `egress`. Decided before `send_to`. Also a bound reply whose counterparty is not a fleet host: "no reply path to this counterparty in this deployment", with nothing allocated |
| `rejected` | `fleet_mail_disabled` | Cold send to a trusted fleet host that cannot be a peer task: more than one recipient, or any `cc` |
| `rejected` | `peer_denied` | Trusted fleet host: the sender's `task_deny` removes the edge (an exact address or `@domain`) |
| `rejected` | `peer_quarantined` | Trusted fleet host: the sender's registry `first_registered_ts` is under 24 h old, in the future, or absent ("sender age unknown") |
| `rejected` | `exposure_unavailable` | Trusted fleet host: the `sender_exposure` assessment returned nothing or failed; a cross-host peer task never goes without it |
| `rejected` | `peer_statement_too_large` | Trusted fleet host: the signed statement would exceed 8192 bytes, measured exactly before anything is allocated or signed |
| `rejected` | `unresolved_reply` | Reply: `in_reply_to` doesn't resolve to a ledger record for this sender; or, for a bound reply, the record binds another agent, has expired, lacks its binding members, or cannot make a valid `bound` |
| `rejected` | `self_send` | Recipient resolves to the sender's own instance |
| `rejected` | `req_id_reused` | The filename's `req_id` was already anchored to a DIFFERENT request (agent deleted its own `outbound/{results,processed}` and resubmitted under a reused id) — refused rather than replaying the stale verdict |
| `rejected` | `quarantined_pre_approval` | The filename was already present in the outbox at the moment this router FIRST SAW the instance — staged-request quarantine, never delivered; resubmit under a fresh `req_id`. (The code keeps its old spelling: it is on the wire, and `approve` was retired after it shipped.) |
| `queued_for_human` | `attachment_too_large` | A declared `size_bytes` (per-file or total) exceeds the configured cap — an HONEST declaration, so held rather than rejected; no sidecar was opened to reach this verdict |
| `queued_for_human` | `attachment_count_exceeded` | More attachments than `attachment_max_count` — no sidecar was opened |
| `accepted` | `peer_routed` | Peer lane: placed in the recipient's `peer/` tree along a declared edge (or, for a reply, the reverse edge). `message_id` is the peer message id. Fresh task and reply alike — the code names the TREE |
| `rejected` | `peer_single_recipient` | Peer lane: a submit touching a declared edge named more than one recipient or carried `cc`. Refused whole; a mixed-lane submit is never half-sent |
| `rejected` | `peer_reply_window_expired` | Peer lane: the reply key resolves to a peer notice, no edge exists in the reply's direction, and the notice is older than `peer_reply_window_seconds` |
| `queued_for_human` | `transport_anomaly` | External leg (see "In-flight requests"): the transport request was archived without a result, its result failed validation, the router's own attachment snapshot was damaged before anything was handed over, a custom cold policy routed outside the request's class, or the plugin's peer codec refused this router's own statement (nothing was signed). Never resubmitted |

**Codes this router never originates.** They reach an agent only as a
transport verdict, passed through verbatim with `detail` prefixed
`transport: `: `hop_version_mismatch`, `hop_invalid_request`,
`recipient_refused`, `loop_refused`, `special_use_domain`,
`delivery_unknown`, `rate_limited`, `halted`, and `transport_timeout`. The
last one in particular: this router never settles a request on age (no
timeout, by operator decision), so a `transport_timeout` is always the
downstream runtime's. `agent_id_mismatch` is in both lists: this router
originates it for its own envelope check, and also passes a downstream one
through. `halted` and `agent_id_mismatch` arrive from the external leg's
runtime and are not in the contract's reason-code table, a gap recorded
for the contract's owner.

## Cross-host classification (`router/classify.py`)

Every cold send is classified before any policy sees it, in this order,
and the first step that answers decides:

1. alias normalisation (hold, then refuse; "Aliases" below);
2. any address outside the one address grammar: `malformed_request`;
3. any address at this router's own domain naming no instance:
   `recipient_unknown`;
4. no transport plugin and any cross-host address: `recipient_unknown`,
   nothing below runs;
5. more than one class across `to` ∪ `cc`: `mixed_recipient_classes`;
6. the one class's rule: **local** (the same-host decision, unchanged);
   **trusted fleet host** (in order: the shape, `task_deny`, the 24 h
   quarantine, the exposure stamp, the peer lane's availability, the
   statement size; see the reason codes above); **fleet host not in the
   trusted list** (permitted when the sender's `remote_fleet` names it,
   else held); **internet** (`no_route` without egress, first; then permitted
   when `send_to` names the address or `@domain`, else held).

A reply (`in_reply_to`) never reaches it: it is decided by its binding, and
an unbound key stays `unresolved_reply`.

The address grammar is one parser, shared by the drain and the loader: an
ASCII dot-atom local part of at most 64 characters, one `@`, LDH labels of
at most 63 characters, a domain of at most 253 and an address of at most
254. A domain is compared lowercased; a remote local part is compared
EXACTLY, never case-folded; a local part at a fleet domain must also match
the registry's name grammar. The envelope's own pattern
(`router/validate.py`) still runs first and refuses some shapes before
classification; both answers are `malformed_request`.
`tests/vectors/address_grammar.json` holds the cases, shared with the
external leg's runtime.

A per-address `task_deny` entry matches every spelling of its target, by
the registry's skeleton (case, the fixed confusables and separators folded),
because the receiving router resolves local parts that way. Permits
(`send_to`, the recipient-set checks) stay exact.

**Config.** All optional:

```json
"trusted_fleet_hosts": ["t1.fleet.example"],
"fleet_hosts": ["t1.fleet.example", "hub2.fleet.example"],
"egress": false,
"ingress_quarantine_days": 14,
"instances": {"alice": {"handoff_dir": "...",
  "task_deny": ["@t1.fleet.example"],
  "send_to": ["bob@example.com", "@partner.example"],
  "remote_fleet": ["hub2.fleet.example"]}}
```

`fleet_hosts` is every fleet host and must include every trusted one. The
loader refuses, and startup stops on: this router's own domain in either
list; a trusted host missing from `fleet_hosts`; `send_to` or
`remote_fleet` naming a trusted host; `remote_fleet` naming a host outside
`fleet_hosts`; a `task_deny` entry outside the trusted hosts; a duplicate in
any list after canonicalisation; anything outside the grammar. Absent keys
reproduce the behaviour before them ONLY without a transport plugin. With
one, an absent `egress` makes every internet address `no_route`. The
per-instance keys exist only in an authored `instances` object for now: a
discovered fleet has no per-instance section to put them in.

**The policy digest.** At staging, the in-flight record stores the
sender's policy digest and the request's route. The digest is
`"sha256:" + hex(sha256(json.dumps(obj, sort_keys=True, separators=(",",
":"), ensure_ascii=False, allow_nan=False).encode("utf-8")))` over
`{"v": 1, "send_to", "remote_fleet", "task_deny", "trusted_fleet_hosts",
"egress"}`, each list canonicalised (domains lowercased, de-duplicated,
sorted) by the same canonicaliser the loader uses.
`tests/vectors/policy_digest.json` holds known answers, shared with the
external leg's runtime.

**The re-check.** Every publication attempt re-classifies the staged
request under the current config: the first, and the re-write of a
handed-but-unwritten one. A digest change is LOGGED and never the trigger,
because what decides a permit (the registry age, the exposure, the plugin's
presence, `fleet_domain`, `fleet_hosts`) is wider than the digest. Still
permitted means the same class, route and recipient set; then the record's
digest is updated durably BEFORE the request is written, so the digest
published with it is the current one. Anything else settles
`queued_for_human`/`recipient_not_allowlisted`, "policy changed before
publication: …", saying "route changed from X to Y" where that is the
cause. A different route is refused, never rebuilt. An alias the table can
no longer decide is a refusal at this point too, not a hold: the request
was already consumed, and holding it would leave a staged request with no
answer.

**Revocation after hand-over.** While a handed request is pending, every
poll re-checks it. If it is no longer permitted, nothing this router
accepts can withdraw it: no transport API has a withdraw operation. The
record is marked `revocation_unenforceable` (a member of its closed schema,
so it survives a restart), an ERROR is logged every poll it stays pending,
and `status` lists it with its age. A result, if one arrives, still settles
it, because the send may have happened. `withdraw_request` is part of the
port from API (3, 0) and is reported (`withdraw_capable`), but the in-flight
table does not call it yet: a withdrawn request needs its own branch in the
"archived, still no result" row first.

**A failing reload.** A reload that fails, or that `reload_config` refuses
(a changed `state_dir` or `transport_plugin`), keeps the last good config
with `reload_failed` set. That is process state, never read from a file;
a restart loads the config afresh and the next good reload clears it.
While it is set the local lane runs unchanged and the external leg fails
closed: nothing new is published, a handed-but-unwritten request is not
re-written, and a revocation is logged but not enacted. An ERROR is
logged every poll, and `status` shows `config_reload_failed`.

**The cold-policy seam.** A custom `cold_policy` decides only a request
whose recipients are all in ONE class of item 6 or item 7, after steps 1-5.
It never decides a same-host request, the peer lane or a trusted host. Its
answer is checked against the class: only a refusal, or an external route
naming recipients of this request's class, is accepted, and anything else
is `queued_for_human`/`transport_anomaly`. No deployment configures one;
it is a test and embedding hook.

## In-flight requests (external leg, partly built)

`router/inflight.py` holds a request that stays unanswered across polls: one
handed to a second runtime and settled from that runtime's result. The
classifier above routes an item 6 or item 7 request here when a transport
is present. The transport is an optional plugin, activated at startup
(below); the hand-over and the retirement of a fenced generation's tree are
built, while re-placement is designed but not built yet.

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

### Listing what is in flight (`inflight list`)

`python3 -m router --config C inflight list [NAME] [--json]` lists every
entry under every `inflight/` directory, while the router runs:

* **Read-only, no lock.** It takes no drain lock, writes nothing, sweeps and
  repairs nothing, and reads the registry with `persist=False` (its seq is
  not recorded). Every file is opened `O_NOFOLLOW` relative to its
  directory, so a planted link is reported, never followed.
* **Every generation.** Without a registry, `state_dir/<name>/`. Under one,
  every generation the generations file lists, current and fenced (a fenced
  generation's records still advance every poll), or the pre-generation
  layout (`legacy`) when there is no generations file; and the runtime
  control namespace, `_runtime/<generation>/`. `NAME` may be `_runtime`.
* **Never skips an entry.** One row per record, orphan marker or stray name.
  `state` is `not_handed`, `handed` (its marker names its own transport id),
  `revoked` (`revocation_unenforceable` is set), `orphan_marker` (a
  `.handed` with no record), `unreadable` (torn, outside the closed record
  schema, a link, not a regular file, or a name that is neither `<id>.json`
  nor `<id>.handed`) or `unresolved` (the registry resolves no logical id,
  or the generations file is held). `reason` says why. The one entry not
  shown is one that vanishes between the directory read and its open: the
  live drain settled it in between.
* **Rows.** Each row has exactly `instance`, `generation`, `current`,
  `entry`, `req_id`, `transport_req_id`, `state`, `written_ts`, `age_s`
  (from the record's `written_ts`), `tree` (`peer` when the record pins a
  signed statement, else `mail`), `signed_kind`, `retransmit` and
  `reason`; an absent fact is `null`. `--json` prints ONLY one document,
  `{"schema": "amap-router-local.inflight-list/1", "at": <UTC ts>,
  "rows": [...]}`, so a truncated output does not parse. Without it, one
  escaped line per row: instance, generation, req_id, transport id, state,
  age and tree (`-` when absent), then the reason.

Exit 0 when the listing was produced, whatever its rows say; 1 for an
unknown `NAME`; 2 for a config error.

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
refused; changing the plugin needs a restart.

The path is used EXACTLY as written: the config does not normalise it, and
the loader compares the raw string with its `realpath`. A normalised copy is
not the same path when a component is a symlink: with `b` a symlink,
`/a/b/../c/p.py` names `c/p.py` beside `b`'s target, while `/a/c/p.py`
names another file. One consequence: respelling the SAME file on a reload
(`/opt/amap/./plugin.py` for `/opt/amap/plugin.py`) is a changed
`transport_plugin`, and the reload is refused like any other change. The loader's refusals, each a
fixed `PluginRefused.reason`:

| reason | refused when |
|---|---|
| `path_not_absolute`, `path_not_canonical` | the path is relative, or is not its own `realpath` exactly as written: any symlinked component, or a spelling such as `..`, `.`, `//` or a trailing `/` |
| `agent_reachable` | the file is inside an instance's root, inbox, outbox or peer tree |
| `parent_owner`, `parent_writable` | a directory between the file and `/` is not root-owned, or is writable by others without the sticky bit |
| `missing`, `symlink`, `not_regular` | the file is absent, is a symlink, or is not a regular file |
| `owner`, `mode` | the file is not root-owned, or its mode is not exactly 0444 or 0644 |
| `too_large` | the file exceeds `transport.MAX_PLUGIN_BYTES` |
| `hash_mismatch` | its bytes, read once from the pinned descriptor, do not hash to `sha256` |
| `exec_failed` | those bytes, the only ones ever executed, fail to run |
| `api_mismatch` | its `PLUGIN_API` is not `(our major, at least our minor)` |
| `missing_factory` | it lacks a callable `make_sender`, `make_intake_reader` or `make_upstream_marker_store` |

With `delegation` configured, a plugin is also refused
`delegation_capability_missing` unless its `PLUGIN_API` is at least `(3, 3)`,
`make_signer`, `make_verifier`, `make_peer_codec` and `make_peer_errors` are all
callable, and its own `OPTIONAL_FACTORIES` declares the two new names at
`(3, 3)` or later (`transport.check_delegation`). Without `delegation` none of
this is consulted, so an older compatible plugin still loads.

`REFUSAL_REASONS` also lists `fsops_unavailable` and `role_mismatch`, which
this router never raises (the first only until its filesystem port was
activated); both loaders share one vocabulary. A plugin that passes every
check is ACTIVATED: `start_transport` builds this router's `HopFsOps` for
the configured hop root, checks its refusal classes, and hands the drain
the plugin with it. `TransportPort.has_pending` is true for a request the
downstream runtime has claimed as well as one it has not.

**The ports a plugin receives** are Protocols in the same module, interface
only: `HopFsOps` (every filesystem operation a plugin may make, on pinned
descriptors; a plugin makes no filesystem call of its own), `KeyOps` (the
signing key as bytes; the signer never opens a path), `Signer` and
`Verifier`, plus the factory signatures (`make_sender`, `make_intake_reader`,
`make_upstream_marker_store`, `make_signer`, `make_verifier`, and the
sibling runtime's four). `PLUGIN_API`'s major covers all of them, and is
`(3, 0)` since contract amendment E8: a `(2, x)` plugin is refused here, and
a `(3, x)` plugin by a `(2, x)` runtime, before any factory is called.
Nothing at `(2, x)` was ever deployed, so plugin and runtime move together.
What `(3, 0)` adds:

- `HopFsOps.list_pinned(dir_fd, *, limit, after=None)` pages a pinned
  directory by name, at most `transport.LIST_LIMIT_MAX` names per call,
  scanning a fresh open description and stopping with the port's own
  `ListingTooLarge` past `transport.LIST_SCAN_MAX` names.
- `InboundPort.list_entries(kind, *, limit, after=None)` pages committed
  entries by their NAME (a notice's is `notice-<id>.json`, so id order is
  not listing order), and fills or exhausts, with a one-entry lookahead
  for `truncated`. A notice bundle is `amap-hop-notice-entry/2`, with a
  REQUIRED `hop` member (the exact facts bytes). A committed notice whose
  facts are missing or invalid is listed, and its read raises the port's
  own `NoticeRefused` (`notice_incomplete`, `notice_invalid`).
- `make_upstream_marker_store` returns `UpstreamMarkers`: exactly
  `retire(retired_at)` (`created`, `exists_same`, `exists`, `absent`) and
  `retired()`, which raises the store's own `GenerationAbsent` for a
  missing tree and raises whenever it cannot decide, never answering
  "not retired" on a failed read.
- `TransportPort.withdraw_request(n)` (`withdrawn`, `too_late`), decided by
  the rename itself.
- `close()` on every plugin object; it never closes the `HopFsOps`
  instance's shared stage descriptors. A factory that raises has released
  everything it opened.
- Every exception a plugin object raises on purpose carries `.reason` from
  `transport.TRANSPORT_REASONS`, and `transport.classify` is the one
  classifier, in a fixed order: the captured verdict classes, the
  runtime's own classes, a plugin reason, `OSError`, anything else.
- An optional `make_intake_remover` at `(3, 1)`, a minor addition: the
  ingress pass removes a waiting entry through it when the plugin offers
  one. Nothing in `(3, 0)` depends on it.

The contracts on `HopFsOps` worth knowing before implementing it:

- `commit_durable` derives its stage name's destination tag from a binding
  the implementation holds, never from a parameter or a bare descriptor
  number.
- `open_regular_pinned` returns `bytes` or the port's own `NOT_YET`, with
  anything else a protocol violation that callers raise on, never skip. Its
  refusals are the port's own `UnsafeRead` class with `.reason` in
  `not_regular`, `link_count`, `too_large`; a missing name is a raw
  `FileNotFoundError`; anything else propagates and is no verdict. The
  reason classifies; the caller decides whether it is terminal.
- `open_private_stage_dir` gives a writer's private root its own
  `.stage/`, so `commit_durable` publishes into a private tree under the
  same rule as a hop tree. NOT_YET is not widened: link count 2 in a
  private tree raises on read. The hop root and private roots must be
  pairwise disjoint.
- `commit_durable(..., deps=...)` checks each earlier member of a
  publication (its directory still at its path in its tree, then size and
  sha256 by a bounded read) before and after the link or compare, on every
  result path, raising on a mismatch. A dependency must be in the
  destination's own tree and outside any stage directory, or it is refused
  before anything is staged. Those are point-in-time observations: a
  publication is complete only once its READER has verified what it
  consumes. A caller treats any exception from `commit_durable` or
  `mkdir_and_pin` as "not committed"; the implementation's anomaly classes
  are not part of the Protocol.
- `mkdir_and_pin` checks the final `fstat` of the descriptor it returns
  (owner, permission bits, no setuid or sticky bit, the parent's setgid
  bit), and never repairs an existing directory.

`router/transport.py` names these at `(2, 0)`, beside the Protocols:
`HOPFSOPS_METHODS` (methods only), `HOPFSOPS_ATTRIBUTES` (`NOT_YET`,
`UnsafeRead`), `Dependency` (a `deps` element's type) and
`UNSAFE_READ_REASONS`.

**This router's implementation of `HopFsOps`** is `router/fsops.py`
(internal), built once per process by `start_transport`. It needs
`renameat2` with `RENAME_NOREPLACE` (Linux, glibc 2.28+), and a startup
capability probe (`fsops.probe`) refuses a filesystem without it or without
a working directory fsync. Whether a given mount honours those is a
deployment measurement, not something this code can show.

### The hand-over (`router/hoplink.py`)

A plugin needs a `hop` object beside it, and a registry: a hand-over names
its sender by logical_id, and generations exist only under a registry.

```json
"hop": {"root": "/srv/amap/hop", "peer_uid": 1001, "version_write": 1,
        "caps": {"document": 50331648, "request": 1048576,
                 "attachment": 8388608, "total": 33554432}}
```

`root` is absolute, written in normal form, and never nested with
`state_dir`, `registry_dir`, `intake_dir` or any directory an agent can
reach (the same list the plugin loader refuses a plugin inside). It is
fixed for the life of `state_dir`: every generation pins it, retiring a
generation needs that generation's root, and there is no move procedure, so
moving the hop tree means a new `state_dir`. `peer_uid`
is the downstream runtime's uid. `version_write` is the envelope's
`hop_contract`, 1 to 2^31-1. The caps are the plugin's, in bytes: the
handover document, the request file, one decoded attachment, all of them.
`caps.document` must be at least the largest handover an accepted request
can make, computed exactly at load (`hoplink.document_floor`), or the
config is refused. `caps.attachment` is at least 1 MiB, the hop's own
per-sidecar cap: a smaller one would refuse, on every read, an inbound
sidecar the peer may commit. The floor counts the attachment caps (the smaller of
the plugin's and this router's), so at this router's defaults it is about
43.7 MiB. `link`, optional, names the inbound reader's link in the hop
codec's link grammar (`[a-z0-9][a-z0-9-]{0,62}`): it keys the ingress
journal and is what admission compares the facts' `admission_link` with.
Without it inbound is DISABLED (nothing is listed, read or placed; the
outbound leg is unaffected). It is rendered by the host adapter from the
fleet policy that names the downstream runtime's link. A reload that changes `hop` is refused, like one
that changes the plugin. Every instance's address must be able to serve as a
handover's `from_address` (at most 254 octets, a local part of at most 64,
the bare addr-spec pattern): one that cannot is refused at load, by the
same check begin runs.

**Who creates what under `root`.** `root` itself is the deployment's
(this router's uid, the downstream runtime's group, 2750), and so are the
downstream runtime's own host intakes beside the identities (`.unresolved/`,
`.control/`, where inbound control mail lands). `.runtime/` is different:
it is this router's OUTBOUND runtime control tree, the upstream side of
control notices (see "The runtime control tree" below). The plugin creates
it, and admits each generation when this router calls `admit` (identity
`logical_id` "runtime" and the router's own address); the downstream
runtime creates `down/` and its receiver directories on first sight. The
deployment never pre-creates it. Everything under `<root>/<logical_id>/` is the
plugin's, created when a generation is admitted or first seen. This router,
admitting a generation, creates `<root>/<logical_id>/`, the generation tree
with its `up/`, and the upstream directories: `outbound/` and `inbound/` with
its parents (2770 under the setgid root) and `withdrawn/` (2750). The
downstream runtime, on its first sight of the generation, creates `down/`
and its `claimed/`, `results/` and `processed/`. The deployment must not
pre-create or chown `<root>/<logical_id>/` or anything under it: the plugin's
owner checks refuse a tree it did not make.

**One sender per generation.** The drain asks for the current
generation's sender on first use. Before the first construction this router
writes the generation's binding pin, `transport/hop.json` (the root,
`peer_uid`, `version_write`, and `admitted_at`: the generation's `minted_ts`
from its durable record, never the clock). A later config that no longer
matches the pin holds that generation (`hop_binding_changed`) rather than
admit it a second time elsewhere. `transport/admitted.json` is written once
the plugin's construction, which admits the tree, has succeeded; if that
write fails, the constructed sender is closed and the generation is held
for a retry, so nothing leaks. Any failure on the way to a sender (a
damaged pin, an unreadable generations record) is likewise a retried
construction hold (`hop_construct_failed:<class>`), never an error that
stops the instance's local mail. A latched construction hold
(`hop_settings_refused`, `hop_identity_conflict`, `hop_plugin_vocabulary`)
is not re-attempted until a restart or a new generation.

**Fence and retire.** The order is the private record (the generations
file naming the new current generation, already durable when a poll first
sees it), then retire every fenced predecessor this router PINNED, then
admit the current generation by constructing its sender. Each poll, under
the drain lock and before any construction, every pinned predecessor not
yet retired in this process is retired through the plugin's upstream marker
store, built from that generation's pin, at that generation's `fenced_ts`
(never the clock). EVERY such predecessor is attempted each poll: one that
holds never stops a newer one being retired, and the oldest hold is the one
kept. A start that finds one unretired retires it first, so recovery is the
same code. The pin, not `admitted.json`, decides what may
exist: a construction can admit the tree and then fail before confirming
it. `created`, `exists_same` and `exists` mean retired, and the store is
then closed. `created` and `exists` each write one AUDIT line,
`generation_retired`, with the attempted `retired_at`. For `exists` the
marker's own value cannot be read through the plugin (`UpstreamMarkers` has
`retire` and a boolean `retired`), and the line says so
(`recorded_retired_at: null`, `recorded_value: "not readable through
PLUGIN_API (3, 1)"`). A replay after a restart (`exists_same`) writes none.
A failure to write the line is an ERROR and never undoes or holds the
retirement, which has already happened. `absent` means there was nothing to retire unless
`admitted.json` says the tree was admitted, in which case the tree is lost:
the whole instance holds `hop_tree_lost` and no successor is admitted until
`router generation new` acknowledges it (below). Any exception holds the
whole instance (`hop_retire_failed:<reason or class>`), retried next poll
with the same store, constructed once. While a predecessor is unretired no
successor is admitted, and the hold says why. Every hold's status entry
names its exit where there is one.

**A fenced generation's own work** gets its own sender, constructed only
after that generation's tree is retired in this process, never before (a
construction is then always the replay of an admitted tree, never a first
admission). A record that was never handed over is answered
`rejected`/`no_route` ("generation fenced before hand-over; nothing was
sent"): there is never a first hand-over into a retired tree. A handed-over
record is probed and settled as in the current generation. A generation
whose tree was absent is never served through the hop: its records are left
for disposal (§5.4). The sender is closed once that generation's in-flight
set is empty; the current generation's sender is never closed while current.

**A lost tree's exit is `router generation new <name> --reason <text>`**
(router stopped). Under the lock, BEFORE anything is written, the verb
finds the lost set itself, never from `status.json`: each fenced generation
with `admitted.json` and no acknowledgement is probed through an upstream
marker store only (`retired()`; a missing tree is the store's
`GenerationAbsent`; a sender is never constructed by any CLI verb). A probe
it cannot decide refuses the verb with nothing changed; a `layout` or
`marker_unreadable` refusal means the tree is present but damaged, NOT
lost. Then the new generation and its audit line are written, and only
then each lost generation's `transport/lost_ack.json`. A crash between the
audit line and the acknowledgement leaves the hold standing; running the
verb again recovers (one more never-admitted generation is harmless).
Nothing else writes the acknowledgement.

**The handover document** is built from the in-flight record only:
`{"schema": "amap-hop-handover/1", "request", "envelope", "attachments",
"settled_through"}`, canonical (sorted, compact, UTF-8, integers only, no
trailing newline). The request's `req_id` is the transport id and its
`agent_id` the logical_id. The envelope is `{"kind": "mail",
"from_address", "hop_contract"}`, where `from_address` is pinned in the
record when the request is begun, never filled in from a later config.
`settled_through` is the lowest transport id still in flight, less one.
When any in-flight entry cannot be read the frontier is undecidable:
skipping one would declare it settled, so this generation's hand-overs are
LATCHED (`hop_frontier_undecidable`), before anything is handed over, and
only `router generation new` releases them. A record that cannot make a
valid handover (one without its pinned `from_address`, a generation with no
pin) latches `hop_handover_invalid` the same way. The envelope's
`hop_contract` is the PIN's `version_write`, never the current config's. A retry
changes `settled_through` and nothing else.

**Attachments go over the leg, from this router's own snapshot.**
- At begin, before a transport id is allocated, each attachment must be
  within the EFFECTIVE per-file cap (the smaller of `hop.caps.attachment`
  and `attachment_max_bytes`) and all of them within the effective total
  (the smaller of `hop.caps.total` and `attachment_max_total_bytes`).
  Over either: `queued_for_human`/`attachment_too_large`, the per-file row
  with the `too_large` per-attachment outcome.
- Then the bytes ingest verified are copied ONCE into private state,
  `<generation>/inflight-snapshots/<req_id>/<i>` (0700 directories, 0600
  files, every directory entry made durable), BEFORE the in-flight record
  is written. The record names each attachment's size and digest, which
  must equal the draft's descriptors. The snapshot sits beside
  `inflight/`, never inside it, so `inflight/` keeps holding only records
  and markers.
- Every hand-over reads the snapshot afresh and re-proves each blob
  against the record (no symlink followed at any level, a regular file
  with one link, exactly the recorded size, the recorded digest), so
  every retry carries exactly the bytes first verified, whatever happens
  later to the agent's own sidecars. The draft's descriptors go out
  unchanged.
- Settlement removes the record (made durably gone first), then its
  marker, then its snapshot. A snapshot whose record is gone is swept on a
  later poll, under the lock, but only when the record's absence is PROVEN
  (ENOENT); anything uncertain is kept and logged as an ERROR, and the
  drain summary counts it (`snapshot_sweep_uncertain`).
- A damaged snapshot is this router's own damage. If nothing was handed
  over yet, the request is settled `queued_for_human`/`transport_anomaly`.
  If it was handed over, this generation's hand-overs are LATCHED
  (`hop_snapshot_damaged`) and only `router generation new` releases them:
  settling could misreport a request pending downstream, and different
  bytes are never handed over.
- Storage: up to the effective total cap, as it was at begin, per
  in-flight request with attachments.
- Residuals: a hop cap lowered (across a restart) below the attachments of
  a request already in flight makes its hand-over invalid at the plugin,
  which latches `hop_handover_invalid` for that generation, the
  "unreachable" row of the hand-over table, reached this way. Writing a
  large snapshot before the record widens the window in which a crash
  burns a transport id; the burned id is harmless and the snapshot is
  swept.

**Mail, or a bound reply.** A cold hand-over carries kind `"mail"`, so a
request the classifier did not put in a cold mail class (`fleet_host`,
`internet`) is refused `rejected`/`no_route` before anything is allocated,
never handed over as mail. The one other kind is `"bound_reply"`, below.

**Refused at begin**, before a transport id is allocated: more than 100
raw recipients across `to`, `cc` and `bcc` (`too_many_recipients`, with
duplicates counted); a recipient over RFC 5321's octet limits, a request the
canonical encoding cannot carry, or one over `caps.request` at the longest
transport id (`malformed_request`); an instance address that cannot be a
`from_address` (`queued_for_human`/`transport_anomaly`).

**When a hand-over fails**, the plugin's `.reason` decides. A reason no
retry can change LATCHES a hold on that generation's hand-overs, in
`transport/hold.json`: `hop_request_conflict`, `hop_request_withdrawn`,
`hop_request_settled`, `hop_frontier_undecidable`, `hop_handover_invalid`,
`hop_heal:<reason>`. Results are still read under it, and `router
generation new` moves the instance on. Anything else is retried next poll
with the same record and transport id, under a named status:
`hop_version_unavailable` (the peer does not read `version_write` yet) and
`hop_layout` log a WARNING until stale (one hour), then an ERROR, as does
`hop_io_error`. `hop_layout` has two causes, and its status entry carries a
hint naming both: the peer's `down/` not existing yet, which clears, or this
router's own tree directories missing, which does not. `hop_anomaly:<reason>`,
`hop_unsafe_read:<reason>` and `hop_object_closed` (the sender is rebuilt)
log an ERROR every poll. An exception the table does not name is
`hop_unexpected`, logged with its traceback. A failed status probe
(`has_result`, `has_pending`, `has_archived`, `read_result`) never settles
anything: whatever it raises, the record, its transport id and its handed
marker are kept, status shows `hop_probe_failed:<reason or class>` (a
WARNING until stale, then an ERROR), and the next poll settles from the
real result. A result that reads but fails validation is still settled
`transport_anomaly`. An I/O error while listing `inflight/` for the
frontier, even a transient one, latches `hop_frontier_undecidable` too:
fail-closed, and `router generation new` releases it. While a sender is held, or this generation's hand-overs
are latched, an external request stays in the outbox, unconsumed: it is
decided once the hold clears or `router generation new` moves the instance
on, never stranded in the held generation.

**A process end, modelled** (`hoplink.reset_process_state(*runtimes)`, for
the hop fixture's restart and for tests): every hop object is closed, each
given runtime's filesystem port is closed (`FsOps.close`: its pinned stage
descriptors and its bindings, so a new port validates the stages again), and
every per-process container in the package is emptied. The runtime is then
spent: build a new one. The plugin module is not reloaded.

**`status.json`** carries a `hop` section, never the drained summary line:
per instance the sender hold, the latched hand-over hold and the current
retry, each with its first sighting and age (and a hint naming the exit
where a hold has one), and the senders and marker stores this process
holds open.

## Signed peer tasks (delegation, `router/peerlane.py`)

A peer task to a TRUSTED fleet host travels as a signed statement: a small
JSON object this router builds, signs with its own Ed25519 key through the
plugin, and hands over as envelope kind `"peer"`. Off unless `delegation` is
configured; then item 5e is on.

**Config** (`delegation`; every member required except `attachment_basis`,
`inbound`, `windows` and `retention`):

```
"delegation": {
  "partition_verified": "<the deploy's evidence that the downstream runtime cannot read the key or write peer/>",
  "signing_key": {"path": "/abs/seed", "key_id": "<id>", "public_key": "<64 lower hex>"},
  "runtimes": [{"name": "...", "runtime": "amap.router@<host>", "domains": ["<host>"],
                "keys": [{"key_id": "...", "public_key": "<64 hex>",
                          "not_before": "...Z", "not_after": "...Z"}]}],
  "crypto": {"crypto_backend": "pyca" | "openssl", "openssl_path": "/abs/openssl"},
  "attachment_basis": "closed_fleet",
  "inbound": false,
  "windows": {"p": 3600, "f": 300},
  "retention": {"sweep": false}
}
```

- Without `partition_verified` the config is refused: delegation never runs
  without the deploy's evidence.
- Each runtime's domains must be trusted fleet hosts (never this router's own
  domain), and its `runtime` must be `amap.router@` one of them. A domain
  belongs to exactly one runtime (`domain_shared` otherwise).
- `attachment_basis`, optional: absent, or `"closed_fleet"`, the deployment's
  basis for asserting `clean` on a signed peer task's attachments (below).
- `inbound`, optional: absent or `false` by default. `true` takes signed
  candidates at all: only with it does a poll run the inbound pass (take,
  checks, decide, place, recovery). It is opt-in per host; enable it only
  after `router peer-store init --never-admitted` (the runbook below).
- `windows`, optional: the receiver's window, `p` (past) and `f` (future
  skew) in seconds, within the profile's bounds (`p` in [300, 86400], `f`
  at most 900). Default `{"p": 3600, "f": 300}`.
- `retention`, optional: `{"sweep": false}` by default. `true` is refused
  while the store has no settled-through frontier (no `peer-store init`).
- `signing_key.path` is in normal form and lexically outside `state_dir`,
  `hop.root`, the registry, the intake directory and every agent-reachable
  root, each compared as configured AND as resolved, by path components.

**Activation**, at startup and at every reload (`peerlane.activate`):
1. the plugin's delegation capabilities (`transport.check_delegation`);
2. the peer codec (`make_peer_codec({})`), whose published reason sets become
   this router's vocabulary. Only the plugin's own `ConfigError`, by exact
   type, refuses here; any other exception from the factory is a bug and
   propagates;
3. the seed, read by walking from `/` with no symlink followed: every
   directory owned by root or this process and writable by group or others
   only when sticky (as for the plugin file: in a sticky directory others
   cannot rename or remove an entry they do not own, and every entry on the
   walk is checked to be root's or this process's), none of them a forbidden
   root (by device and inode);
   the file this process's, mode 0400, one link, exactly 32 bytes. Its bytes
   go to the plugin's signer and nowhere else;
4. the peer table through the codec's key gate (a duplicate `key_id` across
   all runtimes, inverted validity, a non-canonical or small-order key, a
   malformed entry: each refused with its token);
5. this router's own key through the same gate, its `key_id` never equal to
   a peer's;
6. a sign/verify PROBE over a fixed message: the configured `public_key` must
   verify the seed's signature, or `signing_key_mismatch`.

Activation is repeated only when something it depends on changes (the
`delegation` config, the plugin, or the seed file's identity, mode or size),
so an unchanged config costs no seed read, self-test or probe per poll. A
failure stops startup, or refuses the reload. An unexpected fault (a bug,
which propagates out of activation) stops startup loudly; at a reload it is
logged with its traceback and refuses the reload, so a reload never takes the
router down. On a refused reload the last good config and
delegation stay in force, `reload_failed` is set, and `status.json`'s
`classification.config_reload_failure` says since when and why. While a
reload is refused, a key REMOVED in the refused config is not applied; a key
whose `not_after` passes is refused anyway, because validity is evaluated at
verification time, inclusive at both ends. Only an exception that IS exactly
one of the plugin's four classes (`make_peer_errors()`), with a reason in the
codec's set, is a verdict; anything else is a bug and propagates.

**Sending** (`outbound._begin_peer`), after item 5 passes in full:
- the statement (`v` 1, closed: key id, kind, a fresh 128-bit id, from, to,
  ts, subject, the SHA-256 of `body_text` with CRLF replaced by LF, the
  attachments in order, `sender_exposure`, and `sender_since`, the sender's
  registry `first_registered_ts`) is serialised canonically, measured exactly
  (at most 8192 bytes), checked by the codec's own decoder, and signed;
- then, in order, each durable before the next: the transport id, the
  attachment snapshot, the peer ledger's closed `issued` record
  (`state_dir/<logical_id>/peer-ledger/<id>.json`: id, local, local address,
  remote, direction, generation, expiry by `peer_reply_window_seconds`), the
  in-flight record pinning the statement, signature and header, and the
  hand-over (`peer`: the unfolded header, `<id@fleet_domain>`, no
  `in_reply_to`, no references). The draft goes over addressed to the one
  recipient, with the normalised body;
- a local signer fault holds the request unconsumed, retried next poll;
  every retry hands over the pinned bytes, never re-signed;
- the re-check at every publication attempt and pending poll refuses
  (`queued_for_human`/`recipient_not_allowlisted`) when delegation is no
  longer active, the recipient is no longer a trusted host, `task_deny` now
  removes the pair, the sender is quarantined, or, for a task not yet handed
  over, the signing key is no longer the configured one. A handed task is
  never refused for a rotation alone.

`router reset` KEEPS the peer ledger: a fenced generation's peer tasks can
still be handed over after a reset, and a reply must still resolve. Control
notices are a later unit's: the hand-over accepts kind `"control"`, but no
production path begins one, and an in-flight record pinning one is damaged.

**Verifying** (`router/peerverify.py`, public): check 1, then the caller's
check 2 (`known`, required), then checks 3-5, each refusal the codec's cause
token; a local backend fault propagates. Check 2 is answered by the replay
index (`peerjournal.known`, below), excluding the candidate's own
reservation.

**Binding checks and placement** (`router/peerbind.py`, public;
`deliver.deliver_signed_peer`). After verification, `peerbind.bind` runs the
profile's checks 6 (the domain of `from` is one of the domains this router's
config lists for the runtime owning the key), 7 and 8 (supplied by the
caller, required), 9 (the body decodes strictly as `utf-8` or `us-ascii`, an
absent label meaning `us-ascii`, then CRLF -> LF, and hashes to
`body_sha256`), 10 (the attachment count, then each index's size and
digest) and 11 (exactly one `Message-ID`, exactly `<id@domain-of-from>`,
folding removed and its whitespace kept); the first failure decides, as one
of `key_domain`, `body_charset`, `body_digest`, `attachment_count`,
`attachment_digest`, `message_id`. `peerbind.hosting` decides whether `to`
is hosted here: an exact local part at the fleet domain (compared ASCII
case-insensitively), or an ACTIVE alias; a registry-held target, an alias
without a decision or an unverifiable one is undecided, never misrouted.
Unlike the mail lane's resolver, the local part compares exactly, as the
profile compares addresses. A peer domain belongs to exactly one configured
runtime: `delegation.runtimes` listing one domain twice is refused at load
(`domain_shared`).

A placement needs a PERSISTED decision. `authorise` yields a sealed fresh
value; `confirm` re-checks it against the current configuration;
`decision_record` turns a confirmed one into the decision's bytes, MAC'd
under `state_dir/peer-decision.key` (32 bytes, 0600, created once at
activation and made durable before use; never rotated; a reset leaves it,
and the candidate journal, alone; it signs three record types, decisions,
reservations and supersessions, each under its own label, so no one
verifies as another); `commit_decision` links those bytes into
`<state_dir>/<logical_id>/peer-candidates/<key>/decision.json` without ever
replacing a file, makes every step durable, reads them back, and only then
returns a receipt; `resume` takes only a receipt, re-reads the file through
it, and yields the decided value `deliver_signed_peer` requires. After a
restart `reopen_decision` gives the receipt from the file on disk. A decided
record is resumed as recorded: nothing re-decides it, and any mismatch is a
visible hold (`RecoveryCorrupt`), never a different disposition. Sealed
values cannot be pickled and do not outlive the process. These are
cooperative guarantees: code in this process that reads a private key can
forge, and nothing else can by mistake.

What a placement publishes comes from the verified statement, never from
headers: `message.id` (the sender's id, not the notice id), `from`, the
spool's `to`, `subject`, `sender_exposure` as signed, the body text check 9
produced, and each attachment's `filename`, `media_type` and `size_bytes`.
`in_reply_to` is published only when the caller resolved it from its own
ledger; `references` never. A signed `filename` or `media_type` is
published EXACTLY: it may contain path separators, CR/LF, NUL or bidi
controls, and nothing here uses it as a path (the bytes live at
`<notice_id>.attachments/<index>`); escaping belongs to the connector. An
id the notice grammar cannot carry (a leading `-`) is held as
`Unpublishable`, never rewritten.

The bytes stay under core §5. A signature authenticates a sender; it is not
a verdict on the bytes. This router asserts `clean` for a signed
attachment only on the deployment's explicit basis,
`delegation.attachment_basis: "closed_fleet"` (every trusted fleet host is
operator-supervised and no external sender reaches the peer lane); without
it every signed attachment is `unscanned` and no bytes, `sha256` or
`content_ref` are published. This router's caps decide first: an index
beyond `attachment_max_count`, over `attachment_max_bytes`, or crossing
`attachment_max_total_bytes` (counting only bytes actually published) is
`stripped`. Only the cap values are shared with the local lane, which
refuses a whole request at a cap. No type is sniffed and no policy keys on
a type, so the declared `media_type` never changes a disposition.

**Disposal tombstones.** For a host-intake candidate (`.unresolved/`,
`.control/`) the receiving side commits a tombstone under
`<hop.root>/.disposed/<intake>/<id>` with `commit_durable`, from bytes frozen
in its journal, before it marks the candidate done; the downstream runtime
removes an entry only on a valid tombstone. `peerlane.tombstone_bytes` gives
the exact form (a closed object: `v` 1, `intake`, `id` as 32 lower-case hex,
`candidate_sha256` as 64 lower-case hex, `disposition`, and `disposed_at` as
`YYYY-MM-DDTHH:MM:SSZ`), and `fsops` binds `.disposed/<intake>/` as this
router's own kind, rooted at the hop root, with a private `.stage/`. The
candidate journal writes them (below), and creates and checks each
`.stage/` at startup.

### Resending a signed peer task (`router/peerresend.py`)

A signed peer task is never signed again: its peer id is minted once, and
nothing on the resend path calls the signer, the statement builder, the id
minter, the Message-ID builder or the issued-record writer (a static test
and a runtime spy pin both). Nothing is exactly-once either: a resend is
the same bytes again, and the receiver's duplicate check decides.

**Hop configs only.** The workflow keys every copy by `(generation, n)`, so
it exists only where a config has both `registry_dir` and `hop`, the only
one with an external leg to resend over. Elsewhere nothing is preserved and
`retransmit` refuses `not_preserved`.

**Preservation.** Every signed peer task is copied, COMMITTED, before its
handed marker is written, so a copy exists before any byte can reach the
transport: `state_dir/<logical_id>/peer-sent/<peer id>/` holds
`record.json` (the in-flight record as handed), `origin.json`
(`{v, id, logical_id, generation, transport_req_id, req_id,
preserved_ts}`; `req_id` is the agent's request id), `attachments/<i>`, and
`COMMIT`, linked last. An uncommitted directory is never read and is written
again. A committed copy is compared on every field but `preserved_ts`; one
that differs holds the hand-over, never silently replaced. A copy that
cannot be written holds the record unhanded as
`peer_preservation_failed`, retried next poll. `handed.json` is linked by
the first pass that FINDS the handed marker (never the pass that writes
it), and `settled.json` by the original's settlement. A record handed over
before this existed is preserved by the next pass that finds its marker;
one already cleaned up is `not_preserved`.

**`peer-request show ID`** is read-only, for any issued id: the copy's
header fields (never the body), its settlement, the claim, every
retransmit, whether the agent has its Result, whether a signed Result or a
control notice was received, and each action with whether it is refused and
why.

**`peer-request retransmit ID --evidence TEXT [--allow-pending]`**, under
the drain lock. Every refusal writes nothing (no claim, no audit line, no
transport id, no record):

| code | why |
|---|---|
| `evidence_required` | no evidence given |
| `not_preserved`, `ambiguous`, `preservation_damaged` | no committed copy, one under two identities, or a copy that fails its re-checks |
| `retransmit_pending` | a retransmit of this id is already claimed |
| `clock_untrusted` | the peer clock is untrusted: a received signed Result lives in the receive journal, readable only under it |
| `journal_unreadable` | the receive journal cannot be read reliably, so a received signed Result cannot be ruled out: the clock holds no store bookkeeping beside a journal, the bookkeeping is not the exact shape the router writes (its roots, a root entry, or a pending operation), a record is unreadable, not a record or missing from its directory, a journal root is missing or does not match its bookkeeping, a journal directory cannot be listed, or a placed statement's snapshot cannot be read. Read through `peerjournal.strict_records`, never as "not answered" |
| `peer_lane_inactive`, `key_rotated` | no delegation configured, or the copy was signed under another key than the CONFIGURED signing key (conservative: a receiver in a rotation overlap might still accept it) |
| `outside_window` | now is past the statement's `ts + P + F` |
| `answered` | a control notice (the one-per-message `notified/` marker) or a signed Result replying to it was received |
| `not_eligible`, `not_yet_stale` | trigger 1 is a settlement with reason `delivery_unknown`; trigger 2 (no answer yet, still pending or `accepted`) needs `--allow-pending` and `STALE_AFTER_S` since `handed.json`; any other settlement is not eligible |
| `generation_unavailable` | no current generation for the identity |
| `policy_changed` | the sender's own peer re-check refuses it now |

Then it reserves a transport id `n`, links a claim (`retransmit.json`:
generation, `n`, time, `by`, evidence verbatim), appends `peer-request
retransmit requested` to the operator audit, and begins an in-flight record
`rtx.<n>` from the copy alone: the same request, recipients, from address,
attachments and peer block, a fresh `written_ts`, its own route.

At the defaults (`P` 3600 s, `F` 300 s, `STALE_AFTER_S` 3600 s) trigger 2 is
reachable only when the hand-over was found within 300 s of the statement's
`ts`: past that, `ts + P + F` has already gone by.

**The first hand-over, and after.** Before an `rtx.<n>` record's FIRST
hand-over the drain re-runs every dynamic refusal; a failure is a terminal
cancellation, settled `cancelled/<code>` with nothing handed. That outcome is
this router's own: no transaction exists for it downstream and no
downstream outcome, so `retransmit_cancelled` in status is never the
downstream runtime's verdict. While the
peer clock is untrusted, or the receive journal cannot be read reliably
(`journal_unreadable` above), the record is HELD instead (never handed,
never cancelled): those two are router states, not verdicts on the task
(`peerresend.HOLD_CODES`), so the gate's own read holds it and it is gated
again next poll. A claim not yet begun is held the same way; `show`
reports `answered` as unknown rather than "not answered". Once handed nothing cancels it. It settles as ITSELF, from
every settle path, at `peer-sent/<id>/retransmits/<generation>-<n>.json`,
never as the agent's Result or anchor: the original is their only writer.
Then its record goes, then `peer-request retransmit settled` is audited
(its inputs from the claim), then, LAST, the claim. A crash anywhere is
completed by the next pass (`peerresend.finish`), with one hand-over, one
settlement and each audit line exactly once. A claim belongs to its
generation: a generation fenced since is finished by its own fenced pass,
and a claim never begun there is cancelled `generation_unavailable`. (An
unhanded record in a fenced, retired generation settles `rejected/no_route`
by the shared rule first: never a first hand-over into a retired tree.)
After the cleanup a retransmit's settlement is read from
`peer-sent/<id>/retransmits/` (`show` lists them): its in-flight record is
gone by design.

A task can be handed over, settled and cleaned up in the pass that first
finds its handed marker: `handed.json` is linked first in that pass, so it
always exists beside `settled.json`, and the two may carry almost the same
time. That is a fast answer, not a missing hand-over.

**Control notices.** A retransmit the receiver demotes emits a failure
notice about the same id; the one-per-message `notified/<id>` marker caps
the agent at one notice per id, so a second is dropped. A notice is not a
Result.

**Retention.** A copy is pruned when it is settled, unclaimed, without a
live retransmit record, and past `ts + P + F + 7 days`: a prune claim, then
the directory bottom-up, then the claim. On by default; `peer_sent_prune:
false` keeps every copy.

**Status.** Each drain summary carries `peer_sent`: `preserved`,
`in_flight` (no `settled.json`), `settled`, `claimed`, and
`retransmit_<outcome>` counts.

**Against the real downstream runtime: PENDING, by name.** Two rows wait
for that runtime's peer carriage and its resend carve-out, and are not
skipped silently: `realre_check2_duplicate_silent` (an exact copy that
already arrived is dropped by the receiver's duplicate check, silently) and
`realre_first_arrival_placed` (a retransmit that is the first arrival is
placed). Until then a retransmit there settles `rejected/hop_invalid_request`
(no peer carriage), or holds as `held_index_collision` in the same
generation.

**Runbook**, after `delivery_unknown` or a task with no answer: (1) `show
<id>`, and the receiving router's own status; (2) `retransmit` while `ts` is
inside the window, knowing an exact copy that already arrived is dropped
silently as a duplicate; (3) otherwise a NEW task: a new agent request and a
new peer id, with its own Result.

## The candidate journal (`router/peerjournal.py`, `router/peerclock.py`)

Every signed candidate this router takes gets one durable record BEFORE any
check, and every step after it is durable before the next. Both modules are
internal. Inbound intake is off in this build (`delegation.inbound` is
refused at load), so in production no candidate is taken, and with it on
the production decision hooks hold every candidate they would decide
(`hook_absent`); the journal, its clock and the operator verbs below are in
place for when the policy, edge and reply decisions exist.

**The candidate view** (plugin API 3.4). A candidate's bytes become the
verifier's view only through the plugin's `candidate_view`; this router
never parses a candidate itself. A plugin below 3.4, or one without the view
or without its vocabulary (`CANDIDATE_REASONS`), leaves the view OFF:
candidates are held (`candidate_view_unavailable`), never guessed at. A
vocabulary that is not exactly the three 3.4 reasons refuses delegation.

**The inbound poll** (`peerjournal.poll`, after the ingress pass, under the
same lock, with `delegation.inbound` only): H is advanced first; then each
identity's each generation's `candidates/` is listed through the reader
port (one page per poll, with a cursor so held candidates never starve the
rest) and each entry is taken once (its bytes read once, into the snapshot)
and evaluated; then each host intake; then the frontier and, when
configured, the sweep. Without a trustworthy clock, or before
`peer-store init`, nothing is taken. The configured window
(`delegation.windows`) is applied first, at startup and at every poll: a
narrowing takes effect at once, a wider P raises the floor, and every F
joins the history. After the listing passes, RECOVERY walks every record
that is not `done`, by its recorded state and in `take_seq` order, whether
or not its entry is listed again. Each entry and each recovered record is
isolated: one that fails is held or counted and the rest proceed.

**Recovery is bounded by a not-done index.** Beside each owner's journal,
`<owner>/peer-open/` holds one file per OPEN record (not `done`, or `done`
but its tree entry never removed), named by its key and holding its
`take_seq`. `take` writes it durably after its intent and before the
record (take is the only creator of a record), and a record's marker goes
only after the record is durably closed. A pass reads the index, not the
journal: it validates EVERY marker and its record first (the key, the
owner and the take_seq must agree; a closed record's marker is simply
unlinked), and any damage it can see (a bad marker, a marker naming an
absent or unreadable record, an unlistable index, no index beside records)
makes that pass a FULL walk before anything is evaluated. A full walk,
which also rebuilds the index, runs at start, after a failed walk, and on a
monotonic hourly backstop (`FULL_WALK_S`), which catches what validation
cannot see: an open record with no marker is evaluated within the first
full walk at or after the hour, while polling continues. Both the index
and the full walk read each record with the strict reader's own check (a
regular file, a record, its key and its control what the router writes).
A walk that cannot resolve every entry establishes nothing: an owner whose
journal root cannot be listed, is missing while its bookkeeping counts
live records, or holds a key directory without a sound record keeps every
marker, the next pass walks fully again, and the schedule does not
advance. The records it could read are still recovered. Such damage is
logged and costs a full walk per pass until it is repaired; it is never
read as "nothing open". The index is advisory and outside the store's
content sum; it lives under each owner's directory, so it reserves no
instance name, and `reset` keeps it with the journal. Intake-listing truncation is not a trigger: recovery covers
records already taken. A
candidate first observed in a generation that is not current is
`late_inbound`: mailed, quarantined to that generation with that cause, and
never placed. A tree candidate's quarantine item
(for `demoted` and `mail`) goes into its generation's ingress quarantine
with cause `cold_fleet_mail` and the profile's cause as evidence; its entry
is removed through the plugin's remover only after `done`, and a removal
that does not succeed is retried by the next poll, which finds the entry
again with its record `done`.

**Host intakes** (`.unresolved/`, `.control/`, owned by `_host`). An entry
is taken only once its `candidate.json` is committed (at two links it is a
commit in progress). It is disposed of by a TOMBSTONE, never removed by
this router: the tombstone's bytes are frozen in the same record write that
records the disposition (`placed` for a decision, re-frozen as `refused` by
a supersession); then the effect; then the tombstone is committed with
`commit_durable` from exactly those bytes, mode 0640; then the record is
`done`. The downstream runtime removes the entry on a valid tombstone. The
record is kept while its tombstone exists, and a tombstone is removed only
once a complete listing, taken after it was committed, no longer shows the
entry. Without `.disposed/<intake>/` (the deploy creates it) nothing is
taken from that intake.

**Layout**, all under `state_dir`:

```
<logical_id>|_host/peer-candidates/<key>/
    snapshot/candidate.json | view.json | statement   written once
    record.json                                       the record (rev n)
    decision.json                                     a decided placement
    supersede.json                                    a refusal superseding it
peer-replay/<rt>/<idk>.json                           a reservation (MAC'd, immutable)
peer-replay/<rt>/<idk>.done                           its settlement marker
peer-replay/digests/<sha256(statement)>               check 2's index
peer-replay/operator.audit.jsonl                      every operator act
peer-vacant/<seq>                                     a take seq with no record
peer-clock.json                                       the clock AND the bookkeeping
```

`<key>` is sha256 over the delivery (intake, generation, owner, entry id):
one record per delivery, never per message. `rt` is the first 32 hex of
sha256(runtime), `idk` sha256(id). An instance cannot be named after any of
the top-level entries above (`config.RESERVED_STATE_NAMES`): a reset of it
would clear them.

**The lifecycle** is forward-only: `pending` -> `reserved` -> `decided` ->
`done`, or `pending` -> `demoted` | `dropped` | `mail` -> `done`, or
`reserved` -> `dropped` | `refused` -> `done`; `decided` -> `refused` only
through a supersession (below). A HOLD is metadata on a record, never a
state: it names why the record cannot move now (`candidate_view_unavailable`,
`admission_closed`, `hook_absent`, `undecided`, `key_runtime_changed`: each
clears on its own; `candidate_view_refused` and `candidate_malformed` only by
`peer-candidate quarantine`; `recovery_corrupt` only by an operator act
(`restore-key` releases every `recovery_corrupt/mac` hold; `drop` exits key
loss); `recipient_gone` is re-tried once the decision's recipient is
configured again, and never attempted while it is not; `unpublishable`, a
statement id or `in_reply_to` the notice-id grammar cannot carry (a leading
`-`), is re-tried at every start and never dropped). A recipient held by its generation is not a hold: the
decided record stays `decided` with a retry note, and the next poll
retries. A terminal disposition and its pending control notice are one
write.

**Order of evaluation** (the peer-origin profile's checks, in order): the
candidate view (`over_cap` is terminal mail; `candidate_json` and
`candidate_schema` hold); no statement field is mail; checks 1-5 through
the verifier, with check 2 against the replay index (an exact replay is
dropped as `duplicate` with no notice and no replay mutation); checks 6-11
with this router's window as check 7 and the check-8 hook; then check 12,
the reservation. A reservation is linked once, MAC'd, and read back before
it is used; another candidate's reservation for the same (runtime, id) is
the collision: `dropped(duplicate)` with a control notice, the prior
untouched. From the reservation on, a record is decided only from its
reservation and snapshot: checks 1-12 are never run again, whatever time it
is, so a reserved record held past P + F is still decided, never demoted.
Hosting, then the reply, edge and policy hooks (each may hold or refuse),
then the decision, then placement.

**Supersession.** A decided record becomes `refused` only through
`supersede.json`, a closed record MAC'd under the decision key that names
the exact bytes of the decision it supersedes, and only for the generation
fence (`generation_retired`) or the operator's drop
(`decision_unrecoverable`). A valid supersession always wins over the
decision; an invalid one holds (`recovery_corrupt`). Before either writes
one, the recorded recipient's notice is looked for under the reservation's
notice id: if it is there the message was placed, and the record is
`done(placed)` with no supersession and no control notice. RESIDUAL: that
check sees only what is in the peer tree now. A notice placed and since
removed reads as never placed; a durable post-placement fact would close
it, and none exists yet.

**Windows, H, the floor and admission** (`peerclock`). A statement's `ts` is
accepted when `max(H - P, floor) <= ts <= now + F`, both bounds inclusive.
H is the latest receiver time ever observed, only ever raised. A wall clock
stepped back below H keeps the window defined: a statement outside it is
demoted, as the profile's clock-rollback case requires, and status shows a
`clock_behind_h` warning. Without a trustworthy bound, nothing is admitted,
in one of two distinct states:

| state | what a poll does with candidates | status |
|---|---|---|
| **H lost or untrusted**: no clock file (including a store never initialised), unreadable, or its witness mismatched | **nothing is taken**: the inbound pass stops before listing any intake, and candidates stay there, untaken (no record, no hold, no disposition) | the pass reports `held: clock_untrusted` |
| **H trusted, admission CLOSED**: a declared restore, live stores holding more than their bookkeeping | each candidate is taken, then **held** by check 7 (`admission_closed`): nothing reserved, demoted or noticed | the record's hold, `admission_closed` |

Only `peer-store init` or `peer-bound` reopens either. A never-initialised
store reads as the first row (the clock is advanced before the store is
read), so `clock_untrusted` on a host that never ran the init means: run it.

**Startup** (`peerjournal.startup`, from `run`, once, under the drain lock):
settle an unfinished store operation, remove record directories without a
record, mark the top take seq vacant if nothing carries it, and compare
every store with its bookkeeping (live count, high-water seq, an
order-independent content sum and a revision total); then repair missing
digest entries and missing settlement markers. If
the live stores hold MORE than the bookkeeping records, the clock file is
older than the stores and its H proves nothing: admission closes. If they
hold LESS (a record, a marker, a root gone or rolled back), the floor rises
to `max(now, H) + Fmax + 1 s`, where Fmax is the largest F ever in force
(900 when that history is lost), and once that floor is persisted the
bookkeeping is rebased to the live stores, so a loss is accounted for once.
An operation caught in flight is accepted only as not applied or as fully
applied to its own target, and anything else is reported. This detects
corruption and rollback; it
is not a defence against a writer of `state_dir`. A rollback of the WHOLE
`state_dir` is undetectable, which is why a restore is declared.

**Retention.** Off unless `delegation.retention.sweep`. Only a `done` record
at or below the settled-through frontier (the highest take seq up to which
every record is settled) is pruned: with its reservation, marker and digest
entry (the digest first) once H > ts + P + F; without a reservation, 30
days after it settled, so a re-presented intake entry is still recognised.
Never while its control notice is unsent, never (for `candidates/`) before
its entry's removal succeeded, and never (for a host intake) while its
tombstone exists.

**Operator runbook.** Each verb takes the drain lock (stop the router
first), prints one JSON line, and appends to the operator audit:

- **First enable of inbound intake**, in this order: stop the router; run
  `router peer-store init --never-admitted`; set `delegation.inbound: true`;
  start. The retention sweep stays off (`retention.sweep` is `false` by
  default, and `true` is refused until the init has run).
- `router peer-store init --never-admitted [--acknowledge-surviving EVIDENCE]`:
  before the first start with inbound intake. Refused over any peer
  artefact, and over placement evidence that survived a wipe (a disposal
  tombstone, or a signed peer notice in any peer tree) unless acknowledged.
- `router peer-store declare-restored --evidence TEXT`: after ANY restore of
  `state_dir`. Admission closes.
- `router peer-bound --at B --evidence TEXT [--b-not-from-wall-clock]`: after
  a lost clock or a declared restore. `--at` has no default. B below any
  receiver time this router can see (record times, audit lines, settlement
  markers, tombstones, H) is refused, naming the source; "now" is never
  evidence; a B within 60 s of the wall clock needs the flag. Then floor =
  max(floor, B + Fmax + 1 s), H = max(H, B, now), the bookkeeping is rebuilt
  from the live stores (the settled-through frontier never lowered), and
  admission opens. A B in the future needs the same flag. THE EVIDENCE IS AN OPERATOR
  ATTESTATION: it is recorded verbatim and nothing verifies it.
- `router peer-decision restore-key --from FILE`: puts the original decision
  key back; refused unless no decision verifies under the current key and
  at least one verifies under the offered one.
- `router peer-candidate quarantine KEY --evidence TEXT`: the exit from a
  candidate held on a view that can never be read (`candidate_view_refused`,
  `candidate_malformed`): `mail` with cause `candidate_view_refused`, then
  its quarantine item (or, for a host intake, its tombstone, by the next
  poll), then `done`, which settles it for the frontier.
- `router peer-decision drop KEY --evidence TEXT`: the exit from key loss
  and nothing else. A decision, or a reservation without one, that no
  longer verifies becomes `refused(policy, decision_unrecoverable)` with a
  control notice pending; a decision whose notice is present becomes
  `done(placed)`. Refused for anything that still verifies, a reserved
  record held on `key_runtime_changed` included (that hold clears when the
  runtime's configuration is restored).

- `router peer-epochs trust --evidence TEXT`: the exit from an untrusted
  epoch store (below). Regular files of the router's own that do not
  validate are removed (once the root and its witness are restored to the
  token the bookkeeping records), in the same bookkept transaction that recounts the
  store from the files that remain; the store is reseeded from decided
  records that passed the consistency step, read strictly
  (`peerjournal.strict_records`: a journal that cannot be read reliably
  reseeds nothing and keeps the flag, naming why); two-file pairs are completed;
  the store is recounted and must equal its bookkeeping; only then is the
  flag cleared, in its own write. Anything else in the epoch root (a
  directory, a link, another owner's file), or a root that is not itself a
  directory, keeps the flag, and the verb names it and exits non-zero. A
  crash anywhere leaves the flag set; run the verb again. The verb adopts
  every valid file that remains, a rolled-back one included: read the
  status `epochs` section and the store's pairs BEFORE running it, and
  remove a file you know to be stale first.

`router reset` never touches any of this: it clears instance state, and
these stores are not an instance's.

**Sender age and the epoch store.** The production profile requires
`sender_exposure` and `sender_since` on every signed task, and refuses a
sender younger than 24 hours by the router's own clock (`quarantined`).
Each (sending runtime, `from`) pair's accepted `sender_since` is kept in
`state_dir/peer-epochs/`, one immutable file per pair, counted in the
store bookkeeping like the journal and the replay index.

- **A lost or rolled-back epoch store HOLDS (fail-closed, decided
  2026-10-14).** Any loss or behind finding for the epoch
  store, any epoch file that does not read back as written, and any
  `declare-restored`, set a durable `epochs_untrusted` flag. While it is
  set, every statement that reaches the consistency step is held
  `epoch_store_unavailable` (its record stays reserved and is decided after
  the trust verb); refusals before that step, and profiles without an age
  policy, are unaffected. Accepting the residual instead (a lost or
  rolled-back pair accepting an earlier `sender_since` once) was considered
  and rejected.
- **`exposure_missing` may advance the epoch.** The consistency step runs
  before the exposure requirement, so a statement refused for a missing
  exposure still records a later `sender_since`. That only lengthens the
  sender's own wait.
- **An over-late `sender_since` sticks.** One statement carrying a
  `sender_since` later than the sender's real enrolment makes every later
  statement from that pair refuse as `sender_since_inconsistent` until the
  sender re-enrols with a later value.

**Status** (`peer_store`, with `delegation` only): admission and why, H, the
floor, the warnings, the bound B (its evidence cut to 80 characters), the
take seq and the settled-through frontier, every held record and transient
retry with its key, reason and age, whether inbound intake is on, and the
last poll's counts. Its `epochs` section: the tracked pairs, pairs caught
mid-prune, `untrusted`, and, counted since this process started, the
policy refusals by code, the `exposure_signer` demotions and the
`epoch_store_unavailable` holds.

## The ingress journal (`router/ingress.py`)

Inbound from the external leg arrives through the plugin's intake reader
(`hoplink.reader_for`, one per identity and generation) and goes through
ONE durable journal record per entry, per kind, per generation:
`state_dir/<logical_id>/gen-<g>/ingress/<kind>/<key>.json`, the key the
sha256 of the canonical `{kind, link, gen, entry_id}`. The entry id is
opaque and never a path component.

**Inbound is OFF without `hop.link`.** With it, each generation PINS the
link at its first inbound use (`ingress/link.json`), and every later pump
compares the config against the pin before listing anything. A difference
latches that generation's inbound off with one ERROR: the link is inside
every key, so a changed value must never re-key (re-keying would place
entries again). To change the link, begin a new generation.

**The order, per generation, per poll, under the drain lock**: recovery of
`placing` and `prepared` records first; one listing page; then for each
listed id the key lookup BEFORE any read (a placed or quarantined key is a
duplicate, compared whole-bundle with its snapshot and never placed or
quarantined again); the read (`notice_incomplete` held;
`notice_invalid` on first sight QUARANTINED); the
bundle and the facts checked as hostile input (this router's own check is
additional to the reader's and verdict-identical with it); a generation
no longer current gets `late_inbound`; the recipient cross-check (the
tree binds the entry to this identity, and mail whose named To/Cc
recipients resolve only to ANOTHER identity, by name or through an active
alias, is held `recipient_not_this_identity`; an address resolving to
nobody, as for a Bcc'd or list-delivered recipient or a truncated header,
never refuses); the admission order; then snapshot, `prepared` and
placement.

**The admission order.** The INTEGRITY rows come first, for every class: a
`fleet_hosts` admission over another ingress (`admission_inconsistent`, not
reachable while the codec's ingress enum is `hub`) and an `admission_link`
that is not this reader's link (`admission_link_mismatch`). Then the two
classes that pre-empt the COLD rows, and only those: a failure report, and a
reply. Then the cold rows: `open` admission held `admission_not_placeable`,
a trusted fleet host quarantined `cold_fleet_mail`, an unknown host held
`unknown_host`. Untrusted fleet mail is placed.

**Failure reports and replies are believed only against this router's own
records.** The downstream runtime correlates each to one of this router's
outbound transactions; it counts only when this router's own record
agrees: the same identity, one of its generations (fenced ones included:
authorising a reply survives a rebind; delivering pending work does not, so
an entry read through a fenced tree is still `late_inbound`), the link that
generation is PINNED to, and a transaction this router SENT (a settled
anchor, or an in-flight record that was handed over; a record never handed
over matches nothing). Addresses compare in one canonical form (the domain
lowercased, the local part exact).
- A FAILURE REPORT whose every reported recipient is one this router sent
  to places ONE notice, authored by this router alone (from
  `amap.router@<fleet_domain>`, ledgered `authored_by: "router"` so a reply
  to it fails closed; no text from the report, the failed message or what
  the downstream runtime wrote), listing per recipient the RECORDED address,
  the action and the status code with a local description, plus the
  agent's req_id and the transport id, threaded to the sent message's
  Message-ID. It lists only the (transaction, recipient, action) pairs not
  announced before: each pair is RESERVED durably
  (`state_dir/<logical_id>/failure-seen/`) before anything is prepared, and
  a report with nothing new is `suppressed_waiting_remove`, removed upstream
  like any other entry, then `suppressed_complete` (a tombstone). A
  reservation counts as announced while its owner can still place or may
  have placed (including `placing_ambiguous`: at most once); it is released
  when its owner was quarantined, ended terminally without ever placing, or
  is gone; an owner that cannot be read decides nothing that pump
  (`failure_reservations_undecided` in the last pump's counts). Reservations
  are swept with the tombstones, past the same `ingress_dedup_horizon_days`.
  A residual, in the duplicate-safe direction: a report suppressed because
  its pair's owner was still `prepared` stays suppressed if that owner later
  goes `late_inbound` (and so releases the pair); the pair is announced only
  if a further report arrives.
  A report that does not match is held `failure_unmatched` and re-checked
  from its snapshot every pump, since this router's record of the send may
  land after the report.
- A REPLY whose sender is one this router sent to, and whose correlated
  Message-ID is the one it recorded, is placed threaded to that send. One
  that does not match is classified exactly as mail without the
  correlation: never widened.

**Every placed hop mail carries a reply binding** in its ledger record: the
recipient's logical_id, the canonical sender (`counterparty`), where it came
from (`origin_notice_id`, `origin_link`, `origin_logical_id`,
`origin_generation`), how it was admitted (`admission`, `admission_link`,
`admission_rule`, never backfilled), `received_at` and `expires_at` (fixed
when the entry is prepared, from `mail_reply_window_seconds`). A record
without them never resolves as a binding across the external leg.

**Bound replies over the hop.** A reply whose `in_reply_to` names such a
record is decided before the trusted-host rule and before any cold
classification, and handed back over the hop as kind `"bound_reply"`:

- It binds ONLY when the record is mail (its `tree` is the inbox tree),
  carries the binding members, its agent is the replying instance's
  logical_id, and it has not expired. Otherwise
  `rejected`/`unresolved_reply`. A bare id lookup is never enough.
- The recipient is the record's `counterparty`. The draft's `to`, `cc` and
  `bcc` are discarded (logged as a count, never echoed).
- The counterparty must be a fleet host under this router's own classifier
  (`fleet_hosts`, trusted or not: a trusted host's counterparty still gets
  a bound reply, never the peer path); anything else is
  `rejected`/`no_route`, "no reply path to this counterparty in this
  deployment", with nothing allocated.
- An `open` admission (also what an absent one means, written explicitly)
  is decided by egress, as mail to a fleet host is: `remote_fleet`, or a
  custom cold policy, whose only possible answers are a refusal or a
  hand-over of the counterparty (anything else, the peer lane included, is
  `transport_anomaly`). A trusted host is never re-classified as a peer
  task; `remote_fleet` cannot name one, so by default it is
  `queued_for_human`/`recipient_not_allowlisted`. `fleet_hosts` and
  `inbound_allowlist` are permitted by the binding, and egress is not
  consulted.
- The envelope's `bound` is `{bound_address, origin_notice_id, origin_link,
  origin_generation, participants: {agent, counterparty}, admission,
  admission_link, admission_rule, policy_digest}`, with `bound_address`
  equal to the counterparty exactly. `policy_digest` is the sender's mail
  policy digest for `open`, and for the other two that policy with the
  binding added. The binding and the `bound` are PINNED in the in-flight
  record at begin, and every hand-over carries the record's, byte for byte.
- At every publication attempt and every pending poll, the re-check asks
  whether the ledger record is still there with every pinned member
  unchanged, the agent is still this instance's, the counterparty is still a
  fleet host (trusted or not), and (for `open`) egress still permits it. Expiry is NOT
  re-evaluated after begin. A failure is `queued_for_human`/
  `recipient_not_allowlisted`, never a send and never `rejected`.
- A bound reply whose handover could exceed the hop's document cap (the
  config-time floor is sized for a mail envelope) is `rejected`/
  `malformed_request` before anything is allocated.

`delivered_domains_file`, when set, is read at load: no symlink, a regular
file owned by root or this process and not writable by group or others,
outside every agent-reachable root, at most 1 MiB. Its shape is
`{"delivered_domains": [...], "sha256": ..., "attestation": {...}}`, where
`sha256` is the hex digest of the domains lowercased, sorted, each followed
by a newline, and `attestation` is not read. PROVISIONAL: the deployment's
layout for it is not yet frozen. A hash that does not match refuses the
config. A set that differs from `fleet_hosts` does NOT: an ERROR names the
two difference counts (never the domains), every bound reply is held
unconsumed, a bound reply already in flight is refused at publication, and
mail is unaffected. Absent, nothing changes. The file is read when the
config is loaded, so a change to it takes effect on the next reload or
restart only.

**A read that decides nothing, again** (the runtime's own refusal class, or
an OSError from the reader) is kept per journal key with its first sighting
and logged on every pump: a WARNING while young, an ERROR once it has
persisted an hour; and counted
in status (`read_refusals`: a count, the oldest age and the reasons; the
upstream entry id is in the log only, never in status).

**The guarantee: AT MOST ONCE per upstream entry id.** At most one
agent-visible notice is ever placed for an entry id. Placement writes the
RECORDED bytes (minted identity, digests journaled at `prepared`) through
`deliver`'s commit routine, after a generation check immediately before the
first byte. It rests on the ledger row being durable before the notice is
committed, which `deliver._commit` guarantees. A crash between the ledger
write and the notice, with no delivery evidence, is a TERMINAL, VISIBLE hold
(`placing_ambiguous`), delivered to nobody until an operator acts. It is
per entry id, never per message: two ids for one message are two entries.
No ledger row of a record in `placing` or `placing_ambiguous` is ever
pruned (nothing in this repository prunes the binding ledger).

**Removal and the dedup horizon.** The plugin's remover is an optional
capability (`make_intake_remover`, at `PLUGIN_API` (3, 1)). When the loaded
plugin offers it, a placed or quarantined entry's record (`*_waiting_remove`)
is removed through it and becomes its TOMBSTONE on `removed` or `absent`;
any other outcome leaves it waiting, with its reason (a retry is always safe)
and status shows the remover `available`, or `held` with the construction
failure. When it is not offered (`not_offered`), the record waits and
becomes its tombstone only when the horizon has passed AND the reader
reports the entry gone; a tombstone still dedups (a re-publication is a
duplicate, never placed again) and is dropped only after another horizon.
A held record is never dropped. `ingress_dedup_horizon_days` (default 30,
1-3650) is the horizon, and it MUST EXCEED THE LONGEST TIME THE
DOWNSTREAM RUNTIME CAN BE DOWN AFTER A CRASH. A first-seen entry whose
spool date predates it logs `hop_republished_after_horizon` (a WARNING,
best-effort; it is still placed).

**Residuals, stated and accepted with the guarantee**: the dedup horizon
must exceed the longest time the downstream runtime can be down after a
crash, or ONE duplicate placement is possible (never a loss); and a mailbox
UIDVALIDITY reset upstream mints new ids, so each message still present is
placed once more, visibly, in the duplicate direction.

**Holds.** A re-read hold (`notice_incomplete`, `bundle_schema`,
`entry_id_mismatch`, `bundle_invalid`) takes no snapshot and is read again
every pump. A snapshot hold (the admission holds,
`recipient_not_this_identity` and `failure_unmatched`) is re-evaluated from
what was READ and never re-read. The TERMINAL holds are never re-evaluated by a pump:
`placing_ambiguous`, `placing_survivor_mismatch`, `exists_different`,
`snapshot_invalid:<what>`, `quarantine_item_conflict`,
`duplicate_different_held`, and `notice_invalid` on an entry that already
had a record. The operator verbs that release them are OWED by the first
unit that adds ingress verbs; they must also cover
`recipient_not_this_identity` and `failure_unmatched`, and the verb that releases
`placing_ambiguous` MUST warn that releasing is AT-LEAST-ONCE: it may
deliver a notice the agent already consumed.

## The ingress quarantine (`router/quarantine.py`)

Cross-host inbound that is not placed is held in the generation it arrived
for, at `state_dir/<logical_id>/gen-<g>/ingress-quarantine/<id>.json`. This
router FREEZES the item format and inspects it read-only (`quarantine`); the
writer is `ingress.write_quarantine_item`, which checks each item against
those rules before writing it, one item per journal key, create-if-absent.
The expiry sweep is `ingress.sweep_quarantine`: after each generation's
inbound pass it removes the well-formed items older than
`ingress_quarantine_days`, logging each sweep that removed any, and keeps a
damaged item for the operator.

An item has exactly `schema` (`amap-router-local.ingress-quarantine/1`),
`id` (32 hex, the filename stem), `generation` (32 hex, the directory's),
`arrival_ts`, `causes` (non-empty, no duplicates, from a closed
vocabulary: `cold_fleet_mail`, `late_inbound` (an entry for a fenced or
retired generation, held there) and `notice_invalid` (an entry the
transport's reader refused as invalid on first sight) today; the peer-origin profile's §5 causes
are added once the revision defining them is published) and
`evidence` (at most 32 members; keys 1-64 printable ASCII; values strings of
at most 1024 characters or integers, never booleans, of magnitude below
2^53; at most 16 KiB). Evidence is hostile input and is printed
JSON-escaped, never raw. An item file is at most 64 KiB, read without
following a link, regular, with one link; anything that fails a rule,
including an `arrival_ts` more than 300 s in the future, is listed as
DAMAGED with the reason and never hidden, and its content is never printed.

```
router quarantine list [NAME]              one line per item: NAME SOURCE GEN ID, age, expiry, causes
router quarantine show NAME SOURCE GEN ID  one item as escaped JSON
```

SOURCE is `ingress`, `control` or `unresolved`. `.unresolved/` entries
(candidates with no live tree) are listed exactly like `.control/` ones, from
`<hop.root>/.unresolved/`, keyed `- unresolved - ID`, under the same
threshold. An entry of either intake that this router has DISPOSED of (its
disposal tombstone exists under `<hop.root>/.disposed/<intake>/<ID>`, a
regular file of this router's at one link, at most 0640, naming that intake,
ID and the candidate's digest) is listed `disposed` and never counted as an
item or as expired: it waits only for its owner's removal. `.control/` entries (candidates another
runtime writes) are listed from `<hop.root>/.control/` whenever `hop` is
configured (no key of its own, so it can never disagree with the hop root;
`--control-dir` names it only for a router WITHOUT `hop`, and is refused
beside it), keyed `- control - ID` with ID the candidate's 32-hex directory
name, METADATA ONLY (the `candidate.json` size, sha256 and mtime) until the
inbound step freezes their format. They are the downstream runtime's
(2750, its own): this router lists and reads them and never removes one. An
entry older than `ingress_quarantine_days` is REPORTED `expired`; that is
this router's report threshold, and the downstream runtime, which owns the
sweep, never removes an entry sooner. The ingress status counts them
(`control` and `unresolved`: items, expired, in flight, damaged, disposed and
pending removal, the oldest age and the threshold). A `candidate.json` caught
mid-commit (exactly two links) is listed IN FLIGHT, not DAMAGED. Its writer
commits `candidate.json` LAST, so a directory without one is not yet an item:
listed IN FLIGHT ("no committed candidate.json yet"), and nothing in it is
read. `.stage` is the writer's own stage and is not listed. Nothing is moved or written, and
the registry is read without recording its seq. Retention is
`ingress_quarantine_days` (default 14, 1-365). `status` reports a count per
agent under a registry.

## The one clock (`router/clock.py`)

Every wall-clock read in the package is `clock.now()`, an aware UTC datetime;
`util.utc_ts()` formats it. `router/tests/test_one_clock.py` holds every other
module to that: direct, aliased, re-exported (resolved through this package's
own imports), reflective, `sys.modules`, star-imported and import-time reads
all fail it, within the limits its docstring states (a read hidden behind an
allowed helper, or a cache decorator over one). Exactly one other time source is allowed: `hoplink._clock`
(`time.monotonic`), whose consumers are status ages and retry log levels,
never a decision. A time passed in as data (a statement's `ts`, a record's
`recorded_ts`, an operator's bound) and a file time (`st_mtime`, stamped by the
kernel) are not clock reads.

Tests and conformance drivers may `clock.install(source, strict=True)` a
callable that returns an aware datetime (`clock.fixed`, `clock.Stepper`), and
every read then returns it. Strict means a read with the source gone raises
`ClockNotInstalled` instead of falling back to real time. The source is
environment, not process state: it survives `hoplink.reset_process_state()`,
which models a restart, and only `clock.reset()` clears it. Nothing in the
router installs one, and no config key, environment variable or CLI flag
reaches it.

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

## The runtime control tree (`router/peercontrol.py`)

Control notices go out through the router's own runtime tree,
`<hop_root>/.runtime/<generation>/`, which this router reaches ONLY through
the plugin's runtime capability (PLUGIN_API (3, 5): `make_runtime_sender`
and `make_runtime_lister`, named in one table, `transport.RUNTIME_CAPABILITY`).
A plugin that does not declare both factories leaves the capability off, and
every control notice is held `runtime_tree_unavailable`.

- **One recorded generation** (`state_dir/_runtime/generation.json`, with its
  pin beside its in-flight state): minted when the lister shows nothing live
  or unreadable, never beside another live one.
- **Admission is explicit.** Before the first call of any transport method
  in a generation, on every pass, the router calls `admit(admitted_at)` with
  the generation's own recorded time, which is stable on every path: a fresh
  mint's own time; the tree's identity for an adopt or for the automatic
  restore of a listed live generation; the restore's own time, once, for a
  generation never admitted; the plan's time for `new`. A record and pin
  that disagree, or a tree whose identity carries another time
  (`exists_different`), hold visibly and are never re-admitted.
- **The sender's settings** are the plugin's closed list: the hop root, the
  generation, the peer uid, the router's own address (one canonical,
  lowercase `amap.router@<fleet_domain>`, the same bytes on every surface
  that names this router), `version_write` from the generation's pin, and
  `caps` from `hop.caps`.
- **A retired generation.** The plugin refuses a NEW request in a retired
  generation (`generation_retired`) only when no part of it exists in the
  tree; the router settles that attempt `rejected` with reason
  `generation_retired` (counted as failed, never retried, re-signed or handed
  over again) and removes its in-flight record. The settling row is asked
  before the latched and retried rows. Anywhere before the hand-over, a
  retired or unreadable generation holds the attempt instead.
- **Every plugin anomaly** (a misowned tree, a stray entry, an unreadable
  identity) holds as `runtime_tree_unavailable`, naming it, on every path,
  the verbs included.

**Operator verbs** (each takes the drain lock, is audited intent-first, and
prints one JSON line):

- `router runtime-generation adopt GEN --evidence TEXT`: the only live
  generation becomes the recorded one again, with the tree's own admitted
  time.
- `router runtime-generation retire GEN --evidence TEXT`: refused while
  anything of `GEN` is unsettled, and refused for an unreadable generation.
- `router runtime-generation new --evidence TEXT`: retire the recorded
  generation, then mint, as one durable plan; refused before the plan when
  either step would be.
- `router runtime-generation abandon-attempt KEY --evidence TEXT`: end a
  frozen control attempt whose generation can be neither restored nor
  adopted; reads only the lister.
- `router runtime-generation abandon-plan --evidence TEXT`: end a verb's plan
  that cannot complete, auditing what it committed.

A frozen attempt's lost generation record is restored automatically, and
audited, only when its generation is the sole live one, or was never
admitted while no other generation is live or unreadable; nothing is minted
while such an attempt is held. These verbs and the restore rule are final.

**While the peer clock is untrusted these guards refuse rather than pass.**
A frozen attempt, and traffic in an unlisted generation, are read from the
journal, and the journal is readable only under a trusted clock: read
without one it is empty, which would pass every such check vacuously. So
`retire` and `new` are refused ("recover the clock first"), the drain mints
nothing (the runtime tree is unavailable, with the same reason), a lost
record is not restored into a generation that was never listed, and a
pending `new` plan's mint stays pending. The same holds when the clock
verifies but its store bookkeeping is unreadable, or ABSENT while a journal
is on disk: a clock rebuilt by a bound before its bookkeeping (`router
peer-bound` does both) is trusted, and these guards still refuse until the
bookkeeping is rebuilt. The guards read every record on disk, under every
owner, and refuse on one they cannot read or that is not a record, on a
record directory without its record, and on a journal root that is missing
or does not match its bookkeeping (the comparison startup's reconcile
makes, read only), where a plain journal read would skip each of them. Only a router that never journaled anything (no journal
directory, and the clock absent or holding no store) is not blocked.

### Runtime tree repair

- **An unreadable generation** stops sending in it. The plugin never deletes
  a generation and its `retire` refuses one whose identity cannot be read, so
  adopt, retire and abandon cannot act on it: the operator repairs the tree
  out of band, as the transport plugin's operator notes describe for its own
  tree, then retries. Status lists unreadable generations with this exit.
- **A stray entry in `.runtime/`** makes the whole listing fail; status
  names it, and the operator removes it.
- **An address change** makes the existing generation's admission
  `exists_different`: once in-flight attempts settle, `runtime-generation
  new` rotates to a generation admitted with the new address.
- **`.adm-<generation>-*` directories** are crashed admissions' stages: inert,
  never listed; the operator may remove one once no router runs `admit` for
  that generation.

### Testing against the plugin

The suite runs against an in-repository stand-in of the capability. The real
plugin's rows run in `router/tests/run_realhop.py --plugin <file>`: adopt,
retire, new, both restores, abandon-attempt, abandon-plan, the
`generation_retired` settlement and the hold before any hand-over, and the
crash and exactly-once audit seams, against the real runtime sender and
lister over this router's real filesystem port; and one resend row
(`peer_block_republished_under_new_n`): a signed peer task handed over
through the real AGENT sender, then retransmitted under a new transport id,
the hub publishing the identical peer block both times. The file must hash to the
pinned artifact digest (`ARTIFACT_SHA256`); without it the run is refused,
never skipped. Its evidence is a recorded run with the plugin file's
sha256, not continuous integration, which has no copy of the plugin.

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
operator removes the seq FILE, `state_dir/registry/seq`, and nothing else
under `state_dir/registry/` (which also holds the alias store's floor,
witness and audit log, below); the next poll accepts the snapshot's `seq` as
the new floor.

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

Each version-1 conversion's outcome is checked against the record it
describes before `complete`, and again whenever a run resumes at
`complete`. So an operator who repairs or replaces a pending record between
a crash and the resume gets a refusal naming that record (the instance stays
held) rather than a migration that attests something the record no longer
shows.

**Rolling back past this version is not supported.** The last step before a
migration completes leaves a DIRECTORY named `first-seen.json` where the
legacy marker was. An older router run against the migrated layout fails at
its first statement, before listing or delivering anything, instead of
taking a fresh first sight and restarting the transport counter. `reset`
leaves it, and the journal, in place.

### Aliases

Under a registry, the router config may carry an alias table (contract
§2.3): `"aliases": [{"old": ..., "new": ..., "expires": ...}]`. `old` is an
exact address (an ASCII name as its local part, a lowercase domain); `new`
is an identity's canonical `<name>@<fleet_domain>`; `expires` a UTC
timestamp. The loader refuses a table without a registry, a `new` outside
the fleet's domain, a duplicate `old`, a chain (a `new` that is some `old`),
a reserved local part, and a same-domain `old` that is a case or confusable
variant of its own target. An instance named `aliases` is now a load error:
`state_dir/aliases/` is the store. `old`'s domain is not restricted: an entry
the operator writes can make an address that looks external deliver locally.
The table is operator-owned configuration, so that is the operator's choice,
stated here rather than prevented.

**Every poll decides each entry, before anything drains.** ACTIVE: not
expired, not tombstoned, its target a known identity (resolved, or held by
the registry, in which case the delivery holds exactly as a direct address
would), `old`'s local part in that identity's registry name history (whose
last element must be its current name), and `old` no other identity's
current name by skeleton, and no other identity in the registry (served here
or not, retired or not) having had `old`'s local part as a name, compared by
skeleton (its name history, or its current name when it records none): a
name reused by another identity never retargets an alias. An unreadable name
history ANYWHERE in the registry holds every alias, which is fail-closed and
broad, deliberately: it cannot be shown that the unreadable one never held
the name. INACTIVE, deterministically, otherwise: a request
naming an inactive alias is answered `rejected` / `recipient_unknown` right
there, before any policy sees it. Matching is exact: the local part as
written, the domain lowercased, so a case variant is not the alias.
UNVERIFIABLE when the store cannot be trusted, the target's name history is
malformed, or the registry cannot be read: the request is NOT consumed. It
stays in the outbox, is retried every poll, and is listed in `status.json`
under `aliases.held` with the reason, its age (from a marker the drain
writes, bound to the request's digest; it restarts in a new generation) and
the remedy. One unverifiable address holds the whole request, even beside an
inactive one.

**What aliases change.** Only the evaluated copy of `draft.to` and
`draft.cc`, before classification and policy; every use logs a WARNING. The
request's bytes, its snapshot and its digest are never rewritten. An alias
names only a LOCAL identity, so a request in which an alias was applied
never takes the external leg: a policy that routes it there is answered
`queued_for_human` / `transport_anomaly` ("alias-normalised recipients
cannot take the external leg; nothing was sent") before anything is staged.
Pending work pins the aliases it used (`aliases` in the record, with each
target's `address`; a record with any is version 3, which an older router
holds as damaged rather than misread): a later expiry or table edit never
retargets or refuses it, and a target rebound since holds as
`identity_changed`. Pinned work keeps its pin-time target across a §2.4
domain flip too (each pinned address maps to that target's address in the new
domain). A pending draft that named its target in a different letter case
than the pinned address is refused after a flip rather than guessed at. So
drain pending work before a flip if the old addresses must stop working at
once.

**Expiry and tombstones.** At or after `expires` an alias is inactive
whatever else happened. The poll's pre-pass then writes its tombstone to
`state_dir/aliases/tombstones.json`, so that re-listing it can never revive
it: a tombstoned address stays unusable even with a new `expires`. A failed
tombstone write is logged at ERROR, shown as
`aliases.store.tombstone_errors` with the time the drain first saw it fail and
its age (kept by the running router, so a restart starts the age again),
retried every poll, and never stops anything else.

**The store is checked against a floor and a witness** kept outside it, in
`state_dir/registry/`: `aliases.floor` (the highest seq ever written) and
`aliases.created` (written LAST at first initialisation, after the store,
the floor and a durable audit line in `state_dir/registry/aliases.audit.jsonl`).
Only the empty first store, a missing floor or witness of that store, or a
floor one behind its store is recovered, and only by the drain's pre-pass;
every other combination (a store below its floor, a lost store, a foreign
entry in `aliases/`, anything unreadable) is unverified. Losing or restoring
everything at once looks like a first start: that residual is the same as
the registry floor's.

**`router aliases reinit --reason TEXT [--dry-run]`** is the way out of an
unverified store, with the router stopped. It writes a fresh store that
tombstones EVERY configured alias, plus every address the audit log records
as tombstoned and every tombstone of a store that can still be read (trusted
or not), at a seq above anything seen, and audits it. **reinit
permanently retires every configured alias; tombstoned addresses can never
be re-enabled.** Nothing is taken as proof that an alias was still active,
because a store can commit a tombstone and lose it before its audit line.
The residual it cannot close: a tombstone lost with the store, for an alias
since removed from the config.

**Not yet built** (later steps): the hop To and the `to` of a signed
statement are normalised downstream, not here.

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

**Every direct placement uses the same record, as its intent.** Cold mail to
local recipients, a bound reply and a peer route write the pending record
(marked `"origin": "direct"`) before anything is placed, with or without a
registry, and place through it with the pre-minted identity. The private
anchor is written only after placement; if that write (or anything after the
placement) fails, the request stays in `outbound/`, and the next poll finds
the record and answers from it without placing again, instead of minting a
second notice id. Two things differ from a held record: a delivery failure
that is not a hold fails that target at once (the commit writes the notice
last, so a raise means no notice was placed), exactly as the direct paths
always answered; and the record is removed once the request is answered.
The one raise that does not mean "nothing placed" is a failed barrier AFTER
a file was renamed into place (`attachments.PublishedNotDurable`): the
notice may be visible, so that target stays `delivering` and is replayed
with the same identity, never failed.

**Every agent-visible write is durable.** Sidecars, the message spool and
the notice are each fsynced before they are renamed into place and their
directory after, and every directory on the way is made durable in its
parent; a failed barrier raises. So the commit order (blobs, spool, ledger,
notice LAST) holds on disk across a power loss, not only across a process
crash, and the private record can never say "delivered" over a notice the
disk lost: a power loss lands in the re-presentation residual below. An
injected backend that cannot take the `preset` and `from_address` keywords is
called directly, as before, and keeps the old exposure: a failure after its
placement can place again under a new id.

The outbox Result follows the same rule. It is written through the same
barriers, and one whose directory barrier failed (`PublishedNotDurable`) is
visible but not yet durable, so the request is NOT archived: the next
listing finds its private result and re-publishes the Result from it
(nothing is delivered or handed over again), and only then archives it. The
archive rename is followed by a barrier on `processed/` and then on the
outbox; the rename has happened by then, so a failure of either is logged
and not retried, and the private result stays the authority.

Residuals of that rule:
- A barrier that keeps failing keeps the request unarchived: its Result is
  re-published (the same bytes, from the private result) and a WARNING
  logged on every poll until the barrier succeeds.
- While the request is unarchived, the agent can still replace the file
  under that req_id. The next listing then refuses the new file as
  `req_id_reused`, and that refusal overwrites the visible Result; the
  original verdict survives only in the private result.
- A `req_id_reused` refusal has no private result of its own. After a
  failed barrier it is issued again on the next listing: the same outcome
  and reason with a new `ts`, so different bytes. Its status count can
  include the repeat.
- A Result write that fails BEFORE its rename (nothing was published) is
  logged and the request is archived anyway, with no Result in the outbox:
  the private result is the answer, as it was before this rule.

A crash after the notice write but before the "delivered" mark replays with
the SAME id. If the agent consumed the notice in that window, it reappears
with the same notice_id. That is a re-presentation, not a second notice.
Whether a connector dedups by notice_id is unspecified in the draft, so this
router does not claim exactly-once delivery to the agent.

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
