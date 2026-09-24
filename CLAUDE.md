# CLAUDE.md — amap-router-local

## What this repo is

The **runtime** half of the Agent Mailbox Access Protocol seam — "Body 2" in the
family's role taxonomy. *Body names a ROLE relative to the trust boundary, not
a repository*: this repo is one of several runtimes, and the role is what it
shares with them, not a package identity.

It is a **trusted mail runtime that carries no mail**. It moves AMAP artifacts
between agent namespaces on one machine: no provider, no credentials, no
network, no SMTP, no IMAP. What is left when you strip those away is exactly
the obligations AMAP places on a runtime, which is the point — see `README.md`
"Why this exists".

Second job, equally load-bearing: it is **the policy core other AMAP runtimes
import**. `pyproject.toml` says why at the top — `binding.py` calls itself "the
security core: recipient resolution", and two copies of a mutual-allowlist
check drift silently while both suites stay green. If you are tempted to
reimplement something here in a sibling runtime, don't; import it.

## What this repo is NOT

- **Not a connector.** The connector is the untrusted half, runs inside the
  agent's sandbox, holds no credentials. Different repo.
- **Not a mail server.** No transport; it cannot reach a network.
- **Not multi-host.** Every namespace is a local directory. Out of scope by
  design, not omission.
- **Not a deployment.** Installing a connector into sandboxes, wiring a fleet,
  mounting volumes — that belongs to the *host adapter* and *provider
  deployment* repos, which are organized by host system and by mail provider
  respectively. Neither is a body. This repo owns the runtime and nothing else.

## Publication

Released under Apache 2.0, at `proofpoint/amap-router-local`, currently
PRIVATE. Three things still need a decision each time, and none of them is
implied by the repo being releasable:

- **Other repositories in the family.** The release decision named this repo
  and the connector. It is not family-wide, and in particular it does not
  cover the sandy adapter.
- **Going public.** Public is a separate, explicit decision and a one-way
  door — a private org repo is not a rehearsal for it.
- **Whatever is in the history.** A decision to release the CODE is not a
  finding about what the commits contain. This repository's fixtures once
  carried live workspace path-hashes from a developer machine: a slug is
  `<name>-<8 hex>` and the hash identifies a real workspace whatever name
  precedes it, so renaming the word in front sanitises nothing.
  `router/tests/test_no_live_identifiers.py` is the tripwire for that, and it
  is a tripwire rather than a certificate — read its docstring before trusting
  a green run. Check tree AND history before anything leaves for a new
  remote: a clean tree over a dirty history is the failure that looks
  remediated and is not.

## Running it

```sh
python3 -m router --config <config.json> run --interval 5   # drain forever
python3 -m router --config <config.json> once               # drain once, exit
python3 -m router --config <config.json> peers              # review artifact
python3 -m router --config <config.json> status
```

Full subcommand list: `once run peers matrix status provision reset`.

There is **no operator gate before the first drain**. The deliberate human act
is ENROLMENT — putting the instance in this config — which is upstream of the
router seeing the root at all. What the first poll does instead is take a
**first-sight snapshot** of every `req-*.json` already in the outbox and never
deliver any of them (`router/firstsight.py`). `approve` was retired; the
snapshot it used to take is the whole of the protection and is unchanged.

`router/README.md` (~51 KB) is the package's real reference doc — config shape,
deployment postures, the peer lane, attachment transport, the reason-code
vocabulary. Read the section you need there before asking anything about
behaviour.

## Tests

```sh
python3 -m pytest router/tests -q
```

**667 tests, ~3 s** (measured 2026-09-24). No docker and no network:
`router/tests/test_docker.py` pins properties of `docker/` by *reading* it —
it never builds an image.

**Counts in this file go stale; measure before quoting one.** Every count this
section has carried was wrong by the time anyone read it, and nothing fails
when they are — "636 tests", then "637", and "6 modules" for the
spec-dependent set, each true for about a day.

But **not** "no fixtures outside the repo" — that claim was here and was
wrong. Some tests need a sibling spec checkout (`amap-spec`, formerly
`agent-mailbox-protocol`), and on a bare clone they report **1 failure + 34
errors**, spread over **7 modules**: `test_attachments_outbound`,
`test_happy_path`, `test_outcomes`, `test_peer_fixtures`, `test_peer_routing`,
`test_roster_conformance`, `test_validate_fixtures` (the failure is
`test_all_request_fixtures`, deterministically). That is correct behaviour,
not breakage: `helpers._spec_root()` returns a path that does not exist rather
than `None` precisely so the conformance tests fail loudly instead of
skipping. The rule comes from a probe found guarded by a `skipTest`: it **did
not fail, it stopped running**, and the suite went on reporting green without
it. Resolving the checkout is the fix; tolerating the skip is not. Point
`$AMAP_SPEC_REPO` at a checkout, or put one beside this repo, and they run.

**CI runs the FULL suite, since 2026-09-24**, because `proofpoint/amap-spec`
went public and the workflow's spec checkout stopped failing. Nobody edited
the workflow for that: it branches on whether the fixtures are present, and
the phase-1 branch — hold back the spec-dependent modules, emit a `::warning`
naming them — is still there as the fallback if the checkout ever fails
again. Its `skip` list still names the ORIGINAL six modules, not
`test_roster_conformance`, and that is the workflow's stated design rather
than an oversight: a new conformance module is not in `skip`, so under the
fallback it runs and goes red, because the alternative is silently widening
the gap.

**The full suite in CI exposed a flaky test that phase 1 had been hiding.**
`test_attachments_outbound.py::TestOutboundSidecarTOCTOU` — the live-race
harness — fails intermittently: 6–8 runs in 30 on one host, on two failure
sites (the control probe's assertion, and `_reset_side_dir`'s "could not
stabilize ... against the racing attacker", which also takes
`test_live_race_separate_process_secret_never_leaks` with it). Pre-existing:
the same rate was measured on the commit before the most recent feature. It
is **OWED**, and the framing of the fix is "what is the control actually
proving", not "make it flake less" — a probe that needs more attempts may be
reporting that the window it guards has narrowed. Until it is fixed, a red CI
run needs its failing test NAMED before anyone concludes a change broke
something.

**Install editable, always: `pip install -e .`** A copy install puts a second
router under `site-packages` and makes "which copy is running" ambiguous.
`pytest --pyargs router.tests` works under an editable install and fails at
*collection* under a copy install (`test_docker.py` resolves the repo root via
`Path(__file__).parents[2]`). That is the rule enforcing itself, loudly, and it
is the failure mode to want.

## Conventions a newcomer would otherwise violate

### Mutation testing — a test that cannot fail is worse than none

Every guard you add gets proved: **break it in the source, watch the NAMED test
go red, restore it.** Not "the suite went red" — the specific test that claims
to cover it.

Worked example. `test_declared_key_needs_validator` asserted only that
*some* `ConfigError` was raised. Delete the guard it names and
`validate_extra(...)` raises `TypeError`, which the per-key wrapper converts
into a `ConfigError` anyway — **the whole 270-test suite stayed green with the
guard gone.** The fix moved the assertion to the declaration-time path, which
is reachable only through the guard. The sharpest line in the family came out
of that episode: the implementer's own report said the mutation went red
only when the guard *and* the pass-through were mutated together — *that
workaround was the tell*, and it is why "I proved my mutation" is worth less
than someone else choosing the mutation.

**That example was once cited by commit hash, and the hash died.** A history
rewrite renamed every commit, and the instruction to a new contributor became a
command that returned nothing. The citation had been to the wrong thing: a
worked example teaching a convention should name its CONTENT — the test, the
mutation, the assertion that went red — because a hash names a moment in one
repo's history and the example is meant to outlive it. Everything above this
paragraph is that content, which is why it survived the rename and the hash did
not.

**Cite a commit by hash only where the hash is the point**, and expect that to
be almost never. The rule is sharper across repos: a sibling's hash dies on
THEIR rewrite and nobody tells you, so a cross-repo citation should name the
rule or the title it refers to and never the seven characters.

A mutation verified while writing this file, as a live demonstration: disabling
the lane-disjointness guard at the end of `config.load()` turns
`router/tests/test_peer_config.py::LaneDisjointnessTests` (both cases) red and
leaves them green when restored.

### Where to assert: the surface where your cause is the ONLY producer

Mutation tells you a test can fail. It does not tell you the test fails for
the reason it claims, and the recurring defect here is an assertion satisfied
by output it was not pinning — a second producer of the same observable.

**To pin that A causes B, assert B on the surface where A is the only thing
that could have produced it.**

**It does not fire by being known — only by being applied, and the moment to
apply it is when CHOOSING the surface, not when reading the result.** Reading
a green result is exactly when you are least likely to ask the question.

Four instances in this repo, all of them found by mutation and none by
review:

  * `test_task_graph.py` — `task_graph` without a `fleet_domain` is refused
    by TWO guards, and both messages say `fleet_domain`. Deleting the one
    under test left it green; the fix asserts `config.task_graph`, which only
    the right guard emits.
  * `test_discovery.py::ExplicitGraphMapTests` — two refusals in
    `_graph_map` both end "one or the other, never both", and with a
    non-empty fleet the second fires anyway. The fix asserts
    `config.task_graph`, plus a new empty-fleet case that only the first
    guard can catch.
  * `test_discovery.py::JsonStdoutIsTheDocumentAloneTests` — "plain `status`
    still shows the report" stayed green with the LOGGING deleted, because
    `status` PRINTS the report too. Re-pinned against `peers`, which prints
    no report, so the log is the only path to stderr.
  * `test_discovery.py::OnceJsonTests` — "plain `once` keeps its log" stayed
    green with INFO quieted for EVERY command, because the assertion matched
    the bare word `drained` and the discovery report's own WARNING line says
    "a directory with no entry … NOT DRAINED, NOT deleted". Now matched as
    `drained \S+: \{`, which only the INFO line can emit.

The third was written to fix the second. **The fourth was written an hour
after this section was.** That is the point, and it is why the fourth is
listed even though it is the least interesting mechanically: knowing the
shape does not stop you producing it. The wrong surface is usually the
obvious one — you assert on the command you were just thinking about — and
the rule was applied, that time, while reading a green result rather than
while choosing what to assert on.

Pick the surface by asking which producers can reach it, not by which one is
in front of you.

(The formulation is the sandy adapter's, from the exchange that found the
third; the "when it fires" half is theirs too, from the exchange that found
the fourth. The evidence is this repo's.)

### The companion: every after-check needs one that fails when NOTHING HAPPENED

The four above are all "the assertion was satisfied by a second producer".
There is a degenerate case of that worth its own name, because the second
producer is invisible: **the operation did not run at all.**

When the passing state and the no-op state are indistinguishable, an
after-check certifies a change that was never made. Three instances in one
afternoon, 2026-09-22, all of them in throwaway tooling rather than in the
suite — which is the point, since that is where nobody thinks to apply the
rule:

  * A test asserting an outcome beside the pinned `ext/` directory is NOT
    consumed. It placed a hand-made file there, which the FILENAME pattern
    refuses long before the directory is ever chosen, so it stayed green
    under the mutation that adds a second scanned path. It was pinning the
    regex. Fixed by MOVING a file `write_outcome` produced, leaving the
    directory as the only reason it is not read.
  * A host-side script that said **"Idempotent" in its own header** while
    stacking duplicate lines on a second run. Found by running it twice.
  * The identity rewrite. `git rebase --exec` with the exec written across
    two lines is a HARD ERROR (`exec commands cannot contain newlines`); the
    rebase then fast-forwarded and did nothing, and the after-checks reported
    "tree identical" and "messages identical". Both true. Both meaningless.

The third is the sharpest: the check that was fooled had been written
specifically to catch a bad rewrite. "Tree identical" needed a companion
asserting **the shas CHANGED**, and did not have one until the third attempt.

So: pair every "X is unchanged" with an "and Y did change", and pair every
"zero bad ones" with an "and N good ones" — a count that must be nonzero is
what separates *checked* from *the grep did not run*. Ask of each check what
it reports when the operation is a no-op. If the answer is "pass", it is not
a check.

(The positive-control half is the connector's, found on a grep. That it is
not a grep habit is this repo's, found by three different no-ops in one
afternoon.)

### The inverse: a check that CANNOT PASS

The symmetric failure is a guard that is always closed — fail-closed, silent,
and indistinguishable from "nothing is being sent". It produces no red test
because no test drives the real producer. The family's live example is in the
connector repo (a recipient check read a field off the wrong document, so it
was `None != me` forever and every peer notice was refused); the runtime-side
lesson is the general one below.

### Know which document carries which field

One placement produces **two** agent-visible documents, built together in
`router/deliver.py:_message_and_notice` and deliberately not identical:

| | `message` **spool doc** (`inbound-message.schema.json`) | the **notice**'s `message` object (`deliver-notice` / `peer-notice`) |
|---|---|---|
| carries | `id`, `date`, `from`, **`to`**, `subject`, `body_text`, attachment descriptors with `content_ref` | `id`, `from`, `subject`, `preview`, `mailbox` (+ `provenance`, `in_reply_to`, `sender_exposure`, attachment descriptors **also with `content_ref`**, since v3.0.0) |
| written | first | **last** — it is the arrival signal |

`to` and `body_text` are on the **spool doc only**. A consumer that reads them
off the notice reads `None`.

**`content_ref` used to be on the spool doc only too, and is not any more.**
Until 2026-09-20 this router published bytes under `messages/` and omitted the
grant from the notice rather than assert one at a path it did not populate.
AMAP §2 at v3.0.0 closed that the other way — one sidecar dir, under
`notices/`, `<notice-id>.attachments/<index>` with a BARE id — so the omission's
reason expired and both documents now carry the grant. The notice is
self-describing alone rather than only as a pair. Do not restore the asymmetry
from memory: `attachments.content_ref_for` is the single source for the string
and `attachments.sidecar_dir_name` for the directory, deliberately, because
formatting the ref locally is what let a `notice-` prefix the directory never
had survive a year of green runs. The write order is a commit sentinel (blobs →
message spool → ledger → notice LAST), so a consumer resolving a notice always
has the spool doc already on disk — the *pair* is self-describing even though
the notice alone is not. The long comment in `_message_and_notice` explains why
the notice deliberately omits `content_ref`; read it before "fixing" that.

**The schema will not catch you putting a field in the wrong document.**
Runtime-authored documents (`deliver-notice`, `peer-notice`,
`inbound-message`) are **OPEN** — `additionalProperties` is absent at every
level, per §7's v3.0.0 tolerance rule, pinned by
`fixtures/valid/notice-unknown-member.json`. They were closed at v2.3.0 and
were opened deliberately after a strict v2.0.0 connector silently dropped
whole notices when `provenance` was added; only `submit-request`
(agent-authored) and `binding-record` stay closed. So a notice this router
wrongly stamped with `to` would validate **clean**. Emitting an unrecognized
member is still producer non-conformance — the gate just cannot see it. That
is why this split is written down here, and why a test must pin **which
document a field came out of**, not only its value.

Note: the claim that `deliver-notice.schema.json` locks `message` with
`additionalProperties: false` was true at v2.3.0 and is **stale** — the
reasoning it supported (not asserting a grant at a path this router does not
populate) stands on its own without it. `_message_and_notice`'s comment now
says so itself; `router/README.md`'s "Attachment transport" section was
carrying the stale version until 2026-09-20 and no longer does. If you find a
third copy, it is stale too.

### Two lanes, disjoint per ordered pair

| | declared as | shape | enforced by |
|---|---|---|---|
| **mail** | `instances.<x>.peers` | **mutual** allowlist, cold initiation only | `binding.check_cold` |
| **delegation / peer** | `instances.<x>.peer_senders` | **directed**, declared on the RECEIVER | `binding.check_peer_edge` |

`B.peer_senders = ["A"]` means A may task B and says nothing about B tasking A.
No wildcard on the peer lane; `ALLOW_ANY` is refused there on purpose. On the
mail lane `ALLOW_ANY` **never** waives mutuality on the other side — it only
relaxes the side that declares it.

`config.load()` **refuses a config where one ordered pair appears on both
lanes**, using the same `check_cold` predicate the enforcement path uses rather
than a reimplementation of mutuality. Reason: a pair on both lanes would let
the sender pick its lane by how it addressed the message, which is exactly the
sender-controlled lane choice the peer-origin profile forbids.

The peer lane also requires `fleet_domain`, and refuses either end being a
`namespace`-mode instance (that whole tree is agent-writable, so a peer notice
placed there asserts nothing).

Which edges a real fleet declares is **not** in this repo — it is rendered from
the host adapter's fleet policy into a `router.json`. Read that policy file;
never assume it from memory.

### Peer-lane authorisation is THIS side's, not the daemon's (ruling 16)

The in-sandbox delivery daemon holds **no allowlist**. A notice's presence in
the read-only peer tree *is* the router's signature on the decision to deliver
it. So a graph change is a router-only change: nothing needs re-provisioning in
any sandbox. Do not add a second allowlist anywhere downstream "for defence in
depth" — a copy that the router never consults cannot bind the router, and a
copy in an agent-writable path cannot bind the agent.

### The declared public surface must stay honest

`router/__init__.py` carries `PUBLIC_MODULES` / `INTERNAL_MODULES` /
`UNCLASSIFIED_MODULES`. `test_public_surface.py` asserts four things a docstring
cannot: the three tuples **partition** the package (a new module cannot land
unclassified), public modules import with **zero** side effects (measured in a
child interpreter with `PYTHONDONTWRITEBYTECODE=1` and `HOME`/`TMPDIR`/cwd all
pointed at one empty dir), `import router` drags in no submodule, and the same
lists in `router/__init__.py`, `README.md` and `pyproject.toml` agree.

So: adding a module means editing four places, and the suite tells you if you
missed one. `UNCLASSIFIED_MODULES` (`firstsight`, `util`) is not a synonym for
internal — it is the honest record that no ruling has been made. Don't quietly
fold either into a list it was never assigned to.

### Stdlib only, and that is machine-readable

`dependencies = []` in `pyproject.toml` is policy, not an oversight: adding a
dependency has to be a visible diff there rather than a quiet import.

### Instance names are path components

`_NAME_RE` in `config.py` is `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` — the sandy
slug alphabet, so **the instance name IS the slug**, spelled the same way.
Nothing derives one name from another and nothing holds a mapping.

It was `^[a-z0-9][a-z0-9-]{0,63}$` until the widening, and the two properties
that charset gave away for free are now checks, both written BEFORE the
widening landed (`test_config_names.py` pins both):

  * **Casefold.** `state_dir/<name>/` holds the first-sight marker, the reply
    ledger and the quarantine, and on a case-insensitive filesystem two names
    that fold together are ONE directory — two agents sharing one ledger.
    Unrepresentable under the old charset; now `_check_casefold` in `load()`,
    refusing and naming BOTH colliding names.
  * **The dot.** `amap.router` was unreachable as a name because names could
    not contain `.`. Slugs can, so the exclusion is now a check in two places:
    `load()` refuses an instance by that name, and `instance_for` refuses to
    resolve the address.

That order is the rule, not a historical note: **if the charset is ever
widened again, work out what the old one made unrepresentable and write that
guard FIRST.**

### Optional-on-read fields are never backfilled

Ledger records carry `tree` and `transport`. Both are optional on read (older
records predate them). Readers test `tree == "peer"` and never `tree ==
"inbox"`, so an absent value reads correctly. A missing `transport` means "this
record cannot answer", **never** `"local"` — and `record_delivery` has no
default for it, so a forgetful caller gets a `TypeError` at the call site
instead of a wrong ledger record. Silently correct in a transport-free router;
an active lie in a runtime with a second leg.

### Recorded ambiguities stay recorded

Two of them exist — `AMAP-QUESTION-inbound-archive.md` (**RESOLVED**, AMAP
v2.2.0) and `AMAP-QUESTION-attachment-publication-path.md` (**RESOLVED**,
v3.0.0) — because an implementation that quietly picks a reading turns its own
choice into the de facto behaviour and the ambiguity stops being visible to
anyone else. If you hit a new one, write it down rather than resolving it in
code.

**Both are resolved and both stay.** A resolved ambiguity is not spent: the
second one is now the explanation for why this router publishes attachments
where it does, and deleting it would leave the code change unexplained. The
label is what has to keep up — that one read WAITING in this file until
2026-09-20, weeks after v3.0.0 had decided it against us, which is the failure
mode the OWED/WAITING/NEITHER section below is about, committed in the
sentence that introduces it.

**And the answer was (a) — the reading this router had NOT taken.** Recording
that, because "we wrote the question down" reads as diligence and the outcome
here was a year of non-conformance that the question's existence did nothing to
shorten. Writing it down is necessary and is not sufficient; what closed it was
moving the document to the party who could answer it.

**They are no longer in this repo.** Both moved to the spec repo,
`proofpoint/amap-spec`, on 2026-09-20: each is addressed "For the spec" in
its own first line, so filing it here left it visible to everyone except the
party who can answer it. **So file a NEW one there too** — the convention is
"write it down", not "write it down here". `router/deliver.py` and
`router/README.md` cite the attachment one across that boundary; keep those
citations pointed at a real file if it is ever renamed.

**And say WHICH KIND of open it is, because an open item carries an implicit
claim about its own future and that claim is invisible, unversioned and
usually wrong.** A reader six months on cannot tell these apart from the
shape of a list:

  * **OWED** — decided, not yet done. Someone intends to close it.
  * **WAITING** — a decision blocked on a fact nobody has yet, where *one of
    the outcomes is that it stays exactly as it is, forever*. Not a backlog
    item.
  * **NEITHER** — decided, deliberate, and finished in its current form. It
    is in the record so nobody "fixes" it, not because anybody owes anything.

Three examples from this repo, one of each: retiring `SANDY_HANDOFF_*` from
the docs is OWED. **Item 5 of the discovery plan** — `router/README.md`,
"Approved but NOT BUILT" — is WAITING: publishing `directory.json` is off
pending a measurement of whether nested bind mounts apply parent-first, and if
they do not, the correct end state is that it stays off permanently, which §10
calls conformant rather than unfinished. The two layering warts in
`router/__init__.py` are NEITHER: fixing them is a behaviour change, that was
weighed, and the answer was no.

A fourth kind exists and is the easiest to mislabel: **shipped and
deliberately not adopted.** `once --json` exists and the consumer it was
built for has chosen to keep scraping the log line, for a stated reason. Left
in a list as an open row it reads as a gap in somebody's tooling; it is a
choice with a reason on both sides.

**NOT SWEPT.** The distinction landed late and only the items named above
carry it. The rest of this file's recorded-not-fixed entries — the
`UNCLASSIFIED_MODULES` ruling, the mail-lane outcome blindness in
`outcomes.py`, the subpackage gap in the surface partition, the orphan
`state_dir` after de-enrolment — do not yet say which kind they are. Most are
probably WAITING. Do not read that as a backlog; read it as work that has not
been done, which is itself an example of the thing this section is about.

(The distinction came out of the sandy adapter's status ledger, where
applying it moved three rows of five.)

### Git

**Commit only when asked.** The co-author trailer is the running model. This
repo is an independent git repo that is *symlinked* into a workbench — never
`git add` it from there, and never commit sibling repos from here. Concurrent
agents may share this worktree: judge a sha, not the tree.

## Non-obvious things the code does not say

- **`SCOPE.md` is a RECONSTRUCTION, not the original.** No original was ever
  found, yet twenty citations across fifteen files
  pointed at it for the trust story, Posture A, the "no wake to build" rule,
  the provisioning facts, the test strategy, the exfil proof and the §2/§5
  attachment resolution — `binding.py` calls one of them "the exfil-test crux".
  The file now at the repo root was assembled FROM those citations, with every
  claim attributed to the `file:line` that asserts it, so following a citation
  lands somewhere real.
  **Read the direction of authority before citing it.** The content came from
  the code, so the code is the source and `SCOPE.md` is the summary; citing it
  to settle something a module does not already state would be circular. It
  deliberately carries no rationale that was not recoverable, and says so —
  where a section states a conclusion with no justification, that is the honest
  state of the record rather than an omission to tidy.
- **Two stated layering warts, not bugs:** `attachments` → `reset` →
  `firstsight`/`lock`, and public `deliver` → internal `audit`. The declared
  boundary is about what callers may *depend on*, not what the import graph
  touches. Stated in `router/__init__.py` rather than fixed, because fixing
  them is a behaviour change.
- `router/peers.py` is **display-only**. It recomputes from `config` every call
  and stores nothing; enforcement is always `binding`. `render_peers_json`
  emits the graph as `{recipient: [sender, ...]}` so an adapter's `--verify`
  can diff it against the `peers.json` it renders from the same policy,
  element for element without transposing.
- `intake_dir` is accepted by the loader and **read by nothing in this repo**.
  It exists so an adapter can express a mount before a cross-host email router
  is real.
