# amap-router-local — a reference implementation of the Agent Mailbox Access Protocol

A **trusted mail runtime** that speaks [agent-mailbox-protocol][amp] (AMAP) and
carries no mail at all. It moves messages between agent namespaces on **one
machine**: no mail provider, no credentials, no network egress, no SMTP, no
IMAP. Two sandboxed agents on the same box correspond with each other over
exactly the seam a credentialed, mail-carrying runtime would use.

**Status:** working, Apache-2.0-licensed, runs live, with the test suite green.

## Why this exists

AMAP claims to be a wire contract "owned by neither side" — a seam that
independently built runtimes and connectors can meet across. A contract like
that is worth what you can demonstrate with it, so this is a runtime you can
read end to end and actually run.

It is deliberately minimal. A mail-carrying runtime necessarily brings provider
credentials, authentication, screening and network egress, and those obscure
which behaviors the *protocol* requires and which belong to that deployment.
Strip them away — no provider, no credentials, no network — and what remains is
exactly the obligations AMAP places on a runtime, with nothing else to hide
behind.

That makes it useful three ways: a worked example of what a conforming runtime
must do, something to test a connector against with no infrastructure at all,
and evidence that the contract is implementable without the assumptions of any
particular mail stack. The connector it was exercised against required **no
modification** — it was not written for this runtime, and nothing here was
shaped to suit it.

## What it does

- Routes submit-requests from one agent's outbox to another's inbox, applying
  policy the agents cannot influence: a peer matrix, recipient binding for
  replies, and a first-sight quarantine of anything already staged in an
  outbox before this router ever saw it.
- Verifies and republishes attachments — digests and sizes re-computed over the
  bytes it reads itself, never trusted from the sender's descriptor.
- Owns retention and deletion on both sides of the namespace, per AMAP §2.
- Enforces every obligation the seam places on a runtime, including the ones a
  local deployment could quietly skip.

The agent never holds a capability. It writes an inert file; this process
decides what happens next. **No security property depends on an agent
behaving** — the same invariant AMAP §1 states, implemented independently.

## What it is not

- **Not a connector.** It is the runtime half. The connector lives in
  a separate connector package.
- **Not a mail server.** It has no transport and cannot reach a network.
- **Not multi-host.** Every namespace it touches is a local directory. Routing
  between machines is out of scope by design, not by omission.
- **Not a cut-down version of something larger.** It was built against the
  spec, not derived from another implementation.

## Layout

```
router/            the runtime
router/tests/      the test suite
router/README.md   the package's own reference doc
```

### Public surface

Once another repo imports this one, the internals become an API whether or not
anyone says so. So they are named. `router/__init__.py` carries the same lists
as `PUBLIC_MODULES` / `INTERNAL_MODULES` / `UNCLASSIFIED_MODULES`, and a test
holds all three declarations — here, there, and in `pyproject.toml` — to each
other.

| Class | Modules |
|---|---|
| **Public** — another repo may import these, and a later `amap-core` extraction lifts them | `attachments`, `binding`, `config`, `deliver`, `exposure`, `lock`, `outbound`, `peers`, `validate` |
| **Internal** — implementation; may change shape without notice | `__main__`, `audit`, `console`, `outcomes`, `provision`, `reset`, `roster`, `service`, `status` |
| **Unclassified** — no ruling yet; see `router/__init__.py` | `firstsight`, `util` |

Public modules import with no side effects at all: nothing written, no
environment variable read, nothing printed. That is asserted, not assumed —
importing the surface is never itself an action. It is also what lets a caller
supply its own delivery backend and its own extra instance keys without this
repo having to know what they mean.

Run it:

```
python3 -m router --config <config.json> run --interval 5
python3 -m router --config <config.json> peers      # who may cold-initiate to whom
python3 -m router --config <config.json> status
python3 -m pytest router/tests -q
```

## Where it sits

AMAP defines two roles and this repo implements one of them:

| Role | This repo | Notes |
|---|---|---|
| **Runtime** (trusted) | ✅ | Holds every credential, the agent's identity, and all policy. This repo implements the role without carrying mail. |
| **Connector** (untrusted) | — | Runs inside the agent's sandbox, holds no credentials, speaks the other half of the seam. |

Operator setup — installing a connector into sandboxes and wiring two agents
together — belongs to whatever deployment uses this router, not here. This
repo owns the runtime and nothing else.

## Seam questions this implementation surfaced

Implementing a spec is how you find out what it left ambiguous — an ambiguity
is invisible until someone has to choose. Two questions came out of building
this, and are recorded here rather than quietly resolved in code:

**Both now live in the spec repo, `proofpoint/amap-spec`**, and both are
**resolved**: `AMAP-QUESTION-inbound-archive.md` (the inbound archive collided
with inbound integrity — resolved in AMAP v2.2.0, close to this document's own
recommendation) and `AMAP-QUESTION-attachment-publication-path.md` (§2 and §5
disagreed about where a published attachment's sidecar directory lives —
resolved in v3.0.0, **against the reading this router had taken**; the
publication path moved to `notices/` on 2026-09-20). They were kept here until
then; each is addressed "For the spec" in its own first line, so the spec repo
is where its reader is.

Recording them matters more than answering them locally: an implementation that
simply picks a reading turns its own choice into the de facto behavior, and the
ambiguity stops being visible to anyone else. **Recording them where the reader
is matters too** — a question filed in the implementation that raised it is
visible to everyone except the party who can answer it.

[amp]: https://github.com/proofpoint/amap-spec
