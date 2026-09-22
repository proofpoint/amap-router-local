# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately to: **`resero-labs@proofpoint.com`**

You should expect an acknowledgement that your report was received. If you do
not get one, assume it did not arrive and say so through any other channel you
have; a disclosure that goes unanswered is the failure this file exists to
prevent.

Please include whatever you have: what you did, what happened, what you
expected, and which version or commit. A partial report is worth sending.

## What this project is, and what that means for scope

`amap-router-local` is a **transport-free** runtime. It carries no credentials,
opens no network connections, speaks no SMTP or IMAP, and holds no secrets. It
moves files between directories on one machine. Much of the usual attack
surface is absent by construction rather than by mitigation.

What it *does* hold is a trust boundary. It writes into namespaces that
untrusted agents can read, reads from namespaces those agents can write, and
decides which of them may reach which. Reports are most valuable where that
boundary is:

- **Namespace escape** — any path by which a write intended for one instance's
  tree lands outside it, including via symlink, rename, or a check that
  resolves a path separately from the write that follows it.
- **Forged delivery** — anything that lets an agent cause a notice to appear in
  a namespace the router did not place it in, or appear to come from a sender
  it did not come from.
- **Authorisation bypass** — a message crossing between two parties the
  configured graph does not connect, on either lane, or a sender choosing its
  own lane by how it addresses a message.
- **Reply-binding confusion** — anything that lets a reply reach a party other
  than the one the router's own ledger says it should.
- **Attachment publication** — bytes published where the contract says they are
  not, or a grant asserted at a path that was never populated.

Reports outside that boundary are still welcome; these are simply where a
finding is most likely to be load-bearing.

## What is out of scope

- **Anything requiring the operator's own privileges.** The router's state
  directory is operator-owned and is not agent-reachable by design; an attack
  that presumes write access to it presumes the game is already over.
- **Denial of service by resource exhaustion** from a party already authorised
  to submit. The router is not a quota system.
- **The contents of messages.** This runtime does not scan, screen, or filter
  what agents send each other. A `disposition: "clean"` assertion on an
  attachment is a statement about *this runtime's* handling, not a claim that
  the bytes were examined by anything.

## Supported versions

This project is pre-1.0. Fixes land on `main`; there are no maintained release
branches and no backports.

## Disclosure

We will work with you on timing. The preference is coordinated disclosure after
a fix is available, and we would rather agree a date with you than impose one.
