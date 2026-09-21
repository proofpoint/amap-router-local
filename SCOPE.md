# SCOPE.md — reconstructed from its own citations

**Read this header before citing anything below.**

Twenty citations across fifteen files in this repository point at `SCOPE.md`
for load-bearing rationale — `binding.py` calls one of its sections "the
exfil-test crux" — and until this file was written there was nothing at the
other end. The document
has never been found in this repository, and no file carrying its
section headings exists anywhere in the workspace. It was cited from the first
commit onward as though it did.

So this is **not** the original, and it is not a decisions record. It is an
index assembled *from* the citations, in which every claim is attributed to the
file that asserts it. That direction matters: the content here was derived from
the code, so the code is the source and this file is the summary. Citing
`SCOPE.md` as the authority for something a module already states would make
the reasoning circular — the module would point here, and here would point back
at the module.

Use it to find out what a citation meant. Do not use it to settle a question
the cited module does not already answer; for anything genuinely undecided, the
decision belongs in the connector's design record, which is where decisions for
this family live.

---

## Trust story

**The outbox is untrusted input to the host.** Everything an agent can write is
adversarial input to a process running outside that agent's sandbox, and the
router reads it accordingly: bounded reads, filename-derived identifiers, and
hygiene applied before any open.

- Never slurp an agent-controlled file of unbounded size — `read_capped`
  exists for this. *(`router/util.py:22`, `:140`)*
- A hostile or symlinked filename never even reaches `read_capped`; a symlink
  in `outbound/` is excluded and counted rather than followed, because it could
  resolve outside the namespace and filename hygiene says nothing about what a
  name points at. *(`router/outbound.py:15`)*
- `req_id` is derived from the FILENAME, never the body. *(`router/outbound.py:17`)*
- A malformed request is a routine input, not an exceptional one.
  *(`router/tests/test_malformed_request.py:70`)*

**Replies bind from the router's own private ledger, never from anything in any
agent's namespace.** This is the property the exfil test exists to demonstrate:
an agent that controls the contents of its own namespace still cannot redirect
a reply, because the binding is resolved from state it cannot reach. The
discipline is transplanted from `gate/outbound.py:resolve_binding` — read the
gate's own staged copy, never the scope-volume copy the agent can rewrite.
*(`router/binding.py:7`)*

## Posture A

**Both inbound and outbound are read-write, so an agent CAN write a notice
straight into its own inbox.** This is the accepted prototype delta, not
something the router works around.

What the router guarantees instead: a reply to a self-forged notice cannot
resolve, because `resolve_binding` only ever reads the router's own private
ledger. Forging a notice buys an agent a message it wrote to itself and
nothing else. *(`router/tests/test_forged_notice.py:1`)*

## No wake to build

**The router's whole job is writing files.** No wake, no watcher, no thread —
the connector's own watcher (today `inbox-delivery`; `inbox-channel` when this
was written) is already running, unmodified, and does the rest. Delivery completes when the notice file appears; nothing signals it.
*(`router/service.py:25`, `router/deliver.py:55`)*

`run_forever(cfg, interval)` is a thin polling wrapper for deployment and is
not otherwise exercised by the test suite. *(`router/service.py:20`)*

## Provisioning facts

**This tool writes no host-side file.** It never touches the host's own state
directory, `~/.claude*`, or anything host-side. The placement facts below are
DOCUMENTATION ONLY — verified against real host behaviour, and provisioning
around them by hand is left to the operator.
*(`router/provision.py:42`, `router/README.md:434`)*

- The per-sandbox user config is a SIBLING file, `<sandbox-dir>.claude.json`,
  mounted at a fixed point — **not** inside the sandbox directory tree.
- The host strips the `projects` key on first seed and re-applies it.

## Operator decision

**No code or config in this package hard-codes a volume name.** An instance's
root is an explicit config path. The documentation-only example for `namespace`
mode places it under `<sandbox-dir>/claude/mail/` — a neutral leaf name, picked
on the decision that it *not* be named anything meaningful, and outside the
workspace so nothing lands in a git repo. *(`router/README.md:86`)*

Router-private state — the delivery ledger, idempotency anchors, held requests,
first-sight markers, quarantine copies — lives in a separate `state_dir`,
validated at config-load time to be unreachable from every instance namespace.

## Test strategy

**Temp dirs, no threads, no ports.** Two temp dirs stand in for two (or more)
agent sandbox roots, plus a third for `state_dir`. Nothing imports a host tool,
`docker`, or any real connector binary: requests are written directly in the
shape `inbox-submit` would produce, and notices and messages are read back in
the shape the connector (`inbox-delivery` / `inbox-mcp-vol`) would read them.
*(`router/tests/helpers.py:4`)*

`status.json` is a file rather than a listening socket for the same reason:
stdlib-only, zero new listener surface on a security-sensitive host process,
and fully testable with temp dirs. *(`router/status.py:12`)*

The proof that a real connector and a real runtime agree over the seam is a
different exercise and lives in `amap-conformance-harness`, which belongs to
neither side.

## Proof

**The exfil test.** A reply must reach only the sender that the router's own
ledger names, and an agent instructed to redirect it must not be able to —
together with the companion property that replies never consult the allowlist.
These are the two properties `binding.py` exists to guarantee.
*(`router/tests/test_reply_binding.py:1`)*

## The §2/§5 ambiguity, and how this router resolves it

The message-spool document and the deliver-notice share one attachment
descriptor shape and **differ only in `content_ref`**: the message doc carries
it, the notice does not.

Emission of `content_ref` is a MAY, and this router never asserts a grant at a
`notices/`-side path it does not populate — bytes are published once, under
`messages/`. A strict §5-literal reader looking at only the notice, and seeing
`disposition: "clean"` with a verified `sha256` and no grant, could misread that
as "the runtime chose not to publish." It did publish; the grant lives one
artifact over. *(`router/deliver.py:178`, `:234`,
`router/tests/test_attachments_outbound.py:95`)*

`size_bytes` and `sha256` on this lane are ROUTER-VERIFIED — the asymmetry AMAP
§5 notes relative to a real mail provider, where inbound `size_bytes` is only
advisory. *(`router/deliver.py:178`)*

---

## What is NOT here

The original SCOPE.md, if one was ever drafted, would have carried the
reasoning *behind* these decisions rather than the decisions themselves. That
reasoning is not recoverable from the citations, and none has been invented to
fill the gap. Where a section above states a conclusion without a justification,
that is the honest state of the record, not an omission to be tidied.
