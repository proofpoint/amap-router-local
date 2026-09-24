"""amap-router-local — host-side router that moves AMAP artifacts between two
(or more) agent sandboxes on one box, so two connector-backed agents can
mail each other with no mail provider at all.

See README.md for layout, config format, and how to run it; SCOPE.md (one
directory up) for the design rationale and trust story this package
implements.

Public surface
--------------
The moment another repo imports this one, its internals become an API whether
or not anyone says so. The three tuples below say so, and
`router/tests/test_public_surface.py` holds them to it — every module in the
package must appear in exactly one of them, so a new module cannot be added
without being classified, and the same lists in README.md and pyproject.toml
are pinned against these.

`PUBLIC_MODULES` is what another runtime may import and what a later
extraction into `amap-core` lifts.

`outbound` was internal until a combined local+external runtime needed to
DRIVE this one. It exports exactly two callables and the cold-policy types;
everything else in it is `_`-prefixed, so Python's own convention carries the
boundary inside the module and promoting it does not promote its internals.
The alternative was a thin re-export module, which would have added a name
without adding a boundary. `INTERNAL_MODULES` may change shape
without notice. The public modules are also held to importing with no side
effects at all — nothing written, no environment read, nothing printed — so
that importing the surface is never itself an action.

This module deliberately imports NOTHING from the package. `import router`
must not drag the closure in behind it; that is asserted, not merely intended.

A known layering wart, stated rather than fixed (fixing it would be a
behaviour change and is out of scope): `attachments` imports `reset`, which
imports `firstsight` and `lock`. So `import router.attachments` transitively
loads three internal modules. The boundary declared here is about what
callers may DEPEND on, not about what the import graph currently touches.

The peer lane (AMAP 3.1.0 peer-origin profile) added three modules.
`exposure` is public: it is policy — the `sender_exposure` assessment a
runtime stamps — and `deliver` (public) depends on it, so a consumer of
`deliver` already has it in its closure. `audit` and `outcomes` are
internal: `audit` is the record this router keeps of its own actions, and
`outcomes` is the reader for one connector's side channel. That `deliver`
imports `audit` is a second stated layering wart of the same shape as
`attachments` -> `reset`: a public module transitively loading an internal
one. What callers may DEPEND on is unchanged — `deliver`'s signature names
nothing from `audit`.

`lock` became public on 2026-09-03 for the same reason `outbound` did: a
combined local+external runtime that drives this one must take THIS
router's single-drainer lock at startup (`lock.acquire(state_dir)`, raising
`lock.LockHeldError` when another drainer holds the namespace), so that it
and a standalone `python -m router run` on one `state_dir` exclude each
other by the same file. Semantics unchanged; the whole module is small and
every name in it is the surface (`acquire`, `DrainLock`, `LockHeldError`,
`LOCK_NAME`). A re-export from another public module would have been a
second name for the same thing with no boundary of its own.

`UNCLASSIFIED_MODULES` is not an empty category and not a synonym for
internal — it is the honest record that the table this split came from named
13 of the package's 15 modules and ruled on neither of these two. (That table arrived
with a combined-runtime plan whose four items all landed and which is not part
of this repository. The tuples below are the surface now — the plan was only
where they came from.) The
standing recommendation for whoever rules: `util` is already part of the
public exception surface (`attachments.publish_attachment_blobs` and
`write_agent_visible` raise `util.NamespaceEscapeError`, so a caller that
catches it must import `router.util`), and `firstsight` is reached from
`outbound`, `reset`, `console` and `exposure` — all in-package, and NO
out-of-package caller is known.

That last clause has now been wrong twice, in both directions, which is why
it is stated as a checkable fact rather than a recollection. It read
"`outbound`, `reset` and `__main__`" while `console` and `exposure` already
imported the module and `__main__` had stopped; it was then briefly amended
to claim an external dependent, on the strength of an adapter that imported
`approval.approval_path` and was in the middle of deleting the report that
did so. The adapter reads the marker as a FILE, from a program that runs
this router as a subprocess and imports nothing from it — which is the
better boundary, and leaves the classification question genuinely open
rather than forced by a dependent. Re-derive the list from the imports
before relying on it.

Until the ruling lands, neither name is silently folded into a list it was
never assigned to.

THE OUT-OF-PACKAGE DEPENDENT IS REAL, AND IT IS NOT `firstsight`. A host
adapter imports `reset._open_child` — an underscore-prefixed symbol from a
module this file declares may change shape without notice. Two readings, and
only one of them is right:

  * "Stop importing a private symbol" is the WRONG one. `_open_child` is the
    `O_NOFOLLOW` + `O_DIRECTORY` pin: one syscall that either hands back a
    descriptor to the current target inode or refuses. Reimplemented slightly
    wrong — a `lstat` then an `open`, a missing `O_NOFOLLOW` — it is a
    symlink-following hole in a program that walks agent-writable trees. The
    adapter importing it rather than copying it is this package's own stated
    rule (`pyproject.toml`: don't reimplement, import) applied correctly.

  * The symbol is in the WRONG PLACE. A reusable security primitive should
    not be a private function of the destructive-wipe module, reached by
    `attachments` in-package through a stated layering wart and by an adapter
    out-of-package through the underscore. `util` already carries the
    namespace-containment surface these callers use alongside it.

DONE. It is `util.open_child_pinned`, and `reset._open_child` is an ALIAS to
the same object — not a wrapper, so there is one implementation to audit and
a test asserts the identity. The adapter was told before the commit, not
after. `attachments` migrated its four call sites; its fifth reach into
`reset` (`_remove_one`) stays, so the stated wart above shrank rather than
closed, which is the honest description.

What this bought is narrower than it sounds, and the note should say so: the
dependency moved from a PRIVATE name in a module declared "may change shape
without notice" to a PUBLIC name in a module whose classification nobody has
ruled on. Strictly better, not finished — and it makes the `util` ruling
harder to keep deferring, which is the point.

TWO `config` CONSTANTS ARE NOW PINNED FROM OUTSIDE, AND THAT IS NOT AN
OBLIGATION — IT IS AN ALARM SOMEONE ELSE INSTALLED. A host adapter's
layout-agreement test imports `config.TASK_GRAPH_ALL` and `config.ALLOW_ANY`
and asserts its renderer emits exactly those VALUES. `config` is public, so
the import is supported; what is easy to misread is that "public module,
change freely" does not extend to those two strings. They are wire tokens —
one is rendered into a manifest another repo writes and this one parses, the
other is the per-instance mail wildcard that manifest must never emit.

The distinction from `reset._open_child` matters and is the reason this is
written separately. There, silence breaks them: they import a private symbol
and a rename is a failure they cannot anticipate, so it owes notice BEFORE
the commit. Here, their test going red IS the intended behaviour — changing
either value is a coordinated change and their suite is what says so. The
obligation is not "warn them"; it is "expect their red, and do not assume a
green means nobody cares".

AND `reset.py`'s FILENAME IS LOAD-BEARING TOO. That adapter confirms it has
found a router checkout by testing for `router/reset.py` on disk. So the file
may be re-homed internally but not renamed or removed without giving it a new
sentinel to look for first. An alias inside `reset.py` survives the promotion
above; deleting `reset.py` would not.

`router/tests/` IS OUTSIDE THIS MODEL ENTIRELY, and now has a consumer. The
partition above is computed from `_PKG.glob("*.py")` — top level only — so
the test package is neither public, internal nor unclassified; it is
unconsidered. The same adapter imports `router.tests.helpers.RouterTestCase`
for a layout-agreement test, which is a reasonable thing to want (the point
of that test is that the two repos agree, so sharing the fixture is the
mechanism) and is currently supported by nothing at all. Evidence that this
is not theoretical: retiring `approve` renamed `make_config`'s `approve=`
keyword to `seen=` and `_auto_approve` to `_mark_seen`, which is a
call-time `TypeError` in any out-of-package caller and was made without
knowing one existed. DECIDED: the test package now has a declared surface. See
`router/tests/__init__.py` — `PUBLIC_TEST_SURFACE`, two dotted names, plus
the keyword list `make_config` may not silently lose. `test_public_surface.
py` defends them, so the next `approve=` -> `seen=` goes red HERE instead of
in someone else's suite. Everything else under `router/tests/` is explicitly
not promised.

Note what the declaration does NOT do: `router/tests/` is still outside the
three-way partition above, which is computed from `_PKG.glob("*.py")`. A new
top-level module cannot land unclassified; a new subpackage still can. That
is the same gap one level down, and it is recorded rather than closed.

If it IS declared, the adapter's actual usage is the whole of it, and is
smaller than the names above suggest: `RouterTestCase` as a base class, for
its temp-dir lifecycle; `make_config(peers_dict, mode="handoff")` for its
declared behaviour (a config with N handoff instances); and nothing else
about either one's internals. Its third handle, `cfg.instances[name].root`,
is `InstanceConfig`'s public field via `config` and is not part of this
question. So a declaration would be two names and one keyword, which is
also the honest upper bound on what a refactor here may not silently
change.
"""

#: What another repo may import. Held to a no-side-effect bare import.
PUBLIC_MODULES = ("attachments", "binding", "config", "deliver", "exposure",
                  "lock", "outbound", "peers", "validate")

#: Implementation. May change shape without notice.
INTERNAL_MODULES = ("__main__", "audit", "console", "outcomes", "provision", "reset",
                    "roster", "service", "status")

#: Named by no ruling yet. Absent from the plan's table, not assigned by it.
UNCLASSIFIED_MODULES = ("firstsight", "util")
