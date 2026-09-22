# Contributing to amap-router-local

This repository is the **runtime** half of the AMAP seam: it moves AMAP
artifacts between agent namespaces on one machine. It implements a wire
contract that lives somewhere else.

That distinction decides where a change belongs, so it comes first.

## Where your change belongs

| you want to change | open it against |
|---|---|
| how this runtime behaves — a bug, a guard, a reason code it emits | **here** |
| what the wire contract *says* — a field, a schema, an obligation | **the spec repo**, not here |

This repo implements; it does not define. A PR here that changes what a
document means, rather than what this router does with it, will be asked to go
upstream first — not as a formality, but because a second implementation
reading the same spec has to agree with the change and cannot if it landed as a
runtime patch.

## Running the tests

```sh
pip install -e .
python3 -m unittest discover -s router/tests -t .
```

**645 tests, roughly two seconds.** No docker, no network.

**Install editable, always.** A copy install puts a second `router` under
`site-packages` and makes "which copy is running" ambiguous. `test_docker.py`
resolves the repo root by walking up from its own file, so under a copy install
the suite fails at *collection* — loudly, which is the failure mode to want.

### Three results that look like problems and are not

**1. `1 failure, 32 errors` on a fresh clone.** You have not broken anything.
Thirty-two conformance tests validate this runtime's real artifacts against the
spec's own fixtures and schemas, and they need a checkout of the spec repo:

```sh
AMAP_SPEC_REPO=/path/to/amap-spec python3 -m unittest discover -s router/tests -t .
```

or put a clone of it beside this repo. Those tests **error rather than skip**
when the spec is absent, and that is deliberate. This repo once carried a probe
guarded by a `skipTest`: it did not fail, it *stopped running*, and the suite
went on reporting green without it for months. Resolving the checkout is the
fix; tolerating the skip is not. A loud failure you can act on beats a silence
you cannot see.

**2. `OK (skipped=3)` on macOS.** Correct, not degraded. `CasefoldIncumbencyTests`
builds two instance directories differing only in case, to pin which one wins.
APFS is case-insensitive by default, so the second `mkdir` collides with the
first and there is nothing to decide between. The class detects that — by
creating a directory and asking whether its differently-cased name resolves,
never by reading `sys.platform`, which is wrong in both directions — and skips
with the reason attached. A check that cannot run should say so in its own
words rather than impersonate a failure of the thing it was checking.

**3. A rare failure in `test_path_based_control_can_detect_the_bug_class`.**
Known, pre-existing, roughly one run in ten. It is the *control* probe of a
live-race harness and it asserts that a naive reader loses the race. Re-run it.

## Two conventions that surprise people

### `dependencies = []` is policy, not an accident

`pyproject.toml` declares no dependencies **on purpose**. This runtime is meant
to be auditable and to run with nothing but a base image, and an empty list
makes that machine-readable rather than a promise in prose — adding a
dependency has to be a visible diff in that file instead of a quiet import.

This is also why **CI drives the suite with `unittest`, not `pytest`**. Nothing
against pytest; the point is that installing a test runner would mean the job
no longer demonstrates the thing the empty list asserts. A PR that reaches for
pytest is not being corrected on style — it removes the only evidence that the
claim is true.

If a change genuinely needs a dependency, say so in the PR body and make the
argument. The answer is not automatically no; it is that the diff has to be
visible and the reason has to be stated.

### Every guard gets mutation-tested

**Break it in the source, watch the NAMED test go red, restore it** — and say
so in the PR. Not "the suite went red": the specific test that claims to cover
your guard.

This is the convention most likely to be unfamiliar, and it exists because of a
real case here. A test asserted that *some* error was raised. Deleting the
guard it named left the whole suite green, because a different code path raised
a different error that the same assertion accepted. The test could not fail.

Two corollaries worth knowing before you write the assertion:

- **Assert on the surface where your cause is the only producer.** If two
  things can emit the observable you are checking, your test passes for reasons
  it does not claim. Pick the surface by asking which producers can reach it,
  not by which one is in front of you.
- **A skip counts too.** If you add a `skipIf`, prove it can fire *and* that it
  does not fire when it should not. A skip that silently never triggers is
  indistinguishable from a fix.

## Style, and where the real rules live

Match the surrounding code: its naming, its idiom, and in particular its comment
density — this repo explains *why* at the point of the decision, and a change
that drops the reasoning loses more than it saves.

**`CLAUDE.md` is the working document** for this repository's conventions and
the failures that produced them. It is not a summary of this file; it is the
longer version, and it is deliberately not duplicated here, because two copies
of a convention drift and only one of them gets updated.

## Pull requests

- One concern per PR. Separate a behaviour change from a reformat.
- The commit message carries the *why*. This repo's history is short but its
  messages are long, and that is on purpose.
- Say what you tested and how, including the mutation if you added a guard.
- CI must be green. If it is red for a reason you believe is unrelated to your
  change, say which reason — do not assume.

## Reporting a vulnerability

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
