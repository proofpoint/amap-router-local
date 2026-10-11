#!/usr/bin/env python3
"""Every commit reachable from HEAD must carry a no-reply author AND committer,
and every email in its trailers (and in any annotated tag's tagger) must be a
no-reply address too.

This repository is public, and a commit's author and committer emails are
published with it. An address that identifies a person must never reach the
history, including through a commit nobody wrote by hand: on a pull request,
CI checks out GitHub's synthetic merge commit as HEAD, and a merge made in
the web UI is stamped with whatever address the merging account is set to
use. Both are reachable from HEAD, so both are checked here.

Allowed: GitHub's no-reply form EXACTLY, `<digits>+<login>` or a bare
`<login>` (optionally `[bot]`) at `users.noreply.github.com`, case-sensitive
on the domain and with no surrounding whitespace; and exactly
`noreply@github.com` (GitHub's own committer for web merges). A trailer may
also name `noreply@anthropic.com`, the co-author trailer's address. Checking
only the domain is not enough: `<anything>@users.noreply.github.com` would
admit a local part that is itself a personal address. Everything else is a
finding.

Trailers are read as git parses them (`%(trailers:only,unfold)`), every key,
so `Co-authored-by`, `Signed-off-by` and the rest are all covered; any
`x@y` token in a trailer value is checked. Tags are checked when present in
the clone (CI fetches them with `fetch-depth: 0`).

Output names the commit and the role, never the address: a CI log is public
too, and printing the value would publish it a second time.

    python3 tools/check_commit_metadata.py [REPO]

Exit 0 when every identity is allowed, 1 on any finding, 2 when the history
cannot be read or is empty (an empty answer is not a clean one).
"""
from __future__ import annotations

import re
import subprocess
import sys
from typing import List, Tuple

#: GitHub's no-reply address: `<id>+<login>` or a legacy bare `<login>`, where
#: a login is 1-39 of [A-Za-z0-9-] starting with an alphanumeric (logins are
#: case-preserving, so mixed case is real). `[bot]` is GitHub's app suffix.
NOREPLY_RE = re.compile(
    r"(?:[0-9]+\+)?[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?@users\.noreply\.github\.com")
ALLOWED_EXACT = frozenset({"noreply@github.com"})
#: Addresses a trailer may carry beyond the above: the co-author trailer.
TRAILER_EXACT = frozenset({"noreply@anthropic.com"})

#: An address-shaped token inside a trailer value.
_EMAIL_TOKEN = re.compile(r"[^\s<>]+@[^\s<>]+")

#: Commits exempted by an explicit, recorded decision, as FULL 40-hex shas,
#: matched exactly: never a prefix, a pattern or a branch. An entry here does
#: not make an address acceptable; it records that one already-published
#: commit was accepted as it is, by name.
EXCEPTED_SHAS: frozenset = frozenset({
    # The squash merge of PR #2 into hop-integration, whose author address
    # GitHub took from the merging account's settings. Accepted as published
    # by the repository owner on 2026-10-11, rather than rewriting a
    # protected public branch.
    "a6d03d918369d33f25c01cba46726549fd17456c",
})


def email_allowed(email: str) -> bool:
    """Exact matches only: no case folding, no stripping."""
    return email in ALLOWED_EXACT or NOREPLY_RE.fullmatch(email) is not None


def trailer_allowed(value: str) -> bool:
    """Every address-shaped token in one trailer value is allowed. A value
    with no address in it (a plain `Reviewed-by: Someone`) has nothing to
    leak."""
    return all(email_allowed(t) or t in TRAILER_EXACT
               for t in _EMAIL_TOKEN.findall(value))


def identities(repo: str) -> List[Tuple[str, str, str, List[str]]]:
    """`(sha, author_email, committer_email, trailer_values)` for every commit
    reachable from HEAD, merges included."""
    out = subprocess.run(
        ["git", "-C", repo, "log",
         "--format=%x1e%H%x00%ae%x00%ce%x00%(trailers:only,unfold)", "HEAD"],
        capture_output=True, check=True,
    ).stdout.decode("utf-8", "replace")
    rows = []
    for record in out.split("\x1e")[1:]:
        sha, ae, ce, trailers = record.split("\0", 3)
        values = [line.split(":", 1)[1].strip() if ":" in line else line.strip()
                  for line in trailers.splitlines() if line.strip()]
        rows.append((sha, ae, ce, values))
    return rows


def tags(repo: str) -> List[Tuple[str, str]]:
    """`(tag_object_sha, tagger_email)` for every annotated tag in the clone."""
    out = subprocess.run(
        ["git", "-C", repo, "for-each-ref", "refs/tags",
         "--format=%(objectname)%00%(objecttype)%00%(taggeremail)"],
        capture_output=True, check=True,
    ).stdout.decode("utf-8", "replace")
    rows = []
    for line in out.splitlines():
        sha, kind, email = line.split("\0")
        if kind == "tag":
            rows.append((sha, email[1:-1] if email.startswith("<") and email.endswith(">")
                         else email))
    return rows


def findings(rows: List[Tuple[str, str, str, List[str]]],
             tag_rows: List[Tuple[str, str]] = ()) -> List[Tuple[str, str]]:
    """`(sha, role)` for every disallowed identity. Never the address."""
    bad = []
    for sha, ae, ce, trailers in rows:
        if sha in EXCEPTED_SHAS:
            continue
        for role, email in (("author", ae), ("committer", ce)):
            if not email_allowed(email):
                bad.append((sha, role))
        if not all(trailer_allowed(v) for v in trailers):
            bad.append((sha, "trailer"))
    for sha, email in tag_rows:
        if not email_allowed(email):
            bad.append((sha, "tagger"))
    return bad


def main(argv: List[str]) -> int:
    repo = argv[0] if argv else "."
    try:
        rows = identities(repo)
        tag_rows = tags(repo)
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"::error title=commit-metadata::cannot read the history: {type(e).__name__}")
        return 2
    if not rows:
        print("::error title=commit-metadata::no commits reachable from HEAD; refusing to call that clean")
        return 2
    bad = findings(rows, tag_rows)
    for sha, role in bad:
        what = "tag" if role == "tagger" else "commit"
        print(f"::error title=commit-metadata::{what} {sha[:12]} {role} email is not "
              f"a no-reply address (value redacted)")
    print(f"commit-metadata: {len(rows)} commit(s) and {len(tag_rows)} annotated tag(s) "
          f"checked, {len(bad)} finding(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
