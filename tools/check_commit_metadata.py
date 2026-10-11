#!/usr/bin/env python3
"""Every commit reachable from HEAD must carry a no-reply author AND committer.

This repository is public, and a commit's author and committer emails are
published with it. An address that identifies a person must never reach the
history, including through a commit nobody wrote by hand: on a pull request,
CI checks out GitHub's synthetic merge commit as HEAD, and a merge made in
the web UI is stamped with whatever address the merging account is set to
use. Both are reachable from HEAD, so both are checked here.

Allowed: any `<...>@users.noreply.github.com`, and exactly
`noreply@github.com` (GitHub's own committer for web merges). Everything
else is a finding.

Output names the commit and the role, never the address: a CI log is public
too, and printing the value would publish it a second time.

    python3 tools/check_commit_metadata.py [REPO]

Exit 0 when every identity is allowed, 1 on any finding, 2 when the history
cannot be read or is empty (an empty answer is not a clean one).
"""
from __future__ import annotations

import subprocess
import sys
from typing import List, Tuple

ALLOWED_DOMAIN = "users.noreply.github.com"
ALLOWED_EXACT = frozenset({"noreply@github.com"})

#: Commits exempted by an explicit, recorded decision, as FULL 40-hex shas,
#: matched exactly: never a prefix, a pattern or a branch. Empty: no
#: exception has been decided. An entry here does not make an address
#: acceptable; it records that one already-published commit was accepted
#: as it is, by name.
EXCEPTED_SHAS: frozenset = frozenset()


def email_allowed(email: str) -> bool:
    e = email.strip().lower()
    if e in ALLOWED_EXACT:
        return True
    local, at, domain = e.rpartition("@")
    return bool(local) and at == "@" and domain == ALLOWED_DOMAIN


def identities(repo: str) -> List[Tuple[str, str, str]]:
    """`(sha, author_email, committer_email)` for every commit reachable from
    HEAD, merges included."""
    out = subprocess.run(
        ["git", "-C", repo, "log", "--format=%H%x00%ae%x00%ce", "HEAD"],
        capture_output=True, check=True,
    ).stdout.decode("utf-8", "replace")
    rows = []
    for line in out.splitlines():
        sha, ae, ce = line.split("\0")
        rows.append((sha, ae, ce))
    return rows


def findings(rows: List[Tuple[str, str, str]]) -> List[Tuple[str, str]]:
    """`(sha, role)` for every disallowed identity. Never the address."""
    bad = []
    for sha, ae, ce in rows:
        if sha in EXCEPTED_SHAS:
            continue
        for role, email in (("author", ae), ("committer", ce)):
            if not email_allowed(email):
                bad.append((sha, role))
    return bad


def main(argv: List[str]) -> int:
    repo = argv[0] if argv else "."
    try:
        rows = identities(repo)
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"::error title=commit-metadata::cannot read the history: {type(e).__name__}")
        return 2
    if not rows:
        print("::error title=commit-metadata::no commits reachable from HEAD; refusing to call that clean")
        return 2
    bad = findings(rows)
    for sha, role in bad:
        print(f"::error title=commit-metadata::commit {sha[:12]} {role} email is not "
              f"a no-reply address (value redacted)")
    print(f"commit-metadata: {len(rows)} commit(s) checked, {len(bad)} finding(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
