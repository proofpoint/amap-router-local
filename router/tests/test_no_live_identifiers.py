"""No identifier in this repository may name a real workspace.

A sandy slug is `<name>-<8 hex>`, and the hex half is a digest of a real
workspace path. That digest is the IDENTIFYING half: it maps back to the
workspace whatever word precedes it, so an "invented" name over a real digest
discloses the workspace just as completely as the original did, while reading
as though it had been sanitised.

This repository learned that the expensive way. Fixtures carried three slugs
taken from the operator's own machine — two of them introduced as invented
examples, with invented names and real digests — and one named a personal
project unrelated to any of this. They reached the internal remote before
anyone noticed, and removing them meant rewriting history.

So: every `<name>-<8 hex>` in the tree must use a digest from `SYNTHETIC`.

WHAT THIS TEST IS, AND WHAT IT IS NOT. It is a tripwire, not a certificate.
It proves that no identifier here uses a digest outside the approved set. It
CANNOT prove a digest is invented — a real workspace this machine has never
heard of, hashing to something not in `SYNTHETIC`, fails this test for the
right reason, but a real digest someone adds to `SYNTHETIC` passes it for the
wrong one. The allowlist is the thing a reviewer must actually look at.

It deliberately does NOT read `~/.claude/connector/peers.json`. That file is
machine-local and differs per box, so a test keyed on it passes or fails
depending on where it runs — and the version that matters is CI, where the
file is absent and the check would silently become vacuous. An allowlist
needs no external state and behaves identically everywhere.
"""

import re
import subprocess
import unittest
from pathlib import Path

_REPO = Path(__file__).absolute().parents[2]

#: Digests approved for use in fixtures and documentation. Every one is
#: visibly not a hash: hex words, or a counting sequence. Adding to this list
#: is a REVIEWED act — the whole protection is that a real digest cannot be
#: here without someone putting it here on purpose.
SYNTHETIC = frozenset({
    "0badcafe",   # MixedCase_repo — uppercase + underscore shape
    "c0ffee01",   # snake_case_lab — underscore shape
    "deadbeef",   # already-legal — needs no derivation
    "1a2b3c4d",   # My_Repo — the docs' illustrative pair
})

#: Prefixes whose trailing 8 characters are protocol ids rather than digests.
#: `req-00000001` is a submit-request id and matches the slug shape by
#: coincidence — all-digits is valid hex.
PROTOCOL_PREFIXES = ("req-", "notice-", "peer-")

#: `<name>-<8 hex>` at a word boundary. A 32-hex notice id does not match:
#: the boundary after 8 characters fails when a ninth hex digit follows.
_SLUG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]*(?:-[A-Za-z0-9_.]+)*-([0-9a-f]{8})\b")


def _tracked_files():
    """Every file git tracks. Tracked rather than walked, so an untracked
    scratch file cannot fail the suite and — more to the point — so anything
    that WOULD be published is what gets checked."""
    out = subprocess.run(["git", "-C", str(_REPO), "ls-files", "-z"],
                         capture_output=True, text=True)
    return [_REPO / p for p in out.stdout.split("\0") if p]


def _scan(allow=SYNTHETIC):
    """`{identifier: [files]}` for every slug-shaped token whose digest is not
    in `allow`.

    `allow` is a parameter so a test can run the REAL scanner over the REAL
    tree with an empty allowlist and assert it finds the fixtures. Without
    that, a scanner broken into reading nothing returns `{}` — identical to a
    clean tree, and the suite stays green."""
    found = {}
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable: no identifiers to find
        for match in _SLUG_RE.finditer(text):
            token, digest = match.group(0), match.group(1)
            if token.startswith(PROTOCOL_PREFIXES) or digest in allow:
                continue
            found.setdefault(token, []).append(
                str(path.relative_to(_REPO)))
    return found


class NoLiveIdentifiersTests(unittest.TestCase):
    def test_no_tracked_file_uses_a_digest_outside_the_approved_set(self):
        found = _scan()
        if found:
            lines = "\n".join(
                f"    {tok}  in {', '.join(sorted(set(files)))}"
                for tok, files in sorted(found.items()))
            self.fail(
                "identifier(s) with a digest outside SYNTHETIC:\n" + lines +
                "\n\n  A `<name>-<8 hex>` digest identifies a real workspace "
                "whatever name precedes it.\n"
                "  Renaming the word in front does NOT sanitise it.\n"
                "  Use a digest from SYNTHETIC, or add one — deliberately, and "
                "only if it is invented.")

    def test_the_scanner_actually_reads_the_tree(self):
        """A scanner that reads nothing returns `{}`, which is exactly what a
        clean tree returns. So run the REAL scanner over the REAL tree with
        nothing allowed: it must find the synthetic fixtures, in the file that
        holds them.

        An earlier version of this test checked `_tracked_files()` and the
        regex separately and never called `_scan`. Breaking `_scan` to iterate
        an empty list left it green — the same defect this whole file is about,
        one level up."""
        found = _scan(allow=frozenset())

        self.assertTrue(found, "the scanner found nothing at all — it is not "
                               "reading the tree")
        digests = {_SLUG_RE.search(tok).group(1) for tok in found}
        self.assertTrue(
            digests <= SYNTHETIC,
            f"non-synthetic digests present in the tree: {digests - SYNTHETIC}")
        where = {f for files in found.values() for f in files}
        self.assertIn("router/tests/test_console.py", where,
                      "the file holding the slug fixtures was not scanned")

    def test_a_planted_non_synthetic_digest_is_caught(self):
        """The tripwire fires. Without this, `_scan` returning `{}` because it
        is broken is indistinguishable from `{}` because the tree is clean —
        and a tripwire nobody has seen trip is a decoration.

        THE EXAMPLE IS ASSEMBLED AT RUNTIME AND APPEARS NOWHERE AS A LITERAL.
        A test that demonstrates this scanner must contain something the
        scanner rejects, which would fail the scan of this very file — so the
        token is built from fragments and the whole string exists only in
        memory.

        Two corrections are baked in here, both of which cost something. The
        first version used a REAL digest, on the reasoning that catching a
        real one is the point. It is not: the mechanism is "digest outside the
        allowlist", and an invented digest exercises it identically — while a
        real one puts the exact thing this file exists to exclude INTO the
        repository, in the file whose job is to prevent that. It survived one
        commit because `git ls-files` cannot see an untracked new file, so the
        scanner was blind to itself until the moment it was committed.

        The second version used an invented digest, but written out in full,
        which the scanner then flagged in this file — correctly. Hence
        fragments."""
        digest = "f00d" + "face"
        planted = "invented_example" + "-" + digest

        self.assertNotIn(digest, SYNTHETIC)
        self.assertFalse(planted.startswith(PROTOCOL_PREFIXES))

        # Exactly what `_scan` does to a file's text, on a string that is
        # never written to disk and never appears here as a literal.
        hits = [m.group(0) for m in _SLUG_RE.finditer(f"SLUGS = ['{planted}']")
                if m.group(1) not in SYNTHETIC
                and not m.group(0).startswith(PROTOCOL_PREFIXES)]
        self.assertEqual(hits, [planted])

    def test_this_file_does_not_itself_trip_the_scanner(self):
        """The scanner scans every tracked file, including this one. A
        demonstration written as a literal would fail the scan it
        demonstrates — which is how the previous two versions of the test
        above were caught."""
        found = _scan()
        mine = [tok for tok, files in found.items()
                if any(f.endswith("test_no_live_identifiers.py") for f in files)]
        self.assertEqual(mine, [], f"this file carries {mine}")

    def test_protocol_ids_are_not_mistaken_for_slugs(self):
        """`req-00000001` matches the slug shape by coincidence — all-digits
        is valid hex — and there are dozens of them. Excluded by prefix
        rather than by widening the pattern, so the pattern stays strict."""
        hits = [m.group(0) for m in _SLUG_RE.finditer("req-00000001 notice-00000002")
                if not m.group(0).startswith(PROTOCOL_PREFIXES)]
        self.assertEqual(hits, [])

    def test_a_32_hex_notice_id_does_not_match(self):
        """The real ids this router mints are 128-bit hex. They must not trip
        the scanner, and they do not, because the word boundary after eight
        characters fails when a ninth hex digit follows."""
        self.assertIsNone(
            _SLUG_RE.search("notice-b250c1269316f448fe438f1c2ea3cff4"))


if __name__ == "__main__":
    unittest.main()
