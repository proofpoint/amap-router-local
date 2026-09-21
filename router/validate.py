"""router/validate.py — hand-rolled AMAP §3 submit-request validation.

Deliberately does NOT import `agent-mailbox-protocol/fixtures/validate.py`
into the shipped code path (no cross-repo import fragility in the router
itself). Agreement with AMAP is instead *proven in tests*
(`tests/test_validate_fixtures.py`): every fixture under
`agent-mailbox-protocol/fixtures/{valid,invalid}/request-*.json` is run
through `validate_request` here and must land on the expected side.

This module checks SHAPE only — the same thing the AMAP schema checks. It
never inspects policy (allowlists, binding, attachment transport support);
those live in `router/outbound.py`. `validate_request` never guesses or
repairs a malformed document: it returns `(ok, reason_code, detail)` and
lets the caller decide what a failure means for the result file.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Tuple

# Mirror `submit-request.schema.json`'s patterns. One deliberate
# difference in spelling, none in meaning: these anchor `\Z`, not `$`.
# In Python (as in Java and .NET) `$` ALSO matches immediately before a
# trailing newline, so `^[A-Za-z0-9_][A-Za-z0-9_.-]*$` accepts
# `"00000001\n"` — a header-injection payload the schema means to refuse.
# The schema spells that intent as `(?!\n)$`, the portable form for JSON
# Schema's ECMA-262 dialect; `\Z` is the direct Python equivalent, and
# `fixtures/invalid/request-reqid-trailing-newline.json` pins it.
_REQ_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}\Z")

# A bare addr-spec: no display name, comment, quoted local part, address
# list, or folding whitespace. Deliberately narrower than RFC 5322 —
# those forms are what make allowlist evaluation non-mechanical, and
# `"allowed@ok.com" <evil@bad.com>` is the spoof they buy: a policy layer
# matching on the wrong half of that string sends to `evil@bad.com`.
_ADDR_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\Z")

# No C0 control characters and no DEL, anywhere in the string — not just
# at the end. A `\r\n` inside a subject, filename, media type or
# Message-ID terminates the header it lands in and lets the agent append
# headers of its own (`Bcc: exfil@attacker.example`). Nothing downstream
# re-decides this: by the time such a string reaches a MIME builder the
# injection has already happened, which is why it fails here.
_NO_CTL_RE = re.compile(r"^[^\x00-\x1f\x7f]*\Z")

_TOP_KEYS = {"contract_version", "req_id", "agent_id", "ts", "in_reply_to", "draft"}
_DRAFT_KEYS = {"to", "cc", "subject", "body_text", "reply_to_message_id", "attachments"}
_ATTACHMENT_KEYS = {"filename", "media_type", "size_bytes", "sha256"}

REASON_UNSUPPORTED_VERSION = "unsupported_contract_version"
REASON_MALFORMED = "malformed_request"

Result = Tuple[bool, Optional[str], Optional[str]]


def _fail(reason: str, detail: str) -> Result:
    return False, reason, detail


def _ok() -> Result:
    return True, None, None


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) >= 1


def _is_int(v: Any) -> bool:
    # JSON booleans are a `bool` subclass of `int` in Python — exclude them,
    # same distinction the AMAP fixtures/validate.py engine makes.
    return isinstance(v, int) and not isinstance(v, bool)


def _validate_attachment(item: Any, idx: int) -> Result:
    if not isinstance(item, dict):
        return _fail(REASON_MALFORMED, f"draft.attachments[{idx}]: expected an object")
    unknown = set(item) - _ATTACHMENT_KEYS
    if unknown:
        return _fail(
            REASON_MALFORMED,
            f"draft.attachments[{idx}]: unknown key(s) {sorted(unknown)}",
        )
    for req in ("filename", "media_type", "size_bytes", "sha256"):
        if req not in item:
            return _fail(
                REASON_MALFORMED, f"draft.attachments[{idx}]: missing required '{req}'"
            )
    if not _is_nonempty_str(item["filename"]) or not _NO_CTL_RE.match(item["filename"]):
        return _fail(
            REASON_MALFORMED,
            f"draft.attachments[{idx}].filename: expected a non-empty string "
            "with no control characters",
        )
    if not _is_nonempty_str(item["media_type"]) or not _NO_CTL_RE.match(item["media_type"]):
        return _fail(
            REASON_MALFORMED,
            f"draft.attachments[{idx}].media_type: expected a non-empty string "
            "with no control characters",
        )
    if not _is_int(item["size_bytes"]) or item["size_bytes"] < 0:
        return _fail(
            REASON_MALFORMED, f"draft.attachments[{idx}].size_bytes: expected an integer >= 0"
        )
    if not _is_str(item["sha256"]) or not _SHA256_RE.match(item["sha256"]):
        return _fail(
            REASON_MALFORMED,
            f"draft.attachments[{idx}].sha256: expected 64 lowercase hex chars",
        )
    return _ok()


def _validate_draft(draft: Any) -> Result:
    if not isinstance(draft, dict):
        return _fail(REASON_MALFORMED, "draft: expected an object")
    unknown = set(draft) - _DRAFT_KEYS
    if unknown:
        return _fail(REASON_MALFORMED, f"draft: unknown key(s) {sorted(unknown)}")
    for req in ("to", "subject", "body_text"):
        if req not in draft:
            return _fail(REASON_MALFORMED, f"draft: missing required '{req}'")

    to = draft["to"]
    if not isinstance(to, list) or len(to) < 1:
        return _fail(REASON_MALFORMED, "draft.to: expected a non-empty array")
    if not all(_is_str(t) for t in to):
        return _fail(REASON_MALFORMED, "draft.to: every entry must be a string")
    for i, t in enumerate(to):
        if not _ADDR_RE.match(t):
            return _fail(
                REASON_MALFORMED,
                f"draft.to[{i}]: expected one bare addr-spec, got {t!r}",
            )

    if "cc" in draft:
        cc = draft["cc"]
        if not isinstance(cc, list) or not all(_is_str(c) for c in cc):
            return _fail(REASON_MALFORMED, "draft.cc: expected an array of strings")
        for i, c in enumerate(cc):
            if not _ADDR_RE.match(c):
                return _fail(
                    REASON_MALFORMED,
                    f"draft.cc[{i}]: expected one bare addr-spec, got {c!r}",
                )

    if not _is_str(draft["subject"]) or not _NO_CTL_RE.match(draft["subject"]):
        return _fail(
            REASON_MALFORMED, "draft.subject: expected a string with no control characters"
        )
    if not _is_str(draft["body_text"]):
        return _fail(REASON_MALFORMED, "draft.body_text: expected a string")

    if "reply_to_message_id" in draft:
        rtmi = draft["reply_to_message_id"]
        if rtmi is not None and (not _is_str(rtmi) or not _NO_CTL_RE.match(rtmi)):
            return _fail(
                REASON_MALFORMED,
                "draft.reply_to_message_id: expected a string with no control "
                "characters, or null",
            )

    if "attachments" in draft:
        attachments = draft["attachments"]
        if not isinstance(attachments, list):
            return _fail(REASON_MALFORMED, "draft.attachments: expected an array")
        for idx, item in enumerate(attachments):
            ok, reason, detail = _validate_attachment(item, idx)
            if not ok:
                return ok, reason, detail

    return _ok()


def validate_request(doc: Any) -> Result:
    """Validate a parsed submit-request document (already `json.loads`'d —
    JSON-parse failures are the caller's concern, e.g. `router/outbound.py`
    reports those as `rejected`/`malformed_request` before ever calling
    here). Returns `(ok, reason_code, detail)`; `reason_code`/`detail` are
    `None` when `ok` is True."""
    if not isinstance(doc, dict):
        return _fail(REASON_MALFORMED, "request: expected a JSON object")

    unknown = set(doc) - _TOP_KEYS
    if unknown:
        return _fail(REASON_MALFORMED, f"request: unknown key(s) {sorted(unknown)}")

    # §7: contract_version is required; anything other than exactly "2"
    # (absent, lower major, higher major) fails closed. This is the schema's
    # `const: "2"` check plus the fail-closed-on-higher-major obligation
    # from the prose — both collapse to the same wire check.
    cv = doc.get("contract_version")
    if cv != "2":
        return _fail(
            REASON_UNSUPPORTED_VERSION,
            f"contract_version: expected \"2\", got {cv!r}",
        )

    if "req_id" not in doc:
        return _fail(REASON_MALFORMED, "request: missing required 'req_id'")
    req_id = doc["req_id"]
    if not _is_nonempty_str(req_id) or not _REQ_ID_RE.match(req_id):
        return _fail(REASON_MALFORMED, f"req_id: invalid {req_id!r}")

    # No fixture pins these three, but the schema constrains them the same
    # way it constrains `subject`, and this module exists to mirror it.
    if "agent_id" in doc and (
        not _is_nonempty_str(doc["agent_id"]) or not _NO_CTL_RE.match(doc["agent_id"])
    ):
        return _fail(
            REASON_MALFORMED,
            "agent_id: expected a non-empty string with no control characters",
        )
    if "ts" in doc and (
        not _is_nonempty_str(doc["ts"]) or not _NO_CTL_RE.match(doc["ts"])
    ):
        return _fail(
            REASON_MALFORMED, "ts: expected a non-empty string with no control characters"
        )
    if "in_reply_to" in doc and (
        not _is_str(doc["in_reply_to"]) or not _NO_CTL_RE.match(doc["in_reply_to"])
    ):
        return _fail(
            REASON_MALFORMED, "in_reply_to: expected a string with no control characters"
        )

    if "draft" not in doc:
        return _fail(REASON_MALFORMED, "request: missing required 'draft'")
    ok, reason, detail = _validate_draft(doc["draft"])
    if not ok:
        return ok, reason, detail

    return _ok()
