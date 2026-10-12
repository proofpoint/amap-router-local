"""router/hoplink.py — this router's side of the hop transport: the sender.

A request bound for another host is handed to the transport plugin as a
HANDOVER DOCUMENT, written into one generation's hop tree by that
generation's sender (`transport.TransportPort`, API (3, 0)). This module
owns what this router decides about that, and nothing the plugin decides:

  * THE ENCODING. The handover is canonical JSON (sorted keys, compact
    separators, UTF-8, `ensure_ascii` off, integers only); the plugin
    re-encodes it and refuses any difference. `canonical` is the one
    encoder, and it refuses what the plugin would (a non-integer number, a
    lone surrogate, a non-string key) BEFORE a transport id is allocated.
  * THE BEGIN-TIME CHECKS (`check_begin`). A request the plugin would refuse
    for a reason no retry can change must be answered at once, with nothing
    allocated, or it stays in flight forever: more than `MAX_RECIPIENTS`
    raw recipients; an address over its octet bounds; a request whose
    canonical bytes, with the newline the tree file adds, exceed the hop's
    request cap.
  * THE DOCUMENT FLOOR (`document_floor`). `hop.caps.document` must hold the
    largest handover an accepted request can make: the largest request, the
    largest attachment array the three attachment caps admit (`attach_array_max`,
    exact), and the fixed members at their maxima. Checked at config load.

Nothing here opens a file or calls a plugin.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, Iterable, List, Optional

#: The handover document's schema (the plugin's `write_request`).
HANDOVER_SCHEMA = "amap-hop-handover/1"
#: The only envelope kind this router hands over. `peer` and `control` are
#: signed kinds; a request of any other kind is refused `no_route`.
MAIL_KIND = "mail"
#: The most raw `to` + `cc` (+ `bcc`) entries one request may name,
#: duplicates counted (contract amendment E12, `too_many_recipients`).
MAX_RECIPIENTS = 100
#: RFC 5321's limits, in octets: a whole address, its local part, its domain.
ADDRESS_MAX, LOCAL_MAX, DOMAIN_MAX = 254, 64, 255
#: The most digits a transport id, and so `settled_through`, may have.
TRANSPORT_ID_MAX_DIGITS = 18

#: The reason codes this module answers with (all existing ones).
REASON_TOO_MANY_RECIPIENTS = "too_many_recipients"
REASON_MALFORMED_REQUEST = "malformed_request"

#: The bare addr-spec the envelope's `from_address` must match (Q1): ASCII,
#: no `<` or `>`.
Q1_ADDRESS_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\Z")


class Refused(Exception):
    """A request answered at begin, before anything is allocated: `outcome`,
    `reason_code` and `detail` are its Result's."""

    def __init__(self, outcome: str, reason_code: str, detail: str):
        super().__init__(f"{outcome}/{reason_code}: {detail}")
        self.outcome, self.reason_code, self.detail = outcome, reason_code, detail


def _check_integers_only(value: Any, where: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return
    if isinstance(value, float):
        raise ValueError(f"{where}: a non-integer number is not representable")
    if isinstance(value, list):
        for i, v in enumerate(value):
            _check_integers_only(v, f"{where}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"{where}: a non-string key")
            _check_integers_only(v, f"{where}.{k}")
        return
    raise ValueError(f"{where}: a {type(value).__name__} is not JSON")


def canonical(value: Any) -> bytes:
    """`value` in the handover's canonical encoding, or `ValueError` for
    anything that encoding refuses: a non-integer number, a non-string key,
    a lone surrogate (it cannot be UTF-8)."""
    _check_integers_only(value)
    text = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValueError(f"not encodable as UTF-8 ({e.reason})") from None


def address_octets_problem(address: Any) -> Optional[str]:
    """Why `address` breaks RFC 5321's octet limits, or None. The local part
    is everything before the LAST `@`."""
    if not isinstance(address, str):
        return "not a string"
    try:
        raw = address.encode("utf-8")
    except UnicodeEncodeError:
        return "not encodable as UTF-8"
    if len(raw) > ADDRESS_MAX:
        return f"{len(raw)} octets, over {ADDRESS_MAX}"
    local, at, domain = raw.rpartition(b"@")
    if not at:
        return "no '@'"
    if len(local) > LOCAL_MAX:
        return f"a local part of {len(local)} octets, over {LOCAL_MAX}"
    if len(domain) > DOMAIN_MAX:
        return f"a domain of {len(domain)} octets, over {DOMAIN_MAX}"
    return None


def from_address_problem(address: Any) -> Optional[str]:
    """Why `address` cannot be an envelope's `from_address`, or None: the
    octet limits, then the Q1 pattern."""
    why = address_octets_problem(address)
    if why is not None:
        return why
    if not Q1_ADDRESS_RE.fullmatch(address):
        return "not a bare ASCII addr-spec"
    return None


def raw_recipients(draft: Dict[str, Any]) -> List[Any]:
    """Every raw entry of `to`, `cc` and `bcc`, in that order, duplicates
    kept: E12 counts what the agent wrote."""
    out: List[Any] = []
    for key in ("to", "cc", "bcc"):
        value = draft.get(key)
        if isinstance(value, list):
            out.extend(value)
        elif value is not None:
            out.append(value)
    return out


def request_bytes_len(request: Dict[str, Any]) -> int:
    """The bytes the request occupies in the hop tree: its canonical
    encoding plus the newline the plugin's tree file adds, which is what the
    plugin compares with `caps.request`."""
    return len(canonical(request)) + 1


def check_begin(request: Dict[str, Any], *, request_cap: int) -> None:
    """The begin-time checks, in order; `Refused` for the first that fails:
    the recipient count (E12), each recipient's octets (C-b), the encoding,
    then the request cap."""
    draft = request.get("draft") if isinstance(request.get("draft"), dict) else {}
    raw = raw_recipients(draft)
    if len(raw) > MAX_RECIPIENTS:
        raise Refused("rejected", REASON_TOO_MANY_RECIPIENTS,
                      f"{len(raw)} recipients (duplicates counted); at most {MAX_RECIPIENTS}")
    for entry in raw:
        why = address_octets_problem(entry)
        if why is not None:
            raise Refused("rejected", REASON_MALFORMED_REQUEST, f"a recipient: {why}")
    try:
        size = request_bytes_len(request)
    except ValueError as e:
        raise Refused("rejected", REASON_MALFORMED_REQUEST,
                      f"the request cannot be handed over: {e}") from None
    if size > request_cap:
        raise Refused("rejected", REASON_MALFORMED_REQUEST,
                      f"the request is {size} bytes; it exceeds the hop request cap "
                      f"({request_cap})")


def attach_array_max(count_cap: int, file_cap: int, total_cap: int) -> int:
    """The EXACT longest canonical encoding of the handover's `attachments`
    member, brackets excluded: `N` standard-base64 strings, at most
    `count_cap` of them, each decoding to at most `file_cap` bytes, together
    at most `total_cap`. Zero-byte attachments are valid, so every slot may
    be present. With `k = min(N, T)` files able to carry a byte, the most
    4-byte base64 quanta is `C = min(k * ceil(F / 3), floor((min(T, k*F) +
    2k) / 3))`, and the encoding is `4C` plus `2N` quotes and `N - 1`
    commas."""
    if count_cap <= 0:
        return 0
    k = min(count_cap, total_cap) if file_cap > 0 else 0
    quanta = 0 if k == 0 else min(k * math.ceil(file_cap / 3),
                                  (min(total_cap, k * file_cap) + 2 * k) // 3)
    return 4 * quanta + 3 * count_cap - 1


def fixed_overhead(version_write: int) -> int:
    """Every byte of the canonical handover that is neither the request nor
    the attachment array's contents, at its maximum: the member names, the
    brackets, the schema string, `settled_through` at its most digits, and
    the envelope with a `from_address` of `ADDRESS_MAX` octets. Built, not
    counted by hand."""
    skeleton = {
        "attachments": [],
        "envelope": {"from_address": "a" * (ADDRESS_MAX - 2) + "@b",
                     "hop_contract": version_write, "kind": MAIL_KIND},
        "request": None,
        "schema": HANDOVER_SCHEMA,
        "settled_through": 10 ** TRANSPORT_ID_MAX_DIGITS - 1,
    }
    return len(canonical(skeleton)) - len(b"null")


def document_floor(*, request_cap: int, count_cap: int, file_cap: int, total_cap: int,
                   version_write: int) -> int:
    """The smallest `caps.document` that holds every handover an accepted
    request can make. The request member is at most `request_cap - 1`
    bytes: the plugin counts the tree file's newline against the cap."""
    return (request_cap - 1) + attach_array_max(count_cap, file_cap, total_cap) \
        + fixed_overhead(version_write)


def build_handover(request: Dict[str, Any], *, from_address: str, version_write: int,
                   attachments: Iterable[str], settled_through: int) -> bytes:
    """The handover document's canonical bytes. `attachments` are standard
    base64 strings in descriptor order. `ValueError` for anything the
    encoding refuses."""
    return canonical({
        "attachments": list(attachments),
        "envelope": {"from_address": from_address, "hop_contract": version_write,
                     "kind": MAIL_KIND},
        "request": request,
        "schema": HANDOVER_SCHEMA,
        "settled_through": settled_through,
    })
