"""router/peerverify.py — verifying a signed peer candidate: checks 1, 3, 4, 5.

`verify` runs the peer-origin profile's checks in their order, through the
plugin's peer codec (`router/peerlane.py`): check 1 (exactly one signed
field, its grammar), then the caller's CHECK 2 (`known`: a statement this
runtime already holds is a duplicate, even after its key expired or was
removed), then checks 3, 4 and 5 (the key, valid at `now`; the signature;
the statement's encoding, schema and values). Every refusal is the codec's
cause token, unchanged.

`known` is REQUIRED, with no default, so a caller cannot skip check 2 by
omission. The candidate journal and replay index that answer it belong to
a later unit; until then a caller supplies its own.

A LOCAL crypto fault (`BackendError`) is never a cause: it propagates, and
the caller holds and retries. Any exception that is not exactly one of the
plugin's classes, with a reason in the codec's set, propagates too: it is a
bug, never a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Tuple, Union

from . import peerlane


@dataclass(frozen=True)
class Verified:
    """Checks 1 and 3-5 passed and check 2 found nothing: the statement's
    `kind`, its decoded `payload`, and the configured `key` that signed it."""
    kind: str
    payload: Any
    key: Any


@dataclass(frozen=True)
class Refused:
    """A check refused the candidate. `cause` is the codec's token
    (`duplicate` for check 2)."""
    cause: str


CHECK2_DUPLICATE = "duplicate"


def verify(fields: Iterable[Tuple[str, Any]], *, delegation: "peerlane.Delegation", now: Any,
           known: Callable[[str, bytes], bool]) -> Union[Verified, Refused]:
    """The verdict on a candidate whose verifier-view header `fields` are
    given (module docstring). `now` is an aware datetime."""
    codec = delegation.codec
    try:
        kind, k, statement, signature = codec.check1(list(fields))
    except Exception as e:  # noqa: BLE001 -- classified exactly
        if peerlane.error_kind(delegation, e) == "CodecError":
            return Refused(e.reason)
        raise
    if known(kind, statement):
        return Refused(CHECK2_DUPLICATE)
    try:
        kind, payload, key = codec.verify_checked(kind, k, statement, signature,
                                                  delegation.key_table, delegation.verifier, now)
    except Exception as e:  # noqa: BLE001 -- classified exactly
        if peerlane.error_kind(delegation, e) == "CodecError":
            return Refused(e.reason)
        raise
    return Verified(kind, payload, key)
