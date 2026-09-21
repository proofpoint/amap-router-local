"""router/binding.py — the security core: recipient resolution.

Two independent decisions live here, and nowhere else:

  - `resolve_binding`: for a reply, bind the recipient from the router's
    OWN private delivery ledger — never from anything in any agent's
    namespace. This is the exfil-test crux (SCOPE.md "Trust story"),
    transplanted from `gate/outbound.py:resolve_binding`'s discipline
    (read the gate's own staged copy, never the scope-volume copy the
    agent can rewrite).
  - `check_cold`: mutual-allowlist check for a cold send. `ALLOW_ANY`
    never waives mutuality on the OTHER side — it only ever relaxes the
    side that declares it.
  - `check_peer_edge`: the peer lane's one lookup — is the drained sender in
    the recipient's `peer_senders`. Directed, no wildcard, no mutuality; the
    loader guarantees no ordered pair is ever both an edge and a mutual
    mail pair, so the two checks can never both say yes.

Router-private state layout under `state_dir` (validated at config load to
be unreachable from every instance namespace — see `config.py`):

    state_dir/
      <recipient-instance>/
        delivered/notice-<notice_id>.json   # ledger record (see below)
        held/req-<req_id>.json              # non-mutual cold sends, operator-visible
      <sender-instance>/
        results/<req_id>.json               # idempotency anchor (see outbound.py)

Ledger record shape (JSON):
    {"notice_id", "from_instance", "from_address", "to_instance", "ts",
     "req_id", "message_id", "transport", ["tree"], ["authored_by"]}

`tree` names the inbound tree the notice was placed in — `"inbox"` (mail)
or `"peer"` — and is OPTIONAL ON READ: a record without it predates the
peer lane and can only be mail. Readers therefore test `tree == "peer"`
and never `tree == "inbox"`, so an absent value is read correctly without
being backfilled. Unlike `transport` the writer parameter has a default
(`None` = omit the key): "anything but peer is mail" is a safe reading
rule, so a mail backend that never learned the field still writes a
record that reads right, and a downstream runtime already calling
`record_delivery` does not break. `deliver.py` passes it explicitly on
both lanes anyway. `authored_by: "router"` marks a notice this router
authored itself (a DSN); such a record has `from_instance: null`, so a
reply to it fails closed as `unresolved_reply` with no new code, and the
exposure scan (`exposure.py`) knows the notice was not external mail.

`transport` names the DELIVERY LEG this notice arrived over — nothing to
do with this repo's "attachment transport" vocabulary (`config.py`,
`attachments.py`), which is about carrying bytes for one message. It is
OPTIONAL ON READ: records written before the field existed do not carry
it, and they are still valid. A missing `transport` means "this record
cannot answer", NEVER "local" — no reader may backfill it, because under
a runtime with a second delivery leg that default would be an active lie
about how the original actually arrived. Writers must supply a real
string, and `record_delivery` has NO DEFAULT for it: a default of
`"local"` would invent, on the writer's side, exactly the answer readers
are forbidden to backfill — silently correct in this transport-free
router and an active lie in a runtime with a second leg. A caller that
forgets it gets a TypeError at the call site instead of a wrong ledger
record. Passing `None` writes a JSON `null`, which is the same
absent/empty collapse in a third form.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from .config import ALLOW_ANY, RouterConfig

# Verbatim from `gate/outbound.py:_NOTICE_ID_RE` — the notice-id an agent
# supplies in `in_reply_to` is agent-controlled and becomes part of a
# filesystem path; sanitize before it ever touches one.
_NOTICE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def ledger_dir(state_dir: Path, recipient_instance: str) -> Path:
    return state_dir / recipient_instance / "delivered"


def ledger_path(state_dir: Path, recipient_instance: str, notice_id: str) -> Path:
    return ledger_dir(state_dir, recipient_instance) / f"notice-{notice_id}.json"


def record_delivery(
    state_dir: Path,
    *,
    notice_id: str,
    from_instance: Optional[str],
    from_address: str,
    to_instance: str,
    ts: str,
    req_id: str,
    message_id: str,
    transport: str,
    tree: Optional[str] = None,
    authored_by: Optional[str] = None,
) -> bytes:
    """Build the ledger record bytes for one delivered notice. Writing them
    to disk (atomically, BEFORE the notice itself) is `deliver.py`'s job —
    this function only builds the bytes so the write-ordering is explicit
    at the call site.

    `transport` records the delivery leg the notice went out over, so a
    later reply can be routed back over the same one from router-private
    state rather than from anything the agent supplies. This repo knows
    exactly one leg and so names exactly one value, `"local"`; the string
    is recorded as given and never validated against a set, because which
    other values are legal is not this repo's to know.

    `tree` and `authored_by` are written only when given (module docstring:
    absent `tree` reads as mail; absent `authored_by` reads as agent-
    authored)."""
    record = {
        "notice_id": notice_id,
        "from_instance": from_instance,
        "from_address": from_address,
        "to_instance": to_instance,
        "ts": ts,
        "req_id": req_id,
        "message_id": message_id,
        "transport": transport,
    }
    if tree is not None:
        record["tree"] = tree
    if authored_by is not None:
        record["authored_by"] = authored_by
    return json.dumps(record, sort_keys=True).encode("utf-8")


def read_ledger_record(
    state_dir: Path, sender_instance: str, in_reply_to: str
) -> Optional[dict]:
    """Like `resolve_binding`, but returns the FULL ledger record (not just
    `from_instance`) when it resolves — used by `outbound.py` to carry the
    original `message_id` forward as `message.in_reply_to` enrichment
    (`deliver.py`'s `reply_to_record`). Same fail-closed rules as
    `resolve_binding`: `None` on anything not cleanly resolved."""
    if not isinstance(in_reply_to, str) or not _NOTICE_ID_RE.match(in_reply_to):
        return None
    path = ledger_path(state_dir, sender_instance, in_reply_to)
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def resolve_binding(state_dir: Path, sender_instance: str, in_reply_to: str) -> Optional[str]:
    """Resolve an agent-supplied `in_reply_to` to the instance that
    originally sent the notice `sender_instance` claims to be replying to.

    Reads ONLY `state_dir/<sender_instance>/delivered/notice-<id>.json` —
    the router's own private ledger, written by `deliver.py` at delivery
    time. NEVER reads anything inside any agent namespace: the agent's
    inbox copy of a notice is agent-writable (Posture A) and cannot be
    trusted to bind a recipient (`test_forged_notice.py` is the proof).

    Returns the recorded `from_instance`, or `None` (fail closed) if:
    `in_reply_to` fails the charset check, no ledger record exists for it
    under `sender_instance`, or the record is unreadable/malformed.
    """
    doc = read_ledger_record(state_dir, sender_instance, in_reply_to)
    if doc is None:
        return None
    from_instance = doc.get("from_instance")
    if not isinstance(from_instance, str) or not from_instance:
        return None
    return from_instance


def check_cold(cfg: RouterConfig, sender: str, recipient: str) -> bool:
    """Mutual allowlist check for a cold (non-reply) send: True iff
    `recipient` is in `sender`'s peers (or `sender` declares `ALLOW_ANY`)
    AND `sender` is in `recipient`'s peers (or `recipient` declares
    `ALLOW_ANY`). `ALLOW_ANY` only ever relaxes the side that declares it
    — it never waives mutuality on the other side."""
    sender_cfg = cfg.instances.get(sender)
    recipient_cfg = cfg.instances.get(recipient)
    if sender_cfg is None or recipient_cfg is None:
        return False
    sender_allows = recipient in sender_cfg.peers or ALLOW_ANY in sender_cfg.peers
    recipient_allows = sender in recipient_cfg.peers or ALLOW_ANY in recipient_cfg.peers
    return sender_allows and recipient_allows


def check_peer_edge(cfg: RouterConfig, sender: str, recipient: str) -> bool:
    """The peer lane's authorisation check: True iff `sender` is named in
    `recipient`'s `peer_senders`. Directed — nothing about the reverse
    pair is consulted — and never `ALLOW_ANY` (the loader refuses it).
    Both must be configured instances; anything else is False. The reverse
    edge a REPLY may travel without this returning True is decided in
    `outbound._drain_reply` from the router's own ledger, never here."""
    recipient_cfg = cfg.instances.get(recipient)
    if recipient_cfg is None or sender not in cfg.instances:
        return False
    return sender in recipient_cfg.peer_senders
