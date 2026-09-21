"""router/deliver.py — write one delivery into a recipient's namespace.

`deliver()` is called once per recipient (a cold send with multiple `to`/
`cc` addresses fans out into one call each — see `outbound.py`). It never
makes a policy decision; by the time it's called, `binding.py` has already
decided this recipient is allowed to receive this message.

Three writers live here since the peer lane (AMAP 3.1.0 peer-origin
profile), all built on one commit routine (`_place`) so the write order
below holds identically for every tree this router writes:

  - `deliver`             — MAIL lane: `inbox_root`, `kind: "deliver"`,
                            `mailbox: "inbox"`, `provenance: "internal"`.
                            Unchanged in every byte it writes.
  - `deliver_peer`        — PEER lane: `peer_root`, `kind: "peer"`,
                            `mailbox: "peer"`, NO `provenance` (redundant
                            with the tree, and the misreading the profile
                            forbids), `message.sender_exposure` stamped by
                            `exposure.assess`, ledger `tree: "peer"`, and an
                            audit line (`audit.EVENT_PEER_NOTICE_PLACED`).
                            Conforms to `DeliveryBackend`; whether a reply
                            travelled a declared edge or the reply window is
                            recomputed here for the audit line, never
                            passed in.
  - `deliver_router_notice` — a notice THIS ROUTER authors (today: the DSN
                            for a terminal peer outcome, `outcomes.py`) into
                            a recipient's MAIL tree, `from` = the router's
                            own address, ledgered with `from_instance: null`
                            + `authored_by: "router"` so a reply to it fails
                            closed as `unresolved_reply` and the exposure
                            scan never mistakes it for external mail. Not a
                            `DeliveryBackend` — there is no submit-request
                            behind it.

The audit line for a peer notice is written between the ledger record and
the notice — the same crash window the ledger already has (a record for a
notice that never appeared), and deliberately NOT after the notice: a
failure to log after the notice is visible would be reported to the sender
as a delivery failure for a message that was, in fact, delivered. Attachment
bytes, likewise, arrive already VERIFIED — `outbound.py` ran them through
`attachments.ingest_attachments` before `deliver()` is ever called; this
module's job is only to publish them (§5), never to re-verify them.

Write order is the commit-sentinel discipline from
`gate/inbound.py:_deliver_one` / `gate/transport.py`'s module docstring:
attachment blobs, THEN the message spool, THEN the router-private ledger
record, THEN the notice LAST. Blobs-before-message-doc is the AMAP v2.3.0
extension of the same discipline (§2 "Byte-absence is the gate"): the
message doc's `content_ref` is a grant into a sidecar dir that must
already be complete by the time anything could reference it. Ledger-
before-notice is deliberate (not just "ledger before returning"): it
closes the window where a recipient could see a notice and reply to it
before the ledger record that would resolve that reply exists. No wake is
needed or attempted — the connector's own watcher (`inbox-delivery`) picks up the notice
file (SCOPE.md "No wake to build").

Crash-midway trace for the attachment blobs specifically (requirement 6):
  (a) mid-blob — only an unreferenced `.tmp`-shaped turd under the sidecar
      dir; no ordinal name is ever visible as a complete file (`os.rename`
      is the only thing that ever produces the ordinal name).
  (b) after some/all blobs, before the message doc — orphan, complete
      blobs sit under an unguessable, never-announced `notice-<id>`; the
      deployed connector's `read_attachment` only ever reaches a sidecar
      via a message-spool doc it can open by id, and no id was ever
      handed to any agent, so these are unreachable, not merely unlinked.
  (c) after the message doc, before the notice — same as (b): a complete,
      correct message doc with correct `content_ref`s exists, but nothing
      relays it (the connector's watcher acts on the NOTICE file, not the
      message spool) — still unreachable.
  (d) after the notice — the whole delivery is complete and consistent.
At no point is a partially-written attachment ever visible as complete.
Orphaned sidecar dirs from cases (b)/(c) are swept the same way any other
mailbox content is: `router reset` (see this package's README, "Reset").
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

from . import attachments as attachments_mod
from . import audit as audit_mod
from . import binding
from . import exposure as exposure_mod
from .config import RouterConfig, address_for, router_address
from .util import atomic_write, mint_notice_id, utc_ts

#: The two inbound trees this router writes, as the ledger's `tree` names them.
TREE_INBOX = "inbox"
TREE_PEER = "peer"

KIND_DELIVER = "deliver"
KIND_PEER = "peer"


class PeerLaneUnavailable(Exception):
    """Raised by `deliver_peer`/`deliver_router_notice` when the recipient
    has no peer tree (namespace mode, or no `fleet_domain`) — a policy
    bug upstream, since the loader refuses every edge into such an
    instance; surfaced loudly rather than written into the wrong tree."""


class ExternalReplyUnsupported(Exception):
    """Raised by `deliver()` — the local backend — when `outbound.py` hands
    it an EXTERNAL reply (`recipient is None`, see `DeliveryBackend`). This
    router has no leg that reaches outside the box, so it refuses, fail
    closed, before touching any tree; `outbound._drain_reply` answers the
    request once as `queued_for_human`/`delivery_failed`, exactly as it
    answers any other backend failure. Only a runtime that injected a
    backend with an SMTP arm can carry such a reply."""


class DeliveryBackend(Protocol):
    """The callable shape `outbound.py` uses to hand one recipient's
    delivery to somebody. `deliver()` below is this router's only
    implementation, and it is what every code path uses unless a caller
    injects something else through `outbound.drain_instance`'s
    `deliver_backend` keyword.

    Any implementation MUST return all three of `notice_id`,
    `message_id` and `recipient` — `outbound.py` reads each of them
    unguarded when it composes the AMAP `result` document, so a missing
    key is a caller-visible failure, not a defaulted field. `recipient`
    is an INSTANCE NAME (the same string that was passed in), never an
    address: this router turns it back into an address itself.

    THE ONE EXTENSION (2026-09-03, an external reply): `recipient` is
    `None` when, and only when, `outbound._drain_reply` resolved the
    sender's `in_reply_to` to a ledger record that binds OUTSIDE this
    fleet — `from_instance: null` AND `transport == "smtp"` AND
    `origin == "external"` AND a non-empty `from_address`, all four read
    from the router-private ledger and none from the agent's draft. In that
    call `reply_to_record` is always that record, and the backend's
    recipient is `reply_to_record["from_address"]` — the record is the
    authority, never `draft.to`. A backend with no leg to the outside MUST
    raise (this module's `deliver()` raises `ExternalReplyUnsupported`);
    one that does carry it returns the same three keys, with `recipient`
    being the address it actually sent to (`outbound.py` reports the
    record's `from_address` to the sender either way, so the two must
    agree). No other call ever passes `None`: a reply bound to a fleet
    instance still arrives with that instance's name, whatever its record's
    `transport` says.
    """

    def __call__(
        self,
        cfg: RouterConfig,
        state_dir: Path,
        sender: str,
        recipient: Optional[str],
        request: Dict[str, Any],
        *,
        reply_to_record: Optional[Dict[str, Any]] = None,
        attachments: Optional[List[attachments_mod.VerifiedAttachment]] = None,
    ) -> Dict[str, str]:
        ...


PREVIEW_LEN = 200


def _collapse_control(s: str, limit: int) -> str:
    """Collapse control/newline chars to spaces and cap length — same
    defensive posture as the connector's own field sanitiser: a preview is
    interpolated into agent-visible text elsewhere, so it must read as one
    inert token, never as multiple lines an agent could mistake for a
    frame boundary."""
    cleaned = "".join(c if (c.isprintable() and c not in "\r\n") else " " for c in str(s))
    return cleaned[:limit]


def _attachment_descriptor(
    att: attachments_mod.VerifiedAttachment, index: int, notice_id: str, *, with_content_ref: bool,
) -> Dict[str, Any]:
    """One published attachment's descriptor, shared shape for the
    message doc and the deliver-notice (they differ only in
    `content_ref`, per SCOPE.md's resolution of the §2/§5 ambiguity — see
    that section for why). `size_bytes`/`sha256` here are ROUTER-VERIFIED
    (the asymmetry AMAP §5 notes relative to a real mail provider, where
    inbound `size_bytes` is only advisory)."""
    doc: Dict[str, Any] = {
        "filename": att.filename,
        "media_type": att.media_type,
        "size_bytes": att.size_bytes,
        "sha256": att.sha256,
        "disposition": "clean",
    }
    if with_content_ref:
        # NOT formatted here. `attachments.content_ref_for` is the single
        # source shared with `publish_attachment_blobs`, which names the
        # directory the bytes actually go in -- so the grant and the path
        # cannot drift. Formatting it locally is what let this router
        # emit a `notice-` prefix the published directory never had.
        doc["content_ref"] = attachments_mod.content_ref_for(notice_id, index)
    return doc


def _message_and_notice(
    *, notice_id: str, message_id: str, ts: str, kind: str, mailbox: str,
    from_address: str, to_address: str, subject: str, body_text: str,
    attachments: List[attachments_mod.VerifiedAttachment],
    in_reply_to: Optional[str], provenance: Optional[str],
    extra_message: Optional[Dict[str, Any]] = None,
) -> "tuple[Dict[str, Any], Dict[str, Any]]":
    """The two agent-visible documents for one placement: the message spool
    doc (`inbound-message.schema.json`, identical on both lanes — it does
    not carry `sender_exposure`) and the notice (`deliver-notice` or
    `peer-notice`, differing in `kind`, `mailbox`, `provenance` and the
    profile's optional members in `extra_message`)."""
    message_doc: Dict[str, Any] = {
        "contract_version": "2",
        "notice_id": notice_id,
        "body_text": body_text,
        "id": message_id,
        "date": ts,
        "from": from_address,
        "to": to_address,
        "subject": subject,
    }
    if attachments:
        message_doc["attachments"] = [
            _attachment_descriptor(att, i, notice_id, with_content_ref=True)
            for i, att in enumerate(attachments)
        ]

    message_field: Dict[str, Any] = {
        "id": message_id,
        "from": from_address,
        "subject": subject,
        "preview": _collapse_control(body_text, PREVIEW_LEN),
        "mailbox": mailbox,
    }
    if provenance is not None:
        message_field["provenance"] = provenance
    if in_reply_to:
        message_field["in_reply_to"] = in_reply_to
    if attachments:
        # `content_ref` IS emitted here, and this is a v3.0.0 correction
        # rather than a preference. It used to be omitted, deliberately:
        # emission is a MAY, and this router would not assert a grant at a
        # `notices/`-side path it did not populate -- it published under
        # `messages/`. contract.md §2 (v3.0.0) closed that fork the other
        # way: bytes are published ONLY at
        # `<tree>/notices/<notice-id>.attachments/<index>`, "the single
        # sidecar directory named in the layout tree above", and "there is
        # no second, message-specific sidecar directory". So the old
        # reason did not survive the move -- it was never a preference for
        # omission, only a refusal to point somewhere false, and once the
        # bytes are where the spec says, pointing is simply true.
        #
        # What that dissolves, recorded because the reasoning was load-
        # bearing for a year and is now gone: this notice used to be NOT
        # self-describing, and a strict §5-literal reader who saw
        # `disposition:"clean"` + a verified `sha256` with no grant could
        # misread it as "the runtime chose not to publish". The mitigation
        # was that the notice and the message-spool doc are a self-
        # describing PAIR -- the spool doc carried the grant and the
        # commit-sentinel order put it on disk first. The notice is now
        # self-describing ALONE. **Keep the commit-sentinel ordering
        # anyway** (blobs -> message spool -> ledger -> notice LAST): it
        # is correct on its own merits, it is what makes byte-absence the
        # gate, and it simply stops being load-bearing for THIS argument.
        message_field["attachments"] = [
            _attachment_descriptor(att, i, notice_id, with_content_ref=True)
            for i, att in enumerate(attachments)
        ]
    if extra_message:
        message_field.update(extra_message)
    notice_doc = {
        "contract_version": "2",
        "notice_id": notice_id,
        "ts": ts,
        "kind": kind,
        "message": message_field,
    }
    return message_doc, notice_doc


def _place(
    *, root: Path, tree_root: Path, state_dir: Path, recipient: str, notice_id: str,
    message_doc: Dict[str, Any], notice_doc: Dict[str, Any], ledger_bytes: bytes,
    attachments: List[attachments_mod.VerifiedAttachment],
    audit_line: Optional[bytes] = None, audit_instance: Optional[str] = None,
) -> None:
    """THE commit routine, for every tree this router writes: blobs ->
    message spool -> ledger -> [audit] -> notice LAST (module docstring).

    The recipient's root is agent-owned (posture A) — refuse rather than
    follow if `inbound`/`inbox`/`peer` (or a leaf beneath it, `messages`/
    `notices`) has been replaced by a symlink pointing outside `root`.
    REMOVES the separate `verify_namespace_containment(root, ...)` probe
    this used to run before each of the two writes below (a path-based
    check followed by a path-based write — ROUTER-SECURITY.md Finding
    2's exact shape: the directory the check resolved and the directory
    the write resolved were not guaranteed to be the same object). ADDS
    `attachments_mod.write_agent_visible`, which performs one single
    `O_NOFOLLOW`-pinned descent from `root` (the containment ANCHOR —
    see `InstanceConfig.root`'s docstring; NOT `inbox_root`, which would
    be a tautology if `inbox_root` is exactly the directory an agent
    replaced) and writes off that same descriptor — there is no window
    between "checked" and "acted on" left to race. See that function's
    docstring for the full argument. `ledger_path` lives under
    `state_dir`, never agent-reachable (enforced at config load), so it
    is unaffected and keeps using plain `atomic_write`.
    (`publish_attachment_blobs`, above, already used this same pinned-fd
    discipline for the attachment sidecar dir; this brings the message
    doc and the notice doc up to the same standard.)"""
    # 1. Attachment blobs (§5) — published FIRST, before anything that
    # could reference them (§2 "Byte-absence is the gate"). Pinned-fd
    # discipline all the way from `root` (see `attachments.py`'s module
    # docstring); a no-op when `attachments` is empty.
    attachments_mod.publish_attachment_blobs(root, tree_root, notice_id, attachments)

    message_path = tree_root / "messages" / f"notice-{notice_id}.json"
    notice_path = tree_root / "notices" / f"notice-{notice_id}.json"
    ledger_path = binding.ledger_path(state_dir, recipient, notice_id)

    # 2. Message spool -> 3. ledger -> [audit] -> 4. notice LAST.
    attachments_mod.write_agent_visible(
        root, message_path, json.dumps(message_doc, sort_keys=True).encode("utf-8")
    )
    atomic_write(ledger_path, ledger_bytes)
    if audit_line is not None and audit_instance is not None:
        audit_mod.append_bytes(state_dir, audit_instance, audit_line)
    attachments_mod.write_agent_visible(
        root, notice_path, json.dumps(notice_doc, sort_keys=True).encode("utf-8")
    )


def deliver(
    cfg: RouterConfig,
    state_dir: Path,
    sender: str,
    recipient: Optional[str],
    request: Dict[str, Any],
    *,
    reply_to_record: Optional[Dict[str, Any]] = None,
    attachments: Optional[List[attachments_mod.VerifiedAttachment]] = None,
) -> Dict[str, str]:
    """Deliver `request` (a validated submit-request document) from
    instance `sender` to instance `recipient` on the MAIL lane. `reply_to_
    record`, if given, is the sender's own ledger record for the notice
    being replied to (as returned by reading `state_dir/<sender>/delivered/
    notice-<id>.json`) — its `message_id` becomes `message.in_reply_to` on
    the new notice, the one enrichment field L1 carries. `attachments`, if
    given, is the ALREADY-VERIFIED list from `attachments.ingest_attachments`
    (§3) — this function publishes those bytes (§5) but never re-derives or
    re-trusts them from anything in `request` itself. Returns
    `{"notice_id", "message_id", "recipient"}`.

    `recipient is None` is an EXTERNAL reply (`DeliveryBackend`): this
    backend has no leg out of the box and raises `ExternalReplyUnsupported`
    before writing anything. The `None` is checked first and by identity —
    an empty string or any other non-instance is still the `KeyError` it
    always was, not a silent external send.
    """
    if recipient is None:
        raise ExternalReplyUnsupported(
            "the local backend delivers only to fleet instances; an external "
            "reply needs a runtime with an SMTP arm"
        )
    attachments = attachments or []
    notice_id = mint_notice_id()
    message_id = notice_id  # PICKED: no external provider exists; coincide the two.
    ts = utc_ts()

    draft = request.get("draft") or {}
    from_address = address_for(sender, cfg.fleet_domain)
    to_address = address_for(recipient, cfg.fleet_domain)
    recipient_cfg = cfg.instances[recipient]

    message_doc, notice_doc = _message_and_notice(
        notice_id=notice_id, message_id=message_id, ts=ts,
        kind=KIND_DELIVER, mailbox="inbox",
        from_address=from_address, to_address=to_address,
        subject=draft.get("subject") or "", body_text=draft.get("body_text") or "",
        attachments=attachments,
        in_reply_to=_in_reply_to_from(reply_to_record),
        provenance="internal",
    )
    ledger_bytes = binding.record_delivery(
        state_dir,
        notice_id=notice_id,
        from_instance=sender,
        from_address=from_address,
        to_instance=recipient,
        ts=ts,
        req_id=str(request.get("req_id") or ""),
        message_id=message_id,
        # Explicit, not defaulted: the leg is a property of THIS backend,
        # and belongs in view where the record is built. `deliver()` takes
        # no `transport` argument — under the delivery-backend seam an
        # alternate backend replaces this function wholesale and records
        # its own leg, so a parameter here would be dead weight and would
        # put a transport concept in this repo's public signature.
        transport="local",
        tree=TREE_INBOX,
    )
    _place(
        root=recipient_cfg.root, tree_root=recipient_cfg.inbox_root, state_dir=state_dir,
        recipient=recipient, notice_id=notice_id,
        message_doc=message_doc, notice_doc=notice_doc, ledger_bytes=ledger_bytes,
        attachments=attachments,
    )
    return {"notice_id": notice_id, "message_id": message_id, "recipient": recipient}


def _in_reply_to_from(reply_to_record: Optional[Dict[str, Any]]) -> Optional[str]:
    """The `message_id` of the ledger record a reply answers, or `None`.
    THIS is the only source `message.in_reply_to` ever has, on either lane:
    a notice carries it iff the router resolved it from its own ledger."""
    if reply_to_record is None:
        return None
    original = reply_to_record.get("message_id")
    return original if isinstance(original, str) and original else None


def deliver_peer(
    cfg: RouterConfig,
    state_dir: Path,
    sender: str,
    recipient: str,
    request: Dict[str, Any],
    *,
    reply_to_record: Optional[Dict[str, Any]] = None,
    attachments: Optional[List[attachments_mod.VerifiedAttachment]] = None,
) -> Dict[str, str]:
    """`deliver`'s twin on the PEER lane: place `request` from `sender` into
    `recipient`'s `peer/` tree as a `kind: "peer"` notice (module
    docstring). Same signature — a `DeliveryBackend` — so `outbound.py`
    calls both the same way. The peer message id IS `notice_id` (128-bit
    hex, bare on the wire; `message.id` coincides, as on the mail lane),
    returned as `message_id` so the sender learns it from its own result
    and a reply can name it. `sender_exposure` is assessed over the SENDER
    (`exposure.assess`) at `ts` and stamped under `message`; when the
    assessment cannot be made the member is omitted, never guessed."""
    attachments = attachments or []
    recipient_cfg = cfg.instances[recipient]
    if recipient_cfg.peer_root is None:
        raise PeerLaneUnavailable(
            f"instance {recipient!r} has no peer tree (namespace mode, or no fleet_domain)"
        )
    notice_id = mint_notice_id()
    message_id = notice_id
    ts = utc_ts()

    draft = request.get("draft") or {}
    from_address = address_for(sender, cfg.fleet_domain)
    to_address = address_for(recipient, cfg.fleet_domain)
    in_reply_to = _in_reply_to_from(reply_to_record)
    stamp = exposure_mod.assess(cfg, sender, now=ts)

    message_doc, notice_doc = _message_and_notice(
        notice_id=notice_id, message_id=message_id, ts=ts,
        kind=KIND_PEER, mailbox="peer",
        from_address=from_address, to_address=to_address,
        subject=draft.get("subject") or "", body_text=draft.get("body_text") or "",
        attachments=attachments,
        in_reply_to=in_reply_to,
        provenance=None,
        extra_message={"sender_exposure": stamp} if stamp is not None else None,
    )
    ledger_bytes = binding.record_delivery(
        state_dir,
        notice_id=notice_id,
        from_instance=sender,
        from_address=from_address,
        to_instance=recipient,
        ts=ts,
        req_id=str(request.get("req_id") or ""),
        message_id=message_id,
        transport="local",
        tree=TREE_PEER,
    )
    if in_reply_to is None:
        reply_basis = None
    elif binding.check_peer_edge(cfg, sender, recipient):
        reply_basis = "edge"
    else:
        reply_basis = "reply_window"
    audit_line = audit_mod.build_line(
        audit_mod.EVENT_PEER_NOTICE_PLACED, recipient, {
            "notice_id": notice_id,
            "message_id": message_id,
            "tree": TREE_PEER,
            "from": from_address,
            "to": to_address,
            "from_instance": sender,
            "to_instance": recipient,
            "req_id": str(request.get("req_id") or ""),
            "in_reply_to": in_reply_to,
            "reply_basis": reply_basis,
            "sender_exposure": stamp,
            "origin": "local",
            "signature_verdict": None,
            "demotion_cause": None,
        },
    )
    _place(
        root=recipient_cfg.root, tree_root=recipient_cfg.peer_root, state_dir=state_dir,
        recipient=recipient, notice_id=notice_id,
        message_doc=message_doc, notice_doc=notice_doc, ledger_bytes=ledger_bytes,
        attachments=attachments,
        audit_line=audit_line, audit_instance=recipient,
    )
    return {"notice_id": notice_id, "message_id": message_id, "recipient": recipient}


ROUTER_AUTHOR = "router"


def deliver_router_notice(
    cfg: RouterConfig,
    state_dir: Path,
    recipient: str,
    *,
    subject: str,
    body_text: str,
    in_reply_to: Optional[str],
    audit_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """A notice THIS ROUTER authors, into `recipient`'s MAIL tree: `kind:
    "deliver"`, `mailbox: "inbox"`, `from` = `amap.router@<fleet_domain>`,
    `provenance: "internal"`, no attachments. Used for the DSN a sender
    gets when a peer message it sent reached a terminal failure
    (`outcomes.py`). `in_reply_to` is the peer message id being reported
    on — set directly, not through a ledger record, because the router IS
    the party that issued that id. Ledgered with `from_instance: null` and
    `authored_by: "router"` (module docstring). An `audit.EVENT_DSN_SENT`
    line goes to the RECIPIENT's log (it is the recipient's tree that was
    written), with `audit_fields` merged in. Requires a `fleet_domain` —
    the router has no address to author from otherwise."""
    from_address = router_address(cfg.fleet_domain)
    if from_address is None:
        raise PeerLaneUnavailable("no fleet_domain: the router has no address to author from")
    recipient_cfg = cfg.instances[recipient]
    notice_id = mint_notice_id()
    message_id = notice_id
    ts = utc_ts()
    to_address = address_for(recipient, cfg.fleet_domain)

    message_doc, notice_doc = _message_and_notice(
        notice_id=notice_id, message_id=message_id, ts=ts,
        kind=KIND_DELIVER, mailbox="inbox",
        from_address=from_address, to_address=to_address,
        subject=subject, body_text=body_text, attachments=[],
        in_reply_to=in_reply_to, provenance="internal",
    )
    ledger_bytes = binding.record_delivery(
        state_dir,
        notice_id=notice_id,
        from_instance=None,
        from_address=from_address,
        to_instance=recipient,
        ts=ts,
        req_id="",
        message_id=message_id,
        transport="local",
        tree=TREE_INBOX,
        authored_by=ROUTER_AUTHOR,
    )
    fields: Dict[str, Any] = {
        "notice_id": notice_id,
        "tree": TREE_INBOX,
        "from": from_address,
        "to": to_address,
        "to_instance": recipient,
        "in_reply_to": in_reply_to,
        "subject": subject,
    }
    fields.update(audit_fields or {})
    audit_line = audit_mod.build_line(audit_mod.EVENT_DSN_SENT, recipient, fields)
    _place(
        root=recipient_cfg.root, tree_root=recipient_cfg.inbox_root, state_dir=state_dir,
        recipient=recipient, notice_id=notice_id,
        message_doc=message_doc, notice_doc=notice_doc, ledger_bytes=ledger_bytes,
        attachments=[],
        audit_line=audit_line, audit_instance=recipient,
    )
    return {"notice_id": notice_id, "message_id": message_id, "recipient": recipient}
