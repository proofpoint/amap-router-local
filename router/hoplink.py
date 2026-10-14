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
#: signed kinds; a request of any other class is refused `no_route` at
#: begin (`outbound._begin_external`), before anything is allocated.
MAIL_KIND = "mail"
#: The envelope kind of a reply bound to a placed hop mail (`bound`, below):
#: begun only from this router's own ledger record of that mail.
BOUND_REPLY_KIND = "bound_reply"
#: The two SIGNED kinds (`router/peerlane.py`): their envelope carries `peer`
#: (`peer_problem`), never `bound`.
PEER_KIND = "peer"
CONTROL_KIND = "control"
SIGNED_KINDS = (PEER_KIND, CONTROL_KIND)
#: The most raw `to` + `cc` (+ `bcc`) entries one request may name,
#: duplicates counted (`too_many_recipients`).
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


#: Why `canonical` refuses a value: the reason vocabulary shared with the
#: hop plugin's own canonical encoder, so both refuse the same inputs for the
#: same reason (the projection's shared encoding vectors).
REFUSE_FLOAT = "float_not_allowed"
REFUSE_NOT_JSON = "not_json"
REFUSE_SURROGATE = "unpaired_surrogate"
CANONICAL_REFUSALS = (REFUSE_FLOAT, REFUSE_NOT_JSON, REFUSE_SURROGATE)


class CanonicalRefused(ValueError):
    """`canonical` refused `value`. `.reason` is one of `CANONICAL_REFUSALS`."""

    def __init__(self, reason: str, detail: str):
        assert reason in CANONICAL_REFUSALS, reason
        super().__init__(f"{detail} ({reason})")
        self.reason = reason


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _check_integers_only(value: Any, where: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return
    if isinstance(value, str):
        if _has_surrogate(value):
            raise CanonicalRefused(REFUSE_SURROGATE, f"{where}: an unpaired surrogate")
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            # NaN and the infinities are not JSON numbers at all.
            raise CanonicalRefused(REFUSE_NOT_JSON, f"{where}: {value!r} is not a JSON number")
        raise CanonicalRefused(REFUSE_FLOAT, f"{where}: a non-integer number is not representable")
    if isinstance(value, list):
        for i, v in enumerate(value):
            _check_integers_only(v, f"{where}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalRefused(REFUSE_NOT_JSON, f"{where}: a non-string key")
            if _has_surrogate(k):
                raise CanonicalRefused(REFUSE_SURROGATE, f"{where}: an unpaired surrogate in a key")
            _check_integers_only(v, f"{where}.{k}")
        return
    raise CanonicalRefused(REFUSE_NOT_JSON, f"{where}: a {type(value).__name__} is not JSON")


def canonical(value: Any) -> bytes:
    """`value` in the handover's canonical encoding, or `CanonicalRefused`
    (a `ValueError`, `.reason` one of `CANONICAL_REFUSALS`) for anything that
    encoding refuses: a non-integer number (`float_not_allowed`); NaN, an
    infinity, a non-string key or a non-JSON type (`not_json`); a lone
    surrogate in a string or a key (`unpaired_surrogate`)."""
    _check_integers_only(value)
    text = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    return text.encode("utf-8")


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
    kept: the recipient limit counts what the agent wrote."""
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
    the recipient count, each recipient's octets (RFC 5321), the encoding,
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
                   attachments: Iterable[str], settled_through: int,
                   kind: str = MAIL_KIND, bound: Optional[Dict[str, Any]] = None,
                   peer: Optional[Dict[str, Any]] = None) -> bytes:
    """The handover document's canonical bytes. `attachments` are standard
    base64 strings in descriptor order. `kind` is `MAIL_KIND`, with no
    `bound`, or `BOUND_REPLY_KIND`, whose envelope carries `bound` (which
    must pass `bound_problem`), or `PEER_KIND` / `CONTROL_KIND`, whose
    envelope carries `peer` (`peer_problem`). `ValueError` for anything the
    encoding refuses, or for any other combination."""
    envelope: Dict[str, Any] = {"from_address": from_address, "hop_contract": version_write,
                                "kind": kind}
    if kind == BOUND_REPLY_KIND:
        if peer is not None:
            raise ValueError("a bound reply carries no peer object")
        why = bound_problem(bound)
        if why is not None:
            raise ValueError(f"bound: {why}")
        envelope["bound"] = bound
    elif kind in SIGNED_KINDS:
        if bound is not None:
            raise ValueError(f"kind {kind!r} carries no bound object")
        why = peer_problem(peer, from_address)
        if why is not None:
            raise ValueError(f"peer: {why}")
        envelope["peer"] = peer
    elif kind != MAIL_KIND or bound is not None or peer is not None:
        raise ValueError(f"kind {kind!r} with bound {'present' if bound else 'absent'} and "
                         f"peer {'present' if peer else 'absent'}")
    return canonical({
        "attachments": list(attachments),
        "envelope": envelope,
        "request": request,
        "schema": HANDOVER_SCHEMA,
        "settled_through": settled_through,
    })


# The bound reply's `bound` object: its members and the hop codec's grammar
# for each, applied with `fullmatch`. `bound_address` and the counterparty
# are addresses (`from_address_problem`), and equal exactly.
BOUND_MEMBERS = ("bound_address", "origin_notice_id", "origin_link", "origin_generation",
                 "participants", "admission", "admission_link", "admission_rule",
                 "policy_digest")
ORIGIN_NOTICE_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
LINK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
HEX32_RE = re.compile(r"[0-9a-f]{32}\Z")
ADMISSION_RULE_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
POLICY_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
#: `admission`'s values. An absent admission is `ADMISSION_OPEN`, and is
#: always written explicitly.
ADMISSION_OPEN = "open"
ADMISSIONS = (ADMISSION_OPEN, "fleet_hosts", "inbound_allowlist")


def bound_problem(bound: Any) -> Optional[str]:
    """Why `bound` is not a bound reply's `bound` object, or None."""
    if not isinstance(bound, dict) or set(bound) != set(BOUND_MEMBERS):
        return f"not an object with exactly {list(BOUND_MEMBERS)}"
    parts = bound["participants"]
    if not isinstance(parts, dict) or set(parts) != {"agent", "counterparty"}:
        return "participants is not {agent, counterparty}"
    for key, value, pattern in (
            ("origin_notice_id", bound["origin_notice_id"], ORIGIN_NOTICE_ID_RE),
            ("origin_link", bound["origin_link"], LINK_RE),
            ("origin_generation", bound["origin_generation"], HEX32_RE),
            ("participants.agent", parts["agent"], HEX32_RE),
            ("admission_link", bound["admission_link"], LINK_RE),
            ("admission_rule", bound["admission_rule"], ADMISSION_RULE_RE),
            ("policy_digest", bound["policy_digest"], POLICY_DIGEST_RE)):
        if not (isinstance(value, str) and pattern.fullmatch(value)):
            return f"{key} is outside its grammar"
    if bound["admission"] not in ADMISSIONS:
        return "admission is outside its enum"
    for key, value in (("bound_address", bound["bound_address"]),
                       ("participants.counterparty", parts["counterparty"])):
        why = from_address_problem(value)
        if why is not None:
            return f"{key}: {why}"
    if bound["bound_address"] != parts["counterparty"]:
        return "bound_address is not participants.counterparty exactly"
    return None


# The signed kinds' `peer` object: the hop codec's grammar for each member.
#: The unfolded header value: the tag alphabet, no leading or trailing space.
STATEMENT_HEADER_RE = re.compile(r"[A-Za-z0-9_=;.-](?:[A-Za-z0-9_=; .-]*[A-Za-z0-9_=;.-])?\Z")
STATEMENT_HEADER_MAX = 11776
_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
_DOT_ATOM = rf"{_ATEXT}+(?:\.{_ATEXT}+)*"
MSG_ID_RE = re.compile(rf"<{_DOT_ATOM}@({_DOT_ATOM})>\Z")
MSG_ID_MAX = 250
REFERENCES_MAX = 20
PEER_MEMBERS = ("statement_header", "message_id", "in_reply_to", "references")


def _msg_id_problem(value: Any, what: str) -> Optional[str]:
    if not (isinstance(value, str) and len(value) <= MSG_ID_MAX and MSG_ID_RE.fullmatch(value)):
        return f"{what} is not a msg-id"
    return None


def peer_problem(peer: Any, from_address: str) -> Optional[str]:
    """Why `peer` is not a signed kind's `peer` object for an envelope from
    `from_address`, or None. Q9: `message_id`'s domain is `from_address`'s."""
    if not isinstance(peer, dict) or set(peer) != set(PEER_MEMBERS):
        return f"not an object with exactly {list(PEER_MEMBERS)}"
    header = peer["statement_header"]
    if not (isinstance(header, str) and len(header) <= STATEMENT_HEADER_MAX
            and STATEMENT_HEADER_RE.fullmatch(header)):
        return "statement_header is outside its grammar"
    why = _msg_id_problem(peer["message_id"], "message_id")
    if why is not None:
        return why
    domain = MSG_ID_RE.fullmatch(peer["message_id"]).group(1)
    if domain != str(from_address).rpartition("@")[2]:
        return "message_id's domain is not from_address's"
    if peer["in_reply_to"] is not None:
        why = _msg_id_problem(peer["in_reply_to"], "in_reply_to")
        if why is not None:
            return why
    refs = peer["references"]
    if not (isinstance(refs, list) and len(refs) <= REFERENCES_MAX):
        return f"references is not a list of at most {REFERENCES_MAX}"
    for i, r in enumerate(refs):
        why = _msg_id_problem(r, f"references[{i}]")
        if why is not None:
            return why
    return None


def handover_len_max(request: Dict[str, Any], *, from_address: str, version_write: int,
                     attachment_sizes: Iterable[int], kind: str = MAIL_KIND,
                     bound: Optional[Dict[str, Any]] = None,
                     peer: Optional[Dict[str, Any]] = None) -> int:
    """The largest the handover for `request` can be: the transport id and
    `settled_through` at their most digits, and each attachment as the
    standard base64 of its size. Computed, not built: no attachment bytes
    are read."""
    sizes = list(attachment_sizes)
    probe = dict(request, req_id="9" * TRANSPORT_ID_MAX_DIGITS)
    skeleton = build_handover(probe, from_address=from_address, version_write=version_write,
                              attachments=(), settled_through=10 ** TRANSPORT_ID_MAX_DIGITS - 1,
                              kind=kind, bound=bound, peer=peer)
    if not sizes:
        return len(skeleton)
    return len(skeleton) + sum(4 * math.ceil(n / 3) + 2 for n in sizes) + len(sizes) - 1


# ---------------------------------------------------------------------------
# The sender for one generation: its binding pin, its admission
# confirmation, and the per-process cache.
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402  (kept beside the half that uses it)
import logging  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Tuple  # noqa: E402

from . import audit as audit_mod  # noqa: E402
from . import config as config_mod  # noqa: E402
from . import generations as generations_mod  # noqa: E402
from . import transport as transport_mod  # noqa: E402
import time  # noqa: E402

from .util import atomic_write, utc_ts  # noqa: E402

#: The clock hold and retry ages are measured on (tests replace it).
_clock = time.monotonic

logger = logging.getLogger("amap_router_local.hoplink")

#: Where a generation's hop state lives, under its private directory.
TRANSPORT_DIR = "transport"
PIN_FILE = "hop.json"
ADMITTED_FILE = "admitted.json"

#: Hold reasons this half reports (per generation unless said otherwise).
HOLD_BINDING_CHANGED = "hop_binding_changed"
HOLD_PREDECESSOR_UNRETIRED = "hop_predecessor_unretired"   # the whole instance
HOLD_SETTINGS_REFUSED = "hop_settings_refused"
HOLD_IDENTITY_CONFLICT = "hop_identity_conflict"
HOLD_PLUGIN_VOCABULARY = "hop_plugin_vocabulary"           # the whole instance
HOLD_CONSTRUCT_FAILED = "hop_construct_failed"             # retried next poll


class HopHold(Exception):
    """No sender for this generation this poll. `reason` is a hold reason;
    `latched` says whether only an operator act releases it (otherwise the
    next poll tries again); `scope` is `"gen"` or `"instance"`."""

    def __init__(self, reason: str, detail: str, *, latched: bool, scope: str = "gen"):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail, self.latched, self.scope = reason, detail, latched, scope
        self.since, self.since_ts = _clock(), utc_ts()

    def fresh(self) -> "HopHold":
        """The same hold as a new exception, its first sighting kept: a
        cached hold is raised again on every poll, and re-raising ONE object
        grows its traceback (and the frames it pins) without bound."""
        copy = HopHold(self.reason, self.detail, latched=self.latched, scope=self.scope)
        copy.since, copy.since_ts = self.since, self.since_ts
        return copy


def split_gen_key(key: str) -> Tuple[str, str]:
    """`<logical_id>/gen-<gen>` into `(logical_id, gen)`."""
    lid, _, rest = key.partition("/")
    if not (lid and rest.startswith(generations_mod.GEN_PREFIX)):
        raise ValueError(f"{key!r} is not a generation key")
    return lid, rest[len(generations_mod.GEN_PREFIX):]


def transport_dir(cfg: Any, name: str) -> Path:
    return config_mod.gen_state_dir(cfg, name) / TRANSPORT_DIR


def _read_json_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    return json.loads(raw.decode("utf-8"))


def pin_doc(hop: Any, admitted_at: str) -> Dict[str, Any]:
    return {"hop_root": hop.root, "peer_uid": hop.peer_uid,
            "version_write": hop.version_write, "admitted_at": admitted_at}


def minted_ts(cfg: Any, name: str) -> str:
    """The generation's `minted_ts` from its durable record: the sender's
    `admitted_at` (F4), never the clock."""
    lid, gen = split_gen_key(config_mod.gen_key(cfg, name))
    doc = generations_mod.read_doc(cfg.state_dir, lid)
    if doc is None:
        raise HopHold(HOLD_CONSTRUCT_FAILED, "no generations record", latched=False)
    entry = next((g for g in doc["gens"] if g["gen"] == gen), None)
    if entry is None or not isinstance(entry.get("minted_ts"), str):
        raise HopHold(HOLD_CONSTRUCT_FAILED, f"generation {gen} has no minted_ts",
                      latched=False)
    return entry["minted_ts"]


def ensure_pin(cfg: Any, name: str) -> Dict[str, Any]:
    """This generation's binding pin: written durably BEFORE its sender is
    first constructed, and compared on every later construction. A config
    that no longer matches it HOLDS this generation (`hop_binding_changed`):
    a changed root would admit a live generation a second time elsewhere and
    hand a request over twice."""
    path = transport_dir(cfg, name) / PIN_FILE
    want = pin_doc(cfg.hop, minted_ts(cfg, name))
    have = _read_json_file(path)
    if have is None:
        atomic_write(path, canonical(want), durable_root=cfg.state_dir)
        return want
    if have != want:
        raise HopHold(HOLD_BINDING_CHANGED,
                      f"this generation is pinned to {have}, the config now says {want}",
                      latched=True)
    return have


def read_pin(cfg: Any, name: str) -> Optional[Dict[str, Any]]:
    """This generation's binding pin, or None before the first construction."""
    return _read_json_file(transport_dir(cfg, name) / PIN_FILE)


def settings_for(cfg: Any, name: str, pin: Dict[str, Any]) -> Dict[str, Any]:
    """The sender's settings, exactly the plugin's closed list, taken from the
    PIN (never the current config) and the generation key."""
    lid, gen = split_gen_key(config_mod.gen_key(cfg, name))
    return {"hop_root": pin["hop_root"], "logical_id": lid, "generation": gen,
            "peer_uid": pin["peer_uid"], "version_write": pin["version_write"],
            "caps": dict(cfg.hop.caps), "admitted_at": pin["admitted_at"], "role": "hop1"}


def admitted(cfg: Any, name: str) -> bool:
    return (transport_dir(cfg, name) / ADMITTED_FILE).is_file()


def fenced_pinned(cfg: Any, name: str) -> List[str]:
    """The fenced predecessors of `name`'s current generation that this
    router PINNED (a `transport/hop.json`). The pin, not `admitted.json`, is
    the fail-closed key: the pin is written before the first construction,
    and a construction may admit the tree and then fail (or the process
    crash) before `admitted.json` is written. Such a tree is live and
    unretired all the same."""
    lid, current = split_gen_key(config_mod.gen_key(cfg, name))
    doc = generations_mod.read_doc(cfg.state_dir, lid)
    out = []
    for g in (doc or {}).get("gens", []):
        if g["gen"] != current and (generations_mod.gen_dir(cfg.state_dir, lid, g["gen"])
                                    / TRANSPORT_DIR / PIN_FILE).is_file():
            out.append(g["gen"])
    return out


def _pin_key(runtime: Any, state_dir: Any, lid: str, gen: str, pin: Dict[str, Any]) -> Tuple:
    """The per-process cache key of one generation's hop objects."""
    return (id(runtime), str(state_dir), lid, gen, hashlib.sha256(canonical(pin)).hexdigest())


#: The per-process cache: (runtime id, state_dir, logical_id, gen, pin digest)
#: -> the constructed sender. Filled only after a construction succeeded.
_SENDERS: Dict[Tuple, Any] = {}
#: The LATCHED construction holds, by the same key: consulted before any
#: construction, so a latched hold is never re-attempted in this process.
#: Released only by a restart, or by a new generation (a new key).
_LATCHED: Dict[Tuple, "HopHold"] = {}


def sender_for(runtime: Any, cfg: Any, name: str) -> Any:
    """`name`'s CURRENT generation's sender: constructed once per (generation,
    pin) per process, and only after the pin is durable. Its successful
    construction admitted the tree, so `admitted.json` is then written,
    before the first request is handed over. Raises `HopHold`, and ONLY
    `HopHold`: any other failure on the way (reading the generations record,
    the pin, the admission confirmation) is a retried construction hold for
    this generation, never an exception that aborts the instance's drain."""
    try:
        return _sender_for(runtime, cfg, name)
    except HopHold:
        raise
    except Exception as e:  # noqa: BLE001 -- classified as a retried hold, never escaped
        raise HopHold(f"{HOLD_CONSTRUCT_FAILED}:{type(e).__name__}", str(e),
                      latched=False) from e


def _sender_for(runtime: Any, cfg: Any, name: str) -> Any:
    lid, gen = split_gen_key(config_mod.gen_key(cfg, name))
    unretired = [g for g in fenced_pinned(cfg, name) if not _is_retired(runtime, cfg, lid, g)]
    if unretired:
        # Retiring a fenced predecessor is the fence step's (`fence_step`);
        # until it has succeeded in this process, no successor is admitted
        # (one live generation, contract §4.1). Its own hold says why.
        held = FENCE_HOLDS.get((str(cfg.state_dir), name))
        if held is not None:
            raise held.fresh()
        raise HopHold(HOLD_PREDECESSOR_UNRETIRED,
                      f"fenced generation(s) {unretired} not yet retired", latched=False,
                      scope="instance")
    pin = ensure_pin(cfg, name)
    key = _pin_key(runtime, cfg.state_dir, lid, gen, pin)
    port = _SENDERS.get(key)
    if port is not None:
        return port
    if key in _LATCHED:
        raise _LATCHED[key].fresh()
    try:
        port = runtime.plugin.make_sender(settings_for(cfg, name, pin), runtime.fsops)
    except Exception as e:  # noqa: BLE001 -- classified, never swallowed silently
        hold = _construction_hold(e)
        if hold.latched:
            _LATCHED[key] = hold
        raise hold from e
    try:
        atomic_write(transport_dir(cfg, name) / ADMITTED_FILE,
                     canonical({"admitted_at": pin["admitted_at"], "hop_root": pin["hop_root"]}),
                     durable_root=cfg.state_dir)
    except Exception as e:  # noqa: BLE001 -- not cached, so released here, then retried
        # The constructed sender is neither cached nor returned: close it now,
        # or every poll that fails this write leaks one.
        try:
            port.close()
        except Exception:  # noqa: BLE001 -- close is cleanup
            logger.exception("closing a hop sender after a failed admitted.json write failed")
        raise HopHold(f"{HOLD_CONSTRUCT_FAILED}:admitted_not_recorded",
                      f"{type(e).__name__}: {e}", latched=False) from e
    _SENDERS[key] = port
    return port


def _construction_hold(e: BaseException) -> HopHold:
    """The construction row of the closed exception table. The runtime's own
    classes are seen first, as on the write path, so an `UnsafeRead` that
    happens to carry a colliding `.reason` is never latched."""
    kind, detail = transport_mod.classify(e, runtime=tuple(_RUNTIME_CLASSES))
    if kind == "reason" and detail == "settings_invalid":
        return HopHold(HOLD_SETTINGS_REFUSED, str(e), latched=True)
    if kind == "reason" and detail == "exists_different":
        return HopHold(HOLD_IDENTITY_CONFLICT, str(e), latched=True)
    if isinstance(e, transport_mod.SeamRefused):
        return HopHold(HOLD_PLUGIN_VOCABULARY, str(e), latched=True, scope="instance")
    return HopHold(f"{HOLD_CONSTRUCT_FAILED}:{detail or kind}", str(e), latched=False)


def forget_senders() -> None:
    """Drop the caches, closing each sender and reader (tests, and a process
    ending)."""
    for port in list(_SENDERS.values()) + [r.port for r in _READERS.values()]:
        try:
            port.close()
        except Exception:  # noqa: BLE001 -- close is cleanup
            logger.exception("closing a hop object failed")
    for port in list(_REMOVERS.values()) + list(_STORES.values()):
        _close_quietly(port)
    _STORES.clear()
    _STORE_LATCHED.clear()
    _RETIRED.clear()
    _SENDERS.clear()
    _LATCHED.clear()
    _READERS.clear()
    _REMOVERS.clear()
    _REMOVER_LATCHED.clear()
    _READER_LATCHED.clear()


#: Every module-level container that holds PER-PROCESS state, by module: a
#: process that ends forgets all of it, and `reset_process_state` makes a
#: test (or the hop fixture's restart) forget the same. A new one is
#: classified here or as a constant in `test_process_reset.py`, which fails
#: on any it finds in neither.
PROCESS_STATE: Dict[str, Tuple[str, ...]] = {
    "hoplink": ("_SENDERS", "_LATCHED", "_READERS", "_READER_LATCHED", "_REMOVERS",
                "_REMOVER_LATCHED", "HOLDS", "_STORES", "_STORE_LATCHED", "_RETIRED",
                "FENCE_HOLDS", "_RUNTIME_CLASSES", "RETRIES"),
    "ingress": ("_CURSORS", "_CYCLE", "LISTING_ENTRIES_HIGH", "_CURSOR_PORT", "_LINK_LATCHED",
                "REMOVER_STATE", "_LINK_UNSET_LOGGED", "_LAST_CURRENT", "READ_REFUSALS"),
    "outbound": ("_STALE_WARNED",),
    "service": ("LAST_INGRESS", "_REGISTRY_LOGGED", "_RELOAD_FAILURE", "PEER_STARTUP",
                "LAST_PEER_POLL"),
    "peerjournal": ("_CURSORS", "_DISPOSED", "_POLLED", "EPOCH_COUNTS"),
    "peerlane": ("_ACTIVE",),
    "aliases": ("LAST_TOMBSTONE_ERRORS",),
}


def reset_process_state(*runtimes: Any) -> None:
    """What a process end forgets, forgotten now: every hop object closed
    and dropped (`forget_senders`); then each given runtime's filesystem port
    closed (`FsOps.close`: its pinned stage descriptors and its bindings),
    so the runtime is spent and the caller builds a new one
    (`service.start_transport`, or a `HopRuntime` over a new FsOps); then
    every container in `PROCESS_STATE` emptied in place. Durable state is
    untouched. A module not yet imported has nothing to forget. The plugin
    module itself is NOT reloaded: its own module state, if any, is the
    plugin's. For the hop fixture's restart and for tests."""
    import sys
    forget_senders()
    for runtime in runtimes:
        close = getattr(getattr(runtime, "fsops", None), "close", None)
        if close is not None:
            close()
    for module, names in PROCESS_STATE.items():
        mod = sys.modules.get(f"{__package__}.{module}")
        if mod is None:
            continue
        for attr in names:
            getattr(mod, attr).clear()


# ---------------------------------------------------------------------------
# Intake readers: one per (logical_id, generation), current or fenced.
# Reading never admits, so a fenced generation's tree may be read; its
# entries are late.
# ---------------------------------------------------------------------------

HOLD_READER_CONSTRUCT_FAILED = "hop_reader_construct_failed"   # retried next poll
HOLD_READER_SETTINGS_REFUSED = "hop_reader_settings_refused"
HOLD_READER_VOCABULARY = "hop_reader_vocabulary"               # the whole instance


class Reader:
    """A constructed intake reader and its refusal class, captured ONCE at
    construction (`transport.capture_verdict_class`): later dispatch uses
    `notice_refused`, never a fresh attribute lookup."""

    def __init__(self, port: Any, notice_refused: type):
        self.port, self.notice_refused = port, notice_refused


#: (runtime id, state_dir, logical_id, gen) -> Reader. Filled only after a
#: construction and its class capture both succeeded.
_READERS: Dict[Tuple, Reader] = {}
#: Latched reader construction holds, by the same key.
_READER_LATCHED: Dict[Tuple, "HopHold"] = {}


def reader_settings(cfg: Any, logical_id: str, gen: str) -> Dict[str, Any]:
    """A tree reader's settings: exactly the four-key core."""
    return {"hop_root": cfg.hop.root, "logical_id": logical_id, "generation": gen,
            "peer_uid": cfg.hop.peer_uid}


def reader_for(runtime: Any, cfg: Any, logical_id: str, gen: str) -> Reader:
    """The intake reader for generation `gen` of `logical_id`, constructed
    once per process. Raises `HopHold`, and ONLY `HopHold`: settings and
    vocabulary refusals latch; anything else is retried next poll."""
    key = (id(runtime), str(cfg.state_dir), logical_id, gen)
    reader = _READERS.get(key)
    if reader is not None:
        return reader
    if key in _READER_LATCHED:
        raise _READER_LATCHED[key].fresh()
    try:
        port = runtime.plugin.make_intake_reader(reader_settings(cfg, logical_id, gen),
                                                 runtime.fsops)
    except Exception as e:  # noqa: BLE001 -- classified, never escaped
        hold = _reader_construction_hold(e)
        if hold.latched:
            _READER_LATCHED[key] = hold
        raise hold from e
    try:
        refused = transport_mod.capture_verdict_class(port, "NoticeRefused", runtime.fsops,
                                                      "reader_vocabulary")
    except transport_mod.SeamRefused as e:
        _close_quietly(port)
        hold = HopHold(HOLD_READER_VOCABULARY, str(e), latched=True, scope="instance")
        _READER_LATCHED[key] = hold
        raise hold from e
    reader = Reader(port, refused)
    _READERS[key] = reader
    return reader


def _reader_construction_hold(e: BaseException) -> HopHold:
    kind, detail = transport_mod.classify(e, runtime=tuple(_RUNTIME_CLASSES))
    if kind == "reason" and detail == "settings_invalid":
        return HopHold(HOLD_READER_SETTINGS_REFUSED, str(e), latched=True)
    if isinstance(e, transport_mod.SeamRefused):
        return HopHold(HOLD_READER_VOCABULARY, str(e), latched=True, scope="instance")
    return HopHold(f"{HOLD_READER_CONSTRUCT_FAILED}:{detail or kind}", str(e), latched=False)


# --------------------------------------------------------------------------
# The OPTIONAL intake remover (`transport.OPTIONAL_FACTORIES`, at (3, 1)):
# one per (logical_id, generation) per process, constructed only when the
# loaded plugin offers the capability. A refusal of its settings latches the
# REMOVER only (`hop_settings_refused`): reading and placing go on, and the
# entries wait. Anything else is retried next poll.
# --------------------------------------------------------------------------

REMOVER_FACTORY = "make_intake_remover"
HOLD_REMOVER_SETTINGS_REFUSED = "hop_settings_refused"
HOLD_REMOVER_CONSTRUCT_FAILED = "hop_remover_construct_failed"

#: (runtime id, state_dir, logical_id, gen) -> the constructed remover.
_REMOVERS: Dict[Tuple, Any] = {}
#: Latched remover construction holds, by the same key.
_REMOVER_LATCHED: Dict[Tuple, "HopHold"] = {}


def remover_offered(runtime: Any) -> bool:
    return REMOVER_FACTORY in getattr(runtime.plugin, "optional_capabilities", frozenset())


def remover_for(runtime: Any, cfg: Any, logical_id: str, gen: str) -> Optional[Any]:
    """The generation's remover, or None when the plugin does not offer one
    (the interim rule then applies). Raises `HopHold`, and ONLY `HopHold`,
    when one is offered but cannot be constructed."""
    if not remover_offered(runtime):
        return None
    key = (id(runtime), str(cfg.state_dir), logical_id, gen)
    remover = _REMOVERS.get(key)
    if remover is not None:
        return remover
    if key in _REMOVER_LATCHED:
        raise _REMOVER_LATCHED[key].fresh()
    try:
        remover = runtime.plugin.make_intake_remover(
            reader_settings(cfg, logical_id, gen), runtime.fsops)
    except Exception as e:  # noqa: BLE001 -- classified, never escaped
        kind, detail = transport_mod.classify(e, runtime=tuple(_RUNTIME_CLASSES))
        if kind == "reason" and detail == "settings_invalid":
            hold = HopHold(HOLD_REMOVER_SETTINGS_REFUSED, str(e), latched=True)
            _REMOVER_LATCHED[key] = hold
        else:
            hold = HopHold(f"{HOLD_REMOVER_CONSTRUCT_FAILED}:{detail or kind}", str(e),
                           latched=False)
        raise hold from e
    _REMOVERS[key] = remover
    return remover


def evict_remover(cfg: Any, logical_id: str, gen: str) -> int:
    """Close and drop the cached removers of one generation (a remover found
    closed is rebuilt on the next poll)."""
    state = str(cfg.state_dir)
    keys = [k for k in _REMOVERS if k[1] == state and k[2] == logical_id and k[3] == gen]
    for k in keys:
        _close_quietly(_REMOVERS.pop(k))
    return len(keys)


def evict_readers(cfg: Any, logical_id: str, gen: Optional[str] = None) -> int:
    """Close and drop the cached readers of `logical_id` (one generation, or
    all): a cached reader pins its tree, so a fence must not leave it
    reading the old directory. Returns how many were evicted."""
    state = str(cfg.state_dir)
    keys = [k for k in _READERS if k[1] == state and k[2] == logical_id
            and (gen is None or k[3] == gen)]
    for k in keys:
        _close_quietly(_READERS.pop(k).port)
    return len(keys)


def _close_quietly(port: Any) -> None:
    try:
        port.close()
    except Exception:  # noqa: BLE001 -- close is cleanup
        logger.exception("closing a hop object failed")


class Held:
    """The drain's transport when this generation's sender is held: a
    request bound for the external leg stays UNCONSUMED in the outbox (it is
    neither settled nor put in flight), and in-flight records are left as
    they are. Never `None`, which the drain reads as "no transport
    configured" and settles."""

    def __init__(self, hold: HopHold):
        self.hold = hold


def is_runtime(transport: Any) -> bool:
    """The plugin-object seam's carrier (`service.HopRuntime`), recognised
    by its three fields; the drain resolves it to a sender per generation."""
    return all(hasattr(transport, a) for a in ("plugin", "fsops", "hop"))


#: A fenced generation's work before its tree is retired in this process:
#: held, so nothing fenced is begun, handed over or settled (a `None` would
#: read as "no transport configured" and settle). Built per call, so its
#: age is the hold's own.
HOLD_FENCED_UNRETIRED = "hop_fenced_unretired"


def fenced_until_retired() -> HopHold:
    return HopHold(HOLD_FENCED_UNRETIRED,
                   "a fenced generation's work waits for its retirement", latched=False)


#: This process's latest hold per (state_dir, instance), for status.
HOLDS: Dict[Tuple[str, str], HopHold] = {}


def resolve(transport: Any, cfg: Any, name: str) -> Tuple[Any, Any]:
    """`(current, fenced)`: the transport the drain uses for `name`'s current
    generation, and for its fenced generations' work. A runtime first runs
    the fence step (`fence_step`: retire every fenced predecessor), then
    resolves to the current generation's sender (or `Held`); the fenced leg
    gets a `FencedSenders`, which gives each fenced generation its own
    sender once its tree is retired (`Held` before that), or the instance's
    own hold. Anything else (a test's port, or `None`) is used as given for
    both."""
    if not is_runtime(transport):
        return transport, transport
    key = (str(cfg.state_dir), name)
    try:
        if transport.fsops is not None and not _RUNTIME_CLASSES:
            try:
                _RUNTIME_CLASSES.extend(transport_mod.check_fsops_classes(transport.fsops))
            except transport_mod.SeamRefused as e:
                raise HopHold(HOLD_PLUGIN_VOCABULARY, str(e), latched=True,
                              scope="instance") from e
            except Exception as e:  # noqa: BLE001 -- never escapes the drain
                raise HopHold(f"{HOLD_CONSTRUCT_FAILED}:{type(e).__name__}", str(e),
                              latched=False, scope="instance") from e
        fence_step(transport, cfg, name)
        port = sender_for(transport, cfg, name)
    except HopHold as e:
        prior = HOLDS.get(key)
        if prior is None or prior.reason != e.reason:
            (logger.error if e.latched else logger.warning)(
                "instance %r: no hop sender this poll (%s): %s", name, e.reason, e.detail)
        else:
            e.since, e.since_ts = prior.since, prior.since_ts   # the same hold, still
        HOLDS[key] = e
        held = Held(e)
        return held, (FencedSenders(transport) if _fenced_leg_free(e) else held)
    HOLDS.pop(key, None)
    return port, FencedSenders(transport)


def _fenced_leg_free(hold: HopHold) -> bool:
    """Whether the fenced leg may still run while the CURRENT generation is
    held: yes when the hold is the current generation's own (a retired
    predecessor's in-flight work is unaffected by it), no when it is the
    instance's (the plugin, or a predecessor not yet retired)."""
    return hold.scope != "instance"


# ---------------------------------------------------------------------------
# Fence and retire, the sender side's order: the private record (the
# generations file naming the new current generation, already durable when
# a poll first sees it), THEN retire every fenced predecessor this router
# pinned, THEN admit the current generation (its sender's construction).
# Recovery is the same code: a start that finds a pinned predecessor not yet
# retired in this process retires it first. The drain lock excludes the
# operator verbs, so a verb's audited rollback never follows a retire.
# ---------------------------------------------------------------------------

LOST_ACK_FILE = "lost_ack.json"
HOLD_TREE_LOST = "hop_tree_lost"                     # the whole instance
HOLD_RETIRE_FAILED = "hop_retire_failed"             # the whole instance, retried
HOLD_FENCED_TREE_ABSENT = "hop_fenced_tree_absent"   # that generation's work only
HOLD_FENCED_UNPINNED = "hop_fenced_unpinned"         # that generation's work only
#: This router's own attachment snapshot failed its read-back for a request
#: already handed over (`inflight.SnapshotDamaged`): that generation's
#: hand-overs are latched (`set_write_hold`) until `router generation new`.
#: RL-internal: never a plugin `.reason`, so not a write-table row.
HOLD_SNAPSHOT_DAMAGED = "hop_snapshot_damaged"       # that generation's work only
#: The points the test-only hook is called at (`service.FENCE_STOP_AT`).
FENCE_POINTS = ("fence_recorded", "retired_written")
#: The hint `status.json` gives with a lost tree.
TREE_LOST_HINT = (
    "`router generation new <name> --reason <text>` (router stopped) acknowledges the lost "
    "tree and moves the instance on; its in-flight records are left for disposal (§5.4). If "
    "the verb refuses with layout/marker_unreadable, the tree is present but damaged: it is "
    "NOT lost; repair it or dispose of its records (§5.4). A crash during the verb is "
    "recovered by running it again, and so is a lost tree that was the CURRENT "
    "generation when the verb ran (the verb acknowledges fenced generations only).")

#: (runtime id, state_dir, logical_id, gen, pin digest) -> the constructed
#: upstream marker store, while its retirement is not yet confirmed.
_STORES: Dict[Tuple, Any] = {}
#: Latched marker-store construction holds, by the same key.
_STORE_LATCHED: Dict[Tuple, HopHold] = {}
#: The same key -> "retired" (retire said created, exists_same or exists) or
#: "absent" (there was nothing to retire). Per process: a restart retires
#: again, which is the exists replay.
_RETIRED: Dict[Tuple, str] = {}
#: (state_dir, instance) -> the fence step's hold from this process's last
#: run; the current generation's sender is not constructed while it stands.
FENCE_HOLDS: Dict[Tuple[str, str], HopHold] = {}


class FenceStopped(BaseException):
    """The test-only hook stopped the fence (`service.FENCE_STOP_AT`). A
    BaseException, so no isolation belt on the way out of the poll can
    swallow a deliberate stop; the hook's own exception is `raised`."""

    def __init__(self, point: str, raised: BaseException):
        super().__init__(f"the fence stopped at {point}: {raised!r}")
        self.point, self.raised = point, raised


def _stop_hook() -> Any:
    """`service.FENCE_STOP_AT`, read where it is defined, at the moment it is
    needed. Not imported: when `router.service` was never imported, nothing
    can have set it."""
    import sys
    service = sys.modules.get(f"{__package__}.service")
    return getattr(service, "FENCE_STOP_AT", None)


def _stop_at(point: str) -> None:
    hook = _stop_hook()
    if hook is None:
        return
    try:
        hook(point)
    except BaseException as e:  # noqa: BLE001 -- the hook's stop, re-raised whole
        raise FenceStopped(point, e) from e


def gen_transport_dir(state_dir: Any, lid: str, gen: str) -> Path:
    return generations_mod.gen_dir(Path(state_dir), lid, gen) / TRANSPORT_DIR


def _is_retired(runtime: Any, cfg: Any, lid: str, gen: str) -> bool:
    try:
        pin = _read_json_file(gen_transport_dir(cfg.state_dir, lid, gen) / PIN_FILE)
    except (OSError, ValueError):
        return False
    return pin is not None and _pin_key(runtime, cfg.state_dir, lid, gen, pin) in _RETIRED


def fence_step(runtime: Any, cfg: Any, name: str) -> None:
    """Retire every fenced predecessor of `name`'s current generation that
    this router pinned and that is not yet retired in this process, oldest
    first, BEFORE the current generation's sender is constructed. A
    predecessor without a pin was never admitted by this router: there is
    nothing to retire. Records the outcome in `FENCE_HOLDS`; raises only
    `FenceStopped` (the test hook), never anything else."""
    hkey = (str(cfg.state_dir), name)
    try:
        lid, current = split_gen_key(config_mod.gen_key(cfg, name))
    except Exception:  # noqa: BLE001 -- no generation this poll: nothing to fence
        return
    try:
        pending = _unretired(runtime, cfg, lid, current)
    except Exception as e:  # noqa: BLE001 -- cannot be shown retired: hold
        _fence_hold(cfg, name, HopHold(f"{HOLD_RETIRE_FAILED}:{type(e).__name__}", str(e),
                                       latched=False, scope="instance"))
        return
    if not pending:
        FENCE_HOLDS.pop(hkey, None)
        return
    _stop_at("fence_recorded")
    # EVERY pending predecessor is attempted, each poll: one that holds
    # never stops a newer one being retired (a fenced generation's requests
    # stay claimable until its tree is retired). The oldest hold is kept.
    kept: Optional[HopHold] = None
    for entry, pin in pending:
        try:
            hold = _retire_one(runtime, cfg, name, lid, entry, pin)
        except Exception as e:  # noqa: BLE001 -- never escapes the drain
            hold = HopHold(f"{HOLD_RETIRE_FAILED}:{type(e).__name__}", str(e),
                           latched=False, scope="instance")
        if hold is not None and kept is None:
            kept = hold
    if kept is not None:
        _fence_hold(cfg, name, kept)
        return
    FENCE_HOLDS.pop(hkey, None)
    _stop_at("retired_written")


def _fence_hold(cfg: Any, name: str, hold: HopHold) -> None:
    key = (str(cfg.state_dir), name)
    prior = FENCE_HOLDS.get(key)
    if prior is not None and prior.reason == hold.reason:
        hold.since, hold.since_ts = prior.since, prior.since_ts
    FENCE_HOLDS[key] = hold


def _unretired(runtime: Any, cfg: Any, lid: str, current: str) -> List[Tuple[Dict, Dict]]:
    """`(generations entry, pin)` of every fenced generation with a pin that
    is not yet retired in this process, in the generations file's order."""
    doc = generations_mod.read_doc(cfg.state_dir, lid)
    if doc is None:
        raise ValueError(f"no generations record for {lid}")
    out = []
    for g in doc["gens"]:
        if g["gen"] == current:
            continue
        pin = _read_json_file(gen_transport_dir(cfg.state_dir, lid, g["gen"]) / PIN_FILE)
        if pin is None or _pin_key(runtime, cfg.state_dir, lid, g["gen"], pin) in _RETIRED:
            continue
        out.append((g, pin))
    return out


def store_settings(pin: Dict[str, Any], lid: str, gen: str) -> Dict[str, Any]:
    """An upstream marker store's settings: exactly the four-key core, from
    the generation's PIN (the root it was admitted under)."""
    return {"hop_root": pin["hop_root"], "logical_id": lid, "generation": gen,
            "peer_uid": pin["peer_uid"]}


def _store_for(runtime: Any, cfg: Any, lid: str, gen: str, pin: Dict[str, Any],
               key: Tuple) -> Any:
    """The generation's upstream marker store: constructed once and kept
    while its retirement is not confirmed. Raises `HopHold` (the
    construction rows of the closed table)."""
    store = _STORES.get(key)
    if store is not None:
        return store
    if key in _STORE_LATCHED:
        raise _STORE_LATCHED[key].fresh()
    if pin.get("hop_root") != runtime.hop.root:
        # One FsOps has exactly one hop root: a generation pinned to another
        # can never be retired through it.
        raise HopHold(HOLD_BINDING_CHANGED,
                      f"generation {gen} is pinned to {pin.get('hop_root')!r}, the hop root "
                      f"is {runtime.hop.root!r}", latched=True, scope="instance")
    try:
        store = runtime.plugin.make_upstream_marker_store(store_settings(pin, lid, gen),
                                                          runtime.fsops)
    except Exception as e:  # noqa: BLE001 -- classified, never swallowed silently
        hold = _construction_hold(e)
        if hold.latched:
            _STORE_LATCHED[key] = hold
        raise hold from e
    _STORES[key] = store
    return store


def _retire_one(runtime: Any, cfg: Any, name: str, lid: str, entry: Dict[str, Any],
                pin: Dict[str, Any]) -> Optional[HopHold]:
    """Retire one fenced generation at its fence time (never the clock).
    None when it is retired, or there was nothing to retire; else the hold."""
    gen = entry["gen"]
    key = _pin_key(runtime, cfg.state_dir, lid, gen, pin)
    try:
        store = _store_for(runtime, cfg, lid, gen, pin, key)
    except HopHold as e:
        e.scope = "instance"       # no successor is admitted while it stands
        return e
    try:
        result = store.retire(entry["fenced_ts"])
    except Exception as e:  # noqa: BLE001 -- the retire row: BLOCKED, retried
        kind, detail = transport_mod.classify(e, runtime=tuple(_RUNTIME_CLASSES))
        if kind == "reason" and detail == "closed":
            _close_store(key)
        return HopHold(f"{HOLD_RETIRE_FAILED}:{detail or type(e).__name__}",
                       f"generation {gen}: {type(e).__name__}: {e}", latched=False,
                       scope="instance")
    if result in ("created", "exists_same", "exists"):
        if result == "exists":
            logger.warning("instance %r: generation %s was already retired at another "
                           "instant (not an error)", name, gen)
        logger.info("instance %r: generation %s retired (%s)", name, gen, result)
        if result != "exists_same":
            _audit_retired(runtime, cfg, name, lid, gen, result, entry["fenced_ts"])
        _RETIRED[key] = "retired"
        _close_store(key)
        return None
    if result == "absent":
        tdir = gen_transport_dir(cfg.state_dir, lid, gen)
        if (tdir / ADMITTED_FILE).is_file() and not (tdir / LOST_ACK_FILE).is_file():
            return HopHold(HOLD_TREE_LOST,
                           f"generation {gen} was admitted and its hop tree is gone; no "
                           "successor is admitted until the loss is acknowledged",
                           latched=True, scope="instance")
        _RETIRED[key] = "absent"
        _close_store(key)
        return None
    return HopHold(f"{HOLD_RETIRE_FAILED}:protocol",
                   f"generation {gen}: retire returned {result!r}", latched=False,
                   scope="instance")


def recorded_value_unreadable(runtime: Any) -> str:
    """What an "exists" line says in place of the marker's own retired_at:
    the loaded API offers no read of it (`UpstreamMarkers` has `retire` and
    a boolean `retired`)."""
    api = getattr(runtime.plugin, "api", None)
    where = f"PLUGIN_API {tuple(api)}" if api is not None else "the plugin"
    return f"not readable through {where}"


def _audit_retired(runtime: Any, cfg: Any, name: str, lid: str, gen: str, result: str,
                   attempted: str) -> None:
    """One AUDIT line for a retirement this router made ("created") or found
    ("exists"). A failure to write it is an ERROR and never undoes or holds
    the retirement: the retire has happened and cannot be taken back."""
    fields: Dict[str, Any] = {"gen": gen, "result": result, "retired_at_attempted": attempted}
    if result == "exists":
        fields.update(recorded_retired_at=None,
                      recorded_value=recorded_value_unreadable(runtime))
    try:
        audit_mod.append(cfg.state_dir, name, audit_mod.EVENT_GENERATION_RETIRED,
                         state_key=lid, **fields)
    except Exception:  # noqa: BLE001 -- the retirement stands; its line is reported
        logger.exception("instance %r: generation %s retired (%s) but its audit line "
                         "could not be written", name, gen, result)


def _close_store(key: Tuple) -> None:
    store = _STORES.pop(key, None)
    if store is not None:
        _close_quietly(store)


class FencedSenders:
    """The fenced leg's transport: one sender per fenced generation, never
    constructed before that generation's tree is retired in this process
    (so the construction is always the replay of an admitted tree, never a
    first admission). The drain asks per generation (`for_view`)."""

    def __init__(self, runtime: Any):
        self.runtime = runtime

    def for_view(self, view: Any, name: str) -> Any:
        """The sender for `view`'s (fenced) generation, or `Held`."""
        try:
            return fenced_sender_for(self.runtime, view, name)
        except HopHold as e:
            return Held(e)
        except Exception as e:  # noqa: BLE001 -- a fenced leg's failure is a retried hold
            return Held(HopHold(f"{HOLD_CONSTRUCT_FAILED}:{type(e).__name__}", str(e),
                                latched=False))


def fenced_sender_for(runtime: Any, view: Any, name: str) -> Any:
    """A FENCED generation's sender (`view` is keyed on it). Raises `HopHold`:
    not yet retired; retired as absent (its records are never served through
    the hop); never pinned; or a construction row."""
    lid, gen = split_gen_key(config_mod.gen_key(view, name))
    pin = read_pin(view, name)
    if pin is None:
        raise HopHold(HOLD_FENCED_UNPINNED,
                      f"generation {gen} was never admitted through the hop", latched=False)
    key = _pin_key(runtime, view.state_dir, lid, gen, pin)
    state = _RETIRED.get(key)
    if state is None:
        raise fenced_until_retired()
    if state == "absent":
        raise HopHold(HOLD_FENCED_TREE_ABSENT,
                      f"generation {gen} has no hop tree; its records are left for "
                      "disposal (§5.4)", latched=True)
    if key in _SENDERS:
        return _SENDERS[key]
    latched = _LATCHED.get(key)
    if latched is not None:
        raise latched.fresh()
    try:
        port = runtime.plugin.make_sender(settings_for(view, name, pin), runtime.fsops)
    except Exception as e:  # noqa: BLE001 -- classified, never swallowed silently
        hold = _construction_hold(e)
        if hold.latched:
            _LATCHED[key] = hold
        raise hold from e
    _SENDERS[key] = port
    return port


def evict_drained(view: Any, name: str) -> None:
    """A fenced generation whose in-flight set is empty: its sender is closed
    and dropped (every anchor is durable and every record deleted before a
    record leaves `inflight/`). Under the drain lock, like every drain."""
    evict_sender(view, name)


def lost_candidates(cfg: Any, lid: str, doc: Dict[str, Any]) -> List[str]:
    """The fenced generations that may be lost: admitted (`admitted.json`)
    and not acknowledged (`lost_ack.json`)."""
    out = []
    for g in doc.get("gens", []):
        if g["gen"] == doc.get("current"):
            continue
        tdir = gen_transport_dir(cfg.state_dir, lid, g["gen"])
        if (tdir / ADMITTED_FILE).is_file() and not (tdir / LOST_ACK_FILE).is_file():
            out.append(g["gen"])
    return out


class LostSetRefused(Exception):
    """The lost set cannot be decided: the verb refuses and writes no ack."""


def lost_set(runtime: Any, cfg: Any, lid: str, doc: Dict[str, Any]) -> List[str]:
    """The candidates whose tree is ABSENT, decided by probing each through
    an upstream marker store only (its construction writes nothing and never
    admits; no sender is ever constructed here): `GenerationAbsent` means
    lost; True or False means the tree exists; anything else raises
    `LostSetRefused`. Each store is closed after its probe."""
    lost = []
    for gen in lost_candidates(cfg, lid, doc):
        pin = _read_json_file(gen_transport_dir(cfg.state_dir, lid, gen) / PIN_FILE)
        if pin is None:
            raise LostSetRefused(f"generation {gen} is admitted but has no pin")
        try:
            store = runtime.plugin.make_upstream_marker_store(store_settings(pin, lid, gen),
                                                              runtime.fsops)
        except Exception as e:  # noqa: BLE001 -- never guessed
            raise LostSetRefused(f"generation {gen}: {type(e).__name__}: {e}") from e
        try:
            absent = transport_mod.capture_verdict_class(
                store, "GenerationAbsent", runtime.fsops, "marker_vocabulary")
            try:
                store.retired()
            except absent:
                lost.append(gen)
            except Exception as e:  # noqa: BLE001 -- never guessed
                raise LostSetRefused(f"generation {gen}: {type(e).__name__}: {e}") from e
        except transport_mod.SeamRefused as e:
            raise LostSetRefused(f"generation {gen}: {e}") from e
        finally:
            _close_quietly(store)
    return lost


class LostAcks:
    """`generations.operator_new`'s `lost`: the verb's view of lost hop
    trees. The plugin is loaded (`load`, as the service loads it) only when
    there is a candidate to probe."""

    def __init__(self, cfg: Any, load: Any):
        self.cfg, self._load, self._runtime = cfg, load, None

    def candidates(self, lid: str, doc: Dict[str, Any]) -> List[str]:
        return lost_candidates(self.cfg, lid, doc)

    def find(self, lid: str, doc: Dict[str, Any]) -> List[str]:
        if not lost_candidates(self.cfg, lid, doc):
            return []
        if self._runtime is None:
            self._runtime = self._load(self.cfg)
        return lost_set(self._runtime, self.cfg, lid, doc)

    def ack(self, lid: str, gens: Iterable[str], reason: str, audit_ref: str) -> None:
        write_lost_acks(self.cfg, lid, gens, reason, audit_ref)


def write_lost_acks(cfg: Any, lid: str, gens: Iterable[str], reason: str,
                    audit_ref: str) -> None:
    """Acknowledge each lost generation (`router generation new` only, AFTER
    its audit line). Nothing else writes this file."""
    for gen in gens:
        atomic_write(gen_transport_dir(cfg.state_dir, lid, gen) / LOST_ACK_FILE,
                     canonical({"acked_ts": utc_ts(), "reason": reason, "audit_ref": audit_ref}),
                     durable_root=cfg.state_dir)


# ---------------------------------------------------------------------------
# The write_request row of the closed exception table: what LATCHES a hold
# on this generation's hand-overs, and what is retried with the same id.
# ---------------------------------------------------------------------------

HOLD_FILE = "hold.json"

#: A plugin `.reason` from `write_request` that no retry can change, and the
#: hold it latches on THIS generation's hand-overs (results are still read).
#: Every other reason, and every other exception, is retried next poll with
#: the same record and the same transport id.
LATCHED_WRITE_REASONS: Dict[str, str] = {
    "request_exists_different": "hop_request_conflict",
    "request_exists_withdrawn": "hop_request_withdrawn",
    "request_exists_settled": "hop_request_settled",
    "below_frontier": "hop_frontier_undecidable",
    "handover_invalid": "hop_handover_invalid",
    "exists_different": "hop_heal:exists_different",
    "reconcile": "hop_heal:reconcile",
    "sidecars": "hop_heal:sidecars",
    "sidecars_orphaned": "hop_heal:sidecars_orphaned",
}

#: The plugin `.reason`s that are NOT `write_request` rows, and why: with
#: `LATCHED_WRITE_REASONS` and `RETRY_WRITE_REASONS` they partition
#: `transport.TRANSPORT_REASONS` (asserted), so a new reason is classified.
NOT_WRITE_REASONS: Dict[str, str] = {
    "owner": "only an intake reader raises it; from a sender it is unexpected",
    "settings_invalid": "a factory's settings check; a construction row",
}

#: The runtime's own classes with their roles, from the last runtime
#: resolved in this process, so `classify` sees them before any `.reason`.
_RUNTIME_CLASSES: List[Tuple[type, str]] = []


def write_hold(cfg: Any, name: str) -> Optional[Dict[str, Any]]:
    """This generation's latched hand-over hold, or None."""
    return _read_json_file(transport_dir(cfg, name) / HOLD_FILE)


def latch_for_write(exc: BaseException) -> Optional[str]:
    """The hold `exc` latches, or None for a retry."""
    kind, detail = transport_mod.classify(exc, runtime=tuple(_RUNTIME_CLASSES))
    if kind == "reason":
        return LATCHED_WRITE_REASONS.get(detail)
    return None


def set_write_hold(cfg: Any, name: str, reason: str, detail: str, n: str) -> None:
    """Latch it durably: only an operator act (`router generation new`, which
    fences this generation) moves the instance on; the record that hit it is
    left for disposal and never handed over again."""
    atomic_write(transport_dir(cfg, name) / HOLD_FILE,
                 canonical({"reason": reason, "detail": detail[:1024], "transport_req_id": n}),
                 durable_root=cfg.state_dir)


def evict_sender(cfg: Any, name: str) -> None:
    """Drop (and close) `name`'s current generation's cached sender, so the
    next poll constructs a fresh one: a sender that said it is closed."""
    lid, gen = split_gen_key(config_mod.gen_key(cfg, name))
    for key in [k for k in _SENDERS if k[1:4] == (str(cfg.state_dir), lid, gen)]:
        try:
            _SENDERS.pop(key).close()
        except Exception:  # noqa: BLE001 -- close is cleanup
            logger.exception("closing a hop sender failed")


# ---------------------------------------------------------------------------
# The write_request row's RETRIES: the status each one shows, how loudly it
# is logged, and this process's record of them for status.json.
# ---------------------------------------------------------------------------

#: A plugin `.reason` from `write_request` that is retried, and its status.
#: `owner` is not one: only an intake reader raises it, so from a sender it
#: is unexpected.
RETRY_WRITE_REASONS: Dict[str, str] = {
    "version": "hop_version_unavailable",
    "layout": "hop_layout",
    "heal_state": "hop_anomaly:heal_state",
    "protocol_violation": "hop_anomaly:protocol_violation",
    "marker_unreadable": "hop_anomaly:marker_unreadable",
    "closed": "hop_object_closed",
}
#: The retries that self-clear in a routine sequence (an upgrade, readers
#: first; the peer not yet ready): WARNING when first seen, ERROR only once
#: older than `inflight.STALE_AFTER_S`. Every other retry is an ERROR on
#: every poll.
QUIET_RETRIES = ("hop_version_unavailable", "hop_layout", "hop_io_error")
#: What a status means, where its name alone could mislead.
RETRY_HINTS: Dict[str, str] = {
    "hop_layout": ("the peer's down/ does not exist yet (clears once it does), OR this "
                   "router's own tree directories are missing (does NOT clear by itself)"),
}
#: The status for an exception the closed table does not name: retried, and
#: logged with its traceback.
RETRY_UNEXPECTED = "hop_unexpected"

#: This process's latest hand-over retry per (state_dir, instance, generation).
RETRIES: Dict[Tuple[str, str, str], Dict[str, Any]] = {}


def retry_status(exc: BaseException) -> str:
    """The status a retried `write_request` exception shows."""
    kind, detail = transport_mod.classify(exc, runtime=tuple(_RUNTIME_CLASSES))
    if kind == "reason" and detail in RETRY_WRITE_REASONS:
        return RETRY_WRITE_REASONS[detail]
    if kind == "runtime":
        why = getattr(exc, "reason", None)
        return f"hop_{detail}:{why}" if type(why) is str else f"hop_{detail}"
    if kind == "oserror":
        return "hop_io_error"
    return RETRY_UNEXPECTED


def note_retry(cfg: Any, name: str, status: str, detail: str, n: str) -> float:
    """Record a retry of transport id `n` with `status`, keeping its first
    sighting while the status is unchanged; its age in seconds."""
    key = (str(cfg.state_dir), name, config_mod.gen_key(cfg, name))
    prior = RETRIES.get(key)
    now = _clock()
    if prior is None or (prior["status"], prior["transport_req_id"]) != (status, n):
        prior = {"status": status, "transport_req_id": n, "since": now, "since_ts": utc_ts()}
    prior["detail"] = detail[:1024]
    RETRIES[key] = prior
    return now - prior["since"]


def clear_retry(cfg: Any, name: str, *, n: Optional[str] = None,
                prefix: Optional[str] = None) -> None:
    """Forget this generation's retry; with `n` and `prefix`, only when it is
    transport id `n`'s and its status starts with `prefix` (a probe that now
    works clears its own failure, never a hand-over's retry)."""
    key = (str(cfg.state_dir), name, config_mod.gen_key(cfg, name))
    prior = RETRIES.get(key)
    if prior is None:
        return
    if n is not None and (prior["transport_req_id"] != n
                          or not prior["status"].startswith(prefix or "")):
        return
    RETRIES.pop(key, None)


def status_doc(cfg: Any, names: Iterable[str]) -> Dict[str, Any]:
    """`status.json`'s `hop` section: per instance, the sender hold, the
    latched hand-over hold and the current retry, each with its age; and the
    senders this process holds open. Never part of the drained summary line."""
    now = _clock()
    state = str(cfg.state_dir)
    instances: Dict[str, Any] = {}
    for name in sorted(names):
        entry: Dict[str, Any] = {}
        hold = HOLDS.get((state, name))
        if hold is not None:
            entry["sender_hold"] = {
                "reason": hold.reason, "latched": hold.latched, "scope": hold.scope,
                "detail": hold.detail[:1024], "since": hold.since_ts,
                "age_s": int(now - hold.since)}
            hint = HOLD_HINTS.get(hold.reason)
            if hint is not None:
                entry["sender_hold"]["hint"] = hint
        try:
            key = config_mod.gen_key(cfg, name)
        except Exception:  # noqa: BLE001 -- an instance with no generation this poll
            key = None
        if key is not None:
            try:
                held = write_hold(cfg, name)
            except (OSError, ValueError) as e:
                entry["write_hold"] = {"reason": "unreadable", "detail": str(e)[:1024]}
            else:
                if held is not None:
                    entry["write_hold"] = dict(held, hint=WRITE_HOLD_HINT)
            retry = RETRIES.get((state, name, key))
            if retry is not None:
                entry["retry"] = {
                    "status": retry["status"], "transport_req_id": retry["transport_req_id"],
                    "detail": retry["detail"], "since": retry["since_ts"],
                    "age_s": int(now - retry["since"])}
                if retry["status"] in RETRY_HINTS:
                    entry["retry"]["hint"] = RETRY_HINTS[retry["status"]]
        if entry:
            if key is not None:
                entry["generation"] = key
            instances[name] = entry
    return {"instances": instances,
            "senders_open": sum(1 for k in _SENDERS if k[1] == state),
            "marker_stores_open": sum(1 for k in _STORES if k[1] == state)}


#: The operator exit a latched hold's status names (the closed table's).
GENERATION_NEW_HINT = ("`router generation new <name> --reason <text>` (router stopped) fences "
                       "this generation and begins the next; the held record is left for "
                       "disposal (§5.4)")
WRITE_HOLD_HINT = GENERATION_NEW_HINT
HOLD_HINTS: Dict[str, str] = {
    HOLD_TREE_LOST: TREE_LOST_HINT,
    HOLD_BINDING_CHANGED: ("restore the hop config this generation is pinned to: the hop "
                           "root is fixed for the life of state_dir, and moving the hop tree "
                           "means a new state_dir"),
    HOLD_IDENTITY_CONFLICT: ("`router generation new <name> --reason <text>` (router stopped); "
                             "the conflicting tree is left alone"),
}
