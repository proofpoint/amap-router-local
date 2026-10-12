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


# ---------------------------------------------------------------------------
# The sender for one generation: its binding pin, its admission
# confirmation, and the per-process cache.
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402  (kept beside the half that uses it)
import logging  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Tuple  # noqa: E402

from . import config as config_mod  # noqa: E402
from . import generations as generations_mod  # noqa: E402
from . import transport as transport_mod  # noqa: E402
from .util import atomic_write  # noqa: E402

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


def settings_for(cfg: Any, name: str, pin: Dict[str, Any]) -> Dict[str, Any]:
    """The sender's settings, exactly the plugin's closed list, taken from the
    PIN (never the current config) and the generation key."""
    lid, gen = split_gen_key(config_mod.gen_key(cfg, name))
    return {"hop_root": pin["hop_root"], "logical_id": lid, "generation": gen,
            "peer_uid": pin["peer_uid"], "version_write": pin["version_write"],
            "caps": dict(cfg.hop.caps), "admitted_at": pin["admitted_at"], "role": "hop1"}


def admitted(cfg: Any, name: str) -> bool:
    return (transport_dir(cfg, name) / ADMITTED_FILE).is_file()


def fenced_admitted(cfg: Any, name: str) -> List[str]:
    """The fenced predecessors of `name`'s current generation that this
    router ADMITTED (an `admitted.json` beside their pin)."""
    lid, current = split_gen_key(config_mod.gen_key(cfg, name))
    doc = generations_mod.read_doc(cfg.state_dir, lid)
    out = []
    for g in (doc or {}).get("gens", []):
        if g["gen"] != current and (generations_mod.gen_dir(cfg.state_dir, lid, g["gen"])
                                    / TRANSPORT_DIR / ADMITTED_FILE).is_file():
            out.append(g["gen"])
    return out


#: The per-process cache: (runtime id, state_dir, logical_id, gen, pin digest)
#: -> the constructed sender. Filled only after a construction succeeded.
_SENDERS: Dict[Tuple, Any] = {}


def sender_for(runtime: Any, cfg: Any, name: str) -> Any:
    """`name`'s CURRENT generation's sender: constructed once per (generation,
    pin) per process, and only after the pin is durable. Its successful
    construction admitted the tree, so `admitted.json` is then written,
    before the first request is handed over. Raises `HopHold`."""
    fenced = fenced_admitted(cfg, name)
    if fenced:
        # Retiring a fenced predecessor is the fence step's; until it has
        # run, no successor is admitted (one live generation, contract §4.1).
        raise HopHold(HOLD_PREDECESSOR_UNRETIRED,
                      f"fenced generation(s) {fenced} not yet retired", latched=False,
                      scope="instance")
    pin = ensure_pin(cfg, name)
    lid, gen = split_gen_key(config_mod.gen_key(cfg, name))
    key = (id(runtime), str(cfg.state_dir), lid, gen,
           hashlib.sha256(canonical(pin)).hexdigest())
    port = _SENDERS.get(key)
    if port is not None:
        return port
    try:
        port = runtime.plugin.make_sender(settings_for(cfg, name, pin), runtime.fsops)
    except Exception as e:  # noqa: BLE001 -- classified, never swallowed silently
        raise _construction_hold(e) from e
    atomic_write(transport_dir(cfg, name) / ADMITTED_FILE,
                 canonical({"admitted_at": pin["admitted_at"], "hop_root": pin["hop_root"]}),
                 durable_root=cfg.state_dir)
    _SENDERS[key] = port
    return port


def _construction_hold(e: BaseException) -> HopHold:
    """The construction row of the closed exception table."""
    kind, detail = transport_mod.classify(e)
    if kind == "reason" and detail == "settings_invalid":
        return HopHold(HOLD_SETTINGS_REFUSED, str(e), latched=True)
    if kind == "reason" and detail == "exists_different":
        return HopHold(HOLD_IDENTITY_CONFLICT, str(e), latched=True)
    if isinstance(e, transport_mod.SeamRefused):
        return HopHold(HOLD_PLUGIN_VOCABULARY, str(e), latched=True, scope="instance")
    return HopHold(f"{HOLD_CONSTRUCT_FAILED}:{detail or kind}", str(e), latched=False)


def forget_senders() -> None:
    """Drop the cache, closing each sender (tests, and a process ending)."""
    for port in list(_SENDERS.values()):
        try:
            port.close()
        except Exception:  # noqa: BLE001 -- close is cleanup
            logger.exception("closing a hop sender failed")
    _SENDERS.clear()


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


#: This process's latest hold per (state_dir, instance), for status.
HOLDS: Dict[Tuple[str, str], HopHold] = {}


def resolve(transport: Any, cfg: Any, name: str) -> Tuple[Any, Any]:
    """`(current, fenced)`: the transport the drain uses for `name`'s current
    generation, and for its fenced generations' work. A runtime resolves to
    the current generation's sender (or `Held`); fenced generations get none
    here, since a fenced generation's sender may be constructed only after
    its tree is retired. Anything else (a test's port, or `None`) is used as
    given for both."""
    if not is_runtime(transport):
        return transport, transport
    if transport.fsops is not None and not _RUNTIME_CLASSES:
        _RUNTIME_CLASSES.extend(transport_mod.check_fsops_classes(transport.fsops))
    key = (str(cfg.state_dir), name)
    try:
        port = sender_for(transport, cfg, name)
    except HopHold as e:
        if HOLDS.get(key) is None or HOLDS[key].reason != e.reason:
            (logger.error if e.latched else logger.warning)(
                "instance %r: no hop sender this poll (%s): %s", name, e.reason, e.detail)
        HOLDS[key] = e
        return Held(e), None
    HOLDS.pop(key, None)
    return port, None


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
