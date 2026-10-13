"""router/peerlane.py — this router's side of cross-host signed peer traffic.

A peer task to a trusted fleet host travels as a SIGNED STATEMENT: a small
JSON object this router builds, signs with its own Ed25519 key, and hands
over with the hop envelope's `peer` object. This module owns what this
router decides about that, and nothing the plugin decides:

  * ACTIVATION (`activate`). With `delegation` configured, at startup and at
    every reload: the plugin's delegation capabilities
    (`transport.check_delegation`), the peer codec, the signer and verifier,
    the peer key table through the codec's key gate, this router's own key
    through the same gate, and a sign/verify PROBE proving the configured
    public key is the seed's. Any failure is `DelegationRefused`: startup
    stops, and a reload is refused (the last good config is kept).
  * THE SIGNING KEY (`read_seed`). A 32-byte seed, read by walking from `/`
    one component at a time with no symlink followed, every directory owned
    by root or this process and writable by group or others only when
    sticky, none of them a forbidden root, the file itself this process's,
    mode 0400, one link. Its bytes go to the plugin's signer and nowhere
    else.
  * EXACT-CLASS ERRORS (`error_kind`). The plugin's exception classes come
    from `make_peer_errors()`; an exception is one of them only when its
    type IS that class, and a refusal's `.reason` must be in the codec's
    published set. Anything else is a bug and is re-raised by the caller.
  * THE STATEMENT (`build_statement`), serialised with `hoplink.canonical`,
    checked by the codec before it is signed, and never re-serialised.
  * THE PEER LEDGER (`write_issued`): the closed `issued` record a reply or
    control notice resolves against, keyed by logical_id, durable before
    anything is handed over, kept by `router reset`.
  * THE DISPOSAL TOMBSTONE's bytes (`tombstone_bytes`), in the exact form
    the contract fixes, for the receiving side's journal.

Nothing here hands anything over; `router/outbound.py` does.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import json
import logging
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from . import config as config_mod
from . import hoplink
from . import transport as transport_mod
from .config import ConfigError, RouterConfig
from .util import atomic_write

logger = logging.getLogger("amap_router_local.peerlane")

#: The fixed message the signing-key probe signs and verifies.
PROBE = b"amap-rl-signing-key-probe/1"
#: The statement's cap, in bytes (item 5f).
STATEMENT_MAX_BYTES = 8192
#: The minted peer id: 17 random bytes as unpadded base64url (23
#: characters), never starting with `-`. The peer-origin profile requires a
#: peer id of at least 128 bits under the notice_id charset, whose first
#: character cannot be `-`; re-drawing on 16 bytes would leave under 128.
#: Only ISSUED ids (this router's own mints) match: no 22-character issued
#: id exists anywhere, since no peer signing has ever run live.
PEER_ID_BYTES = 17
PEER_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{22}\Z")
#: The peer ledger's directory under a logical_id's private state.
PEER_LEDGER_DIR = "peer-ledger"
#: The peer ledger record's members, exactly: a closed record, keyed by
#: logical_id, that a reply or a control notice resolves against.
LEDGER_MEMBERS = ("id", "local", "local_address", "remote", "direction", "generation",
                  "expires_at")
#: The header field names the codec's check 1 reads.
STATEMENT_FIELD = "AMAP-Peer-Statement"
CONTROL_FIELD = "AMAP-Peer-Control"
#: The tombstone's members and values: the closed form the downstream
#: runtime checks before it removes a host-intake entry.
TOMBSTONE_INTAKES = (".control", ".unresolved")
TOMBSTONE_DISPOSITIONS = ("placed", "mail", "dropped", "refused", "demoted")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_HEX32_RE = re.compile(r"[0-9a-f]{32}\Z")
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
#: The seed is exactly this long.
SEED_BYTES = 32
_CODEC_METHODS = ("check1", "verify_checked", "verify_candidate", "load_key_table",
                  "format_field", "decode_statement", "decode_control", "encode_control")


class DelegationRefused(ConfigError):
    """Delegation cannot be activated. `reason` names the check; startup
    stops and a reload is refused."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"delegation refused ({reason}): {detail}")
        self.reason = reason
        self.detail = detail


class StatementRefused(ValueError):
    """The draft cannot make a statement (a lone surrogate, an encoding the
    canonical encoder refuses). Answered `rejected`/`malformed_request`."""


@dataclass(frozen=True)
class Delegation:
    """Delegation as activated: the config it came from, the plugin's
    objects, and the key table, ready to sign and verify."""
    config: "config_mod.DelegationConfig"
    signer: Any
    verifier: Any
    codec: Any
    errors: Mapping[str, type]
    key_table: Any
    reasons: frozenset
    key_config_reasons: frozenset
    #: What activation depended on (`fingerprint`), set by the caller that
    #: installs it; None when unknown.
    fingerprint: Any = None

    @property
    def key_id(self) -> str:
        return self.config.signing_key_id


#: PROCESS state: the delegation activated for each state_dir.
_ACTIVE: Dict[str, Delegation] = {}


def active(cfg: RouterConfig) -> Optional[Delegation]:
    """The delegation activated for `cfg`'s state_dir, or None. None also
    when `cfg` has no `delegation`: a reload that removed it ends it."""
    if getattr(cfg, "delegation", None) is None:
        return None
    return _ACTIVE.get(str(cfg.state_dir))


def current(cfg: RouterConfig) -> Optional[Delegation]:
    """The delegation installed for `cfg`'s state_dir, whatever `cfg`
    itself configures (a reload compares against it)."""
    return _ACTIVE.get(str(cfg.state_dir))


def fingerprint(cfg: RouterConfig, plugin: Any) -> Optional[Tuple[Any, ...]]:
    """What activating `cfg`'s delegation depends on, cheaply: the
    delegation config, the plugin object, and the seed file's device, inode,
    mtime, size, mode, owner and links (lstat, never following a link).
    None when the seed cannot be stat'ed: then activation runs, and refuses.
    A change to a directory ABOVE the seed is not seen here; it is seen at
    the next activation, which a change to any of these triggers."""
    dc = cfg.delegation
    try:
        st = os.lstat(dc.signing_key_path)
    except OSError:
        return None
    return (dc, id(plugin), st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode,
            st.st_uid, st.st_nlink)


def install(cfg: RouterConfig, delegation: Optional[Delegation]) -> None:
    """Make `delegation` the one `active` returns for `cfg` (None removes it)."""
    if delegation is None:
        _ACTIVE.pop(str(cfg.state_dir), None)
    else:
        _ACTIVE[str(cfg.state_dir)] = delegation


def forget_all() -> None:
    """Drop every activated delegation (tests)."""
    _ACTIVE.clear()


# ---------------------------------------------------------------------------
# The signing key
# ---------------------------------------------------------------------------

def _identities(roots: Iterable[str]) -> set:
    out = set()
    for r in roots:
        try:
            st = os.stat(r)
        except OSError:
            continue
        out.add((st.st_dev, st.st_ino))
    return out


def _check_dir(st: os.stat_result, where: str, forbidden: set) -> None:
    if st.st_uid not in (0, os.geteuid()):
        raise DelegationRefused("signing_key_path", f"{where} is owned by uid {st.st_uid}")
    if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
        raise DelegationRefused("signing_key_path",
                                f"{where} is writable by group or others "
                                f"(mode {oct(stat.S_IMODE(st.st_mode))})")
    if (st.st_dev, st.st_ino) in forbidden:
        raise DelegationRefused("signing_key_path", f"{where} is a forbidden root")


def read_seed(path: str, forbidden_roots: Iterable[str]) -> bytes:
    """The 32-byte seed at `path` (module docstring, THE SIGNING KEY), or
    `DelegationRefused("signing_key_path")`. `path` is already in normal
    form and lexically outside every forbidden root (`config._delegation`)."""
    forbidden = _identities(forbidden_roots)
    parts = path.split("/")[1:]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        _check_dir(os.fstat(fd), "/", forbidden)
        walked = ""
        for comp in parts[:-1]:
            walked += "/" + comp
            try:
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as e:
                why = "a symlink" if e.errno in (errno.ELOOP, errno.ENOTDIR) else e.strerror
                raise DelegationRefused("signing_key_path", f"{walked}: {why}") from None
            os.close(fd)
            fd = nfd
            _check_dir(os.fstat(fd), walked, forbidden)
        try:
            kfd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except OSError as e:
            why = "a symlink" if e.errno == errno.ELOOP else e.strerror
            raise DelegationRefused("signing_key_path", f"{path}: {why}") from None
    finally:
        os.close(fd)
    try:
        try:
            st = os.fstat(kfd)
        except OSError as e:
            raise DelegationRefused("signing_key_path", f"{path}: {e.strerror}") from None
        if not stat.S_ISREG(st.st_mode):
            raise DelegationRefused("signing_key_path", f"{path} is not a regular file")
        if st.st_nlink != 1:
            raise DelegationRefused("signing_key_path", f"{path} has {st.st_nlink} links")
        if st.st_uid != os.geteuid():
            raise DelegationRefused("signing_key_path", f"{path} is owned by uid {st.st_uid}")
        if stat.S_IMODE(st.st_mode) != 0o400:
            raise DelegationRefused("signing_key_path",
                                    f"{path} has mode {oct(stat.S_IMODE(st.st_mode))}; 0400 "
                                    "required")
        try:
            data = os.read(kfd, SEED_BYTES + 1)
        except OSError as e:
            raise DelegationRefused("signing_key_path", f"{path}: {e.strerror}") from None
    finally:
        os.close(kfd)
    if len(data) != SEED_BYTES:
        raise DelegationRefused("signing_key_path", f"{path} is not exactly {SEED_BYTES} bytes")
    return data


class KeyOps:
    """The `transport.KeyOps` the plugin's signer takes: the seed's bytes
    and the configured key id. The signer never opens a path."""

    def __init__(self, seed: bytes, key_id: str):
        self._seed, self._key_id = seed, key_id

    def signing_key(self) -> bytes:
        return self._seed

    def key_id(self) -> str:
        return self._key_id


# ---------------------------------------------------------------------------
# Exact-class errors
# ---------------------------------------------------------------------------

def error_kind(delegation: Delegation, exc: BaseException) -> Optional[str]:
    """Which of the plugin's four classes `exc` IS (its exact type), or None
    for anything else, a subclass or a look-alike included. A
    `CodecError` or `KeyConfigError` counts only with a `str` `.reason` in
    the codec's published set; otherwise it too is None (a bug)."""
    for name, cls in delegation.errors.items():
        if type(exc) is cls:
            if name == "CodecError":
                reason = getattr(exc, "reason", None)
                return name if type(reason) is str and reason in delegation.reasons else None
            if name == "KeyConfigError":
                reason = getattr(exc, "reason", None)
                return (name if type(reason) is str and reason in delegation.key_config_reasons
                        else None)
            return name
    return None


# ---------------------------------------------------------------------------
# Activation
# ---------------------------------------------------------------------------

def _reason_set(value: Any, what: str) -> frozenset:
    if not (type(value) is frozenset and value
            and all(type(x) is str and x for x in value)):
        raise DelegationRefused("codec", f"the peer codec's {what} is not a non-empty "
                                         "frozenset of strings")
    return value


def activate(cfg: RouterConfig, plugin: Any, *, now: Any) -> Delegation:
    """Delegation for `cfg` (module docstring, ACTIVATION), or
    `DelegationRefused`. `plugin` is the loaded plugin; `now` is an aware
    datetime, for the own key's selection."""
    dc = cfg.delegation
    try:
        caps = transport_mod.check_delegation(plugin)
    except transport_mod.PluginRefused as e:
        raise DelegationRefused(e.reason, e.detail) from None
    try:
        codec = caps.make_peer_codec({})
    except Exception as e:  # noqa: BLE001 -- classified exactly
        if type(e) is caps.errors["ConfigError"]:
            raise DelegationRefused("codec", f"make_peer_codec({{}}) refused: {e}") from None
        raise   # a bug: never mistaken for a refusal
    for m in _CODEC_METHODS:
        if not callable(getattr(codec, m, None)):
            raise DelegationRefused("codec", f"the peer codec has no callable {m!r}")
    reasons = _reason_set(getattr(codec, "REASONS", None), "REASONS")
    key_config_reasons = _reason_set(getattr(codec, "KEY_CONFIG_REASONS", None),
                                     "KEY_CONFIG_REASONS")
    probe = Delegation(config=dc, signer=None, verifier=None, codec=codec, errors=caps.errors,
                       key_table=None, reasons=reasons, key_config_reasons=key_config_reasons)

    def local(e: BaseException, what: str) -> DelegationRefused:
        kind = error_kind(probe, e)
        if kind in ("ConfigError", "BackendError"):
            return DelegationRefused("backend", f"{what}: {type(e).__name__}: {e}")
        raise e   # a bug: never mistaken for a refusal

    seed = read_seed(dc.signing_key_path, dc.forbidden_roots)
    settings = dc.crypto_settings()
    try:
        signer = caps.make_signer(dict(settings), KeyOps(seed, dc.signing_key_id))
    except Exception as e:  # noqa: BLE001 -- classified exactly
        raise local(e, "make_signer") from None
    finally:
        del seed
    try:
        verifier = caps.make_verifier(dict(settings))
    except Exception as e:  # noqa: BLE001 -- classified exactly
        raise local(e, "make_verifier") from None

    def gate(peers: List[Dict[str, Any]], what: str) -> Any:
        try:
            return codec.load_key_table(peers)
        except Exception as e:  # noqa: BLE001 -- classified exactly
            if error_kind(probe, e) == "KeyConfigError":
                raise DelegationRefused(e.reason, f"{what}: {e}") from None
            raise

    table = gate(dc.key_table_input(), "delegation.runtimes")
    peer_ids = {k["key_id"] for r in dc.runtimes for k in r.keys}
    if dc.signing_key_id in peer_ids:
        raise DelegationRefused("duplicate_key_id",
                                f"the signing key_id {dc.signing_key_id!r} is also a peer's")
    own_domain = cfg.fleet_domain or ""
    own = gate([{"name": "self", "runtime": f"{config_mod.ROUTER_LOCAL_PART}@{own_domain}",
                 "domains": [own_domain],
                 "keys": [{"key_id": dc.signing_key_id, "public_key": dc.signing_public_key}]}],
               "delegation.signing_key")
    try:
        pub = own.select(dc.signing_key_id, now).public_key
    except Exception as e:  # noqa: BLE001 -- classified exactly
        if error_kind(probe, e) == "CodecError":
            raise DelegationRefused("signing_key_mismatch",
                                    f"the signing key cannot be selected: {e.reason}") from None
        raise
    if not (type(pub) is bytes and len(pub) == 32):
        raise DelegationRefused("codec", "the key gate's public key is not 32 bytes")
    try:
        sig = signer.sign(PROBE)
        ok = verifier.verify(pub, PROBE, sig)
    except Exception as e:  # noqa: BLE001 -- classified exactly
        raise local(e, "the signing-key probe") from None
    finally:
        sig = None
    if ok is not True:
        raise DelegationRefused("signing_key_mismatch",
                                "the configured public_key does not verify the seed's signature")
    return Delegation(config=dc, signer=signer, verifier=verifier, codec=codec,
                      errors=caps.errors, key_table=table, reasons=reasons,
                      key_config_reasons=key_config_reasons)


# ---------------------------------------------------------------------------
# The statement
# ---------------------------------------------------------------------------

def mint_peer_id() -> str:
    """A fresh peer id: 17 random bytes, unpadded base64url, re-drawn while
    it starts with `-` (about 135.98 bits)."""
    while True:
        peer_id = base64.urlsafe_b64encode(secrets.token_bytes(PEER_ID_BYTES)).rstrip(b"=").decode()
        if not peer_id.startswith("-"):
            return peer_id


def normalise_body(body_text: str) -> str:
    """`body_text` with every CRLF replaced by LF: the text handed over and
    the text hashed."""
    return body_text.replace("\r\n", "\n")


def build_statement(*, key_id: str, peer_id: str, from_address: str, to_address: str,
                    ts: str, subject: str, body_text: str,
                    attachments: Iterable[Mapping[str, Any]],
                    sender_exposure: Optional[Mapping[str, Any]],
                    sender_since: Optional[str], in_reply_to: Optional[str] = None) -> bytes:
    """The statement's exact bytes, `v: 1`, closed, canonical. `attachments`
    are the draft's descriptors in order (`sha256`, `size_bytes`,
    `filename`, `media_type`). `StatementRefused` for anything the encoding
    refuses, and for a missing `sender_exposure` or `sender_since`: both are
    mandatory on a cross-host peer task (items 5c and 5d refuse first)."""
    if sender_exposure is None or sender_since is None:
        raise StatementRefused("sender_exposure and sender_since are mandatory")
    try:
        body = normalise_body(body_text).encode("utf-8")
    except UnicodeEncodeError:
        raise StatementRefused("body_text cannot be encoded as UTF-8") from None
    doc: Dict[str, Any] = {
        "v": 1, "key_id": key_id, "kind": "peer", "id": peer_id,
        "from": from_address, "to": to_address, "ts": ts, "subject": subject,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "attachments": [{"sha256": a["sha256"], "size_bytes": a["size_bytes"],
                         "filename": a["filename"], "media_type": a["media_type"]}
                        for a in attachments],
    }
    if in_reply_to is not None:
        doc["in_reply_to"] = in_reply_to
    doc["sender_exposure"] = dict(sender_exposure)
    doc["sender_since"] = sender_since
    try:
        return hoplink.canonical(doc)
    except hoplink.CanonicalRefused as e:
        raise StatementRefused(f"the statement cannot be encoded: {e}") from None


#: Fixed-length stand-ins, the length of a minted id and a `ts`, so a size
#: computed before minting is the size of the statement minted after.
SIZE_ID = "A" * 23
SIZE_TS = "0000-00-00T00:00:00Z"


@dataclass(frozen=True)
class Signed:
    """A signed statement: its bytes, the signature, and the unfolded header
    value the envelope carries."""
    statement: bytes
    signature: bytes
    header: str


def sign_statement(delegation: Delegation, raw: bytes) -> Signed:
    """Check `raw` with the codec's statement decoder, then sign it. A codec
    refusal of this router's own bytes raises `StatementRefused` (an RL bug,
    never signed); a `BackendError` propagates (a local fault, retried)."""
    try:
        delegation.codec.decode_statement(raw, delegation.key_id)
    except Exception as e:  # noqa: BLE001 -- classified exactly
        if error_kind(delegation, e) == "CodecError":
            raise StatementRefused(f"the codec refuses this router's statement: {e.reason}") \
                from None
        raise
    signature = delegation.signer.sign(raw)
    header = delegation.codec.format_field(delegation.key_id, raw, signature)
    return Signed(raw, signature, header)


def sign_control(delegation: Delegation, doc: Mapping[str, Any]) -> Signed:
    """A control notice's encoded bytes, signature and header. NO production
    producer calls this yet: control notices are a later unit's."""
    raw = delegation.codec.encode_control(dict(doc))
    signature = delegation.signer.sign(raw)
    return Signed(raw, signature, delegation.codec.format_field(delegation.key_id, raw, signature))


def message_id(peer_id: str, domain: str) -> str:
    """A peer id's Message-ID: `<id@domain>`."""
    return f"<{peer_id}@{domain}>"


# ---------------------------------------------------------------------------
# The peer ledger
# ---------------------------------------------------------------------------

def ledger_path(cfg: RouterConfig, logical_id: str, peer_id: str) -> Path:
    return Path(cfg.state_dir) / logical_id / PEER_LEDGER_DIR / f"{peer_id}.json"


def issued_record(*, peer_id: str, logical_id: str, local_address: str, remote: str,
                  generation: str, expires_at: str) -> Dict[str, str]:
    """The closed `issued` record."""
    return {"id": peer_id, "local": logical_id, "local_address": local_address,
            "remote": remote, "direction": "issued", "generation": generation,
            "expires_at": expires_at}


def write_issued(cfg: RouterConfig, record: Mapping[str, str]) -> None:
    """Write `record` durably, never replacing one: an existing id is a bug."""
    if set(record) != set(LEDGER_MEMBERS) or record["direction"] != "issued":
        raise ValueError(f"not a closed issued record: {sorted(record)}")
    if not PEER_ID_RE.fullmatch(record["id"]):
        raise ValueError("the peer id is not a minted one")
    path = ledger_path(cfg, record["local"], record["id"])
    if os.path.lexists(path):
        raise FileExistsError(f"{path}: a peer id was minted twice")
    atomic_write(path, json.dumps(dict(record), sort_keys=True).encode("utf-8"),
                 durable_root=cfg.state_dir)


def read_ledger(cfg: RouterConfig, logical_id: str, peer_id: str) -> Optional[Dict[str, str]]:
    """The ledger record for `peer_id` under `logical_id`, or None (absent,
    unreadable, or not closed)."""
    if not PEER_ID_RE.fullmatch(peer_id or ""):
        return None
    try:
        doc = json.loads(ledger_path(cfg, logical_id, peer_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or set(doc) != set(LEDGER_MEMBERS):
        return None
    return doc


# ---------------------------------------------------------------------------
# The disposal tombstone
# ---------------------------------------------------------------------------

def tombstone_bytes(*, intake: str, ident: str, candidate_sha256: str, disposition: str,
                    disposed_at: str) -> bytes:
    """The tombstone's frozen bytes, in exactly the contract's form: a closed
    object of `v` (1), `intake`, `id` (32 lower-case hex), `candidate_sha256`
    (64 lower-case hex), `disposition` and `disposed_at`
    (`YYYY-MM-DDTHH:MM:SSZ`). `ValueError` for any member outside its form."""
    if intake not in TOMBSTONE_INTAKES:
        raise ValueError(f"intake {intake!r} is not one of {list(TOMBSTONE_INTAKES)}")
    if not _HEX32_RE.fullmatch(ident or ""):
        raise ValueError("id is not 32 lower-case hex digits")
    if not _HEX64_RE.fullmatch(candidate_sha256 or ""):
        raise ValueError("candidate_sha256 is not 64 lower-case hex digits")
    if disposition not in TOMBSTONE_DISPOSITIONS:
        raise ValueError(f"disposition {disposition!r} is not one of "
                         f"{list(TOMBSTONE_DISPOSITIONS)}")
    if not _UTC_RE.fullmatch(disposed_at or ""):
        raise ValueError("disposed_at is not YYYY-MM-DDTHH:MM:SSZ")
    return hoplink.canonical({"v": 1, "intake": intake, "id": ident,
                              "candidate_sha256": candidate_sha256, "disposition": disposition,
                              "disposed_at": disposed_at})
