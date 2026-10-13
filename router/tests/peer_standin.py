"""A stand-in for the transport plugin's peer seam (PLUGIN_API (3, 3)), for
tests: the same factories, the same Protocol, the same reason vocabularies,
and SYNTHETIC crypto. Not Ed25519: a "signature" is SHA-512 over the seed and
the message, and a public key is SHA-256 of the seed, with a registry from
public key to seed so the verifier can recompute. That is enough to drive
every branch of this router's side; the real backend's vectors run in the
step-9 harness, against the real plugin, never here.

The vocabularies below are PINNED copies of the plugin's published sets
(`router/tests/test_peerlane.py` asserts this module uses exactly them).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import types
from typing import Any, Dict, List

#: The plugin's CodecError reasons (13) and KeyConfigError reasons (5).
REASONS = frozenset({
    "duplicate", "header_count", "header_encoding", "header_size", "key_id_mismatch",
    "key_validity", "no_statement", "signature", "statement_json", "statement_schema",
    "statement_value", "too_large", "unknown_key",
})
KEY_CONFIG_REASONS = frozenset({
    "duplicate_key_id", "inverted_validity", "key_malformed", "key_not_canonical",
    "key_small_order",
})


class CodecError(ValueError):
    def __init__(self, layer: str, reason: str, detail: str = ""):
        super().__init__(f"{layer}: {reason} {detail}".strip())
        self.layer, self.reason, self.detail = layer, reason, detail


class KeyConfigError(ValueError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"key configuration refused: {reason} {detail}".strip())
        self.reason = reason


class BackendError(RuntimeError):
    pass


class ConfigError(ValueError):
    pass


#: Public keys this module has handed out, to their seeds (the synthetic
#: verifier's only way back).
SEEDS: Dict[bytes, bytes] = {}
#: Public keys the gate refuses as small order or non-canonical (tests seed them).
SMALL_ORDER: set = set()
NON_CANONICAL: set = set()


def public_key(seed: bytes) -> bytes:
    pub = hashlib.sha256(b"standin-pub" + seed).digest()
    SEEDS[pub] = seed
    return pub


def _sign(seed: bytes, msg: bytes) -> bytes:
    return hashlib.sha512(b"standin-sig" + seed + msg).digest()


class Signer:
    def __init__(self, key_id: str, seed: bytes, fail: List[bool]):
        self.key_id, self._seed, self._fail = key_id, seed, fail

    def sign(self, msg: bytes) -> bytes:
        if self._fail and self._fail[0]:
            raise BackendError("the stand-in signer failed locally")
        return _sign(self._seed, msg)


class Verifier:
    def __init__(self, fail: List[bool]):
        self._fail = fail

    def verify(self, pub: bytes, msg: bytes, sig: bytes) -> bool:
        if not isinstance(pub, bytes) or len(pub) != 32:
            return False
        if self._fail and self._fail[0]:
            raise BackendError("the stand-in verifier failed locally")
        seed = SEEDS.get(pub)
        return seed is not None and _sign(seed, msg) == sig


class Key:
    def __init__(self, key_id: str, public_key: bytes, domains, runtime, not_before, not_after):
        self.key_id, self.public_key = key_id, public_key
        self.domains, self.runtime = tuple(domains), runtime
        self.not_before, self.not_after = not_before, not_after

    def valid_at(self, now) -> bool:
        return ((self.not_before is None or self.not_before <= now)
                and (self.not_after is None or now <= self.not_after))


class KeyTable:
    def __init__(self, keys):
        self._keys = {k.key_id: k for k in keys}

    def select(self, k, now):
        key = self._keys.get(k)
        if key is None:
            raise CodecError("codec", "unknown_key")
        if not key.valid_at(_utc(now)):
            raise CodecError("codec", "key_validity")
        return key


def _utc(now):
    return now if now.tzinfo else now.replace(tzinfo=datetime.timezone.utc)


def _instant(text):
    if text is None:
        return None
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise KeyConfigError("key_malformed", "not an instant") from None


def load_key_table(peers):
    if not isinstance(peers, (list, tuple)):
        raise KeyConfigError("key_malformed", "peers")
    keys, seen = [], set()
    for peer in peers:
        if not isinstance(peer, dict) or not isinstance(peer.get("keys", []), (list, tuple)):
            raise KeyConfigError("key_malformed", "peer")
        for e in peer.get("keys", ()):
            if not isinstance(e, dict):
                raise KeyConfigError("key_malformed", "key")
            k, hexpub = e.get("key_id"), e.get("public_key")
            if not isinstance(k, str) or not isinstance(hexpub, str) or len(hexpub) != 64:
                raise KeyConfigError("key_malformed", "key_id/public_key")
            if k in seen:
                raise KeyConfigError("duplicate_key_id", k)
            seen.add(k)
            pub = bytes.fromhex(hexpub)
            if pub in NON_CANONICAL:
                raise KeyConfigError("key_not_canonical", k)
            if pub in SMALL_ORDER:
                raise KeyConfigError("key_small_order", k)
            nb, na = _instant(e.get("not_before")), _instant(e.get("not_after"))
            if nb and na and nb > na:
                raise KeyConfigError("inverted_validity", k)
            keys.append(Key(k, pub, peer.get("domains", ()), peer.get("runtime"), nb, na))
    return KeyTable(keys)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise CodecError("codec", "header_encoding", "base64url") from None


def format_field(k, statement, signature):
    return f"k={k}; s={_b64u(statement)}; b={_b64u(signature)}"


def check1(fields):
    pairs = [(n.lower(), v) for n, v in fields]
    found = [(n, v) for n, v in pairs if n in ("amap-peer-statement", "amap-peer-control")]
    if not found:
        raise CodecError("codec", "no_statement")
    if len(found) != 1:
        raise CodecError("codec", "header_count")
    name, value = found[0]
    if not isinstance(value, str):
        raise CodecError("codec", "header_encoding")
    tags = {}
    for part in value.replace(" ", "").split(";"):
        if "=" not in part:
            raise CodecError("codec", "header_encoding")
        t, _, v = part.partition("=")
        if t in tags:
            raise CodecError("codec", "header_encoding")
        tags[t] = v
    if set(tags) != {"k", "s", "b"}:
        raise CodecError("codec", "header_encoding")
    statement, signature = _unb64u(tags["s"]), _unb64u(tags["b"])
    if len(signature) != 64:
        raise CodecError("codec", "header_encoding")
    if len(statement) > 8192:
        raise CodecError("codec", "header_size")
    kind = "peer" if name == "amap-peer-statement" else "control"
    return kind, tags["k"], statement, signature


def decode_statement(raw, k):
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CodecError("parse", "statement_json") from None
    if not isinstance(doc, dict) or doc.get("kind") != "peer" or doc.get("v") != 1:
        raise CodecError("schema", "statement_schema")
    if doc.get("key_id") != k:
        raise CodecError("schema", "key_id_mismatch")
    return doc


def decode_control(raw, k):
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CodecError("parse", "statement_json") from None
    if not isinstance(doc, dict) or doc.get("kind") != "control":
        raise CodecError("schema", "statement_schema")
    return doc


def encode_control(doc):
    if doc.get("kind") != "control":
        raise CodecError("schema", "statement_schema")
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_checked(kind, k, statement, signature, key_table, verifier, now):
    key = key_table.select(k, now)
    if not verifier.verify(key.public_key, statement, signature):
        raise CodecError("crypto", "signature")
    payload = decode_statement(statement, k) if kind == "peer" else decode_control(statement, k)
    return kind, payload, key


def verify_candidate(fields, key_table, verifier, now, known):
    kind, k, statement, signature = check1(fields)
    if known(kind, statement):
        raise CodecError("codec", "duplicate")
    return verify_checked(kind, k, statement, signature, key_table, verifier, now)


class PeerCodec:
    __slots__ = ()
    check1 = staticmethod(check1)
    verify_checked = staticmethod(verify_checked)
    verify_candidate = staticmethod(verify_candidate)
    load_key_table = staticmethod(load_key_table)
    format_field = staticmethod(format_field)
    decode_statement = staticmethod(decode_statement)
    decode_control = staticmethod(decode_control)
    encode_control = staticmethod(encode_control)
    REASONS = REASONS
    KEY_CONFIG_REASONS = KEY_CONFIG_REASONS


def namespace(*, api=(3, 3), sign_fails=None, verify_fails=None, calls=None) -> Dict[str, Any]:
    """A plugin namespace with the delegation factories. `calls` records
    each factory call's arguments; `sign_fails` / `verify_fails` are
    one-element lists a test flips to make the backend fail locally."""
    calls = calls if calls is not None else []
    sign_fails = sign_fails if sign_fails is not None else [False]
    verify_fails = verify_fails if verify_fails is not None else [False]

    def make_signer(settings, keyops):
        calls.append(("make_signer", dict(settings)))
        seed = keyops.signing_key()
        if len(seed) != 32:
            raise ConfigError("the signing key must be the 32-byte seed")
        return Signer(keyops.key_id(), seed, sign_fails)

    def make_verifier(settings):
        calls.append(("make_verifier", dict(settings)))
        return Verifier(verify_fails)

    def make_peer_codec(settings):
        calls.append(("make_peer_codec", settings))
        if type(settings) is not dict or settings:
            raise ConfigError("peer codec settings must be a plain empty dict")
        return PeerCodec()

    def make_peer_errors(*args):
        calls.append(("make_peer_errors", args))
        return types.MappingProxyType({"CodecError": CodecError, "KeyConfigError": KeyConfigError,
                                       "BackendError": BackendError, "ConfigError": ConfigError})

    return {"PLUGIN_API": api, "make_signer": make_signer, "make_verifier": make_verifier,
            "make_peer_codec": make_peer_codec, "make_peer_errors": make_peer_errors,
            "OPTIONAL_FACTORIES": {"make_intake_remover": (3, 1), "make_peer_codec": (3, 3),
                                   "make_peer_errors": (3, 3)}}


class Plugin:
    """A loaded-plugin stand-in: `api`, `namespace`, and the factories as
    attributes (as `transport.LoadedPlugin` offers them)."""

    def __init__(self, ns: Dict[str, Any]):
        self.api = ns["PLUGIN_API"]
        self.namespace = types.MappingProxyType(ns)

    def __getattr__(self, name):
        try:
            return self.namespace[name]
        except KeyError:
            raise AttributeError(name) from None
