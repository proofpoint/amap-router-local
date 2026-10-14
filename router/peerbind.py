"""router/peerbind.py — from a verified signed peer statement to its placement.

`peerverify.verify` runs the peer-origin profile's checks 1 and 3-5. This
module runs the binding checks after them, in the profile's order, and holds
the chain of authority that ends in a placement:

    authorise -> confirm -> decision_record -> commit_decision
              -> resume -> deliver.deliver_signed_peer

THE BINDING CHECKS (`bind`): 6 (the domain of `from` is one of the signing
runtime's configured domains), 7 (freshness) and 8 (the exposure asserter)
supplied by their callers, 9 (the body decodes under its charset and hashes
to `body_sha256`), 10 (the attachments' count, sizes and digests, in order)
and 11 (exactly one `Message-ID`, exactly `<id@domain-of-from>`). The first
failure decides, as a closed cause. Checks 7 and 8 are REQUIRED callables
with no default, so a caller cannot skip one by omission.

THE HOSTING TEST (`hosting`): `to` names an instance configured here (by
its exact local part, the domain compared ASCII case-insensitively, as the
profile compares addresses), or an ACTIVE alias of one. A registry-held
target, an alias with no decision or an unverifiable one is `Undecided`,
never misrouted: a misrouted drop is final.

THE AUTHORITY CHAIN. Every value that can lead to a placement is a frozen
`Authorised` carrying a seal: an HMAC under a key drawn when this module is
imported, over every part it binds. Only this module computes one, every
consumer re-checks it first, and it cannot be pickled, so no `Authorised`
outlives its process. `authorise` issues a FRESH one; `confirm` re-checks it
against the current configuration; `decision_record` turns a confirmed one
into the decision's bytes, MAC'd under a durable key in `state_dir` (the
key signs decision, reservation and supersession records, each under its
own label);
`commit_decision` writes those bytes into the candidate's record directory
(linked into place, never replacing, every step fsynced, then read back) and
only then returns a `PersistedDecision` receipt; `resume` takes ONLY a
receipt, re-reads the file through it and issues a DECIDED `Authorised`,
which is the only kind placement accepts. After a restart
`reopen_decision` issues the receipt from the file on disk. So a decision
takes effect only once it is durable, and a durable decision is resumed as
recorded, never re-decided.

These are cooperative guarantees, the strongest Python offers: code inside
the router process that deliberately reads a private key can forge. They
make the mistakes they name impossible without doing that.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from . import aliases as aliases_mod
from . import config as config_mod
from . import hoplink

#: The profile's check order. Checks 7 and 8 belong to their callers.
ORDER = (6, 7, 8, 9, 10, 11)

KEY_DOMAIN = "key_domain"
BODY_CHARSET = "body_charset"
BODY_DIGEST = "body_digest"
ATTACHMENT_COUNT = "attachment_count"
ATTACHMENT_DIGEST = "attachment_digest"
MESSAGE_ID = "message_id"
#: The causes this module's checks emit, closed.
CAUSES = frozenset({KEY_DOMAIN, BODY_CHARSET, BODY_DIGEST, ATTACHMENT_COUNT,
                    ATTACHMENT_DIGEST, MESSAGE_ID})

ORIGIN_FRESH = "fresh"
ORIGIN_DECIDED = "decided"

#: The candidate journal's directory under a logical_id's private state.
#: A decided record lives in `<state_dir>/<logical_id>/JOURNAL_DIR/<key>/`.
JOURNAL_DIR = "peer-candidates"
DECISION_FILE = "decision.json"
DECISION_STAGE_PREFIX = ".decision.json.stage-"
DECISION_KEY_FILE = "peer-decision.key"
DECISION_KEY_STAGE_PREFIX = ".peer-decision.key.stage-"
DECISION_KEY_BYTES = 32

#: Domain-separation labels: each key signs one kind of thing only.
_LABEL_AUTHORISED = b"amap-rl/authorised/1\x00"
_LABEL_PERSISTED = b"amap-rl/persisted-decision/1\x00"
_LABEL_DECISION = b"amap-rl/peer-decision/1\x00"

#: The process seal's key. Drawn at import, never exported, logged or
#: persisted; a restart draws a new one, so no sealed value outlives it.
_SEAL_KEY = secrets.token_bytes(32)

_NOTICE_ID_RE = re.compile(r"[a-f0-9]{32}\Z")
_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_FOLD_RE = re.compile(r"\r?\n(?=[ \t])")
_RECORD_MEMBERS = ("v", "state", "disposition", "record_id", "statement_sha256", "key_id",
                   "runtime", "hosted_instance", "notice_id", "ts", "body_sha256",
                   "attachment_sha256s")
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


# ---------------------------------------------------------------------------
# Outcomes and errors
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Demoted:
    """A binding check failed: `cause` is a closed token."""
    cause: str


@dataclass(frozen=True)
class Bound:
    """Every binding check passed: check 9's text and check 10's octets."""
    body_text: str
    attachments: Tuple[bytes, ...]


@dataclass(frozen=True)
class Hosted:
    instance: str


@dataclass(frozen=True)
class NotHosted:
    """`to` is not hosted here: misrouted."""


@dataclass(frozen=True)
class Undecided:
    """Whether `to` is hosted cannot be decided now; never misrouted."""
    reason: str


class CandidateMalformed(ValueError):
    """The candidate view breaks its own shape: a defect in what produced
    it, never a verdict."""


class AuthorisationMismatch(Exception):
    """A fresh authorisation does not hold under the current configuration
    (`kind` "stale"): nothing is persisted, decide again."""

    def __init__(self, kind: str, detail: str):
        super().__init__(f"{kind}: {detail}")
        self.kind, self.detail = kind, detail


class RecoveryCorrupt(Exception):
    """A decided record, its receipt or its snapshot does not hold: hold
    the candidate visibly; never decide it again."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


class NoDecision(Exception):
    """No decided record exists: the candidate is still reserved."""


class DecisionConflict(Exception):
    """A different decided record already exists for this candidate."""


class LinkConflict(Exception):
    """`_link_once`: the name exists with different bytes."""


class Unpublishable(Exception):
    """A decided statement carries a value no notice can publish (`member`):
    hold it visibly, never drop it and never rewrite it."""

    def __init__(self, member: str, detail: str = ""):
        super().__init__(f"{member}: {detail}" if detail else member)
        self.member = member


class RecipientGone(Exception):
    """The recorded recipient is no longer configured: hold visibly."""


# ---------------------------------------------------------------------------
# The candidate view
# ---------------------------------------------------------------------------

def _b64(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        raise CandidateMalformed(f"{where}: not a string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise CandidateMalformed(f"{where}: not base64") from None


def _view(candidate: Any) -> Tuple[List[Tuple[str, Any]], bytes, Optional[str], List[bytes]]:
    """(fields, body octets, charset label or None, attachment octets) of
    the verifier's candidate form, or `CandidateMalformed`."""
    if not isinstance(candidate, Mapping):
        raise CandidateMalformed("not an object")
    fields = candidate.get("fields")
    if not isinstance(fields, list):
        raise CandidateMalformed("fields: not a list")
    out_fields = []
    for i, pair in enumerate(fields):
        if not (isinstance(pair, (list, tuple)) and len(pair) == 2 and isinstance(pair[0], str)):
            raise CandidateMalformed(f"fields[{i}]: not a [name, value] pair")
        if not isinstance(pair[1], (str, Mapping)):
            raise CandidateMalformed(f"fields[{i}]: neither text nor a marker")
        out_fields.append((pair[0], pair[1]))
    body = candidate.get("body")
    if body is None:
        octets, label = b"", None
    elif isinstance(body, Mapping):
        label = body.get("charset")
        if label is not None and not isinstance(label, str):
            raise CandidateMalformed("body.charset: not a string")
        octets = _b64(body.get("octets_b64"), "body.octets_b64")
    else:
        raise CandidateMalformed("body: neither null nor an object")
    atts = candidate.get("attachments")
    if not isinstance(atts, list):
        raise CandidateMalformed("attachments: not a list")
    leaves = []
    for i, a in enumerate(atts):
        if not isinstance(a, Mapping):
            raise CandidateMalformed(f"attachments[{i}]: not an object")
        leaves.append(_b64(a.get("octets_b64"), f"attachments[{i}].octets_b64"))
    return out_fields, octets, label, leaves


# ---------------------------------------------------------------------------
# The binding checks
# ---------------------------------------------------------------------------

def _domain(address: Any) -> Optional[str]:
    """The ASCII-lowercased text after the LAST `@`, or None."""
    if not isinstance(address, str) or "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1]
    return domain.lower() if domain and domain.isascii() else None


def runtime_for_key(dc: "config_mod.DelegationConfig", key_id: str):
    """The configured runtime that owns `key_id` (key ids are unique across
    runtimes), or None."""
    for r in dc.runtimes:
        if any(k.get("key_id") == key_id for k in r.keys):
            return r
    return None


def check6(payload: Mapping[str, Any], dc: "config_mod.DelegationConfig") -> Optional[str]:
    """`key_domain` unless the domain of `from` is one of the domains RL's
    own config lists for the runtime owning the statement's key."""
    runtime = runtime_for_key(dc, payload.get("key_id"))
    domain = _domain(payload.get("from"))
    if runtime is None or domain is None:
        return KEY_DOMAIN
    return None if domain in {d.lower() for d in runtime.domains} else KEY_DOMAIN


def _body_text(octets: bytes, label: Optional[str]) -> Optional[str]:
    """Check 9's decoding: the text after CRLF -> LF, or None for a charset
    failure. An absent label means us-ascii."""
    label = "us-ascii" if label is None else label
    if not label.isascii():
        return None
    codec = {"utf-8": "utf-8", "us-ascii": "ascii"}.get(label.lower())
    if codec is None:
        return None
    try:
        return octets.decode(codec).replace("\r\n", "\n")
    except UnicodeDecodeError:
        return None


def check9(payload: Mapping[str, Any], candidate: Any) -> Union[str, Demoted]:
    """The body text, exactly what is published, or the cause."""
    _fields, octets, label, _atts = _view(candidate)
    text = _body_text(octets, label)
    if text is None:
        return Demoted(BODY_CHARSET)
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != payload.get("body_sha256"):
        return Demoted(BODY_DIGEST)
    return text


def check10(payload: Mapping[str, Any], candidate: Any) -> Union[Tuple[bytes, ...], Demoted]:
    """The attachment octets in order, or the cause: the count first, then
    each index's size and digest."""
    _fields, _octets, _label, leaves = _view(candidate)
    signed = payload.get("attachments") or []
    if len(leaves) != len(signed):
        return Demoted(ATTACHMENT_COUNT)
    for octets, desc in zip(leaves, signed):
        if (len(octets) != desc.get("size_bytes")
                or hashlib.sha256(octets).hexdigest() != desc.get("sha256")):
            return Demoted(ATTACHMENT_DIGEST)
    return tuple(leaves)


def check11(payload: Mapping[str, Any], candidate: Any) -> Optional[str]:
    """`message_id` unless exactly one `Message-ID` field is exactly
    `<id@domain>`: the statement's id exactly, the domain of `from` ASCII
    case-insensitively. Folding is removed and the whitespace it leaves is
    kept (RFC 5322), then the value is trimmed."""
    fields, _octets, _label, _atts = _view(candidate)
    values = [v for n, v in fields if n.isascii() and n.lower() == "message-id"]
    if len(values) != 1 or not isinstance(values[0], str):
        return MESSAGE_ID
    value = _FOLD_RE.sub("", values[0]).strip(" \t")
    if not (value.startswith("<") and value.endswith(">")) or "@" not in value:
        return MESSAGE_ID
    ident, domain = value[1:-1].rsplit("@", 1)
    from_domain = _domain(payload.get("from"))
    if ident != payload.get("id") or not domain.isascii() or domain.lower() != from_domain:
        return MESSAGE_ID
    return None


def bind(verified: Any, candidate: Any, *, delegation: Any,
         check7: Callable[[Mapping[str, Any], str], Optional[str]],
         check8: Callable[[Mapping[str, Any], str], Optional[str]]) -> Union[Bound, Demoted]:
    """Checks 6-11 in ORDER; the first failure decides."""
    if getattr(verified, "kind", None) != "statement":
        raise ValueError(f"only a statement is bound, not {getattr(verified, 'kind', None)!r}")
    payload, key_id = verified.payload, verified.key_id
    _view(candidate)        # a malformed view raises before any check runs
    cause = check6(payload, delegation.config)
    if cause:
        return Demoted(cause)
    for supplied in (check7, check8):
        cause = supplied(payload, key_id)
        if cause:
            return Demoted(cause)
    text = check9(payload, candidate)
    if isinstance(text, Demoted):
        return text
    leaves = check10(payload, candidate)
    if isinstance(leaves, Demoted):
        return leaves
    cause = check11(payload, candidate)
    if cause:
        return Demoted(cause)
    return Bound(text, leaves)


# ---------------------------------------------------------------------------
# The hosting test
# ---------------------------------------------------------------------------

def _host_name(cfg: Any, name: str) -> Union[Hosted, Undecided]:
    if config_mod.target_hold(cfg, name) is not None:
        return Undecided("registry_held")
    return Hosted(name)


def hosting(cfg: Any, to: Any) -> Union[Hosted, NotHosted, Undecided]:
    """Whether `to` is hosted here (module docstring)."""
    if not isinstance(to, str) or "@" not in to:
        return NotHosted()
    local, domain = to.rsplit("@", 1)
    fleet = cfg.fleet_domain
    if (fleet and domain.isascii() and domain.lower() == fleet.lower()
            and local in cfg.instances
            and local.casefold() != config_mod.ROUTER_LOCAL_PART.casefold()):
        return _host_name(cfg, local)
    key = aliases_mod.match_key(to)
    entry = {a.old: a for a in (getattr(cfg, "aliases", None) or ())}.get(key) if key else None
    if entry is None:
        return NotHosted()
    view = getattr(cfg, "alias_view", None)
    decision = view.decisions.get(entry.old) if view is not None else None
    if decision is None:
        return Undecided("alias_undecided")
    if decision.status == aliases_mod.UNVERIFIABLE:
        return Undecided("alias_unverifiable")
    if decision.status == aliases_mod.ACTIVE and decision.target in cfg.instances:
        return _host_name(cfg, decision.target)
    return NotHosted()


# ---------------------------------------------------------------------------
# Sealed values
# ---------------------------------------------------------------------------

def _strict_json(raw: bytes) -> Any:
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"repeated member {k!r}")
            out[k] = v
        return out
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return types.MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _authorised_seal(statement: bytes, key_id: str, runtime: str, body_text: str,
                     attachments: Tuple[bytes, ...], hosted: str, origin: str, confirmed: bool,
                     record_id: Optional[str], notice_id: Optional[str], ts: Optional[str],
                     key: bytes) -> bytes:
    members = {"statement_sha256": _sha(statement), "key_id": key_id, "runtime": runtime,
               "body_sha256": _sha(body_text.encode("utf-8")),
               "attachment_sha256s": [_sha(a) for a in attachments], "hosted": hosted,
               "origin": origin, "confirmed": confirmed, "record_id": record_id,
               "notice_id": notice_id, "ts": ts}
    return hmac.new(key, _LABEL_AUTHORISED + hoplink.canonical(members), hashlib.sha256).digest()


@dataclass(frozen=True)
class Authorised:
    """A statement authorised for placement (module docstring). Built only
    by `authorise`, `confirm` and `resume`; `payload` is derived from
    `statement`, never supplied."""
    statement: bytes
    key_id: str
    runtime: str
    body_text: str
    attachments: Tuple[bytes, ...]
    hosted: str
    origin: str
    confirmed: bool
    record_id: Optional[str]
    notice_id: Optional[str]
    ts: Optional[str]
    seal: bytes = field(repr=False)
    payload: Any = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        _require_seal(self)
        object.__setattr__(self, "payload", _freeze(_strict_json(self.statement)))

    @property
    def statement_sha256(self) -> str:
        return _sha(self.statement)

    def __reduce_ex__(self, protocol):
        raise TypeError("an Authorised is not persisted")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def _require_seal(auth: Any) -> None:
    if not isinstance(auth, Authorised) or not isinstance(getattr(auth, "seal", None), bytes):
        raise TypeError("not a live Authorised")
    want = _authorised_seal(auth.statement, auth.key_id, auth.runtime, auth.body_text,
                            auth.attachments, auth.hosted, auth.origin, auth.confirmed,
                            auth.record_id, auth.notice_id, auth.ts, _SEAL_KEY)
    if not hmac.compare_digest(want, auth.seal):
        raise TypeError("not a live Authorised")


def check_seal(auth: Any) -> None:
    """`TypeError` unless `auth` is an `Authorised` sealed by this process."""
    _require_seal(auth)


def _issue(**parts: Any) -> Authorised:
    seal = _authorised_seal(key=_SEAL_KEY, **parts)
    return Authorised(seal=seal, **parts)


def _persisted_seal(record_id: str, record_sha256: str, dev: int, ino: int, record_dir: str,
                    key: bytes) -> bytes:
    members = {"record_id": record_id, "record_sha256": record_sha256, "dev": dev, "ino": ino,
               "record_dir": record_dir}
    return hmac.new(key, _LABEL_PERSISTED + hoplink.canonical(members), hashlib.sha256).digest()


@dataclass(frozen=True)
class PersistedDecision:
    """The receipt for a decided record that is durable on disk and was read
    back. Issued only by `commit_decision` and `reopen_decision`."""
    record_id: str
    record_sha256: str
    dev: int
    ino: int
    record_dir: str
    seal: bytes = field(repr=False)

    def __post_init__(self):
        _require_receipt(self)

    def __reduce_ex__(self, protocol):
        raise TypeError("a PersistedDecision is not persisted")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def _require_receipt(rcp: Any) -> None:
    if not isinstance(rcp, PersistedDecision) or not isinstance(getattr(rcp, "seal", None), bytes):
        raise TypeError("not a live PersistedDecision")
    want = _persisted_seal(rcp.record_id, rcp.record_sha256, rcp.dev, rcp.ino, rcp.record_dir,
                           _SEAL_KEY)
    if not hmac.compare_digest(want, rcp.seal):
        raise TypeError("not a live PersistedDecision")


def _issue_receipt(record_id: str, record_sha256: str, dev: int, ino: int,
                   record_dir: str) -> PersistedDecision:
    seal = _persisted_seal(record_id, record_sha256, dev, ino, record_dir, _SEAL_KEY)
    return PersistedDecision(record_id, record_sha256, dev, ino, record_dir, seal)


# ---------------------------------------------------------------------------
# authorise and confirm
# ---------------------------------------------------------------------------

def authorise(verified: Any, candidate: Any, *, delegation: Any, cfg: Any,
              check7: Callable[[Mapping[str, Any], str], Optional[str]],
              check8: Callable[[Mapping[str, Any], str], Optional[str]]
              ) -> Union[Authorised, Demoted, NotHosted, Undecided]:
    """A FRESH `Authorised` when every binding check passes and `to` is
    hosted; otherwise the outcome that decided."""
    bound = bind(verified, candidate, delegation=delegation, check7=check7, check8=check8)
    if isinstance(bound, Demoted):
        return bound
    host = hosting(cfg, verified.payload.get("to"))
    if not isinstance(host, Hosted):
        return host
    runtime = runtime_for_key(delegation.config, verified.key_id)
    return _issue(statement=verified.statement, key_id=verified.key_id, runtime=runtime.runtime,
                  body_text=bound.body_text, attachments=bound.attachments,
                  hosted=host.instance, origin=ORIGIN_FRESH, confirmed=False, record_id=None,
                  notice_id=None, ts=None)


def _consistent(auth: Authorised) -> Optional[str]:
    """Why `auth`'s parts disagree with its own statement, or None."""
    payload = auth.payload
    if payload.get("key_id") != auth.key_id:
        return "key_id"
    if _sha(auth.body_text.encode("utf-8")) != payload.get("body_sha256"):
        return "body"
    signed = payload.get("attachments") or ()
    if len(signed) != len(auth.attachments):
        return "attachments"
    for octets, desc in zip(auth.attachments, signed):
        if len(octets) != desc.get("size_bytes") or _sha(octets) != desc.get("sha256"):
            return "attachments"
    return None


def confirm(auth: Authorised, *, cfg: Any) -> Authorised:
    """`auth` re-checked against the CURRENT configuration (hosting, the
    key's runtime, the digests), resealed as confirmed; or
    `AuthorisationMismatch("stale")`. Runs BEFORE a decision is persisted."""
    _require_seal(auth)
    if auth.origin != ORIGIN_FRESH:
        raise TypeError("only a fresh authorisation is confirmed")
    why = _consistent(auth)
    if why is not None:
        raise AuthorisationMismatch("stale", why)
    if hosting(cfg, auth.payload.get("to")) != Hosted(auth.hosted):
        raise AuthorisationMismatch("stale", "hosting")
    dc = getattr(cfg, "delegation", None)
    runtime = runtime_for_key(dc, auth.key_id) if dc is not None else None
    if runtime is None or runtime.runtime != auth.runtime:
        raise AuthorisationMismatch("stale", "runtime")
    return _issue(statement=auth.statement, key_id=auth.key_id, runtime=auth.runtime,
                  body_text=auth.body_text, attachments=auth.attachments, hosted=auth.hosted,
                  origin=ORIGIN_FRESH, confirmed=True, record_id=auth.record_id,
                  notice_id=auth.notice_id, ts=auth.ts)


# ---------------------------------------------------------------------------
# The link-once primitive and the decision key
# ---------------------------------------------------------------------------

def _clean_stage(dirfd: int, prefix: str) -> None:
    for entry in os.listdir(dirfd):
        if entry.startswith(prefix):
            try:
                os.unlink(entry, dir_fd=dirfd)
            except FileNotFoundError:
                pass


def _read_checked(dirfd: int, name: str, *, size: Optional[int] = None) -> Tuple[bytes, int, int, int]:
    """(bytes, fd, dev, ino) of `name` under `dirfd`: opened without
    following, checked on the opened fd (a regular file, this uid's, 0600,
    one link). The caller closes `fd`."""
    fd = os.open(name, _OPEN_READ, dir_fd=dirfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RecoveryCorrupt("not_regular", name)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise RecoveryCorrupt("owner_or_mode", name)
        if st.st_nlink != 1:
            raise RecoveryCorrupt("links", f"{name} has {st.st_nlink} links")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        if size is not None and len(data) != size:
            raise RecoveryCorrupt("size", name)
        return data, fd, st.st_dev, st.st_ino
    except BaseException:
        os.close(fd)
        raise


def _link_once(dirfd: int, name: str, data: bytes, *, stage_prefix: str) -> str:
    """Write `data` at `name` under `dirfd` once: "created", or
    "exists_same" when identical bytes are already there; `LinkConflict`
    for different bytes. Never overwrites, never follows a link; every step
    is made durable before it returns. Runs under the drain lock, so the
    stage cleanup can never remove a live writer's temp."""
    _clean_stage(dirfd, stage_prefix)
    tmp = stage_prefix + secrets.token_hex(8)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=dirfd)
    try:
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
    except FileExistsError:
        os.unlink(tmp, dir_fd=dirfd)
        existing, efd, _dev, _ino = _read_checked(dirfd, name)
        try:
            if existing != data:
                raise LinkConflict(name)
            os.fsync(efd)
        finally:
            os.close(efd)
        os.fsync(dirfd)
        return "exists_same"
    except Exception:
        # A synchronous failure before the link leaves the namespace as it
        # was. (A crash leaves the temp; the next writer's stage cleanup and
        # `reopen_decision` remove it.)
        try:
            os.unlink(tmp, dir_fd=dirfd)
        except OSError:
            pass
        raise
    os.unlink(tmp, dir_fd=dirfd)
    os.fsync(dirfd)
    return "created"


def _open_dir(path: Path) -> int:
    return os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def _present_key(dirfd: int) -> bytes:
    """The present-key path: clean the stage, read with every check, make
    the key and its directory durable, then accept it."""
    _clean_stage(dirfd, DECISION_KEY_STAGE_PREFIX)
    data, fd, _dev, _ino = _read_checked(dirfd, DECISION_KEY_FILE, size=DECISION_KEY_BYTES)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(dirfd)
    return data


def ensure_decision_key(state_dir: Path) -> bytes:
    """The durable decision key in `state_dir`, created once if absent.
    Called only from `service.activate_delegation`, under the drain lock."""
    dirfd = _open_dir(Path(state_dir))
    try:
        try:
            return _present_key(dirfd)
        except FileNotFoundError:
            pass
        for attempt in (1, 2):
            try:
                _link_once(dirfd, DECISION_KEY_FILE, secrets.token_bytes(DECISION_KEY_BYTES),
                           stage_prefix=DECISION_KEY_STAGE_PREFIX)
            except LinkConflict:
                pass                    # another creator won: validate its key
            except FileNotFoundError:
                if attempt == 2:
                    raise
                continue
            return _present_key(dirfd)
        raise AssertionError("unreachable")
    finally:
        os.close(dirfd)


def _decision_key(state_dir: Path) -> bytes:
    """The decision key as it is on disk, read with every check but WITHOUT
    the present-key durability barrier: every caller (`decision_record`,
    `commit_decision`, `reopen_decision`, `resume`) runs only under an active
    delegation, and activation has already made the key durable
    (`ensure_decision_key`)."""
    dirfd = _open_dir(Path(state_dir))
    try:
        data, fd, _dev, _ino = _read_checked(dirfd, DECISION_KEY_FILE, size=DECISION_KEY_BYTES)
        os.close(fd)
        return data
    finally:
        os.close(dirfd)


# ---------------------------------------------------------------------------
# The decided record
# ---------------------------------------------------------------------------

def _record_mac(members: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, _LABEL_DECISION + hoplink.canonical(dict(members)),
                    hashlib.sha256).hexdigest()


def decision_record(auth: Authorised, *, record_id: str, preset: Tuple[str, str], cfg: Any,
                    state_dir: Path) -> bytes:
    """The decided record's bytes for a confirmed fresh `auth`, MAC'd under
    the durable decision key. In memory these are NOT an authority:
    `commit_decision` makes them one."""
    _require_seal(auth)
    if auth.origin != ORIGIN_FRESH or not auth.confirmed:
        raise TypeError("a decision is recorded only from a confirmed fresh authorisation")
    auth = confirm(auth, cfg=cfg)
    notice_id, ts = preset
    if not (isinstance(record_id, str) and record_id):
        raise ValueError("record_id: a non-empty string")
    if not (isinstance(notice_id, str) and _NOTICE_ID_RE.fullmatch(notice_id)):
        raise ValueError("preset notice_id: 32 lower-case hex")
    if not (isinstance(ts, str) and _TS_RE.fullmatch(ts)):
        raise ValueError("preset ts: YYYY-MM-DDTHH:MM:SSZ")
    # A reserved value (`authorise_checked`) carries its reservation's
    # identity; the preset and the record id must be exactly that.
    if auth.notice_id is not None and (notice_id, ts) != (auth.notice_id, auth.ts):
        raise ValueError("the preset is not the reservation's notice_id and ts")
    if auth.record_id is not None and record_id != auth.record_id:
        raise ValueError("record_id is not the reservation's candidate")
    members = {"v": 1, "state": "decided", "disposition": "place", "record_id": record_id,
               "statement_sha256": auth.statement_sha256, "key_id": auth.key_id,
               "runtime": auth.runtime, "hosted_instance": auth.hosted,
               "notice_id": notice_id, "ts": ts,
               "body_sha256": _sha(auth.body_text.encode("utf-8")),
               "attachment_sha256s": [_sha(a) for a in auth.attachments]}
    return hoplink.canonical(dict(members, mac=_record_mac(members, _decision_key(state_dir))))


def _parse_record(raw: bytes, key: bytes, record_id: str) -> Dict[str, Any]:
    """The decided record's members, MAC verified FIRST; `RecoveryCorrupt`."""
    try:
        doc = _strict_json(raw)
    except (UnicodeDecodeError, ValueError):
        raise RecoveryCorrupt("mac", "not a record") from None
    if not isinstance(doc, dict) or set(doc) != set(_RECORD_MEMBERS) | {"mac"}:
        raise RecoveryCorrupt("mac", "not a closed record")
    members = {k: doc[k] for k in _RECORD_MEMBERS}
    try:
        want = _record_mac(members, key)
    except hoplink.CanonicalRefused:
        raise RecoveryCorrupt("mac", "not canonical") from None
    if not (isinstance(doc["mac"], str) and hmac.compare_digest(want, doc["mac"])):
        raise RecoveryCorrupt("mac")
    if members["record_id"] != record_id:
        raise RecoveryCorrupt("record_id")
    if members["state"] != "decided" or members["disposition"] != "place" or members["v"] != 1:
        raise RecoveryCorrupt("state")
    return members


def _record_dir_fd(state_dir: Path, record_dir: str) -> int:
    """`record_dir` (`<logical_id>/JOURNAL_DIR/<key>`, relative to
    `state_dir`), descended without following any link."""
    parts = Path(record_dir).parts
    if (len(parts) != 3 or parts[1] != JOURNAL_DIR or Path(record_dir).is_absolute()
            or any(p in (".", "..") for p in parts)):
        raise ValueError(f"{record_dir!r} is not <logical_id>/{JOURNAL_DIR}/<key>")
    fd = _open_dir(Path(state_dir))
    try:
        for part in parts:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def commit_decision(state_dir: Path, record_dir: str, rec: bytes, *,
                    record_id: str) -> PersistedDecision:
    """Write the decided record durably, read it back, and only then return
    its receipt (module docstring)."""
    _parse_record(rec, _decision_key(state_dir), record_id)
    dirfd = _record_dir_fd(Path(state_dir), record_dir)
    try:
        try:
            _link_once(dirfd, DECISION_FILE, rec, stage_prefix=DECISION_STAGE_PREFIX)
        except LinkConflict:
            raise DecisionConflict(record_dir) from None
        data, fd, dev, ino = _read_checked(dirfd, DECISION_FILE)
        os.close(fd)
        if data != rec:
            raise RecoveryCorrupt("readback")
        return _issue_receipt(record_id, _sha(data), dev, ino, record_dir)
    finally:
        os.close(dirfd)


def reopen_decision(state_dir: Path, record_dir: str, *, record_id: str) -> PersistedDecision:
    """The receipt for a decided record already on disk (after a restart):
    the stage cleaned, the file read with every check, it and its directory
    made durable, its MAC verified. `NoDecision` when there is none."""
    key = _decision_key(state_dir)
    dirfd = _record_dir_fd(Path(state_dir), record_dir)
    try:
        _clean_stage(dirfd, DECISION_STAGE_PREFIX)
        try:
            data, fd, dev, ino = _read_checked(dirfd, DECISION_FILE)
        except FileNotFoundError:
            raise NoDecision(record_dir) from None
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dirfd)
        _parse_record(data, key, record_id)
        return _issue_receipt(record_id, _sha(data), dev, ino, record_dir)
    finally:
        os.close(dirfd)


@dataclass(frozen=True)
class Snapshot:
    """The immutable candidate snapshot the candidate journal wrote once, at
    take: the exact statement bytes and the candidate view."""
    statement: bytes
    candidate: Mapping[str, Any]


def resume(receipt: PersistedDecision, snapshot: Snapshot, *, state_dir: Path) -> Authorised:
    """A DECIDED `Authorised` from a durable decided record: the file
    re-read through the receipt, its MAC first, then the snapshot's
    bindings. Re-runs no binding check, no hosting and no time."""
    _require_receipt(receipt)
    key = _decision_key(state_dir)
    dirfd = _record_dir_fd(Path(state_dir), receipt.record_dir)
    try:
        try:
            data, fd, dev, ino = _read_checked(dirfd, DECISION_FILE)
        except FileNotFoundError:
            raise RecoveryCorrupt("replaced", "the decided record is gone") from None
        os.close(fd)
    finally:
        os.close(dirfd)
    if (dev, ino) != (receipt.dev, receipt.ino) or _sha(data) != receipt.record_sha256:
        raise RecoveryCorrupt("replaced")
    rec = _parse_record(data, key, receipt.record_id)
    if not isinstance(snapshot, Snapshot) or not isinstance(snapshot.statement, bytes):
        raise RecoveryCorrupt("snapshot", "incomplete")
    if _sha(snapshot.statement) != rec["statement_sha256"]:
        raise RecoveryCorrupt("snapshot", "statement")
    try:
        payload = _strict_json(snapshot.statement)
        _fields, octets, label, leaves = _view(snapshot.candidate)
    except (UnicodeDecodeError, ValueError):
        raise RecoveryCorrupt("snapshot", "unreadable") from None
    if not isinstance(payload, dict) or payload.get("key_id") != rec["key_id"]:
        raise RecoveryCorrupt("snapshot", "key_id")
    text = _body_text(octets, label)
    if text is None or _sha(text.encode("utf-8")) != rec["body_sha256"]:
        raise RecoveryCorrupt("snapshot", "body")
    if [_sha(a) for a in leaves] != list(rec["attachment_sha256s"]):
        raise RecoveryCorrupt("snapshot", "attachments")
    return _issue(statement=snapshot.statement, key_id=rec["key_id"], runtime=rec["runtime"],
                  body_text=text, attachments=tuple(leaves), hosted=rec["hosted_instance"],
                  origin=ORIGIN_DECIDED, confirmed=True, record_id=rec["record_id"],
                  notice_id=rec["notice_id"], ts=rec["ts"])


# ---------------------------------------------------------------------------
# The reserved path: checks 6-11 once, the reservation, then hosting
# ---------------------------------------------------------------------------
#
#   bind_for_reservation -> reservation_record -> commit_reservation
#       -> resume_reserved -> authorise_checked -> confirm -> decision_record
#
# A `Checked` carries a statement across check 12. Its `origin` is
# ORIGIN_PRE from `bind_for_reservation`, which only `reservation_record`
# accepts, or ORIGIN_RESERVED from `resume_reserved`, which only
# `authorise_checked` accepts. The fresh path re-reads the reservation it
# just committed exactly as recovery does, so the two are one path, and a
# change of time or of check 8 after an id is reserved can never produce a
# pre-reservation outcome. The reserved `notice_id` is minted by
# `reservation_record` and read back from the reservation; no function
# takes one from its caller.

ORIGIN_PRE = "pre"
ORIGIN_RESERVED = "reserved"
REPLAY_DIR = "peer-replay"
RESERVATION_SUFFIX = ".json"
_LABEL_CHECKED = b"amap-rl/checked/1\x00"
_LABEL_PERSISTED_RESERVATION = b"amap-rl/persisted-reservation/1\x00"
_LABEL_RESERVATION = b"amap-rl/peer-reservation/1\x00"
_RESERVATION_MEMBERS = ("v", "state", "rt", "idk", "runtime", "id", "ts", "statement_sha256",
                        "body_sha256", "attachment_sha256s", "key_id", "notice_id",
                        "candidate_ref", "reserve_seq")
_RT_RE = re.compile(r"[0-9a-f]{32}\Z")
_IDK_RE = re.compile(r"[0-9a-f]{64}\Z")


class ReservationCollision(Exception):
    """A reservation for this (runtime, id) already exists for ANOTHER
    candidate: check 12's duplicate. The prior file is untouched."""

    def __init__(self, candidate_ref: str):
        super().__init__(candidate_ref)
        self.candidate_ref = candidate_ref


def replay_keys(runtime: str, ident: str) -> Tuple[str, str]:
    """(rt, idk) for a (configured runtime, statement id)."""
    return (_sha(runtime.encode("utf-8"))[:32], _sha(ident.encode("utf-8")))


def _checked_seal(statement: bytes, key_id: str, runtime: str, body_text: str,
                  attachments: Tuple[bytes, ...], origin: str, record_id: Optional[str],
                  notice_id: Optional[str], ts: Optional[str], key: bytes) -> bytes:
    members = dict(statement_sha256=_sha(statement), key_id=key_id, runtime=runtime,
                   body_sha256=_sha(body_text.encode("utf-8")),
                   attachment_sha256s=[_sha(a) for a in attachments], origin=origin,
                   record_id=record_id, notice_id=notice_id, ts=ts)
    return hmac.new(key, _LABEL_CHECKED + hoplink.canonical(members), hashlib.sha256).digest()


@dataclass(frozen=True)
class Checked:
    """A statement through checks 6-11 (ORIGIN_PRE), or re-read from its
    durable reservation (ORIGIN_RESERVED). Built only by this module."""
    statement: bytes
    key_id: str
    runtime: str
    body_text: str
    attachments: Tuple[bytes, ...]
    origin: str
    record_id: Optional[str]
    notice_id: Optional[str]
    ts: Optional[str]
    seal: bytes = field(repr=False)
    payload: Any = field(init=False, compare=False, repr=False)

    def __post_init__(self):
        _require_checked(self)
        object.__setattr__(self, "payload", _freeze(_strict_json(self.statement)))

    def __reduce_ex__(self, protocol):
        raise TypeError("a Checked is not persisted")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def _require_checked(chk: Any, origin: Optional[str] = None) -> None:
    if not isinstance(chk, Checked) or not isinstance(getattr(chk, "seal", None), bytes):
        raise TypeError("not a live Checked")
    want = _checked_seal(chk.statement, chk.key_id, chk.runtime, chk.body_text, chk.attachments,
                         chk.origin, chk.record_id, chk.notice_id, chk.ts, _SEAL_KEY)
    if not hmac.compare_digest(want, chk.seal):
        raise TypeError("not a live Checked")
    if origin is not None and chk.origin != origin:
        raise TypeError(f"a {chk.origin!r} Checked where {origin!r} is required")


def _issue_checked(**parts: Any) -> Checked:
    return Checked(seal=_checked_seal(key=_SEAL_KEY, **parts), **parts)


def bind_for_reservation(verified: Any, candidate: Any, *, delegation: Any,
                         check7: Callable[[Mapping[str, Any], str], Optional[str]],
                         check8: Callable[[Mapping[str, Any], str], Optional[str]]
                         ) -> Union[Checked, Demoted]:
    """Checks 6-11, exactly `bind`; a pre-reservation `Checked` when they
    pass. A hold raised by a supplied check propagates."""
    bound = bind(verified, candidate, delegation=delegation, check7=check7, check8=check8)
    if isinstance(bound, Demoted):
        return bound
    runtime = runtime_for_key(delegation.config, verified.key_id)
    return _issue_checked(statement=verified.statement, key_id=verified.key_id,
                          runtime=runtime.runtime, body_text=bound.body_text,
                          attachments=bound.attachments, origin=ORIGIN_PRE, record_id=None,
                          notice_id=None, ts=None)


def _reservation_mac(members: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, _LABEL_RESERVATION + hoplink.canonical(dict(members)),
                    hashlib.sha256).hexdigest()


def reservation_record(checked: Checked, *, record_id: str, reserve_seq: int,
                       state_dir: Path) -> bytes:
    """The reservation's bytes for a pre-reservation `checked`: a freshly
    minted `notice_id`, MAC'd under the decision key with the reservation's
    own label. Not an authority until `commit_reservation`."""
    _require_checked(checked, ORIGIN_PRE)
    if not (isinstance(record_id, str) and record_id):
        raise ValueError("record_id: a non-empty string")
    if not (type(reserve_seq) is int and reserve_seq > 0):
        raise ValueError("reserve_seq: a positive integer")
    p = checked.payload
    rt, idk = replay_keys(checked.runtime, p["id"])
    members = {"v": 1, "state": "reserved", "rt": rt, "idk": idk, "runtime": checked.runtime,
               "id": p["id"], "ts": p["ts"], "statement_sha256": _sha(checked.statement),
               "body_sha256": _sha(checked.body_text.encode("utf-8")),
               "attachment_sha256s": [_sha(a) for a in checked.attachments],
               "key_id": checked.key_id, "notice_id": secrets.token_hex(16),
               "candidate_ref": record_id, "reserve_seq": reserve_seq}
    return hoplink.canonical(dict(members, mac=_reservation_mac(members,
                                                               _decision_key(state_dir))))


def parse_reservation(raw: bytes, key: Optional[bytes]) -> Dict[str, Any]:
    """A reservation's members, its MAC verified FIRST; `RecoveryCorrupt`.
    With `key` None (the decision key is lost) the record is read as DATA
    ONLY: strict JSON, the closed member set and the field grammars, never
    as an authority."""
    try:
        doc = _strict_json(raw)
    except (UnicodeDecodeError, ValueError):
        raise RecoveryCorrupt("mac", "not a reservation") from None
    if not isinstance(doc, dict) or set(doc) != set(_RESERVATION_MEMBERS) | {"mac"}:
        raise RecoveryCorrupt("mac", "not a closed reservation")
    members = {k: doc[k] for k in _RESERVATION_MEMBERS}
    if key is not None:
        try:
            want = _reservation_mac(members, key)
        except hoplink.CanonicalRefused:
            raise RecoveryCorrupt("mac", "not canonical") from None
        if not (isinstance(doc["mac"], str) and hmac.compare_digest(want, doc["mac"])):
            raise RecoveryCorrupt("mac")
    if members["v"] != 1 or members["state"] != "reserved":
        raise RecoveryCorrupt("state")
    if not (isinstance(members["notice_id"], str) and _NOTICE_ID_RE.fullmatch(members["notice_id"])
            and isinstance(members["rt"], str) and _RT_RE.fullmatch(members["rt"])
            and isinstance(members["idk"], str) and _IDK_RE.fullmatch(members["idk"])
            and isinstance(members["candidate_ref"], str)):
        raise RecoveryCorrupt("grammar")
    return members


def _replay_dir_fd(state_dir: Path, rt: str, *, create: bool) -> int:
    """`state_dir/peer-replay/<rt>`, descended without following a link;
    created (durably) when `create`."""
    if not (isinstance(rt, str) and _RT_RE.fullmatch(rt)):
        raise ValueError("rt: 32 lower-case hex")
    fd = _open_dir(Path(state_dir))
    try:
        for part in (REPLAY_DIR, rt):
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                os.fsync(fd)
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _persisted_reservation_seal(rt: str, idk: str, dev: int, ino: int, sha256: str,
                                record_id: str, notice_id: str, key: bytes) -> bytes:
    members = {"rt": rt, "idk": idk, "dev": dev, "ino": ino, "sha256": sha256,
               "record_id": record_id, "notice_id": notice_id}
    return hmac.new(key, _LABEL_PERSISTED_RESERVATION + hoplink.canonical(members),
                    hashlib.sha256).digest()


@dataclass(frozen=True)
class PersistedReservation:
    """The receipt for a reservation durable on disk and read back. Issued
    only by `commit_reservation` and `reopen_reservation`."""
    rt: str
    idk: str
    dev: int
    ino: int
    sha256: str
    record_id: str
    notice_id: str
    seal: bytes = field(repr=False)

    def __post_init__(self):
        _require_reservation_receipt(self)

    def __reduce_ex__(self, protocol):
        raise TypeError("a PersistedReservation is not persisted")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def _require_reservation_receipt(rcp: Any) -> None:
    if (not isinstance(rcp, PersistedReservation)
            or not isinstance(getattr(rcp, "seal", None), bytes)):
        raise TypeError("not a live PersistedReservation")
    want = _persisted_reservation_seal(rcp.rt, rcp.idk, rcp.dev, rcp.ino, rcp.sha256,
                                       rcp.record_id, rcp.notice_id, _SEAL_KEY)
    if not hmac.compare_digest(want, rcp.seal):
        raise TypeError("not a live PersistedReservation")


def _issue_reservation_receipt(rt: str, idk: str, dev: int, ino: int, sha256: str,
                               record_id: str, notice_id: str) -> PersistedReservation:
    seal = _persisted_reservation_seal(rt, idk, dev, ino, sha256, record_id, notice_id, _SEAL_KEY)
    return PersistedReservation(rt, idk, dev, ino, sha256, record_id, notice_id, seal)


def _reservation_name(idk: str) -> str:
    if not (isinstance(idk, str) and _IDK_RE.fullmatch(idk)):
        raise ValueError("idk: 64 lower-case hex")
    return idk + RESERVATION_SUFFIX


def _receipt_from(dirfd: int, name: str, key: bytes, rt: str, idk: str,
                  record_id: str) -> PersistedReservation:
    data, fd, dev, ino = _read_checked(dirfd, name)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(dirfd)
    rec = parse_reservation(data, key)
    if (rec["rt"], rec["idk"]) != (rt, idk):
        raise RecoveryCorrupt("placement", "the reservation is not at its own (rt, idk)")
    if rec["candidate_ref"] != record_id:
        raise ReservationCollision(rec["candidate_ref"])
    return _issue_reservation_receipt(rt, idk, dev, ino, _sha(data), record_id, rec["notice_id"])


def commit_reservation(state_dir: Path, rt: str, idk: str, rec: bytes, *,
                       record_id: str) -> PersistedReservation:
    """Link the reservation at `peer-replay/<rt>/<idk>.json` (never
    replacing, every step durable), read it back, and only then return its
    receipt. An existing reservation for this candidate (a retried step) is
    ours and its receipt is returned; one for another candidate raises
    `ReservationCollision`, the file untouched."""
    key = _decision_key(state_dir)
    mine = parse_reservation(rec, key)
    if (mine["rt"], mine["idk"], mine["candidate_ref"]) != (rt, idk, record_id):
        raise ValueError("the reservation does not name this (rt, idk) and candidate")
    name = _reservation_name(idk)
    dirfd = _replay_dir_fd(Path(state_dir), rt, create=True)
    try:
        try:
            _link_once(dirfd, name, rec, stage_prefix=f".{name}.stage-")
        except LinkConflict:
            pass                        # an existing reservation: ours, or a collision
        return _receipt_from(dirfd, name, key, rt, idk, record_id)
    finally:
        os.close(dirfd)


def reopen_reservation(state_dir: Path, rt: str, idk: str, *,
                       record_id: str) -> PersistedReservation:
    """The receipt for a reservation already on disk: the stage cleaned, the
    file read with every check and made durable, its MAC verified FIRST.
    `FileNotFoundError` when there is none; `ReservationCollision` when it
    belongs to another candidate."""
    key = _decision_key(state_dir)
    name = _reservation_name(idk)
    dirfd = _replay_dir_fd(Path(state_dir), rt, create=False)
    try:
        _clean_stage(dirfd, f".{name}.stage-")
        return _receipt_from(dirfd, name, key, rt, idk, record_id)
    finally:
        os.close(dirfd)


def resume_reserved(receipt: PersistedReservation, snapshot: Snapshot, *,
                    state_dir: Path) -> Checked:
    """A RESERVED `Checked` from a durable reservation: the file re-read
    through the receipt (inode and digest), its MAC first, then the
    snapshot's bindings. Re-runs no check; the runtime is the reservation's
    own, never the current configuration's."""
    _require_reservation_receipt(receipt)
    key = _decision_key(state_dir)
    name = _reservation_name(receipt.idk)
    dirfd = _replay_dir_fd(Path(state_dir), receipt.rt, create=False)
    try:
        try:
            data, fd, dev, ino = _read_checked(dirfd, name)
        except FileNotFoundError:
            raise RecoveryCorrupt("replaced", "the reservation is gone") from None
        os.close(fd)
    finally:
        os.close(dirfd)
    if (dev, ino) != (receipt.dev, receipt.ino) or _sha(data) != receipt.sha256:
        raise RecoveryCorrupt("replaced")
    rec = parse_reservation(data, key)
    if rec["candidate_ref"] != receipt.record_id or rec["notice_id"] != receipt.notice_id:
        raise RecoveryCorrupt("candidate_ref")
    if not isinstance(snapshot, Snapshot) or not isinstance(snapshot.statement, bytes):
        raise RecoveryCorrupt("snapshot", "incomplete")
    if rec["statement_sha256"] != _sha(snapshot.statement):
        raise RecoveryCorrupt("snapshot", "statement")
    try:
        payload = _strict_json(snapshot.statement)
        _fields, octets, label, leaves = _view(snapshot.candidate)
    except (UnicodeDecodeError, ValueError):
        raise RecoveryCorrupt("snapshot", "unreadable") from None
    if (not isinstance(payload, dict) or payload.get("key_id") != rec["key_id"]
            or payload.get("id") != rec["id"] or payload.get("ts") != rec["ts"]):
        raise RecoveryCorrupt("snapshot", "statement_members")
    text = _body_text(octets, label)
    if text is None or rec["body_sha256"] != _sha(text.encode("utf-8")):
        raise RecoveryCorrupt("snapshot", "body")
    if list(rec["attachment_sha256s"]) != [_sha(a) for a in leaves]:
        raise RecoveryCorrupt("snapshot", "attachments")
    return _issue_checked(statement=snapshot.statement, key_id=rec["key_id"],
                          runtime=rec["runtime"], body_text=text, attachments=tuple(leaves),
                          origin=ORIGIN_RESERVED, record_id=rec["candidate_ref"],
                          notice_id=rec["notice_id"], ts=rec["ts"])


def authorise_checked(checked: Checked, *, cfg: Any) -> Union[Authorised, NotHosted, Undecided]:
    """Hosting ONLY, for a RESERVED `checked`; a fresh `Authorised` carrying
    the reservation's candidate, `notice_id` and `ts`. `confirm` (which
    re-checks the key's runtime against the reservation's) and
    `decision_record` follow as for any fresh value."""
    _require_checked(checked, ORIGIN_RESERVED)
    host = hosting(cfg, checked.payload.get("to"))
    if not isinstance(host, Hosted):
        return host
    return _issue(statement=checked.statement, key_id=checked.key_id, runtime=checked.runtime,
                  body_text=checked.body_text, attachments=checked.attachments,
                  hosted=host.instance, origin=ORIGIN_FRESH, confirmed=False,
                  record_id=checked.record_id, notice_id=checked.notice_id, ts=checked.ts)


# ---------------------------------------------------------------------------
# Supersession: the only path from a decision to a refusal
# ---------------------------------------------------------------------------
#
# A decided record is refused only by the generation fence (router) or the
# operator's key-loss drop, and only through `supersede.json`: a closed,
# MAC'd record naming the exact bytes of the decision it supersedes. A
# supersession MAC'd under the CURRENT key is valid even when the decision
# itself can no longer be verified (the key-loss case).

SUPERSEDE_FILE = "supersede.json"
SUPERSEDE_STAGE_PREFIX = ".supersede.json.stage-"
SUPERSEDE_CODES = frozenset({"generation_retired", "decision_unrecoverable"})
_LABEL_SUPERSEDE = b"amap-rl/peer-supersede/1\x00"
_SUPERSEDE_MEMBERS = ("v", "type", "record_id", "decision_sha256", "outcome", "cause",
                      "policy_code", "superseded_at", "by")


def _supersede_mac(members: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, _LABEL_SUPERSEDE + hoplink.canonical(dict(members)),
                    hashlib.sha256).hexdigest()


def read_decision_data(state_dir: Path, record_dir: str) -> Tuple[bytes, Dict[str, Any]]:
    """The decision's bytes and members read as DATA ONLY (no MAC): strict
    JSON, the closed member set, and the notice id and recipient grammars.
    Never an authority; used to find what a supersession names."""
    dirfd = _record_dir_fd(Path(state_dir), record_dir)
    try:
        data, fd, _dev, _ino = _read_checked(dirfd, DECISION_FILE)
        os.close(fd)
    finally:
        os.close(dirfd)
    try:
        doc = _strict_json(data)
    except (UnicodeDecodeError, ValueError):
        raise RecoveryCorrupt("grammar", "not a record") from None
    if not isinstance(doc, dict) or set(doc) != set(_RECORD_MEMBERS) | {"mac"}:
        raise RecoveryCorrupt("grammar", "not a closed record")
    if not (isinstance(doc["notice_id"], str) and _NOTICE_ID_RE.fullmatch(doc["notice_id"])
            and isinstance(doc["hosted_instance"], str)
            and config_mod._NAME_RE.fullmatch(doc["hosted_instance"])):
        raise RecoveryCorrupt("grammar")
    return data, doc


def supersede_record(state_dir: Path, *, record_id: str, decision: bytes, policy_code: str,
                     by: str, at: str) -> bytes:
    """The supersession's bytes, MAC'd under the current decision key with
    the supersession label."""
    if policy_code not in SUPERSEDE_CODES:
        raise ValueError(f"{policy_code!r} is not a supersession code")
    if not (isinstance(at, str) and _TS_RE.fullmatch(at)):
        raise ValueError("at: YYYY-MM-DDTHH:MM:SSZ")
    if not (isinstance(by, str) and by):
        raise ValueError("by: who superseded")
    members = {"v": 1, "type": "supersede", "record_id": record_id,
               "decision_sha256": _sha(decision), "outcome": "refused", "cause": "policy",
               "policy_code": policy_code, "superseded_at": at, "by": by}
    return hoplink.canonical(dict(members, mac=_supersede_mac(members,
                                                             _decision_key(state_dir))))


def parse_supersede(raw: bytes, key: bytes, *, record_id: str,
                    decision_sha256: Optional[str]) -> Dict[str, Any]:
    """A supersession's members, its MAC FIRST, then the record it names and
    (when the decision is present) the decision's exact bytes;
    `RecoveryCorrupt("supersede_invalid", ...)` otherwise."""
    try:
        doc = _strict_json(raw)
    except (UnicodeDecodeError, ValueError):
        raise RecoveryCorrupt("supersede_invalid", "not JSON") from None
    if not isinstance(doc, dict) or set(doc) != set(_SUPERSEDE_MEMBERS) | {"mac"}:
        raise RecoveryCorrupt("supersede_invalid", "not a closed supersession")
    members = {k: doc[k] for k in _SUPERSEDE_MEMBERS}
    try:
        want = _supersede_mac(members, key)
    except hoplink.CanonicalRefused:
        raise RecoveryCorrupt("supersede_invalid", "not canonical") from None
    if not (isinstance(doc["mac"], str) and hmac.compare_digest(want, doc["mac"])):
        raise RecoveryCorrupt("supersede_invalid", "mac")
    if members["record_id"] != record_id:
        raise RecoveryCorrupt("supersede_invalid", "record_id")
    if decision_sha256 is not None and members["decision_sha256"] != decision_sha256:
        raise RecoveryCorrupt("supersede_invalid", "decision_sha256")
    if (members["v"], members["type"], members["outcome"], members["cause"]) != (
            1, "supersede", "refused", "policy") or members["policy_code"] not in SUPERSEDE_CODES:
        raise RecoveryCorrupt("supersede_invalid", "members")
    return members


def commit_supersede(state_dir: Path, record_dir: str, rec: bytes, *, record_id: str,
                     decision_sha256: str) -> Dict[str, Any]:
    """Link the supersession once (never replacing, durable), read it back
    and verify it. An identical one already there is accepted."""
    key = _decision_key(state_dir)
    parse_supersede(rec, key, record_id=record_id, decision_sha256=decision_sha256)
    dirfd = _record_dir_fd(Path(state_dir), record_dir)
    try:
        _link_once(dirfd, SUPERSEDE_FILE, rec, stage_prefix=SUPERSEDE_STAGE_PREFIX)
        data, fd, _dev, _ino = _read_checked(dirfd, SUPERSEDE_FILE)
        os.close(fd)
    finally:
        os.close(dirfd)
    if data != rec:
        raise RecoveryCorrupt("readback")
    return parse_supersede(data, key, record_id=record_id, decision_sha256=decision_sha256)


def reopen_supersede(state_dir: Path, record_dir: str, *, record_id: str
                     ) -> Optional[Dict[str, Any]]:
    """The supersession on disk, verified, or None when there is none. The
    decision's bytes are compared when the decision is present; a
    supersession is valid under the current key whether or not the decision
    still verifies."""
    key = _decision_key(state_dir)
    dirfd = _record_dir_fd(Path(state_dir), record_dir)
    try:
        _clean_stage(dirfd, SUPERSEDE_STAGE_PREFIX)
        try:
            data, fd, _dev, _ino = _read_checked(dirfd, SUPERSEDE_FILE)
        except FileNotFoundError:
            return None
        os.close(fd)
        try:
            dec, dfd, _d, _i = _read_checked(dirfd, DECISION_FILE)
            os.close(dfd)
            decision_sha = _sha(dec)
        except FileNotFoundError:
            decision_sha = None
    finally:
        os.close(dirfd)
    return parse_supersede(data, key, record_id=record_id, decision_sha256=decision_sha)


# ---------------------------------------------------------------------------
# The published fields
# ---------------------------------------------------------------------------

def published(auth: Authorised, *, in_reply_to_resolved: Optional[str] = None) -> Dict[str, Any]:
    """The values a placement publishes from the statement, independent of
    any attachment's disposition: `id`, `from`, `to`, `subject`,
    `body_text`, `sender_exposure` (when signed), each attachment's
    `filename`, `media_type`, `size_bytes` and `sha256`, and `in_reply_to`
    only when the caller resolved it from its own ledger."""
    _require_seal(auth)
    p = auth.payload
    signed_reply = p.get("in_reply_to")
    if signed_reply is not None and in_reply_to_resolved is None:
        raise ValueError("in_reply_to is unresolved: a reply is placed only once resolved")
    if in_reply_to_resolved is not None and in_reply_to_resolved != signed_reply:
        raise ValueError("the resolved in_reply_to is not the statement's")
    out: Dict[str, Any] = {
        "id": p["id"], "from": p["from"], "to": p["to"], "subject": p["subject"],
        "body_text": auth.body_text,
        "attachments": [{"filename": a["filename"], "media_type": a["media_type"],
                         "size_bytes": a["size_bytes"], "sha256": a["sha256"]}
                        for a in (p.get("attachments") or ())],
    }
    if "sender_exposure" in p:
        out["sender_exposure"] = json.loads(json.dumps(p["sender_exposure"], default=dict))
    if signed_reply is not None:
        out["in_reply_to"] = signed_reply
    return out


def consistency(auth: Authorised) -> None:
    """`RecoveryCorrupt` unless a decided `auth`'s parts agree with its own
    statement and its preset is well-formed: placement's only re-check."""
    _require_seal(auth)
    why = _consistent(auth)
    if why is not None:
        raise RecoveryCorrupt("inconsistent", why)
    if not (isinstance(auth.notice_id, str) and _NOTICE_ID_RE.fullmatch(auth.notice_id)
            and isinstance(auth.ts, str) and _TS_RE.fullmatch(auth.ts)):
        raise RecoveryCorrupt("preset")
