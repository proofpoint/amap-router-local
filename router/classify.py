"""router/classify.py — the cold-send classifier, the policy digest, and the
one address grammar.

THREE THINGS LIVE HERE, AND NOTHING ELSE:

  * `parse_address`, the ONE address grammar. Every address a cold send names
    passes through it before anything is compared, and the load-time checks
    on the host lists use the same parser, so there is no second spelling of
    what an address is. It refuses; it never normalises a bad address into a
    match.
  * `canonical_hosts` / `canonical_entries`, the ONE canonicaliser for the
    host lists and for the policy digest's inputs. `config.load()` calls it to
    refuse duplicates, and `policy_object` calls it to build the digest, so a
    case variant or a duplicate cannot give two digests for one policy.
  * `classify`, the cold-send order: a pure function of the config, the
    sender, the draft and two injected facts (is a transport plugin present;
    what time is it). It reads the registry report already attached to the
    config and calls `exposure.assess`; nothing else.

THE ORDER, frozen, each edge with a witness in `tests/test_classify.py`:

  1. alias normalisation, hold then refuse (`aliases.normalise`, run by the
     caller before this module sees the draft);
  2. any malformed address: `rejected` / `malformed_request`;
  3. any address at this router's own domain naming no instance:
     `rejected` / `recipient_unknown`;
  4. no transport plugin and any cross-host address: `rejected` /
     `recipient_unknown`, short-circuiting everything below;
  5. more than one class across `to` ∪ `cc`: `rejected` /
     `mixed_recipient_classes`;
  6. the single class's rule:
       - LOCAL: this router's existing same-host decision, unchanged
         (`outbound.default_cold_policy`);
       - TRUSTED fleet host: `_trusted`, below, in its own frozen order;
       - FLEET host not in the trusted list, or the INTERNET: the item 6 and
         item 7 rules (`remote_rule`), the ONLY decision a custom
         `ColdPolicy` may replace (`outbound._drain_cold`).

A reply never reaches this module: a request carrying `in_reply_to` is
decided by its binding (`outbound._drain_reply`), and an unbound key stays
`unresolved_reply`.

THE TRUSTED-HOST ORDER (item 5):

  a. shape first: more than one recipient, or any cc, cannot be a peer task,
     so it is cold fleet mail: `fleet_mail_disabled`. `peer_single_recipient`
     stays the same-host peer lane's code;
  b. `task_deny` removes the edge: `peer_denied`;
  c. the sender is under 24 h old by its CURRENT registry entry, its
     `first_registered_ts` lies in the future, or there is no such value:
     `peer_quarantined` (the last with detail "sender age unknown");
  d. `exposure.assess` returns None or raises: `exposure_unavailable`. The
     stamp it returns is the one the statement would carry;
  e. no cross-host peer lane on this router (no signer: RL's signing step is
     not built): `recipient_unknown`, "the cross-host peer lane is not
     available on this router". Decided BEFORE the size check, so the
     `statement_size` seam's default, which raises, is never reached;
  f. the signed statement would exceed 8192 bytes: `peer_statement_too_large`.

All of item 5's answers are synchronous and nothing is published.

THE POLICY DIGEST. The sender's EFFECTIVE POLICY OBJECT is exactly the inputs
that decide a cross-host permit for it, canonicalised:

    {"v": 1, "send_to": [...], "remote_fleet": [...], "task_deny": [...],
     "trusted_fleet_hosts": [...], "egress": <bool>}

and its digest is the pinned form, byte for byte:

    "sha256:" + hex(sha256(json.dumps(obj, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        .encode("utf-8")))

`tests/vectors/policy_digest.json` holds known answers, shared with the
external leg's runtime so the two suites cannot drift. The digest is
RECORDED and LOGGED; it is never the trigger for a re-check, because the
registry age, the exposure, the plugin's presence, `fleet_domain` and
`fleet_hosts` are not in it. Every publication re-classifies instead
(`outbound._recheck`).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from . import config as config_mod
from .util import parse_utc_ts

# -- reason codes this module originates ------------------------------------

REASON_MALFORMED = "malformed_request"
REASON_RECIPIENT_UNKNOWN = "recipient_unknown"
REASON_MIXED = "mixed_recipient_classes"
REASON_NO_ROUTE = "no_route"
REASON_FLEET_MAIL_DISABLED = "fleet_mail_disabled"
REASON_PEER_DENIED = "peer_denied"
REASON_PEER_QUARANTINED = "peer_quarantined"
REASON_EXPOSURE_UNAVAILABLE = "exposure_unavailable"
REASON_STATEMENT_TOO_LARGE = "peer_statement_too_large"
REASON_NOT_ALLOWLISTED = "recipient_not_allowlisted"

# -- classes ----------------------------------------------------------------

CLASS_LOCAL = "local"
CLASS_UNKNOWN = "this_domain_unknown"
CLASS_TRUSTED = "trusted_fleet_host"
CLASS_FLEET = "fleet_host"
CLASS_INTERNET = "internet"
#: The classes that leave this host through a transport: the ones a record
#: in flight can carry as its `route`.
REMOTE_ROUTES = (CLASS_FLEET, CLASS_INTERNET)

#: The domain of the legacy address scheme, `agent.<name>@local`, which is
#: this router's own domain when the fleet has no `fleet_domain`.
LEGACY_DOMAIN = "local"

#: Item 5c: a sender younger than this, by its registry entry, is refused.
QUARANTINE_S = 24 * 3600

#: Item 5f: the largest signed peer statement, in bytes.
STATEMENT_MAX_BYTES = 8192

#: Bounds of the address grammar.
LOCAL_MAX = 64
ADDRESS_MAX = 254
DOMAIN_MAX = 253

POLICY_VERSION = 1
DIGEST_PREFIX = "sha256:"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")

# -- the address grammar ----------------------------------------------------

# RFC 5322 atext, ASCII only. A dot-atom is one or more atoms joined by
# single dots: no leading, trailing or doubled dot, no quoting, no comments.
_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
_DOT_ATOM_RE = re.compile(rf"{_ATEXT}+(?:\.{_ATEXT}+)*\Z")
# An LDH label: letters, digits and hyphens, not starting or ending with a
# hyphen. Compared lowercased, so upper case is accepted here and folded.
_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
# The registry's name grammar (`registry._NAME`): what a fleet local part is.
_FLEET_LOCAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class Malformed(ValueError):
    """An address, domain or list entry outside the grammar. `str(e)` says
    which rule it broke and never echoes the input."""


@dataclass(frozen=True)
class Address:
    """A parsed address: the local part exactly as given, the domain
    lowercased. Remote local parts are compared EXACTLY; only a local part at
    this router's own domain is matched case-insensitively, because there it
    names an instance (`config.instance_for`)."""
    local: str
    domain: str

    def canonical(self) -> str:
        return f"{self.local}@{self.domain}"


def check_domain(raw: Any) -> str:
    """`raw` lowercased, or `Malformed`. Dot-separated LDH labels of 1-63
    ASCII letters, digits or inner hyphens, at most 253 characters in all.
    That alone refuses a trailing dot (an empty label), a bracketed IP
    literal and a U-label (refused, never decoded); a dotted numeric address
    is refused by its all-digit last label."""
    if not isinstance(raw, str):
        raise Malformed("a domain must be a string")
    if len(raw) > DOMAIN_MAX:
        raise Malformed(f"a domain is at most {DOMAIN_MAX} characters")
    labels = raw.split(".")
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        raise Malformed("a domain is dot-separated labels of 1-63 ASCII letters, digits "
                        "or inner hyphens")
    if labels[-1].isdigit():
        raise Malformed("a numeric address is not a domain")
    return raw.lower()


def parse_address(raw: Any) -> Address:
    """The one address grammar: an ASCII dot-atom local part of at most 64
    characters, one `@`, a domain per `check_domain`, at most 254 characters
    in all. `@`, quotes, parentheses, whitespace and non-ASCII are not atext,
    so a second `@`, a quoted local part, a comment or folding whitespace
    fails the dot-atom. Anything else is `Malformed`, which a cold send
    answers `malformed_request`."""
    if not isinstance(raw, str):
        raise Malformed("an address must be a string")
    if len(raw) > ADDRESS_MAX:
        raise Malformed(f"an address is at most {ADDRESS_MAX} characters")
    local, _, domain = raw.rpartition("@")
    if len(local) > LOCAL_MAX:
        raise Malformed(f"a local part is at most {LOCAL_MAX} characters")
    if not _DOT_ATOM_RE.fullmatch(local):
        raise Malformed("a local part is an unquoted dot-atom of ASCII atext")
    return Address(local, check_domain(domain))


def check_fleet_local(addr: Address) -> None:
    """A local part at a fleet domain (this router's own, or any host in
    `fleet_hosts`) is a registry NAME, so it must match the registry's name
    grammar too."""
    if not _FLEET_LOCAL_RE.fullmatch(addr.local):
        raise Malformed("a fleet address's local part is outside the name grammar")


# -- the canonicaliser ------------------------------------------------------

def canonical_host(raw: Any) -> str:
    return check_domain(raw)


def canonical_entry(raw: Any) -> str:
    """One `send_to` / `task_deny` entry: an exact address, or `@domain` for
    every address at that domain. Returned with the domain lowercased and the
    local part exact."""
    if isinstance(raw, str) and raw.startswith("@"):
        return "@" + check_domain(raw[1:])
    return parse_address(raw).canonical()


def entry_domain(entry: str) -> str:
    """The domain of a CANONICAL entry."""
    return entry.rsplit("@", 1)[1]


def canonical_hosts(values: Iterable[Any]) -> List[str]:
    """Canonical, de-duplicated and sorted. THE canonicaliser for the host
    lists and for the digest (module docstring)."""
    return sorted({canonical_host(v) for v in values})


def canonical_entries(values: Iterable[Any]) -> List[str]:
    return sorted({canonical_entry(v) for v in values})


def duplicates(values: Iterable[Any], canon: Callable[[Any], str]) -> List[str]:
    """The canonical forms that occur more than once in `values`."""
    seen: Dict[str, int] = {}
    for v in values:
        c = canon(v)
        seen[c] = seen.get(c, 0) + 1
    return sorted(c for c, k in seen.items() if k > 1)


# -- the policy digest ------------------------------------------------------

def policy_object_from(
    *, send_to: Iterable[Any], remote_fleet: Iterable[Any], task_deny: Iterable[Any],
    trusted_fleet_hosts: Iterable[Any], egress: bool,
) -> Dict[str, Any]:
    """The effective policy object from raw inputs, canonicalised (module
    docstring). Raises `Malformed` on any entry outside the grammar."""
    if not isinstance(egress, bool):
        raise Malformed("egress must be a boolean")
    return {
        "v": POLICY_VERSION,
        "send_to": canonical_entries(send_to),
        "remote_fleet": canonical_hosts(remote_fleet),
        "task_deny": canonical_entries(task_deny),
        "trusted_fleet_hosts": canonical_hosts(trusted_fleet_hosts),
        "egress": egress,
    }


def digest_of(obj: Dict[str, Any]) -> str:
    """The pinned digest form (module docstring), exactly."""
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    return DIGEST_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()


def policy_object(cfg: "config_mod.RouterConfig", sender: str) -> Dict[str, Any]:
    inst = cfg.instances[sender]
    return policy_object_from(
        send_to=inst.send_to, remote_fleet=inst.remote_fleet, task_deny=inst.task_deny,
        trusted_fleet_hosts=cfg.trusted_fleet_hosts, egress=cfg.egress,
    )


def policy_digest(cfg: "config_mod.RouterConfig", sender: str) -> str:
    return digest_of(policy_object(cfg, sender))


# -- decisions --------------------------------------------------------------

@dataclass(frozen=True)
class Refuse:
    """Answered now; nothing is published."""
    outcome: str
    reason_code: str
    detail: Optional[str] = None
    hold: bool = False


@dataclass(frozen=True)
class Local:
    """Every recipient is an instance of this router: the same-host decision
    decides, unchanged."""


@dataclass(frozen=True)
class Remote:
    """Every recipient is in ONE cross-host class, item 6's or item 7's, and
    has passed steps 1-5. `recipients` is `to` ∪ `cc` as the agent spelled
    them; `canonical` is the same set canonicalised, for comparison."""
    klass: str
    recipients: Tuple[str, ...]
    canonical: Tuple[str, ...]


@dataclass(frozen=True)
class PeerRemote:
    """A trusted-host peer task that passed every item 5 check. No production
    path reaches this before the cross-host peer lane exists (item 5e)."""
    recipient: str
    exposure: Dict[str, Any]


Decision = Union[Refuse, Local, Remote, PeerRemote]


def peer_lane_available(cfg: "config_mod.RouterConfig") -> bool:
    """Item 5e: can this router sign a cross-host peer statement? Not before
    its signing step exists, so never, today. A seam, not a setting."""
    return False


def statement_size(cfg: "config_mod.RouterConfig", sender: str, draft: Dict[str, Any],
                   exposure: Dict[str, Any]) -> int:
    """Item 5f: the size of the signed statement this draft would make. The
    signing step supplies it; until then this raises, and item 5e makes it
    unreachable (module docstring)."""
    raise NotImplementedError("no cross-host peer statement can be built on this router")


def address_class(cfg: "config_mod.RouterConfig", raw: Any) -> Tuple[str, Address]:
    """`raw`'s class, or `Malformed`."""
    addr = parse_address(raw)
    own = cfg.fleet_domain or LEGACY_DOMAIN
    if addr.domain == own:
        check_fleet_local(addr)
        name = config_mod.instance_for(addr.canonical(), cfg.fleet_domain, cfg.instances)
        return (CLASS_LOCAL if name is not None else CLASS_UNKNOWN), addr
    if addr.domain in cfg.trusted_fleet_hosts:
        check_fleet_local(addr)
        return CLASS_TRUSTED, addr
    if addr.domain in cfg.fleet_hosts:
        check_fleet_local(addr)
        return CLASS_FLEET, addr
    return CLASS_INTERNET, addr


def recipients(draft: Dict[str, Any]) -> List[Any]:
    """`to` ∪ `cc`, in order, as the agent spelled them."""
    return list(draft.get("to") or []) + list(draft.get("cc") or [])


def remote_of(cfg: "config_mod.RouterConfig", draft: Dict[str, Any]) -> Remote:
    """The `Remote` decision for a draft `classify` already found to be one
    cross-host class of item 6 or 7. Raises `Malformed` or `ValueError` for a
    draft that is not one: it is for a policy, after classification."""
    raws = recipients(draft)
    classes = [address_class(cfg, r) for r in raws]
    kinds = {k for k, _ in classes}
    if len(kinds) != 1 or not kinds <= set(REMOTE_ROUTES):
        raise ValueError("not a single item 6 or item 7 class")
    return Remote(kinds.pop(), tuple(raws), tuple(a.canonical() for _, a in classes))


def classify(
    cfg: "config_mod.RouterConfig", sender: str, draft: Dict[str, Any],
    *, plugin: bool, now: str,
) -> Decision:
    """Steps 2-6 of the order (module docstring). `draft` is already
    alias-normalised (step 1). `plugin` says whether a transport plugin is
    present; `now` is the decision's time."""
    raws = recipients(draft)
    classes: List[Tuple[str, Address]] = []
    malformed = 0
    for raw in raws:
        try:
            classes.append(address_class(cfg, raw))
        except Malformed:
            malformed += 1
    if malformed:
        return Refuse("rejected", REASON_MALFORMED,
                      detail=f"{malformed} recipient address(es) outside the address grammar")
    if any(k == CLASS_UNKNOWN for k, _ in classes):
        return Refuse("rejected", REASON_RECIPIENT_UNKNOWN)
    if not plugin and any(k != CLASS_LOCAL for k, _ in classes):
        return Refuse("rejected", REASON_RECIPIENT_UNKNOWN,
                      detail="no transport plugin: a cross-host recipient cannot be routed")
    kinds = {k for k, _ in classes}
    if len(kinds) > 1:
        return Refuse("rejected", REASON_MIXED,
                      detail="one request goes to one class of recipient: "
                             + ", ".join(sorted(kinds)))
    if not kinds or kinds == {CLASS_LOCAL}:
        return Local()
    klass = sorted(kinds)[0]
    if klass == CLASS_TRUSTED:
        return _trusted(cfg, sender, draft, [a for _, a in classes], now=now)
    return Remote(klass, tuple(raws), tuple(a.canonical() for _, a in classes))


def _denied(entries: Iterable[str], addr: Address) -> bool:
    canon = addr.canonical()
    return any(e == canon or e == "@" + addr.domain for e in canonical_entries(entries))


def sender_age_refusal(cfg: "config_mod.RouterConfig", sender: str,
                       now: str) -> Optional[str]:
    """Item 5c: None when the sender is old enough, else the detail. Reads
    the CURRENT registry entry from this poll's report."""
    report = cfg.registry_report
    entries = getattr(report, "entries", None) or {}
    entry = entries.get(sender)
    first = parse_utc_ts(getattr(entry, "first_registered_ts", None))
    if first is None:
        return "sender age unknown"
    now_dt = parse_utc_ts(now)
    if now_dt is None:
        return "sender age unknown"
    age = (now_dt - first).total_seconds()
    if age < 0:
        return "the sender's first_registered_ts is in the future"
    if age < QUARANTINE_S:
        return f"the sender registered {int(age)}s ago, under {QUARANTINE_S}s"
    return None


def _trusted(cfg: "config_mod.RouterConfig", sender: str, draft: Dict[str, Any],
             addrs: List[Address], *, now: str) -> Decision:
    """Item 5, in its frozen order (module docstring, a-f)."""
    # `addrs` is to ∪ cc, so any cc makes it more than one.
    if len(addrs) != 1:
        return Refuse("rejected", REASON_FLEET_MAIL_DISABLED,
                      detail="cold mail to a trusted fleet host is disabled; a peer task "
                             "names exactly one recipient, in to, with no cc")
    addr = addrs[0]
    if _denied(cfg.instances[sender].task_deny, addr):
        return Refuse("rejected", REASON_PEER_DENIED)
    age = sender_age_refusal(cfg, sender, now)
    if age is not None:
        return Refuse("rejected", REASON_PEER_QUARANTINED, detail=age)
    from . import exposure as exposure_mod   # late: patchable, and no import cycle
    try:
        stamp = exposure_mod.assess(cfg, sender, now=now)
    except Exception:  # noqa: BLE001 -- any failure is "unavailable", never a send
        stamp = None
    if stamp is None:
        return Refuse("rejected", REASON_EXPOSURE_UNAVAILABLE)
    if not peer_lane_available(cfg):
        return Refuse("rejected", REASON_RECIPIENT_UNKNOWN,
                      detail="the cross-host peer lane is not available on this router")
    if statement_size(cfg, sender, draft, stamp) > STATEMENT_MAX_BYTES:
        return Refuse("rejected", REASON_STATEMENT_TOO_LARGE)
    return PeerRemote(addr.canonical(), stamp)


def remote_rule(cfg: "config_mod.RouterConfig", sender: str, remote: Remote
                ) -> Union[Refuse, Remote]:
    """Items 6 and 7, the default for a `Remote` decision.

    Item 6, a fleet host not in the trusted list: permitted when every
    recipient's host is in the sender's `remote_fleet`; otherwise held for a
    human. Item 7, the internet: no egress on this host is `no_route`, FIRST;
    then `send_to` permits each recipient by exact address or by `@domain`,
    or the request is held for a human."""
    inst = cfg.instances[sender]
    if remote.klass == CLASS_FLEET:
        hosts = set(canonical_hosts(inst.remote_fleet))
        if all(entry_domain(c) in hosts for c in remote.canonical):
            return remote
        return Refuse("queued_for_human", REASON_NOT_ALLOWLISTED, hold=True,
                      detail="remote_fleet does not permit this fleet host")
    if not cfg.egress:
        return Refuse("rejected", REASON_NO_ROUTE,
                      detail="this host has no egress to the internet")
    allowed = set(canonical_entries(inst.send_to))
    if all(c in allowed or "@" + entry_domain(c) in allowed for c in remote.canonical):
        return remote
    return Refuse("queued_for_human", REASON_NOT_ALLOWLISTED, hold=True,
                  detail="send_to does not permit this recipient")
