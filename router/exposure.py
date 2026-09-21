"""router/exposure.py — the `sender_exposure` stamp on a peer notice.

The one tracing field the peer-origin profile ships (AMAP 3.1.0, `message.
sender_exposure`), and it is the ROUTER's assertion, never the sender's: a
submit-request carrying it is `rejected`/`malformed_request` by the closed
envelope before policy runs (`router/validate.py`, pinned by
`tests/test_peer_fixtures.py`). What it asserts is narrow and delivery-based:
"was external mail written into the SENDER's mail tree during this window",
a proxy for "may this peer message paraphrase something a stranger wrote".
Advisory only — it MUST NOT drive routing or treatment, and nothing in this
repo reads it back.

    {"asserted_by": "amap.router@<fleet_domain>",
     "external_mail_delivered": false,
     "window_start": "...", "window_end": "...",
     ["last_external_delivery_ts": "..."]}       # only when true

The window is `[now - sender_exposure_window_seconds, now]` (default 24 h),
`now` being the moment the router accepts the submit, with `window_start`
CLAMPED FORWARD to the sender's `first_seen_ts` when first sight is later:
`reset` clears the ledger and the first-sight marker together, so anything
before the current first sight is genuinely unassessed, and the window on the
wire must be exactly
the span the boolean covers — never wider.

Two sources, in this order:

  1. The router's own ledger for the sender (`state_dir/<sender>/delivered/`)
     — every notice this router placed in the sender's trees, in window. A
     record counts as EXTERNAL iff it carries `origin: "external"`, the mark
     the cross-host DEMOTION branch will write when an unverifiable
     candidate is downgraded to mail. No record written today carries it:
     same-principal agent mail and the router's own DSNs (`authored_by:
     "router"`) are internal by construction.
  2. A bounded, read-only LISTING of the sender's `inbox/notices/` for
     notice files whose id this router did not ledger. Those can only have
     been written by another mail deliverer (the email router, when one
     exists), which is the open transport by definition. Names and
     `fstat` only — nothing is opened or parsed, because a notice this
     router did not write is not this router's to trust; the file's mtime
     places it in or out of the window and, when in, is the
     `last_external_delivery_ts`. The listing is pinned (`O_NOFOLLOW`
     descent from the instance root, the read-side discipline every
     agent-adjacent path gets) and CAPPED: past `MAX_NOTICE_LISTING`
     entries the assessment is abandoned and `assess` returns `None`, so
     the notice carries NO stamp — absence means "not assessed", never "no
     exposure", and a false `false` is the one answer this module must
     never give.

In this fleet today the answer is `false` over the full window for every
sender, and it is ASSERTED, not omitted: this router is the only writer of
every mail tree and knows it. When an email router is added the same code
starts answering `true` with no change, because source 2 is already looking
for exactly its footprint.

`derived_from` is not populated by this router: a reply to a MAIL-tree notice
binds to the mail sender and leaves as mail (`outbound._drain_reply`), so the
derivation the field records never leads to a peer notice here. Recorded so
its absence reads as "not applicable", not as a bug (handoff rev 2 §4).
"""

from __future__ import annotations

import logging
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

from . import firstsight as firstsight_mod
from . import attachments as attachments_mod
from . import binding
from .config import RouterConfig, router_address
from .util import format_utc_ts, parse_utc_ts

logger = logging.getLogger("amap_router_local.exposure")

#: Ledger records carrying this mark were placed by the demotion branch —
#: mail that arrived off the open transport and failed peer verification.
ORIGIN_EXTERNAL = "external"

#: Past this many entries in the sender's `inbox/notices/`, the listing is
#: abandoned and the stamp omitted (module docstring).
MAX_NOTICE_LISTING = 50_000

_NOTICE_FILE_RE = re.compile(r"^notice-([A-Za-z0-9_][A-Za-z0-9_.-]*)\.json$")


def _window(cfg: RouterConfig, sender: str, now: datetime) -> datetime:
    """`window_start`: `now - window`, clamped forward to the sender's
    `first_seen_ts` when that is later. An unparseable `first_seen_ts` is
    ignored (the first-sight marker is router-private; a corrupt one is a bug
    to log, not a reason to widen the window)."""
    start = now - timedelta(seconds=cfg.sender_exposure_window_seconds)
    doc = firstsight_mod.read_marker(cfg.state_dir, sender)
    if doc is not None:
        first_seen = parse_utc_ts(doc.get("first_seen_ts"))
        if first_seen is not None and first_seen > start:
            start = first_seen
    return start


def _scan_ledger(
    state_dir: Path, sender: str, start: datetime, end: datetime,
) -> "tuple[Set[str], Optional[datetime]]":
    """Source 1. Returns `(ledgered_ids, latest_external_ts_in_window)`.
    Every record's id is collected regardless of window (source 2 needs
    the full set to know what this router wrote); only in-window external
    records move the timestamp."""
    ids: Set[str] = set()
    latest: Optional[datetime] = None
    ledger = binding.ledger_dir(state_dir, sender)
    try:
        entries = list(os.scandir(ledger))
    except OSError:
        return ids, None
    for entry in entries:
        m = _NOTICE_FILE_RE.match(entry.name)
        if not m:
            continue
        ids.add(m.group(1))
        record = binding.read_ledger_record(state_dir, sender, m.group(1))
        if not record or record.get("origin") != ORIGIN_EXTERNAL:
            continue
        ts = parse_utc_ts(record.get("ts"))
        if ts is None or ts < start or ts > end:
            continue
        if latest is None or ts > latest:
            latest = ts
    return ids, latest


def _scan_unledgered_notices(
    cfg: RouterConfig, sender: str, ledgered: Set[str], start: datetime, end: datetime,
) -> "tuple[bool, Optional[datetime]]":
    """Source 2. Returns `(assessed, latest_unledgered_mtime_in_window)`.
    `assessed=False` means the listing overflowed `MAX_NOTICE_LISTING` and
    the caller must NOT stamp. A missing or non-directory `notices/` is an
    assessed "nothing there"."""
    inst = cfg.instances[sender]
    root = inst.root
    notices_rel = (inst.inbox_root / "notices").relative_to(root)
    latest: Optional[datetime] = None
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        notices_fd = attachments_mod._descend_pinned(root_fd, notices_rel)
        if notices_fd is None:
            return True, None
        try:
            seen = 0
            with os.scandir(notices_fd) as it:
                for entry in it:
                    seen += 1
                    if seen > MAX_NOTICE_LISTING:
                        logger.warning(
                            "instance %r: inbox/notices/ exceeds %d entries; "
                            "sender_exposure NOT assessed for this notice",
                            sender, MAX_NOTICE_LISTING,
                        )
                        return False, None
                    m = _NOTICE_FILE_RE.match(entry.name)
                    if not m or m.group(1) in ledgered:
                        continue
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    # Second precision, like every timestamp on the wire: a
                    # notice written in the same second as `now` is IN the
                    # window, not a few hundred microseconds past its end.
                    mtime = datetime.fromtimestamp(int(st.st_mtime), tz=timezone.utc)
                    if mtime < start or mtime > end:
                        continue
                    if latest is None or mtime > latest:
                        latest = mtime
        finally:
            os.close(notices_fd)
    finally:
        os.close(root_fd)
    return True, latest


def assess(cfg: RouterConfig, sender: str, *, now: str) -> Optional[Dict[str, Any]]:
    """The `sender_exposure` object for a peer notice `sender` is sending
    now (`now` = the notice's `ts`, so the window ends exactly at the
    stamp). `None` — stamp nothing — when the fleet has no domain (no
    `asserted_by` to name) or the listing overflowed (module docstring).
    Never raises for an ordinary filesystem surprise on the agent-adjacent
    path: that too returns `None`, because an unassessed notice is
    conformant and a wrongly-stamped one is not."""
    asserted_by = router_address(cfg.fleet_domain)
    end = parse_utc_ts(now)
    if asserted_by is None or end is None:
        return None
    start = _window(cfg, sender, end)
    ledgered, latest = _scan_ledger(cfg.state_dir, sender, start, end)
    try:
        assessed, latest_unledgered = _scan_unledgered_notices(cfg, sender, ledgered, start, end)
    except OSError as e:
        logger.warning(
            "instance %r: could not list inbox/notices/ for the exposure "
            "assessment (%s: %s); sender_exposure NOT assessed",
            sender, type(e).__name__, e,
        )
        return None
    if not assessed:
        return None
    if latest_unledgered is not None and (latest is None or latest_unledgered > latest):
        latest = latest_unledgered
    doc: Dict[str, Any] = {
        "asserted_by": asserted_by,
        "external_mail_delivered": latest is not None,
        "window_start": format_utc_ts(start),
        "window_end": format_utc_ts(end),
    }
    if latest is not None:
        doc["last_external_delivery_ts"] = format_utc_ts(latest)
    return doc
