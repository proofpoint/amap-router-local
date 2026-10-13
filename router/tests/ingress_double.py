"""A test-only InboundPort double for the ingress pump: committed entries
by id, the cursor-and-lookahead listing the Protocol describes, a refusal
class captured like the real one, and a count of every call. Built from the
Protocol's member names only; it lives in router/tests and nowhere else."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple


class NoticeRefused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ListingTooLarge(Exception):
    pass


class DoublePort:
    """`entries` maps an entry id to its bytes, or to a refusal reason
    (`"notice_incomplete"` / `"notice_invalid"`), or to an exception
    instance to raise. Listing is by id in code-point order."""

    NoticeRefused = NoticeRefused

    def __init__(self, entries: Optional[Dict[str, object]] = None):
        self.entries: Dict[str, object] = dict(entries or {})
        self.reads: List[str] = []
        self.lists = 0
        self.too_large = False

    def list_entries(self, kind: str, *, limit: int,
                     after: Optional[str] = None) -> Tuple[List[str], bool]:
        assert kind == "notice"
        self.lists += 1
        if self.too_large:
            raise ListingTooLarge("too many names")
        ids = sorted(e for e in self.entries if after is None or e > after)
        return ids[:limit], len(ids) > limit

    def read_entry(self, kind: str, entry_id: str) -> bytes:
        assert kind == "notice"
        self.reads.append(entry_id)
        if entry_id not in self.entries:
            raise FileNotFoundError(entry_id)
        value = self.entries[entry_id]
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            raise NoticeRefused(value)
        raise value

    def close(self) -> None:
        pass


class DoubleReader:
    """What `hoplink.reader_for` returns: the port and its captured class."""

    def __init__(self, port: DoublePort):
        self.port = port
        self.notice_refused = port.NoticeRefused
