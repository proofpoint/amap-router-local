"""A read that decides nothing, again and again (`ingress.Pump._read`): the
runtime's own refusal class, or an OSError, from `read_entry`. It is never
silent: kept per journal key with its first sighting, a WARNING while young
and an ERROR once it has persisted, and counted in status, COUNT-ONLY (the
upstream entry id never reaches status.json). A read that decides clears it."""
from __future__ import annotations

import json
import logging

from router import hoplink, ingress
from router.fsops import ListingTooLarge as RuntimeTooLarge, UnsafeRead
from router.tests.ingress_double import DoubleReader, ListingTooLarge
from router.tests.test_ingress_pump import CAP, E1, HORIZON, LINK, _Pump, entry


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _unsafe(reason):
    e = UnsafeRead.__new__(UnsafeRead)
    Exception.__init__(e, reason)
    e.reason = reason
    return e


class ReadRefusalTests(_Pump):

    def setUp(self):
        super().setUp()
        self.clock = _Clock()
        orig = hoplink._clock
        hoplink._clock = self.clock
        self.addCleanup(setattr, hoplink, "_clock", orig)
        ingress.READ_REFUSALS.clear()
        self.addCleanup(ingress.READ_REFUSALS.clear)

    def pump_rt(self):
        p = ingress.Pump(self.keyed, DoubleReader(self.port), self.lid, self.gen, LINK,
                         report=self.report, recipient="bravo", unresolved=None,
                         attachment_cap=CAP, runtime_classes=(UnsafeRead,),
                         runtime_roles=((UnsafeRead, "unsafe_read"),
                                        (RuntimeTooLarge, "listing_too_large")))
        return ingress.pump_generation(p, listing_too_large=ListingTooLarge, horizon_s=HORIZON)

    def section(self):
        doc = ingress.status_doc(self.keyed)
        return doc["generations"].get(f"{self.lid}/{self.gen}", {})

    def logged(self, fn):
        log = logging.getLogger("amap_router_local")
        was = log.disabled
        log.disabled = False
        try:
            with self.assertLogs("amap_router_local.ingress", level="WARNING") as cm:
                fn()
        finally:
            log.disabled = was
        return [r for r in cm.records if "cannot be read" in r.getMessage()]

    def test_quiet_then_loud_once_stale_and_counted_without_the_entry_id(self):
        self.port.entries[E1] = _unsafe("link_count")
        records = self.logged(self.pump_rt)
        self.assertEqual([r.levelname for r in records], ["WARNING"])
        self.assertIsNone(self.state(E1), "no decision: no journal record")
        refusals = self.section().get("read_refusals")
        self.assertIsNotNone(refusals, "not counted in status")
        self.assertEqual((refusals["count"], refusals["reasons"]),
                         (1, {"unsafe_read:link_count": 1}))
        self.clock.t += ingress.READ_REFUSAL_STALE_S
        records = self.logged(self.pump_rt)
        self.assertEqual([r.levelname for r in records], ["ERROR"], "persisted: loud")
        self.assertEqual(self.section()["read_refusals"]["oldest_age_s"],
                         ingress.READ_REFUSAL_STALE_S, "the first sighting is kept")
        text = json.dumps(ingress.status_doc(self.keyed))
        self.assertNotIn(E1, text, "the upstream entry id reached status")

    def test_an_oserror_is_tracked_alike(self):
        self.port.entries[E1] = OSError(5, "EIO")
        self.pump_rt()
        self.assertEqual(self.section()["read_refusals"]["reasons"], {"oserror:EIO": 1})

    def test_a_read_that_decides_clears_it(self):
        self.port.entries[E1] = _unsafe("link_count")
        self.pump_rt()
        self.port.entries[E1] = entry(E1)
        self.pump_rt()
        self.assertNotIn("read_refusals", self.section())
        self.assertIsNotNone(self.state(E1), "the entry was decided")

    def test_a_changed_reason_restarts_the_age(self):
        self.port.entries[E1] = _unsafe("link_count")
        self.pump_rt()
        self.clock.t += ingress.READ_REFUSAL_STALE_S
        self.port.entries[E1] = OSError(5, "EIO")
        self.pump_rt()
        self.assertEqual(self.section()["read_refusals"]["oldest_age_s"], 0)
