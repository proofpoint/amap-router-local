"""The ingress pump: one dispatch order per generation under the drain lock.
Every witness counts agent-visible notices and quarantine items; the
double counts every read and listing, so "never re-read" and "nothing
listed" are observations, not assumptions."""
from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from router import generations, ingress, registry
from router.tests.helpers import keyed_for_poll, list_notices
from router.tests.ingress_double import DoublePort, DoubleReader, ListingTooLarge
from router.tests.peer_helpers import addr
from router.tests.test_held_local import LIDS, _Fleet
from router.tests.test_ingress_bundle import CAP, enc, make

LINK = "link-a"
E1 = "1700000000-1"
E2 = "1700000000-2"
E3 = "1700000000-3"
FLEET = ("fleet-a.example", "fleet-b.example")
TRUSTED = ("fleet-a.example",)
HORIZON = 30 * 86400
LATER = datetime.now(timezone.utc) + timedelta(seconds=HORIZON + 60)
MUCH_LATER = LATER + timedelta(seconds=HORIZON + 60)


def entry(eid, **kw):
    kw.setdefault("to", addr("bravo"))
    return enc(make(nid=eid, **kw))


class _Pump(_Fleet):

    def setUp(self):
        super().setUp()
        self.poll()
        self.lid = LIDS["bravo"]
        self.gen = generations.read_doc(self.state_dir, self.lid)["current"]
        self.port = DoublePort()
        self.rekey()

    def rekey(self, **cfg_changes):
        self.keyed = replace(keyed_for_poll(self.cfg), fleet_hosts=FLEET,
                             trusted_fleet_hosts=TRUSTED, **cfg_changes)
        self.report = registry.report_for(self.cfg.registry_dir, self.state_dir,
                                          self.cfg.instances, persist=False)

    def pump(self, gen=None, recipient="bravo", limit=1024, proven_unknown=False,
             now=None, horizon_s=HORIZON):
        p = ingress.Pump(self.keyed, DoubleReader(self.port), self.lid, gen or self.gen, LINK,
                         report=self.report, recipient=recipient, unresolved=None,
                         attachment_cap=CAP, proven_unknown=proven_unknown)
        return ingress.pump_generation(p, listing_too_large=ListingTooLarge, limit=limit,
                                       horizon_s=horizon_s, now=now)

    def state(self, eid, gen=None):
        st = ingress.journal_state(self.state_dir, self.lid, gen or self.gen, "notice", LINK,
                                   eid)
        return st and (st["state"], st["reason"])

    def notices(self):
        return list_notices(self.cfg, "bravo")

    def items(self, gen=None):
        return ingress.quarantine_items(self.state_dir, self.lid, "bravo", gen or self.gen,
                                        days=14)

    def snapshots(self, gen=None):
        return ingress.snapshots(self.state_dir, self.lid, gen or self.gen, "notice")

    def mint(self):
        old = self.gen
        generations.operator_new(self.cfg, "bravo", "test: a new generation")
        self.rekey()
        return old


class DispatchTests(_Pump):

    def test_untrusted_fleet_mail_is_placed_once_over_five_pumps(self):
        self.port.entries[E1] = entry(E1)
        for _ in range(5):
            self.pump()
        self.assertEqual(len(self.notices()), 1)
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_incomplete_is_held_unsnapshotted_then_placed_when_readable(self):
        self.port.entries[E1] = "notice_incomplete"
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, "notice_incomplete"))
        self.assertEqual(self.snapshots(), [])
        self.port.entries[E1] = entry(E1)
        self.pump()
        self.assertEqual(len(self.notices()), 1)

    def test_an_older_bundle_is_held_then_placed_once_rendered_current(self):
        b = make(nid=E1, to=addr("bravo"))
        b["schema"] = "amap-hop-notice-entry/1"
        self.port.entries[E1] = enc(b)
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, "bundle_schema"))
        self.port.entries[E1] = entry(E1)
        self.pump()
        self.assertEqual(len(self.notices()), 1)

    def test_first_sight_invalid_is_quarantined_once_e17(self):
        self.port.entries[E1] = "notice_invalid"
        self.pump()
        self.pump()
        (item,) = self.items()
        self.assertEqual(item["cause"], "notice_invalid")
        self.assertIsNone(item["digests"])
        self.assertEqual(self.state(E1),
                         (ingress.QUARANTINED_WAITING_REMOVE, None))
        self.assertEqual(self.notices(), [])
        # Now it reads: nothing was kept to compare with, so it differs.
        self.port.entries[E1] = entry(E1)
        self.pump()
        self.assertEqual(self.state(E1), (ingress.DUPLICATE_DIFFERENT_HELD, "differs"))
        self.assertEqual(len(self.items()), 1)
        self.assertEqual(self.notices(), [])

    def test_rl_s_own_facts_check_is_notice_invalid_too(self):
        self.port.entries[E1] = entry(E1, facts_extra=lambda f: dict(f, admission="weird"))
        self.pump()
        (item,) = self.items()
        self.assertEqual(item["cause"], "notice_invalid")

    def test_a_reread_hold_later_refused_invalid_is_held_not_quarantined(self):
        self.port.entries[E1] = "notice_incomplete"
        self.pump()
        self.port.entries[E1] = "notice_invalid"
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, "notice_invalid"))
        self.assertEqual(self.items(), [])

    def test_a_trusted_host_is_quarantined_cold(self):
        self.port.entries[E1] = entry(E1, facts_extra=lambda f: dict(
            f, origin_host="fleet-a.example"),
            notice_extra=None)
        b = json.loads(self.port.entries[E1])
        n = json.loads(base64.b64decode(b["notice"]))
        n["message"]["from"] = "a@fleet-a.example"
        b["notice"] = base64.b64encode(json.dumps(n).encode()).decode()
        self.port.entries[E1] = json.dumps(b, sort_keys=True, separators=(",", ":")).encode()
        self.pump()
        (item,) = self.items()
        self.assertEqual(item["cause"], "cold_fleet_mail")
        self.assertIsNotNone(item["digests"])
        self.assertEqual(self.notices(), [])

    def test_a_snapshot_hold_is_reevaluated_from_the_snapshot_never_reread(self):
        self.rekey()
        self.keyed = replace(self.keyed, fleet_hosts=("fleet-a.example",))
        self.port.entries[E1] = entry(E1)
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, "unknown_host"))
        self.assertEqual(self.snapshots(), [E1])
        reads = len(self.port.reads)
        self.pump()
        self.assertEqual(len(self.port.reads), reads, "a snapshot hold was re-read")
        # The host becomes a fleet host: placed from the snapshot kept.
        self.rekey()
        self.pump()
        self.assertEqual(len(self.port.reads), reads, "placement re-read upstream")
        self.assertEqual(len(self.notices()), 1)

    def test_mail_for_another_identity_is_held(self):
        self.port.entries[E1] = entry(E1, to=addr("charlie"))
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, "recipient_not_this_identity"))
        self.assertEqual(self.notices(), [])

    def test_a_transient_registry_hold_takes_no_snapshot_and_no_record(self):
        self.port.entries[E1] = entry(E1)
        self.pump(recipient=None)
        self.assertIsNone(self.state(E1))
        self.assertEqual(self.snapshots(), [])
        self.assertEqual(self.notices(), [])

    def test_a_differing_republication_is_held_and_never_placed_again(self):
        self.port.entries[E1] = entry(E1)
        self.pump()
        self.port.entries[E1] = entry(E1, blobs=(b"other",))
        self.pump()
        self.assertEqual(self.state(E1), (ingress.DUPLICATE_DIFFERENT_HELD, "differs"))
        self.assertEqual(len(self.notices()), 1)

    def test_listing_is_paged_with_a_cursor(self):
        for e in (E1, E2, E3):
            self.port.entries[e] = entry(e)
        self.pump(limit=2)
        self.assertEqual(len(self.notices()), 2)
        self.pump(limit=2)
        self.assertEqual(len(self.notices()), 3)

    def test_a_terminal_hold_is_never_read_or_moved(self):
        for reason in (ingress.HELD_PLACING_AMBIGUOUS, "snapshot_invalid:hash"):
            with self.subTest(reason=reason):
                ingress.write(self.state_dir, self.lid, self.gen, "notice", LINK, E1,
                              ingress.HELD, reason=reason)
                self.port.entries[E1] = entry(E1)
                self.port.reads.clear()
                self.pump()
                self.assertEqual(self.port.reads, [])
                self.assertEqual(self.state(E1), (ingress.HELD, reason))
                self.assertEqual(self.notices(), [])

    def test_a_listing_too_large_holds_and_reads_nothing(self):
        self.port.entries[E1] = entry(E1)
        self.port.too_large = True
        counts = self.pump()
        self.assertEqual(counts.get("hop_listing_too_large"), 1)
        self.assertEqual(self.port.reads, [])


class RemovalTests(_Pump):
    """RL-E8b's interim rule (the remover not offered): a waiting record
    becomes its tombstone only when the horizon has passed AND the entry is
    gone upstream; a tombstone is kept at least the horizon."""

    def placed(self):
        self.port.entries[E1] = entry(E1)
        self.pump()
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_an_entry_still_upstream_keeps_waiting_past_the_horizon(self):
        self.placed()
        self.pump(now=LATER)
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_an_entry_gone_before_the_horizon_keeps_waiting(self):
        self.placed()
        del self.port.entries[E1]
        self.pump()
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_gone_and_past_the_horizon_is_a_tombstone_that_still_dedups(self):
        self.placed()
        del self.port.entries[E1]
        self.pump(now=LATER)
        self.assertEqual(self.state(E1), (ingress.COMPLETE, None))
        # Re-published within the tombstone's life: a duplicate, removed again.
        self.port.entries[E1] = entry(E1)
        self.pump(now=LATER)
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))
        self.assertEqual(len(self.notices()), 1)

    def test_a_tombstone_past_the_horizon_is_dropped_with_its_snapshot(self):
        self.placed()
        del self.port.entries[E1]
        self.pump(now=LATER)
        self.assertEqual(self.snapshots(), [E1])
        # The tombstone was written at the real clock: its age runs from there.
        written = datetime.now(timezone.utc)
        self.pump(now=written + timedelta(seconds=HORIZON - 60))
        self.assertEqual(self.state(E1), (ingress.COMPLETE, None), "dropped too early")
        self.pump(now=written + timedelta(seconds=HORIZON + 60))
        self.assertIsNone(self.state(E1))
        self.assertEqual(self.snapshots(), [])

    def test_a_held_record_is_never_dropped(self):
        self.port.entries[E1] = entry(E1, to=addr("charlie"))
        self.pump()
        del self.port.entries[E1]
        self.pump(now=MUCH_LATER + timedelta(seconds=HORIZON))
        self.assertEqual(self.state(E1), (ingress.HELD, "recipient_not_this_identity"))
        with self.assertRaises(ingress.JournalError):
            ingress.drop_tombstone(self.state_dir, self.lid, self.gen, "notice",
                                   ingress.key_for("notice", LINK, self.gen, E1))

    def test_a_quarantined_entry_follows_the_same_rule(self):
        self.port.entries[E1] = "notice_invalid"
        self.pump()
        del self.port.entries[E1]
        self.pump(now=LATER)
        self.assertEqual(self.state(E1), (ingress.QUARANTINED_COMPLETE, None))

    def test_an_old_first_seen_entry_warns_and_is_still_placed(self):
        old = "Mon, 01 Jan 2024 00:00:00 +0000"
        b = make(nid=E1, to=addr("bravo"))
        sp = json.loads(base64.b64decode(b["spool"]))
        sp["date"] = old
        b["spool"] = base64.b64encode(json.dumps(sp).encode()).decode()
        self.port.entries[E1] = enc(b)
        with self.assertLogs("amap_router_local.ingress", "WARNING") as logs:
            counts = self.pump()
        self.assertEqual(counts.get("hop_republished_after_horizon"), 1)
        self.assertIn("hop_republished_after_horizon", logs.output[0])
        self.assertEqual(len(self.notices()), 1)

    def test_a_recent_or_unparseable_date_does_not_warn(self):
        for date in ("garbage", ""):
            with self.subTest(date=date):
                eid = E2 if date else E3
                b = make(nid=eid, to=addr("bravo"))
                sp = json.loads(base64.b64decode(b["spool"]))
                sp["date"] = date
                b["spool"] = base64.b64encode(json.dumps(sp).encode()).decode()
                self.port.entries[eid] = enc(b)
                counts = self.pump()
                self.assertNotIn("hop_republished_after_horizon", counts)


class LateTests(_Pump):

    def test_an_entry_read_through_a_fenced_generation_is_late(self):
        old = self.mint()
        self.port.entries[E1] = entry(E1)
        self.pump(gen=old)
        (item,) = self.items(gen=old)
        self.assertEqual(item["cause"], "late_inbound")
        self.assertEqual(self.notices(), [])
        # Decided at dispatch (step 7), before anything was prepared: no
        # identity was minted. (place()'s own check would also quarantine,
        # but only after minting one.)
        st = ingress.journal_state(self.state_dir, self.lid, old, "notice", LINK, E1)
        self.assertIsNone(st["notice_id"])

    def test_refused_and_late_is_notice_invalid_e17_precedence(self):
        old = self.mint()
        self.port.entries[E1] = "notice_invalid"
        self.pump(gen=old)
        (item,) = self.items(gen=old)
        self.assertEqual(item["cause"], "notice_invalid")

    def test_a_held_entry_whose_generation_is_fenced_goes_late(self):
        self.port.entries[E1] = entry(E1, to=addr("charlie"))
        self.pump()
        self.assertEqual(self.state(E1), (ingress.HELD, "recipient_not_this_identity"))
        old = self.mint()
        self.pump(gen=old)
        (item,) = self.items(gen=old)
        self.assertEqual(item["cause"], "late_inbound")

    def test_a_proven_unknown_identity_is_late(self):
        self.port.entries[E1] = entry(E1)
        self.pump(recipient=None, proven_unknown=True)
        (item,) = self.items()
        self.assertEqual(item["cause"], "late_inbound")


class LinkTests(_Pump):

    def test_a_changed_link_after_placement_lists_nothing_and_places_nothing(self):
        def with_link(link):
            return SimpleNamespace(state_dir=self.state_dir, hop=SimpleNamespace(link=link))

        self.assertEqual(ingress.pump_link(with_link(LINK), self.lid, self.gen), LINK)
        self.port.entries[E1] = entry(E1)
        self.pump()
        self.assertEqual(len(self.notices()), 1)
        changed = with_link("link-b")
        with self.assertLogs("amap_router_local.ingress", "ERROR") as logs:
            self.assertIsNone(ingress.pump_link(changed, self.lid, self.gen))
        self.assertIsNone(ingress.pump_link(changed, self.lid, self.gen))
        self.assertEqual(len(logs.output), 1, "the ERROR is once per process")
        self.assertEqual(json.loads(ingress.link_pin_path(
            self.state_dir, self.lid, self.gen).read_bytes())["link"], LINK)

    def tearDown(self):
        ingress._LINK_LATCHED.clear()
        super().tearDown()


del _Fleet
