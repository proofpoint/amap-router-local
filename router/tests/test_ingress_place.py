"""Ingress placement: the RECORDED bytes, through `deliver`'s commit routine,
after the generation check, and the `placing` recovery table. AT MOST ONE
notice per upstream entry id: every crash witness below counts notices."""
from __future__ import annotations

import base64
import json
from unittest import mock

from router import attachments as attachments_mod, deliver as deliver_mod
from router import generations, ingress, quarantine
from router.tests.helpers import keyed_for_poll, list_notices
from router.tests.test_held_local import LIDS, _Fleet
from router.tests.test_ingress_bundle import CAP, enc, make

LINK = "link-a"
EID = "1700000000-42"


class _Placement(_Fleet):

    def setUp(self):
        super().setUp()
        self.poll()
        self.keyed = keyed_for_poll(self.cfg)
        self.lid = LIDS["bravo"]
        self.gen = generations.read_doc(self.state_dir, self.lid)["current"]

    # -- driving --------------------------------------------------------

    def prepared(self, blobs=(b"hello", b"world"), clean=True):
        parsed = ingress.parse_bundle(enc(make(blobs=blobs, clean=clean, nid=EID)), EID,
                                      attachment_cap=CAP)
        rec = ingress.prepare(self.keyed, self.state_dir, self.lid, self.gen, LINK, EID,
                              parsed, recipient="bravo")
        self.assertEqual(rec["state"], ingress.PREPARED)
        return rec

    def place(self):
        return ingress.place(self.keyed, self.state_dir, self.lid, self.gen, LINK, EID,
                             attachment_cap=CAP)

    def recover(self):
        return ingress.recover_placing(self.keyed, self.state_dir, self.lid, self.gen, LINK,
                                       EID, attachment_cap=CAP)

    def state(self):
        st = ingress.journal_state(self.state_dir, self.lid, self.gen, "notice", LINK, EID)
        return st and (st["state"], st["reason"])

    def notices(self):
        return list_notices(self.cfg, "bravo")

    def tree(self):
        return self.cfg.instances["bravo"].inbox_root

    def items(self, gen=None):
        return [i for i in ingress.quarantine_items(self.state_dir, self.lid, "bravo",
                                                    gen or self.gen, days=14)]

    def mint_generation(self):
        generations.operator_new(self.cfg, "bravo", "test: a new generation")
        self.keyed = keyed_for_poll(self.cfg)
        self.assertNotEqual(generations.read_doc(self.state_dir, self.lid)["current"],
                            self.gen, "control: a generation was minted")


class PlaceTests(_Placement):

    def test_the_recorded_bytes_are_placed_once(self):
        rec = self.prepared()
        self.assertEqual(self.place(), ingress.PUBLISHED_WAITING_REMOVE)
        nid = rec["notice_id"]
        self.assertEqual(self.notices(), [f"notice-{nid}.json"])
        notice_raw = (self.tree() / "notices" / f"notice-{nid}.json").read_bytes()
        self.assertEqual(ingress._part(notice_raw), rec["final"]["notice"])
        notice = json.loads(notice_raw)
        self.assertEqual(notice["notice_id"], nid)
        self.assertEqual(notice["message"]["mailbox"], "inbox")
        self.assertEqual([d["content_ref"] for d in notice["message"]["attachments"]],
                         [f"{nid}.attachments/0", f"{nid}.attachments/1"])
        side = self.tree() / "notices" / attachments_mod.sidecar_dir_name(nid)
        self.assertEqual((side / "0").read_bytes(), b"hello")
        self.assertEqual((side / "1").read_bytes(), b"world")
        self.assertEqual(self.state(), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_a_gap_keeps_every_later_index(self):
        rec = self.prepared(blobs=(b"x", b"y"), clean=(False, True))
        try:
            self.assertEqual(self.place(), ingress.PUBLISHED_WAITING_REMOVE)
        except Exception as e:  # noqa: BLE001
            self.fail(f"place raised {e!r}")
        side = self.tree() / "notices" / attachments_mod.sidecar_dir_name(rec["notice_id"])
        self.assertEqual(sorted(p.name for p in side.iterdir()), ["1"])
        self.assertEqual((side / "1").read_bytes(), b"y")

    def test_a_part_without_bytes_is_a_gap_never_a_renumbering(self):
        rec = self.prepared(blobs=(b"x",), clean=False)
        try:
            self.assertEqual(self.place(), ingress.PUBLISHED_WAITING_REMOVE)
        except Exception as e:  # noqa: BLE001
            self.fail(f"place raised {e!r}")
        side = self.tree() / "notices" / attachments_mod.sidecar_dir_name(rec["notice_id"])
        self.assertFalse(side.exists(), "a gap-only placement made a sidecar directory")

    def test_a_mint_between_prepared_and_placing_quarantines_to_the_old_generation(self):
        self.prepared()
        self.mint_generation()
        self.assertEqual(self.place(), ingress.QUARANTINED)
        self.assertEqual(self.notices(), [])
        (item,) = self.items()
        self.assertEqual((item["entry_id"], item["cause"]), (EID, "late_inbound"))
        self.assertEqual(self.state(), (ingress.QUARANTINED, "late_inbound"))

    def test_a_tampered_snapshot_holds_and_places_nothing(self):
        self.prepared()
        snap = ingress.snapshot_dir(self.state_dir, self.lid, self.gen, "notice",
                                    ingress.key_for("notice", LINK, self.gen, EID))
        (snap / "att-0").write_bytes(b"hellO")
        try:
            self.assertEqual(self.place(), ingress.HELD)
        except Exception as e:  # noqa: BLE001
            self.fail(f"place raised {e!r}")
        self.assertEqual(self.state(), (ingress.HELD, "snapshot_invalid:hash"))
        self.assertEqual(self.notices(), [])

    def test_a_held_recipient_gets_nothing_and_the_record_waits(self):
        self.prepared()
        self.hold("registry_unavailable", "bravo")
        held = keyed_for_poll(self.cfg)
        try:
            got = ingress.place(held, self.state_dir, self.lid, self.gen, LINK, EID,
                                attachment_cap=CAP)
        except Exception as e:  # noqa: BLE001
            self.fail(f"place raised {e!r} for a held recipient")
        self.assertIsNone(got)
        self.assertEqual(self.state(), (ingress.PREPARED, None))
        self.assertEqual(self.notices(), [])
        self.put()
        self.keyed = keyed_for_poll(self.cfg)
        self.assertEqual(self.place(), ingress.PUBLISHED_WAITING_REMOVE)
        self.assertEqual(len(self.notices()), 1)


class _Crash(Exception):
    pass


class RecoveryTests(_Placement):
    """A crash at each `_commit` step leaves the record in `placing`; the
    table then decides, and at most one notice is ever observed."""

    def crash_at(self, step):
        """Prepare, then place with the commit failing at `step`: "spool"
        (the first agent-visible write), "ledger", "notice" (the second
        agent-visible write) or "published" (the journal after the commit)."""
        self.prepared()
        real_wav = attachments_mod.write_agent_visible
        real_aw = deliver_mod.atomic_write
        real_write = ingress.write
        seen = {"wav": 0}

        def wav(root, path, data, **kw):
            seen["wav"] += 1
            if (step, seen["wav"]) in (("spool", 1), ("notice", 2)):
                raise _Crash(step)
            return real_wav(root, path, data, **kw)

        def aw(path, data, *a, **kw):
            if step == "ledger":
                raise _Crash(step)
            return real_aw(path, data, *a, **kw)

        def jw(*a, **kw):
            if step == "published" and a[6] == ingress.PUBLISHED:
                raise _Crash(step)
            return real_write(*a, **kw)

        with mock.patch.object(attachments_mod, "write_agent_visible", wav), \
                mock.patch.object(deliver_mod, "atomic_write", aw), \
                mock.patch.object(ingress, "write", jw):
            with self.assertRaises(_Crash):
                self.place()
        self.assertEqual(self.state(), (ingress.PLACING, None), "control: left in placing")

    def nid(self):
        return ingress.read(self.state_dir, self.lid, self.gen, "notice",
                            ingress.key_for("notice", LINK, self.gen, EID))["notice_id"]

    def ledger(self):
        from router import binding, config
        return binding.ledger_path(self.state_dir, "bravo", self.nid(),
                                   state_key=config.state_key(self.keyed, "bravo"))

    def test_row_2_before_the_spool_places_once_with_the_same_identity(self):
        self.crash_at("spool")
        nid = self.nid()
        self.assertEqual(self.notices(), [])
        self.assertEqual(self.recover(), ingress.PUBLISHED_WAITING_REMOVE)
        self.assertEqual(self.notices(), [f"notice-{nid}.json"])

    def test_row_2_before_the_ledger_places_once(self):
        self.crash_at("ledger")
        self.assertFalse(self.ledger().exists(), "control: no ledger row")
        self.assertEqual(self.recover(), ingress.PUBLISHED_WAITING_REMOVE)
        self.assertEqual(len(self.notices()), 1)

    def test_row_2_a_different_survivor_holds(self):
        self.crash_at("ledger")
        spool = self.tree() / "messages" / f"notice-{self.nid()}.json"
        spool.write_bytes(spool.read_bytes() + b" ")
        self.assertEqual(self.recover(), ingress.HELD)
        self.assertEqual(self.state(), (ingress.HELD, ingress.HELD_EXISTS_DIFFERENT))
        self.assertEqual(self.notices(), [])

    def test_row_2_after_a_mint_quarantines_late(self):
        self.crash_at("spool")
        self.mint_generation()
        self.assertEqual(self.recover(), ingress.QUARANTINED)
        self.assertEqual(self.notices(), [])
        self.assertEqual(len(self.items()), 1)

    def test_row_3_the_ledger_without_the_notice_is_ambiguous_and_terminal(self):
        self.crash_at("notice")
        self.assertTrue(self.ledger().exists(), "control: the ledger row is durable")
        self.assertEqual(self.recover(), ingress.HELD)
        self.assertEqual(self.state(), (ingress.HELD, ingress.HELD_PLACING_AMBIGUOUS))
        self.assertEqual(self.notices(), [])
        self.assertIn(ingress.HELD_PLACING_AMBIGUOUS, ingress.TERMINAL_HOLDS)
        # It never re-enters the table: the table refuses anything not placing.
        with self.assertRaises(ingress.JournalError):
            self.recover()

    def test_row_1_the_notice_present_publishes_without_placing_again(self):
        self.crash_at("published")
        self.assertEqual(len(self.notices()), 1, "control: the notice was committed")
        before = self.notices()
        with mock.patch.object(ingress, "_fsync_agent", wraps=ingress._fsync_agent) as fs:
            self.assertEqual(self.recover(), ingress.PUBLISHED_WAITING_REMOVE)
        self.assertEqual(self.notices(), before)
        self.assertEqual(fs.call_count, 1, "the surviving notice was not fsynced first")

    def test_row_1_a_consumed_notice_is_row_3(self):
        self.crash_at("published")
        (self.tree() / "notices" / self.notices()[0]).unlink()   # the consumer read it
        self.assertEqual(self.recover(), ingress.HELD)
        self.assertEqual(self.state(), (ingress.HELD, ingress.HELD_PLACING_AMBIGUOUS))
        self.assertEqual(self.notices(), [])

    def test_row_1_every_expected_part_is_required(self):
        for part in ("spool", "blob", "ledger"):
            with self.subTest(part=part):
                self.tearDown()
                self.setUp()
                self.crash_at("published")
                nid = self.nid()
                path = {"spool": self.tree() / "messages" / f"notice-{nid}.json",
                        "blob": self.tree() / "notices"
                        / attachments_mod.sidecar_dir_name(nid) / "1",
                        "ledger": self.ledger()}[part]
                path.unlink()
                self.assertEqual(self.recover(), ingress.HELD)
                self.assertEqual(self.state(), (ingress.HELD, ingress.HELD_SURVIVOR_MISMATCH))

    def test_the_generic_pending_replay_never_touches_an_ingress_record(self):
        from router import outbound
        self.crash_at("spool")
        key = ingress.key_for("notice", LINK, self.gen, EID)
        path = ingress.record_path(self.state_dir, self.lid, self.gen, "notice", key)
        before = path.read_bytes()
        self.poll()          # an ordinary poll: drains and the pending replay
        self.assertEqual(path.read_bytes(), before, "a poll moved an ingress record")
        self.assertEqual(self.notices(), [])
        self.assertEqual(outbound._pending_ids(keyed_for_poll(self.cfg), "bravo"), [])

    def test_row_1_a_corrupt_survivor_holds(self):
        self.crash_at("published")
        side = self.tree() / "notices" / attachments_mod.sidecar_dir_name(self.nid())
        (side / "0").write_bytes(b"hellO")
        self.assertEqual(self.recover(), ingress.HELD)
        self.assertEqual(self.state(), (ingress.HELD, ingress.HELD_SURVIVOR_MISMATCH))


del _Fleet
