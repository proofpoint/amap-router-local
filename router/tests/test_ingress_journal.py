"""`router/ingress.py`'s journal core: keying per kind, the forward-only state
machine, durable records, and damage that is never read as absent."""
from __future__ import annotations

import json
import os
import stat

from router import ingress
from router.tests import helpers

LID = "a1" * 16
GEN = "b2" * 16
LINK = "hop1"


class _J(helpers.RouterTestCase):

    def write(self, state, entry_id="n-1", kind="notice", **kw):
        return ingress.write(self.state_dir, LID, GEN, kind, LINK, entry_id, state, **kw)

    def read(self, entry_id="n-1", kind="notice"):
        return ingress.read(self.state_dir, LID, GEN, kind,
                            ingress.key_for(kind, LINK, GEN, entry_id))

    def path(self, entry_id="n-1", kind="notice"):
        return ingress.record_path(self.state_dir, LID, GEN, kind,
                                   ingress.key_for(kind, LINK, GEN, entry_id))


class KeyTests(_J):

    def test_the_same_id_in_two_kinds_is_two_records(self):
        k_notice = ingress.key_for("notice", LINK, GEN, "x1")
        k_cand = ingress.key_for("candidate", LINK, GEN, "x1")
        self.assertNotEqual(k_notice, k_cand)
        self.write(ingress.HELD, "x1", kind="notice", reason="r")
        self.assertIsNone(self.read("x1", kind="candidate"), "a notice record read as a candidate's")

    def test_every_identity_member_changes_the_key(self):
        base = ingress.key_for("notice", LINK, GEN, "x1")
        self.assertNotEqual(base, ingress.key_for("notice", "hop2", GEN, "x1"))
        self.assertNotEqual(base, ingress.key_for("notice", LINK, "c3" * 16, "x1"))
        self.assertNotEqual(base, ingress.key_for("notice", LINK, GEN, "x2"))

    def test_the_id_is_never_a_path_component(self):
        hostile = "../../etc/passwd"
        self.write(ingress.HELD, hostile, reason="r")
        p = self.path(hostile)
        self.assertEqual(p.parent, ingress.kind_dir(self.state_dir, LID, GEN, "notice"))
        self.assertRegex(p.name, r"\A[0-9a-f]{64}\.json\Z")

    def test_bad_identities_are_refused(self):
        for args in (("nope", LINK, GEN, "x"), ("notice", "", GEN, "x"),
                     ("notice", LINK, "G" * 32, "x"), ("notice", LINK, GEN, "")):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    ingress.key_for(*args)


class StateMachineTests(_J):

    def test_the_placed_path_moves_forward(self):
        for s in (ingress.PREPARED, ingress.PLACING, ingress.PUBLISHED,
                  ingress.PUBLISHED_WAITING_REMOVE, ingress.COMPLETE):
            self.write(s)
            self.assertEqual(self.read()["state"], s)

    def test_the_quarantined_path_moves_forward(self):
        for s in (ingress.QUARANTINED, ingress.QUARANTINED_WAITING_REMOVE,
                  ingress.QUARANTINED_COMPLETE):
            self.write(s)
        self.assertEqual(self.read()["state"], ingress.QUARANTINED_COMPLETE)

    def test_a_new_record_starts_only_in_an_initial_state(self):
        for s in ingress.STATES:
            with self.subTest(state=s):
                eid = f"new-{s}"
                if s in ingress.INITIAL:
                    self.write(s, eid)
                    self.assertEqual(self.read(eid)["state"], s)
                else:
                    with self.assertRaises(ingress.JournalError):
                        self.write(s, eid)
                    self.assertFalse(self.path(eid).exists(), "written despite the refusal")

    def test_every_move_the_table_does_not_allow_is_refused_and_writes_nothing(self):
        reach = {  # how to reach each state from nothing
            ingress.HELD: [ingress.HELD],
            ingress.PREPARED: [ingress.PREPARED],
            ingress.PLACING: [ingress.PREPARED, ingress.PLACING],
            ingress.PUBLISHED: [ingress.PREPARED, ingress.PLACING, ingress.PUBLISHED],
            ingress.PUBLISHED_WAITING_REMOVE: [ingress.PREPARED, ingress.PLACING, ingress.PUBLISHED,
                                               ingress.PUBLISHED_WAITING_REMOVE],
            ingress.COMPLETE: [ingress.PREPARED, ingress.PLACING, ingress.PUBLISHED,
                               ingress.PUBLISHED_WAITING_REMOVE, ingress.COMPLETE],
            ingress.QUARANTINED: [ingress.QUARANTINED],
            ingress.QUARANTINED_WAITING_REMOVE: [ingress.QUARANTINED,
                                                 ingress.QUARANTINED_WAITING_REMOVE],
            ingress.QUARANTINED_COMPLETE: [ingress.QUARANTINED, ingress.QUARANTINED_WAITING_REMOVE,
                                           ingress.QUARANTINED_COMPLETE],
            ingress.DUPLICATE_DIFFERENT_HELD: [ingress.QUARANTINED, ingress.QUARANTINED_WAITING_REMOVE,
                                               ingress.QUARANTINED_COMPLETE,
                                               ingress.DUPLICATE_DIFFERENT_HELD],
        }
        self.assertEqual(set(reach), set(ingress.STATES))
        refused = 0
        for src, path in reach.items():
            for dst in ingress.STATES:
                if dst in ingress.TRANSITIONS[src]:
                    continue
                with self.subTest(src=src, dst=dst):
                    eid = f"{src}->{dst}"
                    for s in path:
                        self.write(s, eid)
                    before = self.path(eid).read_bytes()
                    with self.assertRaises(ingress.JournalError):
                        self.write(dst, eid)
                    self.assertEqual(self.path(eid).read_bytes(), before, "written despite the refusal")
                    refused += 1
        self.assertGreater(refused, 50, "control: the refusals were exercised")

    def test_members_carry_forward_and_first_seen_never_moves(self):
        first = self.write(ingress.PREPARED, notice_id="n" * 32, snapshot={"sha256": "a" * 64})
        later = self.write(ingress.PLACING)
        self.assertEqual(later["notice_id"], "n" * 32)
        self.assertEqual(later["snapshot"], {"sha256": "a" * 64})
        self.assertEqual(later["first_seen_ts"], first["first_seen_ts"])

    def test_reserved_members_cannot_be_overridden(self):
        with self.assertRaises(ValueError):
            self.write(ingress.HELD, state_ts="x")


class DurabilityAndDamageTests(_J):

    def test_records_are_private(self):
        self.write(ingress.HELD, reason="r")
        self.assertEqual(stat.S_IMODE(os.stat(self.path()).st_mode), 0o600)

    def test_damage_is_never_read_as_absent(self):
        self.write(ingress.HELD, reason="r")
        p = self.path()
        cases = {
            "not json": lambda: p.write_text("{damaged"),
            "wrong schema": lambda: p.write_text(json.dumps({"schema": "x"})),
            "over the cap": lambda: p.write_bytes(b" " * (ingress.RECORD_MAX + 1)),
        }
        for why, make in cases.items():
            with self.subTest(why=why):
                make()
                with self.assertRaises(ingress.JournalError):
                    self.read()
        p.unlink()
        os.symlink("/etc/hostname", p)
        with self.assertRaises(ingress.JournalError):
            self.read()

    def test_a_record_moved_under_another_key_is_refused(self):
        self.write(ingress.HELD, "a", reason="r")
        self.write(ingress.HELD, "b", reason="r")
        os.replace(self.path("a"), self.path("b"))
        with self.assertRaises(ingress.JournalError):
            self.read("b")

    def test_the_probe(self):
        self.assertIsNone(ingress.journal_state(self.state_dir, LID, GEN, "notice", LINK, "n-1"))
        self.write(ingress.PREPARED, notice_id="n" * 32)
        self.assertEqual(ingress.journal_state(self.state_dir, LID, GEN, "notice", LINK, "n-1"),
                         {"state": "prepared", "reason": None, "notice_id": "n" * 32})


if __name__ == "__main__":
    import unittest
    unittest.main()
