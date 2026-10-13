"""The reply binding a mail placed from the external leg carries in its
ledger record (`binding.MAIL_ORIGIN_MEMBERS`, written by `ingress.prepare`):
exactly those members, the counterparty in its canonical form, `expires_at`
fixed when the entry is prepared, and no binding at all when the sender has
no canonical address. Also `mail_reply_window_seconds`' bounds."""
from __future__ import annotations

import unittest
from dataclasses import replace

from router import binding, ingress
from router import config as config_mod
from router.config import ConfigError
from router.tests import helpers
from router.tests.test_ingress_pump import E1, LINK, _Pump, entry
from router.util import parse_utc_ts


class MailBindingTests(_Pump):

    def placed_record(self, eid=E1):
        rec = ingress.journal_state(self.state_dir, self.lid, self.gen, "notice", LINK, eid)
        self.assertIsNotNone(rec, "not decided")
        full = ingress.read(self.state_dir, self.lid, self.gen, "notice",
                            ingress.key_for("notice", LINK, self.gen, eid))
        return binding.read_ledger_record(self.state_dir, "bravo", full["notice_id"],
                                          state_key=self.lid)

    def test_a_placed_mail_carries_exactly_the_binding(self):
        self.port.entries[E1] = entry(E1)
        self.pump()
        rec = self.placed_record()
        self.assertIsNotNone(rec, "no ledger record")
        self.assertTrue(set(binding.MAIL_ORIGIN_MEMBERS) <= set(rec))
        self.assertEqual(
            {k: rec[k] for k in binding.MAIL_ORIGIN_MEMBERS if k not in ("received_at",
                                                                         "expires_at")},
            {"agent": self.lid, "counterparty": "a@fleet-b.example",
             "origin_notice_id": E1, "origin_link": LINK, "origin_logical_id": self.lid,
             "origin_generation": self.gen, "admission": "fleet_hosts",
             "admission_link": LINK, "admission_rule": "fleet-hosts.v1"})
        self.assertEqual(rec["transport"], "hop")
        received, expires = parse_utc_ts(rec["received_at"]), parse_utc_ts(rec["expires_at"])
        self.assertEqual((expires - received).total_seconds(),
                         config_mod.MAIL_REPLY_WINDOW_SECONDS_DEFAULT)
        self.assertEqual(rec["received_at"], rec["ts"])

    def test_the_counterparty_is_canonical(self):
        notice_extra = {"message": {"id": "42", "from": "Someone <A.b@Fleet-B.Example>",
                                    "subject": "s", "preview": "b", "mailbox": "inbox",
                                    "provenance": "fleet-remote", "attachments": []}}
        self.port.entries[E1] = entry(E1, blobs=(), notice_extra=notice_extra)
        self.pump()
        rec = self.placed_record()
        self.assertEqual(rec["counterparty"], "A.b@fleet-b.example",
                         "the domain lowercased, the local part exact")

    def test_the_window_is_fixed_when_prepared(self):
        self.keyed = replace(self.keyed, mail_reply_window_seconds=3600)
        self.port.entries[E1] = entry(E1)
        self.pump()
        rec = self.placed_record()
        self.assertEqual((parse_utc_ts(rec["expires_at"])
                          - parse_utc_ts(rec["received_at"])).total_seconds(), 3600)

    def test_no_canonical_sender_means_no_binding(self):
        """A sender the From rule gives no canonical address: no binding, so
        the ledger record can never resolve as a reply across the leg."""
        parsed = {"notice": {"message": {"from": "nobody, no address"}},
                  "facts": {"notice_id": E1, "admission": "fleet_hosts",
                            "admission_link": LINK, "admission_rule": "r"}}
        self.assertIsNone(ingress.mail_origin(self.keyed, self.lid, self.gen, LINK, parsed,
                                              "2026-10-13T00:00:00Z"))
        parsed["notice"]["message"]["from"] = "Someone <a@fleet-b.example>"
        got = ingress.mail_origin(self.keyed, self.lid, self.gen, LINK, parsed,
                                  "2026-10-13T00:00:00Z")
        self.assertEqual(got["counterparty"], "a@fleet-b.example", "control: the twin binds")


class RecordDeliveryTests(unittest.TestCase):

    def test_mail_origin_is_exactly_its_members(self):
        base = dict(notice_id="n", from_instance=None, from_address="a@b.example",
                    to_instance="x", ts="2026-10-13T00:00:00Z", req_id="", message_id="m",
                    transport="hop")
        good = {k: "v" for k in binding.MAIL_ORIGIN_MEMBERS}
        binding.record_delivery(None, **base, mail_origin=good)
        for bad in (dict(good, extra="x"), {k: v for k, v in good.items() if k != "agent"}):
            with self.subTest(members=sorted(bad)):
                with self.assertRaises(ValueError):
                    binding.record_delivery(None, **base, mail_origin=bad)


class WindowConfigTests(helpers.RouterTestCase):

    def load(self, **top):
        root = self.tmp / "alice"
        root.mkdir(exist_ok=True)
        return config_mod.load_obj(dict({"state_dir": str(self.state_dir),
                                         "instances": {"alice": {"namespace": str(root)}}},
                                        **top))

    def test_the_default_and_the_bounds(self):
        self.assertEqual(self.load().mail_reply_window_seconds, 604800)
        self.assertEqual(self.load(mail_reply_window_seconds=7776000)
                         .mail_reply_window_seconds, 7776000)
        for bad in (0, -1, True, 1.5, 7776001):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError) as cm:
                    self.load(mail_reply_window_seconds=bad)
                self.assertIn("mail_reply_window_seconds", str(cm.exception))
