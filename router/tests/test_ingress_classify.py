"""The §7.2 order and admission over the facts: first match wins, one
outcome per facts document, and a value outside the enums is notice_invalid,
never a row. Untrusted fleet mail is the only placeable class."""
from __future__ import annotations

import unittest

from router import ingress

LINK = "link-a"
FLEET = ("fleet-a.example", "fleet-b.example")
TRUSTED = ("fleet-a.example",)


def facts(**kw):
    doc = {"notice_class": "mail", "ingress": "hub", "admission": "fleet_hosts",
           "admission_link": LINK, "admission_rule": "rule-1",
           "origin_host": "fleet-b.example"}
    for k, v in kw.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


class ClassifyTests(unittest.TestCase):

    def outcome(self, doc, **kw):
        try:
            return ingress.classify_facts(doc, link=LINK, fleet_hosts=FLEET,
                                          trusted_fleet_hosts=TRUSTED, **kw)
        except ingress.FactsInvalid as e:
            self.fail(f"refused as invalid: {e}")

    def invalid(self, doc):
        with self.assertRaises(Exception) as cm:
            ingress.classify_facts(doc, link=LINK, fleet_hosts=FLEET,
                                   trusted_fleet_hosts=TRUSTED)
        self.assertIsInstance(cm.exception, ingress.FactsInvalid)

    # -- one witness per row ---------------------------------------------

    def test_row_8_untrusted_fleet_mail_is_placed(self):
        self.assertEqual(self.outcome(facts()), (ingress.PLACE, None))

    def test_row_1_a_failure_notice_goes_to_the_matcher(self):
        self.assertEqual(self.outcome(facts(notice_class="failure_notice")),
                         (ingress.FAILURE, None))

    def test_row_2_a_reply_goes_to_the_matcher(self):
        self.assertEqual(self.outcome(facts(in_reply_to={"message_id": "<a@b>"})),
                         (ingress.REPLY, None))

    def test_an_unmatched_reply_is_classified_as_mail_without_one(self):
        irt = {"message_id": "<a@b>"}
        for kw, want in (({}, (ingress.PLACE, None)),
                         ({"origin_host": "fleet-a.example"},
                          (ingress.QUARANTINE, "cold_fleet_mail")),
                         ({"admission": "open", "origin_host": None},
                          (ingress.HOLD, ingress.HELD_NOT_PLACEABLE))):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                self.assertEqual(self.outcome(facts(in_reply_to=irt, **kw),
                                              reply_unmatched=True), want)

    def test_row_3_open_admission_is_not_placeable(self):
        self.assertEqual(self.outcome(facts(admission="open", origin_host=None)),
                         (ingress.HOLD, ingress.HELD_NOT_PLACEABLE))

    def test_row_5_another_link_is_a_mismatch(self):
        self.assertEqual(self.outcome(facts(admission_link="link-b")),
                         (ingress.HOLD, ingress.HELD_LINK_MISMATCH))

    def test_row_6_a_trusted_host_is_quarantined_cold(self):
        self.assertEqual(self.outcome(facts(origin_host="fleet-a.example")),
                         (ingress.QUARANTINE, "cold_fleet_mail"))

    def test_row_7_an_unknown_host_is_held(self):
        self.assertEqual(self.outcome(facts(origin_host="elsewhere.example")),
                         (ingress.HOLD, ingress.HELD_UNKNOWN_HOST))

    # -- the former overlaps: first match wins ---------------------------

    def test_trusted_with_the_wrong_link_is_row_5_not_cold(self):
        self.assertEqual(self.outcome(facts(origin_host="fleet-a.example",
                                            admission_link="link-b")),
                         (ingress.HOLD, ingress.HELD_LINK_MISMATCH))

    def test_the_link_integrity_row_comes_before_open_admission(self):
        self.assertEqual(self.outcome(facts(admission="open", origin_host=None,
                                            admission_link="link-b")),
                         (ingress.HOLD, ingress.HELD_LINK_MISMATCH))

    def test_a_reply_pre_empts_only_the_cold_rows(self):
        self.assertEqual(self.outcome(facts(origin_host="fleet-a.example",
                                            in_reply_to={"message_id": "<a@b>"})),
                         (ingress.REPLY, None), "row 6 (cold) is pre-empted")
        self.assertEqual(self.outcome(facts(admission="open", origin_host=None,
                                            in_reply_to={"message_id": "<a@b>"})),
                         (ingress.REPLY, None), "row 3 (cold) is pre-empted")
        self.assertEqual(self.outcome(facts(in_reply_to={"message_id": "<a@b>"},
                                            admission_link="link-b")),
                         (ingress.HOLD, ingress.HELD_LINK_MISMATCH),
                         "the link integrity row is NOT pre-empted")

    def test_a_failure_notice_pre_empts_only_the_cold_rows(self):
        self.assertEqual(self.outcome(facts(notice_class="failure_notice",
                                            origin_host="fleet-a.example")),
                         (ingress.FAILURE, None))
        self.assertEqual(self.outcome(facts(notice_class="failure_notice",
                                            origin_host="elsewhere.example")),
                         (ingress.FAILURE, None), "row 7 (cold) is pre-empted")
        self.assertEqual(self.outcome(facts(notice_class="failure_notice",
                                            admission_link="link-b")),
                         (ingress.HOLD, ingress.HELD_LINK_MISMATCH),
                         "the link integrity row is NOT pre-empted")

    # -- outside the enums: notice_invalid, never a row -----------------

    def test_values_outside_the_enums_are_invalid(self):
        for doc in (facts(notice_class="other"), facts(admission="other"),
                    facts(admission="inbound_allowlist", origin_host=None),
                    facts(ingress="internet"), facts(ingress=None),
                    facts(admission_link=""), facts(admission_rule=None),
                    facts(origin_host="Fleet-B.example"), facts(origin_host=None),
                    facts(origin_host="not a host")):
            with self.subTest(doc=doc):
                self.invalid(doc)

    def test_non_hub_ingress_is_invalid_while_the_enum_is_hub_only(self):
        # The frozen "non-hub ingress with a trusted origin gives row 4"
        # witness cannot hold under the codec's enum: such facts are refused
        # first, as the plugin's reader refuses them.
        self.invalid(facts(ingress="internet", origin_host="fleet-a.example"))


if __name__ == "__main__":
    unittest.main()
