"""The §7.2 order and A5 admission over the facts: first match wins, one
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

    def outcome(self, doc):
        try:
            return ingress.classify_facts(doc, link=LINK, fleet_hosts=FLEET,
                                          trusted_fleet_hosts=TRUSTED)
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

    def test_row_1_a_failure_notice_is_held(self):
        self.assertEqual(self.outcome(facts(notice_class="failure_notice")),
                         (ingress.HOLD, ingress.HELD_FAILURE_NOTICE))

    def test_row_2_a_bound_reply_is_held(self):
        self.assertEqual(self.outcome(facts(in_reply_to={"message_id": "<a@b>"})),
                         (ingress.HOLD, ingress.HELD_BOUND_REPLY))

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

    def test_open_admission_from_a_fleet_origin_is_row_3(self):
        self.assertEqual(self.outcome(facts(admission="open", origin_host=None,
                                            admission_link="link-b")),
                         (ingress.HOLD, ingress.HELD_NOT_PLACEABLE))

    def test_a_bound_reply_from_a_trusted_host_is_row_2(self):
        self.assertEqual(self.outcome(facts(origin_host="fleet-a.example",
                                            in_reply_to={"message_id": "<a@b>"})),
                         (ingress.HOLD, ingress.HELD_BOUND_REPLY))

    def test_a_failure_notice_is_row_1_whatever_else_it_says(self):
        self.assertEqual(self.outcome(facts(notice_class="failure_notice",
                                            origin_host="fleet-a.example")),
                         (ingress.HOLD, ingress.HELD_FAILURE_NOTICE))

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
