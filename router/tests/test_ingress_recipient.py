"""The plain-mail recipient cross-check: the tree binds a notice to L, and
mail whose named recipients (the spool's to and cc) resolve only to ANOTHER
identity is held, never retargeted. An address that resolves to nobody
neither binds nor refuses, so a Bcc'd recipient, a list delivery or a
truncated header is never held. With no valid registry reading there is no
decision."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from router import aliases, ingress
from router.config import AliasEntry

L = "a" * 32
M = "b" * 32
DOMAIN = "fleet.example"
OLD = "old-alpha@fleet.example"


def cfg(decision=None):
    view = None
    if decision is not None:
        view = aliases.AliasView("ok", decisions={OLD: decision})
    return SimpleNamespace(fleet_domain=DOMAIN, instances={"alpha": 1, "bravo": 2},
                           aliases=(AliasEntry(OLD, f"alpha@{DOMAIN}",
                                               "2027-01-01T00:00:00Z"),),
                           alias_view=view)


REPORT = SimpleNamespace(state="ok", known={"alpha": L, "bravo": M})


class RecipientTests(unittest.TestCase):

    def to(self, to, cc=None, c=None, report=REPORT):
        spool = {"to": to}
        if cc is not None:
            spool["cc"] = cc
        return ingress.addressed_to(c or cfg(), report, L, spool)

    def test_addressed_to_l(self):
        self.assertIs(self.to(f"alpha@{DOMAIN}"), True)
        self.assertIs(self.to(f"Alpha <ALPHA@{DOMAIN}>"), True)

    def test_l_among_others_in_to_or_cc(self):
        self.assertIs(self.to(f"bravo@{DOMAIN}, alpha@{DOMAIN}"), True)
        self.assertIs(self.to(f"bravo@{DOMAIN}", cc=f"\"Doe, J\" <alpha@{DOMAIN}>"), True)

    def test_mail_addressed_only_to_another_identity_is_held(self):
        self.assertIs(self.to(f"bravo@{DOMAIN}"), False)
        self.assertIs(self.to("x@outside.example", cc=f"bravo@{DOMAIN}"), False)

    def test_a_bcc_d_or_list_delivered_recipient_is_not_held(self):
        # Named in neither header: the tree it was delivered to binds it.
        self.assertIs(self.to("list@outside.example"), True)
        self.assertIs(self.to(""), True)
        self.assertIs(ingress.addressed_to(cfg(), REPORT, L, {}), True)

    def test_a_truncated_header_is_not_held(self):
        long_to = ", ".join(f"p{i}@outside.example" for i in range(40))[:500]
        self.assertIs(self.to(long_to), True)
        # Even when the cut leaves a fragment of another fleet address.
        self.assertIs(self.to(f"x@outside.example, bravo@{DOMAIN[:4]}"), True)

    def test_an_active_alias_of_l(self):
        active = aliases.Decision(aliases.ACTIVE, target="alpha")
        self.assertIs(self.to(OLD, c=cfg(active)), True)

    def test_an_inactive_or_undecided_alias_resolves_to_nobody(self):
        for d in (aliases.Decision(aliases.INACTIVE, reason="expired"),
                  aliases.Decision(aliases.UNVERIFIABLE, reason="x"), None):
            with self.subTest(d=d):
                self.assertIs(self.to(OLD, c=cfg(d)), True)

    def test_an_active_alias_of_another_identity_is_held(self):
        other = aliases.Decision(aliases.ACTIVE, target="bravo")
        self.assertIs(self.to(OLD, c=cfg(other)), False)

    def test_the_case_rule(self):
        # By name: domain and local part both case-insensitive.
        self.assertIs(self.to("BRAVO@FLEET.EXAMPLE"), False)
        self.assertIs(self.to("bravo@Fleet.Example"), False)
        # Through an alias: the local part exact, the domain case-insensitive.
        other = aliases.Decision(aliases.ACTIVE, target="bravo")
        self.assertIs(self.to("old-alpha@FLEET.EXAMPLE", c=cfg(other)), False)
        self.assertIs(self.to("Old-Alpha@fleet.example", c=cfg(other)), True)

    def test_a_rename_reaches_l_through_an_active_alias_and_otherwise_the_tree(self):
        # The registry renamed L from old-alpha to alpha; mail still names
        # the old address. With the alias active it resolves to L; without
        # one it resolves to nobody, and the tree binds it.
        self.assertIs(self.to(OLD, c=cfg(aliases.Decision(aliases.ACTIVE, target="alpha"))),
                      True)
        self.assertIs(self.to(OLD, c=cfg(None)), True)

    def test_no_valid_registry_reading_is_no_decision(self):
        for state in ("unavailable", "rolled_back", "off"):
            with self.subTest(state=state):
                self.assertIsNone(self.to(f"alpha@{DOMAIN}",
                                          report=SimpleNamespace(state=state, known={})))


if __name__ == "__main__":
    unittest.main()
