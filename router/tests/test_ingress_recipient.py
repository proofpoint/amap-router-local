"""The plain-mail recipient binding: a notice read from L's tree is for L
only if a named recipient (the spool's to or cc) resolves to L, by name or
through an alias active this poll. Otherwise it is held, never retargeted;
with no valid registry reading there is no decision."""
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

    def test_mail_addressed_only_to_another_agent_is_not_for_l(self):
        self.assertIs(self.to(f"bravo@{DOMAIN}"), False)
        self.assertIs(self.to(f"alpha@other.example"), False)
        self.assertIs(self.to(""), False)

    def test_an_active_alias_of_l(self):
        active = aliases.Decision(aliases.ACTIVE, target="alpha")
        self.assertIs(self.to(OLD, c=cfg(active)), True)

    def test_an_inactive_or_undecided_alias_is_not_l(self):
        for d in (aliases.Decision(aliases.INACTIVE, reason="expired"),
                  aliases.Decision(aliases.UNVERIFIABLE, reason="x"), None):
            with self.subTest(d=d):
                self.assertIs(self.to(OLD, c=cfg(d)), False)

    def test_an_active_alias_of_another_identity_is_not_l(self):
        other = aliases.Decision(aliases.ACTIVE, target="bravo")
        self.assertIs(self.to(OLD, c=cfg(other)), False)

    def test_no_valid_registry_reading_is_no_decision(self):
        for state in ("unavailable", "rolled_back", "off"):
            with self.subTest(state=state):
                self.assertIsNone(self.to(f"alpha@{DOMAIN}",
                                          report=SimpleNamespace(state=state, known={})))


if __name__ == "__main__":
    unittest.main()
