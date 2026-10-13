"""`ingress.check_facts`: this router's additional strict check over the
facts, verdict-identical with the plugin's reader (member names and
grammars only). One witness per rule, each beside the valid twin it is
measured against; every refusal is FactsInvalid (notice_invalid).

VERDICT IDENTITY, and where it is measured. Run offline over the codec
owner's facts-version-2 corpus at its merged head, this check agreed on
valid-versus-refused in every case but one, which does not apply here (a
read without the spool; this router always reads it). Recorded beside it,
so neither reads as a gap:

  * version-1 facts CARRYING `attachments` are refused here at the
    version guard and there at the version-1 closed schema: the same
    verdict, no difference.
  * a spool that is not JSON or not an object, and a present null
    `attachments` on the notice or the spool, are refused here at the
    BUNDLE layer (`bundle_invalid`, a re-read hold) where the plugin's
    reader says notice_invalid. The reader refuses such a bundle first, so
    this router never sees one; the difference is of layer, not of
    outcome reaching an agent.

The corpus rows themselves stay PENDING to the fixture upgrade; nothing of
the private corpus is copied into this repository."""
from __future__ import annotations

import base64
import copy
import json
import unittest

from router import ingress
from router.tests.test_ingress_bundle import CAP, NID, enc, make

TX = {"link": "link-a", "logical_id": "a" * 32, "generation": "b" * 32, "n": "00000005"}


def parsed(*, facts=None, notice=None, raw_facts=None, spool=None, **kw):
    """A parsed bundle. `facts(f)` and `notice(n)` edit the documents in
    place; `raw_facts` replaces the facts bytes outright."""
    b = make(facts_extra=(lambda f: (facts(f), f)[1]) if facts else None, **kw)
    if notice:
        n = json.loads(base64.b64decode(b["notice"]))
        notice(n)
        b["notice"] = base64.b64encode(json.dumps(n).encode()).decode()
    if spool:
        sp = json.loads(base64.b64decode(b["spool"]))
        spool(sp)
        b["spool"] = base64.b64encode(json.dumps(sp).encode()).decode()
    if raw_facts is not None:
        b["hop"] = base64.b64encode(raw_facts).decode()
    return ingress.parse_bundle(enc(b), NID, attachment_cap=CAP)


def v1(f):
    del f["facts_version"], f["attachments"]


def openly(f):
    f["admission"] = "open"
    del f["origin_host"]


def failure(f):
    f["notice_class"] = "failure_notice"
    f["failure"] = {"transaction": dict(TX), "correlated_by": "envid",
                    "reports": [{"recipient": "x@y.example", "action": "failed",
                                 "status": "5.1.1"}]}


def reply(f):
    f["in_reply_to"] = {"message_id": "<a.b@c.d>", "transaction": dict(TX)}


class FactsCheckTests(unittest.TestCase):

    def ok(self, p, version=2):
        try:
            self.assertEqual(ingress.check_facts(p), version)
        except ingress.FactsInvalid as e:
            self.fail(f"refused: {e}")

    def bad(self, p):
        with self.assertRaises(Exception) as cm:
            ingress.check_facts(p)
        self.assertIsInstance(cm.exception, ingress.FactsInvalid, str(cm.exception))

    # -- the valid twins ---------------------------------------------------

    def test_valid_twins(self):
        self.ok(parsed())
        self.ok(parsed(blobs=()))
        self.ok(parsed(facts=v1, blobs=()), version=1)
        self.ok(parsed(facts=lambda f: (openly(f)), notice=lambda n: n["message"].update(
            provenance="unverified")))
        self.ok(parsed(facts=failure))
        self.ok(parsed(facts=reply))
        self.ok(parsed(blobs=(b"a", b"b"), clean=(False, True)))

    # -- parse and members -------------------------------------------------

    def test_the_bytes_must_be_canonical(self):
        good = parsed()
        raw = json.dumps(good["facts"], indent=1).encode()
        self.bad(parsed(raw_facts=raw))
        dup = good["raw"]["facts"][:-1] + b',"admission":"open"}'
        self.bad(parsed(raw_facts=dup))   # a duplicate key never re-encodes to itself

    def test_closed_at_every_level(self):
        self.bad(parsed(facts=lambda f: f.update(extra=1)))
        self.bad(parsed(facts=lambda f: (reply(f), f["in_reply_to"].update(x=1))))
        self.bad(parsed(facts=lambda f: (reply(f), f["in_reply_to"]["transaction"]
                                         .update(x=1))))
        self.bad(parsed(facts=lambda f: (failure(f), f["failure"].update(x=1))))
        self.bad(parsed(facts=lambda f: (failure(f), f["failure"]["reports"][0]
                                         .update(x=1))))
        self.bad(parsed(facts=lambda f: f["attachments"][0].update(x=1)))

    def test_each_required_member(self):
        for member in ("hop_contract", "notice_id", "notice_class", "ingress", "admission",
                       "admission_link", "admission_rule", "attachments"):
            with self.subTest(member=member):
                self.bad(parsed(facts=lambda f, m=member: f.pop(m)))

    # -- grammars and enums ------------------------------------------------

    def test_hop_contract_is_an_integer_token_in_range(self):
        for v in (0, -1, 2 ** 31, True, "1"):
            with self.subTest(v=v):
                self.bad(parsed(facts=lambda f, v=v: f.update(hop_contract=v),
                                notice=lambda n, v=v: n.update(hop_contract=v)))
        # True beside the notice's integer 1: only the type check refuses it
        # (the hop_contract pair rule compares equal, True == 1).
        self.bad(parsed(facts=lambda f: f.update(hop_contract=True)))

    def test_grammars(self):
        for member, v in (("admission_link", "Link-A"), ("admission_link", "a" * 64),
                          ("admission_rule", "Rule"), ("admission_rule", "r" * 129),
                          ("notice_id", "n" * 129)):
            with self.subTest(member=member, v=v):
                self.bad(parsed(facts=lambda f, m=member, v=v: f.update({m: v})))

    def test_origin_host(self):
        for v in ("fleet", "Fleet-b.example", "-a.example", "a-.example",
                  "a." + "b" * 64 + ".example", "x.hosts.internal", ("a" * 60 + ".") * 5):
            with self.subTest(v=v):
                self.bad(parsed(facts=lambda f, v=v: f.update(origin_host=v),
                                notice=lambda n, v=v: n["message"].update(
                                    **{"from": f"a@{v}"})))

    def test_conditionals(self):
        self.bad(parsed(facts=lambda f: f.pop("origin_host")))
        self.bad(parsed(facts=lambda f: (openly(f), f.update(origin_host="fleet-b.example")),
                        notice=lambda n: n["message"].update(provenance="unverified")))
        self.bad(parsed(facts=lambda f: (failure(f), reply(f))))
        self.bad(parsed(facts=lambda f: f.update(failure={})))
        self.bad(parsed(facts=lambda f: (failure(f), f.pop("failure"))))

    def test_in_reply_to_grammar(self):
        for mid in ("a@b", "<a@b", "<\"q\"@b>", "<a@[1.2.3.4]>", "<" + "a" * 250 + "@b>",
                    "<a..b@c>"):
            with self.subTest(mid=mid):
                self.bad(parsed(facts=lambda f, mid=mid: (
                    reply(f), f["in_reply_to"].update(message_id=mid))))
        for k, v in (("n", "1234567"), ("n", "1" * 19), ("logical_id", "A" * 32),
                     ("link", "Hub")):
            with self.subTest(k=k, v=v):
                self.bad(parsed(facts=lambda f, k=k, v=v: (
                    reply(f), f["in_reply_to"]["transaction"].update({k: v}))))

    def test_failure_reports(self):
        def edit(fn):
            return parsed(facts=lambda f: (failure(f), fn(f["failure"])))
        self.bad(edit(lambda fl: fl.update(reports=[])))
        self.bad(edit(lambda fl: fl.update(reports=[
            {"recipient": f"r{i}@y.example", "action": "failed", "status": "5.1.1"}
            for i in range(101)])))
        self.bad(edit(lambda fl: fl["reports"].append(copy.deepcopy(fl["reports"][0]))))
        self.bad(edit(lambda fl: fl.update(correlated_by="other")))
        for action, status in (("delivered", "5.1.1"), ("failed", "4.1.1"),
                               ("delayed", "5.1.1"), ("failed", "5.1.5"),
                               ("failed", "2.0.0"), ("failed", "5.7.26")):
            with self.subTest(action=action, status=status):
                self.bad(edit(lambda fl, a=action, s=status: fl["reports"][0].update(
                    action=a, status=s)))
        self.bad(edit(lambda fl: fl["reports"][0].update(recipient="r" * 250 + "@y.ex")))
        self.ok(edit(lambda fl: fl["reports"][0].update(action="delayed", status="4.7.7")))

    def test_the_status_table_has_ninety_six_codes(self):
        self.assertEqual(len(ingress.STATUSES), 96)
        self.assertNotIn("5.1.5", ingress.STATUSES)
        self.assertIn("4.7.7", ingress.STATUSES)

    # -- the pair rules ----------------------------------------------------

    def test_pair_notice_id(self):
        self.bad(parsed(facts=lambda f: f.update(notice_id="1700000000-43")))

    def test_pair_hop_contract(self):
        self.bad(parsed(notice=lambda n: n.pop("hop_contract")))
        self.bad(parsed(notice=lambda n: n.update(hop_contract=2)))
        self.bad(parsed(notice=lambda n: n.update(hop_contract=True),
                        facts=lambda f: f.update(hop_contract=1)))

    def test_pair_provenance(self):
        for prov in (None, "internal", "external", "unverified"):
            with self.subTest(prov=prov):
                self.bad(parsed(notice=lambda n, p=prov: (
                    n["message"].pop("provenance") if p is None
                    else n["message"].update(provenance=p))))
        self.bad(parsed(facts=openly))   # fleet-remote under open

    def test_pair_from_domain(self):
        for frm in ("a@other.example", "a@fleet-b.example ", "<a@fleet-b.example> x",
                    "nobody"):
            with self.subTest(frm=frm):
                self.bad(parsed(notice=lambda n, v=frm: n["message"].update(**{"from": v})))
        for frm in ("a@FLEET-B.example", "Name <x@fleet-b.example>", "a@fleet-b.example"):
            with self.subTest(frm=frm):
                self.ok(parsed(notice=lambda n, v=frm: n["message"].update(**{"from": v})))

    def test_the_from_domain_reads_only_the_last_at(self):
        self.assertEqual(ingress.domain_of("a@b@Fleet.Example"), "fleet.example")
        self.assertIsNone(ingress.domain_of(ingress.addr_of("x <a@b>y")))

    def test_attachment_alignment_at_version_2(self):
        self.bad(parsed(facts=lambda f: f["attachments"].append(
            {"source_sha256": "c" * 64, "size_bytes": 1})))
        # An extra row the SPOOL agrees with: only the notice count refuses it.
        self.bad(parsed(facts=lambda f: f["attachments"].append(
            {"source_sha256": "c" * 64, "size_bytes": 1}),
            spool=lambda sp: sp["attachments"].append(
                {"filename": "x", "media_type": "text/plain", "size_bytes": 1,
                 "disposition": "stripped"})))
        self.bad(parsed(facts=lambda f: f["attachments"][0].update(size_bytes=99)))
        self.bad(parsed(facts=lambda f: f["attachments"][0].update(source_sha256="c" * 64)))
        self.bad(parsed(spool=lambda sp: sp.pop("attachments")))
        self.bad(parsed(facts=lambda f: f.update(attachments=None)))
        # A present null on the notice or the spool: refused, never a crash
        # (the codec owner's p5-*-attachments-null cases).
        p = parsed()
        p["notice"]["message"]["attachments"] = None
        self.bad(p)
        p = parsed()
        p["spool"]["attachments"] = None
        self.bad(p)
        # The digest is aligned only where the descriptor carries sha256: a stripped part is
        # aligned by size alone.
        self.ok(parsed(clean=False, facts=lambda f: f["attachments"][0].update(
            source_sha256="c" * 64)))


if __name__ == "__main__":
    unittest.main()
