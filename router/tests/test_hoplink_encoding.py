"""`router/hoplink.py`'s encoding half: the canonical encoder, the
begin-time checks, the exact attachment-array maximum and the document
floor, each against a witness that would fail if the rule were off by one.
"""
from __future__ import annotations

import base64
import itertools
import math
import unittest

from router import config as config_mod
from router import hoplink
from router.config import ConfigError
from router.tests import helpers


class CanonicalTests(unittest.TestCase):

    def test_sorted_compact_utf8(self):
        self.assertEqual(hoplink.canonical({"b": 1, "a": ["é", None, True]}),
                         '{"a":["é",null,true],"b":1}'.encode("utf-8"))

    def test_refusals(self):
        for bad in ({"x": 1.0}, {"x": float("nan")}, {1: "k"}, {"x": "\ud800"}, {"x": b"b"},
                    [{"y": [0.5]}]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    hoplink.canonical(bad)


class AddressTests(unittest.TestCase):

    def test_octet_boundaries(self):
        local64 = "l" * 64
        self.assertIsNone(hoplink.address_octets_problem(local64 + "@example.org"))
        self.assertIn("local part", hoplink.address_octets_problem("l" * 65 + "@example.org"))
        at254 = "a" * 64 + "@" + "d" * (254 - 65)
        self.assertEqual(len(at254), 254)
        self.assertIsNone(hoplink.address_octets_problem(at254))
        self.assertIn("over 254", hoplink.address_octets_problem(at254 + "d"))
        self.assertIn("octets", hoplink.address_octets_problem("é" * 128 + "@x"))
        self.assertEqual(hoplink.address_octets_problem("no-at"), "no '@'")

    def test_from_address(self):
        self.assertIsNone(hoplink.from_address_problem("alice@fleet.example.org"))
        at254 = "a" * 64 + "@" + "d" * (254 - 65)
        self.assertIsNone(hoplink.from_address_problem(at254))
        self.assertIsNotNone(hoplink.from_address_problem(at254 + "d"))
        for bad in ("Alice <a@b.org>", "a@b.org\n", "é@b.org", "a b@c.org"):
            with self.subTest(bad=bad):
                self.assertIsNotNone(hoplink.from_address_problem(bad))


def _req(n_to=1, *, to=None, extra=None):
    draft = {"to": to if to is not None else [f"r{i}@example.org" for i in range(n_to)],
             "subject": "s", "body_text": "b"}
    req = {"contract_version": "2", "req_id": "00000001", "agent_id": "x", "draft": draft}
    if extra:
        req.update(extra)
    return req


class BeginCheckTests(unittest.TestCase):

    def refused(self, request, code, cap=1 << 20):
        with self.assertRaises(hoplink.Refused) as cm:
            hoplink.check_begin(request, request_cap=cap)
        self.assertEqual((cm.exception.outcome, cm.exception.reason_code), ("rejected", code))

    def test_recipient_count_counts_every_raw_entry(self):
        hoplink.check_begin(_req(100), request_cap=1 << 20)
        self.refused(_req(101), "too_many_recipients")
        req = _req(60)
        req["draft"]["cc"] = list(req["draft"]["to"])[:41]   # duplicates counted
        self.refused(req, "too_many_recipients")
        req = _req(99)
        req["draft"]["bcc"] = ["x@example.org", "y@example.org"]
        self.refused(req, "too_many_recipients")

    def test_each_octet_bound(self):
        at254 = "a" * 64 + "@" + "d" * (254 - 65)
        hoplink.check_begin(_req(to=[at254]), request_cap=1 << 20)
        self.refused(_req(to=[at254 + "d"]), "malformed_request")
        self.refused(_req(to=["l" * 65 + "@example.org"]), "malformed_request")

    def test_the_encoding(self):
        self.refused(_req(extra={"n": 1.5}), "malformed_request")
        self.refused(_req(extra={"s": "\udfff"}), "malformed_request")

    def test_the_request_cap_counts_the_newline(self):
        req = _req()
        size = len(hoplink.canonical(req)) + 1
        hoplink.check_begin(req, request_cap=size)
        self.refused(req, "malformed_request", cap=size - 1)


def _brute(n, f, t):
    best = 0
    for count in range(n + 1):
        for sizes in itertools.product(range(f + 1), repeat=count):
            if sum(sizes) <= t:
                enc = sum(4 * math.ceil(s / 3) for s in sizes) + (3 * count - 1 if count else 0)
                best = max(best, enc)
    return best


class AttachArrayTests(unittest.TestCase):

    def test_exact_against_brute_force(self):
        for n in range(0, 4):
            for f in range(0, 8):
                for t in range(0, 12):
                    with self.subTest(n=n, f=f, t=t):
                        got = hoplink.attach_array_max(n, f, t)
                        # The formula assumes all N slots present (zero-byte ones too).
                        want = max(_brute(n, f, t), 3 * n - 1 if n else 0)
                        self.assertEqual(got, want)

    def test_the_count_cap_limits_the_total(self):
        mib = 1 << 20
        self.assertEqual(hoplink.attach_array_max(1, 8 * mib, 32 * mib),
                         4 * math.ceil(8 * mib / 3) + 2)

    def test_it_is_the_real_encoding(self):
        n, f, t = 3, 7, 10
        sizes = (4, 4, 2)   # one realisation of the maximum
        arr = [base64.b64encode(b"x" * s).decode() for s in sizes]
        self.assertEqual(len(hoplink.canonical(arr)) - 2, hoplink.attach_array_max(n, f, t))


class FloorTests(unittest.TestCase):

    def test_the_floor_is_exact(self):
        """The worst case, built: a request of exactly cap - 1 canonical
        bytes and attachments realising the maximum, at the longest fixed
        members. Its length is the floor, to the byte."""
        request_cap, n, f, t, v = 4096, 2, 10, 12, 1
        base = _req()
        pad = request_cap - 1 - len(hoplink.canonical(dict(base, pad="")))
        request = dict(base, pad="p" * pad)
        self.assertEqual(len(hoplink.canonical(request)) + 1, request_cap)
        atts = [base64.b64encode(b"x" * s).decode() for s in (7, 5)]   # 3 + 2 quanta... max
        self.assertEqual(len(hoplink.canonical(atts)) - 2, hoplink.attach_array_max(n, f, t))
        doc = hoplink.build_handover(
            request, from_address="a" * 252 + "@b", version_write=v, attachments=atts,
            settled_through=10 ** 18 - 1)
        self.assertEqual(len(doc), hoplink.document_floor(
            request_cap=request_cap, count_cap=n, file_cap=f, total_cap=t, version_write=v))


class ConfigFloorTests(helpers.RouterTestCase):

    def doc(self, document):
        root = self.tmp / "alice"
        root.mkdir(exist_ok=True)
        doc = helpers.with_hop({
            "state_dir": str(self.state_dir),
            "instances": {"alice": {"namespace": str(root)}},
            "attachment_max_count": 2, "attachment_max_bytes": 10,
            "attachment_max_total_bytes": 12,
            "transport_plugin": {"path": "/opt/p.py", "sha256": "a" * 64}}, self.tmp)
        doc["hop"]["caps"] = {"document": document, "request": 4096,
                              "attachment": 1 << 20, "total": 1 << 20}
        return doc

    def test_exactly_the_floor_loads_and_one_less_is_refused(self):
        floor = hoplink.document_floor(request_cap=4096, count_cap=2, file_cap=10,
                                       total_cap=12, version_write=1)
        config_mod.load_obj(self.doc(floor))
        with self.assertRaises(ConfigError) as cm:
            config_mod.load_obj(self.doc(floor - 1))
        self.assertIn("config.hop.caps.document", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
