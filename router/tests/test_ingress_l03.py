"""The L03 rows this router's own suite carries (design v3 §11): a, c, d, f
and g, against the test-only double, one port per generation's tree. The
fixture-mode rows and b1/b2 are pending elsewhere and are not claimed here.

  L03-a: N0 pumped in G1 (held, never quarantined); the fence; N1 committed
         into G1 afterwards: late_inbound in G1, and N0, still held when its
         generation is fenced, goes late too.
  L03-c: N2 uncommitted before the fence is INVISIBLE (no journal file, no
         quarantine item, no snapshot); committed after it, it is late.
  L03-d: the control: N3 committed in G2 after the fence is journaled under
         G2 and never late.
  L03-f: N5 committed in G1 before the fence but first pumped after it is
         late: decided on this router's own observation.
  L03-g: a snapshot prepared, then the fence, then the re-check before
         placing: quarantined late, nothing placed."""
from __future__ import annotations

from router import generations, ingress
from router.tests.ingress_double import DoublePort
from router.tests.peer_helpers import addr
from router.tests.test_ingress_bundle import CAP, enc, make
from router.tests.test_ingress_pump import LINK, _Pump, entry

N0, N1, N2, N3, N5 = (f"1700000000-{i}" for i in (10, 11, 12, 13, 15))


class L03Tests(_Pump):

    def setUp(self):
        super().setUp()
        self.ports = {self.gen: self.port}

    def on(self, gen):
        self.port = self.ports.setdefault(gen, DoublePort())
        return gen

    def items_of(self, gen):
        return {i["entry_id"]: i["cause"] for i in self.items(gen=gen)}

    def test_l03_a(self):
        g1 = self.gen
        self.port.entries[N0] = entry(N0, to=addr("charlie"))   # held, never placed
        self.pump(gen=self.on(g1))
        self.assertEqual(self.state(N0, gen=g1), (ingress.HELD, "recipient_not_this_identity"))
        self.assertEqual(self.items_of(g1), {})
        self.mint()
        self.ports[g1].entries[N1] = entry(N1)
        self.pump(gen=self.on(g1))
        self.assertEqual(self.items_of(g1), {N0: "late_inbound", N1: "late_inbound"})
        self.assertEqual(self.notices(), [])

    def test_l03_c(self):
        g1 = self.gen
        self.pump(gen=self.on(g1))          # N2 not committed: not listed
        self.assertIsNone(self.state(N2, gen=g1))
        self.assertEqual(self.items_of(g1), {})
        self.assertEqual(self.snapshots(gen=g1), [])
        self.assertGreater(self.ports[g1].lists, 0, "control: the generation was listed")
        self.mint()
        self.ports[g1].entries[N2] = entry(N2)               # completed after the fence
        self.pump(gen=self.on(g1))
        self.assertEqual(self.items_of(g1), {N2: "late_inbound"})

    def test_l03_d(self):
        g1 = self.mint()
        g2 = generations.read_doc(self.state_dir, self.lid)["current"]
        self.ports[g1].entries[N0] = entry(N0, to=addr("charlie"))
        self.on(g2)
        self.port.entries[N3] = entry(N3)
        self.pump(gen=g2)
        self.assertEqual(self.state(N3, gen=g2), (ingress.PUBLISHED_WAITING_REMOVE, None))
        self.assertEqual(self.items_of(g2), {})
        self.assertEqual(len(self.notices()), 1)

    def test_l03_f(self):
        g1 = self.gen
        self.ports[g1].entries[N5] = entry(N5)               # committed BEFORE the fence
        self.mint()
        self.pump(gen=self.on(g1))                           # first seen AFTER it
        self.assertEqual(self.items_of(g1), {N5: "late_inbound"})
        self.assertEqual(self.notices(), [])

    def test_l03_g(self):
        g1 = self.gen
        parsed = ingress.parse_bundle(enc(make(nid=N1, to=addr("bravo"))), N1,
                                      attachment_cap=CAP)
        ingress.prepare(self.keyed, self.state_dir, self.lid, g1, LINK, N1, parsed,
                        recipient="bravo")
        self.mint()
        self.assertEqual(ingress.place(self.keyed, self.state_dir, self.lid, g1, LINK, N1,
                                       attachment_cap=CAP), ingress.QUARANTINED)
        self.assertEqual(self.items_of(g1), {N1: "late_inbound"})
        self.assertEqual(self.notices(), [])
