"""Fence scenarios this router's own suite carries, against the test-only
double, one port per generation's tree. The fixture-mode scenarios and the
fence-stop injections are pending to their own units and not claimed here.

  held then fenced: an entry pumped before the fence (held, never
      quarantined), the fence, then a commit into the fenced generation
      afterwards: both late_inbound in the fenced generation.
  invisible until committed: an entry uncommitted before the fence leaves no
      journal file, quarantine item or snapshot; completed after it, late.
  the control: an entry committed in the new generation after the fence is
      journaled there, placed, and never late.
  first seen after the fence: committed before it, pumped first after it:
      late, decided on this router's own observation.
  prepared then fenced: a snapshot prepared, the fence, then the re-check
      before placing: quarantined late, nothing placed."""
from __future__ import annotations

from router import generations, ingress
from router.tests.ingress_double import DoublePort
from router.tests.peer_helpers import addr
from router.tests.test_ingress_bundle import CAP, enc, make
from router.tests.test_ingress_pump import LINK, _Pump, entry

N0, N1, N2, N3, N5 = (f"1700000000-{i}" for i in (10, 11, 12, 13, 15))


class FenceScenarioTests(_Pump):

    def setUp(self):
        super().setUp()
        self.ports = {self.gen: self.port}

    def on(self, gen):
        self.port = self.ports.setdefault(gen, DoublePort())
        return gen

    def items_of(self, gen):
        return {i["entry_id"]: i["cause"] for i in self.items(gen=gen)}

    def test_held_then_fenced(self):
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

    def test_invisible_until_committed(self):
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

    def test_the_control_in_the_new_generation(self):
        g1 = self.mint()
        g2 = generations.read_doc(self.state_dir, self.lid)["current"]
        self.ports[g1].entries[N0] = entry(N0, to=addr("charlie"))
        self.on(g2)
        self.port.entries[N3] = entry(N3)
        self.pump(gen=g2)
        self.assertEqual(self.state(N3, gen=g2), (ingress.PUBLISHED_WAITING_REMOVE, None))
        self.assertEqual(self.items_of(g2), {})
        self.assertEqual(len(self.notices()), 1)

    def test_first_seen_after_the_fence(self):
        g1 = self.gen
        self.ports[g1].entries[N5] = entry(N5)               # committed BEFORE the fence
        self.mint()
        self.pump(gen=self.on(g1))                           # first seen AFTER it
        self.assertEqual(self.items_of(g1), {N5: "late_inbound"})
        self.assertEqual(self.notices(), [])

    def test_prepared_then_fenced(self):
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
