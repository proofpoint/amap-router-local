"""The optional remover in the ingress pass (the remover's caller contract):
a waiting record is removed through it when the plugin offers one, every
result and every exception class has its outcome, an offered remover that
cannot be built leaves the entries waiting, and status says which."""
from __future__ import annotations

from types import SimpleNamespace

from router import hoplink, ingress
from router.tests.ingress_double import DoubleReader, ListingTooLarge
from router.tests.test_ingress_pump import E1, HORIZON, LINK, _Pump, entry, later


class _UnsafeRead(Exception):
    def __init__(self, reason="not_regular"):
        super().__init__(reason)
        self.reason = reason


class _Reasoned(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


ROLES = ((_UnsafeRead, "unsafe_read"), (ListingTooLarge, "listing_too_large"))


class RecordingRemover:
    def __init__(self, result="removed", raises=None):
        self.result, self.raises, self.calls = result, raises, []

    def remove_entry(self, kind, entry_id):
        self.calls.append((kind, entry_id))
        if self.raises is not None:
            raise self.raises
        return self.result

    def close(self):
        pass


class RemoverPassTests(_Pump):

    def pump_with(self, remover=None, hold=None, now=None):
        p = ingress.Pump(self.keyed, DoubleReader(self.port), self.lid, self.gen, LINK,
                         report=self.report, recipient="bravo", unresolved=None,
                         attachment_cap=1024, remover=remover, remover_hold=hold,
                         runtime_roles=ROLES)
        return ingress.pump_generation(p, listing_too_large=ListingTooLarge,
                                       horizon_s=HORIZON, now=now), p

    def placed(self):
        self.port.entries[E1] = entry(E1)
        self.pump_with()
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_removed_and_absent_each_make_the_tombstone_at_once(self):
        for result in ("removed", "absent"):
            with self.subTest(result=result):
                self.tearDown()
                self.setUp()
                self.placed()
                remover = RecordingRemover(result)
                self.pump_with(remover)
                self.assertEqual(remover.calls, [("notice", E1)])
                self.assertEqual(self.state(E1), (ingress.COMPLETE, None))

    def test_a_quarantined_entry_is_removed_alike(self):
        self.port.entries[E1] = "notice_invalid"
        self.pump_with()
        self.pump_with(RecordingRemover())
        self.assertEqual(self.state(E1), (ingress.QUARANTINED_COMPLETE, None))

    def test_an_unknown_return_is_a_protocol_hold_and_the_record_waits(self):
        self.placed()
        counts, _ = self.pump_with(RecordingRemover(result="gone"))
        self.assertEqual(counts.get(ingress.HOLD_REMOVE_PROTOCOL), 1)
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_each_exception_class_has_its_hold_and_the_record_waits(self):
        cases = [
            (ListingTooLarge("big"), ingress.HOLD_REMOVE_LISTING_TOO_LARGE),
            (_UnsafeRead("link_count"), "hop_unsafe_read:link_count"),
            (_Reasoned("layout"), "hop_remove_anomaly:layout"),
            (_Reasoned("owner"), "hop_remove_anomaly:owner"),
            (OSError(5, "io"), ingress.HOLD_IO_ERROR),
            (RuntimeError("?"), ingress.HOLD_UNEXPECTED),
            (_Reasoned("not_a_reason"), ingress.HOLD_UNEXPECTED),
        ]
        for exc, why in cases:
            with self.subTest(why=why):
                self.tearDown()
                self.setUp()
                self.placed()
                counts, _ = self.pump_with(RecordingRemover(raises=exc))
                self.assertEqual(counts.get(why), 1, counts)
                self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_a_closed_remover_is_evicted(self):
        self.placed()
        key = (id(None), str(self.state_dir), self.lid, self.gen)
        remover = RecordingRemover(raises=_Reasoned("closed"))
        hoplink._REMOVERS[key] = remover
        self.addCleanup(hoplink._REMOVERS.clear)
        counts, pump = self.pump_with(remover)
        self.assertEqual(counts.get(ingress.HOLD_OBJECT_CLOSED), 1)
        self.assertNotIn(key, hoplink._REMOVERS)
        self.assertIsNone(pump.remover)

    def test_after_a_close_the_rest_of_the_pass_waits_never_the_interim_rule(self):
        # Two waiting records: the first closes the remover; the second is
        # gone upstream and past the horizon, so the not-offered rule WOULD
        # tombstone it. It must stay waiting until the remover is rebuilt.
        e2 = "1700000000-2"
        self.port.entries[E1] = entry(E1)
        self.port.entries[e2] = entry(e2)
        self.pump_with()
        del self.port.entries[e2]
        remover = RecordingRemover(raises=_Reasoned("closed"))
        counts, pump = self.pump_with(remover, now=later())
        self.assertEqual(remover.calls, [("notice", E1)], "the closed remover was called again")
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))
        self.assertEqual(self.state(e2), (ingress.PUBLISHED_WAITING_REMOVE, None),
                         "the rest of the pass fell to the interim rule")
        self.assertEqual(pump.remover_hold, ingress.HOLD_OBJECT_CLOSED)

    def test_a_held_remover_leaves_entries_waiting_even_gone_past_the_horizon(self):
        self.placed()
        del self.port.entries[E1]
        self.pump_with(hold="hop_settings_refused", now=later())
        self.assertEqual(self.state(E1), (ingress.PUBLISHED_WAITING_REMOVE, None))

    def test_without_a_remover_the_interim_rule_still_applies(self):
        self.placed()
        del self.port.entries[E1]
        self.pump_with(now=later())
        self.assertEqual(self.state(E1), (ingress.COMPLETE, None))

    def test_an_entry_never_journaled_is_never_passed_to_the_remover(self):
        # Listed, but the reader says it is not there: no record, no removal.
        self.port.entries[E1] = FileNotFoundError(E1)
        remover = RecordingRemover()
        self.pump_with(remover)
        self.assertIsNone(self.state(E1))
        self.assertEqual(remover.calls, [])


class RemoverForTests(_Pump):

    def setUp(self):
        super().setUp()
        hoplink.forget_senders()
        self.addCleanup(hoplink.forget_senders)

    def runtime(self, factory=None, offered=True):
        plugin = SimpleNamespace(
            optional_capabilities=frozenset({"make_intake_remover"}) if offered else frozenset(),
            make_intake_remover=factory or (lambda s, f: RecordingRemover()))
        return SimpleNamespace(plugin=plugin, fsops=None, hop=None)

    def small_cfg(self):
        hop = SimpleNamespace(root=str(self.tmp / "hop"), peer_uid=0)
        return SimpleNamespace(state_dir=self.state_dir, hop=hop)

    def test_not_offered_is_none_and_never_calls_the_factory(self):
        calls = []
        rt = self.runtime(factory=lambda s, f: calls.append(s), offered=False)
        self.assertIsNone(hoplink.remover_for(rt, self.small_cfg(), self.lid, self.gen))
        self.assertEqual(calls, [])

    def test_offered_is_built_once_with_the_four_key_core(self):
        made = []

        def factory(settings, fsops):
            made.append(dict(settings))
            return RecordingRemover()

        rt = self.runtime(factory)
        a = hoplink.remover_for(rt, self.small_cfg(), self.lid, self.gen)
        b = hoplink.remover_for(rt, self.small_cfg(), self.lid, self.gen)
        self.assertIs(a, b)
        self.assertEqual(made, [{"hop_root": str(self.tmp / "hop"), "logical_id": self.lid,
                                 "generation": self.gen, "peer_uid": 0}])

    def test_refused_settings_latch_the_remover_only(self):
        calls = []

        def factory(settings, fsops):
            calls.append(1)
            raise _Reasoned("settings_invalid")

        rt = self.runtime(factory)
        for _ in range(2):
            with self.assertRaises(hoplink.HopHold) as cm:
                hoplink.remover_for(rt, self.small_cfg(), self.lid, self.gen)
            self.assertEqual(cm.exception.reason, "hop_settings_refused")
            self.assertTrue(cm.exception.latched)
        self.assertEqual(calls, [1], "a latched refusal was retried")

    def test_any_other_construction_failure_is_retried(self):
        calls = []

        def factory(settings, fsops):
            calls.append(1)
            raise _Reasoned("layout")

        rt = self.runtime(factory)
        for _ in range(2):
            with self.assertRaises(hoplink.HopHold) as cm:
                hoplink.remover_for(rt, self.small_cfg(), self.lid, self.gen)
            self.assertFalse(cm.exception.latched)
        self.assertEqual(calls, [1, 1])


class RemoverStatusTests(_Pump):

    def test_status_names_the_remover_state(self):
        self.addCleanup(ingress.REMOVER_STATE.clear)
        key = (str(self.state_dir), self.lid, self.gen)
        for state, summary in (("not_offered", "not_offered"), ("available", "available"),
                               ("held:hop_settings_refused", "held")):
            with self.subTest(state=state):
                ingress.REMOVER_STATE.clear()
                ingress.REMOVER_STATE[key] = state
                doc = ingress.status_doc(self.keyed)
                self.assertEqual(doc["remover"], summary)
                gen_doc = doc["generations"].get(f"{self.lid}/{self.gen}", {})
                self.assertEqual(gen_doc.get("remover"), state)
