"""The runtime capability at PLUGIN_API (3, 5), against the frozen stand-in
(`runtime_standin`): the closed sender settings, the explicit admission and
its `admitted_at` on every path, the settling write row and its order, the
refusals of an unreadable generation before any plan, every plugin anomaly
held as `runtime_tree_unavailable`, and one canonical own address. The real
plugin's rows are `run_realhop.py`'s."""
from __future__ import annotations

import ast
import dataclasses
import json
import pathlib
from unittest import mock

import router
from router import config as config_mod
from router import hoplink, inflight, peercontrol, peerjournal
from router import transport as transport_mod
from router.tests import runtime_standin as rs
from router.tests import test_discovery as tdisc
from router.tests import test_peercontrol as tpc

NOW, AT = tpc.NOW, tpc.AT
ROUTER = pathlib.Path(router.__file__).parent
OTHER_AT = "2026-10-01T09:00:00Z"


class _Repoint(tpc._Control):

    def cap(self):
        return peercontrol.capability(self.cfg, self.runtime)

    def control(self, key):
        return self.record(key)["control"]

    def pin(self, gen):
        return peercontrol.runtime_pin(self.cfg, gen)

    def record_bytes(self, gen):
        d = peercontrol.runtime_dir(self.cfg)
        return ((d / config_mod.RUNTIME_GENERATION_FILE).read_bytes(),
                (d / gen / hoplink.TRANSPORT_DIR / hoplink.PIN_FILE).read_bytes())

    def plan(self, verb, **detail):
        """A verb's durable plan, as `_begin_verb_audit` writes it."""
        return peercontrol._begin_verb_audit(self.cfg, verb, NOW, **detail)


class SettingsTests(_Repoint):
    """R1: the capability's names and the sender's closed settings."""

    def test_the_capability_table_names_admit(self):
        self.assertEqual(transport_mod.RUNTIME_CAPABILITY.get("admit"), "admit")

    def test_the_sender_settings_are_the_closed_six_from_the_pin_and_the_caps(self):
        gen = "c" * 32
        peercontrol.record_generation(self.cfg, gen, admitted_at=AT)
        pin = self.pin(gen)
        pin["version_write"] = 7
        path = peercontrol.runtime_dir(self.cfg) / gen / hoplink.TRANSPORT_DIR / hoplink.PIN_FILE
        path.write_bytes(hoplink.canonical(pin))
        self.cfg = dataclasses.replace(self.cfg, hop=dataclasses.replace(self.cfg.hop)
                                       if dataclasses.is_dataclass(self.cfg.hop) else self.cfg.hop)
        self.cfg.hop.caps = {"document": 1, "request": 2, "attachment": 3, "total": 4}
        try:
            self.cap().sender(gen, port=True)
        except Exception:  # noqa: BLE001 -- the settings below decide
            pass
        role, settings = self.tree.calls[-1] if self.tree.calls else (None, {})
        self.assertEqual(role, "sender")
        self.assertEqual(set(settings), rs.SENDER_SETTINGS)
        self.assertEqual((settings.get("version_write"), settings.get("caps")),
                         (7, {"document": 1, "request": 2, "attachment": 3, "total": 4}))

    def test_a_port_needs_the_pin_and_a_reader_does_not(self):
        gen = "d" * 32
        with self.assertRaises(peercontrol.Unavailable) as cm:
            self.cap().sender(gen, port=True)
        self.assertIn("no pinned version_write", str(cm.exception))
        self.cap().sender(gen)          # retire and identity never send
        self.assertEqual(self.tree.calls[-1][1]["version_write"], self.cfg.hop.version_write)


class AdmitTests(_Repoint):
    """R2: admit before ANY port call, with the generation's stable value."""

    def spy(self):
        """Every port call on every sender, in order, by method name."""
        order = []
        real = rs.RuntimeSender.__getattribute__
        names = {"admit", "has_result", "has_pending", "has_archived", "read_result",
                 "write_request", "withdraw_request"}

        def get(obj, name):
            attr = real(obj, name)
            if name in names and callable(attr):
                def call(*a, **k):
                    order.append(name)
                    return attr(*a, **k)
                return call
            return attr
        p = mock.patch.object(rs.RuntimeSender, "__getattribute__", get)
        p.start()
        self.addCleanup(p.stop)
        return order

    def test_admit_is_the_first_port_call_with_the_minted_time(self):
        order = self.spy()
        key = self.refused()
        self.send()
        self.assertEqual(order[0], "admit", order)
        self.assertIn("write_request", order, "handed over")
        gen = self.gen()
        minted = peercontrol.recorded_admitted_at(self.cfg)
        self.assertEqual(self.tree.admits, [(gen, minted[1])])
        self.assertEqual(self.pin(gen)["admitted_at"], minted[1])
        self.assertTrue(self.control(key)["attempt"]["n"])

    def test_every_resume_admits_again_and_a_steady_state_is_exists(self):
        key = self.refused()
        self.send()
        self.send()
        gen = self.gen()
        self.assertEqual([g for g, _ in self.tree.admits], [gen, gen])
        self.assertEqual(self.tree.identities[gen]["admitted_at"],
                         peercontrol.recorded_admitted_at(self.cfg)[1])
        self.assertTrue(self.control(key)["attempt"])

    def test_a_record_and_pin_that_disagree_hold_and_never_admit(self):
        gen = "e" * 32
        peercontrol.record_generation(self.cfg, gen, admitted_at=AT)
        path = peercontrol.runtime_dir(self.cfg) / config_mod.RUNTIME_GENERATION_FILE
        path.write_text(json.dumps({"generation": gen, "minted_ts": OTHER_AT}))
        self.refused()
        got = self.send()
        self.assertEqual(got, {peercontrol.UNAVAILABLE: 1})
        self.assertEqual(self.tree.admits, [], "never re-admitted with another time")

    def test_an_identity_with_another_time_holds_exists_different(self):
        gen = "e" * 32
        self.tree.admit(gen, OTHER_AT, address=peercontrol.runtime_address(self.cfg))
        peercontrol.record_generation(self.cfg, gen, admitted_at=AT)
        key = self.refused()
        got = self.send()
        self.assertEqual(got, {peercontrol.UNAVAILABLE: 1})
        self.assertEqual(self.tree.senders[gen].pending, {}, "nothing handed over")
        self.assertFalse(self.control(key).get("sent"))

    def test_adopt_copies_the_identitys_time_into_the_record_and_the_pin(self):
        gen = "f" * 32
        self.tree.admit(gen, OTHER_AT, address=peercontrol.runtime_address(self.cfg))
        peercontrol.operator_adopt(self.cfg, self.cap(), gen, now=NOW, evidence="x")
        self.assertEqual(peercontrol.recorded_admitted_at(self.cfg), (gen, OTHER_AT))
        self.assertEqual(self.pin(gen)["admitted_at"], OTHER_AT)

    def test_an_adopt_plan_replayed_writes_the_same_bytes(self):
        gen = "f" * 32
        self.tree.admit(gen, OTHER_AT, address=peercontrol.runtime_address(self.cfg))
        marker = self.plan(peercontrol.ADOPT_VERB, generation=gen, evidence="x",
                           admitted_at=OTHER_AT)
        peercontrol._complete_plan(self.cfg, self.cap(), marker, NOW)
        first = self.record_bytes(gen)
        later = NOW.replace(hour=NOW.hour + 1)
        peercontrol._complete_plan(self.cfg, self.cap(), marker, later)
        self.assertEqual(self.record_bytes(gen), first)

    def test_a_new_plan_replayed_uses_the_plans_time(self):
        old = "a" * 32
        self.tree.gens[old] = "live"
        peercontrol.record_generation(self.cfg, old, admitted_at=AT)
        minted = "b" * 32
        marker = self.plan(peercontrol.NEW_VERB, retired=old, minted=minted, evidence="x")
        peercontrol._complete_plan(self.cfg, self.cap(), marker, NOW)
        first = self.record_bytes(minted)
        peercontrol._complete_plan(self.cfg, self.cap(), marker, NOW.replace(hour=NOW.hour + 2))
        self.assertEqual(self.record_bytes(minted), first)
        self.assertEqual(peercontrol.recorded_admitted_at(self.cfg), (minted, marker["at"]))

    def frozen_and_lost(self, listed_at=None):
        """An attempt frozen in a generation whose record is then lost."""
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        gen = self.control(key)["attempt"]["gen"]
        (peercontrol.runtime_dir(self.cfg) / config_mod.RUNTIME_GENERATION_FILE).unlink()
        return key, gen

    def test_a_listed_live_restore_copies_the_identity(self):
        key, gen = self.frozen_and_lost()
        self.tree.gens[gen] = "live"
        self.tree.identities[gen] = dict(self.tree.identities.get(gen) or {
            "address": peercontrol.runtime_address(self.cfg), "generation": gen,
            "logical_id": "runtime"}, admitted_at=OTHER_AT)
        self.send()
        self.assertEqual(peercontrol.recorded_admitted_at(self.cfg), (gen, OTHER_AT))
        self.assertEqual(self.pin(gen)["admitted_at"], OTHER_AT)

    def test_an_unlisted_restore_takes_its_own_time_and_a_later_adopt_converges(self):
        key, gen = self.frozen_and_lost()
        self.tree.gens.pop(gen, None)
        self.tree.identities.pop(gen, None)
        # No pin survived either (the transport counter beside it stays: it
        # holds the attempt's `n`).
        (peercontrol.runtime_dir(self.cfg) / gen / hoplink.TRANSPORT_DIR
         / hoplink.PIN_FILE).unlink()
        later = NOW.replace(minute=30)
        self.send(now=later)
        t = later.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(peercontrol.recorded_admitted_at(self.cfg), (gen, t))
        self.assertEqual(self.tree.identities[gen]["admitted_at"], t, "admitted at T")
        before = self.record_bytes(gen)
        peercontrol.operator_adopt(self.cfg, self.cap(), gen, now=NOW.replace(hour=15),
                                   evidence="x")
        self.assertEqual(self.record_bytes(gen), before, "adopt is a byte-equal no-op")

    def test_an_unlisted_restore_with_a_surviving_pin_takes_the_pins_time(self):
        key, gen = self.frozen_and_lost()
        self.tree.gens.pop(gen, None)
        self.tree.identities.pop(gen, None)
        pinned = self.pin(gen)["admitted_at"]
        later = NOW.replace(minute=30)
        self.assertNotEqual(pinned, later.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.send(now=later)
        self.assertEqual(peercontrol.recorded_admitted_at(self.cfg), (gen, pinned))
        self.assertEqual(self.tree.identities[gen]["admitted_at"], pinned, "admitted at the pin's")


class SettleTests(_Repoint):
    """R3 and C4: a retired generation at write_request settles; elsewhere it holds."""

    def frozen_unhanded(self):
        key = self.refused()
        real = inflight.advance

        def admit_then_stop(*a, **k):
            raise RuntimeError("crash before the hand-over")
        with mock.patch.object(inflight, "advance", admit_then_stop):
            self.send()
        return key

    def test_a_retired_generation_at_write_request_settles_rejected_and_cleans_up(self):
        key = self.frozen_unhanded()
        gen = self.control(key)["attempt"]["gen"]
        self.tree.gens[gen] = "retired"
        with mock.patch.object(peercontrol, "_require_writable"):   # the backstop alone
            got = self.send()
        c = self.control(key)
        self.assertTrue(c.get("sent"), got)
        settled = c.get("settled") or {}
        self.assertEqual((settled.get("outcome"), settled.get("reason_code")),
                         ("rejected", "generation_retired"))
        self.assertEqual(self.tree.senders[gen].pending, {}, "nothing handed over")
        self.assertEqual(peercontrol.unsettled_attempts(self.cfg), [])
        self.assertEqual(peercontrol._inflight_entries(self.cfg, gen), [],
                         "the in-flight record and its marker are cleaned up")
        doc = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)
        self.assertEqual(doc["failed"], {"rejected": 1})

    def test_the_settle_row_is_asked_before_the_latched_and_retried_rows(self):
        """C4: even with a latched row naming the same reason, it settles."""
        key = self.frozen_unhanded()
        gen = self.control(key)["attempt"]["gen"]
        self.tree.gens[gen] = "retired"
        latched = dict(hoplink.LATCHED_WRITE_REASONS, generation_retired="hop_retired")
        with mock.patch.object(peercontrol, "_require_writable"), \
                mock.patch.object(hoplink, "LATCHED_WRITE_REASONS", latched):
            self.send()
        self.assertEqual((self.control(key).get("settled") or {}).get("reason_code"),
                         "generation_retired")
        self.assertIsNone(hoplink.write_hold(self.cfg, config_mod.RUNTIME_NS)
                          if config_mod.runtime_generation is not None else None)

    def test_a_crash_between_the_settlement_and_the_cleanup_completes(self):
        key = self.frozen_unhanded()
        gen = self.control(key)["attempt"]["gen"]
        self.tree.gens[gen] = "retired"
        real = inflight._cleanup
        calls = []

        def crash_once(*a, **k):
            calls.append(a)
            if len(calls) == 1:
                raise RuntimeError("crash after the settlement")
            return real(*a, **k)
        with mock.patch.object(peercontrol, "_require_writable"), \
                mock.patch.object(inflight, "_cleanup", crash_once):
            self.send()
            self.send()
        self.assertEqual(peercontrol._inflight_entries(self.cfg, gen), [])
        self.assertEqual(self.control(key)["settled"]["outcome"], "rejected")

    def test_a_settled_attempt_never_blocks_a_later_retire_or_new(self):
        key = self.frozen_unhanded()
        gen = self.control(key)["attempt"]["gen"]
        self.tree.gens[gen] = "retired"
        with mock.patch.object(peercontrol, "_require_writable"):
            self.send()
        self.tree.gens[gen] = "live"            # say a stale lister: the record is clean
        peercontrol._check_retirable(self.cfg, self.cap(), gen)

    def test_a_retired_generation_before_the_handed_marker_holds(self):
        key = self.frozen_unhanded()
        gen = self.control(key)["attempt"]["gen"]
        sender = self.cap().sender(gen, port=True)
        with mock.patch.object(type(sender), "has_result",
                               side_effect=rs.RuntimeRetired("before any hand-over")):
            got = self.send()
        self.assertEqual(got, {peercontrol.UNAVAILABLE: 1})
        self.assertFalse(self.control(key).get("sent"), "held, never settled")


class UnreadableTests(_Repoint):
    """R4 and R4b."""

    def refusal(self, fn):
        """(exception type, message) of `fn()`, or ("returned", repr)."""
        try:
            out = fn()
        except Exception as e:  # noqa: BLE001 -- a wrong outcome must FAIL
            return type(e).__name__, str(e)
        return "returned", repr(out)

    def no_plan(self):
        self.assertFalse(peercontrol._verb_marker_path(self.cfg).exists(),
                         "no durable plan was written")

    def test_retire_refuses_an_unreadable_target_before_any_plan(self):
        gen = "a" * 32
        self.tree.gens[gen] = "unreadable"
        kind, msg = self.refusal(lambda: peercontrol.operator_retire(
            self.cfg, self.cap(), gen, now=NOW, evidence="x"))
        self.assertEqual(kind, "ValueError", msg)
        self.assertIn(peercontrol.REPAIR_EXIT, msg)
        self.no_plan()

    def test_new_refuses_an_unreadable_recorded_target_before_any_plan(self):
        gen = "a" * 32
        peercontrol.record_generation(self.cfg, gen, admitted_at=AT)
        self.tree.gens[gen] = "unreadable"
        kind, msg = self.refusal(lambda: peercontrol.operator_new(
            self.cfg, self.cap(), now=NOW, evidence="x"))
        self.assertEqual(kind, "ValueError", msg)
        self.assertIn(peercontrol.REPAIR_EXIT, msg)
        self.no_plan()

    def test_each_exit_names_the_repair_for_unreadable_and_adopt_or_retire_for_live(self):
        cases = {"unreadable": peercontrol.REPAIR_EXIT, "live": "adopt or retire"}
        for state, text in cases.items():
            with self.subTest(state=state):
                self.setUp()
                other = "b" * 32
                self.tree.gens[other] = state
                with self.assertRaises(peercontrol.Unavailable) as cm:
                    peercontrol.generation(self.cfg, self.cap(), now=NOW)
                self.assertIn(text, str(cm.exception))
                if state == "unreadable":
                    self.assertNotIn("retire one", str(cm.exception))

    def test_abandon_attempt_names_the_repair_for_an_unreadable_generation(self):
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        gen = self.control(key)["attempt"]["gen"]
        for state, text in (("unreadable", peercontrol.REPAIR_EXIT), ("live", "adopt or retire")):
            with self.subTest(state=state):
                self.tree.gens[gen] = state
                with self.assertRaises(ValueError) as cm:
                    peercontrol.operator_abandon_attempt(self.cfg, self.cap(), key, now=NOW,
                                                         evidence="x")
                self.assertIn(text, str(cm.exception))


class AnomalyTests(_Repoint):
    """R6 and N3a: every plugin anomaly is Unavailable, named, on every path."""

    STRAY = rs.Anomaly("layout", "stray entry in .runtime/: .junk")

    def test_a_stray_entry_holds_the_pass_and_status_names_it(self):
        self.refused()
        self.tree.lister_anomaly = self.STRAY
        self.assertEqual(self.send(), {peercontrol.UNAVAILABLE: 1})
        tree = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)["runtime_tree"]
        self.assertIn(".junk", tree["lister_error"])
        self.assertIn(peercontrol.UNAVAILABLE, tree["lister_error"])

    def test_every_verb_refuses_named_with_no_traceback(self):
        self.tree.lister_anomaly = self.STRAY
        peercontrol.record_generation(self.cfg, "a" * 32, admitted_at=AT)
        case = tpc.AttemptTests("test_a_pending_notice_is_signed_handed_over_and_settled")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.tree.lister_anomaly = self.STRAY
        peercontrol.record_generation(case.cfg, "a" * 32, admitted_at=AT)
        for command, args in (("adopt", {"gen": "a" * 32}), ("retire", {"gen": "a" * 32}),
                              ("new", {}), ("abandon-plan", {}),
                              ("abandon-attempt", {"key": "nokey"})):
            with self.subTest(command=command):
                code, err = case.cli(command, **args)
                self.assertNotIn("raised", str(code))
                if command in ("adopt", "retire", "new"):
                    self.assertEqual(code, 1, err)
                    self.assertIn(".junk", err)
                self.assertNotIn("Traceback", err)

    def test_a_sender_method_anomaly_holds(self):
        key = self.refused()
        self.send()
        gen = self.gen()
        with mock.patch.object(rs.RuntimeSender, "has_result",
                               side_effect=rs.Anomaly("owner", "up/ misowned")):
            got = self.send()
        self.assertEqual(got, {peercontrol.UNAVAILABLE: 1})
        self.assertTrue(self.control(key)["attempt"])

    def test_a_construction_anomaly_holds(self):
        self.refused()
        bad = rs.runtime(self.tree)
        ns = dict(bad.plugin.namespace)

        def refuse(settings, fsops):
            raise rs.Anomaly("owner", ".runtime misowned")
        ns["make_runtime_sender"] = refuse
        import types
        bad.plugin = types.SimpleNamespace(api=(3, 5), namespace=types.MappingProxyType(ns),
                                           optional_capabilities=frozenset(ns))
        self.assertEqual(self.send(runtime=bad), {peercontrol.UNAVAILABLE: 1})


class AddressTests(_Repoint):
    """One canonical own address, lowercase, on all five surfaces (N3b)."""

    MIXED = "Host-A.Example.ORG"
    LOWER = "amap.router@host-a.example.org"

    def test_a_mixed_case_fleet_domain_is_refused_at_load(self):
        case = tdisc.AdmissionTests("test_a_directory_with_a_verdict_is_an_instance")
        case.setUp()
        self.addCleanup(case.doCleanups)
        try:
            case.load(fleet_domain=self.MIXED)
            got = "loaded"
        except config_mod.ConfigError as e:
            got = str(e)
        self.assertIn("fleet_domain", got)
        self.assertIn("lowercase", got)

    def test_the_one_construction_lowercases_and_every_surface_takes_it(self):
        mixed = dataclasses.replace(self.cfg, fleet_domain=self.MIXED)
        self.assertEqual(config_mod.router_address(self.MIXED), self.LOWER)
        # runtime identity and the control notice's from / envelope from_address
        self.assertEqual(peercontrol.runtime_address(mixed), self.LOWER)
        peercontrol.Capability(self.runtime.plugin, self.runtime.fsops, mixed).sender("a" * 32)
        self.assertEqual(self.tree.calls[-1][1]["address"], self.LOWER)

    def mixed(self):
        return dataclasses.replace(self.cfg, fleet_domain=self.MIXED)

    def test_an_authored_dsn_is_from_the_lowercase_address(self):
        from router import deliver
        mixed = self.mixed()
        out = deliver.deliver_router_notice(mixed, self.state_dir, tpc.tpe.HOSTED
                                            if hasattr(tpc.tpe, "HOSTED") else "bob",
                                            subject="Delivery report", body_text="x\n",
                                            in_reply_to=None)
        inst = mixed.instances[out["recipient"]]
        notice = json.loads((inst.inbox_root / "notices"
                             / f"notice-{out['notice_id']}.json").read_text())
        self.assertEqual(notice["message"]["from"], self.LOWER)

    def test_an_exposure_stamp_is_asserted_by_the_lowercase_address(self):
        from router import exposure
        stamp = exposure.assess(self.mixed(), "bob", now=AT)
        self.assertEqual((stamp or {}).get("asserted_by"), self.LOWER)

    def test_the_handed_envelope_and_control_statement_are_from_the_lowercase_address(self):
        import base64
        key = self.refused()
        self.cfg = self.mixed()
        self.send()
        n, doc = self.handover(key)
        self.assertEqual(doc["envelope"]["from_address"], self.LOWER)
        header = doc["envelope"]["peer"]["statement_header"]
        s = [p.strip()[2:] for p in header.split(";") if p.strip().startswith("s=")][0]
        statement = json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        self.assertEqual(statement["from"], self.LOWER)

    def test_the_control_receive_check_takes_the_lowercase_address(self):
        from router import peerclock, peerpolicy
        from router.tests.test_peerbind import KEY_ID, T1
        import types
        mixed = self.mixed()
        clock = peerclock.read(self.state_dir)
        hctx = peerpolicy.hook_context(mixed, delegation=self.lane, state_dir=self.state_dir,
                                       now=NOW, clock=clock)
        hooks = peerpolicy.production_hooks(hctx)

        def receive(to):
            payload = {"v": 1, "key_id": KEY_ID, "kind": "control", "id": "c" * 23,
                       "from": f"amap.router@{T1}", "to": to, "ts": AT, "about": "a" * 23,
                       "outcome": "refused", "cause": "policy"}
            verdict = types.SimpleNamespace(payload=payload, key_id=KEY_ID)
            try:
                return hooks.control_receive(None, verdict)
            except Exception as e:  # noqa: BLE001 -- a wrong outcome must FAIL
                return f"raised {type(e).__name__}"
        def cause(out):
            return getattr(out, "cause", out)
        self.assertNotEqual(cause(receive(self.LOWER)), peerpolicy.CONTROL_MISROUTED,
                            "its own lowercase address")
        self.assertEqual(cause(receive("amap.router@other.example.org")),
                         peerpolicy.CONTROL_MISROUTED, "positive control")

    def test_no_module_but_config_builds_the_own_address(self):
        """Every surface reaches the address through `config.router_address`:
        the runtime identity and control from (peercontrol.runtime_address),
        the DSN from (ingress, deliver), asserted_by (exposure), the control
        `to` check (peerpolicy); and no module but config writes the local
        part beside an `@`."""
        bad = []
        for path in sorted(ROUTER.glob("*.py")):
            if path.name == "config.py":
                continue
            bad += [f"{path.name}:{line}" for line in
                    _own_address_builders(path.read_text(encoding="utf-8"))]
        self.assertEqual(bad, [])
        users = {}
        for name in ("peercontrol.py", "ingress.py", "deliver.py", "exposure.py",
                     "peerpolicy.py"):
            tree = ast.parse((ROUTER / name).read_text(encoding="utf-8"))
            users[name] = any(isinstance(n, ast.Call) and (
                (isinstance(n.func, ast.Attribute) and n.func.attr == "router_address")
                or (isinstance(n.func, ast.Name) and n.func.id == "router_address"))
                for n in ast.walk(tree))
        self.assertEqual(users, {k: True for k in users})


    def test_the_address_scanner_sees_every_build_shape(self):
        """Positive control: each shape is found; a comparison is not."""
        shapes = [
            'x = "amap.router@d"',
            'x = f"amap.router@{d}"',
            'x = f"{config_mod.ROUTER_LOCAL_PART}@{d}"',
            'x = f"{ROUTER_LOCAL_PART}@{d}"',
            'x = config_mod.ROUTER_LOCAL_PART + "@" + d',
            'x = ROUTER_LOCAL_PART + "@" + d',
            'x = "%s@%s" % (ROUTER_LOCAL_PART, d)',
            'x = "{}@{}".format(config_mod.ROUTER_LOCAL_PART, d)',
            'x = "@".join([ROUTER_LOCAL_PART, d])',
        ]
        self.assertEqual([s for s in shapes if not _own_address_builders(s)], [])
        self.assertEqual(_own_address_builders(
            "ok = local.casefold() != config_mod.ROUTER_LOCAL_PART.casefold()"), [])

def _is_local_part(node) -> bool:
    """`ROUTER_LOCAL_PART`, bare (imported) or as an attribute."""
    return ((isinstance(node, ast.Name) and node.id == "ROUTER_LOCAL_PART")
            or (isinstance(node, ast.Attribute) and node.attr == "ROUTER_LOCAL_PART"))


def _own_address_builders(source: str) -> list:
    """Every line of `source` that builds this router's own address outside
    `config.router_address`: the literal, an f-string carrying it, or the
    local part formatted, concatenated, %-formatted, `.format`ted or joined.
    A comparison or a `.casefold()` of the local part is not a build."""
    out = []
    for n in ast.walk(ast.parse(source)):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) \
                and n.value.startswith("amap.router@"):
            out.append(n.lineno)
        elif isinstance(n, ast.JoinedStr) and any(
                (isinstance(v, ast.Constant) and "amap.router@" in str(v.value))
                or (isinstance(v, ast.FormattedValue) and _is_local_part(v.value))
                for v in n.values):
            out.append(n.lineno)
        elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)) and (
                _is_local_part(n.left) or _is_local_part(n.right)
                or (isinstance(n.right, ast.Tuple) and any(_is_local_part(e) for e in n.right.elts))):
            out.append(n.lineno)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr in ("format", "join") and any(
                    _is_local_part(a) or (isinstance(a, (ast.List, ast.Tuple))
                                          and any(_is_local_part(e) for e in a.elts))
                    for a in list(n.args) + [k.value for k in n.keywords]):
            out.append(n.lineno)
    return out


class RealPluginHarnessTests(tpc._Control):
    """The real-plugin matrix refuses to run, by name, without the pinned
    plugin: it never skips and never passes vacuously."""

    def run_main(self, argv):
        import contextlib
        import io
        from router.tests import run_realhop
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = run_realhop.main(argv)
        return code, err.getvalue()

    def test_no_plugin_is_refused(self):
        code, err = self.run_main([])
        self.assertEqual(code, 2)
        self.assertIn("REFUSED: no --plugin given", err)

    def test_a_plugin_of_another_digest_is_refused(self):
        other = self.tmp / "plugin.py"
        other.write_text("PLUGIN_API = (3, 5)\n")
        code, err = self.run_main(["--plugin", str(other)])
        self.assertEqual(code, 2)
        self.assertIn("REFUSED: digest mismatch", err)

    def test_the_pin_and_the_rows(self):
        from router.tests import run_realhop
        self.assertEqual(run_realhop.ARTIFACT_SHA256,
                         "f15855c974df021c2ae5c551aff2448d934725a6796fb03434e573305d24fe93")
        self.assertEqual(run_realhop.PLUGIN_API, (3, 5))
        self.assertEqual(set(run_realhop.ROWS) >= {
            "adopt", "retire", "new", "restore_listed_live", "restore_unlisted",
            "abandon_attempt", "abandon_plan", "settle_generation_retired",
            "hold_before_hand_over"}, True)
        matrix = run_realhop._cases()
        self.assertEqual(sorted(n[5:] for n in dir(matrix) if n.startswith("test_")),
                         sorted(run_realhop.ROWS), "every row is run, and only these")


class CrashBoundaryTests(_Repoint):
    """R2: a crash between the pin and the record never strands the tree."""

    def crash_between_the_writes(self):
        """A crash at the SECOND of record_generation's two writes, whichever
        it is: the pin first leaves a pin and no record, which a later pass
        mints or restores past; the record first would leave a record
        naming a generation with no pin, held forever."""
        real = peercontrol.atomic_write
        names = {config_mod.RUNTIME_GENERATION_FILE, hoplink.PIN_FILE}
        state = {"seen": 0}

        def write(path, *a, **k):
            if pathlib.Path(path).name in names and state["seen"] < 2:
                state["seen"] += 1
                if state["seen"] == 2:
                    raise OSError("crash between the pin and the record")
            return real(path, *a, **k)
        return mock.patch.object(peercontrol, "atomic_write", write)

    def test_a_crash_at_the_fresh_mints_record_then_the_next_pass_hands_over(self):
        key = self.refused()
        with self.crash_between_the_writes():
            self.send()
        self.assertIsNone(peercontrol.recorded_admitted_at(self.cfg), "no record without its pin")
        self.send()
        n, _doc = self.handover(key)
        self.assertTrue(n)

    def test_a_crash_at_a_restores_record_then_the_next_pass_hands_over(self):
        key = self.refused()
        with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
            self.send()
        gen = self.control(key)["attempt"]["gen"]
        (peercontrol.runtime_dir(self.cfg) / config_mod.RUNTIME_GENERATION_FILE).unlink()
        with self.crash_between_the_writes():
            self.send()
        self.assertIsNone(peercontrol.recorded_admitted_at(self.cfg))
        self.send()
        self.assertEqual(peercontrol.recorded_admitted_at(self.cfg)[0], gen)
        n, _doc = self.handover(key)
        self.assertTrue(n)


class ProductionShapeTests(_Repoint):
    """R6: with `hop` and a registry (`_is_hop`), as production always has,
    a runtime port anomaly holds the pass named, never a silent retry."""

    def setUp(self):
        super().setUp()
        p = mock.patch.object(inflight, "_is_hop", return_value=True)
        p.start()
        self.addCleanup(p.stop)

    def test_a_sender_method_anomaly_holds_named_in_the_production_shape(self):
        key = self.refused()
        self.send()
        with mock.patch.object(rs.RuntimeSender, "has_result",
                               side_effect=rs.Anomaly("owner", "up/ misowned")):
            got = self.send()
        self.assertEqual(got, {peercontrol.UNAVAILABLE: 1})
        tree = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)["runtime_tree"]
        self.assertIn("owner", (tree.get("unavailable") or {}).get(peercontrol.UNAVAILABLE, {})
                      .get("detail", ""))
        self.assertTrue(self.control(key)["attempt"])


class UnavailableNamedTests(_Repoint):
    """R6: why the tree is unavailable is logged and named in status."""

    def named(self):
        tree = peercontrol.status_doc(self.cfg, self.runtime, now=NOW)["runtime_tree"]
        return ((tree.get("unavailable") or {}).get(peercontrol.UNAVAILABLE) or {}).get("detail", "")

    def test_an_identity_with_another_time_is_named_exists_different(self):
        gen = "e" * 32
        self.tree.admit(gen, OTHER_AT, address=peercontrol.runtime_address(self.cfg))
        peercontrol.record_generation(self.cfg, gen, admitted_at=AT)
        self.refused()
        with self.assertLogs("amap_router_local.peercontrol", level="WARNING") as logs:
            self.send()
        self.assertIn("exists_different", self.named())
        self.assertTrue(any("exists_different" in line for line in logs.output))

    def test_a_missing_pin_is_named(self):
        gen = "e" * 32
        peercontrol.record_generation(self.cfg, gen, admitted_at=AT)
        (peercontrol.runtime_dir(self.cfg) / gen / hoplink.TRANSPORT_DIR / hoplink.PIN_FILE).unlink()
        self.refused()
        self.send()
        self.assertIn("no pinned", self.named())


class HeldPassCleanupTests(_Repoint):
    """R3: the cleanup a settlement owes runs before the held pass's
    early returns, so its residue never blocks retire or new."""

    def residue(self):
        key = self.refused()
        with mock.patch.object(inflight, "advance", side_effect=RuntimeError("crash")):
            self.send()
        gen = self.control(key)["attempt"]["gen"]
        self.tree.gens[gen] = "retired"
        real = inflight._cleanup
        calls = []

        def crash_once(*a, **k):
            calls.append(a)
            if len(calls) == 1:
                raise RuntimeError("crash after the settlement")
            return real(*a, **k)
        with mock.patch.object(peercontrol, "_require_writable"), \
                mock.patch.object(inflight, "_cleanup", crash_once), \
                mock.patch.object(peercontrol, "finish_settled", return_value=0):
            self.send()
        self.assertTrue(self.control(key)["sent"])
        self.assertTrue(peercontrol._inflight_entries(self.cfg, gen), "the residue")
        return key, gen

    def test_closed_admission_still_cleans_up(self):
        key, gen = self.residue()
        from router import peerclock
        peerclock.close(self.state_dir, peerclock.read(self.state_dir), "test")
        got = self.send()
        self.assertIn("held_admission_closed", got)
        self.assertEqual(peercontrol._inflight_entries(self.cfg, gen), [])
        self.assertEqual(peercontrol.unsettled_attempts(self.cfg), [])

    def test_an_untrusted_clock_defers_the_cleanup_to_the_first_trusted_pass(self):
        # The journal is verified by the same clock (`read_meta`), so no
        # settlement can be read while it is untrusted: nothing is removed,
        # and the first trusted pass, held or not, completes it.
        key, gen = self.residue()
        from router import peerclock
        with mock.patch.object(peerclock, "read",
                               side_effect=peerclock.ClockUntrusted("lost")):
            got = self.send()
        self.assertIn("held_clock_untrusted", got)
        self.assertNotIn("settled_cleaned", got)
        self.assertTrue(peercontrol._inflight_entries(self.cfg, gen))
        peerclock.close(self.state_dir, peerclock.read(self.state_dir), "test")
        got = self.send()
        self.assertEqual(got.get("settled_cleaned"), 1)
        self.assertIn("held_admission_closed", got)
        self.assertEqual(peercontrol._inflight_entries(self.cfg, gen), [])
