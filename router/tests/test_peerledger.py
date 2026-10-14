"""The peer ledger's placed direction, the one resolution, and the decide
hooks built by `peerpolicy` (the receiver's deny, reply and edge, and the
profile-factory seam every pass entry builds its hooks through)."""
from __future__ import annotations

import ast
import dataclasses
import json
import pathlib
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import router
from router import config as config_mod
from router import peerjournal, peerlane, peerledger, peerpolicy
from router.tests.test_peerbind import FD, KEY_ID, T1, T2, _Base

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
LATER = "2026-10-20T00:00:00Z"
EARLIER = "2026-10-13T11:00:00Z"
PLANNER = f"planner@{T1}"
BOB = f"bob@{FD}"
ROUTER = pathlib.Path(router.__file__).parent


class _Ledger(_Base):

    def issued(self, rid, *, remote=PLANNER, local="bob", address=BOB, expires=LATER):
        peerlane.write_issued(self.cfg, peerlane.issued_record(
            peer_id=rid, logical_id=local, local_address=address, remote=remote,
            generation="g" * 32, expires_at=expires))

    def placed(self, rid, *, remote=PLANNER, local="bob", address=BOB, expires=LATER):
        return peerledger.write_placed(self.cfg, peerledger.placed_record(
            record_id=rid, logical_id=local, local_address=address, remote=remote,
            generation="g" * 32, expires_at=expires))

    def try_placed(self, rid, **kw):
        """`placed`'s result, or the exception's class name: a wrong outcome
        is then an assertion failure, never an error."""
        try:
            return self.placed(rid, **kw)
        except Exception as e:  # noqa: BLE001
            return type(e).__name__

    def refused(self, record):
        try:
            peerledger.write_placed(self.cfg, record)
        except ValueError:
            return True
        except Exception:  # noqa: BLE001 -- any other failure is not the refusal
            return False
        return False

    def resolve(self, rid, *, remote=PLANNER, local="bob", address=BOB, now=NOW):
        return peerledger.resolve(self.cfg, in_reply_to=rid, local_logical_id=local,
                                  local_address=address, remote=remote, now=now)


class PlacedRecordTests(_Ledger):

    def test_two_remotes_with_the_same_id_get_their_own_records(self):
        other = f"planner@{T2}"
        self.assertEqual(self.try_placed("same-id", remote=PLANNER), "created")
        self.assertEqual(self.try_placed("same-id", remote=other), "created")
        self.assertIsInstance(self.resolve("same-id", remote=PLANNER), peerledger.Resolved)
        self.assertEqual(self.resolve("same-id", remote=other).record["remote"], other)
        self.assertNotEqual(peerledger.placed_path(self.state_dir, "bob", PLANNER, "same-id"),
                            peerledger.placed_path(self.state_dir, "bob", other, "same-id"))

    def test_a_retry_with_identical_bytes_is_accepted_and_different_bytes_conflict(self):
        self.placed("rid")
        self.assertEqual(self.placed("rid"), "exists_same")
        with self.assertRaises(peerledger.LedgerConflict):
            self.placed("rid", expires=EARLIER)

    def test_the_record_is_closed_and_the_id_is_the_statement_grammar(self):
        rec = peerledger.placed_record(record_id="0123456789abcdef" * 2, logical_id="bob",
                                       local_address=BOB, remote=PLANNER, generation="g",
                                       expires_at=LATER)
        self.assertEqual(peerledger.write_placed(self.cfg, rec), "created")
        self.assertTrue(self.refused(dict(rec, extra="x")), "an extra member")
        self.assertTrue(self.refused(dict(rec, id="a/b")), "an id outside the grammar")
        self.assertTrue(self.refused(dict(rec, direction="issued")), "the other direction")

    def test_the_remote_is_keyed_canonically(self):
        self.placed("rid", remote=f"planner@{T1.upper()}")
        self.assertIsInstance(self.resolve("rid", remote=PLANNER), peerledger.Resolved)
        self.assertIsInstance(self.resolve("rid", remote=f"planner@{T1.upper()}"),
                              peerledger.Resolved, "the lookup is keyed canonically too")
        self.assertIsNone(self.resolve("rid", remote=f"Planner@{T1}"),
                          "the local part compares exactly")


class ResolveTests(_Ledger):

    def test_both_directions_resolve_with_their_direction(self):
        self.issued("issued-1")
        self.placed("placed-1")
        self.assertEqual(self.resolve("issued-1").direction, "issued")
        self.assertEqual(self.resolve("placed-1").direction, "placed")

    def test_each_participant_mismatch_is_unresolved(self):
        self.issued("r1")
        self.assertIsNone(self.resolve("r1", remote=f"other@{T1}"), "wrong remote")
        self.assertIsNone(self.resolve("r1", address=f"carol@{FD}"), "wrong local address")
        self.assertIsNone(self.resolve("r1", local="carol"), "another agent's ledger")
        self.assertIsNone(self.resolve("absent"), "no record")

    def test_an_expired_record_is_expired_not_resolved(self):
        self.issued("old", expires="2026-10-13T12:00:00Z")
        self.assertIsInstance(self.resolve("old"), peerledger.Expired)
        self.assertIsInstance(self.resolve("old", now=NOW - timedelta(seconds=1)),
                              peerledger.Resolved)

    def test_an_id_in_both_namespaces_is_unresolved(self):
        self.issued("both")
        self.placed("both")
        self.assertIsNone(self.resolve("both"))
        self.assertIsNone(self.resolve("both", remote=None))

    def test_at_submit_two_placed_matches_are_unresolved_and_one_resolves(self):
        self.placed("twice", remote=PLANNER)
        self.placed("twice", remote=f"planner@{T2}")
        self.assertIsNone(self.resolve("twice", remote=None))
        self.placed("once", remote=PLANNER)
        got = self.resolve("once", remote=None)
        self.assertIsInstance(got, peerledger.Resolved)
        self.assertEqual(got.record["remote"], PLANNER)

    def test_a_foreign_shaped_id_resolves_and_a_mail_notice_id_never_does(self):
        self.issued("0123456789abcdef" * 2)
        self.assertIsInstance(self.resolve("0123456789abcdef" * 2), peerledger.Resolved)
        # A mail delivery ledger record under the same logical_id is a
        # different store: never a peer resolution.
        mail = self.state_dir / "bob" / "ledger" / ("notice-" + "c" * 32 + ".json")
        mail.parent.mkdir(parents=True, exist_ok=True)
        mail.write_text(json.dumps({"notice_id": "c" * 32}))
        self.assertIsNone(self.resolve("c" * 32))
        self.assertIsNone(self.resolve("notice-" + "c" * 32))


def payload(**over):
    doc = {"v": 1, "key_id": KEY_ID, "kind": "peer", "id": "s" * 23, "from": PLANNER,
           "to": BOB, "ts": "2026-10-13T11:59:00Z"}
    doc.update(over)
    return doc


class _Hooks(_Ledger):

    def ctx(self, *, cfg=None, state_dir=None, delegation=None, now=NOW, clock=None):
        return peerpolicy.hook_context(cfg or self.cfg,
                                       delegation=delegation or types.SimpleNamespace(config=self.dc),
                                       state_dir=state_dir or self.state_dir, now=now,
                                       clock=clock if clock is not None else object())

    def production(self, **kw):
        return peerpolicy.production_hooks(self.ctx(**kw))

    def conformance(self, pairs=(), **kw):
        return peerpolicy.decide_hooks(peerpolicy.conformance_profile(self.ctx(**kw), None, pairs))

    def deny(self, *entries):
        inst = dataclasses.replace(self.cfg.instances["bob"], task_deny=tuple(entries))
        self.cfg = dataclasses.replace(self.cfg, instances={**self.cfg.instances, "bob": inst})


def outcome(out):
    if isinstance(out, peerjournal.Refuse):
        return ("refuse", out.cause, out.policy_code)
    if isinstance(out, peerjournal.Hold):
        return ("hold", out.reason, out.detail)
    if isinstance(out, peerjournal.Resolved):
        return ("resolved", out.in_reply_to)
    return out


class DenyReplyEdgeTests(_Hooks):

    def test_a_deny_refuses_policy_denied_on_every_path(self):
        self.deny(PLANNER)
        self.issued("issued-1")
        hk = self.production()
        for label, p in (("fresh task", payload()),
                         ("reverse result", payload(in_reply_to="issued-1")),
                         ("unresolvable reply", payload(in_reply_to="nowhere"))):
            with self.subTest(label):
                self.assertEqual(outcome(hk.reply(p, "bob")), ("refuse", "policy", "denied"))

    def test_the_deny_uses_the_submit_sides_skeleton_match(self):
        self.deny(f"Planner@{T1}")
        self.assertEqual(outcome(self.production().reply(payload(), "bob")),
                         ("refuse", "policy", "denied"))

    def test_reply_resolves_or_refuses_unresolved(self):
        self.issued("issued-1")
        hk = self.production()
        self.assertEqual(outcome(hk.reply(payload(), "bob")), ("resolved", None))
        self.assertEqual(outcome(hk.reply(payload(in_reply_to="issued-1"), "bob")),
                         ("resolved", "issued-1"))
        self.assertEqual(outcome(hk.reply(payload(in_reply_to="nowhere"), "bob")),
                         ("refuse", "unresolved_reply", None))

    def test_a_reverse_result_needs_no_edge_and_anything_else_does(self):
        self.issued("issued-1")
        self.placed("placed-1")
        hk = self.conformance(pairs=())
        self.assertIsNone(hk.edge(payload(in_reply_to="issued-1"), "bob"))
        self.assertEqual(outcome(hk.edge(payload(in_reply_to="placed-1"), "bob")),
                         ("refuse", "no_edge", None))
        self.assertEqual(outcome(hk.edge(payload(), "bob")), ("refuse", "no_edge", None))

    def test_a_conformance_pair_is_an_edge_and_an_absent_one_is_no_edge(self):
        hk = self.conformance(pairs=[(PLANNER, BOB)])
        self.assertIsNone(hk.edge(payload(), "bob"))
        self.assertEqual(outcome(hk.edge(payload(**{"from": f"other@{T1}"}), "bob")),
                         ("refuse", "no_edge", None))

    def test_the_production_edge_is_the_trusted_host_default(self):
        hk = self.production()
        self.assertIsNone(hk.edge(payload(), "bob"))
        self.assertEqual(outcome(hk.edge(payload(**{"from": "planner@elsewhere.example"}), "bob")),
                         ("refuse", "no_edge", None))


class BuilderTests(_Hooks):

    def test_production_holds_every_statement_at_check8_and_policy(self):
        hk = self.production()
        self.assertEqual(outcome(hk.check8(payload(), KEY_ID)), ("hold", "hook_absent", "check8"))
        self.assertEqual(outcome(hk.policy(payload(), "bob")), ("hold", "hook_absent", "policy"))

    def test_production_hooks_is_decide_hooks_of_the_production_profile(self):
        self.issued("issued-1")
        ctx = self.ctx()
        a = peerpolicy.production_hooks(ctx)
        b = peerpolicy.decide_hooks(peerpolicy.production_profile(ctx))
        self.assertIs(a.context, ctx)
        for p in (payload(), payload(in_reply_to="issued-1"), payload(in_reply_to="x"),
                  payload(**{"from": "planner@elsewhere.example"})):
            with self.subTest(p=p):
                self.assertEqual(outcome(a.check8(p, KEY_ID)), outcome(b.check8(p, KEY_ID)))
                for m in ("reply", "edge", "policy"):
                    self.assertEqual(outcome(getattr(a, m)(p, "bob")),
                                     outcome(getattr(b, m)(p, "bob")))
                self.assertEqual(outcome(a.control_receive(None, None)),
                                 outcome(b.control_receive(None, None)))

    def test_conformance_differs_only_in_the_policy_and_edge_members(self):
        self.issued("issued-1")
        prod, conf = self.production(), self.conformance(pairs=[])
        probes = (payload(), payload(in_reply_to="issued-1"), payload(in_reply_to="x"))
        for p in probes:
            self.assertEqual(outcome(prod.reply(p, "bob")), outcome(conf.reply(p, "bob")))
            self.assertEqual(outcome(prod.control_receive(None, None)),
                             outcome(conf.control_receive(None, None)))
        self.assertNotEqual(outcome(prod.policy(payload(), "bob")),
                            outcome(conf.policy(payload(), "bob")))
        self.assertNotEqual(outcome(prod.check8(payload(), KEY_ID)),
                            outcome(conf.check8(payload(), KEY_ID)))
        self.assertNotEqual(outcome(prod.edge(payload(), "bob")),
                            outcome(conf.edge(payload(), "bob")))

    def test_two_contexts_resolve_only_in_their_own_ledger(self):
        self.issued("only-in-a")
        other = self.state_dir.parent / "other-state"
        other.mkdir()
        cfg_b = dataclasses.replace(self.cfg, state_dir=other)
        in_a, in_b = self.production(), self.production(cfg=cfg_b, state_dir=other)
        p = payload(in_reply_to="only-in-a")
        self.assertEqual(outcome(in_a.reply(p, "bob")), ("resolved", "only-in-a"))
        self.assertEqual(outcome(in_b.reply(p, "bob")), ("refuse", "unresolved_reply", None))

    def test_every_part_must_be_data(self):
        ctx = self.ctx()
        for label, prof in (
                ("callable edge", peerpolicy.Profile(ctx, lambda *_a: None, peerpolicy.HOLD)),
                ("callable policy", peerpolicy.Profile(ctx, peerpolicy.TRUSTED_HOST_DEFAULT,
                                                       lambda *_a: None)),
                ("a set of non-pairs", peerpolicy.Profile(ctx, frozenset({"x"}), peerpolicy.HOLD)),
                ("a foreign context", peerpolicy.Profile(object(), peerpolicy.TRUSTED_HOST_DEFAULT,
                                                         peerpolicy.HOLD))):
            with self.subTest(label):
                with self.assertRaises(TypeError):
                    peerpolicy.decide_hooks(prof)


class ContextBindingTests(_Hooks):

    def build_ctx(self, hooks, *, clock, now=NOW, delegation):
        return peerjournal.Ctx(state_dir=self.state_dir, cfg=self.cfg, delegation=delegation,
                               hooks=hooks, now=now, clock=clock, view=None, effects=None,
                               retired=lambda _r: False)

    def test_hooks_bound_to_this_pass_are_accepted_and_any_other_refused(self):
        delegation, clock = types.SimpleNamespace(config=self.dc), object()
        hooks = peerpolicy.production_hooks(self.ctx(delegation=delegation, clock=clock))
        self.build_ctx(hooks, clock=clock, delegation=delegation)
        for label, kw in (("another clock", dict(clock=object(), delegation=delegation)),
                          ("another now", dict(clock=clock, delegation=delegation,
                                               now=NOW + timedelta(0))),
                          ("another delegation", dict(clock=clock,
                                                      delegation=types.SimpleNamespace(config=self.dc)))):
            with self.subTest(label):
                with self.assertRaises(TypeError):
                    self.build_ctx(hooks, **kw)


class PassFactoryTests(unittest.TestCase):
    """The factory seam, at `peerjournal._pass_hooks`, the one place every
    pass entry builds its hooks."""

    def test_the_factory_gets_this_pass_context_and_must_return_it(self):
        cfg, delegation, clock = object(), object(), object()
        seen = []

        def probe(hctx):
            seen.append(hctx)
            return peerpolicy.production_profile(hctx)
        hooks = peerjournal._pass_hooks(cfg, delegation=delegation, state_dir=pathlib.Path("/x"),
                                        now=NOW, clock=clock, profile_factory=probe)
        [hctx] = seen
        self.assertIs(hooks.context, hctx)
        self.assertIs(hctx.clock, clock)
        self.assertIs(hctx.now, NOW)
        self.assertIs(hctx.cfg, cfg)
        with self.assertRaises(TypeError):
            peerjournal._pass_hooks(cfg, delegation=delegation, state_dir=pathlib.Path("/x"),
                                    now=NOW, clock=clock,
                                    profile_factory=lambda h: peerpolicy.production_profile(
                                        peerpolicy.hook_context(cfg, delegation=delegation,
                                                                state_dir="/x", now=NOW,
                                                                clock=clock)))

    def test_no_factory_is_production(self):
        hooks = peerjournal._pass_hooks(object(), delegation=object(), state_dir=pathlib.Path("/x"),
                                        now=NOW, clock=object(), profile_factory=None)
        self.assertEqual(outcome(hooks.policy(payload(), "bob")), ("hold", "hook_absent", "policy"))


class ForwardingTests(unittest.TestCase):
    """`poll` forwards the factory it was given, unchanged, into every
    nested pass entry, which build their hooks over poll's own clock."""

    def test_poll_forwards_the_identical_factory_and_its_clock(self):
        import inspect
        src = inspect.getsource(peerjournal.poll)
        tree = ast.parse(src)
        nested = {"poll_generation", "poll_host", "recover"}
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", None) in nested]
        self.assertEqual({c.func.id for c in calls}, nested, "every nested entry is called")
        for c in calls:
            with self.subTest(entry=c.func.id):
                kw = {k.arg: k.value for k in c.keywords}
                self.assertIn("profile_factory", kw)
                self.assertIsInstance(kw["profile_factory"], ast.Name)
                self.assertEqual(kw["profile_factory"].id, "profile_factory")
                self.assertEqual(getattr(kw.get("clock"), "id", None), "clock")


class SeamRulesTests(unittest.TestCase):

    def modules(self):
        return sorted(p for p in ROUTER.glob("*.py"))

    def test_no_module_outside_peerjournal_passes_a_profile_factory(self):
        bad = []
        for path in self.modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    for k in n.keywords:
                        if k.arg != "profile_factory":
                            continue
                        ok = (path.name == "peerjournal.py" and isinstance(k.value, ast.Name)
                              and k.value.id == "profile_factory")
                        if not ok:
                            bad.append(f"{path.name}:{n.lineno}")
        self.assertEqual(bad, [])

    def test_the_entry_definitions_carry_it_as_a_parameter(self):
        params = {f: {a.arg for a in getattr(peerjournal, f).__code__.co_varnames[:0]} for f in ()}
        import inspect
        for f in ("poll", "poll_generation", "poll_host", "recover"):
            with self.subTest(entry=f):
                self.assertIn("profile_factory", inspect.signature(getattr(peerjournal, f)).parameters)
                self.assertNotIn("hooks", inspect.signature(getattr(peerjournal, f)).parameters)

    def test_no_router_module_builds_a_conformance_profile(self):
        bad = []
        for path in self.modules():
            if path.name == "peerpolicy.py":
                continue
            for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(n, (ast.Name, ast.Attribute)) and \
                        getattr(n, "attr", getattr(n, "id", None)) in ("conformance_profile",
                                                                        "conformance_edges"):
                    bad.append(f"{path.name}:{n.lineno}")
        self.assertEqual(bad, [])

    def test_the_hook_modules_hold_no_mutable_state_and_read_no_clock(self):
        for name in ("peerpolicy.py", "peerledger.py"):
            tree = ast.parse((ROUTER / name).read_text(encoding="utf-8"))
            with self.subTest(module=name):
                for st in tree.body:
                    if isinstance(st, (ast.Assign, ast.AnnAssign)):
                        value = st.value
                        self.assertNotIsInstance(value, (ast.List, ast.Dict, ast.Set, ast.ListComp,
                                                         ast.DictComp, ast.SetComp),
                                                 f"{name}:{st.lineno} module-level mutable state")
                        if isinstance(value, ast.Call):
                            self.assertNotIn(getattr(value.func, "id", None),
                                             ("list", "dict", "set", "defaultdict"),
                                             f"{name}:{st.lineno} module-level mutable state")
                for n in ast.walk(tree):
                    if isinstance(n, ast.Attribute) and n.attr == "now" \
                            and isinstance(n.value, ast.Name) and n.value.id == "clock":
                        self.fail(f"{name}:{n.lineno} reads the clock")


from router.tests import test_peerevaluate as tpe  # noqa: E402


class PlacedBeforeNoticeTests(tpe._Eval):
    """A placed statement's `placed` record is durable before its notice."""

    def placed_record(self):
        from router.tests.test_peerbind import STATEMENT_ID
        lid = config_mod.state_key(self.cfg, "bob")
        return peerledger.read_placed(self.state_dir, lid, PLANNER, STATEMENT_ID)

    def test_the_placed_record_exists_when_the_notice_is_written(self):
        from router import deliver
        seen = []
        real = deliver.deliver_signed_peer

        def spy(*a, **kw):
            seen.append(self.placed_record())
            return real(*a, **kw)
        with mock.patch.object(deliver, "deliver_signed_peer", spy):
            rec = self.evaluate(self.take(self.raw()))
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"))
        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0], "no placed record when the notice was written")
        self.assertEqual((seen[0]["direction"], seen[0]["remote"], seen[0]["local_address"]),
                         ("placed", PLANNER, BOB))

    def test_a_crash_between_placed_and_the_notice_places_once(self):
        from router import deliver
        key = self.take(self.raw())
        with mock.patch.object(deliver, "deliver_signed_peer", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.evaluate(key)
        self.assertIsNotNone(self.placed_record())
        self.assertEqual(self.notices(), [])
        rec = self.evaluate(key)
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"))
        self.assertEqual(len(self.notices()), 1)


class FactoryThroughAPassTests(tpe._Polling):
    """A conformance factory handed to a pass entry decides with its edges."""

    def poll_with(self, factory, port):
        from router import peerclock
        return peerjournal.poll_generation(
            self.cfg, delegation=self.lane, profile_factory=factory,
            clock=peerclock.advance(self.state_dir, tpe.NOW), now=tpe.NOW, logical_id=tpe.OWNER,
            gen=tpe.GEN, link="hub", reader=types.SimpleNamespace(port=port),
            remover=tpe.FakeRemover(port), retired=lambda _r: False)

    def test_an_absent_pair_is_no_edge_and_a_present_one_places(self):
        no_pairs = lambda h: peerpolicy.conformance_profile(h, None, [])  # noqa: E731
        port = tpe.FakePort({"c1": self.raw()})
        self.poll_with(no_pairs, port)
        rec = peerjournal.read_record(self.state_dir, tpe.OWNER, self.key("c1"))
        self.assertEqual((rec["disposed"], rec["cause"]), ("refused", "no_edge"))
        pairs = lambda h: peerpolicy.conformance_profile(h, None, [(PLANNER, BOB)])  # noqa: E731
        port = tpe.FakePort({"c2": self.raw(id="qB2c3D4e5F6g7H8i9J0kLmx")})
        self.poll_with(pairs, port)
        rec = peerjournal.read_record(self.state_dir, tpe.OWNER, self.key("c2"))
        self.assertEqual(rec["disposed"], "placed")

    def test_the_production_default_holds_at_check8(self):
        port = tpe.FakePort({"c1": self.raw()})
        self.poll_with(None, port)
        rec = peerjournal.read_record(self.state_dir, tpe.OWNER, self.key("c1"))
        self.assertEqual((rec["hold"] or {}).get("reason"), "hook_absent")


if __name__ == "__main__":
    unittest.main()
