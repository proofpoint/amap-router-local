"""`service.poll_inputs`: the (keyed cfg, report, gen_keys) one poll runs on,
the four steps `run_once` takes before any pass, factored out so a single
pass can be driven on exactly the inputs production uses.

Pinned here: each of the four steps is taken (the registry report, the
generations applied, the config keyed by identity and generation, the alias
view attached), on a fixture with a registry, generations and an alias
table; `run_once` drains on exactly `poll_inputs`' configuration; and, by
AST, `run_once` calls `poll_inputs` and repeats none of its steps while
`poll_inputs` takes all four and nothing beyond them."""
from __future__ import annotations

import ast
import inspect
import textwrap
from unittest import mock

from router import config as config_mod
from router import outbound, service
from router.tests.test_aliases import _Aliases
from router.tests.test_generations import LIDS

#: The four steps, by the name each call is made under.
STEPS = ("registry_report", "apply", "keyed_config", "keyed", "attach")
#: What poll_inputs must never do.
PASSES = ("drain_instance", "pump_all", "poll", "send_pending", "start_transport")


def _key(fn, cfg, name):
    """`fn(cfg, name)`, or the exception's name: a wrong outcome FAILS."""
    try:
        return fn(cfg, name)
    except Exception as e:  # noqa: BLE001
        return type(e).__name__


def _calls(fn) -> set:
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            out.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None))
    return out


class PollInputsTests(_Aliases):

    def test_each_of_the_four_steps_is_taken(self):
        inputs = service.poll_inputs(self.cfg)
        cfg, report, gen_keys = inputs                      # unpacks as the triple
        self.assertEqual(report.state, "ok", "the registry report")
        self.assertTrue(gen_keys, "the generations applied")
        self.assertEqual(_key(config_mod.state_key, cfg, "alpha"), LIDS["alpha"],
                         "keyed by the registry identity")
        self.assertEqual(_key(config_mod.gen_key, cfg, "alpha"), gen_keys.get("alpha"),
                         "keyed by the current generation")
        self.assertIsNotNone(cfg.alias_view, "the alias view attached")

    def test_given_report_and_generation_keys_are_used_not_recomputed(self):
        first = service.poll_inputs(self.cfg)
        with mock.patch.object(service, "registry_report",
                               side_effect=AssertionError("recomputed")):
            again = service.poll_inputs(self.cfg, report=first.report,
                                        gen_keys=first.gen_keys)
        self.assertIs(again.report, first.report)
        self.assertEqual(again.gen_keys, first.gen_keys)

    def test_run_once_consumes_exactly_the_poll_inputs_it_got(self):
        """Every downstream consumer gets the very objects poll_inputs
        returned: the drain its cfg, the inbound pump its cfg AND its report
        (object identity, so no re-derived or altered value can pass)."""
        from router import hoplink, ingress
        got, drained, pumped = [], [], []
        real = service.poll_inputs

        def capture(*a, **k):
            got.append(real(*a, **k))
            return got[-1]
        with mock.patch.object(service, "poll_inputs", capture), \
                mock.patch.object(outbound, "drain_instance",
                                  lambda cfg, name, **kw: drained.append(cfg) or {}), \
                mock.patch.object(hoplink, "is_runtime", return_value=True), \
                mock.patch.object(ingress, "pump_all",
                                  lambda cfg, transport, report: pumped.append((cfg, report)) or {}):
            service.run_once(self.cfg, None)
        self.assertEqual(len(got), 1, "poll_inputs called once")
        self.assertTrue(drained and pumped, "both consumers ran")
        self.assertTrue(all(c is got[0].cfg for c in drained), "the drain's cfg")
        self.assertIs(pumped[0][0], got[0].cfg, "the pump's cfg")
        self.assertIs(pumped[0][1], got[0].report, "the pump's report")

    def test_run_once_drains_on_exactly_poll_inputs_configuration(self):
        seen = []
        real = outbound.drain_instance

        def drain(cfg, name, **kw):
            seen.append(cfg)
            return real(cfg, name, **kw)
        with mock.patch.object(outbound, "drain_instance", drain):
            self.poll()
        self.assertTrue(seen, "run_once drained something")
        inputs = service.poll_inputs(self.cfg)
        for name in ("alpha", "bravo"):
            with self.subTest(name=name):
                self.assertEqual(config_mod.state_key(seen[0], name),
                                 config_mod.state_key(inputs.cfg, name))
                self.assertEqual(config_mod.gen_key(seen[0], name),
                                 config_mod.gen_key(inputs.cfg, name))
        self.assertEqual(seen[0].alias_view is None, inputs.cfg.alias_view is None)
        self.assertEqual(seen[0].aliases, inputs.cfg.aliases)


class SendControlPendingTests(_Aliases):

    def test_the_wrapper_passes_its_arguments_and_returns_the_result_unchanged(self):
        from router import peercontrol
        result = {"runtime_tree_unavailable": 2}
        transport, delegation, now = object(), object(), object()
        with mock.patch.object(peercontrol, "send_pending", return_value=result) as sp:
            got = service.send_control_pending(self.cfg, transport, delegation=delegation, now=now)
        self.assertIs(got, result)
        sp.assert_called_once_with(self.cfg, transport, delegation=delegation, now=now)

    def run_twin(self, call):
        """One fresh fixture with one pending control notice, the pass run
        through `call`, every random mint pinned: (result, the record's
        control member as canonical bytes)."""
        import json
        from router import peercontrol
        from router.tests import test_peercontrol as tpc
        case = tpc.AttemptTests("test_the_request_shape")
        case.setUp()
        self.addCleanup(case.doCleanups)
        key = case.refused()
        with mock.patch.object(peercontrol, "_mint_id", return_value="qTwin0123456789abcdefgh"), \
                mock.patch.object(peercontrol.secrets, "token_hex", return_value="c" * 32):
            result = call(case.cfg, case.runtime, delegation=case.signing, now=tpc.NOW)
        control = case.record(key)["control"]
        return result, json.dumps(control, sort_keys=True).encode("utf-8")

    def test_its_result_and_record_effects_are_the_direct_calls(self):
        from router import peercontrol
        direct = self.run_twin(peercontrol.send_pending)
        wrapped = self.run_twin(service.send_control_pending)
        self.assertEqual(wrapped[0], direct[0], "the same result")
        self.assertEqual(wrapped[1], direct[1], "the same record bytes")
        self.assertIn(b'"attempt"', direct[1], "the pass did take the attempt")


class StructureTests(_Aliases):

    def test_poll_inputs_takes_no_transport(self):
        params = inspect.signature(service.poll_inputs).parameters
        self.assertNotIn("transport", params, "the glue needs no transport")

    def test_run_once_reaches_send_pending_only_through_the_wrapper(self):
        calls = _calls(service.run_once)
        self.assertIn("send_control_pending", calls)
        self.assertNotIn("send_pending", calls)


    def test_run_once_calls_poll_inputs_and_repeats_none_of_its_steps(self):
        calls = _calls(service.run_once)
        self.assertIn("poll_inputs", calls)
        self.assertEqual(calls & set(STEPS), set(), "the glue is not repeated")

    def test_poll_inputs_takes_the_four_steps_and_nothing_else(self):
        calls = _calls(service.poll_inputs)
        self.assertEqual(set(STEPS) - calls, set(), "every step")
        self.assertEqual(calls & set(PASSES), set(), "no drain, pump or poll")
