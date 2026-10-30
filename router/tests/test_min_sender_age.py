"""ENROL-AGE-CONFIG: `min_sender_age_s`, one sender-age duration for every
enforcing path and every reporting surface (design d8; contract §8.6 as
amended by E30).

Each class pins one claim on the surface only its producer reaches:

  * LoadTests — the config key's shape, on `config.min_sender_age_s`'s own
    refusal message.
  * DivergenceTests — ONE cfg value drives item 5c, the pre-publication
    re-check and the receiver's policy hook, at non-default values (a
    default-reading mutant passes at the default and fails here).
  * ReportedTests — what the operator and a fleet check SEE (startup line,
    status.json, `status` text, console) is the value ENFORCED, never the
    default filled in.
  * ZeroTests / SkewTests — 0 is an active zero-second policy, and a future
    `sender_since` is refused at every value, 0 included.
  * ReloadTests — restart-only, by effective value.
  * DigestVectorTests — the D2 digest against literal known answers.
  * StructuralTests — a tripwire against a reintroduced 86400 literal; the
    behavioural tests above, not this, are the proof.
  * DeployedValueTests — the production receiver path at the deployed value
    (E30 r4 clause 5: suite evidence at the ACTUAL V), plus supporting
    values. Set AMAP_M1_SENDER_AGE_V to the render-go integer to add it.
"""
import ast
import dataclasses
import hashlib
import json
import logging
import os
import types
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import router
from router import classify, config as config_mod, console, outbound, peerjournal, peerpolicy
from router import service, status as status_mod
from router.config import ConfigError, load_obj
from router.tests import helpers
from router.tests import test_classify as tcl
from router.tests import test_peer_policy_e2e as te2e
from router.tests import test_peerepochs as tep
from router.tests import test_peerlane as tpl
from router.tests.helpers import write_request
from router.util import format_utc_ts, parse_utc_ts, utc_ts

DEFAULT = config_mod.MIN_SENDER_AGE_S_DEFAULT
MAX = config_mod.MIN_SENDER_AGE_S_MAX
#: Non-default values first: a mutant that reads the default instead of the
#: config passes at 86400 and must fail at 300.
VALUES = (300, 1, 7200, DEFAULT, MAX)
VECTORS = Path(__file__).parent / "vectors" / "sender_age_policy_digest.json"
WARNING_TEXT = ("sender-age gate allows ages >= {v}s; this is below the 86400s release "
                "default; other policy checks still apply")


def _ago(now: str, seconds: int) -> str:
    return format_utc_ts(parse_utc_ts(now) - timedelta(seconds=seconds))


# ---------------------------------------------------------------------------
# The config key
# ---------------------------------------------------------------------------

class LoadTests(helpers.RouterTestCase):

    def load(self, **top):
        return tcl.make_cfg(self, top=top)

    def refused(self, value):
        with self.assertRaises(ConfigError) as cm:
            self.load(min_sender_age_s=value)
        self.assertIn("config.min_sender_age_s", str(cm.exception))

    def test_absent_is_86400(self):
        cfg = self.load()
        self.assertEqual(cfg.min_sender_age_s, 86400)
        # The default is also the ENFORCED boundary, not just a stored number.
        self.assertIsNotNone(classify.sender_age_refusal(
            tcl.with_age(cfg, _ago(tcl.NOW, 86399)), "alice", tcl.NOW))
        self.assertIsNone(classify.sender_age_refusal(
            tcl.with_age(cfg, _ago(tcl.NOW, 86400)), "alice", tcl.NOW))

    def test_accepted_values(self):
        for v in (0, 1, 300, DEFAULT):
            with self.subTest(v=v):
                self.assertEqual(self.load(min_sender_age_s=v).min_sender_age_s, v)

    def test_max_accepted(self):
        self.assertEqual(self.load(min_sender_age_s=31536000).min_sender_age_s, 31536000)

    def test_above_max_refused(self):
        self.refused(31536001)

    def test_bool_refused(self):
        for v in (True, False):
            with self.subTest(v=v):
                self.refused(v)

    def test_negative_refused(self):
        self.refused(-1)

    def test_float_refused(self):
        for v in (0.0, 86400.0, 300.5, float("nan"), float("inf")):
            with self.subTest(v=v):
                self.refused(v)

    def test_string_and_null_refused(self):
        for v in ("0", "86400", None):
            with self.subTest(v=v):
                self.refused(v)

    def test_a_delegation_member_cannot_set_it(self):
        # The top-level key is the ONLY way: inside `delegation` the overlay
        # guard refuses it, on its own message (contract §8.8 as worded).
        base = tpl.DelegationConfigTests("run")
        base.tmp, base.state_dir = self.tmp, self.state_dir
        doc = tpl.DelegationConfigTests.doc(base, min_sender_age_s=0)
        with self.assertRaises(ConfigError) as cm:
            load_obj(doc)
        self.assertIn("set only by the top-level min_sender_age_s", str(cm.exception))


# ---------------------------------------------------------------------------
# One value, every enforcing path
# ---------------------------------------------------------------------------

class SenderDivergenceTests(helpers.RouterTestCase):

    def test_sender_5c_tracks_cfg(self):
        base = tcl.make_cfg(self)
        for v in VALUES:
            with self.subTest(v=v):
                cfg = dataclasses.replace(base, min_sender_age_s=v)
                young = classify.sender_age_refusal(
                    tcl.with_age(cfg, _ago(tcl.NOW, v - 1)), "alice", tcl.NOW)
                self.assertEqual(young, f"the sender registered {v - 1}s ago, under {v}s")
                self.assertIsNone(classify.sender_age_refusal(
                    tcl.with_age(cfg, _ago(tcl.NOW, v)), "alice", tcl.NOW))


class RecheckDivergenceTests(tpl._Send):
    """The pre-publication re-check (`outbound._recheck_peer`) reads the same
    effective cfg value. Ages are taken against the REAL clock, which the
    re-check uses, with a margin of 60 s either side of the threshold."""

    def stage(self, cfg):
        write_request(cfg, "alice", "00000001", to=[tpl.TRUSTED])
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.assertEqual(self.port.writes, [])

    def test_recheck_tracks_cfg(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.stage(cfg)
        now = utc_ts()
        # 300 s threshold, sender 360 s old: published at 300, but a
        # default-reading re-check (86400) would refuse it.
        at = tcl.with_age(dataclasses.replace(cfg, min_sender_age_s=300), _ago(now, 360))
        self.drain(at)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_recheck_refuses_under_the_cfg_threshold(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.stage(cfg)
        now = utc_ts()
        at = tcl.with_age(dataclasses.replace(cfg, min_sender_age_s=7200), _ago(now, 3600))
        self.drain(at)
        self.assertEqual(self.port.writes, [])
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"], r["detail"]),
                         ("queued_for_human", "recipient_not_allowlisted",
                          "policy changed before publication: now peer_quarantined"))


class ReceiverDivergenceTests(tep._Epochs):
    """The receiver's production profile, built by `production_profile` from
    the pass's cfg: the SAME cfg field item 5c reads."""

    def production_decide(self, cfg, p):
        clock = peerjournal.peerclock.read(self.state_dir)
        hctx = peerpolicy.hook_context(cfg, delegation=self.lane, state_dir=self.state_dir,
                                       now=tep.NOW, clock=clock)
        out = peerpolicy.decide_hooks(peerpolicy.production_profile(hctx)).policy(
            p, "bob", tep.RUNTIME)
        if isinstance(out, peerjournal.Refuse):
            return out.policy_code
        if isinstance(out, peerjournal.Hold):
            return ("hold", out.reason)
        return out

    def test_receiver_tracks_cfg(self):
        for i, v in enumerate(VALUES):
            with self.subTest(v=v):
                cfg = dataclasses.replace(self.cfg, min_sender_age_s=v)
                self.assertEqual(peerpolicy.production_policy(cfg),
                                 peerpolicy.PolicyPart(exposure_required=True,
                                                       min_sender_age_s=v))
                young, old = f"young{i}@{tep.T1}", f"old{i}@{tep.T1}"
                self.assertEqual(self.production_decide(cfg, tep.payload(
                    sender_since=tep.ts(-(v - 1)), sender_exposure=tep.EXPOSED,
                    **{"from": young})), "quarantined")
                self.assertIsNone(self.production_decide(cfg, tep.payload(
                    sender_since=tep.ts(-v), sender_exposure=tep.EXPOSED,
                    **{"from": old})))


# ---------------------------------------------------------------------------
# Zero is active; a future sender_since is refused at every value
# ---------------------------------------------------------------------------

class SenderZeroTests(helpers.RouterTestCase):

    def test_zero_is_kept(self):
        cfg = tcl.make_cfg(self, top={"min_sender_age_s": 0})
        self.assertEqual(cfg.min_sender_age_s, 0)
        # A just-registered sender passes at 0 (and would not at the default).
        self.assertIsNone(classify.sender_age_refusal(
            tcl.with_age(cfg, tcl.NOW), "alice", tcl.NOW))

    def test_zero_still_refuses_unknown_and_future(self):
        cfg = tcl.make_cfg(self, top={"min_sender_age_s": 0})
        self.assertEqual(classify.sender_age_refusal(tcl.with_age(cfg, None), "alice", tcl.NOW),
                         "sender age unknown")
        self.assertEqual(classify.sender_age_refusal(
            tcl.with_age(cfg, _ago(tcl.NOW, -1)), "alice", tcl.NOW),
            "the sender's first_registered_ts is in the future")


class ReceiverZeroTests(ReceiverDivergenceTests):

    def zero(self):
        return dataclasses.replace(self.cfg, min_sender_age_s=0)

    def test_receiver_zero_still_requires_sender_since(self):
        self.assertEqual(self.production_decide(self.zero(), tep.payload(
            sender_exposure=tep.EXPOSED)), "sender_age_missing")

    def test_receiver_zero_consults_epochs(self):
        cfg = self.zero()
        self.assertEqual(self.epoch_files(), [])
        self.assertIsNone(self.production_decide(cfg, tep.payload(
            sender_since=tep.ts(-60), sender_exposure=tep.EXPOSED)))
        self.assertEqual(len(self.epoch_files()), 1, "the epoch store was written at 0")
        self.assertEqual(self.production_decide(cfg, tep.payload(
            sender_since=tep.ts(-120), sender_exposure=tep.EXPOSED)),
            "sender_since_inconsistent")

    def test_receiver_zero_refuses_a_future_sender_since(self):
        # Skew: a sending host's clock 30 s ahead puts sender_since in this
        # receiver's future. Refused `quarantined` at 0 too; at `now` it passes.
        cfg = self.zero()
        self.assertEqual(self.production_decide(cfg, tep.payload(
            sender_since=tep.ts(30), sender_exposure=tep.EXPOSED,
            **{"from": f"ahead@{tep.T1}"})), "quarantined")
        self.assertIsNone(self.production_decide(cfg, tep.payload(
            sender_since=tep.ts(0), sender_exposure=tep.EXPOSED,
            **{"from": f"level@{tep.T1}"})))


# ---------------------------------------------------------------------------
# What is reported is what is enforced
# ---------------------------------------------------------------------------

class _RunLoop(helpers.RouterTestCase):
    """`run_forever` driven for two polls with no plugin: the poll body only
    writes status, the loop ends at the second sleep."""

    def setUp(self):
        super().setUp()
        service._RELOAD_FAILURE.clear()
        self.addCleanup(service._RELOAD_FAILURE.clear)

    def doc(self, **top):
        inst = self.tmp / "instances" / "alice"
        inst.mkdir(parents=True, exist_ok=True)
        d = {"state_dir": str(self.state_dir),
             "instances": {"alice": {"namespace": str(inst)}}}
        d.update(top)
        return d

    def cfg_file(self, doc):
        p = self.tmp / "router.json"
        p.write_text(json.dumps(doc))
        return p

    def run_loop(self, cfg_path, *, between=lambda: None):
        sleeps = []

        def sleep(_):
            sleeps.append(1)
            if len(sleeps) == 1:
                between()
                return
            raise KeyboardInterrupt

        def poll(cfg, tracker, *a, **kw):
            # As `poll_once` does: the classification section (which carries
            # `config_reload_failed`) from the config this poll runs on.
            tracker.record_classification(service.classification_status(cfg, None, None))
            tracker.record_poll({})
            tracker.write(cfg.state_dir)

        cfg = config_mod.load(cfg_path)
        helpers._mark_seen(cfg)
        with mock.patch.object(service, "start_transport", return_value=None), \
                mock.patch.object(service, "peer_startup", return_value=None), \
                mock.patch.object(service, "poll_once", side_effect=poll), \
                mock.patch.object(service.time, "sleep", side_effect=sleep), \
                self.assertLogs("amap_router_local", level="INFO") as logs:
            service.run_forever(cfg, 5.0, config_path=str(cfg_path))
        return logs

    def status(self):
        return json.loads((self.state_dir / status_mod.STATUS_FILENAME).read_text())


class ReportedTests(_RunLoop):

    def lines(self, logs, level):
        return [r.getMessage() for r in logs.records if r.levelname == level]

    def test_startup_reports_enforced(self):
        for v in (0, 7200):
            with self.subTest(v=v):
                logs = self.run_loop(self.cfg_file(self.doc(min_sender_age_s=v)))
                digest = config_mod.sender_age_policy_digest(v)
                self.assertIn(f"min_sender_age_s={v} (default 86400) policy_digest={digest}",
                              self.lines(logs, "INFO"))

    def test_status_reports_enforced(self):
        for v in (0, 7200):
            with self.subTest(v=v):
                self.run_loop(self.cfg_file(self.doc(min_sender_age_s=v)))
                self.assertEqual(self.status()["policy"], {
                    "min_sender_age_s": v, "default": 86400,
                    "digest": config_mod.sender_age_policy_digest(v)})

    def test_digest_reports_enforced(self):
        self.run_loop(self.cfg_file(self.doc(min_sender_age_s=0)))
        cases = {c["min_sender_age_s"]: c for c in json.loads(VECTORS.read_text())["cases"]}
        self.assertEqual(self.status()["policy"]["digest"], cases[0]["digest"])

    def test_warning_exact_text_and_level(self):
        for v in (0, 86399):
            with self.subTest(v=v):
                logs = self.run_loop(self.cfg_file(self.doc(min_sender_age_s=v)))
                self.assertIn(WARNING_TEXT.format(v=v), self.lines(logs, "WARNING"))
                self.assertNotIn(WARNING_TEXT.format(v=v), self.lines(logs, "INFO"))

    def test_no_warning_at_86400(self):
        for doc in (self.doc(), self.doc(min_sender_age_s=86400), self.doc(min_sender_age_s=MAX)):
            with self.subTest(doc=doc.get("min_sender_age_s")):
                logs = self.run_loop(self.cfg_file(doc))
                self.assertFalse([m for m in self.lines(logs, "WARNING")
                                  if m.startswith("sender-age gate")])

    def test_status_text_shows_the_value_and_the_banner(self):
        doc = {"policy": service.policy_status(dataclasses.replace(
            tcl.make_cfg(self), min_sender_age_s=0))}
        text = status_mod.render(doc)
        self.assertIn("sender age: 0s (default 86400s)", text)
        self.assertIn("** sender-age gate allows ages >= 0s; below the 86400s release "
                      "default **", text)
        at_default = status_mod.render({"policy": service.policy_status(tcl.make_cfg(self))})
        self.assertIn("sender age: 86400s (default 86400s)", at_default)
        self.assertNotIn("sender-age gate", at_default)

    def test_console_reports_enforced(self):
        def section(policy):
            status = {"polls": 1, "pid": 1}
            if policy is not None:
                status["policy"] = policy
            return console._health_section({
                "status": status, "poll_age_seconds": 1.0, "instances": {},
                "host": {"available": False, "reason": "not in this test"}})
        zero = service.policy_status(dataclasses.replace(tcl.make_cfg(self), min_sender_age_s=0))
        html = section(zero)
        self.assertIn(">0s<", html)
        self.assertIn("below the release default", html)
        self.assertIn(zero["digest"], html)
        self.assertIn("not reported", section(None))


# ---------------------------------------------------------------------------
# Restart-only, by effective value
# ---------------------------------------------------------------------------

class ReloadTests(_RunLoop):

    def reload(self, start_doc, new_doc):
        path = self.cfg_file(start_doc)
        current = config_mod.load(path)
        path.write_text(json.dumps(new_doc))
        with self.assertLogs("amap_router_local", level="INFO") as logs:
            logging.getLogger("amap_router_local").info("reload probe")
            fresh = service.reload_config(str(path), current)
        return current, fresh, [r.getMessage() for r in logs.records]

    def test_change_refused(self):
        current, fresh, _ = self.reload(self.doc(min_sender_age_s=300),
                                        self.doc(min_sender_age_s=600))
        self.assertTrue(fresh.reload_failed)
        self.assertEqual(fresh.min_sender_age_s, 300)

    def test_refusal_names_key_and_restart(self):
        _, _, lines = self.reload(self.doc(min_sender_age_s=300), self.doc(min_sender_age_s=600))
        self.assertIn("config reload changed min_sender_age_s (300 -> 600) — REFUSED and "
                      "ignored; restart required", lines)
        self.assertEqual(service._RELOAD_FAILURE[str(self.state_dir)]["error"],
                         "min_sender_age_s changed (restart required)")

    def test_absent_to_explicit_default_is_unchanged(self):
        for a, b in ((self.doc(), self.doc(min_sender_age_s=86400)),
                     (self.doc(min_sender_age_s=86400), self.doc())):
            with self.subTest(a="min_sender_age_s" in a):
                _, fresh, _ = self.reload(a, b)
                self.assertFalse(fresh.reload_failed)
                self.assertEqual(fresh.min_sender_age_s, 86400)

    def test_an_unchanged_value_reloads(self):
        _, fresh, _ = self.reload(self.doc(min_sender_age_s=300), self.doc(min_sender_age_s=300))
        self.assertFalse(fresh.reload_failed)

    def test_refused_reload_keeps_last_good_policy(self):
        path = self.cfg_file(self.doc(min_sender_age_s=300))
        changed = self.doc(min_sender_age_s=600)
        self.run_loop(path, between=lambda: path.write_text(json.dumps(changed)))
        st = self.status()
        self.assertEqual(st["polls"], 2, "the second poll ran after the refused reload")
        self.assertTrue(st["classification"]["config_reload_failed"])
        self.assertEqual(st["policy"]["min_sender_age_s"], 300)
        self.assertEqual(st["policy"]["digest"], config_mod.sender_age_policy_digest(300))


# ---------------------------------------------------------------------------
# The D2 digest
# ---------------------------------------------------------------------------

class DigestVectorTests(unittest.TestCase):

    def test_known_answers(self):
        cases = json.loads(VECTORS.read_text())["cases"]
        self.assertGreaterEqual(len(cases), 4)
        for c in cases:
            with self.subTest(v=c["min_sender_age_s"]):
                v = c["min_sender_age_s"]
                # Two producers: the vectors' literal text, and the function.
                self.assertEqual(c["canonical"], '{"min_sender_age_s":%d,"v":1}' % v)
                self.assertEqual(c["digest"], "sha256:" + hashlib.sha256(
                    c["canonical"].encode("utf-8")).hexdigest())
                self.assertEqual(config_mod.sender_age_policy_digest(v), c["digest"])

    def test_the_shared_policy_digest_vectors_are_unchanged(self):
        # D2 leaves the RE-shared policy digest alone: its object has no age.
        obj = classify.policy_object_from(send_to=[], remote_fleet=[], task_deny=[],
                                          trusted_fleet_hosts=[], egress=False)
        self.assertNotIn("min_sender_age_s", obj)


# ---------------------------------------------------------------------------
# Tripwire
# ---------------------------------------------------------------------------

def _folded_86400(tree):
    """Every constant expression in `tree` that folds to 86400, and every name
    shaped like a day or age constant bound to one."""
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.BinOp, ast.Constant)):
            try:
                value = eval(compile(ast.Expression(node), "<expr>", "eval"), {"__builtins__": {}})
            except Exception:  # noqa: BLE001 -- not a constant expression
                continue
            if value == 86400 and not isinstance(value, bool):
                hits.append(ast.unparse(node))
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and any(s in t.id.upper()
                                                   for s in ("DAY", "QUARANTINE", "AGE")):
                    try:
                        value = eval(compile(ast.Expression(node.value), "<expr>", "eval"),
                                     {"__builtins__": {}})
                    except Exception:  # noqa: BLE001
                        continue
                    # A NUMBER bound to such a name; a reason-code string is not one.
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        hits.append(t.id)
    return hits


class StructuralTests(unittest.TestCase):

    MODULES = ("classify.py", "peerpolicy.py")

    def test_no_sender_age_literal_outside_config(self):
        root = Path(router.__file__).parent
        for name in self.MODULES:
            with self.subTest(module=name):
                self.assertEqual(_folded_86400(ast.parse((root / name).read_text())), [])

    def test_the_scan_finds_a_planted_constant(self):
        planted = ast.parse("DAY = 24 * 60 * 60\nx = 1440 * 60\n")
        self.assertEqual(sorted(_folded_86400(planted)), ["1440 * 60", "24 * 60 * 60", "DAY"])


# ---------------------------------------------------------------------------
# The production receiver at the deployed value (E30 r4 clause 5)
# ---------------------------------------------------------------------------

def _deployed_values():
    vals = [0, 300, 7200]
    env = os.environ.get("AMAP_M1_SENDER_AGE_V")
    if env is not None:
        vals.insert(0, int(env))   # the render-go integer: a non-int is an ERROR, never skipped
    return vals


class DeployedValueTests(te2e._E2E):
    """`evaluate_production` (the hook set the router builds) at V: a sender
    one second younger than V is refused `quarantined` and never placed; one
    exactly V old with its exposure asserted is placed."""

    def run_at(self, v, i):
        self.cfg = dataclasses.replace(self.cfg, min_sender_age_s=v)
        # Distinct statement ids (PEER_ID_RE: 23 characters), or a later
        # value's statements are duplicates of an earlier one's.
        if v > 0:
            rec = self.evaluate_production(self.take(self.raw(
                id=f"young{i}".ljust(23, "y"), sender_since=te2e.ts(-(v - 1)),
                sender_exposure=te2e.EXPOSED, **{"from": f"young{i}@{te2e.T1}"})))
            self.assertEqual((rec["disposed"], rec["policy_code"]), ("refused", "quarantined"))
        rec = self.evaluate_production(self.take(self.raw(
            id=f"old{i}".ljust(23, "o"), sender_since=te2e.ts(-v),
            sender_exposure=te2e.EXPOSED, **{"from": f"old{i}@{te2e.T1}"})))
        self.assertEqual(rec["disposed"], "placed")

    def test_the_production_receiver_at_each_deployed_value(self):
        for i, v in enumerate(_deployed_values()):
            with self.subTest(v=v):
                self.run_at(v, i)


if __name__ == "__main__":
    unittest.main()
