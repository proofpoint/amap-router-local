"""The spec's control-notice cases (peer-origin §5.8), driven through this
router's own receive path: the `.control/` host intake, the candidate
journal, the receive hook and the failure notice.

Each case's receiver (`receiver-host-a.json`) becomes a router config: its
hosted agents, its one peer runtime and key, its windows and its `issued`
ledger. Every candidate is written into `.control/` and polled. The
signatures are the spec's real Ed25519 test signatures, verified with the
spec's own reference implementation (`ed25519_ref.verify`); the peer codec is
the test stand-in's (the real one is the transport plugin's).

The spec checkout is REQUIRED: without one these tests fail, never skip
(`helpers._spec_root`).

One case maps by design rather than by token: `control-in-statement-field`
(a control notice in the statement field) expects `mail, statement_schema`.
Here such a candidate reaches `.control/` without a control field, so it is
held as `control_plain_mail` and becomes mail when the ingress quarantine
expires: the case's property (mail, never a control notice in return) holds,
under this router's own cause."""
from __future__ import annotations

import dataclasses
import importlib.util
import json
import types
import unittest
from datetime import timedelta
from unittest import mock

from router import config as config_mod
from router import peerbind, peerclock, peercontrol, peerjournal, peerlane, peerledger
from router.tests import helpers
from router.tests import peer_standin as si
from router.tests.peer_helpers import make_peer_config
from router.util import parse_utc_ts

SPEC = helpers._spec_root()
SIGNED = SPEC / "fixtures" / "peer-signed"
CASES = ("control-accepted", "control-accepted-policy", "control-about-other-host",
         "control-about-unknown", "control-and-statement-together", "control-bad-signature",
         "control-duplicate-about", "control-field-carrying-statement",
         "control-from-not-runtime", "control-replay", "seq-control-crash-before-agent-notice")


def _ed25519_ref():
    spec = importlib.util.spec_from_file_location("amap_spec_ed25519_ref",
                                                  SIGNED / "ed25519_ref.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RefVerifier:
    """The verifier port over the spec's reference Ed25519."""

    def __init__(self):
        self._ref = _ed25519_ref()

    def verify(self, pub, msg, sig):
        return bool(self._ref.verify(pub, msg, sig))


class _Receiver(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.receiver = json.loads((SIGNED / "receiver-host-a.json").read_text())
        self.now = parse_utc_ts(self.receiver["now"])
        fd = self.receiver["self"]["domains"][0]
        hosted = {a.split("@", 1)[0]: {} for a in self.receiver["hosted"]}
        cfg = make_peer_config(self, hosted, fleet_domain=fd)
        peer = self.receiver["peers"][0]
        dc = config_mod.DelegationConfig(
            partition_verified="evidence", signing_key_path="/k/seed", signing_key_id="rl-key",
            signing_public_key="ab" * 32,
            runtimes=(config_mod.DelegationRuntime(
                name=peer["name"], runtime=peer["runtime"], domains=tuple(peer["domains"]),
                keys=tuple(types.MappingProxyType(k) for k in peer["keys"])),),
            crypto_backend="pyca")
        self.hop = self.tmp / "hop"
        for intake in (".unresolved", ".control"):
            (self.hop / ".disposed" / intake).mkdir(parents=True)
            (self.hop / intake).mkdir(parents=True)
        self.cfg = dataclasses.replace(cfg, delegation=dc,
                                       hop=types.SimpleNamespace(root=str(self.hop)))
        w = self.receiver["windows"]
        self.state_dir.mkdir(parents=True, exist_ok=True)
        peerjournal.init_store(self.state_dir, self.now - timedelta(hours=1), hop_root=None,
                               peer_roots=(), p=w["ts_past_s"], f=w["ts_future_s"])
        peerbind.ensure_decision_key(self.state_dir)
        self.lane = peerlane.Delegation(
            config=dc, signer=None, verifier=RefVerifier(), codec=si.PeerCodec(),
            errors=types.MappingProxyType({"CodecError": si.CodecError,
                                           "KeyConfigError": si.KeyConfigError,
                                           "BackendError": si.BackendError,
                                           "ConfigError": si.ConfigError}),
            key_table=si.load_key_table([{"domains": peer["domains"], "runtime": peer["runtime"],
                                          "keys": peer["keys"]}]),
            reasons=si.REASONS, key_config_reasons=si.KEY_CONFIG_REASONS,
            candidate_view=lambda raw: json.loads(raw))
        for e in self.receiver["ledger"]:
            local = e["local"].split("@", 1)[0]
            peerlane.write_issued(self.cfg, peerlane.issued_record(
                peer_id=e["id"], logical_id=config_mod.state_key(self.cfg, local),
                local_address=e["local"], remote=e["remote"], generation="g" * 32,
                expires_at=e["expires"]))
        from router import fsops as fsops_mod
        self.ops = fsops_mod.FsOps(hop_root=str(self.hop))
        self.addCleanup(self.ops.close)
        self.addCleanup(peerjournal._DISPOSED.clear)
        self.n = 0

    def poll(self, now=None):
        now = now or self.now
        return peerjournal.poll_host(self.cfg, self.ops, delegation=self.lane,
                                     clock=peerclock.advance(self.state_dir, now), now=now,
                                     intake=".control")

    def put(self, candidate):
        self.n += 1
        ident = f"{self.n:032x}"
        d = self.hop / ".control" / ident
        d.mkdir()
        view = {"fields": candidate["fields"], "body": candidate["body"],
                "attachments": candidate.get("attachments", [])}
        (d / "candidate.json").write_bytes(json.dumps(view, sort_keys=True).encode())
        return ident

    def rec(self, ident):
        key = peerjournal.record_key(intake=".control", gen="", owner="_host", entry_id=ident)
        return peerjournal.read_record(self.state_dir, "_host", key)

    def notices(self, agent):
        name = agent.split("@", 1)[0]
        d = self.cfg.instances[name].inbox_root / "notices"
        return sorted(d.glob("notice-*.json")) if d.is_dir() else []

    def all_notices(self):
        return sum((self.notices(a) for a in self.receiver["hosted"]), [])

    def check_notify(self, ident, notify, before):
        rec = self.rec(ident)
        self.assertEqual((rec["state"], rec["disposed"], rec.get("hold")),
                         ("done", "placed", None))
        new = [p for p in self.notices(notify["agent"]) if p not in before]
        self.assertEqual(len(new), 1, "one failure notice, to the issuing agent")
        notice = json.loads(new[0].read_text())
        self.assertEqual(notice["message"]["in_reply_to"], notify["about"])
        spool = json.loads((new[0].parent.parent / "messages" / new[0].name).read_text())
        _subject, body = peercontrol.failure_notice(
            about=notify["about"], outcome=notify["outcome"], cause=notify["cause"],
            policy_code=notify.get("policy_code"))
        self.assertEqual(spool["body_text"], body, "the text names exactly this report")


class ControlCaseTests(_Receiver):
    """One test per spec case, each on a fresh receiver, so a failure names
    its case."""

    def run_case(self, name):
        case = json.loads((SIGNED / "cases" / f"{name}.json").read_text())
        self.assertEqual(case["receiver"], "receiver-host-a.json")
        steps = case["steps"] if "steps" in case else [case]
        last = None
        for step in steps:
            expect = step["expect"]
            before = self.all_notices()
            if step.get("event") == "recover":
                self.poll()
                for r in expect["recovered"]:
                    self.check_notify(last, r["notify"], before)
                continue
            ident = self.put(step["candidate"])
            last = ident
            if step.get("crash") == "after_reserve":
                real = peerledger.claim_notified

                def crash(*_a, **_k):
                    raise SystemExit("crash after the reservation")
                with mock.patch.object(peerledger, "claim_notified", crash):
                    with self.assertRaises(SystemExit):
                        self.poll()
                self.assertEqual(expect["outcome"], "crashed")
                self.assertEqual(self.rec(ident)["state"], "reserved")
                self.assertIs(peerledger.claim_notified, real)
                continue
            self.poll()
            rec = self.rec(ident)
            if expect["outcome"] == "control":
                self.check_notify(ident, expect["notify"], before)
            elif expect["outcome"] == "drop":
                self.assertEqual((rec["state"], rec["disposed"], rec["cause"]),
                                 ("done", "dropped", expect["cause"]))
                self.assertIsNone(rec["control"], "never answered")
                self.assertEqual(self.all_notices(), before, "never placed")
            else:
                self.fail(f"{name}: unexpected expectation {expect}")



def _case_test(name):
    def test(self):
        self.run_case(name)
    test.__name__ = "test_" + name.replace("-", "_")
    return test


for _name in CASES:
    setattr(ControlCaseTests, "test_" + _name.replace("-", "_"), _case_test(_name))


class StatementInControlFieldTests(_Receiver):
    """control-in-statement-field: a control notice in the statement field.
    Here it reaches `.control/` without a control field: held as plain mail,
    then mail, never answered with a control notice (module docstring)."""

    def test_it_becomes_mail_and_is_never_answered(self):
        case = json.loads((SIGNED / "cases" / "control-in-statement-field.json").read_text())
        (step,) = case["steps"] if "steps" in case else [case]
        self.assertEqual(step["expect"], {"outcome": "mail", "cause": "statement_schema"})
        ident = self.put(step["candidate"])
        self.poll()
        rec = self.rec(ident)
        self.assertEqual((rec["state"], (rec.get("hold") or {}).get("reason")),
                         ("pending", "control_plain_mail"))
        self.poll(now=self.now + timedelta(days=self.cfg.ingress_quarantine_days))
        rec = self.rec(ident)
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "mail"))
        self.assertIsNone(rec["control"])
        self.assertEqual(self.all_notices(), [])


if __name__ == "__main__":
    unittest.main()
