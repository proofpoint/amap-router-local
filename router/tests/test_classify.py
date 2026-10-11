"""The cold-send classification order (`router/classify.py`).

Each edge of the frozen order has a witness here, driven through the drain
where the answer is observable there (the agent's result is the one surface
only the decision produces) and through `classify.classify` directly where
the drain cannot tell two steps apart.
"""
import dataclasses
import json
import types
import unittest
from pathlib import Path
from unittest import mock

from router import aliases as aliases_mod
from router import classify, config as config_mod, exposure, outbound
from router.config import ConfigError, load_obj
from router.tests import helpers
from router.tests.helpers import read_json, result_path, write_request
from router.tests.test_inflight import FakeTransport

FD = "fleet.example"
T1, T2 = "t1.fleet.example", "t2.fleet.example"
HUB2 = "hub2.fleet.example"
LOCAL_BOB = f"bob@{FD}"
TRUSTED = f"carol@{T1}"
FLEET = f"dave@{HUB2}"
NET = "erin@example.com"
NOW = "2026-10-11T12:00:00Z"
VECTORS = Path(__file__).parent / "vectors"


def make_cfg(tc, *, top=None, alice=None, seen=True):
    """alice and bob, mutual mail peers on fleet.example; two trusted hosts and
    one more fleet host; `top` and `alice` add or override keys."""
    doc = {
        "state_dir": str(tc.state_dir), "fleet_domain": FD,
        "trusted_fleet_hosts": [T1, T2], "fleet_hosts": [T1, T2, HUB2],
        "instances": {
            "alice": {"namespace": str(tc.tmp / "instances" / "alice"), "peers": ["bob"]},
            "bob": {"namespace": str(tc.tmp / "instances" / "bob"), "peers": ["alice"]},
        },
    }
    doc.update(top or {})
    doc["instances"]["alice"].update(alice or {})
    for n in ("alice", "bob"):
        (tc.tmp / "instances" / n).mkdir(parents=True, exist_ok=True)
    cfg = load_obj(doc)
    if seen:
        helpers._mark_seen(cfg)
    return cfg


def with_age(cfg, ts):
    """A registry report whose entry for alice carries `ts` (None: no entry)."""
    entries = {} if ts is None else {"alice": types.SimpleNamespace(first_registered_ts=ts)}
    return dataclasses.replace(cfg, registry_report=types.SimpleNamespace(entries=entries))


OLD_ENOUGH = "2026-10-01T00:00:00Z"
STAMP = {"asserted_by": f"amap.router@{FD}", "external_mail_delivered": False,
         "window_start": NOW, "window_end": NOW}


class _Case(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.port = FakeTransport()

    def drain(self, cfg, req_id="00000001", plugin=True, **kw):
        """The agent's result, or a stand-in naming its absence, so that a
        request left unanswered (or put in flight) FAILS an assertion rather
        than erroring on a missing file."""
        outbound.drain_instance(cfg, "alice", transport=self.port if plugin else None, **kw)
        p = result_path(cfg, "alice", req_id)
        if not p.exists():
            return {"outcome": None, "reason_code": "<no result>", "detail": None}
        return read_json(p)

    def send(self, cfg, to, cc=None, req_id="00000001", plugin=True, **kw):
        write_request(cfg, "alice", req_id, to=to, cc=cc)
        return self.drain(cfg, req_id, plugin=plugin, **kw)

    def code(self, r):
        return (r["outcome"], r["reason_code"])

    def decide(self, cfg, to, cc=None, plugin=True):
        draft = {"to": to}
        if cc is not None:
            draft["cc"] = cc
        try:
            d = classify.classify(cfg, "alice", draft, plugin=plugin, now=NOW)
        except Exception as e:  # noqa: BLE001 -- a raise is a wrong answer, so a FAILURE
            self.fail(f"classify raised {e!r}")
        if isinstance(d, classify.Refuse):
            return d
        # Not a refusal: its type stands in for the code, so comparing a code
        # FAILS rather than erroring on a missing attribute.
        return types.SimpleNamespace(reason_code=type(d).__name__, outcome=None,
                                     detail=None, decision=d)


# ---------------------------------------------------------------------------
# Item 1: the order, each edge
# ---------------------------------------------------------------------------

class OrderTests(_Case):

    def test_alias_normalisation_runs_before_anything_is_classified(self):
        cfg = make_cfg(self)
        for norm, want in (
            (aliases_mod.Hold(("x@old.example",), "undecidable"), None),
            (aliases_mod.Refuse(("x@old.example",)), ("rejected", "recipient_unknown")),
        ):
            with self.subTest(norm=type(norm).__name__), \
                    mock.patch.object(aliases_mod, "normalise", return_value=norm), \
                    mock.patch.object(classify, "classify") as spy:
                req = "00000001" if want is None else "00000002"
                # passes the envelope's own pattern, fails the address grammar
                write_request(cfg, "alice", req, to=["x@example.com."])
                outbound.drain_instance(cfg, "alice", transport=self.port)
                spy.assert_not_called()
                if want is not None:
                    self.assertEqual(self.code(read_json(result_path(cfg, "alice", req))), want)

    def test_malformed_wins_over_this_domain_unknown(self):
        """The malformed address passes the envelope's own pattern, so only
        the grammar can refuse it."""
        cfg = make_cfg(self)
        r = self.send(cfg, [f"nobody@{FD}", "x@example.com."])
        self.assertEqual(self.code(r), ("rejected", "malformed_request"))

    def test_this_domain_unknown_wins_over_no_plugin(self):
        """Step 3's answer carries no detail; step 4's names the plugin."""
        cfg = make_cfg(self)
        r = self.send(cfg, [f"nobody@{FD}", NET], plugin=False)
        self.assertEqual(self.code(r), ("rejected", "recipient_unknown"))
        self.assertIsNone(r.get("detail"))

    def test_this_domain_unknown_wins_over_mixed(self):
        cfg = make_cfg(self)
        r = self.send(cfg, [f"nobody@{FD}", NET])
        self.assertEqual(self.code(r), ("rejected", "recipient_unknown"))

    def test_the_routers_own_address_is_this_domain_unknown(self):
        cfg = make_cfg(self)
        r = self.send(cfg, [f"amap.router@{FD}"])
        self.assertEqual(self.code(r), ("rejected", "recipient_unknown"))

    def test_no_plugin_wins_over_mixed_and_over_every_class_rule(self):
        cfg = make_cfg(self, top={"egress": True}, alice={"send_to": [NET]})
        cases = {"mixed": ([LOCAL_BOB, NET], None), "trusted": ([TRUSTED], None),
                 "fleet": ([FLEET], None), "internet": ([NET], None)}
        for i, (label, (to, cc)) in enumerate(sorted(cases.items())):
            with self.subTest(label):
                r = self.send(cfg, to, cc, req_id=f"0000000{i + 1}", plugin=False)
                self.assertEqual(self.code(r), ("rejected", "recipient_unknown"))
                self.assertIn("no transport plugin", r["detail"])
        self.assertEqual(self.port.writes, [])

    def test_mixed_classes(self):
        cfg = make_cfg(self, top={"egress": True})
        cases = [
            ([LOCAL_BOB, NET], None),
            ([TRUSTED], [NET]),        # not fleet_mail_disabled
            ([TRUSTED], [LOCAL_BOB]),  # not fleet_mail_disabled
            ([FLEET], [NET]),
            ([TRUSTED, FLEET], None),
        ]
        for i, (to, cc) in enumerate(cases):
            with self.subTest(to=to, cc=cc):
                r = self.send(cfg, to, cc, req_id=f"0000000{i + 1}")
                self.assertEqual(self.code(r), ("rejected", "mixed_recipient_classes"))

    def test_two_trusted_hosts_are_one_class(self):
        cfg = make_cfg(self)
        d = self.decide(cfg, [TRUSTED, f"x@{T2}"])
        self.assertEqual((d.reason_code,), ("fleet_mail_disabled",))

    def test_local_is_the_same_host_decision_unchanged(self):
        cfg = make_cfg(self)
        self.assertIsInstance(self.decide(cfg, [LOCAL_BOB]).decision, classify.Local)
        r = self.send(cfg, [LOCAL_BOB])
        self.assertEqual(self.code(r), ("accepted", "allowlisted"))

    def test_an_unbound_reply_key_is_unresolved_reply_never_classified(self):
        cfg = make_cfg(self)
        with mock.patch.object(classify, "classify") as spy:
            write_request(cfg, "alice", "00000001", to=[TRUSTED], in_reply_to="no-such-notice")
            r = self.drain(cfg)
        spy.assert_not_called()
        self.assertEqual(r["reason_code"], "unresolved_reply")


# ---------------------------------------------------------------------------
# Item 2: the one address grammar
# ---------------------------------------------------------------------------

class GrammarTests(unittest.TestCase):

    def test_the_shared_vectors(self):
        cases = json.loads((VECTORS / "address_grammar.json").read_text())["cases"]
        ok = bad = 0
        for c in cases:
            with self.subTest(why=c["why"]):
                if c.get("malformed"):
                    self.assert_malformed(c["in"])
                    bad += 1
                else:
                    self.assertEqual(classify.parse_address(c["in"]).canonical(), c["out"])
                    ok += 1
        self.assertGreater(ok, 5)
        self.assertGreater(bad, 20)

    def assert_malformed(self, value, parse=classify.parse_address):
        try:
            got = parse(value)
        except classify.Malformed:
            return
        except Exception as e:  # noqa: BLE001 -- the wrong refusal is a wrong answer
            self.fail(f"{value!r}: raised {e!r}, not Malformed")
        self.fail(f"{value!r}: accepted as {got!r}")

    def test_non_strings_are_malformed(self):
        for v in (None, 3, ["a@example.com"], b"a@example.com"):
            self.assert_malformed(v)
            self.assert_malformed(v, classify.check_domain)

    def test_a_domain_over_253_characters(self):
        d253 = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertEqual(len(d253), 253)
        self.assertEqual(classify.check_domain(d253), d253)
        self.assert_malformed(d253 + "b", classify.check_domain)

    def test_malformed_never_echoes_the_input(self):
        try:
            classify.parse_address("secret-token\n@example.com")
        except classify.Malformed as e:
            self.assertNotIn("secret-token", str(e))


class FleetLocalPartTests(_Case):

    def test_a_fleet_local_part_outside_the_name_grammar_is_malformed(self):
        cfg = make_cfg(self)
        for addr in (f"a+b@{FD}", f"a+b@{T1}", f"a+b@{HUB2}", f"-a@{FD}"):
            with self.subTest(addr), self.assertRaises(classify.Malformed):
                classify.address_class(cfg, addr)

    def test_a_remote_local_part_keeps_the_full_grammar(self):
        cfg = make_cfg(self)
        self.assertEqual(classify.address_class(cfg, "a+b@example.com")[0],
                         classify.CLASS_INTERNET)

    def test_upper_case_is_matched_lowercased_not_refused(self):
        cfg = make_cfg(self)
        self.assertEqual(classify.address_class(cfg, "BOB@Fleet.Example")[0],
                         classify.CLASS_LOCAL)
        self.assertEqual(classify.address_class(cfg, "x@T1.FLEET.example")[0],
                         classify.CLASS_TRUSTED)

    def test_a_trailing_dot_never_matches_a_fleet_domain(self):
        cfg = make_cfg(self)
        r = self.send(cfg, [f"bob@{FD}."])
        self.assertEqual(self.code(r), ("rejected", "malformed_request"))

    def test_a_homoglyph_domain_is_malformed_not_a_fleet_host(self):
        """At the classifier, not the drain: the envelope's own pattern
        refuses non-ASCII first, so the drain could not tell which refused."""
        cfg = make_cfg(self)
        with self.assertRaises(classify.Malformed):
            classify.address_class(cfg, "carol@t1.fleet.ex\u0430mple")

    def test_without_a_fleet_domain_the_legacy_scheme_is_local(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        self.assertEqual(classify.address_class(cfg, "agent.bob@local")[0],
                         classify.CLASS_LOCAL)
        self.assertEqual(classify.address_class(cfg, "bob@local")[0], classify.CLASS_UNKNOWN)


# ---------------------------------------------------------------------------
# Item 3: the config inputs and their load-time refusals
# ---------------------------------------------------------------------------

class ConfigTests(helpers.RouterTestCase):

    def refused(self, needle, **kw):
        with self.assertRaises(ConfigError) as cm:
            make_cfg(self, **kw)
        self.assertIn(needle, str(cm.exception))

    def test_accepted_and_canonical(self):
        cfg = make_cfg(self, top={"trusted_fleet_hosts": ["T1.fleet.example"],
                                  "fleet_hosts": ["t1.fleet.example", HUB2], "egress": True,
                                  "ingress_quarantine_days": 30},
                       alice={"send_to": ["Bob@EXAMPLE.com", "@Partner.example"],
                              "remote_fleet": [HUB2.upper()],
                              "task_deny": ["X@T1.fleet.example"]})
        self.assertEqual(cfg.trusted_fleet_hosts, (T1,))
        self.assertEqual(cfg.fleet_hosts, (HUB2, T1))
        self.assertTrue(cfg.egress)
        self.assertEqual(cfg.ingress_quarantine_days, 30)
        a = cfg.instances["alice"]
        self.assertEqual(a.send_to, ("@partner.example", "Bob@example.com"))
        self.assertEqual(a.remote_fleet, (HUB2,))
        self.assertEqual(a.task_deny, (f"X@{T1}",))

    def test_absent_keys_are_empty(self):
        cfg = self.make_config({"alice": []})
        self.assertEqual((cfg.trusted_fleet_hosts, cfg.fleet_hosts, cfg.egress,
                          cfg.ingress_quarantine_days), ((), (), False, 14))
        a = cfg.instances["alice"]
        self.assertEqual((a.send_to, a.remote_fleet, a.task_deny), ((), (), ()))

    def test_own_domain_in_either_list(self):
        self.refused("own domain", top={"trusted_fleet_hosts": [FD], "fleet_hosts": [FD]})
        self.refused("own domain", top={"trusted_fleet_hosts": [], "fleet_hosts": [FD.upper()]})

    def test_the_legacy_domain_is_own_without_a_fleet_domain(self):
        with self.assertRaises(ConfigError) as cm:
            load_obj({"state_dir": str(self.state_dir), "fleet_hosts": ["local"],
                      "instances": {"a": {"namespace": str(self.tmp / "a")}}})
        self.assertIn("own domain", str(cm.exception))

    def test_trusted_must_be_fleet_hosts(self):
        self.refused("not in config.fleet_hosts", top={"fleet_hosts": [T1]})

    def test_send_to_naming_a_trusted_host(self):
        self.refused("trusted fleet host", alice={"send_to": [f"x@{T1}"]})
        self.refused("trusted fleet host", alice={"send_to": [f"@{T2.upper()}"]})

    def test_remote_fleet_naming_a_trusted_host_or_a_stranger(self):
        self.refused("trusted fleet hosts", alice={"remote_fleet": [T1]})
        self.refused("not in config.fleet_hosts", alice={"remote_fleet": ["example.com"]})

    def test_task_deny_outside_the_trusted_hosts(self):
        self.refused("not at a trusted fleet host", alice={"task_deny": [f"x@{HUB2}"]})
        self.refused("not at a trusted fleet host", alice={"task_deny": ["@example.com"]})

    def test_duplicates_after_canonicalisation(self):
        self.refused("duplicate", top={"trusted_fleet_hosts": [T1, T1.upper()]})
        self.refused("duplicate", top={"fleet_hosts": [T1, T2, HUB2, HUB2]})
        self.refused("duplicate", alice={"send_to": ["a@example.com", "a@EXAMPLE.com"]})
        self.refused("duplicate", alice={"remote_fleet": [HUB2, HUB2.upper()]})
        self.refused("duplicate", alice={"task_deny": [f"@{T1}", f"@{T1.upper()}"]})

    def test_a_local_part_case_variant_is_not_a_duplicate(self):
        cfg = make_cfg(self, alice={"send_to": ["a@example.com", "A@example.com"]})
        self.assertEqual(len(cfg.instances["alice"].send_to), 2)

    def test_malformed_entries_and_shapes(self):
        self.refused("trusted_fleet_hosts", top={"trusted_fleet_hosts": ["t1.fleet.example."]})
        self.refused("fleet_hosts", top={"fleet_hosts": "t1.fleet.example"})
        self.refused("send_to", alice={"send_to": ["not an address"]})
        self.refused("send_to", alice={"send_to": [7]})
        self.refused("egress", top={"egress": "yes"})
        self.refused("egress", top={"egress": 1})

    def test_ingress_quarantine_days_bounds(self):
        for bad in (0, 366, True, "14", 1.5):
            with self.subTest(bad):
                self.refused("ingress_quarantine_days", top={"ingress_quarantine_days": bad})
        for good in (1, 365):
            self.assertEqual(make_cfg(self, top={"ingress_quarantine_days": good})
                             .ingress_quarantine_days, good)

    def test_the_keys_are_reserved_from_extra_instance_keys(self):
        with self.assertRaises(ConfigError):
            load_obj({"state_dir": str(self.state_dir),
                      "instances": {"a": {"namespace": str(self.tmp / "a")}}},
                     extra_instance_keys=["send_to"], validate_extra=lambda n, k, v: v)


class AbsentKeysTests(_Case):
    """Absent keys reproduce the behaviour before them ONLY without a plugin."""

    def test_without_a_plugin_an_internet_address_is_recipient_unknown(self):
        cfg = self.make_config({"alice": []})
        r = self.send(cfg, [NET], plugin=False)
        self.assertEqual(self.code(r), ("rejected", "recipient_unknown"))

    def test_with_a_plugin_and_no_egress_it_is_no_route(self):
        cfg = self.make_config({"alice": []})
        r = self.send(cfg, [NET])
        self.assertEqual(self.code(r), ("rejected", "no_route"))


# ---------------------------------------------------------------------------
# Item 5 (trusted host), items 6 and 7, with the exposure and age rules
# ---------------------------------------------------------------------------

class TrustedHostTests(_Case):

    def ready(self, **kw):
        return with_age(make_cfg(self, **kw), OLD_ENOUGH)

    def test_shape_first_more_than_one_recipient_or_any_cc(self):
        """Run before peer_denied: a denied host still answers the shape."""
        cfg = self.ready(alice={"task_deny": [f"@{T1}"]})
        for to, cc in (([TRUSTED, f"x@{T1}"], None), ([TRUSTED], [f"y@{T1}"])):
            with self.subTest(to=to, cc=cc):
                self.assertEqual(self.decide(cfg, to, cc).reason_code, "fleet_mail_disabled")

    def test_peer_denied_by_address_and_by_domain(self):
        for deny in ([TRUSTED], [f"@{T1}"], [f"@{T1.upper()}"]):
            with self.subTest(deny=deny):
                cfg = self.ready(alice={"task_deny": deny})
                self.assertEqual(self.decide(cfg, [TRUSTED]).reason_code, "peer_denied")

    def test_a_deny_for_another_host_does_not_deny(self):
        cfg = self.ready(alice={"task_deny": [f"@{T2}"]})
        with mock.patch.object(exposure, "assess", return_value=STAMP):
            self.assertEqual(self.decide(cfg, [TRUSTED]).reason_code, "recipient_unknown")

    def test_task_deny_matches_local_parts_exactly(self):
        cfg = self.ready(alice={"task_deny": [f"Carol@{T1}"]})
        with mock.patch.object(exposure, "assess", return_value=STAMP):
            d = self.decide(cfg, [TRUSTED])
        self.assertNotEqual(d.reason_code, "peer_denied")

    def test_denied_wins_over_quarantine(self):
        cfg = with_age(make_cfg(self, alice={"task_deny": [f"@{T1}"]}), None)
        self.assertEqual(self.decide(cfg, [TRUSTED]).reason_code, "peer_denied")

    def test_the_24_hour_quarantine_edges(self):
        cases = {
            "1 s under 24 h": ("2026-10-10T12:00:01Z", "peer_quarantined"),
            "exactly 24 h": ("2026-10-10T12:00:00Z", "recipient_unknown"),
            "1 s over 24 h": ("2026-10-10T11:59:59Z", "recipient_unknown"),
            "in the future": ("2026-10-11T12:00:01Z", "peer_quarantined"),
            "far in the future": ("2027-10-11T12:00:00Z", "peer_quarantined"),
        }
        for label, (ts, want) in cases.items():
            with self.subTest(label), mock.patch.object(exposure, "assess", return_value=STAMP):
                d = self.decide(with_age(make_cfg(self), ts), [TRUSTED])
                self.assertEqual(d.reason_code, want)
                if "future" in label:
                    self.assertEqual(d.detail, "the sender's first_registered_ts is in the future")

    def test_sender_age_unknown(self):
        for label, cfg in (("no entry", with_age(make_cfg(self), None)),
                           ("no registry report", make_cfg(self))):
            with self.subTest(label):
                d = self.decide(cfg, [TRUSTED])
                self.assertEqual((d.reason_code, d.detail),
                                 ("peer_quarantined", "sender age unknown"))

    def test_quarantine_wins_over_exposure(self):
        cfg = with_age(make_cfg(self), None)
        with mock.patch.object(exposure, "assess", return_value=None) as spy:
            self.assertEqual(self.decide(cfg, [TRUSTED]).reason_code, "peer_quarantined")
        spy.assert_not_called()

    def test_exposure_unavailable_on_none_or_on_any_exception(self):
        for effect in (None, OSError("disk"), RuntimeError("bug")):
            with self.subTest(effect=repr(effect)):
                kw = ({"return_value": None} if effect is None else {"side_effect": effect})
                with mock.patch.object(exposure, "assess", **kw):
                    d = self.decide(self.ready(), [TRUSTED])
                self.assertEqual(d.reason_code, "exposure_unavailable")

    def test_exposure_is_assessed_for_the_sender_at_the_decision_time(self):
        with mock.patch.object(exposure, "assess", return_value=STAMP) as spy:
            self.decide(self.ready(), [TRUSTED])
        spy.assert_called_once()
        self.assertEqual(spy.call_args.args[1], "alice")
        self.assertEqual(spy.call_args.kwargs, {"now": NOW})

    def test_no_peer_lane_is_recipient_unknown_and_the_size_seam_is_never_reached(self):
        size = mock.Mock(side_effect=AssertionError("reached"))
        with mock.patch.object(exposure, "assess", return_value=STAMP), \
                mock.patch.object(classify, "statement_size", size):
            d = self.decide(self.ready(), [TRUSTED])
        self.assertEqual((d.outcome, d.reason_code), ("rejected", "recipient_unknown"))
        self.assertEqual(d.detail, "the cross-host peer lane is not available on this router")
        size.assert_not_called()

    def test_the_size_seam_default_raises(self):
        with self.assertRaises(NotImplementedError):
            classify.statement_size(make_cfg(self), "alice", {}, STAMP)

    def test_statement_too_large_through_the_seam(self):
        for size, want in ((8193, "peer_statement_too_large"), (8192, None)):
            with self.subTest(size=size), \
                    mock.patch.object(exposure, "assess", return_value=STAMP), \
                    mock.patch.object(classify, "peer_lane_available", return_value=True), \
                    mock.patch.object(classify, "statement_size", return_value=size):
                d = self.decide(self.ready(), [TRUSTED])
            if want:
                self.assertEqual(d.reason_code, want)
            else:
                self.assertEqual(getattr(d, "decision", d), classify.PeerRemote(TRUSTED, STAMP))

    def test_a_peer_remote_decision_is_answered_never_sent(self):
        cfg = self.ready()
        with mock.patch.object(exposure, "assess", return_value=STAMP), \
                mock.patch.object(classify, "peer_lane_available", return_value=True), \
                mock.patch.object(classify, "statement_size", return_value=10):
            r = self.send(cfg, [TRUSTED])
        self.assertEqual(self.code(r), ("queued_for_human", "transport_anomaly"))
        self.assertEqual(self.port.writes, [])

    def test_a_custom_policy_never_decides_a_trusted_host(self):
        cfg = self.ready()
        called = []
        with mock.patch.object(exposure, "assess", return_value=STAMP):
            r = self.send(cfg, [TRUSTED], cold_policy=lambda c, s, d: called.append(s))
        self.assertEqual(called, [])
        self.assertEqual(self.code(r), ("rejected", "recipient_unknown"))
        self.assertEqual(self.port.writes, [])


class FleetAndInternetTests(_Case):

    def test_item_6_remote_fleet(self):
        cfg = make_cfg(self)
        r = self.send(cfg, [FLEET])
        self.assertEqual(self.code(r), ("queued_for_human", "recipient_not_allowlisted"))
        self.assertTrue((cfg.state_dir / "alice" / "held" / "req-00000001.json").exists())
        cfg = make_cfg(self, alice={"remote_fleet": [HUB2]})
        write_request(cfg, "alice", "00000002", to=[FLEET])
        outbound.drain_instance(cfg, "alice", transport=self.port)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_item_7_no_egress_is_no_route_first(self):
        cfg = make_cfg(self, alice={"send_to": [NET]})
        r = self.send(cfg, [NET])
        self.assertEqual(self.code(r), ("rejected", "no_route"))

    def test_item_7_no_egress_wins_over_a_send_to_miss(self):
        cfg = make_cfg(self, alice={"send_to": ["other@example.com"]})
        self.assertEqual(self.code(self.send(cfg, [NET])), ("rejected", "no_route"))

    def test_item_7_send_to_miss_is_held(self):
        cfg = make_cfg(self, top={"egress": True}, alice={"send_to": ["other@example.com"]})
        r = self.send(cfg, [NET])
        self.assertEqual(self.code(r), ("queued_for_human", "recipient_not_allowlisted"))
        self.assertTrue((cfg.state_dir / "alice" / "held" / "req-00000001.json").exists())

    def test_item_7_send_to_by_address_and_by_domain(self):
        cfg = make_cfg(self, top={"egress": True},
                       alice={"send_to": [NET, "@Partner.example"]})
        write_request(cfg, "alice", "00000001", to=[NET])
        write_request(cfg, "alice", "00000002", to=["zed@PARTNER.example"])
        outbound.drain_instance(cfg, "alice", transport=self.port)
        self.assertEqual(self.port.writes, ["00000001", "00000002"])

    def test_item_7_send_to_matches_local_parts_exactly(self):
        cfg = make_cfg(self, top={"egress": True}, alice={"send_to": [NET]})
        r = self.send(cfg, ["Erin@example.com"])
        self.assertEqual(self.code(r), ("queued_for_human", "recipient_not_allowlisted"))

    def test_the_route_and_digest_are_recorded_before_anything_is_handed(self):
        cfg = make_cfg(self, top={"egress": True}, alice={"send_to": [NET]})
        seen = {}

        class Capture(FakeTransport):
            def write_request(s, n, data):
                from router import inflight
                seen["record"] = inflight.read_record(cfg, "alice", "00000001")
                super().write_request(n, data)
        self.port = Capture()
        write_request(cfg, "alice", "00000001", to=[NET])
        outbound.drain_instance(cfg, "alice", transport=self.port)
        self.assertEqual(seen["record"].get("route"), "internet")
        self.assertEqual(seen["record"].get("policy_digest"),
                         classify.policy_digest(cfg, "alice"))


# ---------------------------------------------------------------------------
# Item 10: every code RL originates, paired with its outcome
# ---------------------------------------------------------------------------

class OriginatedCodeTests(_Case):

    def test_each_code_with_its_outcome(self):
        """§9's table, for the codes this router originates at its own
        submit; each produced through the drain."""
        base = with_age(make_cfg(self, top={"egress": True},
                                 alice={"send_to": ["other@example.com"]}), OLD_ENOUGH)
        denied = with_age(make_cfg(self, alice={"task_deny": [f"@{T1}"]}), OLD_ENOUGH)
        young = with_age(make_cfg(self), "2026-10-11T11:00:00Z")
        noegress = make_cfg(self)
        cases = [
            (base, ["two@@example.com"], None, "rejected", "malformed_request", {}),
            (base, [f"nobody@{FD}"], None, "rejected", "recipient_unknown", {}),
            (base, [LOCAL_BOB, NET], None, "rejected", "mixed_recipient_classes", {}),
            (noegress, [NET], None, "rejected", "no_route", {}),
            (base, [TRUSTED], [f"x@{T2}"], "rejected", "fleet_mail_disabled", {}),
            (denied, [TRUSTED], None, "rejected", "peer_denied", {}),
            (young, [TRUSTED], None, "rejected", "peer_quarantined", {}),
            (base, [TRUSTED], None, "rejected", "exposure_unavailable", {"assess": None}),
            (base, [TRUSTED], None, "rejected", "peer_statement_too_large",
             {"assess": STAMP, "lane": True, "size": 9000}),
            (base, [NET], None, "queued_for_human", "recipient_not_allowlisted", {}),
        ]
        for i, (cfg, to, cc, outcome, code, patches) in enumerate(cases, 1):
            with self.subTest(code=code):
                req = f"{i:08d}"
                ctx = [mock.patch.object(exposure, "assess",
                                         return_value=patches.get("assess"))]
                if patches.get("lane"):
                    ctx.append(mock.patch.object(classify, "peer_lane_available",
                                                 return_value=True))
                    ctx.append(mock.patch.object(classify, "statement_size",
                                                 return_value=patches["size"]))
                for c in ctx:
                    c.start()
                try:
                    r = self.send(cfg, to, cc, req_id=req)
                finally:
                    for c in ctx:
                        c.stop()
                self.assertEqual(self.code(r), (outcome, code))
        self.assertEqual(self.port.writes, [])

    def test_peer_single_recipient_stays_the_same_host_code(self):
        from router.tests.peer_helpers import make_peer_config, addr
        cfg = make_peer_config(self, {"a": {"peers": ["c"]}, "b": {"peer_senders": ["a"]},
                                      "c": {"peers": ["a"]}})
        write_request(cfg, "a", "00000001", to=[addr("b"), addr("c")])
        outbound.drain_instance(cfg, "a")
        r = read_json(result_path(cfg, "a", "00000001"))
        self.assertEqual(self.code(r), ("rejected", "peer_single_recipient"))


class PassThroughCodeTests(_Case):
    """Codes this router never originates arrive as transport verdicts and
    pass through verbatim, the detail prefixed `transport: `."""

    CODES = [
        ("rejected", "hop_version_mismatch"), ("rejected", "hop_invalid_request"),
        ("rejected", "recipient_refused"), ("rejected", "loop_refused"),
        ("rejected", "special_use_domain"), ("queued_for_human", "transport_timeout"),
        ("queued_for_human", "delivery_unknown"), ("queued_for_human", "rate_limited"),
        ("rejected", "halted"), ("rejected", "agent_id_mismatch"),
        # shared codes arriving from downstream
        ("rejected", "malformed_request"), ("rejected", "mixed_recipient_classes"),
        ("rejected", "no_route"), ("queued_for_human", "recipient_not_allowlisted"),
        ("queued_for_human", "transport_anomaly"),
    ]

    def test_each_verdict_passes_through(self):
        cfg = make_cfg(self, top={"egress": True}, alice={"send_to": [NET]})
        for i, (outcome, code) in enumerate(self.CODES, 1):
            with self.subTest(code=code):
                req = f"{i:08d}"
                write_request(cfg, "alice", req, to=[NET])
                outbound.drain_instance(cfg, "alice", transport=self.port)
                n = self.port.writes[-1]
                self.port.send(n, outcome=outcome, reason_code=code, detail="hub link: x")
                outbound.drain_instance(cfg, "alice", transport=self.port)
                r = read_json(result_path(cfg, "alice", req))
                self.assertEqual(self.code(r), (outcome, code))
                self.assertEqual(r["detail"], "transport: hub link: x")


if __name__ == "__main__":
    unittest.main()
