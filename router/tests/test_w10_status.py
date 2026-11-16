"""ALPHA-2 W10, status.json: "drained" bound to THIS poll (B1), and the
`delegation` section built from what this process ACTIVATED (B3).

Both are read by an external verifier, so the tests pin the reader's rules
as well as the writer's output. `registry_drained` below is the rule the
verifier applies (design r3 §2); it is here so every negative case is proved
to FAIL it on the real producer's output, not merely to differ from a
positive one.
"""
import dataclasses
import json
import logging
import os
import types
import unittest
from unittest import mock

from router import config as config_mod, peerlane, registry, service
from router.status import StatusTracker
from router.tests import helpers
from router.tests import peer_standin as si
from router.tests.test_classify import T1, T2
from router.tests.test_peerlane import KEY_ID, PEER_KEY_ID, _Base, _seed
from router.tests import test_registry


def registry_drained(doc, agents):
    """VERIFY.RL_REGISTRY as design r3 §2 states it: None when every agent
    was drained cleanly IN THIS POLL, else the first reason."""
    reg = doc.get("registry")
    if reg is None:
        return "no registry section"
    if reg.get("state") != "ok":
        return f"registry state {reg.get('state')!r}"
    if reg.get("held") != {}:
        return f"held {sorted(reg.get('held') or {})}"
    for name in agents:
        if name not in (doc.get("admitted") or []):
            return f"{name} not admitted"
        inst = (doc.get("instances") or {}).get(name)
        if inst is None:
            return f"{name} has no summary"
        if inst.get("poll") != doc["polls"]:
            return f"{name} summary is from poll {inst.get('poll')}, not {doc['polls']}"
        last = inst.get("last_summary") or {}
        if last.get("instance_errored") or last.get("outbound_errored"):
            return f"{name} errored this poll"
    return None


# ---------------------------------------------------------------------------
# B1: per-instance poll identity
# ---------------------------------------------------------------------------

class PollIdentityTests(helpers.RouterTestCase):

    def test_every_instance_folded_carries_this_polls_number(self):
        cfg = self.make_config({"alice": [], "bob": []})
        tracker = StatusTracker()
        service.poll_once(cfg, tracker)
        service.poll_once(cfg, tracker)
        doc = tracker.to_doc()
        self.assertEqual(doc["polls"], 2)
        self.assertEqual({n: i.get("poll") for n, i in doc["instances"].items()},
                         {"alice": 2, "bob": 2})

    def test_a_poll_that_raised_wholesale_leaves_every_summary_behind(self):
        """(b): the outer belt folds `{}`, so no instance is from this poll."""
        cfg = self.make_config({"alice": [], "bob": []})
        tracker = StatusTracker()
        service.poll_once(cfg, tracker)
        self.assertIsNone(registry_drained(_with_ok_registry(tracker.to_doc()),
                                           ["alice", "bob"]))

        def boom(_cfg):
            raise RuntimeError("the whole poll fell over")
        with mock.patch.object(service, "run_once", boom):
            service.poll_once(cfg, tracker)
        doc = tracker.to_doc()
        self.assertEqual(doc["polls"], 2)
        self.assertEqual(doc["instances"]["alice"].get("poll"), 1)
        # The summary is still the clean one from poll 1: exactly the
        # stale-clean case the poll number exists to catch.
        self.assertNotIn("instance_errored", doc["instances"]["alice"]["last_summary"])
        self.assertEqual(registry_drained(_with_ok_registry(doc), ["alice", "bob"]),
                         "alice summary is from poll 1, not 2")

    def test_an_errored_drain_is_from_this_poll_and_still_fails(self):
        """(c): current, but errored."""
        cfg = self.make_config({"alice": [], "mallory": []})
        out = cfg.instances["mallory"].outbox_root
        out.mkdir(parents=True, exist_ok=True)
        os.chmod(out, 0o000)
        try:
            tracker = StatusTracker()
            with self.assertLogs("amap_router_local", logging.ERROR):
                service.poll_once(cfg, tracker)
        finally:
            os.chmod(out, 0o755)
        doc = tracker.to_doc()
        self.assertEqual(doc["instances"]["mallory"].get("poll"), doc["polls"])
        self.assertEqual(registry_drained(_with_ok_registry(doc), ["alice", "mallory"]),
                         "mallory errored this poll")

    def test_no_registry_section_fails_the_rule(self):
        cfg = self.make_config({"alice": []})
        tracker = StatusTracker()
        service.poll_once(cfg, tracker)
        doc = tracker.to_doc()
        self.assertNotIn("registry", doc)
        self.assertEqual(registry_drained(doc, ["alice"]), "no registry section")


def _with_ok_registry(doc):
    """These layouts run without a registry; the rule's registry clauses are
    pinned by `HeldInstanceTests`, so here a passing registry is supplied to
    isolate the poll and error clauses."""
    return dict(doc, registry={"state": "ok", "held": {}})


class HeldInstanceTests(helpers.RouterTestCase):
    """(a): an instance the registry holds is skipped, and keeps the clean
    summary of the last poll that drained it. The layout is test_registry's
    ServiceTests fixture, restated (subclassing it would run its tests a
    second time here)."""

    def setUp(self):
        super().setUp()
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        snap = json.loads((test_registry.FIXTURES / "snapshot.json").read_text())
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(snap))
        self.cfg = dataclasses.replace(self.make_config({"alpha": [], "beta": []}),
                                       registry_dir=self.reg)
        (self.cfg.state_dir / "alpha").rename(self.cfg.state_dir / test_registry.ALPHA_LID)
        helpers.adopt_test_markers(self.cfg)
        service._REGISTRY_LOGGED.clear()

    def test_a_skipped_instance_keeps_its_older_poll_and_fails(self):
        tracker = StatusTracker(interval_s=5.0)
        with self.assertLogs("amap_router_local", logging.WARNING):
            service.poll_once(self.cfg, tracker, None)
        doc = tracker.to_doc()
        self.assertEqual(doc["instances"]["alpha"].get("poll"), 1)
        # beta is held from the start: a held registry fails first.
        self.assertEqual(registry_drained(doc, ["alpha"]), "held ['beta']")
        self.assertIsNone(registry_drained(dict(doc, registry=dict(doc["registry"], held={})),
                                           ["alpha"]))

        # The registry turns bad: alpha is held and skipped this poll.
        snap = json.loads((self.reg / registry.SNAPSHOT).read_text())
        snap["entries"][0]["state"] = []
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(snap))
        with self.assertLogs("amap_router_local", logging.ERROR):
            service.poll_once(self.cfg, tracker, None)
        doc = tracker.to_doc()
        self.assertEqual((doc["polls"], doc["instances"]["alpha"].get("poll")), (2, 1))
        self.assertNotIn("instance_errored", doc["instances"]["alpha"]["last_summary"])
        # Even with the registry clauses forced to pass, the stale summary
        # alone fails the rule: the poll number is the only thing that can.
        forced = dict(doc, registry={"state": "ok", "held": {}})
        self.assertEqual(registry_drained(forced, ["alpha"]),
                         "alpha summary is from poll 1, not 2")


# ---------------------------------------------------------------------------
# B3: status `delegation`
# ---------------------------------------------------------------------------

class DelegationStatusTests(_Base):

    def test_absent_without_delegation(self):
        cfg = dataclasses.replace(self.cfg(), delegation=None)
        self.assertIsNone(peerlane.status_doc(cfg))
        tracker = StatusTracker()
        tracker.record_delegation(peerlane.status_doc(cfg))
        self.assertNotIn("delegation", tracker.to_doc())

    def test_configured_but_not_activated_is_the_inactive_form(self):
        doc = peerlane.status_doc(self.cfg())
        self.assertEqual(doc, {"v": 1, "active": False})
        self.assertIsNone(peerlane.check_delegation_status(doc))

    def test_the_full_form_is_what_was_activated(self):
        cfg = self.cfg()
        self.activate(cfg)
        doc = peerlane.status_doc(cfg)
        self.assertIsNone(peerlane.check_delegation_status(doc))
        self.assertEqual(doc, {
            "v": 1, "active": True,
            "signing_key_id": KEY_ID,
            "signing_public_key": si.public_key(self.seed).hex(),
            "runtimes": [{"name": "host-a", "domains": [T1],
                          "keys": [{"key_id": PEER_KEY_ID,
                                    "public_key": self.peer_pub.hex()}]}],
            "window": {"p": 3600, "f": 300}, "inbound": False})

    def test_it_shows_the_activated_snapshot_not_the_config_on_disk(self):
        cfg = self.cfg()
        self.activate(cfg)
        other = si.public_key(_seed(b"other")).hex()
        edited = dataclasses.replace(cfg, delegation=dataclasses.replace(
            cfg.delegation, signing_key_id="edited-key", signing_public_key=other))
        # No reload has activated the edit: status keeps what is in force.
        doc = peerlane.status_doc(edited)
        self.assertEqual((doc["signing_key_id"], doc["signing_public_key"]),
                         (KEY_ID, si.public_key(self.seed).hex()))

    def test_no_secret_or_path_material(self):
        cfg = self.cfg(openssl_path="/usr/bin/openssl")
        self.activate(cfg)
        doc = peerlane.status_doc(cfg)
        text = json.dumps(doc)
        for needle in (str(self.seed_path), self.seed.hex(), "/usr/bin/openssl", "pyca",
                       "probe-evidence-1"):
            self.assertNotIn(needle, text)

        def keys(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    yield k
                    yield from keys(v)
            elif isinstance(o, list):
                for v in o:
                    yield from keys(v)
        self.assertEqual(set(keys(doc)) - {"v", "active", "signing_key_id",
                                           "signing_public_key", "runtimes", "name",
                                           "domains", "keys", "key_id", "public_key",
                                           "window", "p", "f", "inbound"}, set())

    def _code(self, **over):
        """The status form for an activated snapshot whose config has
        `over` applied (installed directly: activation would refuse most)."""
        cfg = self.cfg()
        d = self.activate(cfg)
        bad = dataclasses.replace(d, config=dataclasses.replace(d.config, **over))
        peerlane.install(cfg, bad)
        with self.assertLogs("amap_router_local.peerlane", logging.ERROR):
            doc = peerlane.status_doc(cfg)
        self.assertEqual(set(doc), {"v", "active", "error"})
        self.assertIsNone(peerlane.check_delegation_status(doc))
        return doc["error"]

    def _rt(self, name="host-a", domains=(T1,), keys=None):
        keys = keys if keys is not None else ({"key_id": PEER_KEY_ID,
                                               "public_key": self.peer_pub.hex()},)
        return config_mod.DelegationRuntime(
            name=name, runtime=f"amap.router@{domains[0]}", domains=tuple(domains),
            keys=tuple(types.MappingProxyType(dict(k)) for k in keys))

    def test_each_closed_error_code(self):
        pub = self.peer_pub.hex()
        cases = {
            "no_runtimes": dict(runtimes=()),
            "invalid_key_id": dict(signing_key_id="-starts-with-dash"),
            "invalid_public_key": dict(signing_public_key=pub.upper()),
            "invalid_runtime_name": dict(runtimes=(self._rt(name="-bad"),)),
            "duplicate_runtime": dict(runtimes=(self._rt(), self._rt(
                domains=(T2,), keys=({"key_id": "k2", "public_key": pub},)))),
            "invalid_domain": dict(runtimes=(self._rt(domains=("Not A Domain",)),)),
            "duplicate_domain": dict(runtimes=(self._rt(domains=(T1, T1)),)),
            "duplicate_key_id": dict(runtimes=(self._rt(keys=(
                {"key_id": KEY_ID, "public_key": pub},)),)),
            "invalid_window": dict(window_p=299),
        }
        self.assertEqual(set(cases), peerlane.DELEGATION_STATUS_ERRORS)
        for code, over in cases.items():
            with self.subTest(code=code):
                self.assertEqual(self._code(**over), code)

    def test_more_malformed_values(self):
        pub = self.peer_pub.hex()
        for over, code in (
                (dict(signing_public_key=pub[:63]), "invalid_public_key"),
                (dict(runtimes=(self._rt(keys=({"key_id": PEER_KEY_ID,
                                                "public_key": pub[:-1] + "G"},)),)),
                 "invalid_public_key"),
                (dict(runtimes=(self._rt(keys=({"key_id": "x" * 65, "public_key": pub},)),)),
                 "invalid_key_id"),
                (dict(window_f=901), "invalid_window"),
                (dict(window_p=86401), "invalid_window")):
            with self.subTest(over=sorted(over)):
                self.assertEqual(self._code(**over), code)

    def test_the_reader_accepts_only_the_three_forms(self):
        cfg = self.cfg()
        self.activate(cfg)
        full = peerlane.status_doc(cfg)
        bad = [
            {"v": 1, "active": True},
            {"v": 1, "active": False, "error": "no_runtimes"},
            {"v": 1, "active": True, "error": "internal"},
            {"v": 2, "active": False},
            dict(full, extra=1),
            dict(full, active=False),
            dict(full, inbound="yes"),
            dict(full, window={"p": 3600, "f": 300, "x": 1}),
            dict(full, runtimes=[dict(full["runtimes"][0], runtime="amap.router@x")]),
            dict(full, runtimes=[dict(full["runtimes"][0], keys=[
                dict(full["runtimes"][0]["keys"][0], not_after="2027-01-01T00:00:00Z")])]),
            {k: v for k, v in full.items() if k != "window"},
        ]
        for doc in bad:
            with self.subTest(doc=sorted(doc)):
                self.assertIsNotNone(peerlane.check_delegation_status(doc))


class DelegationPollTests(_Base):
    """The section is written by every poll and never carried over."""

    def test_each_poll_replaces_it(self):
        cfg = self.cfg()
        tracker = StatusTracker()
        self.activate(cfg)
        with mock.patch.object(service, "run_once", return_value={}):
            service.poll_once(cfg, tracker)
            self.assertTrue(tracker.to_doc().get("delegation", {}).get("active"))
            peerlane.forget_all()                    # activation lost
            service.poll_once(cfg, tracker)
        self.assertEqual(tracker.to_doc().get("delegation"), {"v": 1, "active": False})

    def test_a_failure_building_it_leaves_it_out_never_stale(self):
        cfg = self.cfg()
        tracker = StatusTracker()
        self.activate(cfg)
        with mock.patch.object(service, "run_once", return_value={}):
            service.poll_once(cfg, tracker)
            self.assertIn("delegation", tracker.to_doc())
            with mock.patch.object(peerlane, "status_doc", side_effect=RuntimeError("bug")), \
                    self.assertLogs("amap_router_local", logging.ERROR):
                service.poll_once(cfg, tracker)
        self.assertNotIn("delegation", tracker.to_doc())


def cross_match(a, b, a_name_on_b, s5_pub_a):
    """The verifier's B3 cross-match for one direction: A's activated
    signing key is the S5 value, and B's activated table lists it under
    A's runtime with the same key_id."""
    if a.get("signing_public_key") != s5_pub_a:
        return "A's key is not the S5 value"
    rt = [r for r in b["runtimes"] if r["name"] == a_name_on_b]
    if len(rt) != 1:
        return "B does not list A's runtime once"
    if {"key_id": a["signing_key_id"], "public_key": a["signing_public_key"]} not in rt[0]["keys"]:
        return "B does not hold A's key"
    return None


class CrossMatchTests(unittest.TestCase):
    A_PUB, B_PUB = "a" * 64, "b" * 64

    def docs(self, b_holds=None, a_holds=None):
        a = {"v": 1, "active": True, "signing_key_id": "ka", "signing_public_key": self.A_PUB,
             "runtimes": [{"name": "vm-b", "domains": ["b.example"],
                           "keys": [{"key_id": "kb", "public_key": a_holds or self.B_PUB}]}],
             "window": {"p": 3600, "f": 300}, "inbound": True}
        b = {"v": 1, "active": True, "signing_key_id": "kb", "signing_public_key": self.B_PUB,
             "runtimes": [{"name": "vm-a", "domains": ["a.example"],
                           "keys": [{"key_id": "ka", "public_key": b_holds or self.A_PUB}]}],
             "window": {"p": 3600, "f": 300}, "inbound": True}
        for d in (a, b):
            assert peerlane.check_delegation_status(d) is None
        return a, b

    def test_both_directions_and_the_s5_value(self):
        a, b = self.docs()
        self.assertIsNone(cross_match(a, b, "vm-a", self.A_PUB))
        self.assertIsNone(cross_match(b, a, "vm-b", self.B_PUB))

    def test_each_direction_fails_alone(self):
        a, b = self.docs(b_holds="c" * 64)
        self.assertEqual(cross_match(a, b, "vm-a", self.A_PUB), "B does not hold A's key")
        self.assertIsNone(cross_match(b, a, "vm-b", self.B_PUB))
        a, b = self.docs(a_holds="c" * 64)
        self.assertIsNone(cross_match(a, b, "vm-a", self.A_PUB))
        self.assertEqual(cross_match(b, a, "vm-b", self.B_PUB), "B does not hold A's key")

    def test_a_wrong_s5_value_fails(self):
        a, b = self.docs()
        self.assertEqual(cross_match(a, b, "vm-a", "d" * 64), "A's key is not the S5 value")


if __name__ == "__main__":
    unittest.main()
