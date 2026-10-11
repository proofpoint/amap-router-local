"""The re-check at publication, the published digest, the failing-reload
gate, and revocation after hand-over (`inflight.advance`, THE RE-CHECK;
`outbound._recheck`).

Every "nothing was published" claim is checked on `port.writes`, the one
surface only a transport write produces, and every refusal on the agent's
result."""
import dataclasses
import json
import logging
import unittest
from unittest import mock

from router import classify, inflight, outbound, service
from router.config import load_obj
from router.status import StatusTracker
from router.tests import helpers
from router.tests.helpers import read_json, result_path, write_request
from router.tests.test_classify import HUB2, NET, T1, T2, make_cfg
from router.tests.test_inflight import FakeTransport


class Capture(FakeTransport):
    """Records the in-flight record as it stood when each request was
    written: the published digest is the record's at that moment."""

    def __init__(self, cfg_ref):
        super().__init__()
        self.cfg_ref = cfg_ref
        self.at_write = {}

    def write_request(self, n, data):
        self.at_write[n] = inflight.read_record(self.cfg_ref[0], "alice", "00000001")
        super().write_request(n, data)


class _Case(helpers.RouterTestCase):

    def cfg(self, **kw):
        kw.setdefault("top", {"egress": True})
        kw.setdefault("alice", {"send_to": [NET]})
        return make_cfg(self, **kw)

    def setUp(self):
        super().setUp()
        self.ref = [None]
        self.port = Capture(self.ref)

    def drain(self, cfg, **kw):
        self.ref[0] = cfg
        return outbound.drain_instance(cfg, "alice", transport=self.port, **kw)

    def stage(self, cfg):
        """A record staged and NOT published: the first drain runs with the
        reload failing, so the publication step is skipped."""
        write_request(cfg, "alice", "00000001", to=[NET])
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.assertEqual(inflight.list_records(cfg, "alice"), ["00000001"])
        self.assertEqual(self.port.writes, [])

    def result(self, cfg):
        return read_json(result_path(cfg, "alice", "00000001"))

    def record(self, cfg):
        return inflight.read_record(cfg, "alice", "00000001")


# ---------------------------------------------------------------------------
# Item 4: the re-check at publication
# ---------------------------------------------------------------------------

class PublicationRecheckTests(_Case):

    def test_unchanged_policy_publishes(self):
        cfg = self.cfg()
        self.stage(cfg)
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_a_policy_change_that_still_permits_publishes_the_NEW_digest(self):
        """The digest published with the request is the record's
        after the re-check's durable update."""
        cfg = self.cfg()
        self.stage(cfg)
        old = self.record(cfg)["policy_digest"]
        wider = self.cfg(alice={"send_to": [NET, "@partner.example"]})
        self.drain(wider)
        self.assertEqual(self.port.writes, ["00000001"])
        published = self.port.at_write["00000001"]["policy_digest"]
        self.assertNotEqual(published, old)
        self.assertEqual(published, classify.policy_digest(wider, "alice"))

    def test_a_policy_change_that_no_longer_permits_is_refused_unpublished(self):
        cfg = self.cfg()
        self.stage(cfg)
        self.drain(self.cfg(alice={"send_to": ["other@example.com"]}))
        self.assertEqual(self.port.writes, [])
        r = self.result(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "recipient_not_allowlisted"))
        self.assertEqual(r["detail"],
                         "policy changed before publication: now recipient_not_allowlisted")
        self.assertEqual(inflight.list_records(cfg, "alice"), [])

    def test_losing_egress_is_refused_with_its_code_named(self):
        cfg = self.cfg()
        self.stage(cfg)
        self.drain(self.cfg(top={"egress": False}))
        self.assertEqual(self.result(cfg)["detail"],
                         "policy changed before publication: now no_route")
        self.assertEqual(self.port.writes, [])

    def test_a_route_change_is_refused_not_rebuilt(self):
        """The host became a permitted fleet host: the request would still go
        somewhere, but not by the route it was staged for, so it is refused
        rather than rebuilt, and the detail names both routes."""
        cfg = self.cfg(top={"egress": True})
        self.stage(cfg)
        moved = self.cfg(top={"egress": True,
                              "fleet_hosts": [T1, T2, HUB2, "example.com"]},
                         alice={"send_to": [NET], "remote_fleet": ["example.com"]})
        self.assertNotEqual(classify.policy_digest(moved, "alice"),
                            classify.policy_digest(cfg, "alice"))
        self.drain(moved)
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result(cfg)["detail"],
                         "policy changed before publication: route changed from internet "
                         "to fleet_host")

    def test_an_unchanged_digest_does_not_skip_the_recheck(self):
        """What decides a permit is wider than the digest: losing the plugin's
        reach to a host by moving it into fleet_hosts WITHOUT any digest input
        changing is refused all the same."""
        cfg = self.cfg(top={"egress": True})
        self.stage(cfg)
        moved = self.cfg(top={"egress": True, "fleet_hosts": [T1, T2, HUB2, "example.com"]})
        self.assertEqual(classify.policy_digest(moved, "alice"),
                         classify.policy_digest(cfg, "alice"))
        self.drain(moved)
        self.assertEqual(self.port.writes, [])
        self.assertIn("route changed from internet to fleet_host", self.result(cfg)["detail"])

    def test_a_record_from_before_the_digest_is_rechecked_and_repinned(self):
        cfg = self.cfg()
        self.stage(cfg)
        p = inflight.record_path(cfg, "alice", "00000001")
        rec = json.loads(p.read_text())
        del rec["policy_digest"], rec["route"]
        p.write_text(json.dumps(rec))
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])
        self.assertEqual(self.port.at_write["00000001"]["policy_digest"],
                         classify.policy_digest(cfg, "alice"))

    def route_less(self, cfg):
        p = inflight.record_path(cfg, "alice", "00000001")
        rec = json.loads(p.read_text())
        del rec["policy_digest"], rec["route"]
        p.write_text(json.dumps(rec))

    def test_a_route_less_record_is_pinned_before_its_first_publication(self):
        """The route is backfilled with the digest, durably, before the write;
        then a later change of route while it is pending is caught and marked."""
        cfg = self.cfg()
        self.stage(cfg)
        self.route_less(cfg)
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])
        at_write = self.port.at_write["00000001"]
        self.assertEqual((at_write.get("route"), at_write.get("policy_digest")),
                         ("internet", classify.policy_digest(cfg, "alice")))
        moved = self.cfg(top={"egress": True, "fleet_hosts": [T1, T2, HUB2, "example.com"]},
                         alice={"send_to": [NET], "remote_fleet": ["example.com"]})
        with self.assertLogs("amap_router_local.inflight", logging.ERROR) as logs:
            self.drain(moved)
        self.assertTrue(any("route changed from internet to fleet_host" in m
                            for m in logs.output))
        self.assertIn("revocation_unenforceable", self.record(cfg))

    def test_a_route_less_handed_record_is_pinned_on_its_pending_recheck(self):
        cfg = self.cfg()
        write_request(cfg, "alice", "00000001", to=[NET])
        self.drain(cfg)
        self.route_less(cfg)
        self.drain(cfg)
        self.assertEqual(self.record(cfg).get("route"), "internet")

    def test_a_record_from_before_the_digest_still_refuses_when_not_permitted(self):
        cfg = self.cfg()
        self.stage(cfg)
        p = inflight.record_path(cfg, "alice", "00000001")
        rec = json.loads(p.read_text())
        del rec["policy_digest"], rec["route"]
        p.write_text(json.dumps(rec))
        self.drain(self.cfg(top={"egress": False}))
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result(cfg)["reason_code"], "recipient_not_allowlisted")

    def test_a_narrowed_recipient_set_is_refused(self):
        """Same class and route, but the policy now permits fewer of the
        recipients: the set changed, so it is refused."""
        cfg = self.cfg()
        both = lambda c, s, d: outbound.ExternalRoute((NET, "x@example.com"))  # noqa: E731
        write_request(cfg, "alice", "00000001", to=[NET, "x@example.com"])
        self.drain(dataclasses.replace(cfg, reload_failed=True), cold_policy=both)
        self.drain(cfg, cold_policy=lambda c, s, d: outbound.ExternalRoute((NET,)))
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result(cfg)["detail"],
                         "policy changed before publication: the permitted recipient set "
                         "changed")

    def test_an_alias_now_naming_a_recipient_is_refused(self):
        from router import aliases as aliases_mod
        cfg = self.cfg()
        self.stage(cfg)
        with mock.patch.object(aliases_mod, "normalise",
                               return_value=aliases_mod.Hold((NET,), "x")):
            self.drain(cfg)
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result(cfg)["detail"],
                         "policy changed before publication: an alias now names a recipient")

    def test_a_record_from_before_the_digest_is_refused_by_the_order(self):
        """With no recorded route there is nothing to compare a route with,
        so the order itself decides: the fleet's domain is now the
        recipient's, and no instance there has that name."""
        cfg = self.cfg()
        self.stage(cfg)
        p = inflight.record_path(cfg, "alice", "00000001")
        rec = json.loads(p.read_text())
        del rec["policy_digest"], rec["route"]
        p.write_text(json.dumps(rec))
        renamed = self.cfg(top={"egress": True, "fleet_domain": "example.com"})
        self.drain(renamed)
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result(cfg)["detail"],
                         "policy changed before publication: now recipient_unknown")

    def test_a_handed_but_unwritten_record_is_rechecked_too(self):
        """A crash between the HANDED marker and the transport write: the
        re-write is a publication attempt like the first."""
        cfg = self.cfg()
        self.stage(cfg)
        inflight.handed_path(cfg, "alice", "00000001").write_bytes(b"00000001")
        self.drain(self.cfg(alice={"send_to": ["other@example.com"]}))
        self.assertEqual(self.port.writes, [])
        self.assertEqual(self.result(cfg)["reason_code"], "recipient_not_allowlisted")

    def test_losing_the_plugin_leaves_the_record_alone(self):
        cfg = self.cfg()
        self.stage(cfg)
        outbound.drain_instance(cfg, "alice", transport=None)
        self.assertEqual(inflight.list_records(cfg, "alice"), ["00000001"])
        self.assertFalse(result_path(cfg, "alice", "00000001").exists())


# ---------------------------------------------------------------------------
# Item 8: the failing reload
# ---------------------------------------------------------------------------

class BadReloadTests(_Case):

    def write_config(self, doc):
        p = self.tmp / "router.json"
        p.write_text(json.dumps(doc))
        return p

    def doc(self):
        return {"state_dir": str(self.state_dir),
                "instances": {"alice": {"namespace": str(self.tmp / "instances" / "alice")}}}

    def test_failed_and_refused_reloads_set_the_flag_and_a_good_one_clears_it(self):
        (self.tmp / "instances" / "alice").mkdir(parents=True)
        p = self.write_config(self.doc())
        good = load_obj(self.doc())
        p.write_text("{ not json")
        self.assertTrue(service.reload_config(p, good).reload_failed)
        moved = dict(self.doc(), state_dir=str(self.tmp / "elsewhere"))
        p.write_text(json.dumps(moved))
        self.assertTrue(service.reload_config(p, good).reload_failed)
        p.unlink()
        self.assertTrue(service.reload_config(p, good).reload_failed)
        p = self.write_config(self.doc())
        failing = dataclasses.replace(good, reload_failed=True)
        self.assertFalse(service.reload_config(p, failing).reload_failed)

    def test_the_flag_is_never_read_from_a_file(self):
        doc = dict(self.doc(), reload_failed=True)
        (self.tmp / "instances" / "alice").mkdir(parents=True)
        with self.assertRaises(Exception):
            load_obj(doc)

    def test_nothing_new_is_published_while_it_fails(self):
        cfg = self.cfg()
        with self.assertLogs("amap_router_local.inflight", logging.ERROR) as logs:
            self.stage(cfg)
            self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.assertEqual(self.port.writes, [])
        self.assertTrue(any("NOT published" in m for m in logs.output))
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_the_handed_but_unwritten_rewrite_is_blocked_too(self):
        cfg = self.cfg()
        self.stage(cfg)
        inflight.handed_path(cfg, "alice", "00000001").write_bytes(b"00000001")
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.assertEqual(self.port.writes, [])

    def test_the_local_lane_keeps_running(self):
        cfg = dataclasses.replace(make_cfg(self), reload_failed=True)
        write_request(cfg, "alice", "00000001", to=["bob@fleet.example"])
        self.drain(cfg)
        self.assertEqual(self.result(cfg)["outcome"], "accepted")

    def test_status_says_so(self):
        cfg = dataclasses.replace(make_cfg(self), reload_failed=True)
        tracker = StatusTracker(interval_s=5.0)
        with self.assertLogs("amap_router_local", logging.ERROR) as logs:
            service.poll_once(cfg, tracker)
        self.assertTrue(any("the config reload is failing" in m for m in logs.output))
        self.assertEqual(tracker.to_doc()["classification"], {"config_reload_failed": True})
        from router.status import render
        self.assertIn("CONFIG RELOAD FAILING", render(tracker.to_doc()))
        tracker = StatusTracker(interval_s=5.0)
        service.poll_once(make_cfg(self), tracker)
        self.assertNotIn("classification", tracker.to_doc())
        self.assertNotIn("CONFIG RELOAD FAILING", render(tracker.to_doc()))


# ---------------------------------------------------------------------------
# Revocation after hand-over
# ---------------------------------------------------------------------------

class RevocationTests(_Case):

    def handed(self):
        cfg = self.cfg()
        write_request(cfg, "alice", "00000001", to=[NET])
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])
        return cfg

    def test_a_revoked_pending_request_is_marked_and_logged_every_poll(self):
        cfg = self.handed()
        narrow = self.cfg(alice={"send_to": ["other@example.com"]})
        with self.assertLogs("amap_router_local.inflight", logging.ERROR) as logs:
            self.drain(narrow)
            self.drain(narrow)
        revoked = [m for m in logs.output if "REVOKED" in m]
        self.assertEqual(len(revoked), 2, "logged on every poll it stays pending")
        self.assertIn("no way to withdraw it", revoked[0])
        self.assertIn("REVOKED since", revoked[1], "a marked record is not re-decided")
        since = self.record(cfg)["revocation_unenforceable"]
        self.assertIsInstance(since, str)
        self.assertEqual(inflight.revoked(cfg, "alice"), [{"req_id": "00000001",
                                                            "since": since}])
        self.assertEqual(self.port.writes, ["00000001"], "never re-handed")
        self.assertFalse(result_path(cfg, "alice", "00000001").exists(),
                         "a revocation it cannot enforce settles nothing")

    def test_a_permitted_pending_request_is_not_marked(self):
        cfg = self.handed()
        self.drain(cfg)
        self.assertNotIn("revocation_unenforceable", self.record(cfg))

    def test_a_result_still_settles_a_revoked_request(self):
        cfg = self.handed()
        narrow = self.cfg(alice={"send_to": ["other@example.com"]})
        self.drain(narrow)
        self.port.send_all()
        self.drain(narrow)
        self.assertEqual(self.result(cfg)["outcome"], "accepted")
        self.assertEqual(inflight.list_records(cfg, "alice"), [])

    def test_the_mark_survives_a_restart(self):
        cfg = self.handed()
        self.drain(self.cfg(alice={"send_to": ["other@example.com"]}))
        reread = inflight.read_record(make_cfg(self), "alice", "00000001")
        self.assertIn("revocation_unenforceable", reread)

    def test_not_enacted_while_the_reload_fails(self):
        cfg = self.handed()
        narrow = dataclasses.replace(self.cfg(alice={"send_to": ["other@example.com"]}),
                                     reload_failed=True)
        with self.assertLogs("amap_router_local.inflight", logging.ERROR) as logs:
            self.drain(narrow)
        self.assertTrue(any("nothing is enacted" in m for m in logs.output))
        self.assertNotIn("revocation_unenforceable", self.record(cfg))

    def test_a_withdraw_request_on_the_port_is_never_called(self):
        """The capability is reported, never depended on."""
        calls = []
        self.port.withdraw_request = lambda n: calls.append(n)
        cfg = self.handed()
        with self.assertLogs("amap_router_local.inflight", logging.ERROR) as logs:
            self.drain(self.cfg(alice={"send_to": ["other@example.com"]}))
        self.assertEqual(calls, [])
        self.assertTrue(any("never called" in m for m in logs.output))
        self.assertTrue(inflight.withdraw_capable(self.port))
        self.assertFalse(inflight.withdraw_capable(FakeTransport()))

    def test_status_lists_it_with_its_age(self):
        cfg = self.handed()
        narrow = self.cfg(alice={"send_to": ["other@example.com"]})
        self.drain(narrow)
        tracker = StatusTracker(interval_s=5.0)
        service.poll_once(narrow, tracker, self.port)
        doc = tracker.to_doc()["classification"]
        [row] = doc["revocation_unenforceable"]["alice"]
        self.assertEqual(row["req_id"], "00000001")
        self.assertIsInstance(row["age_s"], int)
        self.assertIs(doc["withdraw_capable"], False)
        from router.status import render
        self.assertIn("alice: req 00000001 REVOKED after hand-over", render(tracker.to_doc()))


# ---------------------------------------------------------------------------
# The closed record schema
# ---------------------------------------------------------------------------

class RecordSchemaTests(_Case):

    def test_an_unknown_member_is_damaged_and_never_handed(self):
        cfg = self.cfg()
        self.stage(cfg)
        p = inflight.record_path(cfg, "alice", "00000001")
        rec = json.loads(p.read_text())
        rec["withdraw_after_s"] = 60
        p.write_text(json.dumps(rec))
        with self.assertRaises(inflight.RecordDamaged):
            inflight.read_record(cfg, "alice", "00000001")
        with self.assertLogs("amap_router_local.outbound", logging.ERROR):
            self.drain(cfg)
        self.assertEqual(self.port.writes, [])
        self.assertFalse(result_path(cfg, "alice", "00000001").exists())

    def test_each_member_rule(self):
        good = {"digest": None, "transport_req_id": "00000001", "recipients": [NET],
                "request": {}, "written_ts": "2026-10-11T00:00:00Z",
                "policy_digest": "sha256:" + "0" * 64, "route": "internet",
                "revocation_unenforceable": "2026-10-11T00:00:00Z"}
        inflight.check_record(dict(good))
        bad = [("transport_req_id", "1"), ("recipients", NET), ("request", []),
               ("written_ts", 0), ("policy_digest", "sha256:xyz"), ("route", "local"),
               ("revocation_unenforceable", True), ("digest", 3)]
        for key, value in bad:
            with self.subTest(key=key), self.assertRaises(inflight.RecordDamaged):
                inflight.check_record(dict(good, **{key: value}))
        for key in ("transport_req_id", "recipients", "request", "written_ts"):
            with self.subTest(missing=key), self.assertRaises(inflight.RecordDamaged):
                inflight.check_record({k: v for k, v in good.items() if k != key})


if __name__ == "__main__":
    unittest.main()
