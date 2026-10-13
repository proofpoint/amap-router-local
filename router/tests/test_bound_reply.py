"""A reply to mail placed from the hop leg, handed back over the hop as a
bound reply (`outbound._drain_bound_reply`, `outbound._recheck_bound`,
`hoplink.build_handover`'s `bound`), and the delivered-domain file that
holds every bound reply while it disagrees with `fleet_hosts`
(`config._delivered_domains`).

What was handed over is read off `port.pending`, the one surface only a
transport write produces; every refusal is read off the agent's result, and
"nothing allocated" off the transport counter, which only `inflight.begin`
writes."""
import dataclasses
import hashlib
import json
import logging
import os
import unittest
from unittest import mock

from router import binding, classify, config as config_mod, hoplink, inflight, outbound
from router.config import ConfigError
from router.tests import helpers
from router.tests.helpers import read_json, result_path, write_request
from router.tests.test_classify import FD, HUB2, NET, T1, TRUSTED, make_cfg
from router.tests.test_inflight import FakeTransport
from router.util import mint_notice_id

LID = "0123456789abcdef0123456789abcdef"
BOB_LID = "b" * 32
GEN = "fedcba9876543210fedcba9876543210"
CP = f"carol@{HUB2}"
LINK = "hub"
RULE = "example.rule"   # synthetic: rule values are the downstream runtime's
FAR = "2099-01-01T00:00:00Z"


class _Case(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.port = FakeTransport()

    def cfg(self, *, top=None, alice=None):
        cfg = make_cfg(self, top=top, alice=alice, seen=False)
        cfg = dataclasses.replace(cfg, state_keys={"alice": LID, "bob": BOB_LID})
        helpers._mark_seen(cfg)
        return cfg

    def ledger(self, cfg, *, agent=LID, counterparty=CP, admission="fleet_hosts",
               expires=FAR, drop=(), transport="hop", tree="inbox"):
        """A ledger record of mail placed from the hop leg, written where
        ingress writes it; returns its notice id."""
        nid = mint_notice_id()
        origin = {"agent": agent, "counterparty": counterparty,
                  "origin_notice_id": "up-1.a", "origin_link": LINK,
                  "origin_logical_id": agent, "origin_generation": GEN,
                  "admission": admission, "admission_link": LINK, "admission_rule": RULE,
                  "received_at": "2026-10-13T00:00:00Z", "expires_at": expires}
        rec = json.loads(binding.record_delivery(
            cfg.state_dir, notice_id=nid, from_instance=None, from_address=counterparty,
            to_instance="alice", ts="2026-10-13T00:00:00Z", req_id="",
            message_id=f"<m1@{HUB2}>", transport=transport, tree=tree, mail_origin=origin))
        for k in drop:
            rec.pop(k)
        p = binding.ledger_path(cfg.state_dir, "alice", nid, state_key=LID)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rec), encoding="utf-8")
        return nid

    def drain(self, cfg, **kw):
        return outbound.drain_instance(cfg, "alice", transport=self.port, **kw)

    def result(self, cfg):
        """The agent's result, or None. Refusal tests read it through
        `answered`, so a request left unanswered FAILS an assertion rather
        than erroring on a missing key."""
        p = result_path(cfg, "alice", "00000001")
        return read_json(p) if p.exists() else None

    def answered(self, cfg):
        r = self.result(cfg)
        self.assertIsNotNone(r, "the request was not answered")
        return r

    def handover(self, n="00000001"):
        self.assertIn(n, self.port.pending, "nothing was handed over")
        return json.loads(self.port.pending[n])

    def nothing_allocated(self, cfg):
        self.assertFalse(inflight.counter_path(cfg, "alice").exists())
        self.assertEqual(inflight.list_records(cfg, "alice"), [])
        self.assertEqual(self.port.writes, [])

    def expected_bound(self, cfg, admission="fleet_hosts", digest=None):
        return {"bound_address": CP, "origin_notice_id": "up-1.a", "origin_link": LINK,
                "origin_generation": GEN, "participants": {"agent": LID, "counterparty": CP},
                "admission": admission, "admission_link": LINK, "admission_rule": RULE,
                "policy_digest": digest}


class BeginTests(_Case):

    def test_a_fleet_counterparty_is_handed_over_as_a_bound_reply(self):
        """The positive case: the fixed recipient, the full `bound`, kind
        bound_reply, and the record pinning all of it."""
        cfg = self.cfg()
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])
        doc = self.handover()
        env = doc["envelope"]
        self.assertEqual(env["kind"], "bound_reply")
        record = inflight.read_record(cfg, "alice", "00000001")
        self.assertEqual(env["bound"], self.expected_bound(cfg, digest=record["policy_digest"]))
        self.assertEqual(doc["request"]["draft"]["to"], [CP])
        self.assertEqual(record["recipients"], [CP])
        self.assertEqual(record["route"], classify.CLASS_FLEET)
        self.assertEqual(record["bound_reply"]["notice_id"], nid)
        self.assertEqual(record["bound_reply"]["bound"], env["bound"])
        self.assertIsNone(self.result(cfg))

    def test_draft_recipients_are_discarded_for_the_counterparty(self):
        cfg = self.cfg()
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[f"mallory@{HUB2}"], cc=[NET],
                      in_reply_to=nid)
        with self.assertLogs("amap_router_local.outbound", logging.WARNING) as logs:
            self.drain(cfg)
        draft = self.handover()["request"]["draft"]
        self.assertEqual(draft["to"], [CP])
        self.assertNotIn("cc", draft)
        line = "\n".join(logs.output)
        self.assertIn("addressed 2 recipient(s) other than its counterparty", line)
        self.assertNotIn("mallory", line)
        self.assertNotIn(NET, line)

    def test_bound_address_and_counterparty_are_equal_and_canonical(self):
        """The ledger's counterparty is canonical (the domain lowercased);
        both envelope members are that one string."""
        cfg = self.cfg()
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[f"carol@{HUB2.upper()}"], in_reply_to=nid)
        self.drain(cfg)
        bound = self.handover()["envelope"]["bound"]
        self.assertEqual(bound["bound_address"], CP)
        self.assertEqual(bound["participants"]["counterparty"], CP)

    def test_another_agents_binding_is_unresolved(self):
        cfg = self.cfg()
        nid = self.ledger(cfg, agent=BOB_LID)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "unresolved_reply"))
        self.assertIn("binds another agent", r["detail"])
        self.nothing_allocated(cfg)

    def test_an_expired_binding_is_unresolved(self):
        cfg = self.cfg()
        nid = self.ledger(cfg, expires="2026-01-01T00:00:00Z")
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "unresolved_reply"))
        self.assertIn("expired", r["detail"])
        self.nothing_allocated(cfg)

    def test_a_record_without_the_binding_members_is_unresolved(self):
        cfg = self.cfg()
        nid = self.ledger(cfg, drop=("origin_generation",))
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.answered(cfg)["reason_code"], "unresolved_reply")
        self.nothing_allocated(cfg)

    def test_a_peer_tree_record_is_unresolved(self):
        cfg = self.cfg()
        nid = self.ledger(cfg, tree="peer")
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.answered(cfg)["reason_code"], "unresolved_reply")
        self.nothing_allocated(cfg)

    def test_an_internet_counterparty_has_no_route_and_nothing_is_allocated(self):
        cfg = self.cfg(top={"egress": True}, alice={"send_to": [NET]})
        nid = self.ledger(cfg, counterparty=NET)
        write_request(cfg, "alice", "00000001", to=[NET], in_reply_to=nid)
        self.drain(cfg)
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"], r["detail"]),
                         ("rejected", "no_route", outbound.DETAIL_NO_REPLY_PATH))
        self.nothing_allocated(cfg)

    def test_a_trusted_host_counterparty_gets_a_bound_reply(self):
        """A bound reply is decided before the trusted-host rule: a trusted
        host's counterparty gets a bound reply over the hop, never the peer
        path and never no_route."""
        cfg = self.cfg()
        nid = self.ledger(cfg, counterparty=TRUSTED)
        write_request(cfg, "alice", "00000001", to=[TRUSTED], in_reply_to=nid)
        self.drain(cfg)
        env = self.handover()["envelope"]
        self.assertEqual(env["kind"], "bound_reply")
        self.assertEqual(env["bound"]["bound_address"], TRUSTED)
        self.assertEqual(self.handover()["request"]["draft"]["to"], [TRUSTED])

    def test_a_trusted_host_counterparty_with_open_admission_is_decided_by_egress(self):
        """Egress decides an open admission: with no `remote_fleet` for the
        trusted host, the default is queued for a human, nothing allocated."""
        cfg = self.cfg()
        nid = self.ledger(cfg, counterparty=TRUSTED, admission="open")
        write_request(cfg, "alice", "00000001", to=[TRUSTED], in_reply_to=nid)
        self.drain(cfg)
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "recipient_not_allowlisted"))
        self.nothing_allocated(cfg)

    def test_a_trusted_host_counterparty_with_open_admission_permitted_by_a_policy(self):
        """A permitting custom cold policy hands it over, as a bound reply."""
        cfg = self.cfg()
        nid = self.ledger(cfg, counterparty=TRUSTED, admission="open")
        write_request(cfg, "alice", "00000001", to=[TRUSTED], in_reply_to=nid)
        self.drain(cfg, cold_policy=lambda c, s, d: outbound.ExternalRoute(tuple(d["to"])))
        env = self.handover()["envelope"]
        self.assertEqual((env["kind"], env["bound"]["admission"], env["bound"]["bound_address"]),
                         ("bound_reply", "open", TRUSTED))

    def test_a_policy_routing_a_bound_reply_to_the_peer_lane_is_never_sent(self):
        """Never peer traffic: a policy answering with the peer lane is a
        transport anomaly, with nothing allocated and nothing placed."""
        cfg = self.cfg()
        nid = self.ledger(cfg, counterparty=TRUSTED, admission="open")
        write_request(cfg, "alice", "00000001", to=[TRUSTED], in_reply_to=nid)
        self.drain(cfg, cold_policy=lambda c, s, d: outbound.PeerRoute("bob"))
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "transport_anomaly"))
        self.nothing_allocated(cfg)
        self.assertFalse((self.tmp / "instances" / "bob" / "peer").exists())

    def test_a_record_without_a_tree_is_unresolved(self):
        """Mail placed from the hop leg always records its tree; a record
        without one is not taken for mail."""
        cfg = self.cfg()
        nid = self.ledger(cfg, drop=("tree",))
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.answered(cfg)["reason_code"], "unresolved_reply")
        self.nothing_allocated(cfg)

    def test_decided_before_the_trusted_host_rule(self):
        """A draft naming a trusted host (the peer-task rule's class, which
        would refuse two recipients as fleet_mail_disabled) is still a bound
        reply to the counterparty."""
        cfg = self.cfg()
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED, f"x@{T1}"], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])
        self.assertEqual(self.handover()["request"]["draft"]["to"], [CP])

    def test_fleet_hosts_admission_bypasses_egress(self):
        """No `remote_fleet` for the host: mail there would be held; the
        binding permits the reply, under the policy plus the binding."""
        cfg = self.cfg()
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])
        record = inflight.read_record(cfg, "alice", "00000001")
        pinned = record["bound_reply"]["binding"]
        self.assertEqual(record["policy_digest"], classify.digest_of(
            dict(classify.policy_object(cfg, "alice"), binding=pinned)))
        self.assertNotEqual(record["policy_digest"], classify.policy_digest(cfg, "alice"))

    def test_inbound_allowlist_admission_bypasses_egress(self):
        cfg = self.cfg()
        nid = self.ledger(cfg, admission="inbound_allowlist")
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.handover()["envelope"]["bound"]["admission"], "inbound_allowlist")

    def test_open_admission_refused_by_egress_is_queued(self):
        cfg = self.cfg()
        nid = self.ledger(cfg, admission="open")
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "recipient_not_allowlisted"))
        self.nothing_allocated(cfg)

    def test_open_admission_permitted_by_egress_carries_the_mail_digest(self):
        cfg = self.cfg(alice={"remote_fleet": [HUB2]})
        nid = self.ledger(cfg, admission="open")
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        bound = self.handover()["envelope"]["bound"]
        self.assertEqual(bound["admission"], "open")
        self.assertEqual(bound["policy_digest"], classify.policy_digest(cfg, "alice"))

    def test_an_absent_admission_is_open_written_explicitly(self):
        """Absent maps to open: egress decides (refused here, with no
        `remote_fleet`), and the envelope says "open"."""
        cfg = self.cfg()
        nid = self.ledger(cfg, drop=("admission",))
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.answered(cfg)["reason_code"], "recipient_not_allowlisted")
        self.nothing_allocated(cfg)
        allowed = self.cfg(alice={"remote_fleet": [HUB2]})
        nid = self.ledger(allowed, drop=("admission",))
        write_request(allowed, "alice", "00000002", to=[CP], in_reply_to=nid)
        self.drain(allowed)
        self.assertEqual(self.handover()["envelope"]["bound"]["admission"], "open")

    def hop_cfg(self, document):
        return dataclasses.replace(self.cfg(), hop=config_mod.HopConfig(
            root=str(self.tmp / "hop"), peer_uid=os.getuid(), version_write=1,
            caps=(("document", document), ("request", 1 << 16), ("attachment", 1 << 20),
                  ("total", 1 << 22))))

    def test_a_bound_reply_over_the_document_cap_is_refused_before_allocation(self):
        cfg = self.hop_cfg(400)
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "malformed_request"))
        self.assertIn("hop document cap (400)", r["detail"])
        self.nothing_allocated(cfg)

    def test_a_bound_reply_within_the_document_cap_is_begun(self):
        """The control: the same reply under a large cap is begun (this
        test's hop has no pinned generation, so it is not handed over)."""
        cfg = self.hop_cfg(1 << 20)
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertIsNone(self.result(cfg))
        self.assertEqual(inflight.list_records(cfg, "alice"), ["00000001"])


class PublicationRecheckTests(_Case):
    """The re-check at every publication attempt, for a bound reply. Each
    record is staged unpublished (the first drain runs with the reload
    failing), then published under a changed config."""

    def stage(self, cfg, **ledger):
        nid = self.ledger(cfg, **ledger)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.assertEqual(inflight.list_records(cfg, "alice"), ["00000001"])
        self.assertEqual(self.port.writes, [])
        return nid

    def refused(self, cfg, why):
        self.assertEqual(self.port.writes, [])
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "recipient_not_allowlisted"))
        self.assertIn(why, r["detail"])

    def test_fleet_hosts_reply_stays_publishable_when_egress_would_refuse(self):
        cfg = self.cfg(alice={"remote_fleet": [HUB2]})
        self.stage(cfg)
        self.drain(self.cfg())
        self.assertEqual(self.port.writes, ["00000001"])

    def test_open_reply_is_queued_when_egress_changes(self):
        cfg = self.cfg(alice={"remote_fleet": [HUB2]})
        self.stage(cfg, admission="open")
        self.drain(self.cfg())
        self.refused(cfg, "now recipient_not_allowlisted")

    def test_a_removed_ledger_record_is_queued(self):
        cfg = self.cfg()
        nid = self.stage(cfg)
        binding.ledger_path(cfg.state_dir, "alice", nid, state_key=LID).unlink()
        self.drain(cfg)
        self.refused(cfg, "binding no longer resolves")

    def test_a_changed_ledger_record_is_queued(self):
        cfg = self.cfg()
        nid = self.stage(cfg)
        p = binding.ledger_path(cfg.state_dir, "alice", nid, state_key=LID)
        rec = json.loads(p.read_text())
        rec["counterparty"] = f"dave@{HUB2}"
        p.write_text(json.dumps(rec))
        self.drain(cfg)
        self.refused(cfg, "its ledger record changed")

    def test_a_counterparty_no_longer_a_fleet_host_is_queued(self):
        cfg = self.cfg()
        self.stage(cfg)
        self.drain(self.cfg(top={"fleet_hosts": [T1, "t2.fleet.example"]}))
        self.refused(cfg, "route changed from fleet_host to internet")

    def test_a_trusted_host_counterparty_stays_publishable(self):
        cfg = self.cfg()
        nid = self.ledger(cfg, counterparty=TRUSTED)
        write_request(cfg, "alice", "00000001", to=[TRUSTED], in_reply_to=nid)
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.assertEqual(self.port.writes, [])
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_expiry_passing_after_begin_still_publishes(self):
        cfg = self.cfg()
        self.stage(cfg, expires="2030-01-01T00:00:00Z")
        with mock.patch.object(outbound, "utc_ts", return_value="2031-01-01T00:00:00Z"):
            self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_the_bound_handed_over_is_the_pinned_one(self):
        """A policy change that still permits a fleet_hosts reply would give
        a different digest if the bound were rebuilt now: the one handed over
        is the record's."""
        cfg = self.cfg()
        self.stage(cfg)
        pinned = inflight.read_record(cfg, "alice", "00000001")["bound_reply"]["bound"]
        changed = self.cfg(alice={"remote_fleet": [HUB2]})
        self.assertNotEqual(classify.policy_digest(changed, "alice"),
                            classify.policy_digest(cfg, "alice"))
        self.drain(changed)
        self.assertEqual(self.handover()["envelope"]["bound"], pinned)

    def test_two_builds_of_one_record_are_byte_identical(self):
        cfg = self.cfg()
        self.stage(cfg)
        record = inflight.read_record(cfg, "alice", "00000001")
        a = inflight.transport_request_bytes(cfg, "alice", record, req_id="00000001")
        b = inflight.transport_request_bytes(cfg, "alice", record, req_id="00000001")
        self.assertEqual(a, b)
        self.assertEqual(json.loads(a)["envelope"]["bound"], record["bound_reply"]["bound"])


class RecordSchemaTests(_Case):

    def staged(self):
        cfg = self.cfg()
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        return inflight.read_record(cfg, "alice", "00000001")

    def test_a_pin_naming_another_recipient_is_damage(self):
        record = self.staged()
        record["recipients"] = [f"dave@{HUB2}"]
        with self.assertRaisesRegex(inflight.RecordDamaged, "other than the evaluated one"):
            inflight.check_record(record)

    def test_a_pin_whose_digest_is_not_the_records_is_damage(self):
        record = self.staged()
        record["policy_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(inflight.RecordDamaged, "policy_digest is not the record"):
            inflight.check_record(record)

    def test_an_invalid_bound_is_damage(self):
        record = self.staged()
        record["bound_reply"]["bound"]["origin_generation"] = "nothex"
        with self.assertRaisesRegex(inflight.RecordDamaged, "origin_generation"):
            inflight.check_record(record)


class BoundObjectTests(unittest.TestCase):

    def bound(self, **kw):
        b = {"bound_address": CP, "origin_notice_id": "up-1.a", "origin_link": LINK,
             "origin_generation": GEN, "participants": {"agent": LID, "counterparty": CP},
             "admission": "open", "admission_link": LINK, "admission_rule": RULE,
             "policy_digest": "sha256:" + "a" * 64}
        b.update(kw)
        return b

    def test_valid(self):
        self.assertIsNone(hoplink.bound_problem(self.bound()))

    def test_each_member_outside_its_grammar(self):
        for key, value in (("origin_notice_id", ".lead"), ("origin_notice_id", "a" * 129),
                           ("origin_link", "Hub"), ("origin_generation", "a" * 31),
                           ("admission", "fleet"), ("admission_link", "-x"),
                           ("admission_rule", "R"), ("policy_digest", "sha256:abc"),
                           ("bound_address", "carol")):
            with self.subTest(key=key, value=value):
                self.assertIsNotNone(hoplink.bound_problem(self.bound(**{key: value})))

    def test_a_trailing_newline_is_outside_every_grammar(self):
        self.assertIsNotNone(hoplink.bound_problem(self.bound(origin_link=LINK + "\n")))

    def test_bound_address_must_equal_the_counterparty_exactly(self):
        why = hoplink.bound_problem(self.bound(bound_address=f"Carol@{HUB2}"))
        self.assertEqual(why, "bound_address is not participants.counterparty exactly")

    def test_build_handover_kinds(self):
        common = dict(from_address=f"alice@{FD}", version_write=1, attachments=(),
                      settled_through=0)
        mail = json.loads(hoplink.build_handover({}, **common))
        self.assertEqual(mail["envelope"], {"from_address": f"alice@{FD}", "hop_contract": 1,
                                            "kind": "mail"})
        reply = json.loads(hoplink.build_handover({}, kind="bound_reply", bound=self.bound(),
                                                  **common))
        self.assertEqual(reply["envelope"], {"from_address": f"alice@{FD}", "hop_contract": 1,
                                             "kind": "bound_reply", "bound": self.bound()})
        with self.assertRaises(ValueError):
            hoplink.build_handover({}, kind="bound_reply", bound=None, **common)
        with self.assertRaises(ValueError):
            hoplink.build_handover({}, kind="mail", bound=self.bound(), **common)

    def test_handover_len_max_is_the_built_length_at_the_maxima(self):
        request = {"draft": {"to": [CP]}, "req_id": "00000001"}
        for sizes in ((), (0,), (1, 2, 3, 1000)):
            with self.subTest(sizes=sizes):
                built = hoplink.build_handover(
                    dict(request, req_id="9" * 18), from_address=f"alice@{FD}",
                    version_write=1, settled_through=10 ** 18 - 1, kind="bound_reply",
                    bound=self.bound(),
                    attachments=[__import__("base64").b64encode(b"x" * n).decode()
                                 for n in sizes])
                self.assertEqual(hoplink.handover_len_max(
                    request, from_address=f"alice@{FD}", version_write=1,
                    attachment_sizes=sizes, kind="bound_reply", bound=self.bound()),
                    len(built))


class DeliveredDomainsTests(_Case):
    """`delivered_domains_file`: the delivered-domain set the downstream hub
    delivers to, as the deployment renders it. The shape here is synthetic,
    in that deployment's form; PROVISIONAL: the deployment's layout for it is
    not yet frozen."""

    def artifact(self, domains, *, sha=None, mode=0o644, name="delivered.json"):
        p = self.tmp / name
        p.write_text(json.dumps({
            "delivered_domains": domains,
            "sha256": sha if sha is not None else config_mod.delivered_domains_hash(domains),
            "attestation": {"by": "deploy", "at": "2026-10-13T00:00:00Z",
                            "statement": "synthetic"}}), encoding="utf-8")
        os.chmod(p, mode)
        return p

    def with_file(self, path):
        return self.cfg(top={"delivered_domains_file": str(path)})

    def test_the_hash_is_the_sorted_lowercased_lines(self):
        self.assertEqual(config_mod.delivered_domains_hash(["B.example.org", "a.example.org"]),
                         hashlib.sha256(b"a.example.org\nb.example.org\n").hexdigest())

    def test_an_agreeing_set_loads_with_no_drift(self):
        cfg = self.with_file(self.artifact([T1, "T2.fleet.example", HUB2]))
        self.assertIsNone(cfg.delivered_drift)

    def test_a_hash_mismatch_is_refused(self):
        p = self.artifact([T1, "t2.fleet.example", HUB2], sha="0" * 64)
        with self.assertRaisesRegex(ConfigError, "sha256 does not match"):
            self.with_file(p)

    def test_a_symlink_is_refused(self):
        real = self.artifact([T1, "t2.fleet.example", HUB2])
        link = self.tmp / "link.json"
        link.symlink_to(real)
        with self.assertRaisesRegex(ConfigError, "is a symlink"):
            self.with_file(link)

    def test_a_foreign_owner_is_refused(self):
        p = self.artifact([T1, "t2.fleet.example", HUB2])
        with mock.patch.object(config_mod, "_delivered_domains_uids",
                               return_value=(os.geteuid() + 1,)):
            with self.assertRaisesRegex(ConfigError, "not root or this process"):
                self.with_file(p)

    def test_a_group_writable_file_is_refused(self):
        p = self.artifact([T1, "t2.fleet.example", HUB2], mode=0o664)
        with self.assertRaisesRegex(ConfigError, "writable by group or others"):
            self.with_file(p)

    def test_a_file_inside_an_agent_root_is_refused(self):
        p = self.artifact([T1, "t2.fleet.example", HUB2])
        inside = self.tmp / "instances" / "alice" / "d.json"
        inside.parent.mkdir(parents=True, exist_ok=True)
        inside.write_bytes(p.read_bytes())
        with self.assertRaisesRegex(ConfigError, "which an agent can reach"):
            self.with_file(inside)

    def test_a_set_difference_logs_counts_not_domains(self):
        p = self.artifact([T1, "t2.fleet.example", "other.example.org"])
        with self.assertLogs("amap_router_local.config", logging.ERROR) as logs:
            cfg = self.with_file(p)
        self.assertEqual(cfg.delivered_drift, (1, 1))
        line = "\n".join(logs.output)
        self.assertIn("1 delivered but not a fleet host, 1 fleet hosts not delivered", line)
        self.assertNotIn("other.example.org", line)
        self.assertNotIn(HUB2, line)

    def test_a_set_difference_holds_bound_replies_only(self):
        p = self.artifact([T1, "t2.fleet.example"])
        cfg = self.cfg(top={"delivered_domains_file": str(p)},
                       alice={"remote_fleet": [HUB2]})
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        write_request(cfg, "alice", "00000002", to=[f"dave@{HUB2}"])
        self.drain(cfg)
        self.assertIsNone(self.result(cfg))
        self.assertTrue((cfg.instances["alice"].outbox_root / "req-00000001.json").exists())
        self.assertEqual(inflight.list_records(cfg, "alice"), ["00000002"])
        self.assertEqual(self.port.writes, ["00000001"])
        self.assertEqual(self.handover()["envelope"]["kind"], "mail")

    def test_a_set_difference_after_begin_refuses_publication(self):
        cfg = self.cfg()
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.drain(self.with_file(self.artifact([T1])))
        self.assertEqual(self.port.writes, [])
        self.assertIn("delivered-domain set differs", self.answered(cfg)["detail"])

    def test_an_absent_key_changes_nothing(self):
        cfg = self.cfg()
        self.assertIsNone(cfg.delivered_domains_file)
        self.assertIsNone(cfg.delivered_drift)
        nid = self.ledger(cfg)
        write_request(cfg, "alice", "00000001", to=[CP], in_reply_to=nid)
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])


if __name__ == "__main__":
    unittest.main()
