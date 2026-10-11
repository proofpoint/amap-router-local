"""Held local delivery under a registry (router/README.md, "Held local
delivery"): a local target the poll's report does not resolve HOLDS the
request — no Result, nothing on the recipient's side, the request kept —
and on recovery it is delivered exactly once.

The fleet: alpha <-> bravo and alpha <-> charlie are mail pairs, and alpha
may task delta on the peer lane. Everything is migrated under a registry
before each test, so every resolved instance's private state is under its
logical_id.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import replace
from pathlib import Path
from unittest import mock

from router import binding, deliver as deliver_mod, outbound, outcomes, registry, service
from router.config import HELD_REPORT_MISSING
from router.tests.helpers import (
    RouterTestCase, adopt_test_markers, gen_state, keyed_for_poll, list_notices, notices_dir, read_json,
    result_path, write_request,
)
from router.tests.peer_helpers import addr, list_peer_notices, make_peer_config, write_outcome

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "registry"
NAMES = ("alpha", "bravo", "charlie", "delta")
LIDS = {"alpha": "a1" * 16, "bravo": "b2" * 16, "charlie": "c3" * 16, "delta": "d4" * 16,
        "brav0": "e5" * 16, "de1ta": "e6" * 16, "a1pha": "e7" * 16}
#: An active registry name whose skeleton collides with each target's.
COLLIDER = {"bravo": "brav0", "delta": "de1ta", "alpha": "a1pha"}
REASONS = ("not_registered", "skeleton_collision", "registry_unavailable",
           "registry_rolled_back", "state_not_migrated", "state_conflict")
GLOBAL = ("registry_unavailable", "registry_rolled_back")


class Crash(BaseException):
    """A crash: nothing in the router catches it."""


def snapshot(names, seq):
    doc = json.loads((FIXTURES / "snapshot.json").read_text())
    proto = next(e for e in doc["entries"] if e["state"] == "active")
    entries = []
    for n in names:
        e = json.loads(json.dumps(proto))
        e.update(logical_id=LIDS[n], name=n, stable_key=f"/srv/work/{n}")
        e["names"][0]["name"] = n
        e["bindings"][0]["stable_key"] = f"/srv/work/{n}"
        entries.append(e)
    doc["entries"] = entries
    doc["seq"] = seq
    return doc


class _Fleet(RouterTestCase):

    def setUp(self):
        super().setUp()
        plain = make_peer_config(self, {
            "alpha": {"peers": ["bravo", "charlie"]},
            "bravo": {"peers": ["alpha"]},
            "charlie": {"peers": ["alpha"]},
            "delta": {"peer_senders": ["alpha"]},
        })
        for n in NAMES:
            if (self.state_dir / n).exists():
                (self.state_dir / n).rename(self.state_dir / LIDS[n])
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        self.seq = 2
        self.put()
        self.cfg = replace(plain, registry_dir=self.reg)
        adopt_test_markers(self.cfg)
        service._REGISTRY_LOGGED.clear()

    # -- the registry ---------------------------------------------------

    def put(self, names=NAMES, seq=None):
        if seq is None:
            self.seq += 1
            seq = self.seq
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(snapshot(list(names), seq)))

    def hold(self, reason, target):
        others = [n for n in NAMES if n != target]
        if reason == "not_registered":
            self.put(others)
        elif reason == "skeleton_collision":
            self.put(list(NAMES) + [COLLIDER[target]])
        elif reason == "registry_unavailable":
            (self.reg / registry.SNAPSHOT).unlink()
        elif reason == "registry_rolled_back":
            registry.report_for(self.reg, self.state_dir, NAMES)   # a poll accepted self.seq
            self.put(seq=self.seq - 2)
        elif reason == "state_not_migrated":
            (self.state_dir / LIDS[target]).rename(self.state_dir / target)
        elif reason == "state_conflict":
            (self.state_dir / target).mkdir()

    def recover(self, reason, target):
        if reason == "state_not_migrated":
            (self.state_dir / target).rename(self.state_dir / LIDS[target])
        elif reason == "state_conflict":
            (self.state_dir / target).rmdir()
        elif reason == "registry_rolled_back":
            self.seq += 5
        self.put()

    # -- polls and observations ----------------------------------------

    def poll(self):
        log = logging.getLogger("amap_router_local")
        log.disabled = True
        try:
            return service.run_once(self.cfg, None)
        finally:
            log.disabled = False

    def keyed(self):
        return keyed_for_poll(self.cfg)

    def recipient_side(self, name):
        """Every file a delivery to `name` could create: its trees, and its
        ledger under its logical_id."""
        out = []
        for base in (self.cfg.instances[name].root, self.state_dir / LIDS[name] / "delivered"):
            for root, _dirs, files in os.walk(base):
                out += [os.path.join(root, f) for f in files]
        return sorted(out)

    def pending(self, sender, req_id):
        return gen_state(self.state_dir, LIDS[sender]) / outbound.PENDING_DIR / f"{req_id}.json"

    def assertRetained(self, sender, req_id):
        outbox = self.cfg.instances[sender].outbox_root
        self.assertTrue((outbox / f"req-{req_id}.json").is_file(), "the request was consumed")
        self.assertFalse(result_path(self.cfg, sender, req_id).exists(), "a Result was written")
        self.assertFalse((gen_state(self.state_dir, LIDS[sender]) / "results"
                          / f"{req_id}.json").exists())

    def result(self, sender, req_id):
        return read_json(result_path(self.cfg, sender, req_id))


class EveryHoldReasonTests(_Fleet):
    """For each hold reason, on the mail lane and the peer lane: nothing on
    the recipient's side and the request kept while held; exactly one
    delivery after recovery."""

    def run_case(self, reason, lane):
        target = "bravo" if lane == "mail" else "delta"
        before = self.recipient_side(target)
        self.hold(reason, target)
        write_request(self.cfg, "alpha", "00000001", to=[addr(target)], body_text="go")
        self.poll()
        self.poll()                                  # repeated held polls
        self.assertRetained("alpha", "00000001")
        self.assertEqual(self.recipient_side(target), before,
                         "a held delivery touched the recipient's side")
        if reason not in GLOBAL:
            rec = json.loads(self.pending("alpha", "00000001").read_text())
            self.assertEqual([(t["recipient"], t["state"], t["reason"]) for t in rec["targets"]],
                             [(target, "held", reason)])
        self.recover(reason, target)
        self.poll()
        res = self.result("alpha", "00000001")
        self.assertEqual(res["outcome"], "accepted", res)
        notices = list_notices(self.cfg, target) if lane == "mail" else \
            list_peer_notices(self.cfg, target)
        self.assertEqual(len(notices), 1, "not exactly one delivery after recovery")
        self.assertFalse(self.pending("alpha", "00000001").exists())
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, target) if lane == "mail" else
                             list_peer_notices(self.cfg, target)), 1, "re-delivered")

    def test_mail(self):
        for reason in REASONS:
            with self.subTest(reason=reason):
                self.setUp()
                self.run_case(reason, "mail")

    def test_peer(self):
        for reason in REASONS:
            with self.subTest(reason=reason):
                self.setUp()
                self.run_case(reason, "peer")


class RepliesTests(_Fleet):
    """Replies hold on a held target with their binding PINNED."""

    def mail_task(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        return self.result("alpha", "00000001")["message_id"]

    def peer_task(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        res = self.result("alpha", "00000001")
        self.assertEqual(res["reason_code"], "peer_routed")
        return res["message_id"]

    def test_mail_reply_to_a_held_sender_holds_then_binds(self):
        for reason in REASONS:
            with self.subTest(reason=reason):
                self.setUp()
                task = self.mail_task()
                before = self.recipient_side("alpha")
                self.hold(reason, "alpha")
                write_request(self.cfg, "bravo", "00000002", in_reply_to=task,
                              to=[addr("alpha")], body_text="re")
                self.poll()
                self.assertRetained("bravo", "00000002")
                self.assertEqual(self.recipient_side("alpha"), before)
                self.recover(reason, "alpha")
                self.poll()
                res = self.result("bravo", "00000002")
                self.assertEqual((res["outcome"], res["reason_code"]),
                                 ("accepted", "recipient_bound"))
                self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)

    def test_peer_reply_to_a_held_sender_holds_then_binds(self):
        for reason in REASONS:
            with self.subTest(reason=reason):
                self.setUp()
                task = self.peer_task()
                before = self.recipient_side("alpha")
                self.hold(reason, "alpha")
                write_request(self.cfg, "delta", "00000002", in_reply_to=task,
                              to=[addr("alpha")], body_text="re")
                self.poll()
                self.assertRetained("delta", "00000002")
                self.assertEqual(self.recipient_side("alpha"), before)
                self.recover(reason, "alpha")
                self.poll()
                res = self.result("delta", "00000002")
                self.assertEqual((res["outcome"], res["reason_code"]), ("accepted", "peer_routed"))
                self.assertEqual(len(list_peer_notices(self.cfg, "alpha")), 1)

    def test_peer_reply_eligible_at_first_evaluation_survives_the_wait(self):
        task = self.peer_task()
        self.hold("not_registered", "alpha")
        write_request(self.cfg, "delta", "00000002", in_reply_to=task, to=[addr("alpha")])
        self.poll()
        self.assertRetained("delta", "00000002")
        rec = json.loads(self.pending("delta", "00000002").read_text())
        self.assertTrue(rec["binding"]["window_ok"])
        # The window passes while held: the pinned eligibility still stands.
        self.cfg = replace(self.cfg, peer_reply_window_seconds=1)
        led = binding.ledger_path(self.state_dir, "delta", task, state_key=LIDS["delta"])
        doc = json.loads(led.read_text())
        doc["ts"] = "2000-01-01T00:00:00Z"
        led.write_text(json.dumps(doc))
        self.recover("not_registered", "alpha")
        self.poll()
        res = self.result("delta", "00000002")
        self.assertEqual((res["outcome"], res["reason_code"]), ("accepted", "peer_routed"))
        self.assertEqual(len(list_peer_notices(self.cfg, "alpha")), 1)

    def test_peer_reply_expired_at_first_evaluation_is_refused_not_pinned(self):
        task = self.peer_task()
        led = binding.ledger_path(self.state_dir, "delta", task, state_key=LIDS["delta"])
        doc = json.loads(led.read_text())
        doc["ts"] = "2000-01-01T00:00:00Z"
        led.write_text(json.dumps(doc))
        self.hold("not_registered", "alpha")
        write_request(self.cfg, "delta", "00000002", in_reply_to=task, to=[addr("alpha")])
        self.poll()
        res = self.result("delta", "00000002")
        self.assertEqual((res["outcome"], res["reason_code"]),
                         ("rejected", "peer_reply_window_expired"))
        self.assertFalse(self.pending("delta", "00000002").exists())


class RouterNoticeTests(_Fleet):
    """A DSN to a held sender is queued (durably, before the outcome is
    recorded) and placed exactly once after recovery."""

    def denied_task(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        write_outcome(self.cfg, "delta", nid, "denied")
        return nid

    def intents(self):
        d = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        return sorted(p.name for p in d.iterdir() if not p.name.startswith(".")) \
            if d.is_dir() else []

    def test_every_hold_reason(self):
        for reason in REASONS:
            with self.subTest(reason=reason):
                self.setUp()
                nid = self.denied_task()
                before = self.recipient_side("alpha")
                self.hold(reason, "alpha")
                self.poll()
                self.poll()
                self.assertEqual(self.recipient_side("alpha"), before,
                                 "a DSN reached a held sender")
                self.recover(reason, "alpha")
                self.poll()
                dsns = list_notices(self.cfg, "alpha")
                self.assertEqual(len(dsns), 1, "not exactly one DSN after recovery")
                self.assertEqual(self.intents(), [])
                self.poll()
                self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)

    def test_the_dsn_carries_the_pre_minted_id(self):
        nid = self.denied_task()
        self.hold("not_registered", "alpha")
        self.poll()
        [name] = self.intents()
        intent = json.loads((self.state_dir / LIDS["delta"] / outcomes.DSN_DIR / name).read_text())
        self.recover("not_registered", "alpha")
        self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [f"notice-{intent['dsn_notice_id']}.json"])


class NoReportFailsClosedTests(_Fleet):
    """A placement under a registry with no report attached places nothing."""

    def test_every_placement_function(self):
        cfg = self.cfg                                 # registry_dir set, no report
        doc = {"contract_version": "2", "req_id": "00000001",
               "draft": {"to": [addr("bravo")], "subject": "s", "body_text": "b"}}
        before = {n: self.recipient_side(n) for n in ("bravo", "delta", "alpha")}
        calls = (
            lambda: deliver_mod.deliver(cfg, cfg.state_dir, "alpha", "bravo", doc),
            lambda: deliver_mod.deliver_peer(cfg, cfg.state_dir, "alpha", "delta", doc),
            lambda: deliver_mod.deliver_router_notice(cfg, cfg.state_dir, "alpha", subject="s",
                                                      body_text="b", in_reply_to=None),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(deliver_mod.RecipientHeld) as cm:
                    call()
                self.assertEqual(cm.exception.reason, HELD_REPORT_MISSING)
        self.assertEqual({n: self.recipient_side(n) for n in before}, before)


class MixedRecipientsTests(_Fleet):
    """alpha -> {bravo (held), charlie}: charlie is delivered at once and
    never again; bravo after recovery; then ONE Result naming both."""

    def test_completed_recipients_are_never_redelivered(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo"), addr("charlie")])
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "charlie")), 1)
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        self.assertRetained("alpha", "00000001")
        self.poll()
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "charlie")), 1, "charlie re-delivered")
        self.recover("not_registered", "bravo")
        self.poll()
        self.assertEqual((len(list_notices(self.cfg, "bravo")),
                          len(list_notices(self.cfg, "charlie"))), (1, 1))
        res = self.result("alpha", "00000001")
        self.assertEqual((res["outcome"], res["reason_code"]), ("accepted", "allowlisted"))
        self.assertEqual(sorted(res["recipients"]), [addr("bravo"), addr("charlie")])


class FreshPolicyTests(_Fleet):
    """Fresh policy applies to a pending request every poll; a refusal is
    terminal and reports what was already delivered."""

    def unpair(self):
        doc = {"state_dir": str(self.state_dir), "fleet_domain": "example.invalid",
               "registry_dir": str(self.reg), "instances": {}}
        for n in NAMES:
            entry = {"handoff_dir": str(self.tmp / "instances" / n)}
            if n == "alpha":
                entry["peers"] = ["charlie"]
            elif n == "charlie":
                entry["peers"] = ["alpha"]
            elif n == "delta":
                entry["peer_senders"] = ["alpha"]
            doc["instances"][n] = entry
        from router.config import load_obj
        self.cfg = load_obj(doc)

    def test_a_refusal_wins_and_keeps_the_delivered_history(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo"), addr("charlie")])
        self.poll()
        self.unpair()                                 # alpha <-> bravo is no longer a pair
        self.recover("not_registered", "bravo")
        self.poll()
        res = self.result("alpha", "00000001")
        self.assertEqual((res["outcome"], res["reason_code"]),
                         ("queued_for_human", "recipient_not_allowlisted"))
        self.assertEqual(res["recipients"], [addr("charlie")])
        self.assertIn("already delivered", res["detail"])
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        self.assertFalse(self.pending("alpha", "00000001").exists())


class RequestIdentityTests(_Fleet):

    def make_pending(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        self.assertTrue(self.pending("alpha", "00000001").is_file())

    def test_a_changed_request_does_not_change_the_held_work(self):
        """A version-2 record carries its own snapshot: when the file under
        its id changes (a reused id), the ORIGINAL request is still the one
        delivered, it settles privately (nothing published or archived for
        it), and the changed file is then refused as req_id_reused."""
        self.make_pending()
        original = self.cfg.instances["alpha"].outbox_root / "req-00000001.json"
        sent = json.loads(original.read_text())["draft"]["body_text"]
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="CHANGED")
        self.recover("not_registered", "bravo")
        self.poll()
        notices = list_notices(self.cfg, "bravo")
        self.assertEqual(len(notices), 1, "the held work was not delivered")
        spool = json.loads((self.cfg.instances["bravo"].inbox_root / "messages" / notices[0])
                           .read_text())
        self.assertEqual(spool["body_text"], sent, "the changed file was delivered")
        anchor = gen_state(self.state_dir, LIDS["alpha"]) / "results" / "00000001.json"
        self.assertEqual(json.loads(anchor.read_text())["result"]["outcome"], "accepted")
        self.assertFalse(self.pending("alpha", "00000001").exists())
        self.poll()
        r = self.result("alpha", "00000001")
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)

    def test_a_changed_request_blocks_a_version_1_record(self):
        """A version-1 record (no snapshot) still requires the live file to
        be its request: changed, it blocks and delivers nothing."""
        self.make_pending()
        path = self.pending("alpha", "00000001")
        rec = json.loads(path.read_text())
        rec["v"] = 1
        for k in ("snapshot", "source_gen", "from_address", "aliases"):
            rec.pop(k, None)
        for t in rec["targets"]:
            t.pop("recipient_gen", None)
            t.pop("address", None)
        path.write_text(json.dumps(rec))
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="CHANGED")
        self.recover("not_registered", "bravo")
        self.poll()
        self.assertRetained("alpha", "00000001")
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        rec = json.loads(path.read_text())
        self.assertEqual(rec["block"], outbound.BLOCK_REQUEST_CHANGED)
        held = outbound.held_report(self.keyed(), "alpha")
        self.assertEqual(held[0]["block"], outbound.BLOCK_REQUEST_CHANGED)

    def test_a_damaged_record_fails_closed(self):
        self.make_pending()
        self.pending("alpha", "00000001").write_text("{not json")
        self.recover("not_registered", "bravo")
        self.poll()
        self.assertRetained("alpha", "00000001")
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        held = outbound.held_report(self.keyed(), "alpha")
        self.assertIn("damaged", held[0])

    def test_a_reused_name_never_reroutes_a_bound_delivery(self):
        """bravo is bound (delivering, logical_id recorded) when the process
        crashes; the name then resolves to ANOTHER identity: held as
        identity_changed, nothing placed for the newcomer."""
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        self.recover("not_registered", "bravo")
        with mock.patch.object(outbound, "_place_target", side_effect=Crash):
            with self.assertRaises(Crash):
                self.poll()
        rec = json.loads(self.pending("alpha", "00000001").read_text())
        self.assertEqual((rec["targets"][0]["state"], rec["targets"][0]["lid"]),
                         ("delivering", LIDS["bravo"]))
        LIDS["bravo"], old = "f6" * 16, LIDS["bravo"]
        try:
            (self.state_dir / old).rename(self.state_dir / LIDS["bravo"])
            self.put()
            self.poll()
        finally:
            LIDS["bravo"] = old
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        rec = json.loads(self.pending("alpha", "00000001").read_text())
        self.assertEqual(rec["targets"][0]["reason"], outbound.HOLD_IDENTITY_CHANGED)


class RepeatedHeldPollsTests(_Fleet):
    def test_one_audit_line_and_no_rewrite_per_quiet_poll(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        path = self.pending("alpha", "00000001")
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        for _ in range(5):
            self.poll()
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)
        from router import audit
        lines = [e for e in audit.read_events(self.state_dir, "alpha", state_key=LIDS["alpha"])
                 if e.get("event") == "delivery_held"]
        self.assertEqual(len(lines), 1)
        held = outbound.held_report(self.keyed(), "alpha")
        self.assertEqual(held[0]["targets"],
                         [{"recipient": "bravo", "state": "held", "reason": "not_registered"}])


class CrashAndBarrierTests(_Fleet):
    """P4': whatever stage a crash or a failed barrier hits, recovery offers
    exactly one notice id to the target, and the request gets one Result."""

    def start(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        self.recover("not_registered", "bravo")

    def finish_and_check(self):
        self.poll()
        res = self.result("alpha", "00000001")
        self.assertEqual(res["outcome"], "accepted", res)
        notices = list_notices(self.cfg, "bravo")
        self.assertEqual(len(notices), 1, notices)
        ledger = sorted((self.state_dir / LIDS["bravo"] / "delivered").glob("notice-*.json"))
        self.assertEqual([p.name for p in ledger], notices, "a second ledger record or id")
        self.assertFalse(self.pending("alpha", "00000001").exists())
        return notices[0]

    def crash_at(self, target, attr, nth=1):
        real = getattr(target, attr)
        calls = {"n": 0}

        def boom(*a, **kw):
            calls["n"] += 1
            if calls["n"] == nth:
                raise Crash
            return real(*a, **kw)
        return mock.patch.object(target, attr, boom)

    def test_failed_barrier_on_the_delivering_write_places_nothing(self):
        self.start()
        with mock.patch.object(outbound, "_write_pending", side_effect=OSError("EIO")):
            self.poll()
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        self.finish_and_check()

    def test_crash_after_delivering_before_placement(self):
        self.start()
        with self.crash_at(outbound, "_place_target"):
            with self.assertRaises(Crash):
                self.poll()
        nid = json.loads(self.pending("alpha", "00000001").read_text())["targets"][0]["notice_id"]
        self.assertEqual(self.finish_and_check(), f"notice-{nid}.json")

    def test_crash_at_each_placement_stage(self):
        stages = (
            (deliver_mod.attachments_mod, "publish_attachment_blobs", 1),
            (deliver_mod.attachments_mod, "write_agent_visible", 1),   # message spool
            (deliver_mod, "atomic_write", 1),                         # ledger
            (deliver_mod.attachments_mod, "write_agent_visible", 2),   # notice
        )
        for target, attr, nth in stages:
            with self.subTest(stage=f"{attr}#{nth}"):
                self.setUp()
                self.start()
                with self.crash_at(target, attr, nth):
                    with self.assertRaises(Crash):
                        self.poll()
                nid = json.loads(self.pending("alpha", "00000001").read_text())["targets"][0]["notice_id"]
                self.assertEqual(self.finish_and_check(), f"notice-{nid}.json")

    def test_crash_after_placement_before_the_delivered_update(self):
        self.start()
        real = outbound._write_pending

        def boom(cfg, path, rec):
            if any(t["state"] == "delivered" for t in rec["targets"]):
                raise Crash
            return real(cfg, path, rec)
        with mock.patch.object(outbound, "_write_pending", boom):
            with self.assertRaises(Crash):
                self.poll()
        nid = json.loads(self.pending("alpha", "00000001").read_text())["targets"][0]["notice_id"]
        self.assertEqual(list_notices(self.cfg, "bravo"), [f"notice-{nid}.json"])
        self.assertEqual(self.finish_and_check(), f"notice-{nid}.json")

    def test_crash_at_the_result_or_the_record_removal(self):
        for target, attr in ((outbound, "_finish"), (outbound, "_remove_pending")):
            with self.subTest(at=attr):
                self.setUp()
                self.start()
                with self.crash_at(target, attr):
                    with self.assertRaises(Crash):
                        self.poll()
                self.finish_and_check()


class DsnCrashTests(_Fleet):
    """P6': the intent is durable BEFORE the outcome is recorded or unlinked;
    every crash point recovers to exactly one DSN, with the pre-minted id."""

    def denied(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        return nid

    def outcome_file(self, nid):
        from router.tests.peer_helpers import outcomes_dir
        return outcomes_dir(self.cfg, "delta") / f"peer-{nid}.json"

    def record(self, nid, outcome="denied"):
        return outcomes.record_path(self.state_dir, "delta", "peer", nid, outcome,
                                    state_key=LIDS["delta"])

    def intent_dir(self):
        return self.state_dir / LIDS["delta"] / outcomes.DSN_DIR

    def recover_and_count(self):
        self.recover("not_registered", "alpha")
        self.poll()
        self.poll()
        dsns = list_notices(self.cfg, "alpha")
        self.assertEqual(len(dsns), 1, dsns)
        self.assertEqual([p for p in self.intent_dir().glob("*.json")], [])
        return dsns[0]

    def test_a_failed_enqueue_keeps_the_source_and_records_nothing(self):
        nid = self.denied()
        with mock.patch.object(outcomes, "_enqueue_dsn", side_effect=OSError("EIO")):
            self.poll()
        self.assertTrue(self.outcome_file(nid).is_file(), "the source was unlinked")
        self.assertFalse(self.record(nid).exists(), "the outcome was recorded")
        self.recover_and_count()

    def test_crash_after_the_enqueue_before_the_record(self):
        nid = self.denied()
        real = outcomes.atomic_write

        def boom(path, data, **kw):
            if Path(path) == self.record(nid):
                raise Crash
            return real(path, data, **kw)
        with mock.patch.object(outcomes, "atomic_write", boom):
            with self.assertRaises(Crash):
                self.poll()
        [intent] = list(self.intent_dir().glob("*.json"))
        dsn_id = json.loads(intent.read_text())["dsn_notice_id"]
        self.assertTrue(self.outcome_file(nid).is_file())
        self.assertEqual(self.recover_and_count(), f"notice-{dsn_id}.json")

    def test_crash_after_the_record_before_the_unlink(self):
        nid = self.denied()
        real = os.unlink

        def boom(path, *a, **kw):
            if str(path).startswith("peer-") and kw.get("dir_fd") is not None:
                raise Crash
            return real(path, *a, **kw)
        with mock.patch.object(outcomes.os, "unlink", boom):
            with self.assertRaises(Crash):
                self.poll()
        self.assertTrue(self.record(nid).exists())
        self.recover_and_count()

    def test_crash_after_the_dsn_before_the_intent_is_removed(self):
        nid = self.denied()
        self.poll()
        [intent] = list(self.intent_dir().glob("*.json"))
        dsn_id = json.loads(intent.read_text())["dsn_notice_id"]
        self.recover("not_registered", "alpha")
        real = os.unlink

        def boom(path, *a, **kw):
            if Path(path) == intent:
                raise Crash
            return real(path, *a, **kw)
        with mock.patch.object(outcomes.os, "unlink", boom):
            with self.assertRaises(Crash):
                self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [f"notice-{dsn_id}.json"])
        self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [f"notice-{dsn_id}.json"])
        self.assertEqual(list(self.intent_dir().glob("*.json")), [])


class DsnKeyingTests(_Fleet):

    def task(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        return self.result("alpha", "00000001")["message_id"]

    def test_duplicate_connectors_map_to_one_intent_and_one_dsn(self):
        self.cfg = replace(self.cfg, connector_outcome_ids=("claude-code", "codex"))
        nid = self.task()
        self.hold("not_registered", "alpha")
        from router.tests.peer_helpers import outcomes_dir
        write_outcome(self.cfg, "delta", nid, "denied")
        d2 = outcomes_dir(self.cfg, "delta", "codex")
        d2.mkdir(parents=True, exist_ok=True)
        (d2 / f"peer-{nid}.json").write_text(json.dumps(
            {"outcome": "denied", "ts": "2026-09-03T12:00:00Z", "tree": "peer", "notice_id": nid}))
        self.poll()
        self.assertEqual(len(list((self.state_dir / LIDS["delta"] / outcomes.DSN_DIR).glob("*.json"))), 1)
        self.recover("not_registered", "alpha")
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)

    def test_denied_then_refused_are_two_intents_and_two_dsns(self):
        nid = self.task()
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        write_outcome(self.cfg, "delta", nid, "refused", ts="2026-09-03T12:00:05Z")
        self.poll()
        names = sorted(p.name for p in (self.state_dir / LIDS["delta"] / outcomes.DSN_DIR).glob("*.json"))
        self.assertEqual(names, [f"peer-{nid}.denied.json", f"peer-{nid}.refused.json"])
        self.recover("not_registered", "alpha")
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 2)


class DsnFairnessTests(_Fleet):
    """1000+ held intents: a fresh outcome is still consumed in the same
    poll, and a healthy intent behind the held prefix is delivered within a
    bounded number of polls."""

    def test_held_prefix_neither_blocks_outcomes_nor_starves_a_healthy_dsn(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        d = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        d.mkdir(parents=True)
        # 1100 intents for a target the registry never resolves, every one armed,
        # all sorting BEFORE the healthy one.
        for i in range(1100):
            fake = f"{i:032x}"
            (d / f"peer-{fake}.denied.json").write_text(json.dumps({
                "v": 1, "tree": "peer", "notice_id": fake, "outcome": "denied",
                "outcome_ts": "2026-09-03T12:00:00Z", "receiver": "delta", "sender": "ghost",
                "sender_lid": None, "dsn_notice_id": f"{i:032x}", "dsn_ts": "2026-09-03T12:00:00Z",
                "reason": None, "created_ts": "2026-09-03T12:00:00Z"}))
            rec = outcomes.record_path(self.state_dir, "delta", "peer", fake, "denied",
                                       state_key=LIDS["delta"])
            rec.parent.mkdir(parents=True, exist_ok=True)
            rec.write_text("{}")
        write_outcome(self.cfg, "delta", nid, "denied")
        polls = 0
        while not list_notices(self.cfg, "alpha"):
            self.poll()
            polls += 1
            if polls == 1:
                self.assertTrue(outcomes.record_path(
                    self.state_dir, "delta", "peer", nid, "denied", state_key=LIDS["delta"]).exists(),
                    "the fresh outcome waited behind the queue")
            self.assertLessEqual(polls, 1100 // outcomes.MAX_DSN_PER_POLL + 2,
                                 "the healthy DSN was starved")
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)


class NoRegistryUnchangedTests(RouterTestCase):
    """Without a registry: no pending records, no DSN queue, and the drain
    and outcome summaries carry exactly the keys they always did."""

    def test_summaries_and_state_are_unchanged(self):
        cfg = make_peer_config(self, {"alpha": {}, "delta": {"peer_senders": ["alpha"]}})
        write_request(cfg, "alpha", "00000001", to=[addr("delta")])
        summary = service.run_once(cfg, None)
        self.assertNotIn("outbound_held", summary["alpha"])
        self.assertNotIn("held_local", summary["alpha"])
        nid = read_json(result_path(cfg, "alpha", "00000001"))["message_id"]
        write_outcome(cfg, "delta", nid, "denied")
        summary = service.run_once(cfg, None)
        self.assertNotIn("dsn_held", summary["delta"])
        self.assertEqual(summary["delta"]["peer_dsn_sent"], 1)       # inline, as before
        self.assertFalse((self.state_dir / "delta" / outcomes.DSN_DIR).exists())
        self.assertFalse((self.state_dir / "alpha" / outbound.PENDING_DIR).exists())


class GlobalHoldSuppressesRecoveryTests(_Fleet):
    """An unavailable or rolled-back registry holds every instance, senders
    included: an existing pending request is not advanced."""

    def test_pending_waits(self):
        for reason in GLOBAL:
            with self.subTest(reason=reason):
                self.setUp()
                self.hold("not_registered", "bravo")
                write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
                self.poll()
                path = self.pending("alpha", "00000001")
                before = path.read_bytes()
                self.recover("not_registered", "bravo")
                self.hold(reason, "bravo")
                self.poll()
                self.assertEqual(path.read_bytes(), before, "advanced under a global hold")
                self.assertEqual(list_notices(self.cfg, "bravo"), [])
                self.recover(reason, "bravo")
                self.poll()
                self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)


class DsnArmingAndIdentityTests(_Fleet):

    def task(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        return self.result("alpha", "00000001")["message_id"]

    def test_an_intent_is_not_armed_until_its_outcome_is_recorded(self):
        """The record write fails (an ordinary error, so the poll goes on to
        the queue): the intent must not be delivered then, or the retry of
        the kept source would enqueue a SECOND DSN with a new id."""
        nid = self.task()
        write_outcome(self.cfg, "delta", nid, "denied")
        rec = outcomes.record_path(self.state_dir, "delta", "peer", nid, "denied",
                                   state_key=LIDS["delta"])
        real = outcomes.atomic_write

        def fail_once(path, data, **kw):
            if Path(path) == rec and not fail_once.done:
                fail_once.done = True
                raise OSError("EIO")
            return real(path, data, **kw)
        fail_once.done = False
        with mock.patch.object(outcomes, "atomic_write", fail_once):
            summary = self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [])
        # Not armed: skipped, not even attempted (so not reported as a
        # failed barrier either).
        self.assertEqual(summary["delta"]["dsn_held"], [])
        self.poll()
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)

    def test_a_dsn_never_follows_a_reused_name(self):
        nid = self.task()
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        d = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        [path] = list(d.glob("*.json"))
        intent = json.loads(path.read_text())
        intent["sender_lid"] = "9" * 32                # bound to another identity
        path.write_text(json.dumps(intent))
        self.recover("not_registered", "alpha")
        summary = self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [])
        self.assertEqual(summary["delta"]["dsn_held"],
                         [{"notice_id": nid, "outcome": "denied", "target": "alpha",
                           "reason": "identity_changed"}])

    def test_held_dsns_and_held_requests_are_reported(self):
        nid = self.task()
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        write_request(self.cfg, "delta", "00000002", in_reply_to=nid, to=[addr("alpha")])
        summary = self.poll()
        self.assertEqual(summary["delta"]["dsn_held"],
                         [{"notice_id": nid, "outcome": "denied", "target": "alpha",
                           "reason": "not_registered"}])
        [held] = summary["delta"]["held_local"]
        self.assertEqual((held["req_id"], held["targets"]),
                         ("00000002", [{"recipient": "alpha", "state": "held",
                                        "reason": "not_registered"}]))



class _BarrierFails:
    """`util.fsync_dir` fails for `directory` while `when()` is true: the
    REAL write and rename happen first (`atomic_write`'s order), so the new
    contents are visible but not durable."""

    def __init__(self, directory, when=lambda: True):
        from router import util
        self.util, self.real, self.directory, self.when = util, util.fsync_dir, Path(directory), when
        self.failed = 0

    def __call__(self, path):
        if Path(path) == self.directory and self.when():
            self.failed += 1
            raise OSError(5, "EIO (injected after the rename)")
        return self.real(path)

    def __enter__(self):
        # Every module that holds its own reference to fsync_dir: a barrier
        # that keeps failing fails for the repairs too.
        self.patches = [mock.patch.object(m, "fsync_dir", self)
                        for m in (self.util, outbound, outcomes)]
        for pt in self.patches:
            pt.start()
        return self

    def __exit__(self, *exc):
        for pt in self.patches:
            pt.stop()


class BarrierAfterReplaceTests(_Fleet):
    """A record or intent replaced on disk whose directory barrier then fails
    is visible but NOT durable: nothing may be placed on it until a rewrite
    makes it durable, and a repair that keeps failing stops."""

    def test_a_failed_target_keeps_its_identity_and_the_record_stays_valid(self):
        self.hold("not_registered", "bravo")
        real = outbound._place_target

        def eio_for_charlie(cfg, name, target, *a, **kw):
            if target["recipient"] == "charlie":
                raise OSError(5, "EIO")
            return real(cfg, name, target, *a, **kw)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo"), addr("charlie")])
        with mock.patch.object(outbound, "_place_target", eio_for_charlie):
            self.poll()
        rec = json.loads(self.pending("alpha", "00000001").read_text())
        charlie = next(t for t in rec["targets"] if t["recipient"] == "charlie")
        # An error after placement began is NOT terminal: kept delivering,
        # with its identity, and replayed next poll.
        self.assertEqual((charlie["state"], charlie["reason"]), ("delivering", "failing: OSError"))
        self.assertIsNotNone(charlie["notice_id"])
        self.recover("not_registered", "bravo")
        self.poll()
        res = self.result("alpha", "00000001")
        self.assertEqual((res["outcome"], res["reason_code"]), ("accepted", "allowlisted"))
        self.assertEqual(list_notices(self.cfg, "charlie"), [f"notice-{charlie['notice_id']}.json"])
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)

    def test_a_failed_target_with_an_identity_is_a_valid_record(self):
        """The identity rule for every reachable state (`failed` included)."""
        base = {"v": 1, "req_id": "00000001", "request_sha256": "0" * 64, "kind": "mail",
                "sender_lid": None, "created_ts": "2026-10-11T00:00:00Z", "block": None,
                "binding": None}
        t = {"recipient": "bravo", "kind": "mail", "lid": None, "state": "failed", "reason": None,
             "notice_id": "a" * 32, "ts": "2026-10-11T00:00:00Z", "message_id": None,
             "error": "OSError"}
        outbound._check_pending(dict(base, targets=[t]), "00000001")
        with self.assertRaises(outbound.PendingDamaged):
            outbound._check_pending(dict(base, targets=[dict(t, state="held")]), "00000001")

    def test_a_visible_delivering_record_is_made_durable_before_any_placement(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        self.recover("not_registered", "bravo")
        path = self.pending("alpha", "00000001")
        delivering = lambda: '"delivering"' in path.read_text()
        with _BarrierFails(path.parent, delivering) as b:
            self.poll()                       # replaced to delivering, barrier failed
            self.assertGreaterEqual(b.failed, 1)
            self.assertIn('"delivering"', path.read_text())
            self.assertEqual(list_notices(self.cfg, "bravo"), [])
            self.poll()                       # the repair keeps failing: still nothing placed
            self.assertEqual(list_notices(self.cfg, "bravo"), [])
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)
        nid = json.loads((gen_state(self.state_dir, LIDS["alpha"]) / "results" / "00000001.json")
                         .read_text())["result"]["message_id"]
        self.assertEqual(list_notices(self.cfg, "bravo"), [f"notice-{nid}.json"])

    def test_a_visible_intent_is_made_durable_before_the_source_is_consumed(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        from router.tests.peer_helpers import outcomes_dir
        source = outcomes_dir(self.cfg, "delta") / f"peer-{nid}.json"
        intents = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        rec = outcomes.record_path(self.state_dir, "delta", "peer", nid, "denied",
                                   state_key=LIDS["delta"])
        with _BarrierFails(intents):
            self.poll()                       # intent replaced, barrier failed
            self.assertTrue(source.is_file())
            self.assertEqual(len(list(intents.glob("*.json"))), 1)
            self.poll()                       # repair keeps failing: source NOT consumed
            self.assertTrue(source.is_file(), "consumed without a durable intent")
            self.assertFalse(rec.exists())
        self.poll()
        self.assertFalse(source.exists())
        self.assertTrue(rec.exists())
        self.recover("not_registered", "alpha")
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)

    def test_a_visible_dsn_binding_is_made_durable_before_the_dsn(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        self.recover("not_registered", "alpha")
        intents = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        with _BarrierFails(intents):
            self.poll()
            self.poll()
            self.assertEqual(list_notices(self.cfg, "alpha"), [], "a DSN on a non-durable intent")
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)


    def test_an_existing_intent_that_does_not_match_keeps_the_source(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        intents = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        intents.mkdir(parents=True)
        (intents / f"peer-{nid}.denied.json").write_text(json.dumps({
            "v": 1, "tree": "peer", "notice_id": nid, "outcome": "denied",
            "outcome_ts": "2026-09-03T12:00:00Z", "receiver": "delta", "sender": "bravo",
            "sender_lid": None, "dsn_notice_id": "f" * 32, "dsn_ts": "2026-09-03T12:00:00Z",
            "reason": None, "created_ts": "2026-09-03T12:00:00Z"}))
        write_outcome(self.cfg, "delta", nid, "denied")
        from router.tests.peer_helpers import outcomes_dir
        self.poll()
        self.assertTrue((outcomes_dir(self.cfg, "delta") / f"peer-{nid}.json").is_file())
        self.assertFalse(outcomes.record_path(self.state_dir, "delta", "peer", nid, "denied",
                                              state_key=LIDS["delta"]).exists())



def _after_then_fail(target, attr, nth=1):
    """`target.attr` runs FOR REAL, then raises OSError on its `nth` call: a
    failure after the write, as a failed barrier is."""
    real = getattr(target, attr)
    calls = {"n": 0}

    def wrapped(*a, **kw):
        out = real(*a, **kw)
        calls["n"] += 1
        if calls["n"] == nth:
            raise OSError(5, "EIO after the write")
        return out
    return mock.patch.object(target, attr, wrapped)


class FailureAfterEachStageTests(_Fleet):
    """An error AFTER a placement stage's write keeps the target
    `delivering`; the next poll replays it with the SAME id, and the notice
    left visible is that same one, never a second."""

    STAGES = (
        (deliver_mod.attachments_mod, "publish_attachment_blobs", 1),
        (deliver_mod.attachments_mod, "write_agent_visible", 1),   # spool
        (deliver_mod, "atomic_write", 1),                         # ledger
        (deliver_mod.attachments_mod, "write_agent_visible", 2),   # notice
    )

    def test_every_stage_mail_and_peer(self):
        for lane, target in (("mail", "bravo"), ("peer", "delta")):
            for mod, attr, nth in self.STAGES:
                with self.subTest(lane=lane, stage=f"{attr}#{nth}"):
                    self.setUp()
                    self.hold("not_registered", target)
                    write_request(self.cfg, "alpha", "00000001", to=[addr(target)])
                    self.poll()
                    self.recover("not_registered", target)
                    with _after_then_fail(mod, attr, nth):
                        self.poll()
                    rec = json.loads(self.pending("alpha", "00000001").read_text())
                    t = rec["targets"][0]
                    self.assertEqual((t["state"], t["reason"]), ("delivering", "failing: OSError"))
                    self.assertRetained("alpha", "00000001")
                    self.poll()
                    lst = list_notices if lane == "mail" else list_peer_notices
                    self.assertEqual(lst(self.cfg, target), [f"notice-{t['notice_id']}.json"])
                    self.assertEqual(self.result("alpha", "00000001")["outcome"], "accepted")


class RefusalReportsEveryPlacementTests(_Fleet):
    """A placement interrupted after its notice, then a fresh refusal:
    the placement is settled with its identity first, and the refusal's
    Result names it."""

    def test_a_delivering_target_is_settled_and_reported(self):
        self.hold("not_registered", "charlie")
        real = outbound._write_pending

        def crash_on_bravo_delivered(cfg, path, rec):
            if any(t["recipient"] == "bravo" and t["state"] == "delivered" for t in rec["targets"]):
                raise Crash
            return real(cfg, path, rec)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo"), addr("charlie")])
        with mock.patch.object(outbound, "_write_pending", crash_on_bravo_delivered):
            with self.assertRaises(Crash):
                self.poll()
        rec = json.loads(self.pending("alpha", "00000001").read_text())
        bravo = next(t for t in rec["targets"] if t["recipient"] == "bravo")
        self.assertEqual(bravo["state"], "delivering")
        FreshPolicyTests.unpair(self)                 # alpha <-> bravo no longer a pair
        self.poll()
        res = self.result("alpha", "00000001")
        self.assertEqual(res["reason_code"], "recipient_not_allowlisted")
        self.assertEqual(res["recipients"], [addr("bravo")])
        self.assertEqual(list_notices(self.cfg, "bravo"), [f"notice-{bravo['notice_id']}.json"])


class PinnedIdentityTests(_Fleet):
    """A reply or a DSN held when pinned follows the
    IDENTITY the task was delivered between, never the name."""

    def rebind_alpha(self):
        old = LIDS["alpha"]
        LIDS["alpha"] = "9" * 32
        self.addCleanup(LIDS.__setitem__, "alpha", old)
        self.put()

    def test_a_held_reply_never_follows_the_name(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        task = self.result("alpha", "00000001")["message_id"]
        self.hold("not_registered", "alpha")         # unknown NOW; known at the task
        write_request(self.cfg, "bravo", "00000002", in_reply_to=task, to=[addr("alpha")])
        self.poll()
        rec = json.loads(self.pending("bravo", "00000002").read_text())
        self.assertEqual(rec["targets"][0]["lid"], "a1" * 16)
        (self.state_dir / ("a1" * 16)).rename(self.state_dir / ("9" * 32))
        self.rebind_alpha()                          # a valid rebind of the NAME
        self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [])
        rec = json.loads(self.pending("bravo", "00000002").read_text())
        self.assertEqual(rec["targets"][0]["reason"], outbound.HOLD_IDENTITY_CHANGED)

    def test_a_held_dsn_never_follows_the_name(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        [path] = list((self.state_dir / LIDS["delta"] / outcomes.DSN_DIR).glob("*.json"))
        self.assertEqual(json.loads(path.read_text())["sender_lid"], "a1" * 16)
        (self.state_dir / ("a1" * 16)).rename(self.state_dir / ("9" * 32))
        self.rebind_alpha()
        summary = self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [])
        self.assertEqual(summary["delta"]["dsn_held"][0]["reason"], "identity_changed")

    def test_a_truly_unknown_dsn_target_is_bound_at_first_resolution(self):
        """Pinned at its first resolution, durably, BEFORE the DSN: a crash
        there and then a rebind holds, it does not follow the name."""
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        led = binding.ledger_path(self.state_dir, "delta", nid, state_key=LIDS["delta"])
        doc = json.loads(led.read_text())
        doc.pop("from_lid", None)                    # a task from before the registry knew it
        led.write_text(json.dumps(doc))
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        [path] = list((self.state_dir / LIDS["delta"] / outcomes.DSN_DIR).glob("*.json"))
        self.assertIsNone(json.loads(path.read_text())["sender_lid"])
        self.recover("not_registered", "alpha")
        with mock.patch.object(outcomes, "_dsn", side_effect=Crash):
            with self.assertRaises(Crash):
                self.poll()
        self.assertEqual(json.loads(path.read_text())["sender_lid"], "a1" * 16)
        (self.state_dir / ("a1" * 16)).rename(self.state_dir / ("9" * 32))
        self.rebind_alpha()
        self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [])


class StrandedWithoutRegistryTests(_Fleet):
    """Removing registry_dir while requests are pending is an
    unsupported transition: everything holds, visibly, instead of
    re-delivering completed targets with new ids."""

    def test_pending_state_without_a_registry_holds_everything(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo"), addr("charlie")])
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "charlie")), 1)
        registered = self.cfg
        self.cfg = replace(self.cfg, registry_dir=None)
        from router.status import StatusTracker
        tracker = StatusTracker(interval_s=5.0)
        log = logging.getLogger("amap_router_local")
        log.disabled = True
        try:
            service.poll_once(self.cfg, tracker, None)
        finally:
            log.disabled = False
        self.assertEqual(len(list_notices(self.cfg, "charlie")), 1, "re-delivered")
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        doc = tracker.to_doc()["registry"]
        self.assertEqual(doc["state"], "stranded")
        self.assertEqual(set(doc["held"].values()), {registry.HELD_STRANDED})
        self.cfg = registered
        self.recover("not_registered", "bravo")
        self.poll()
        self.assertEqual((len(list_notices(self.cfg, "bravo")),
                          len(list_notices(self.cfg, "charlie"))), (1, 1))


class SurvivingMutantTests(_Fleet):
    """One witness per mutant a review found surviving."""

    def test_window_eligibility_is_pinned_false_when_only_an_edge_allowed_it(self):
        """Eligible at first evaluation by an EDGE alone (the window already
        passed): pinned with window_ok False, so losing the edge refuses."""
        both = make_peer_config(self, {
            "alpha": {"peers": ["bravo", "charlie"], "peer_senders": ["delta"]},
            "bravo": {"peers": ["alpha"]}, "charlie": {"peers": ["alpha"]},
            "delta": {"peer_senders": ["alpha"]}}, provision=False, seen=False)
        self.cfg = replace(both, registry_dir=self.reg)
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        task = self.result("alpha", "00000001")["message_id"]
        led = binding.ledger_path(self.state_dir, "delta", task, state_key=LIDS["delta"])
        doc = json.loads(led.read_text())
        doc["ts"] = "2000-01-01T00:00:00Z"
        led.write_text(json.dumps(doc))
        self.hold("state_not_migrated", "alpha")
        write_request(self.cfg, "delta", "00000002", in_reply_to=task, to=[addr("alpha")])
        self.poll()
        rec = json.loads(self.pending("delta", "00000002").read_text())
        self.assertFalse(rec["binding"]["window_ok"])
        no_edge = make_peer_config(self, {
            "alpha": {"peers": ["bravo", "charlie"]}, "bravo": {"peers": ["alpha"]},
            "charlie": {"peers": ["alpha"]}, "delta": {"peer_senders": ["alpha"]}},
            provision=False, seen=False)
        self.cfg = replace(no_edge, registry_dir=self.reg)
        self.recover("state_not_migrated", "alpha")
        self.poll()
        res = self.result("delta", "00000002")
        self.assertEqual(res["reason_code"], "peer_reply_window_expired")

    def test_peer_replay_uses_the_preset(self):
        self.hold("not_registered", "delta")
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        self.recover("not_registered", "delta")
        real = outbound._write_pending

        def crash_on_delivered(cfg, path, rec):
            if rec["targets"][0]["state"] == "delivered":
                raise Crash
            return real(cfg, path, rec)
        with mock.patch.object(outbound, "_write_pending", crash_on_delivered):
            with self.assertRaises(Crash):
                self.poll()
        nid = json.loads(self.pending("alpha", "00000001").read_text())["targets"][0]["notice_id"]
        self.poll()
        self.assertEqual(list_peer_notices(self.cfg, "delta"), [f"notice-{nid}.json"])
        ledger = sorted(p.name for p in (self.state_dir / LIDS["delta"] / "delivered").glob("*.json"))
        self.assertEqual(ledger, [f"notice-{nid}.json"])

    def test_a_failing_dsn_keeps_its_intent_and_its_id(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        self.hold("not_registered", "alpha")
        write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        [path] = list((self.state_dir / LIDS["delta"] / outcomes.DSN_DIR).glob("*.json"))
        dsn_id = json.loads(path.read_text())["dsn_notice_id"]
        self.recover("not_registered", "alpha")
        with mock.patch.object(outcomes, "_dsn", side_effect=OSError("EIO")):
            self.poll()
        self.assertTrue(path.is_file(), "a failing DSN dropped its intent")
        self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [f"notice-{dsn_id}.json"])

    def test_a_delivered_target_is_never_placed_again(self):
        self.hold("not_registered", "bravo")
        placed = []
        real = outbound._place_target

        def spy(cfg, name, target, *a, **kw):
            placed.append(target["recipient"])
            return real(cfg, name, target, *a, **kw)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo"), addr("charlie")])
        with mock.patch.object(outbound, "_place_target", spy):
            self.poll()
            self.poll()
            self.recover("not_registered", "bravo")
            self.poll()
        self.assertEqual(sorted(placed), ["bravo", "charlie"])


class InjectedBackendTests(_Fleet):
    """Every backend path places with the pre-minted identity; a
    backend that cannot take it is held BEFORE placement."""

    def test_the_default_deliver_passed_explicitly_gets_the_preset(self):
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        k = self.keyed()
        outbound.drain_instance(k, "alpha", deliver_backend=deliver_mod.deliver)
        self.recover("not_registered", "bravo")
        k = self.keyed()
        real = outbound._write_pending

        def crash_on_delivered(cfg, path, rec):
            if rec["targets"][0]["state"] == "delivered":
                raise Crash
            return real(cfg, path, rec)
        with mock.patch.object(outbound, "_write_pending", crash_on_delivered):
            with self.assertRaises(Crash):
                outbound.drain_instance(k, "alpha", deliver_backend=deliver_mod.deliver)
        nid = json.loads(self.pending("alpha", "00000001").read_text())["targets"][0]["notice_id"]
        outbound.drain_instance(self.keyed(), "alpha", deliver_backend=deliver_mod.deliver)
        self.assertEqual(list_notices(self.cfg, "bravo"), [f"notice-{nid}.json"])

    def test_a_backend_without_a_preset_is_held_before_placement(self):
        def legacy(cfg, state_dir, sender, recipient, request, *, reply_to_record=None,
                   attachments=None):
            raise AssertionError("placed without the pre-minted identity")
        self.hold("not_registered", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        outbound.drain_instance(self.keyed(), "alpha", deliver_backend=legacy)
        self.recover("not_registered", "bravo")
        outbound.drain_instance(self.keyed(), "alpha", deliver_backend=legacy)
        rec = json.loads(self.pending("alpha", "00000001").read_text())
        self.assertEqual(rec["targets"][0]["reason"], outbound.HOLD_BACKEND_NO_PRESET)
        self.assertEqual(list_notices(self.cfg, "bravo"), [])


class DamagedIntentsCountTests(_Fleet):
    """Damaged intents ahead of a healthy one still move
    the fair cursor, and are reported."""

    def test_damaged_prefix_does_not_starve_a_healthy_intent(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        d = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        d.mkdir(parents=True)
        for i in range(150):
            (d / f"peer-{i:032x}.denied.json").write_text("{damaged")
        write_outcome(self.cfg, "delta", nid, "denied")
        for polls in range(1, 6):
            summary = self.poll()
            if list_notices(self.cfg, "alpha"):
                break
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 1, "starved behind damaged intents")
        self.assertTrue(any(w.get("reason") == "damaged" for w in summary["delta"]["dsn_held"]))



class OutcomeRecordBarrierTests(_Fleet):
    """An outcome record replaced but not durable (its
    barrier failed after the rename) must not arm the queue, in that poll or
    any later one, until it is made durable."""

    def test_a_non_durable_record_arms_nothing(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("delta")])
        self.poll()
        nid = self.result("alpha", "00000001")["message_id"]
        write_outcome(self.cfg, "delta", nid, "denied")
        from router.tests.peer_helpers import outcomes_dir
        source = outcomes_dir(self.cfg, "delta") / f"peer-{nid}.json"
        rec = outcomes.record_path(self.state_dir, "delta", "peer", nid, "denied",
                                   state_key=LIDS["delta"])
        intents = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        with _BarrierFails(rec.parent):
            self.poll()                       # record replaced, barrier failed
            self.assertTrue(rec.exists())
            self.assertTrue(source.is_file(), "source consumed on a non-durable record")
            self.assertEqual(list_notices(self.cfg, "alpha"), [], "armed on a non-durable record")
            self.assertEqual(len(list(intents.glob("*.json"))), 1)
            self.poll()                       # duplicate path: still not durable
            self.assertTrue(source.is_file())
            self.assertEqual(list_notices(self.cfg, "alpha"), [])
        self.poll()
        self.assertFalse(source.exists())
        self.assertEqual(len(list_notices(self.cfg, "alpha")), 1)


class CollisionPinTests(_Fleet):
    def test_a_target_held_by_a_collision_pins_its_known_identity(self):
        self.hold("skeleton_collision", "bravo")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        rec = json.loads(self.pending("alpha", "00000001").read_text())
        self.assertEqual(rec["targets"][0]["lid"], LIDS["bravo"])
        old = LIDS["bravo"]
        LIDS["bravo"] = "8" * 32
        self.addCleanup(LIDS.__setitem__, "bravo", old)
        (self.state_dir / old).rename(self.state_dir / LIDS["bravo"])
        self.put()
        self.poll()
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        rec = json.loads(self.pending("alpha", "00000001").read_text())
        self.assertEqual(rec["targets"][0]["reason"], outbound.HOLD_IDENTITY_CHANGED)



class StrandedFailsClosedTests(RouterTestCase):
    """An unreadable state directory cannot be shown empty: held, never
    read as "nothing stranded"."""

    def test_unreadable_state_dir_and_subdir_are_stranded(self):
        lid = "a1" * 16
        (self.state_dir / lid / outbound.PENDING_DIR).mkdir(parents=True)
        real = os.scandir

        def deny(target):
            def scandir(path="."):
                if Path(path) == target:
                    raise PermissionError(13, "denied")
                return real(path)
            return scandir
        for target in (self.state_dir, self.state_dir / lid / outbound.PENDING_DIR):
            with self.subTest(target=target.name):
                with mock.patch.object(registry.os, "scandir", deny(target)):
                    r = registry.report_for(None, self.state_dir, ["alpha"])
                self.assertEqual((r.state, r.held), ("stranded", {"alpha": registry.HELD_STRANDED}))
        # The twins: readable and empty, or missing, is NOT stranded.
        self.assertEqual(registry.report_for(None, self.state_dir, ["alpha"]).state, "off")
        self.assertEqual(registry.report_for(None, self.tmp / "nowhere", ["alpha"]).state, "off")



class DsnErrorUpdateIsolatedTests(_Fleet):
    """A failing DSN whose reason cannot be recorded (a backend error, then
    the update's own write failing BEFORE its rename) is isolated to that
    intent: its on-disk state stays frozen, it is reported, and a healthy
    neighbour is still delivered."""

    def test_a_neighbour_is_delivered_while_one_intent_fails_twice_over(self):
        nids = []
        for req in ("00000001", "00000002"):
            write_request(self.cfg, "alpha", req, to=[addr("delta")])
            self.poll()
            nids.append(self.result("alpha", req)["message_id"])
        self.hold("not_registered", "alpha")
        for nid in nids:
            write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        d = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        names = sorted(p.name for p in d.glob("*.json"))
        first, second = d / names[0], d / names[1]
        failing_nid = json.loads(first.read_text())["notice_id"]
        frozen = first.read_bytes()
        healthy_id = json.loads(second.read_text())["dsn_notice_id"]
        self.recover("not_registered", "alpha")
        real_dsn, real_write = outcomes._dsn, outcomes.atomic_write

        def dsn(cfg, sender, recipient, notice_id, outcome, **kw):
            if notice_id == failing_nid:
                raise OSError(5, "backend EIO")
            return real_dsn(cfg, sender, recipient, notice_id, outcome, **kw)

        def write(path, data, **kw):
            if Path(path) == first and b'"failing:' in data:
                raise OSError(5, "EIO at the temp file's fsync, before the rename")
            return real_write(path, data, **kw)
        with mock.patch.object(outcomes, "_dsn", dsn), \
                mock.patch.object(outcomes, "atomic_write", write):
            for _ in range(3):
                summary = self.poll()
        self.assertEqual(list_notices(self.cfg, "alpha"), [f"notice-{healthy_id}.json"])
        self.assertEqual(first.read_bytes(), frozen, "the failing intent's state changed")
        self.assertIn({"notice_id": failing_nid, "outcome": "denied", "target": "alpha",
                       "reason": "barrier_failed"}, summary["delta"]["dsn_held"])



class DsnRemovalFailureIsolatedTests(_Fleet):
    """A DSN placed, then the removal of its intent fails (the unlink, or the
    directory fsync after it): that intent is NOT lost and NOT duplicated
    under a new id, and the pass goes on to its neighbour."""

    def setup_two(self):
        nids = []
        for req in ("00000001", "00000002"):
            write_request(self.cfg, "alpha", req, to=[addr("delta")])
            self.poll()
            nids.append(self.result("alpha", req)["message_id"])
        self.hold("not_registered", "alpha")
        for nid in nids:
            write_outcome(self.cfg, "delta", nid, "denied")
        self.poll()
        d = self.state_dir / LIDS["delta"] / outcomes.DSN_DIR
        first, second = sorted(d.glob("*.json"))
        ids = [json.loads(p.read_text())["dsn_notice_id"] for p in (first, second)]
        self.recover("not_registered", "alpha")
        return d, first, ids

    def check(self, ids):
        self.assertEqual(sorted(list_notices(self.cfg, "alpha")),
                         sorted(f"notice-{i}.json" for i in ids),
                         "a DSN was lost or offered under a second id")

    def consume(self, nid):
        """The agent consumes the first DSN's notice, so only a REPLAY can put
        it back: an unchanged listing after the next poll then proves nothing
        ran, and the same name reappearing proves the replay used the same id."""
        notice = notices_dir(self.cfg, "alpha") / f"notice-{nid}.json"
        notice.unlink()
        self.assertNotIn(notice.name, list_notices(self.cfg, "alpha"))

    def test_unlink_failure(self):
        d, first, ids = self.setup_two()
        real = os.unlink

        def unlink(path, *a, **kw):
            if Path(path) == first:
                raise OSError(5, "EIO at the unlink")
            return real(path, *a, **kw)
        with mock.patch.object(outcomes.os, "unlink", unlink):
            self.poll()
        self.check(ids)                               # the neighbour went too
        self.assertTrue(first.is_file())              # kept, so it replays
        self.consume(ids[0])
        self.poll()                                   # replay: the SAME id, then removed
        self.check(ids)
        self.assertEqual(list(d.glob("*.json")), [])

    def test_directory_fsync_failure(self):
        """The unlink happened but its directory barrier failed: after a crash
        the intent may come back. Restored as that crash survivor, it is
        replayed with the SAME id and only then removed."""
        d, first, ids = self.setup_two()
        frozen = first.read_bytes()
        real = outcomes.fsync_dir
        calls = {"n": 0}

        def fsync_dir(path):
            if Path(path) == d and calls["n"] == 0:
                calls["n"] += 1
                raise OSError(5, "EIO at the directory fsync")
            return real(path)
        with mock.patch.object(outcomes, "fsync_dir", fsync_dir):
            self.poll()
        self.assertEqual(calls["n"], 1, "the injected directory-fsync fault never fired")
        self.check(ids)                               # the neighbour went too
        first.write_bytes(frozen)                     # the crash survivor
        self.consume(ids[0])
        self.poll()                                   # replay: the SAME id, then removed
        self.check(ids)
        self.assertEqual(list(d.glob("*.json")), [])
