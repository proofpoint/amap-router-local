"""Control notices IN: the `.control/` host intake, through the candidate
journal (`router/peerjournal.py`), the receive hook (`router/peerpolicy.py`)
and the failure notice (`router/peercontrol.py`, `deliver.deliver_router_notice`).

Pinned here: plain mail in `.control/` is held until the ingress quarantine
expires and only then tombstoned; every failing control is dropped (never
placed, never answered); a good control reserves (the fourth replay-store
record type, its digest entry of kind control), claims the one-per-message
marker, and places one runtime-authored failure notice, once, across every
crash point; a second control about the same message is dropped."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import types
from datetime import timedelta
from unittest import mock

from router import config as config_mod
from router import deliver, peerbind, peerclock, peercontrol, peerjournal, peerlane, peerledger
from router.tests import peer_standin as si
from router.tests import test_peerevaluate as tpe
from router.tests.test_peerbind import FD, KEY_ID, T1

NOW = tpe.NOW
CID = "0123456789abcdef0123456789abcdef"
CID2 = "fedcba9876543210fedcba9876543210"
ABOUT = "qAbout0123456789abcdefg"
SIGNER = f"amap.router@{T1}"
OWN = f"amap.router@{FD}"


def held(rec):
    return (rec.get("hold") or {}).get("reason")


class _ControlIn(tpe._Eval):

    def setUp(self):
        super().setUp()
        from router import fsops as fsops_mod
        self.hop = self.tmp / "hop"
        for intake in (".unresolved", ".control"):
            (self.hop / ".disposed" / intake).mkdir(parents=True)
            (self.hop / intake).mkdir(parents=True)
        self.ops = fsops_mod.FsOps(hop_root=str(self.hop))
        self.addCleanup(self.ops.close)
        self.addCleanup(peerjournal._DISPOSED.clear)
        self.cfg = dataclasses.replace(self.cfg, hop=types.SimpleNamespace(root=str(self.hop)))
        self.lane = dataclasses.replace(self.lane, candidate_view=lambda raw: json.loads(raw))
        self.lid = config_mod.state_key(self.cfg, "bob")

    # -- the world ----------------------------------------------------------

    def issued(self, rid=ABOUT, *, remote=f"planner@{T1}", lid=None, expires="2026-10-20T00:00:00Z"):
        peerlane.write_issued(self.cfg, peerlane.issued_record(
            peer_id=rid, logical_id=lid or self.lid, local_address=f"bob@{FD}", remote=remote,
            generation="g" * 32, expires_at=expires))

    def control_raw(self, *, both=False, bad_signature=False, **over):
        doc = {"v": 1, "key_id": KEY_ID, "kind": "control", "id": "cTRL0123456789abcdefgh",
               "from": SIGNER, "to": OWN, "ts": "2026-10-13T11:59:00Z", "about": ABOUT,
               "outcome": "refused", "cause": "no_edge"}
        doc.update(over)
        st = si.encode_control({k: v for k, v in doc.items() if v is not None})
        sig = si._sign(tpe.SEED, st if not bad_signature else st + b"x")
        fields = [["Message-ID", f"<{doc['id']}@{T1}>"],
                  [peerlane.CONTROL_FIELD, si.format_field(KEY_ID, st, sig)]]
        if both:
            _sdoc, sraw = tpe.statement()
            fields.append([peerlane.STATEMENT_FIELD,
                           si.format_field(KEY_ID, sraw, si._sign(tpe.SEED, sraw))])
        view = {"fields": fields, "body": {"charset": "utf-8", "octets_b64": ""},
                "attachments": []}
        return json.dumps(view, sort_keys=True).encode()

    def entry(self, raw, ident=CID, intake=".control"):
        d = self.hop / intake / ident
        d.mkdir()
        (d / "candidate.json").write_bytes(raw)
        return d

    def poll(self, now=NOW, cfg=None):
        return peerjournal.poll_host(cfg or self.cfg, self.ops, delegation=self.lane,
                                     profile_factory=tpe.permissive,
                                     clock=peerclock.advance(self.state_dir, now), now=now,
                                     intake=".control")

    def rec(self, ident=CID):
        key = peerjournal.record_key(intake=".control", gen="", owner="_host", entry_id=ident)
        return peerjournal.read_record(self.state_dir, "_host", key)

    def tomb(self, ident=CID):
        p = self.hop / ".disposed" / ".control" / ident
        return json.loads(p.read_bytes()) if p.is_file() else None

    def inbox_notices(self):
        d = self.cfg.instances["bob"].inbox_root / "notices"
        return sorted(d.glob("notice-*.json")) if d.is_dir() else []

    def outcome(self, ident=CID):
        r = self.rec(ident)
        return (r["state"], r["disposed"], r["cause"], held(r))


class AcceptedControlTests(_ControlIn):

    def test_a_control_places_one_runtime_authored_failure_notice(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        self.assertEqual(self.outcome(), ("done", "placed", None, None))
        notices = self.inbox_notices()
        self.assertEqual(len(notices), 1, "one failure notice in the agent's inbox")
        self.assertEqual(self.notices(), [], "nothing is placed in the peer tree")
        notice = json.loads(notices[0].read_text())
        msg = notice["message"]
        self.assertEqual((notice["kind"], msg["mailbox"], msg["from"], msg["in_reply_to"]),
                         ("deliver", "inbox", OWN, ABOUT))
        spool = json.loads((self.cfg.instances["bob"].inbox_root / "messages"
                            / notices[0].name).read_text())
        self.assertIn(ABOUT, spool["body_text"], "about is in the runtime-authored text")
        self.assertIn("you may not task", spool["body_text"])
        self.assertEqual(self.tomb()["disposition"], "placed")
        self.assertIsNone(self.rec()["control"], "a control is never answered")
        self.assertEqual(peerjournal.reconcile(self.state_dir), [])

    def test_the_reservation_is_a_control_record_with_its_own_label_and_digest_kind(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        rt, idk = self.rec()["replay_ref"].split("/")
        raw = (self.state_dir / "peer-replay" / rt / f"{idk}.json").read_bytes()
        doc = peerbind.parse_reservation(raw, peerbind._decision_key(self.state_dir))
        self.assertEqual((doc["kind"], doc["about"], doc["logical_id"], doc["issued_path"]),
                         ("control", ABOUT, self.lid, f"{self.lid}/peer-ledger/{ABOUT}.json"))
        self.assertEqual(peerjournal.known(self.state_dir, doc["statement_sha256"], "control"),
                         (rt, idk))
        self.assertIsNone(peerjournal.known(self.state_dir, doc["statement_sha256"], "statement"))
        # The statement label never verifies it.
        members = {k: v for k, v in json.loads(raw).items() if k != "mac"}
        self.assertNotEqual(peerbind._reservation_mac(members,
                                                      peerbind._decision_key(self.state_dir)),
                            json.loads(raw)["mac"])
        marker = peerledger.notified_path(self.state_dir, self.lid, ABOUT).read_bytes()
        self.assertEqual(json.loads(marker)["notice_id"], doc["notice_id"])

    def test_the_notice_is_placed_under_the_reservations_id_and_time(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        rt, idk = self.rec()["replay_ref"].split("/")
        doc = json.loads((self.state_dir / "peer-replay" / rt / f"{idk}.json").read_bytes())
        self.assertEqual([p.name for p in self.inbox_notices()],
                         [f"notice-{doc['notice_id']}.json"])

    def test_a_control_reservation_is_never_resumed_as_a_statement(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        rec = self.rec()
        rt, idk = rec["replay_ref"].split("/")
        rcp = peerbind.reopen_reservation(self.state_dir, rt, idk, record_id=rec["key"])
        snap = peerbind.Snapshot(
            peerjournal.read_snapshot(self.state_dir, rec, peerjournal.SNAPSHOT_STATEMENT),
            json.loads(peerjournal.read_snapshot(self.state_dir, rec, peerjournal.SNAPSHOT_VIEW)))
        try:
            peerbind.resume_reserved(rcp, snap, state_dir=self.state_dir)
            got = "resumed"
        except Exception as e:  # noqa: BLE001
            got = (type(e).__name__, getattr(e, "reason", None))
        self.assertEqual(got, ("RecoveryCorrupt", "kind"))

    def test_a_reply_to_the_failure_notice_has_no_binding(self):
        from router import binding
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        notice_id = self.inbox_notices()[0].name[len("notice-"):-len(".json")]
        rec = json.loads(binding.ledger_path(self.state_dir, "bob", notice_id,
                                             state_key=self.lid).read_text())
        self.assertEqual((rec["from_instance"], rec.get("authored_by")), (None, "router"),
                         "a router-authored record: a reply to it is unresolved_reply")

    def test_a_late_control_after_expires_at_still_finds_its_record(self):
        self.issued(expires="2026-10-13T11:00:00Z")
        self.entry(self.control_raw())
        self.poll()
        self.assertEqual(self.outcome()[:2], ("done", "placed"))


class DroppedControlTests(_ControlIn):

    def dropped(self, raw, cause):
        self.issued()
        self.entry(raw)
        self.poll()
        self.assertEqual(self.outcome(), ("done", "dropped", cause, None))
        self.assertEqual(self.inbox_notices(), [], "never placed")
        self.assertIsNone(self.rec()["control"], "never answered")
        self.assertEqual(self.tomb()["disposition"], "dropped")
        self.assertEqual(self.effects.quarantined, [], "never handed to mail admission")

    def test_from_not_the_keys_runtime(self):
        self.dropped(self.control_raw(**{"from": f"planner@{T1}"}), "control_signer")

    def test_to_not_this_routers_runtime(self):
        self.dropped(self.control_raw(to=f"bob@{FD}"), "misrouted")

    def test_ts_outside_the_window(self):
        self.dropped(self.control_raw(ts="2026-10-13T09:00:00Z"), "ts_window")

    def test_about_names_nothing_issued(self):
        self.dropped(self.control_raw(about="qNothing0123456789abcd"), "unknown_about")

    def test_a_bad_signature(self):
        self.dropped(self.control_raw(bad_signature=True), "signature")

    def test_both_fields(self):
        self.dropped(self.control_raw(both=True), "header_count")

    def test_a_control_in_an_agents_candidates_is_dropped(self):
        self.issued()
        key = self.take(self.control_raw())
        try:
            self.evaluate(key)
        except Exception:  # noqa: BLE001 -- a wrong outcome must FAIL below, not error
            pass
        rec = peerjournal.read_record(self.state_dir, tpe.OWNER, key)
        self.assertEqual((rec["state"], rec["disposed"], rec["cause"]),
                         ("done", "dropped", peerjournal.CONTROL_OUTSIDE_INTAKE))
        self.assertIsNone(rec["control"])
        self.assertEqual(self.inbox_notices(), [])


class DuplicateTests(_ControlIn):

    def test_the_same_control_twice_is_a_duplicate(self):
        self.issued()
        raw = self.control_raw()
        self.entry(raw)
        self.poll()
        self.entry(raw, ident=CID2)
        self.poll()
        self.assertEqual(self.outcome(CID2), ("done", "dropped", "duplicate", None))
        self.assertEqual(len(self.inbox_notices()), 1)

    def test_the_same_runtime_and_id_with_other_bytes_is_a_duplicate(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        self.entry(self.control_raw(cause="policy", policy_code="x"), ident=CID2)
        self.poll()
        self.assertEqual(self.outcome(CID2), ("done", "dropped", "duplicate", None))
        self.assertEqual(len(self.inbox_notices()), 1)

    def test_a_second_control_about_the_same_message_is_dropped(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        self.entry(self.control_raw(id="cTRL0123456789abcdefgX", outcome="dropped",
                                    cause="duplicate"), ident=CID2)
        self.poll()
        self.assertEqual(self.outcome(CID2), ("done", "dropped", "duplicate_about", None))
        self.assertEqual(len(self.inbox_notices()), 1, "one failure notice per message")


class ControlCrashTests(_ControlIn):

    def crash_once(self, target, name):
        real = getattr(target, name)

        def crash(*a, **k):
            if not crash.done:
                crash.done = True
                raise SystemExit(f"crash in {name}")
            return real(*a, **k)
        crash.done = False
        return mock.patch.object(target, name, crash)

    def test_a_crash_after_the_reservation_places_the_notice_once_on_recovery(self):
        self.issued()
        raw = self.control_raw()
        self.entry(raw)
        with self.crash_once(peerledger, "claim_notified"):
            with self.assertRaises(SystemExit):
                self.poll()
        self.assertEqual(self.rec()["state"], "reserved")
        self.assertEqual(self.inbox_notices(), [])
        self.poll()
        self.assertEqual(self.outcome(), ("done", "placed", None, None))
        self.assertEqual(len(self.inbox_notices()), 1)
        self.entry(raw, ident=CID2)
        self.poll()
        self.assertEqual(self.outcome(CID2)[:3], ("done", "dropped", "duplicate"))

    def test_a_crash_between_the_marker_and_the_notice_places_once(self):
        self.issued()
        self.entry(self.control_raw())
        with self.crash_once(deliver, "deliver_router_notice"):
            with self.assertRaises(SystemExit):
                self.poll()
        self.assertEqual(self.rec()["state"], "decided")
        self.poll()
        self.assertEqual(self.outcome(), ("done", "placed", None, None))
        self.assertEqual(len(self.inbox_notices()), 1)

    def test_a_changed_issued_record_is_recovery_corrupt_never_placed(self):
        self.issued()
        self.entry(self.control_raw())
        with self.crash_once(peerledger, "claim_notified"):
            with self.assertRaises(SystemExit):
                self.poll()
        path = self.state_dir / self.lid / "peer-ledger" / f"{ABOUT}.json"
        path.write_bytes(path.read_bytes().replace(b"2026-10-20", b"2026-10-21"))
        self.poll()
        rec = self.rec()
        self.assertEqual((rec["state"], (rec.get("hold") or {}).get("reason")),
                         ("reserved", "recovery_corrupt"))
        self.assertEqual(self.inbox_notices(), [])

    def test_another_reservations_marker_drops_without_a_notice(self):
        """The RE interleaving: two reservations about one message; the one
        finding the other's marker gets no notice."""
        self.issued()
        self.entry(self.control_raw())
        with self.crash_once(peerledger, "claim_notified"):
            with self.assertRaises(SystemExit):
                self.poll()
        peerledger.claim_notified(self.state_dir, self.lid, ABOUT, b'{"another":"winner"}')
        self.poll()
        self.assertEqual(self.outcome(), ("done", "dropped", "duplicate_about", None))
        self.assertEqual(self.inbox_notices(), [])


class HeldControlTests(_ControlIn):

    def test_plain_mail_is_held_until_the_quarantine_expires_then_tombstoned(self):
        self.entry(self.raw(signed=False))
        self.poll()
        rec = self.rec()
        self.assertEqual((rec["state"], held(rec)), ("pending", "control_plain_mail"))
        self.assertIsNone(self.tomb(), "no tombstone before expiry")
        self.assertEqual(peerjournal.advance_frontier(self.state_dir), rec["take_seq"] - 1,
                         "the intake's frontier is blocked")
        days = self.cfg.ingress_quarantine_days
        self.poll(now=NOW + timedelta(days=days) - timedelta(minutes=1))
        self.assertEqual(self.rec()["state"], "pending")
        self.poll(now=NOW + timedelta(days=days))
        self.assertEqual(self.outcome(), ("done", "mail", "control_plain_mail", None))
        self.assertEqual(self.tomb()["disposition"], "mail")
        self.assertEqual(self.inbox_notices(), [], "never answered")

    def test_a_peer_statement_in_the_control_intake_is_held_as_plain_mail(self):
        self.entry(self.raw())
        self.poll()
        self.assertEqual(held(self.rec()), "control_plain_mail")
        self.assertEqual(self.notices(), [], "never placed")

    def test_an_agent_no_longer_configured_holds_recipient_gone(self):
        self.issued(lid="gone-agent")
        self.entry(self.control_raw())
        self.poll()
        rec = self.rec()
        self.assertEqual((rec["state"], held(rec)), ("decided", "recipient_gone"))

    def test_no_fleet_domain_holds(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll(cfg=dataclasses.replace(self.cfg, fleet_domain=None))
        self.assertEqual(held(self.rec()), "no_fleet_domain")


class FailureTextTests(_ControlIn):

    def test_an_unknown_policy_code_is_escaped_never_interpreted(self):
        _s, body = peercontrol.failure_notice(about=ABOUT, outcome="refused", cause="policy",
                                              policy_code="weird code\n<b>")
        self.assertIn("refused by the receiving runtime's policy (weird\\x20code\\x0a\\x3cb\\x3e)",
                      body)
        self.assertNotIn("<b>", body)

    def test_a_duplicate_report_says_it_is_not_proof(self):
        _s, body = peercontrol.failure_notice(about=ABOUT, outcome="dropped", cause="duplicate",
                                              policy_code=None)
        self.assertIn("NOT proof that the task failed", body)

    def test_every_schema_pair_has_local_text(self):
        for outcome, causes in peercontrol.CAUSES.items():
            for cause in causes:
                with self.subTest(outcome=outcome, cause=cause):
                    self.assertIn((outcome, cause), peercontrol.FAILURE_TEXT)


class ControlRetentionTests(_ControlIn):

    def test_a_controls_reservation_is_kept_while_its_issued_record_is(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        rec = self.rec()
        rt, idk = rec["replay_ref"].split("/")
        res = self.state_dir / "peer-replay" / rt / f"{idk}.json"
        (self.hop / ".disposed" / ".control" / CID).unlink()     # the entry's removal done
        peerjournal.advance_frontier(self.state_dir)
        later = NOW + timedelta(days=3)
        peerclock.advance(self.state_dir, later)
        peerjournal.sweep(self.state_dir, later, enabled=True, hop_root=self.hop)
        self.assertTrue(res.is_file(), "kept while the issued record is retained")
        self.assertTrue(peerledger.notified_path(self.state_dir, self.lid, ABOUT).is_file())
        (self.state_dir / self.lid / "peer-ledger" / f"{ABOUT}.json").unlink()
        peerjournal.sweep(self.state_dir, later, enabled=True, hop_root=self.hop)
        self.assertFalse(res.is_file(), "pruned once the issued record is gone")
