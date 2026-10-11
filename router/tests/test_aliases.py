"""The alias table (`router/aliases.py`; contract §2.3, design v2 + v2.1 +
A1-A3).

Each test pins one rule; `router/tests/mutate_aliases.py` breaks each rule
in the source and names the test that must go red.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import shutil
from dataclasses import replace
from unittest import mock

from router import aliases, audit as audit_mod, config as config_mod, generations, outbound, \
    registry, service
from router.config import AliasEntry, ConfigError
from router.tests.helpers import gen_state, keyed_for_poll, list_notices, read_json, \
    result_path, write_request
from router.tests.peer_helpers import FLEET_DOMAIN, addr, make_peer_config
from router.tests.test_generations import LIDS, snapshot
from router.tests.test_generations_pending import _Pending
from router.tests.test_inflight import EXT, FakeTransport

OLD = "bravo@old.example.invalid"          # §2.4: the same name, the old domain
FUTURE = "2999-01-01T00:00:00Z"
PAST = "2000-01-01T00:00:00Z"


class _Aliases(_Pending):

    def setUp(self):
        super().setUp()
        self.table(AliasEntry(OLD, addr("bravo"), FUTURE))

    def table(self, *entries):
        self.cfg = replace(self.cfg, aliases=tuple(entries))

    def send(self, req_id="00000001", to=None, body="via the alias", poll=True):
        write_request(self.cfg, "alpha", req_id, to=to or [OLD], body_text=body)
        if poll:
            self.poll()

    def result(self, req_id="00000001"):
        p = result_path(self.cfg, "alpha", req_id)
        return read_json(p) if p.exists() else None

    def answered(self, req_id="00000001"):
        """The Result; its absence is a FAILURE, not an error."""
        r = self.result(req_id)
        if r is None:
            self.fail(f"request {req_id} was not answered")
        return r

    def names(self, name, hist, name_seq=None):
        """`name`'s registry entry with name history `hist` (a list of names,
        or None for no history, or a raw value)."""
        def h(e):
            if hist is None:
                e["names"] = None
            elif isinstance(hist, list) and all(isinstance(x, str) for x in hist):
                e["names"] = [{"name": n, "seq": i + 1, "ts": "2026-10-11T04:00:00Z"}
                              for i, n in enumerate(hist)]
                e["name_seq"] = len(hist)
            else:
                e["names"] = hist
        return h

    def put_entry(self, **edits):
        """The registry with each named entry edited by its function."""
        self.seq += 1
        doc = snapshot(self.seq)
        for e in doc["entries"]:
            if e["name"] in edits:
                edits[e["name"]](e)
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(doc))

    def audit_lines(self):
        p = aliases.audit_path(self.state_dir)
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


# ---------------------------------------------------------------------------
# Load-time rules (config.py)
# ---------------------------------------------------------------------------

class LoadTests(_Aliases):

    def check(self, entries, *, registry_dir=True):
        return config_mod._aliases({"aliases": entries},
                                   self.reg if registry_dir else None, FLEET_DOMAIN)

    def refused(self, entries, why, **kw):
        with self.assertRaises(ConfigError) as cm:
            self.check(entries, **kw)
        self.assertIn(why, str(cm.exception))

    def e(self, old, new=None, expires=FUTURE):
        return {"old": old, "new": new or addr("bravo"), "expires": expires}

    def test_a_valid_table_loads(self):
        got = self.check([self.e(OLD)])
        self.assertEqual(got, (AliasEntry(OLD, addr("bravo"), FUTURE),))

    def test_rules(self):
        cases = {
            "needs a registry": ([self.e(OLD)], "needs registry_dir", {"registry_dir": False}),
            "non-ASCII local part": ([self.e("bräv@old.example.invalid")], "not a valid name", {}),
            "an uppercase domain": ([self.e("bravo@OLD.example.invalid")], "normalised", {}),
            "new outside the fleet": ([self.e(OLD, "bravo@elsewhere.invalid")], "canonical", {}),
            "a bad expires": ([self.e(OLD, expires="soon")], "expires", {}),
            "old is new": ([self.e(addr("bravo"))], "same address", {}),
            "reserved": ([self.e("postmaster@old.example.invalid")], "reserved", {}),
            "a same-domain variant of its target": (
                [self.e("BRAVO@" + FLEET_DOMAIN)], "variant of its own target", {}),
            "a duplicate old": ([self.e(OLD), self.e(OLD)], "more than once", {}),
            "a chain": ([self.e(OLD), self.e(addr("bravo"), addr("alpha"))], "no chains", {}),
        }
        for label, (entries, why, kw) in cases.items():
            with self.subTest(label):
                self.refused(entries, why, **kw)

    def test_the_cross_domain_rename_is_valid(self):
        try:
            self.check([self.e(OLD)])      # bravo@old -> bravo@fleet: the §2.4 flip
        except ConfigError as e:
            self.fail(f"the cross-domain rename was refused: {e}")

    def test_an_instance_named_aliases_is_a_load_error(self):
        with self.assertRaises(ConfigError):
            make_peer_config(self, {"aliases": {}})


# ---------------------------------------------------------------------------
# Decisions and normalisation
# ---------------------------------------------------------------------------

class NormaliseTests(_Aliases):

    def test_an_active_alias_delivers_to_its_target_and_warns(self):
        logging.getLogger("amap_router_local").disabled = False
        with self.assertLogs("amap_router_local.outbound", "WARNING") as logs:
            self.send()
        self.assertEqual(self.bodies(), ["via the alias"])
        self.assertEqual(self.answered()["outcome"], "accepted")
        self.assertTrue(any("alias used" in m and OLD in m for m in logs.output))

    def test_the_request_bytes_are_never_rewritten(self):
        path = write_request(self.cfg, "alpha", "00000001", to=[OLD], body_text="x")
        raw = path.read_bytes()
        self.poll()
        archived = self.cfg.instances["alpha"].outbox_root / "processed" / path.name
        self.assertEqual(archived.read_bytes(), raw)

    def test_a_case_variant_fails_closed(self):
        self.send(to=["Bravo@old.example.invalid"])
        self.assertEqual(self.answered()["reason_code"], outbound.REASON_RECIPIENT_UNKNOWN)
        self.assertEqual(self.bodies(), [])

    def test_an_inactive_alias_is_refused_before_any_policy(self):
        called = []

        def policy(cfg, sender, draft):
            called.append(draft)
            return ["bravo"]
        self.table(AliasEntry(OLD, addr("bravo"), PAST))
        write_request(self.cfg, "alpha", "00000001", to=[OLD])
        outbound.drain_instance(keyed_view(self), "alpha", cold_policy=policy)
        self.assertEqual(self.answered()["reason_code"], outbound.REASON_RECIPIENT_UNKNOWN)
        self.assertEqual(called, [], "a policy saw an inactive alias")

    def test_inactive_reasons(self):
        cases = {
            "not in the target's name history": (lambda: self.put_entry(
                bravo=self.names("bravo", ["bravo-x", "bravo"]))) ,
            "no name history": (lambda: self.put_entry(bravo=self.names("bravo", None))),
            "target unknown": (lambda: self.table(
                AliasEntry(OLD, addr("zulu"), FUTURE))),
            "a collision with another identity's current name": (lambda: (
                self.table(AliasEntry("ALPHA@old.example.invalid", addr("bravo"), FUTURE)),
                self.put_entry(bravo=self.names("bravo", ["ALPHA", "bravo"])))),
        }
        want = {"not in the target's name history": aliases.NOT_IN_HISTORY,
                "no name history": aliases.NO_HISTORY,
                "target unknown": aliases.TARGET_UNKNOWN,
                "a collision with another identity's current name": aliases.COLLISION}
        for label, setup in cases.items():
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                if label == "not in the target's name history":
                    self.table(AliasEntry("other@old.example.invalid", addr("bravo"), FUTURE))
                setup()
                to = [self.cfg.aliases[0].old]
                k = keyed_view(self)
                self.assertEqual(k.alias_view.decisions[to[0]].reason, want[label], label)
                self.send(to=to)
                self.assertEqual(self.answered()["reason_code"],
                                 outbound.REASON_RECIPIENT_UNKNOWN, label)

    def test_a_name_in_history_activates_the_alias(self):
        self.table(AliasEntry("bravo-old@old.example.invalid", addr("bravo"), FUTURE))
        self.put_entry(bravo=self.names("bravo", ["bravo-old", "bravo"]))
        self.send(to=["bravo-old@old.example.invalid"])
        self.assertEqual(self.bodies(), ["via the alias"])

    def test_a_malformed_history_holds_unconsumed(self):
        self.put_entry(bravo=self.names("bravo", [{"name": "bravo"}]))
        self.send()
        self.assertIsNone(self.result(), "a held request was answered")
        self.assertTrue((self.cfg.instances["alpha"].outbox_root / "req-00000001.json").exists())
        held = aliases.held_list(keyed_view(self), "alpha")
        self.assertEqual([(h["req_id"], h["reason"]) for h in held],
                         [("00000001", aliases.HELD_HISTORY)])

    def test_a_hold_wins_over_a_refusal(self):
        self.table(AliasEntry(OLD, addr("bravo"), FUTURE),
                   AliasEntry("gone@old.example.invalid", addr("bravo"), PAST))
        self.put_entry(bravo=self.names("bravo", [{"name": "bravo"}]))
        self.send(to=[OLD, "gone@old.example.invalid"])
        self.assertIsNone(self.result())

    def test_the_last_history_element_must_be_the_current_name(self):
        self.put_entry(bravo=self.names("bravo", [
            {"name": "bravo", "seq": 1, "ts": "2026-10-11T04:00:00Z"},
            {"name": "other", "seq": 2, "ts": "2026-10-11T04:00:00Z"}]))
        self.send()
        self.assertIsNone(self.result(), "an unbound history was trusted")

    def test_an_unavailable_registry_holds(self):
        (self.reg / registry.SNAPSHOT).write_text("{")
        k = keyed_view(self)
        n = aliases.normalise(replace(k, alias_view=aliases.prepare(
            k, k.registry_report, write=False)), {"to": [OLD]})
        self.assertIsInstance(n, aliases.Hold)

    def test_a_held_target_goes_pending_then_delivers(self):
        root = self.cfg.instances["bravo"].root
        shutil.move(str(root), str(root) + ".away")
        self.send()
        self.assertIsNone(self.result())
        self.assertTrue((self.pending_dir() / "00000001.json").is_file(), "not pending")
        shutil.move(str(root) + ".away", str(root))
        self.poll()
        self.assertEqual(self.bodies(), ["via the alias"])


def keyed_view(tc):
    k = keyed_for_poll(tc.cfg)
    return aliases.attach(k, k.registry_report)


# ---------------------------------------------------------------------------
# The external leg (R7)
# ---------------------------------------------------------------------------

class ExternalTests(_Aliases):

    def test_an_aliased_draft_never_reaches_the_external_leg(self):
        port = FakeTransport()

        def policy(cfg, sender, draft):
            return outbound.ExternalRoute(tuple([OLD]))      # the ORIGINAL recipients
        write_request(self.cfg, "alpha", "00000001", to=[OLD])
        outbound.drain_instance(keyed_view(self), "alpha", transport=port, cold_policy=policy)
        r = self.answered()
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", outbound.REASON_TRANSPORT_ANOMALY))
        self.assertEqual(r["detail"], "alias-normalised recipients cannot take the external "
                                      "leg; nothing was sent")
        self.assertEqual(port.writes, [])
        self.assertFalse((gen_state(self.state_dir, LIDS["alpha"]) / "inflight").exists()
                         and any((gen_state(self.state_dir, LIDS["alpha"]) / "inflight").iterdir()))


# ---------------------------------------------------------------------------
# Expiry and tombstones (V2-7)
# ---------------------------------------------------------------------------

class TombstoneTests(_Aliases):

    def test_an_expired_alias_is_unknown_and_tombstoned(self):
        self.table(AliasEntry(OLD, addr("bravo"), PAST))
        self.send()
        self.assertEqual(self.answered()["reason_code"], outbound.REASON_RECIPIENT_UNKNOWN)
        s = aliases.read_store(self.state_dir)
        self.assertIn(OLD, s.tombstones)
        self.assertTrue(any(l.get("action") == "tombstoned" and l.get("old") == OLD
                            for l in self.audit_lines()))

    def test_a_failed_tombstone_write_leaves_it_inactive_and_retries(self):
        self.table(AliasEntry(OLD, addr("bravo"), PAST))
        real = aliases.write_tombstone
        with mock.patch.object(aliases, "write_tombstone",
                               side_effect=OSError(errno.EIO, "injected")):
            try:
                self.send()
                write_request(self.cfg, "bravo", "00000001", to=[addr("alpha")], body_text="b")
                self.poll()
            except OSError as e:
                self.fail(f"a failed tombstone write stopped the poll: {e}")
        self.assertEqual(self.answered()["reason_code"], outbound.REASON_RECIPIENT_UNKNOWN)
        self.assertTrue(result_path(self.cfg, "bravo", "00000001").exists(),
                        "an unrelated instance stopped")
        self.assertIn(OLD, aliases.LAST_TOMBSTONE_ERRORS)
        self.assertNotIn(OLD, aliases.read_store(self.state_dir).tombstones)
        self.poll()
        self.assertIn(OLD, aliases.read_store(self.state_dir).tombstones)
        self.assertEqual(aliases.LAST_TOMBSTONE_ERRORS, {})

    def test_a_relisted_tombstoned_alias_stays_inactive(self):
        self.table(AliasEntry(OLD, addr("bravo"), PAST))
        self.poll()
        self.table(AliasEntry(OLD, addr("bravo"), FUTURE))
        self.send()
        self.assertEqual(self.answered()["reason_code"], outbound.REASON_RECIPIENT_UNKNOWN)


# ---------------------------------------------------------------------------
# The store, the floor and the witness (R4, A3)
# ---------------------------------------------------------------------------

class StoreTests(_Aliases):

    def state(self):
        return aliases.store_row(self.state_dir)[0]

    def test_first_initialisation_in_order(self):
        order = []
        for fn in ("_write_store", "_write_floor", "_audit", "_write_witness"):
            real = getattr(aliases, fn)

            def wrap(*a, _real=real, _fn=fn, **kw):
                order.append(_fn)
                return _real(*a, **kw)
            patcher = mock.patch.object(aliases, fn, wrap)   # enterContext is 3.11+
            patcher.start()
            self.addCleanup(patcher.stop)
        self.poll()
        self.assertEqual(order, ["_write_store", "_write_floor", "_audit", "_write_witness"])
        self.assertEqual(self.state(), aliases.ROW_OK)
        self.assertEqual(self.audit_lines()[0]["action"], "init")

    def crash_in(self, fn):
        with mock.patch.object(aliases, fn, side_effect=OSError(errno.EIO, "crash")):
            self.send()
        self.assertIsNone(self.result(), "an alias was used without a settled store")

    def test_a_crash_before_the_floor_recovers(self):
        self.crash_in("_write_floor")
        self.assertEqual(self.state(), aliases.ROW_RECOVER_FLOOR)
        self.poll()
        self.assertEqual(self.state(), aliases.ROW_OK)
        self.assertEqual(self.bodies(), ["via the alias"])

    def test_a_failed_audit_append_leaves_no_witness_and_holds(self):
        self.crash_in("_audit")
        self.assertEqual(aliases.read_witness(self.state_dir), "absent")
        self.assertEqual(self.state(), aliases.ROW_RECOVER_WITNESS)
        self.poll()
        self.assertEqual(self.state(), aliases.ROW_OK)
        self.assertEqual(self.bodies(), ["via the alias"])

    def test_a_crash_before_the_witness_recovers(self):
        self.crash_in("_write_witness")
        self.assertEqual(self.state(), aliases.ROW_RECOVER_WITNESS)
        self.poll()
        self.assertEqual(self.state(), aliases.ROW_OK)

    def test_a_floor_eio_on_an_update_is_raised_next_pass(self):
        self.poll()
        self.table(AliasEntry(OLD, addr("bravo"), PAST))
        with mock.patch.object(aliases, "_write_floor", side_effect=OSError(errno.EIO, "x")):
            self.poll()
        self.assertEqual(self.state(), aliases.ROW_RAISE_FLOOR)
        self.poll()
        self.assertEqual(self.state(), aliases.ROW_OK)

    def test_holding_rows(self):
        def S(seq, tombs=None):
            aliases._write_store(self.state_dir, seq, tombs or {})

        def F(n):
            aliases._write_floor(self.state_dir, n)

        def W():
            aliases._write_witness(self.state_dir)
        cases = {
            "seq 1, no floor, a witness": lambda: (S(1), W()),
            "seq 1, floor above it, no witness": lambda: (S(1), F(2)),
            "below the floor": lambda: (S(2), F(3), W()),
            "two above the floor": lambda: (S(4), F(2), W()),
            "a later store with no floor": lambda: (S(3), W()),
            "a store lost": lambda: (F(2), W()),
            "a corrupt store": lambda: (os.makedirs(self.state_dir / "aliases", exist_ok=True),
                                        (self.state_dir / "aliases" / "tombstones.json")
                                        .write_text("{"), F(1), W()),
            "a foreign entry in aliases/": lambda: (S(1), F(1), W(),
                                                    (self.state_dir / "aliases" / "x").write_text("")),
            "a corrupt witness": lambda: (S(1), F(1), (self.state_dir / "registry")
                                          .mkdir(exist_ok=True),
                                          aliases.witness_path(self.state_dir).write_text("?")),
            "a non-empty seq-1 store with nothing else": lambda: (S(1, {OLD: {
                "expires": PAST, "tombstoned_ts": "2026-10-11T04:00:00Z"}}),),
        }
        for label, setup in cases.items():
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                setup()
                self.assertEqual(self.state(), aliases.ROW_UNVERIFIED, label)
                self.send()
                self.assertIsNone(self.result(), f"{label}: answered")

    def test_status_never_writes(self):
        k = keyed_for_poll(self.cfg)
        aliases.status_doc(k, k.registry_report)
        self.assertEqual(aliases.read_store(self.state_dir).kind, "absent")
        self.assertEqual(aliases.read_witness(self.state_dir), "absent")


# ---------------------------------------------------------------------------
# reinit (V2-2, R5, A1)
# ---------------------------------------------------------------------------

class ReinitTests(_Aliases):

    def lose_store(self):
        self.poll()
        shutil.rmtree(self.state_dir / "aliases")

    def test_a_lost_store_holds_then_reinit_decides(self):
        self.lose_store()
        self.send()
        self.assertIsNone(self.result())
        held = aliases.held_list(keyed_view(self), "alpha")
        self.assertEqual(held[0]["reason"], aliases.HELD_STORE)
        self.assertIsNotNone(held[0]["age_s"])
        plan = aliases.reinit(self.cfg, "store lost on the host")
        self.assertIn(OLD, plan["tombstoned"])
        self.assertEqual(plan["warning"], aliases.REINIT_WARNING)
        self.poll()
        self.assertEqual(self.answered()["reason_code"], outbound.REASON_RECIPIENT_UNKNOWN)

    def test_reinit_tombstones_every_configured_alias(self):
        """(i) a committed tombstone whose audit line is missing, then store
        loss; (ii) a store below its floor that omits a tombstone; (iii) a
        still-listed, unexpired alias: each is tombstoned."""
        for label in ("missing audit line", "below the floor", "unexpired"):
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                self.poll()
                if label == "missing audit line":
                    s = aliases.read_store(self.state_dir)
                    aliases._write_store(self.state_dir, s.seq + 1, {OLD: {
                        "expires": FUTURE, "tombstoned_ts": "2026-10-11T04:00:00Z"}})
                    aliases._write_floor(self.state_dir, s.seq + 1)
                    shutil.rmtree(self.state_dir / "aliases")
                elif label == "below the floor":
                    aliases._write_floor(self.state_dir, 9)
                plan = aliases.reinit(self.cfg, "r")
                self.assertIn(OLD, plan["tombstoned"])
                self.assertIn(OLD, aliases.read_store(self.state_dir).tombstones)
                self.send()
                self.assertEqual(self.answered()["reason_code"],
                                 outbound.REASON_RECIPIENT_UNKNOWN, label)

    def test_reinit_adds_what_the_audit_log_records_as_tombstoned(self):
        self.poll()
        aliases._audit(self.state_dir, action="tombstoned", old="removed@old.example.invalid",
                       seq=7)
        self.table()
        plan = aliases.reinit(self.cfg, "r", dry_run=True)
        self.assertEqual(plan["tombstoned"], ["removed@old.example.invalid"])

    def test_a_dry_run_writes_nothing(self):
        self.lose_store()
        before = sorted(os.listdir(self.state_dir / "registry"))
        plan = aliases.reinit(self.cfg, "r", dry_run=True)
        self.assertTrue(plan.get("dry_run"), "not a dry run")
        self.assertIn(OLD, plan["tombstoned"])
        self.assertFalse((self.state_dir / "aliases").exists())
        self.assertEqual(sorted(os.listdir(self.state_dir / "registry")), before)

    def test_reinit_needs_a_reason_and_a_stopped_router(self):
        from router import lock
        with self.assertRaises(aliases.ReinitRefused):
            aliases.reinit(self.cfg, " ")
        lk = lock.acquire(self.state_dir)
        try:
            with self.assertRaises(aliases.ReinitRefused):
                aliases.reinit(self.cfg, "r")
        finally:
            lk.release()

    def test_reinit_is_audited_durably(self):
        self.lose_store()
        aliases.reinit(self.cfg, "store lost")
        line = self.audit_lines()[-1]
        self.assertEqual((line.get("action"), line.get("reason")), ("reinit", "store lost"))


# ---------------------------------------------------------------------------
# Pending work pins its aliases (V2-1, R1, A2)
# ---------------------------------------------------------------------------

class PinTests(_Aliases):

    def pending_via_alias(self):
        root = self.cfg.instances["bravo"].root
        shutil.move(str(root), str(root) + ".away")
        self.send()
        rec = self.record()
        self.assertEqual(rec["v"], outbound.PENDING_VERSION_ALIASED)
        self.assertEqual(rec["aliases"], {OLD: addr("bravo")})
        self.assertEqual(rec["targets"][0]["address"], addr("bravo"))
        return root

    def release(self, root):
        shutil.move(str(root) + ".away", str(root))
        self.poll()

    def test_an_alias_that_expires_while_pending_still_delivers(self):
        root = self.pending_via_alias()
        self.table(AliasEntry(OLD, addr("bravo"), PAST))
        self.release(root)
        self.assertEqual(self.bodies(), ["via the alias"])

    def test_a_table_edit_while_pending_does_not_retarget(self):
        root = self.pending_via_alias()
        self.table()
        self.release(root)
        self.assertEqual(self.bodies(), ["via the alias"])

    def test_a_target_rebound_while_pending_holds(self):
        root = self.pending_via_alias()
        self.put_entry(bravo=lambda e: e.update(logical_id="c3" * 16))
        shutil.move(str(root) + ".away", str(root))
        self.poll()
        self.assertEqual(self.bodies(), [])
        self.assertEqual(self.record()["targets"][0]["reason"], outbound.HOLD_IDENTITY_CHANGED,
                         "a rebound target was not held as identity_changed")

    def damaged(self, edit):
        root = self.cfg.instances["bravo"].root
        shutil.move(str(root), str(root) + ".away")
        self.send()
        path = self.pending_dir() / "00000001.json"
        rec = json.loads(path.read_text())
        edit(rec)
        path.write_text(json.dumps(rec))
        try:
            outbound._read_pending(path, "00000001")
        except outbound.PendingDamaged:
            return
        except Exception as e:  # noqa: BLE001
            self.fail(f"read as {type(e).__name__}, not as damage: {e}")
        self.fail("a damaged record was accepted")

    def test_the_schema_is_closed(self):
        cases = {
            "an unknown member": lambda r: r.update(extra=1),
            "an unknown target member": lambda r: r["targets"][0].update(extra=1),
            "aliases without addresses": lambda r: r["targets"][0].pop("address"),
            "addresses without aliases": lambda r: r.pop("aliases"),
            "a non-empty map at version 2": lambda r: r.update(v=2),
            "an alias to no target": lambda r: r.update(aliases={OLD: addr("alpha")}),
        }
        for label, edit in cases.items():
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                self.damaged(edit)

    def test_a_record_written_before_aliases_stays_readable(self):
        self.table()
        root = self.cfg.instances["bravo"].root
        shutil.move(str(root), str(root) + ".away")
        self.send(to=[addr("bravo")])
        path = self.pending_dir() / "00000001.json"
        rec = json.loads(path.read_text())
        rec.pop("aliases")
        for t in rec["targets"]:
            t.pop("address")
        self.assertEqual(rec["v"], 2)
        path.write_text(json.dumps(rec))
        self.release(root)
        self.assertEqual(self.bodies(), ["via the alias"])


class HoldMarkerTests(_Aliases):
    """N4: a router-owned age, bound to the request, cleared on consume."""

    def held(self):
        self.put_entry(bravo=self.names("bravo", [{"name": "bravo"}]))
        self.send()
        return aliases.held_list(keyed_view(self), "alpha")

    def test_the_marker_binds_the_request_and_clears_on_consume(self):
        held = self.held()
        self.assertEqual(len(held), 1)
        d = gen_state(self.state_dir, LIDS["alpha"]) / aliases.HELD_DIR
        doc = json.loads((d / "00000001").read_text())
        self.assertEqual(set(doc), {"req_id", "request_sha256", "first_held_ts", "reason"})
        self.put_entry()                              # history repaired
        self.poll()
        self.assertEqual(self.bodies(), ["via the alias"])
        self.assertFalse((d / "00000001").exists(), "the marker outlived its request")

    def test_a_malformed_marker_has_an_unknown_age_and_decides_nothing(self):
        self.held()
        d = gen_state(self.state_dir, LIDS["alpha"]) / aliases.HELD_DIR
        (d / "00000001").write_text("{")
        held = aliases.held_list(keyed_view(self), "alpha")
        self.assertEqual(held[0]["age_s"], None)
        self.put_entry()
        self.poll()
        self.assertEqual(self.bodies(), ["via the alias"])
