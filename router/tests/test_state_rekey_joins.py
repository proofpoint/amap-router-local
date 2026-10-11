"""Every `state_dir` join under a registry, pinned by a READ or a WRITE that
only the keyed join can satisfy.

The fleet is migrated the way the README says: tasks run before the
registry, then `mv state_dir/<name> state_dir/<logical_id>`, then the
registry is switched on. So everything an un-keyed join would read is
missing (the name directories are gone) and everything it would write
appears under a name, which each test checks for.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from router import (binding, config as config_mod, console, exposure, inflight, outbound,
                    outcomes, registry, reset, service)
from router.config import ConfigError, load_obj
from router.tests.helpers import RouterTestCase, read_json, result_path, write_request
from router.tests.peer_helpers import addr, list_peer_notices, make_peer_config, write_outcome
from router.util import format_utc_ts, parse_utc_ts, utc_ts

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "registry"
LIDS = {"a": "a1" * 16, "b": "b2" * 16, "c": "c3" * 16}


def snapshot(names, seq=3):
    """snapshot.json's active entry, once per name, each with its own lid."""
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


class _Migrated(RouterTestCase):
    """a may task b (b.peer_senders = [a]). One task a -> b runs BEFORE the
    registry; then both are migrated and the registry switched on."""

    def setUp(self):
        super().setUp()
        self.plain = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        write_request(self.plain, "a", "00000001", to=[addr("b")], body_text="do it")
        outbound.drain_instance(self.plain, "a")
        res = read_json(result_path(self.plain, "a", "00000001"))
        self.assertEqual(res["reason_code"], "peer_routed")
        self.task_id = res["message_id"]
        for n in ("a", "b"):
            (self.state_dir / n).rename(self.state_dir / LIDS[n])
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        self.put(["a", "b"])
        self.cfg = replace(self.plain, registry_dir=self.reg)
        service._REGISTRY_LOGGED.clear()

    def put(self, names, seq=3):
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(snapshot(names, seq)))

    def keyed(self):
        report = registry.report_for(self.reg, self.state_dir, self.cfg.instances)
        return registry.keyed_config(self.cfg, report)

    def lid_dir(self, n):
        return self.state_dir / LIDS[n]

    def assertNoNameDirs(self):
        self.assertEqual(sorted(p.name for p in self.state_dir.iterdir()
                                if p.name in self.cfg.instances), [],
                         "something was joined under an instance NAME")


class MigrationEndToEndTests(_Migrated):
    """The central property: a reply to a pre-registry task binds after the
    documented move."""

    def reply(self):
        write_request(self.cfg, "b", "00000002", in_reply_to=self.task_id,
                      to=["anyone@example.invalid"], body_text="done")
        with self.assertLogs("amap_router_local"):
            service.run_once(self.cfg, None)
        return read_json(result_path(self.cfg, "b", "00000002"))

    def test_the_reply_binds_and_its_ledger_lands_under_the_logical_id(self):
        res = self.reply()
        self.assertEqual((res["outcome"], res["reason_code"]), ("accepted", "peer_routed"))
        reply_id = res["message_id"]
        self.assertTrue(binding.ledger_path(self.state_dir, "a", reply_id,
                                            state_key=LIDS["a"]).is_file())
        # The delivery's audit line is in a's log, under a's logical_id.
        log = (self.lid_dir("a") / "audit").glob("*")
        lines = [json.loads(line) for p in log for line in p.read_text().splitlines()]
        self.assertIn(reply_id, [ln.get("notice_id") for ln in lines
                                 if ln.get("event") == "peer_notice_placed"])
        self.assertNoNameDirs()

    def test_without_the_ledger_the_reply_is_unresolved(self):
        """The twin: the binding came from the moved ledger and nowhere else."""
        binding.ledger_path(self.state_dir, "b", self.task_id, state_key=LIDS["b"]).unlink()
        res = self.reply()
        self.assertEqual((res["outcome"], res["reason_code"]), ("rejected", "unresolved_reply"))
        self.assertNoNameDirs()


class OutcomeJoinTests(_Migrated):
    """outcomes: the ledger read, the record write, and placed_but_denied's
    record listing and ledger read; plus the console's ledger and outcome
    reads over the same records."""

    def consume_denied(self):
        write_outcome(self.cfg, "b", self.task_id, "denied")
        return outcomes.consume_instance(self.keyed(), "b")

    def test_a_denied_outcome_is_recorded_and_listed_under_the_logical_id(self):
        summary = self.consume_denied()
        rec = self.lid_dir("b") / "outcomes"
        self.assertEqual([p.name for p in rec.iterdir()], [f"peer-{self.task_id}.denied.json"])
        self.assertEqual([d["notice_id"] for d in summary["peer_placed_denied"]], [self.task_id])
        self.assertNoNameDirs()

    def test_the_console_reads_the_ledger_and_the_outcome_under_the_logical_id(self):
        self.consume_denied()
        data = console.gather(self.cfg)
        task = [m for m in data["messages"] if m["notice_id"] == self.task_id]
        self.assertEqual(len(task), 1, "the console did not find the task in b's ledger")
        self.assertEqual(task[0]["outcome"], "denied")


class ConsoleWithAHeldInstanceTests(_Migrated):
    """The page renders while an instance is held, shows it as held with the
    registry's reason, and reads none of its private state."""

    def page(self):
        return console.render_html(self.cfg)

    def test_state_not_migrated(self):
        self.lid_dir("a").rename(self.state_dir / "a")          # a is back under its name
        data = console.gather(self.cfg)
        self.assertEqual(data["instances"]["a"]["held"], registry.HELD_NOT_MIGRATED)
        self.assertIsNone(data["instances"]["a"]["seen"])
        self.assertIn("HELD: state_not_migrated", self.page())
        # b is resolved and its ledger (the pre-registry task) is still listed.
        self.assertIn(self.task_id, [m["notice_id"] for m in data["messages"]])

    def test_not_registered(self):
        self.put(["a"])
        data = console.gather(self.cfg)
        self.assertEqual(data["instances"]["b"]["held"], registry.HELD_NOT_REGISTERED)
        self.assertEqual(data["messages"], [], "b's ledger was read although b is held")
        self.assertIn("HELD: not_registered", self.page())

    def test_state_conflict(self):
        (self.state_dir / "b").mkdir()                     # beside b's logical_id dir
        data = console.gather(self.cfg)
        self.assertEqual(data["instances"]["b"]["held"], registry.HELD_STATE_CONFLICT)
        self.assertEqual(data["messages"], [])
        self.assertIn("HELD: state_conflict", self.page())

    def test_registry_unavailable(self):
        (self.reg / registry.SNAPSHOT).unlink()
        data = console.gather(self.cfg)
        self.assertEqual({n: i["held"] for n, i in data["instances"].items()},
                         {"a": registry.HELD_UNAVAILABLE, "b": registry.HELD_UNAVAILABLE})
        self.assertIn("HELD: registry_unavailable", self.page())

    def test_registry_rolled_back_and_the_floor_is_preserved(self):
        self.put(["a", "b"], seq=9)
        registry.report_for(self.reg, self.state_dir, ["a"])     # a poll accepts seq 9
        floor = registry.seq_path(self.state_dir)
        before = floor.read_bytes()
        self.put(["a", "b"], seq=3)
        data = console.gather(self.cfg)
        self.assertEqual({n: i["held"] for n, i in data["instances"].items()},
                         {"a": registry.HELD_ROLLED_BACK, "b": registry.HELD_ROLLED_BACK})
        self.assertIn("HELD: registry_rolled_back", self.page())
        self.assertEqual(floor.read_bytes(), before, "the console touched the seq floor")

    def test_healthy_twin(self):
        """No hold: nothing is marked held, and the task is listed."""
        data = console.gather(self.cfg)
        self.assertEqual({n: i["held"] for n, i in data["instances"].items()},
                         {"a": None, "b": None})
        self.assertIn(self.task_id, [m["notice_id"] for m in data["messages"]])
        self.assertNotIn("HELD:", self.page())
        self.assertFalse(registry.seq_path(self.state_dir).exists(),
                         "the console wrote a seq floor")


class ExposureJoinTests(_Migrated):
    """exposure.assess reads the sender's ledger under its logical_id."""

    def test_an_external_ledger_record_is_seen(self):
        now = parse_utc_ts(utc_ts()) + timedelta(seconds=60)
        rec = binding.ledger_path(self.state_dir, "a", "e" * 32, state_key=LIDS["a"])
        rec.parent.mkdir(parents=True, exist_ok=True)
        rec.write_text(json.dumps({"origin": exposure.ORIGIN_EXTERNAL,
                                   "ts": format_utc_ts(now - timedelta(seconds=30))}))
        stamp = exposure.assess(self.keyed(), "a", now=format_utc_ts(now))
        self.assertTrue(stamp["external_mail_delivered"])


class InflightJoinTests(_Migrated):
    def test_inflight_records_and_counter_live_under_the_logical_id(self):
        k = self.keyed()
        for p in (inflight.record_path(k, "a", "00000009"), inflight.counter_path(k, "a")):
            self.assertEqual(p.relative_to(self.state_dir).parts[0], LIDS["a"])


class ResetPlanJoinTests(_Migrated):
    def test_the_plan_lists_the_logical_id_directory(self):
        stale = self.lid_dir("a") / "results" / "00000099.json"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text("{}")
        plan = reset.plan_reset(self.cfg, "a")
        self.assertIn(stale.parent, plan.state_paths)


class QuarantineJoinTests(RouterTestCase):
    """A request already in a never-seen outbox is quarantined under the
    instance's logical_id."""

    def test_quarantine_lands_under_the_logical_id(self):
        plain = self.make_config({"c": []}, seen=False)
        reg = self.tmp / "registry"
        reg.mkdir()
        (reg / registry.SNAPSHOT).write_text(json.dumps(snapshot(["c"])))
        cfg = replace(plain, registry_dir=reg)
        write_request(cfg, "c", "00000001")
        service._REGISTRY_LOGGED.clear()
        with self.assertLogs("amap_router_local"):
            service.run_once(cfg, None)     # first sight: snapshot
            service.run_once(cfg, None)     # the snapshotted request is quarantined
        q = self.state_dir / LIDS["c"] / "quarantine"
        self.assertTrue(q.is_dir() and any(q.iterdir()), "nothing quarantined under the lid")
        self.assertFalse((self.state_dir / "c").exists())


class HeldRecipientWritesNothingTests(_Migrated):
    """A migrated recipient that drops out of the registry is held.
    A delivery to it fails through the ordinary failure path and writes
    nothing under its name, so it does not come back as state_conflict."""

    def test_delivery_to_a_held_recipient_fails_and_writes_no_name_dir(self):
        self.put(["a"])                               # b is now not_registered
        write_request(self.cfg, "a", "00000002", to=[addr("b")], body_text="again")
        with self.assertLogs("amap_router_local"):
            service.run_once(self.cfg, None)
        res = read_json(result_path(self.cfg, "a", "00000002"))
        self.assertEqual((res["outcome"], res["reason_code"]),
                         ("queued_for_human", "delivery_failed"))
        self.assertNoNameDirs()
        self.assertEqual(len(list_peer_notices(self.cfg, "b")), 1, "only the pre-registry task")
        # b comes back cleanly: re-registered, it resolves (no state_conflict).
        self.put(["a", "b"], seq=4)
        r = registry.report_for(self.reg, self.state_dir, self.cfg.instances)
        self.assertEqual(r.held, {})

    def test_state_key_fails_closed_for_a_held_name(self):
        k = registry.keyed_config(self.cfg, registry.report_for(
            self.reg, self.state_dir, ["a"]))
        with self.assertRaises(config_mod.StateKeyUnresolved):
            config_mod.state_key(replace(k, state_keys={"a": LIDS["a"]}), "b")


class ReservedStateNameTests(RouterTestCase):
    """`registry` and `status.json` (this router's own
    state_dir entries) are refused as instance names in BOTH modes, and
    skipped in discovery."""

    def doc(self, name, registry_dir):
        root = self.tmp / "instances" / name
        root.mkdir(parents=True, exist_ok=True)
        d = {"state_dir": str(self.state_dir),
             "instances": {name: {"namespace": str(root), "peers": []}}}
        if registry_dir:
            reg = self.tmp / "registry-dir"
            reg.mkdir(exist_ok=True)
            d["registry_dir"] = str(reg)
        return d

    def test_refused_at_load_in_both_modes(self):
        for name in ("registry", "Registry", "status.json", "STATUS.JSON"):
            for with_registry in (False, True):
                with self.subTest(name=name, registry=with_registry):
                    with self.assertRaises(ConfigError) as cm:
                        load_obj(self.doc(name, with_registry))
                    self.assertIn("keeps directly under state_dir", str(cm.exception))

    def test_skipped_in_discovery(self):
        from router.config import LANE_LEAVES
        base = self.tmp / "fleet"
        slugs = ("registry", "status.json", "alice-deadbeef")
        for slug in slugs:
            for lane, leaves in LANE_LEAVES.items():
                for leaf in leaves:
                    (base / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        sel = self.tmp / "selected.json"
        sel.write_text(json.dumps({"schema": 1, "not_selected": [], "selected": [
            {"slug": s, "at": "2026-10-11T00:00:00Z"} for s in slugs]}))
        cfg = load_obj({"state_dir": str(self.state_dir), "instances_dir": str(base),
                        "selected_json": str(sel)})
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef"])
        for slug in ("registry", "status.json"):
            self.assertIn("keeps in state_dir", cfg.discovery.skipped[slug])

    def test_the_set_is_the_entries_this_router_owns(self):
        from router import lock, status
        self.assertEqual(config_mod.RESERVED_STATE_NAMES,
                         frozenset({registry.SEQ_DIR.casefold(),
                                    status.STATUS_FILENAME.casefold()}))
        self.assertIsNone(config_mod._NAME_RE.fullmatch(lock.LOCK_NAME),
                          "the lock file's name must stay unrepresentable as an instance")


class ResetUnderTheLockTests(_Migrated):
    """The under-lock reset reads the registry FRESH, whatever keys
    the config arrived with, and refuses a held batch before removing
    anything. A dry run does not persist the seq floor."""

    def setUp(self):
        super().setUp()
        self.cached = self.keyed()        # healthy, from just after the migration
        self.result = self.lid_dir("a") / "results" / "00000077.json"
        self.result.parent.mkdir(parents=True, exist_ok=True)
        self.result.write_text("{}")

    def refused(self, reason):
        with self.assertRaises(reset.ResetError) as cm:
            reset.reset_instances(self.cached, ["a"])
        self.assertIn(reason, str(cm.exception))
        self.assertTrue(self.result.is_file(), "a refused reset removed private state")

    def test_a_healthy_cached_config_resets(self):
        """The positive twin."""
        reset.reset_instances(self.cached, ["a"])
        self.assertFalse(self.result.exists())

    def test_a_conflict_since_the_keys_were_cached_is_refused(self):
        (self.state_dir / "a").mkdir()
        self.refused(registry.HELD_STATE_CONFLICT)

    def test_an_unavailable_registry_is_refused(self):
        (self.reg / registry.SNAPSHOT).unlink()
        self.refused(registry.HELD_UNAVAILABLE)

    def test_a_rolled_back_registry_is_refused(self):
        self.put(["a", "b"], seq=9)
        registry.report_for(self.reg, self.state_dir, ["a"])     # accept seq 9
        self.put(["a", "b"], seq=3)
        self.refused(registry.HELD_ROLLED_BACK)

    def test_a_dry_run_does_not_persist_the_seq_floor(self):
        floor = registry.seq_path(self.state_dir)
        if floor.exists():
            floor.unlink()
        reset.plan_resets(self.cfg, ["a"])
        self.assertFalse(floor.exists(), "a dry run wrote the seq floor without the lock")
        reset.reset_instances(self.cfg, ["a"])                    # the twin, under the lock
        self.assertTrue(floor.exists())
