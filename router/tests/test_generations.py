"""Generations under a registry (`router/generations.py`; contract §2.2, as
amended).

Each test pins one rule; `router/tests/mutate_generations.py` breaks each
rule in the source and names the test that must go red.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import shutil
from dataclasses import replace
from pathlib import Path
from unittest import mock

from router import generations, inflight, lock, outbound, registry, reset, service
from router.status import StatusTracker
from router.tests.helpers import (
    RouterTestCase, adopt_test_markers, gen_state, keyed_for_poll, list_notices, read_json,
    result_path, write_request,
)
from router.tests.peer_helpers import addr, make_peer_config
from router.tests.test_inflight import EXT, FakeTransport, _external

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "registry"
LIDS = {"alpha": "a1" * 16, "bravo": "b2" * 16}


def snapshot(seq, **overrides):
    """A registry with alpha and bravo active. `overrides` maps a name to
    entry fields to change (e.g. `binding_seq`, `name_seq`)."""
    doc = json.loads((FIXTURES / "snapshot.json").read_text())
    proto = next(e for e in doc["entries"] if e["state"] == "active")
    entries = []
    for n in LIDS:
        e = json.loads(json.dumps(proto))
        e.update(logical_id=LIDS[n], name=n, stable_key=f"/srv/work/{n}")
        e["names"][0]["name"] = n
        e["bindings"][0]["stable_key"] = f"/srv/work/{n}"
        e.update(overrides.get(n, {}))
        entries.append(e)
    doc["entries"] = entries
    doc["seq"] = seq
    return doc


class _Gens(RouterTestCase):

    def setUp(self):
        super().setUp()
        plain = make_peer_config(self, {"alpha": {"peers": ["bravo"]},
                                        "bravo": {"peers": ["alpha"]}})
        for n in LIDS:
            (self.state_dir / n).rename(self.state_dir / LIDS[n])
        self.reg = self.tmp / "registry"
        self.reg.mkdir()
        self.seq = 1
        self.put()
        self.cfg = replace(plain, registry_dir=self.reg)
        adopt_test_markers(self.cfg)
        service._REGISTRY_LOGGED.clear()
        logging.getLogger("amap_router_local").disabled = True
        self.addCleanup(setattr, logging.getLogger("amap_router_local"), "disabled", False)

    def put(self, **overrides):
        self.seq += 1
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(snapshot(self.seq, **overrides)))

    def poll(self, transport=None):
        return service.run_once(self.cfg, transport)

    def doc(self, name="alpha"):
        return generations.read_doc(self.state_dir, LIDS[name])

    def raw_doc(self, name="alpha"):
        """The generations file as written, without its validation."""
        return json.loads((self.state_dir / LIDS[name] / generations.GEN_FILE).read_text())

    def expect(self, exc, fn, *a, **kw):
        """A wrong outcome is a FAILURE, never an error."""
        try:
            fn(*a, **kw)
        except exc as e:
            return e
        except Exception as e:  # noqa: BLE001
            self.fail(f"expected {exc.__name__}, got {type(e).__name__}: {e}")
        self.fail(f"{exc.__name__} was not raised")

    def unfinished_migration(self, name="alpha"):
        """A well-formed journal of a migration that has not finished: only
        the migration check can refuse on it (a malformed one is refused by
        every reader of the journal, the transport counter's included)."""
        legacy = {"basis": "empty", "counter": None, "local": 0, "transport": 0,
                  "malformed": 0, "inflight": 0, "positive_evidence_count": 0,
                  "manifest_sha256": generations.manifest_digest([])}
        ts = "2026-01-01T00:00:00Z"
        (self.state_dir / LIDS[name] / generations.MIGRATION_FILE).write_text(json.dumps({
            "schema": generations.JOURNAL_SCHEMA, "verb": "fence-legacy", "phase": "planned",
            "planned_ts": ts, "name": name, "logical_id": LIDS[name], "reason": "r",
            "gen": "c" * 32, "fresh_gen": "d" * 32,
            "source": {"binding": {"adapter": "sandy", "stable_key": "/k", "binding_seq": 1},
                       "root": {"path": "/r", "st_dev": None, "st_ino": None}},
            "paths": [], "legacy": legacy, "manifest": [], "declared_root": None,
            "first_seen": None}))

    def cur(self, name="alpha"):
        return self.doc(name)["current"]

    def held(self, name="alpha"):
        report = registry.report_for(self.reg, self.state_dir, self.cfg.instances, persist=False)
        report, _ = generations.apply(self.cfg, report)
        return (report.held or {}).get(name)

    def replace_root(self, name="alpha"):
        root = self.cfg.instances[name].root
        shutil.move(str(root), str(root) + ".old")
        shutil.copytree(str(root) + ".old", str(root), symlinks=True)


# ---------------------------------------------------------------------------
# When a generation begins, and when it holds
# ---------------------------------------------------------------------------

class BeginTests(_Gens):

    def test_the_first_poll_of_an_identity_with_no_state_begins_one(self):
        shutil.rmtree(self.state_dir / LIDS["alpha"])
        self.poll()
        doc = self.doc()
        self.assertEqual(len(doc["gens"]), 1)
        self.assertEqual(doc["gens"][0]["reason"], generations.REASON_FIRST)
        d = gen_state(self.state_dir, LIDS["alpha"])
        self.assertEqual((d / "transport" / "next_req_id").read_text(), "1")
        self.assertTrue((d / "first-seen.json").is_file(), "first sight is in the generation")

    def test_ordinary_polls_keep_the_generation(self):
        before = self.cur()
        for _ in range(3):
            self.poll()
        self.assertEqual(self.cur(), before)
        self.assertEqual(len(self.doc()["gens"]), 1)

    def test_a_rebind_begins_one_and_fences_the_old(self):
        old = self.cur()
        self.put(alpha={"binding_seq": 9})
        self.poll()
        doc = self.raw_doc()
        self.assertNotEqual(doc["current"], old)
        cur = next(g for g in doc["gens"] if g["gen"] == doc["current"])
        self.assertEqual(cur["reason"], generations.REASON_REBIND)
        fenced = next(g for g in doc["gens"] if g["gen"] == old)
        self.assertIsNotNone(fenced.get("fenced_ts"), "the old generation is not fenced")

    def test_a_replaced_root_begins_one(self):
        old = self.cur()
        self.replace_root()
        self.poll()
        self.assertNotEqual(self.cur(), old)
        self.assertEqual(generations.current(self.doc())["reason"], generations.REASON_ROOT)

    def test_a_name_seq_or_epoch_change_does_not(self):
        old = self.cur()
        self.put(alpha={"name_seq": 5, "enrollment_epoch": 3})
        self.poll()
        self.assertEqual(self.cur(), old)

    def test_the_root_identity_comes_from_the_opened_descriptor(self):
        """The identity recorded is the opened directory's, so a symlink at
        the root path is refused, never followed."""
        root = self.cfg.instances["alpha"].root
        shutil.move(str(root), str(root) + ".real")
        os.symlink(str(root) + ".real", str(root))
        self.assertEqual(self.held(), generations.HELD_CONNECTOR_UNVERIFIED)


class HoldTests(_Gens):

    def test_an_unopenable_root_holds(self):
        shutil.rmtree(self.cfg.instances["alpha"].root)
        self.assertEqual(self.held(), generations.HELD_CONNECTOR_UNVERIFIED)

    def test_the_pre_generation_layout_holds_and_nothing_is_written(self):
        lid = self.state_dir / LIDS["alpha"]
        shutil.rmtree(lid)
        (lid / "results").mkdir(parents=True)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        summary = self.poll()
        self.assertNotIn("alpha", summary)
        self.assertEqual(self.held(), generations.HELD_LEGACY_UNADOPTED)
        self.assertEqual(sorted(p.name for p in lid.iterdir()), ["results"])

    def test_per_identity_state_alone_is_not_legacy(self):
        lid = self.state_dir / LIDS["alpha"]
        shutil.rmtree(lid)
        (lid / "delivered").mkdir(parents=True)
        self.assertIsNone(self.held())

    def test_a_damaged_generations_file_holds(self):
        f = self.state_dir / LIDS["alpha"] / generations.GEN_FILE
        for bad in (b"{", b'{"schema": "other"}', json.dumps(
                {"schema": generations.SCHEMA, "gens": [], "current": None}).encode()):
            with self.subTest(bad=bad):
                f.write_bytes(bad)
                self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_a_missing_current_generation_holds(self):
        shutil.rmtree(gen_state(self.state_dir, LIDS["alpha"]))
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_a_lost_generations_file_holds_rather_than_restart(self):
        """Generation directories without the file that lists them: a fresh
        start at counter 1 would reuse their transport ids and ignore their
        anchors. Held; reset refuses too."""
        d = gen_state(self.state_dir, LIDS["alpha"])
        (d / "transport" / "next_req_id").write_text("42")
        (self.state_dir / LIDS["alpha"] / generations.GEN_FILE).unlink()
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
        self.assertFalse((self.state_dir / LIDS["alpha"] / generations.GEN_FILE).exists())
        with self.assertRaises(reset.ResetError):
            reset.reset_instances(self.cfg, ["alpha"])
        self.assertEqual(generations.generation_dirs(self.state_dir / LIDS["alpha"]), [d])

    def test_an_empty_leftover_of_an_interrupted_first_start_is_not_a_loss(self):
        lid = self.state_dir / LIDS["alpha"]
        shutil.rmtree(lid)
        left = generations.gen_dir(self.state_dir, LIDS["alpha"], "f" * 32)
        (left / "transport").mkdir(parents=True)
        (left / "transport" / "next_req_id").write_text("1")
        self.assertIsNone(self.held())
        self.assertIsNotNone(self.doc())

    def test_an_unfinished_migration_holds(self):
        self.unfinished_migration()
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_a_lost_marker_in_a_generation_with_state_holds_never_resnapshots(self):
        self.poll()
        d = gen_state(self.state_dir, LIDS["alpha"])
        (d / "first-seen.json").unlink()
        self.assertEqual(self.held(), generations.HELD_MARKER_LOST)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        self.assertFalse((d / "first-seen.json").exists(), "re-snapshotted")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists())

    def test_first_sight_in_a_fresh_generation_survives_losing_its_marker(self):
        """First sight taken by a poll leaves its sentinel BEFORE the marker,
        so the marker's later loss holds rather than re-snapshotting."""
        shutil.rmtree(self.state_dir / LIDS["alpha"])
        self.poll()
        d = gen_state(self.state_dir, LIDS["alpha"])
        self.assertTrue((d / "first-sight.taken").is_file())
        (d / "first-seen.json").unlink()
        self.assertEqual(self.held(), generations.HELD_MARKER_LOST)

    def test_a_corrupt_marker_holds_too(self):
        d = gen_state(self.state_dir, LIDS["alpha"])
        (d / "first-seen.json").write_text("{not json")
        self.assertEqual(self.held(), generations.HELD_MARKER_LOST)

    def test_a_fresh_generation_without_a_marker_takes_first_sight(self):
        shutil.rmtree(self.state_dir / LIDS["alpha"])
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        self.assertIsNone(self.held())
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["reason_code"],
                         outbound.REASON_QUARANTINED)

    def test_a_held_recipient_receives_nothing(self):
        shutil.rmtree(self.cfg.instances["bravo"].root / "inbox", ignore_errors=True)
        shutil.rmtree(self.cfg.instances["bravo"].root)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        self.poll()
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists())


# ---------------------------------------------------------------------------
# The transport counter carried into a successor
# ---------------------------------------------------------------------------

class CounterTests(_Gens):

    def pred(self):
        return gen_state(self.state_dir, LIDS["alpha"])

    def rebind(self):
        self.put(alpha={"binding_seq": self.seq + 10})
        self.poll()

    def test_the_successor_starts_at_the_next_unused_id(self):
        (self.pred() / "transport" / "next_req_id").write_text("7")
        self.rebind()
        self.assertEqual((self.pred() / "transport" / "next_req_id").read_text(), "7")

    def test_a_predecessor_that_never_handed_one_out_gives_one(self):
        (self.pred() / "transport" / "next_req_id").unlink()
        self.rebind()
        self.assertEqual((self.pred() / "transport" / "next_req_id").read_text(), "1")

    def test_a_missing_counter_with_ids_handed_out_holds(self):
        for what in ("inflight", "transport anchor"):
            with self.subTest(what=what):
                self.setUp()
                p = self.pred()
                (p / "transport" / "next_req_id").unlink()
                if what == "inflight":
                    (p / "inflight").mkdir()
                    (p / "inflight" / "00000001.json").write_text("{}")
                else:
                    (p / "results").mkdir()
                    (p / "results" / "00000001.json").write_text(json.dumps(
                        {"digest": "x", "result": {}, "transport_req_id": "00000001"}))
                self.put(alpha={"binding_seq": 99})
                self.assertEqual(self.held(), generations.HELD_COUNTER_UNVERIFIED)

    def test_a_hand_off_settled_as_an_anomaly_still_counts(self):
        """An id handed out and settled as an anomaly (archived with no
        result) left no verdict text from the transport; its anchor records
        the id it held, so a lost counter still holds."""
        port = FakeTransport()
        write_request(self.cfg, "alpha", "00000001", to=[EXT])
        k = keyed_for_poll(self.cfg)
        outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
        port.archived["00000001"] = port.pending.pop("00000001")    # archived, no result
        outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
        anchor = read_json(self.pred() / "results" / "00000001.json")
        self.assertEqual(anchor["result"]["reason_code"], "transport_anomaly")
        self.assertEqual(anchor.get("transport_req_id"), "00000001")
        (self.pred() / "transport" / "next_req_id").unlink()
        self.put(alpha={"binding_seq": 99})
        self.assertEqual(self.held(), generations.HELD_COUNTER_UNVERIFIED)

    def test_a_corrupt_counter_holds(self):
        (self.pred() / "transport" / "next_req_id").write_text("seven")
        self.put(alpha={"binding_seq": 99})
        self.assertEqual(self.held(), generations.HELD_COUNTER_UNVERIFIED)

    def test_a_new_generation_allocates_from_its_own_counter(self):
        (self.pred() / "transport" / "next_req_id").write_text("41")
        old = self.pred()
        self.rebind()
        k = keyed_for_poll(self.cfg)
        self.assertEqual(inflight.allocate_transport_req_id(k, "alpha"), "00000041")
        self.assertEqual((old / "transport" / "next_req_id").read_text(), "41",
                         "the fenced generation allocated")

    def test_the_generations_file_names_it_only_after_its_counter_is_durable(self):
        """A crash between the counter and the generations file leaves the
        file unchanged: the new directory is unlisted and nothing reads it."""
        before = self.doc()
        self.put(alpha={"binding_seq": 99})
        with mock.patch.object(generations, "_write_doc",
                               side_effect=OSError(errno.EIO, "injected")):
            self.held()
        self.assertEqual(self.doc(), before)
        dirs = generations.generation_dirs(self.state_dir / LIDS["alpha"])
        self.assertEqual(len(dirs), 2, "the successor's directory was not written first")


# ---------------------------------------------------------------------------
# Placement verifies the recipient's root
# ---------------------------------------------------------------------------

class RecipientRootTests(_Gens):

    def test_a_root_replaced_after_the_pre_pass_receives_nothing(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        k = keyed_for_poll(self.cfg)
        self.replace_root("bravo")
        outbound.drain_instance(k, "alpha")
        self.assertEqual(list_notices(self.cfg, "bravo"), [], "placed into a replaced root")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists())
        self.poll()     # the next pre-pass begins bravo's generation for the new root
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)

    def test_the_write_itself_verifies_the_root(self):
        """Even past the hold check (a root replaced in the instant between
        the check and the write), the descriptor the placement writes through
        must be the recorded root: nothing reaches the new one."""
        from router import config as config_mod
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        k = keyed_for_poll(self.cfg)
        self.replace_root("bravo")
        from router import deliver as deliver_mod
        passed = lambda cfg, name: None  # noqa: E731
        with mock.patch.object(outbound, "target_hold", passed), \
                mock.patch.object(config_mod, "target_hold", passed), \
                mock.patch.object(deliver_mod, "target_hold", passed):
            outbound.drain_instance(k, "alpha")
        self.assertEqual(list_notices(self.cfg, "bravo"), [], "written through a replaced root")

    def test_a_recipient_without_a_generation_holds(self):
        """Under a registry, a resolved recipient with no current generation
        this poll (no pre-pass ran) is held, never written on a guess."""
        from router import config as config_mod
        k = registry.keyed_config(self.cfg, registry.report_for(
            self.reg, self.state_dir, self.cfg.instances, persist=False))
        self.assertEqual(config_mod.target_hold(k, "bravo"),
                         generations.HELD_RECIPIENT_UNRESOLVED)

    def test_a_sender_root_replaced_after_the_pre_pass_is_not_drained(self):
        """The drain verifies its OWN root against the generation's: a root
        replaced since the pre-pass gets no anchor in the old generation, no
        result, no delivery; the next poll begins its generation, whose first
        sight quarantines what was staged."""
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        k = keyed_for_poll(self.cfg)
        old = gen_state(self.state_dir, LIDS["alpha"])
        self.replace_root("alpha")
        with self.assertRaises(generations.GenerationHeld):
            outbound.drain_instance(k, "alpha")
        self.assertFalse((old / "results" / "00000001.json").exists())
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists())
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        self.poll()
        self.poll()
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["reason_code"],
                         outbound.REASON_QUARANTINED)

    def test_a_root_replaced_inside_the_drain_is_never_read(self):
        """The read window: the root is replaced AFTER the drain pinned and
        checked it, before any request is read. The drain acts only through
        the pinned descriptor: the replacement's request is never read,
        delivered or anchored; the original is processed in the directory it
        was verified as, under its own generation."""
        from router import firstsight
        root = self.cfg.instances["alpha"].root
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="original")
        k = keyed_for_poll(self.cfg)
        real = firstsight.record_first_sight

        def swap_then_first_sight(cfg, name, **kw):
            if name == "alpha":
                self.replace_root("alpha")
                write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")],
                              body_text="REPLACEMENT")
            return real(cfg, name, **kw)
        with mock.patch.object(firstsight, "record_first_sight", swap_then_first_sight):
            outbound.drain_instance(k, "alpha")
        inbox = self.cfg.instances["bravo"].inbox_root / "messages"
        bodies = [json.loads((inbox / n).read_text())["body_text"]
                  for n in list_notices(self.cfg, "bravo")]
        self.assertNotIn("REPLACEMENT", bodies, "read through the replaced root")
        self.assertEqual(bodies, ["original"])
        anchor = read_json(gen_state(self.state_dir, LIDS["alpha"]) / "results" / "00000001.json")
        live = (self.cfg.instances["alpha"].outbox_root / "req-00000001.json").read_bytes()
        import hashlib
        self.assertNotEqual(anchor["digest"], hashlib.sha256(live).hexdigest(),
                            "the old generation anchored the replacement")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "a result was published into the replacement root")
        old = Path(str(root) + ".old")
        self.assertTrue((old / "outbox" / "results" / "00000001.json").is_file()
                        or (old / "outbound" / "results" / "00000001.json").is_file())

    def test_the_publish_itself_verifies_its_root(self):
        """Defence in depth behind the pinned view: a publish handed a root
        path that now names another directory refuses before writing."""
        from router import attachments as attachments_mod
        k = keyed_for_poll(self.cfg)
        self.replace_root("alpha")
        with self.assertRaises(attachments_mod.RootChanged):
            outbound._publish_result_and_archive(k, "alpha", "00000001", b"{}")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists())

    def test_a_result_is_never_published_into_a_replaced_root(self):
        """Past the drain's own check (a root replaced mid-request), the
        publish's root descriptor must be the recorded root."""
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        k = keyed_for_poll(self.cfg)
        real = outbound._finish

        def swap_then_finish(*a, **kw):
            self.replace_root("alpha")
            return real(*a, **kw)
        with mock.patch.object(outbound, "_finish", swap_then_finish):
            outbound.drain_instance(k, "alpha")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "published into a replaced root")

    def test_the_pre_pass_runs_before_any_instance_drains(self):
        order = []
        real = generations.resolve

        def spy(state_dir, name, entry, root):
            order.append(("resolve", name))
            return real(state_dir, name, entry, root)

        real_drain = outbound.drain_instance

        def drain(cfg, name, **kw):
            order.append(("drain", name))
            return real_drain(cfg, name, **kw)
        with mock.patch.object(generations, "resolve", spy), \
                mock.patch.object(service.outbound, "drain_instance", drain):
            self.poll()
        kinds = [k for k, _ in order]
        self.assertEqual(kinds, ["resolve", "resolve", "drain", "drain"])


# ---------------------------------------------------------------------------
# The stranded guard
# ---------------------------------------------------------------------------

class StrandedTests(_Gens):

    def test_a_generation_chain_without_its_registry_is_stranded(self):
        self.assertTrue(registry.stranded_state(self.state_dir))

    def test_in_flight_work_inside_a_generation_is_seen(self):
        lid = self.state_dir / LIDS["alpha"]
        gdir = generations.generation_dirs(lid)[0]
        (lid / generations.GEN_FILE).rename(lid / "parked")
        self.assertNotIn(LIDS["alpha"], registry.stranded_state(self.state_dir))
        (gdir / "inflight").mkdir()
        (gdir / "inflight" / "00000001.json").write_text("{}")
        self.assertIn(LIDS["alpha"], registry.stranded_state(self.state_dir))


# ---------------------------------------------------------------------------
# The operator verb
# ---------------------------------------------------------------------------

class OperatorNewTests(_Gens):

    def new(self, name="alpha", reason="counter reset seen by the operator", **kw):
        return generations.operator_new(self.cfg, name, reason, **kw)

    def test_it_fences_carries_and_audits(self):
        old = self.cur()
        (gen_state(self.state_dir, LIDS["alpha"]) / "transport" / "next_req_id").write_text("12")
        plan = self.new()
        self.assertEqual(plan["fences"], old)
        self.assertEqual(self.cur(), plan["generation"])
        cur = generations.current(self.doc())
        self.assertEqual((cur["reason"], cur.get("note")),
                         (generations.REASON_OPERATOR, "counter reset seen by the operator"))
        self.assertEqual((gen_state(self.state_dir, LIDS["alpha"]) / "transport"
                          / "next_req_id").read_text(), "12")
        log = (self.state_dir / LIDS["alpha"] / "audit" / "log.jsonl").read_text()
        line = json.loads(log.strip().splitlines()[-1])
        self.assertEqual((line["event"], line["gen"], line["fenced"]),
                         (generations.EVENT_GENERATION_MINTED, plan["generation"], old))

    def test_a_failed_audit_line_commits_nothing(self):
        """The audit line is part of the verb's commit: if it cannot be
        written, the verb refuses and the current generation is unchanged."""
        from router import audit as audit_mod
        before = self.doc()
        with mock.patch.object(audit_mod, "append", side_effect=OSError(errno.EIO, "injected")):
            e = self.expect(generations.OperatorRefused, self.new)
        self.assertIn("audit", str(e))
        self.assertEqual(self.doc(), before)

    def test_a_dry_run_writes_nothing(self):
        before = self.doc()
        shutil.rmtree(self.state_dir / "registry", ignore_errors=True)
        plan = self.new(dry_run=True)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(self.doc(), before)
        self.assertFalse(registry.seq_path(self.state_dir).exists(), "wrote the seq floor")

    def test_refusals_write_nothing(self):
        before = self.doc()
        cases = {
            "unknown": lambda: self.new(name="zulu"),
            "empty reason": lambda: self.new(reason="  "),
            "no registry": lambda: generations.operator_new(
                replace(self.cfg, registry_dir=None), "alpha", "r"),
        }
        for label, call in cases.items():
            with self.subTest(label):
                with self.assertRaises(generations.OperatorRefused):
                    call()
                self.assertEqual(self.doc(), before)

    def test_a_running_router_refuses_it(self):
        lk = lock.acquire(self.state_dir)
        try:
            with self.assertRaises(generations.OperatorRefused) as cm:
                self.new()
        finally:
            lk.release()
        self.assertIn("running", str(cm.exception))

    def test_a_registry_held_instance_is_refused(self):
        doc = snapshot(self.seq + 1)
        doc["entries"] = [e for e in doc["entries"] if e["name"] != "alpha"]
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(doc))
        self.expect(generations.OperatorRefused, self.new)

    def test_the_pre_generation_layout_and_no_generation_are_refused(self):
        lid = self.state_dir / LIDS["alpha"]
        shutil.rmtree(lid)
        with self.assertRaises(generations.OperatorRefused) as cm:
            self.new()
        self.assertIn("no current generation", str(cm.exception))
        (lid / "pending").mkdir(parents=True)
        with self.assertRaises(generations.OperatorRefused) as cm:
            self.new()
        self.assertIn("pre-generation", str(cm.exception))

    def test_an_unfinished_migration_is_refused(self):
        self.unfinished_migration()
        with self.assertRaises(generations.OperatorRefused) as cm:
            self.new()
        self.assertIn("unfinished", str(cm.exception))

    def test_an_unreadable_root_does_not_stop_the_fence(self):
        old = self.cur()
        shutil.rmtree(self.cfg.instances["alpha"].root)
        plan = self.new()
        self.assertNotEqual(self.cur(), old)
        self.assertIsNone(plan["root"]["st_ino"])

    def test_the_cli(self):
        import contextlib
        import io
        from router import __main__ as cli
        old = self.cur()
        argv = ["--config", "unused", "generation", "new", "alpha", "--reason", "seen"]
        out = io.StringIO()
        with mock.patch.object(cli, "load", lambda path: self.cfg), \
                contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(argv + ["--dry-run"]), 0)
            self.assertEqual(self.cur(), old)
            self.assertEqual(cli.main(argv), 0)
        self.assertNotEqual(self.cur(), old)
        self.assertEqual(json.loads(out.getvalue().splitlines()[-1])["generation"], self.cur())
        err = io.StringIO()
        with mock.patch.object(cli, "load", lambda path: self.cfg), \
                contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["--config", "unused", "generation", "new", "zulu",
                                       "--reason", "x"]), 1)
        self.assertIn("refused", err.getvalue())


# ---------------------------------------------------------------------------
# A reused id held across a generation
# ---------------------------------------------------------------------------

class ReusePendingExitTests(_Gens):
    """The documented way out of `req_id_reused_pending`: status shows it,
    with its age and the hint; `generation new` fences the old work; the new
    generation's first sight quarantines the held request."""

    def test_status_shows_it_and_generation_new_lets_the_agent_resubmit(self):
        port = FakeTransport()
        cfg = self.cfg
        write_request(cfg, "alpha", "00000001", to=[EXT], subject="original")
        k = keyed_for_poll(cfg)
        outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
        self.assertEqual(port.writes, ["00000001"])
        old = self.cur()
        write_request(cfg, "alpha", "00000001", to=[EXT], subject="brand new after reset")
        tracker = StatusTracker(interval_s=5.0)
        service.poll_once(cfg, tracker, port)
        doc = tracker.to_doc()["generations"]["alpha"]
        [entry] = doc.get("req_id_reused_pending") or [None]
        self.assertIsNotNone(entry, "status shows no held reused id")
        self.assertEqual(entry["req_id"], "00000001")
        self.assertGreaterEqual(entry["age_s"], 0)
        self.assertIn("router generation new", doc["hint"])
        generations.operator_new(cfg, "alpha", "counter reset")
        service.poll_once(cfg, tracker, port)
        r = read_json(result_path(cfg, "alpha", "00000001"))
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", outbound.REASON_QUARANTINED))
        self.assertEqual(tracker.to_doc()["generations"]["alpha"]["fenced_work"],
                         {old: {"inflight": 1, "pending": 0}})
        self.assertEqual(port.writes, ["00000001"], "the held request was handed over")


class GenerationScopedAnchorsTests(_Gens):
    """The promise a generation exists to keep: after `generation new`, an id
    the connector reuses is a NEW request. Its old anchor answered it within
    the old generation and stays there, untouched."""

    def test_a_reused_id_is_refused_within_a_generation_and_accepted_after_new(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="first")
        self.poll()
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")
        old_anchor = gen_state(self.state_dir, LIDS["alpha"]) / "results" / "00000001.json"
        before = old_anchor.read_bytes() if old_anchor.exists() else None
        outbox = self.cfg.instances["alpha"].outbox_root
        shutil.rmtree(outbox / "results")
        shutil.rmtree(outbox / "processed")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="second")
        self.poll()
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual((r["outcome"], r["reason_code"]), ("rejected", "req_id_reused"))
        generations.operator_new(self.cfg, "alpha", "connector counter reset")
        self.poll()                      # the new generation's first sight: outbox empty
        shutil.rmtree(outbox / "results")
        shutil.rmtree(outbox / "processed")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="third")
        self.poll()
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual(r["outcome"], "accepted", "a reused id was refused in a new generation")
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 2)
        self.assertIsNotNone(before, "no anchor in the generation it settled in")
        self.assertEqual(old_anchor.read_bytes(), before, "the old generation's anchor changed")


class ExposureClampTests(_Gens):

    def test_the_window_is_clamped_to_first_sight_in_the_generation(self):
        """Under a registry `exposure.assess` reads the first-sight marker
        from the sender's generation, so a young first sight still clamps."""
        from router import exposure
        d = gen_state(self.state_dir, LIDS["alpha"])
        marker = json.loads((d / "first-seen.json").read_text())
        marker["first_seen_ts"] = "2026-09-03T11:00:00Z"
        (d / "first-seen.json").write_text(json.dumps(marker))
        stamp = exposure.assess(keyed_for_poll(self.cfg), "alpha", now="2026-09-03T12:00:00Z")
        self.assertEqual(stamp["window_start"], "2026-09-03T11:00:00Z")


class ResetGenerationTests(_Gens):
    """`reset` under a registry: refused during a migration, all selected
    instances checked before any acts, and the new generation begun before
    anything is wiped."""

    def test_an_unfinished_migration_refuses_reset(self):
        self.unfinished_migration()
        before = self.doc()
        with self.assertRaises(reset.ResetError) as cm:
            reset.reset_instances(self.cfg, ["alpha"])
        self.assertIn("unfinished", str(cm.exception))
        self.assertEqual(self.doc(), before)

    def test_one_instance_that_cannot_begin_refuses_the_whole_batch(self):
        before = self.doc("alpha")
        write_request(self.cfg, "alpha", "00000009", to=[addr("bravo")])
        (gen_state(self.state_dir, LIDS["bravo"]) / "transport" / "next_req_id").write_text("x")
        with self.assertRaises(reset.ResetError):
            reset.reset_instances(self.cfg, ["alpha", "bravo"])
        self.assertEqual(self.doc("alpha"), before, "alpha was acted on")
        self.assertTrue((self.cfg.instances["alpha"].outbox_root / "req-00000009.json").exists())

    def test_the_generation_is_begun_before_anything_is_wiped(self):
        old = self.cur()
        ledger = self.state_dir / LIDS["alpha"] / "delivered"
        ledger.mkdir()
        (ledger / "notice-x.json").write_text("{}")
        with mock.patch.object(reset, "_clear_state", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                reset.reset_instances(self.cfg, ["alpha"])
        self.assertNotEqual(self.cur(), old, "nothing was begun before the wipe")
        self.assertTrue((ledger / "notice-x.json").exists())
        fenced = next(g for g in self.raw_doc()["gens"] if g["gen"] == old)
        self.assertIsNotNone(fenced.get("fenced_ts"))


class ReuseCountTests(_Gens):

    def test_status_counts_settled_reuse_per_generation(self):
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="first")
        self.poll()
        outbox = self.cfg.instances["alpha"].outbox_root
        shutil.rmtree(outbox / "results")
        shutil.rmtree(outbox / "processed")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="second")
        tracker = StatusTracker(interval_s=5.0)
        service.poll_once(self.cfg, tracker, None)
        doc = tracker.to_doc()["generations"]["alpha"]
        self.assertEqual(doc.get("req_id_reused"), {self.cur(): 1})


class OutcomeConsumeTests(_Gens):
    """The peer outcome consume reads and deletes files inside an instance's
    root: it runs through the same verified descriptor as the drain, and not
    at all after a drain held for the root."""

    def outcome(self):
        from router.tests.peer_helpers import write_outcome
        self.assertIsNotNone(self.cfg.instances["alpha"].peer_root, "precondition: peer lane")
        return write_outcome(self.cfg, "alpha", "0" * 32, "delivered")

    def test_outcomes_are_consumed_only_through_the_verified_root(self):
        path = self.outcome()
        real = outbound.drain_instance

        def drain_then_swap(cfg, name, **kw):
            out = real(cfg, name, **kw)
            if name == "alpha":
                self.replace_root("alpha")      # the copy carries the outcome file
            return out
        with mock.patch.object(service.outbound, "drain_instance", drain_then_swap):
            summary = self.poll()
        self.assertTrue(path.exists(), "an outcome was consumed through a replaced root")
        self.assertEqual(summary["alpha"].get("peer_outcome_errored"), 1)

    def test_no_consume_after_a_drain_held_for_its_root(self):
        path = self.outcome()

        def held(cfg, name, **kw):
            raise generations.GenerationHeld(generations.HELD_CONNECTOR_UNVERIFIED, "test")
        with mock.patch.object(service.outbound, "drain_instance", held):
            self.poll()
        self.assertTrue(path.exists(), "outcomes were consumed after a held drain")
