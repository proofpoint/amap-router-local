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

    def test_an_unfinished_migration_holds(self):
        (self.state_dir / LIDS["alpha"] / generations.MIGRATION_FILE).write_text("{}")
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
                        {"digest": "x", "result": {"detail": "transport: sent"}}))
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
        (self.state_dir / LIDS["alpha"] / generations.MIGRATION_FILE).write_text("{}")
        with self.assertRaises(generations.OperatorRefused):
            self.new()

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
