"""Migrating pre-generation state: `router generation adopt | fence-legacy`
(`router/generations.py`, the migration verbs; `outbound.convert_v1_pending`).

Each test pins one rule; `router/tests/mutate_generations_migration.py`
breaks each rule in the source and names the test that must go red.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
from dataclasses import replace
from unittest import mock

from router import audit as audit_mod
from router import generations, lock, outbound, registry, reset
from router.tests.helpers import gen_state, keyed_for_poll, list_notices, read_json, result_path, write_request
from router.tests.peer_helpers import addr
from router.tests.test_generations import LIDS
from router.tests.test_generations_pending import _Pending


class Crash(Exception):
    """An injected crash: the verb stops where it is."""


def tree(d):
    """`{relative path: sha256 or "dir"}` of everything under `d`."""
    out = {}
    for root, dirs, files in os.walk(d):
        for n in dirs:
            out[os.path.relpath(os.path.join(root, n), d)] = "dir"
        for n in files:
            p = os.path.join(root, n)
            with open(p, "rb") as f:
                out[os.path.relpath(p, d)] = hashlib.sha256(f.read()).hexdigest()
    return out


class _Legacy(_Pending):

    def lid(self, name="alpha"):
        return self.state_dir / LIDS[name]

    def to_legacy(self, name="alpha"):
        """Put `name`'s generation-scoped state back in the pre-generation
        layout, as a router before generations left it: every entry of its
        one generation directly under `state_dir/<logical_id>/`, and no
        generations file. Returns `{entry: tree}` of what was moved."""
        d = gen_state(self.state_dir, LIDS[name])
        moved = {}
        for p in sorted(d.iterdir()):
            if p.name in ("first-sight.taken", generations.REUSE_COUNT_FILE,
                          generations.REUSE_PENDING_DIR):
                continue                    # written only by generation-era code
            moved[p.name] = tree(p) if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest()
            os.rename(p, self.lid(name) / p.name)
        shutil.rmtree(d)
        (self.lid(name) / generations.GEN_FILE).unlink()
        self.assertEqual(self.held(name), generations.HELD_LEGACY_UNADOPTED)
        return moved

    def to_v1(self, req_id="00000001", d=None):
        """Rewrite a pending record as the version 1 a pre-generation router
        wrote: no snapshot, no source generation, no pinned sender."""
        d = d if d is not None else self.lid() / outbound.PENDING_DIR
        path = d / f"{req_id}.json"
        rec = json.loads(path.read_text())
        shutil.rmtree(d / f"{req_id}.{rec['snapshot']['nonce']}.snap")
        for k in ("snapshot", "source_gen", "from_address"):
            rec.pop(k)
        rec["v"] = 1
        path.write_text(json.dumps(rec, sort_keys=True))

    def migrate(self, verb="adopt", name="alpha", reason="upgrade, root unchanged", **kw):
        """The verb, expected to succeed: a refusal is a FAILURE, not an error."""
        try:
            return generations.operator_migrate(self.cfg, name, verb, reason, **kw)
        except generations.OperatorRefused as e:
            self.fail(f"{verb} refused: {e}")

    def refuse(self, verb="adopt", name="alpha", reason="upgrade, root unchanged", **kw):
        """The verb, expected to refuse. Returns the refusal."""
        return self.expect(generations.OperatorRefused, generations.operator_migrate,
                           self.cfg, name, verb, reason, **kw)

    def journal(self, name="alpha"):
        return generations.read_journal(self.state_dir, LIDS[name])

    def expect(self, exc, fn, *a, **kw):
        try:
            fn(*a, **kw)
        except exc as e:
            return e
        except Exception as e:  # noqa: BLE001
            self.fail(f"expected {exc.__name__}, got {type(e).__name__}: {e}")
        self.fail(f"{exc.__name__} was not raised")

    def with_traffic(self):
        """alpha has answered one request and holds one pending (bravo held)."""
        write_request(self.cfg, "alpha", "00000002", to=[addr("bravo")], body_text="answered")
        self.poll()
        self.assertTrue(result_path(self.cfg, "alpha", "00000002").is_file())
        self.make_pending(body="pending across the upgrade")


# ---------------------------------------------------------------------------
# adopt
# ---------------------------------------------------------------------------

class AdoptTests(_Legacy):

    def test_adopt_moves_every_entry_exactly_into_the_current_generation(self):
        self.with_traffic()
        (gen_state(self.state_dir, LIDS["alpha"]) / "transport").mkdir(exist_ok=True)
        (gen_state(self.state_dir, LIDS["alpha"]) / "transport" / "next_req_id").write_text("37")
        moved = self.to_legacy()
        self.to_v1()
        moved["pending"] = tree(self.lid() / "pending")
        plan = self.migrate()
        g = gen_state(self.state_dir, LIDS["alpha"])
        self.assertEqual(g.name, generations.GEN_PREFIX + plan["generation"])
        for n, before in moved.items():
            if n == "pending":
                continue                      # converted below, by design
            with self.subTest(entry=n):
                after = tree(g / n) if (g / n).is_dir() else hashlib.sha256(
                    (g / n).read_bytes()).hexdigest()
                self.assertEqual(after, before)
        self.assertEqual((g / "transport" / "next_req_id").read_text(), "37")
        # ...and they LEFT the legacy layout (the after-check that fails on a no-op).
        self.assertEqual(generations.legacy_entries(self.state_dir, LIDS["alpha"]), [])
        cur = generations.current(self.doc())
        self.assertEqual((cur["reason"], cur["note"]),
                         (generations.REASON_ADOPTED, "upgrade, root unchanged"))
        self.assertEqual(cur["binding"]["binding_seq"],
                         registry.report_for(self.reg, self.state_dir, self.cfg.instances,
                                             persist=False).resolved["alpha"].binding_seq)
        self.assertEqual(self.journal()["phase"], "done")
        self.assertIsNone(self.held())

    def test_an_adopted_instance_drains_on_the_next_poll(self):
        self.poll()
        self.to_legacy()
        self.migrate()
        write_request(self.cfg, "alpha", "00000009", to=[addr("bravo")], body_text="after")
        self.poll()
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000009"))["outcome"],
                         "accepted")
        self.assertIn("after", self.bodies())

    def test_a_v1_pending_record_gains_a_snapshot_from_its_matching_live_request(self):
        self.make_pending(body="converted")
        self.to_legacy()
        self.to_v1()
        plan_conv = self.migrate()
        self.assertEqual(self.journal()["converted"], {"00000001": outbound.CONVERTED})
        rec = self.record()
        self.assertEqual(rec["v"], outbound.PENDING_VERSION)
        self.assertEqual(rec["source_gen"], plan_conv["generation"])
        snap = self.pending_dir() / f"00000001.{rec['snapshot']['nonce']}.snap"
        self.assertEqual(hashlib.sha256((snap / "request").read_bytes()).hexdigest(),
                         rec["request_sha256"])
        # The converted record replays from its snapshot even with the live file gone.
        os.unlink(self.cfg.instances["alpha"].outbox_root / "req-00000001.json")
        self.release_bravo()
        self.poll()
        self.assertEqual(self.bodies(), ["converted"])

    def test_a_v1_record_whose_live_request_changed_stays_v1(self):
        self.make_pending(body="original")
        self.to_legacy()
        self.to_v1()
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="changed")
        self.migrate()
        self.assertEqual(self.journal()["converted"], {"00000001": outbound.KEPT_CHANGED})
        rec = self.record()
        self.assertEqual(rec["v"], 1)
        self.assertNotIn("snapshot", rec)
        self.assertEqual([p.name for p in self.pending_dir().iterdir()], ["00000001.json"],
                         "a snapshot was written for bytes that do not match")

    def test_a_v1_record_whose_live_request_is_gone_stays_v1(self):
        self.make_pending()
        self.to_legacy()
        self.to_v1()
        os.unlink(self.cfg.instances["alpha"].outbox_root / "req-00000001.json")
        self.migrate()
        self.assertEqual(self.journal()["converted"], {"00000001": outbound.KEPT_UNREAD})
        self.assertEqual(self.record()["v"], 1)

    def test_adopt_refuses_an_unopenable_root_and_writes_nothing(self):
        self.poll()
        self.to_legacy()
        shutil.rmtree(self.cfg.instances["alpha"].root)
        e = self.refuse()
        self.assertIn("root", str(e))
        self.assertFalse(generations.journal_path(self.state_dir, LIDS["alpha"]).exists())


# ---------------------------------------------------------------------------
# fence-legacy
# ---------------------------------------------------------------------------

class FenceLegacyTests(_Legacy):

    def test_fence_legacy_fences_the_old_state_and_begins_a_fresh_generation(self):
        self.with_traffic()
        (gen_state(self.state_dir, LIDS["alpha"]) / "transport").mkdir(exist_ok=True)
        (gen_state(self.state_dir, LIDS["alpha"]) / "transport" / "next_req_id").write_text("23")
        self.to_legacy()
        plan = self.migrate("fence-legacy", reason="rebound before the upgrade")
        doc = self.raw_doc()
        self.assertEqual(doc["current"], plan["generation"])
        old = next(g for g in doc["gens"] if g["gen"] == plan["fenced"])
        self.assertEqual(old["reason"], generations.REASON_LEGACY)
        self.assertIsNotNone(old["fenced_ts"])
        self.assertEqual((old["root"]["st_dev"], old["root"]["st_ino"]), (None, None))
        fresh = generations.gen_dir(self.state_dir, LIDS["alpha"], plan["generation"])
        self.assertEqual((fresh / "transport" / "next_req_id").read_text(), "23",
                         "the fresh generation's counter was not carried")
        fenced = generations.gen_dir(self.state_dir, LIDS["alpha"], plan["fenced"])
        self.assertTrue((fenced / "results" / "00000002.json").is_file())
        self.assertEqual(generations.legacy_entries(self.state_dir, LIDS["alpha"]), [])
        self.assertIsNone(self.held())

    def test_a_fenced_legacy_v1_record_holds_legacy_snapshot_missing(self):
        self.make_pending()
        self.to_legacy()
        self.to_v1()
        plan = self.migrate("fence-legacy")
        self.release_bravo()
        self.poll()
        fenced = generations.gen_dir(self.state_dir, LIDS["alpha"], plan["fenced"])
        rec = self.record(gen_dir=fenced)
        self.assertEqual(rec["block"], outbound.BLOCK_LEGACY_SNAPSHOT_MISSING)
        self.assertEqual(self.bodies(), [])

    def test_fenced_legacy_work_settles_privately(self):
        """The legacy generation recorded only a path for its root, which
        vouches for nothing: its pending work completes and its verdict
        stays private. What the root shows is the FRESH generation's first
        sight of the live file (quarantined, resubmit), as fence-legacy
        promises, never the legacy verdict."""
        self.make_pending(body="legacy work")
        self.to_legacy()
        plan = self.migrate("fence-legacy")
        self.release_bravo()
        self.poll()
        fenced = generations.gen_dir(self.state_dir, LIDS["alpha"], plan["fenced"])
        self.assertEqual(self.bodies(), ["legacy work"])
        anchor = read_json(fenced / "results" / "00000001.json")["result"]
        self.assertEqual(anchor["outcome"], "accepted")
        shown = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual(shown["reason_code"], outbound.REASON_QUARANTINED,
                         "a legacy generation published its verdict into the root")


# ---------------------------------------------------------------------------
# The journal: resume, refusals, the rollback blocker
# ---------------------------------------------------------------------------

class JournalTests(_Legacy):

    def legacy_with_work(self):
        self.with_traffic()
        self.to_legacy()
        self.to_v1()

    def final_state(self):
        g = gen_state(self.state_dir, LIDS["alpha"])
        return (self.journal()["phase"], tree(g / "results"),
                self.record()["v"], (self.lid() / generations.BLOCKER).is_dir())

    def test_a_crash_after_every_phase_resumes_to_the_same_end(self):
        for verb in generations.VERBS:
            for stop in generations.PHASES[1:]:
                with self.subTest(verb=verb, crash_after=stop):
                    self.doCleanups()
                    self.setUp()
                    self.legacy_with_work()
                    real = generations._advance

                    def advance(cfg, journal, phase, _stop=stop):
                        real(cfg, journal, phase)
                        if phase == _stop:
                            raise Crash(phase)
                    with mock.patch.object(generations, "_advance", advance):
                        self.expect(Crash, self.migrate, verb)
                    if stop != "done":
                        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
                    self.migrate(verb)
                    j = self.journal()
                    self.assertEqual(j["phase"], "done")
                    self.assertTrue((self.lid() / generations.BLOCKER).is_dir())
                    self.assertEqual(generations.legacy_entries(self.state_dir, LIDS["alpha"]), [])
                    self.assertIsNone(self.held())
                    lines = [json.loads(l) for l in (self.lid() / "audit" / "log.jsonl")
                             .read_text().splitlines()]
                    self.assertEqual(sum(1 for l in lines
                                         if l["event"] == audit_mod.EVENT_MIGRATION),
                                     1, "one attestation line, however many runs")

    def migration_lines(self):
        return [l for l in (json.loads(x) for x in (self.lid() / "audit" / "log.jsonl")
                            .read_text().splitlines()) if l["event"] == audit_mod.EVENT_MIGRATION]

    def test_a_crash_right_after_the_plan_resumes(self):
        self.legacy_with_work()
        with mock.patch.object(generations, "_move_paths", side_effect=Crash("after plan")):
            self.expect(Crash, self.migrate)
        self.assertEqual((self.journal() or {}).get("phase"), "planned")
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
        self.migrate()
        self.assertEqual(self.journal()["phase"], "done")

    def test_a_crash_between_the_attestation_and_done_writes_it_once(self):
        self.legacy_with_work()
        real = generations._advance

        def advance(cfg, journal, phase):
            if phase == "done":
                raise Crash("after the audit line, before done")
            real(cfg, journal, phase)
        with mock.patch.object(generations, "_advance", advance):
            self.expect(Crash, self.migrate)
        self.assertEqual(len(self.migration_lines()), 1)
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
        self.migrate()
        self.assertEqual(self.journal()["phase"], "done")
        self.assertEqual(len(self.migration_lines()), 1, "the attestation was written twice")

    def test_a_crash_between_two_renames_resumes(self):
        self.legacy_with_work()
        real = os.rename
        calls = []

        def rename(src, dst):
            calls.append(src)
            if len(calls) == 2:
                raise Crash("between renames")
            return real(src, dst)
        with mock.patch.object(generations.os, "rename", rename):
            self.expect(Crash, self.migrate)
        self.assertEqual((self.journal() or {}).get("phase"), "planned",
                         "no durable journal before the first rename")
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
        self.migrate()
        self.assertEqual(self.journal()["phase"], "done")
        self.assertEqual(generations.legacy_entries(self.state_dir, LIDS["alpha"]), [])

    def test_a_crash_before_the_blocker_is_made_resumes_and_makes_it(self):
        self.legacy_with_work()
        real = os.mkdir

        def mkdir(path, *a, **kw):
            if str(path).endswith("/" + generations.BLOCKER):
                raise Crash("before the blocker")
            return real(path, *a, **kw)
        with mock.patch.object(generations.os, "mkdir", mkdir):
            self.expect(Crash, self.migrate)
        self.assertIs(self.journal().get("blocker"), True, "the blocker was not recorded first")
        self.assertFalse((self.lid() / generations.BLOCKER).exists())
        self.migrate()
        self.assertTrue((self.lid() / generations.BLOCKER).is_dir())

    def test_both_ends_present_is_a_conflict_not_a_tie_break(self):
        self.legacy_with_work()
        real = os.rename
        n = []

        def rename(src, dst):
            n.append(1)
            if len(n) == 1:
                real(src, dst)
                os.mkdir(src)       # something reappears at the source
                raise Crash("after the first rename")
            return real(src, dst)
        with mock.patch.object(generations.os, "rename", rename):
            self.expect(Crash, self.migrate)
        e = self.refuse()
        self.assertIn("both", str(e))
        self.assertEqual(self.journal()["phase"], "planned")
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_a_planned_entry_changed_before_its_rename_is_a_conflict(self):
        self.legacy_with_work()
        real = generations._write_journal

        def write(state_dir, lid, doc):
            raw = real(state_dir, lid, doc)
            if doc["phase"] == "planned":
                (self.lid() / "first-seen.json").write_text('{"changed": true}')
            return raw
        with mock.patch.object(generations, "_write_journal", write):
            e = self.refuse()
        self.assertIn("changed", str(e))

    def test_a_legacy_entry_that_appears_after_the_plan_is_a_conflict(self):
        self.legacy_with_work()
        real = generations._write_journal

        def write(state_dir, lid, doc):
            raw = real(state_dir, lid, doc)
            if doc["phase"] == "planned":
                (self.lid() / "held").mkdir()
            return raw
        with mock.patch.object(generations, "_write_journal", write):
            e = self.refuse()
        self.assertIn("not planned", str(e))
        self.assertEqual(self.journal()["phase"], "planned")

    def test_a_resume_after_a_rebind_is_refused_and_stays_held(self):
        self.legacy_with_work()
        with mock.patch.object(generations, "_advance", side_effect=Crash("x")):
            self.expect(Crash, self.migrate)
        self.put(alpha={"binding_seq": 9}, bravo={})
        e = self.refuse()
        self.assertIn("binding", str(e))
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_rerunning_a_done_verb_is_a_noop_and_the_other_is_refused(self):
        self.poll()
        self.to_legacy()
        self.migrate()
        before = tree(self.lid())
        self.assertTrue(self.migrate().get("noop"), "a done verb ran again")
        self.assertEqual(tree(self.lid()), before)
        e = self.refuse("fence-legacy")
        self.assertIn("adopt", str(e))

    def test_a_done_journal_is_retained_and_does_not_hold(self):
        self.poll()
        self.to_legacy()
        self.migrate()
        self.assertTrue(generations.journal_path(self.state_dir, LIDS["alpha"]).is_file())
        try:
            state = generations.migration_state(self.state_dir, LIDS["alpha"])
        except generations.GenerationHeld as e:
            self.fail(f"a done journal holds: {e}")
        self.assertEqual(state, "done")
        self.assertIsNone(self.held())

    def test_done_is_more_than_the_phase(self):
        """A journal at `done` is believed only when what it made is there:
        the generation listed with the same legacy record, and the blocker."""
        def adopted():
            self.doCleanups()
            self.setUp()
            self.poll()
            self.to_legacy()
            self.migrate()
        breaks = {
            "blocker gone": lambda: os.rmdir(self.lid() / generations.BLOCKER),
            "legacy record differs": lambda: self._edit_entry(lambda e: e["legacy"].update(counter="99")),
            "generations file lost": lambda: (self.lid() / generations.GEN_FILE).unlink(),
        }
        for label, brk in breaks.items():
            with self.subTest(label):
                adopted()
                brk()
                self.expect(generations.GenerationHeld, generations.migration_state,
                            self.state_dir, LIDS["alpha"])
                self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def _edit_entry(self, fn):
        doc = self.raw_doc()
        fn(doc["gens"][0])
        (self.lid() / generations.GEN_FILE).write_text(json.dumps(doc))

    def test_the_attestation_line_is_written_durably(self):
        self.poll()
        self.to_legacy()
        real = audit_mod.append_bytes
        seen = []

        def append_bytes(*a, **kw):
            if audit_mod.EVENT_MIGRATION.encode() in a[2]:
                seen.append(kw.get("durable"))
            return real(*a, **kw)
        with mock.patch.object(audit_mod, "append_bytes", append_bytes):
            self.migrate()
        self.assertEqual(seen, [True])

    def test_refusals_write_nothing(self):
        self.poll()
        before = tree(self.lid())
        cases = {
            "already in the generation layout": lambda: self.refuse(),
            "unknown name": lambda: self.refuse(name="zulu"),
            "empty reason": lambda: self.refuse(reason=" "),
            "unknown verb": lambda: self.refuse("merge"),
            "no registry": lambda: self.expect(
                generations.OperatorRefused, generations.operator_migrate,
                replace(self.cfg, registry_dir=None), "alpha", "adopt", "r"),
        }
        for label, call in cases.items():
            with self.subTest(label):
                call()
                self.assertEqual(tree(self.lid()), before)

    def test_nothing_pre_generation_is_refused(self):
        shutil.rmtree(self.lid())
        self.lid().mkdir()
        e = self.refuse()
        self.assertIn("no pre-generation state", str(e))

    def test_a_running_router_refuses_the_verb(self):
        self.poll()
        self.to_legacy()
        lk = lock.acquire(self.state_dir)
        try:
            e = self.refuse()
        finally:
            lk.release()
        self.assertIn("running", str(e))
        self.assertFalse(generations.journal_path(self.state_dir, LIDS["alpha"]).exists())

    def test_a_dry_run_writes_nothing(self):
        self.poll()
        self.to_legacy()
        before = tree(self.lid())
        shutil.rmtree(self.state_dir / "registry", ignore_errors=True)
        plan = self.migrate(dry_run=True)
        self.assertTrue(plan["dry_run"])
        self.assertFalse(registry.seq_path(self.state_dir).exists(), "wrote the seq floor")
        self.assertEqual(plan["paths"], ["transport", "first-seen.json"])
        self.assertEqual(tree(self.lid()), before)

    def test_the_audit_line_records_the_attestation(self):
        self.poll()
        self.to_legacy()
        self.migrate()
        lines = [json.loads(l) for l in (self.lid() / "audit" / "log.jsonl").read_text().splitlines()]
        line = next(l for l in lines if l["event"] == audit_mod.EVENT_MIGRATION)
        j = self.journal()
        self.assertEqual((line["verb"], line["reason"]), ("adopt", "upgrade, root unchanged"))
        self.assertEqual(line["journal_sha256"], j["journal_sha256"])
        self.assertEqual((line["binding"], line["root"]), (j["source"]["binding"], j["source"]["root"]))
        self.assertEqual(line["counts"]["basis"], j["legacy"]["basis"])
        body = {k: v for k, v in j.items() if k not in ("audit_line", "journal_sha256")}
        body["phase"] = "complete"
        self.assertEqual(j["journal_sha256"], hashlib.sha256(
            json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest())
        log = (self.lid() / "audit" / "log.jsonl").read_text()
        self.assertEqual(log.count(j["audit_line"]), 1, "the line is not the planned bytes")

    def test_a_failed_audit_line_leaves_it_held_until_a_rerun(self):
        self.poll()
        self.to_legacy()
        with mock.patch.object(audit_mod, "append_bytes",
                               side_effect=OSError(errno.EIO, "injected")):
            e = self.refuse()
        self.assertIn("audit", str(e))
        self.assertEqual(self.journal()["phase"], "complete")
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
        self.migrate()
        self.assertEqual(self.journal()["phase"], "done")


class BlockerTests(_Legacy):

    def adopted(self):
        self.poll()
        self.to_legacy()
        self.migrate()

    def test_the_recorded_blocker_is_not_legacy_state(self):
        self.adopted()
        self.assertTrue((self.lid() / generations.BLOCKER).is_dir())
        self.assertEqual(generations.legacy_entries(self.state_dir, LIDS["alpha"]), [])

    def test_an_unrecorded_blocker_shaped_directory_is_legacy(self):
        self.adopted()
        j = self.journal()
        j.pop("blocker")
        generations._write_journal(self.state_dir, LIDS["alpha"], j)
        self.assertEqual(generations.legacy_entries(self.state_dir, LIDS["alpha"]),
                         [generations.BLOCKER])

    def test_reset_keeps_the_blocker_and_the_journal(self):
        self.adopted()
        reset.reset_instances(self.cfg, ["alpha"])
        self.assertTrue((self.lid() / generations.BLOCKER).is_dir(), "reset removed the blocker")
        self.assertTrue(generations.journal_path(self.state_dir, LIDS["alpha"]).is_file())

    def test_an_older_router_against_the_migrated_layout_delivers_nothing(self):
        """The rollback witness, simulated: today's drain keyed exactly as a
        router before generations keyed it (every generation-scoped path at
        `state_dir/<logical_id>/`). Its first statement meets the blocker,
        and nothing is delivered. The control removes the blocker and the
        same simulation delivers, so the blocker is what stopped it."""
        self.adopted()
        view = keyed_for_poll(self.cfg)
        # No registry checks (they arrived with generations), and the
        # generation key pointing at the logical_id directory itself.
        old = replace(view, registry_dir=None,
                      gen_keys={**view.gen_keys, "alpha": LIDS["alpha"]})
        write_request(self.cfg, "alpha", "00000005", to=[addr("bravo")], body_text="rolled back")
        with self.assertRaises(OSError):
            outbound.drain_instance(old, "alpha")
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        # Control: no blocker, the same view takes first sight, then delivers.
        os.rmdir(self.lid() / generations.BLOCKER)
        outbound.drain_instance(old, "alpha")          # first sight (quarantines 00000005)
        write_request(self.cfg, "alpha", "00000006", to=[addr("bravo")], body_text="control")
        outbound.drain_instance(old, "alpha")
        self.assertIn("control", self.bodies())
