"""The migration verbs' frozen rules (`router/generations.py`): how legacy
transport evidence is classified, how the counter is known, what a
successor of a migrated generation may start from, what "done" is checked
against, how the attestation line is committed, and adopt's evidence.

Each test pins one rule; `router/tests/mutate_generations_migration.py`
breaks each rule in the source and names the test that must go red.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import shutil
from datetime import timedelta
from unittest import mock

from router import audit as audit_mod
from router import generations, outbound, registry, reset
from router.tests.helpers import AMP_ROOT, gen_state, keyed_for_poll, read_json, write_request
from router.tests.peer_helpers import addr
from router.tests.test_generations import LIDS
from router.tests.test_generations_migration import Crash, _Legacy
from router.tests.test_inflight import EXT, FakeTransport, _external
from router.util import parse_utc_ts

REQ = "00000001"


def result(**over):
    doc = outbound._result_doc(REQ, "accepted", reason_code="allowlisted",
                               recipients=["x@example.invalid"])
    doc.update(over)
    return doc


def forge(journal, edit):
    """`journal` edited and then made self-consistent: its digest and its
    planned line re-derived from the edited body, so that only the check
    under test can see the edit."""
    j = {k: v for k, v in journal.items() if k not in ("audit_line", "journal_sha256")}
    edit(j)
    generations._plan_audit(j["name"], j)
    return j


def anchor(res=None, **env):
    e = {"digest": "a" * 64, "result": res if res is not None else result()}
    e.update(env)
    return json.dumps(e).encode()


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

class ClassifyTests(_Legacy):

    def test_local_anchors_are_the_shape_the_writer_made_and_conform(self):
        spec = importlib.util.spec_from_file_location(
            "amp_fixtures_validate", AMP_ROOT / "fixtures" / "validate.py")
        v = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(v)
        for label, res in {
            "accepted": result(),
            "rejected": outbound._result_doc(REQ, "rejected", reason_code="recipient_unknown"),
            "begin_external refusal": outbound._result_doc(
                REQ, "queued_for_human", reason_code="transport_anomaly",
                detail="the external leg is not configured for this instance", recipients=[]),
            "attachments": dict(result(), attachments=[
                {"index": 0, "outcome": "accepted", "detail": None}]),
        }.items():
            with self.subTest(label):
                self.assertEqual(v.check_document("result-produced.json", res), [])
                self.assertEqual(generations.classify_anchor(anchor(res), REQ), generations.LOCAL)

    def test_transport_evidence_is_positive(self):
        cases = {
            "a recorded transport id": anchor(transport_req_id="00000007"),
            "a verdict from the transport": anchor(result(detail="transport: relayed")),
            "an anomaly after allocation": anchor(outbound._result_doc(
                REQ, "queued_for_human", reason_code="transport_anomaly",
                detail="the transport request was archived without a result", recipients=[])),
        }
        for label, raw in cases.items():
            with self.subTest(label):
                self.assertEqual(generations.classify_anchor(raw, REQ), generations.TRANSPORT)

    def test_anything_else_is_malformed(self):
        res_missing = result()
        del res_missing["job_id"]
        cases = {
            "not JSON": b"{",
            "an arbitrary result object": anchor({"anything": 1}),
            "a required member missing": anchor(res_missing),
            "an extra result member": anchor(dict(result(), extra=1)),
            "a different req_id": anchor(result(req_id="00000002")),
            "an extra envelope member": anchor(note="x"),
            "a bad digest": anchor(digest="XYZ"),
            "duplicate keys": (b'{"digest": null, "result": ' + json.dumps(result()).encode()
                               + b', "result": ' + json.dumps(result()).encode() + b'}'),
            "a bad ts": anchor(result(ts="yesterday")),
            "a non-null job_id": anchor(result(job_id="j")),
        }
        for label, raw in cases.items():
            with self.subTest(label):
                self.assertEqual(generations.classify_anchor(raw, REQ), generations.MALFORMED)


# ---------------------------------------------------------------------------
# How the counter is known (plan time, both verbs)
# ---------------------------------------------------------------------------

class BasisTests(_Legacy):

    def legacy(self, *, counter=None, anchors=(), inflight=False):
        self.poll()
        self.to_legacy()
        t = self.lid() / "transport" / "next_req_id"
        if counter is None:
            t.unlink()
        else:
            t.write_text(counter)
        if anchors:
            (self.lid() / "results").mkdir(exist_ok=True)
        for i, raw in enumerate(anchors, 1):
            (self.lid() / "results" / f"{i:08d}.json").write_bytes(raw)
        if inflight:
            (self.lid() / "inflight").mkdir()
            (self.lid() / "inflight" / "00000009.json.handed").write_text("")

    def local(self, i):
        return anchor(outbound._result_doc(f"{i:08d}", "accepted", reason_code="allowlisted",
                                           recipients=["x@example.invalid"]))

    def test_a_counter_is_preserved_exactly(self):
        self.legacy(counter="17", anchors=[anchor(transport_req_id="1")])
        self.migrate()
        self.assertEqual(self.journal()["legacy"]["basis"], generations.BASIS_COUNTER)

    def test_positive_evidence_without_a_counter_refuses_whatever_is_attested(self):
        for label, kw in {"in flight": {"inflight": True},
                          "a transport verdict": {"anchors": [anchor(
                              result(req_id="00000001", detail="transport: ok"))]}}.items():
            for verb in generations.VERBS:
                with self.subTest(label, verb=verb):
                    self.doCleanups()
                    self.setUp()
                    self.legacy(**kw)
                    e = self.refuse(verb, no_transport_history=1)
                    self.assertIn("proven allocated", str(e))
                    self.assertIsNone(self.journal())

    def test_a_malformed_anchor_without_a_counter_refuses(self):
        self.legacy(anchors=[b"{"])
        e = self.refuse(no_transport_history=0)
        self.assertIn("cannot be classified", str(e))

    def test_nothing_at_all_is_empty(self):
        self.legacy()
        self.migrate()
        self.assertEqual(self.journal()["legacy"]["basis"], generations.BASIS_EMPTY)

    def test_local_anchors_alone_need_the_exact_count_attested(self):
        for verb in generations.VERBS:
            with self.subTest(verb=verb):
                self.doCleanups()
                self.setUp()
                self.legacy(anchors=[self.local(1), self.local(2)])
                self.assertIn("--no-transport-history=2", str(self.refuse(verb)))
                self.assertIn("does not match", str(self.refuse(verb, no_transport_history=3)))
                self.assertIsNone(self.journal())
                self.migrate(verb, no_transport_history=2)
                leg = self.journal()["legacy"]
                self.assertEqual((leg["basis"], leg["local"]), (generations.BASIS_ATTESTED, 2))

    def test_a_corrupt_counter_refuses(self):
        self.legacy(counter="seven")
        self.assertIn("corrupt", str(self.refuse()))

    def test_an_attested_adoption_is_shown_and_warned_about(self):
        self.legacy(anchors=[self.local(1)])
        self.migrate(no_transport_history=1)
        a = generations.attested(self.state_dir, LIDS["alpha"])
        self.assertEqual(a["local_anchors"], 1)
        k = keyed_for_poll(self.cfg)
        from router.status import StatusTracker  # noqa: F401  (status_doc is what writes it)
        doc = generations.status_doc(k, k.registry_report)
        self.assertEqual(doc["alpha"].get("legacy_attested", {}).get("gen"), a["gen"])
        logging.getLogger("amap_router_local").disabled = False
        for label, act in {
            "generation new": lambda: generations.operator_new(self.cfg, "alpha", "after"),
            "reset": lambda: reset.reset_instances(self.cfg, ["alpha"]),
        }.items():
            with self.subTest(label):
                with self.assertLogs("amap_router_local.generations", "WARNING") as logs:
                    act()
                self.assertTrue(any("ATTESTED" in m and label in m for m in logs.output))

    def test_the_classification_is_never_redone_on_resume(self):
        self.legacy(counter="5", anchors=[self.local(1)])
        with mock.patch.object(generations, "_move_paths", side_effect=Crash("after plan")):
            self.expect(Crash, self.migrate)
        planned = self.journal()["legacy"]
        # Something lands in a planned directory after the plan: it moves
        # with the directory, but the facts the plan recorded stand.
        (self.lid() / "results" / "00000003.json").write_bytes(b"{")
        self.migrate()
        self.assertEqual(self.journal()["legacy"], planned)
        self.assertEqual(self.raw_doc()["gens"][0]["legacy"], planned)


# ---------------------------------------------------------------------------
# A successor of a migrated generation
# ---------------------------------------------------------------------------

class SuccessorTests(_Legacy):

    def adopted(self, counter="9"):
        self.poll()
        self.to_legacy()
        (self.lid() / "transport" / "next_req_id").write_text(counter)
        self.migrate()
        return gen_state(self.state_dir, LIDS["alpha"])

    def edit_entry(self, fn, name="alpha"):
        f = self.state_dir / LIDS[name] / generations.GEN_FILE
        doc = json.loads(f.read_text())
        fn(doc["gens"][0])
        f.write_text(json.dumps(doc))

    def test_a_counter_below_the_migrated_one_holds(self):
        g = self.adopted("9")
        (g / "transport" / "next_req_id").write_text("4")
        self.expect(generations.GenerationHeld, generations.next_counter, g)
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_a_lost_migrated_counter_holds(self):
        """Even at 1, where the floor alone would pass it: a counter that was
        migrated and is now gone is lost, never "nothing handed out"."""
        g = self.adopted("1")
        (g / "transport" / "next_req_id").unlink()
        e = self.expect(generations.GenerationHeld, generations.next_counter, g)
        self.assertEqual(e.reason, generations.HELD_COUNTER_UNVERIFIED)

    def test_a_migrated_generation_without_its_legacy_record_holds(self):
        g = self.adopted()
        self.edit_entry(lambda e: e.pop("legacy"))
        e = self.expect(generations.GenerationHeld, generations.next_counter, g)
        self.assertEqual(e.reason, generations.HELD_COUNTER_UNVERIFIED)

    def test_a_legacy_record_no_journal_names_holds(self):
        self.poll()
        g = gen_state(self.state_dir, LIDS["bravo"])
        self.edit_entry(lambda e: e.update(legacy={"basis": "empty"}), name="bravo")
        e = self.expect(generations.GenerationHeld, generations.next_counter, g)
        self.assertEqual(e.reason, generations.HELD_COUNTER_UNVERIFIED)

    def test_an_inconsistent_legacy_record_holds(self):
        g = self.adopted()
        j = forge(self.journal(), lambda j: j["legacy"].update(local=j["legacy"]["local"] + 1))
        generations._write_journal(self.state_dir, LIDS["alpha"], j)
        self.edit_entry(lambda e: e["legacy"].update(local=j["legacy"]["local"]))
        e = self.expect(generations.GenerationHeld, generations.next_counter, g)
        self.assertEqual(e.reason, generations.HELD_COUNTER_UNVERIFIED)

    def test_an_attested_history_does_not_count_its_local_anchors(self):
        self.poll()
        self.to_legacy()
        (self.lid() / "transport" / "next_req_id").unlink()
        (self.lid() / "results").mkdir(exist_ok=True)
        (self.lid() / "results" / "00000001.json").write_bytes(anchor(
            result(req_id="00000001")))
        self.migrate(no_transport_history=1)
        plan = generations.operator_new(self.cfg, "alpha", "rebuild")
        self.assertEqual(plan["transport_counter"], 1)

    def test_every_in_flight_settlement_records_its_transport_id(self):
        """A settled in-flight request's anchor records the id it held, on
        the published path and on the private one (the request under the id
        changed meanwhile): that record is what a successor counts."""
        for private in (False, True):
            with self.subTest(private=private):
                self.doCleanups()
                self.setUp()
                port = FakeTransport()
                write_request(self.cfg, "alpha", REQ, to=[EXT])
                k = keyed_for_poll(self.cfg)
                outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
                if private:
                    write_request(self.cfg, "alpha", REQ, to=[EXT], body_text="another")
                port.send(REQ)
                outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
                a = read_json(gen_state(self.state_dir, LIDS["alpha"]) / "results"
                              / f"{REQ}.json")
                self.assertEqual(a.get("transport_req_id"), "00000001")


# ---------------------------------------------------------------------------
# What "done" is checked against, every poll
# ---------------------------------------------------------------------------

class DoneReaderTests(_Legacy):

    def made(self, verb="adopt"):
        self.doCleanups()
        self.setUp()
        self.with_traffic()
        self.to_legacy()
        (self.lid() / "transport" / "next_req_id").write_text("6")
        self.migrate(verb)
        return generations.gen_dir(self.state_dir, LIDS["alpha"], self.journal()["gen"])

    def raw_entries(self, fn):
        f = self.lid() / generations.GEN_FILE
        doc = json.loads(f.read_text())
        fn(doc["gens"])
        f.write_text(json.dumps(doc))

    def assert_held(self):
        self.expect(generations.GenerationHeld, generations.migration_state,
                    self.state_dir, LIDS["alpha"])
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_each_check(self):
        cases = {
            "binding": lambda g: self.raw_entries(
                lambda gs: gs[0]["binding"].update(binding_seq=77)),
            "root": lambda g: self.raw_entries(lambda gs: gs[0]["root"].update(st_ino=1)),
            "destination type": lambda g: (shutil.rmtree(g / "results"),
                                           (g / "results").write_text("x")),
            "digest": lambda g: (g / "first-seen.json").write_text('{"changed": 1}'),
            "manifest anchor": lambda g: (g / "results" / "00000002.json").write_text("{}"),
            "basis consistency": lambda g: self._both_legacy(lambda leg: leg.update(local=9)),
            "counter floor": lambda g: (g / "transport" / "next_req_id").write_text("2"),
            "blocker": lambda g: os.rmdir(self.lid() / generations.BLOCKER),
        }
        for label, brk in cases.items():
            with self.subTest(label):
                g = self.made()
                self.assertEqual(generations.migration_state(self.state_dir, LIDS["alpha"]), "done")
                brk(g)
                self.assert_held()

    def _both_legacy(self, fn):
        j = forge(self.journal(), lambda j: fn(j["legacy"]))
        generations._write_journal(self.state_dir, LIDS["alpha"], j)
        self.raw_entries(lambda gs: fn(gs[0]["legacy"]))

    def test_the_fence_legacy_chain(self):
        for label, brk in {
            "successor not adjacent": lambda gs: gs.insert(1, dict(gs[1], gen="c" * 32,
                                                                   fenced_ts="x")),
            "legacy generation unfenced": lambda gs: gs[0].update(reason="first"),
        }.items():
            with self.subTest(label):
                self.made("fence-legacy")
                self.raw_entries(brk)
                self.expect(generations.GenerationHeld, generations.migration_state,
                            self.state_dir, LIDS["alpha"])

    def test_the_audit_match_is_checked_before_reset_and_new_not_each_poll(self):
        self.made()
        line = self.journal()["audit_line"]
        with open(self.lid() / "audit" / "log.jsonl", "a") as f:
            f.write(line)                       # a duplicate
        self.assertIsNone(self.held(), "an ordinary poll read the audit log")
        with self.assertRaises(reset.ResetError):
            reset.reset_instances(self.cfg, ["alpha"])
        self.expect(generations.OperatorRefused, generations.operator_new,
                    self.cfg, "alpha", "r")


# ---------------------------------------------------------------------------
# The attestation line: planned once, committed exactly once
# ---------------------------------------------------------------------------

class AuditCommitTests(_Legacy):

    def to_complete(self):
        """Stop the verb at `complete` (its line planned, not yet written)."""
        self.poll()
        self.to_legacy()
        with mock.patch.object(generations, "commit_audit", side_effect=OSError(5, "crash")):
            self.refuse()
        j = self.journal()
        self.assertEqual(j["phase"], "complete")
        return j

    def log(self):
        return self.lid() / "audit" / "log.jsonl"

    def add(self, data: bytes):
        self.log().parent.mkdir(parents=True, exist_ok=True)
        with open(self.log(), "ab") as f:
            f.write(data)

    def copies(self, j):
        return self.log().read_bytes().split(b"\n").count(j["audit_line"].encode()[:-1])

    def test_an_unrelated_malformed_line_is_skipped(self):
        j = self.to_complete()
        self.add(b"{not json from an older crash\n")
        self.migrate()
        self.assertEqual(self.copies(j), 1)

    def test_a_malformed_line_with_this_journals_digest_holds(self):
        j = self.to_complete()
        self.add(b'{"torn": "' + j["journal_sha256"].encode() + b'\n')
        self.assertIn("digest", str(self.refuse()))

    def test_duplicate_keys_are_malformed(self):
        j = self.to_complete()
        # Read leniently the LAST value wins and the line looks unrelated.
        self.add(('{"journal_sha256": "%s", "journal_sha256": "%s"}\n'
                  % (j["journal_sha256"], "0" * 64)).encode())
        self.assertIn("digest", str(self.refuse()))

    def test_a_torn_prefix_is_terminated_then_the_line_written_whole(self):
        j = self.to_complete()
        self.add(j["audit_line"].encode()[:25])
        self.migrate()
        self.assertEqual(self.copies(j), 1)
        self.assertTrue(self.log().read_bytes().endswith(j["audit_line"].encode()))
        self.assertEqual(generations.migration_state(self.state_dir, LIDS["alpha"], audit=True),
                         "done")

    def test_a_whole_unterminated_copy_is_only_terminated(self):
        j = self.to_complete()
        self.add(j["audit_line"].encode()[:-1])
        self.migrate()
        self.assertEqual(self.copies(j), 1)

    def test_a_different_line_for_this_journal_holds(self):
        j = self.to_complete()
        doc = json.loads(j["audit_line"])
        doc["reason"] = "rewritten"
        self.add((json.dumps(doc) + "\n").encode())
        self.assertIn("differs", str(self.refuse()))

    def test_two_copies_hold(self):
        j = self.to_complete()
        self.add(j["audit_line"].encode() * 2)
        self.assertIn("more than once", str(self.refuse()))

    def test_an_unreadable_log_holds(self):
        self.to_complete()
        with mock.patch.object(audit_mod, "read_raw", side_effect=OSError(5, "EIO")):
            self.assertIn("cannot be read", str(self.refuse()))

    def test_a_durable_append_writes_whole_and_syncs_file_and_new_directories(self):
        d = self.tmp / "fresh-state"
        d.mkdir()
        synced = []
        real = os.fsync

        def fsync(fd):
            synced.append(fd)
            return real(fd)
        writes = []
        real_write = os.write

        def write(fd, data):
            n = real_write(fd, bytes(data)[:3])       # a short write each time
            writes.append(n)
            return n
        with mock.patch.object(audit_mod.os, "fsync", fsync), \
                mock.patch.object(audit_mod.os, "write", write):
            audit_mod.append_bytes(d, "alpha", b"0123456789\n", state_key="k", durable=True)
        self.assertEqual((d / "k" / "audit" / "log.jsonl").read_bytes(), b"0123456789\n")
        self.assertEqual(len(synced), 3, "file, log directory and its parent")


# ---------------------------------------------------------------------------
# adopt's evidence
# ---------------------------------------------------------------------------

class AdoptEvidenceTests(_Legacy):

    def marker_ts(self):
        return parse_utc_ts(json.loads((self.lid() / "first-seen.json").read_text())
                            ["first_seen_ts"])

    def at(self, delta_s):
        return (self.marker_ts() + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def history(self, *elems, flat_seq=None):
        hist = [{"adapter": "sandy", "seq": s, "stable_key": "/srv/work/alpha", "ts": ts}
                for s, ts in elems]
        self.put(alpha={"bindings": hist, "binding_seq": flat_seq or hist[-1]["seq"]})

    def legacy(self):
        self.poll()
        self.to_legacy()

    def test_an_initial_binding_after_first_sight_still_adopts(self):
        """As the registry fixture's seq-2 entry: a registry imported after
        the router first saw the instance records its initial binding later."""
        self.legacy()
        self.history((2, self.at(3600)))
        self.migrate()

    def test_a_rebind_at_or_after_first_sight_refuses(self):
        for label, delta in {"after": 60, "within the skew margin": -1}.items():
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                self.legacy()
                self.history((1, self.at(-86400)), (5, self.at(delta)))
                self.assertIn("rebind", str(self.refuse()))
                self.migrate("fence-legacy")      # the way out

    def test_a_rebind_before_first_sight_adopts(self):
        self.legacy()
        self.history((1, self.at(-86400)), (5, self.at(-2)))
        self.migrate()

    def test_a_malformed_history_refuses(self):
        cases = {
            "an earlier element is current": lambda: self.history(
                (1, self.at(-9)), (5, self.at(-5)), flat_seq=1),
            "seqs not increasing": lambda: self.history((5, self.at(-9)), (5, self.at(-5))),
            "timestamps decreasing": lambda: self.history((1, self.at(-5)), (5, self.at(-9))),
            "an extra key": lambda: self.put(alpha={"bindings": [
                {"adapter": "sandy", "seq": 1, "stable_key": "/srv/work/alpha",
                 "ts": self.at(-9), "x": 1}]}),
            "no history": lambda: self.put(alpha={"bindings": None}),
        }
        for label, setup in cases.items():
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                self.legacy()
                setup()
                self.assertIn("binding history", str(self.refuse()))

    def test_the_declared_root_must_be_this_root(self):
        self.legacy()
        m = self.lid() / "first-seen.json"
        doc = json.loads(m.read_text())
        doc["declared_root"] = doc["declared_root"] + "/"          # normalises equal
        m.write_text(json.dumps(doc))
        self.assertIsNone(generations.journal_path(self.state_dir, LIDS["alpha"]).exists() or None)
        doc["declared_root"] = "/elsewhere"
        m.write_text(json.dumps(doc))
        self.assertIn("written for root", str(self.refuse()))
        doc["declared_root"] = str(self.cfg.instances["alpha"].root) + "/"
        m.write_text(json.dumps(doc))
        self.migrate()

    def test_a_missing_marker_refuses_unless_a_dated_approval_stands_in(self):
        self.legacy()
        m = json.loads((self.lid() / "first-seen.json").read_text())
        (self.lid() / "first-seen.json").unlink()
        self.assertIn("no legacy first-sight marker", str(self.refuse()))
        approval = {"approved_ts": m["first_seen_ts"], "declared_root": m["declared_root"],
                    "outbox_snapshot": []}
        (self.lid() / "approval.json").write_text(json.dumps({**approval, "approved_ts": None}))
        self.assertIn("no legacy first-sight marker", str(self.refuse()))
        (self.lid() / "approval.json").write_text(json.dumps(approval))
        self.migrate()

    def test_a_marker_adopted_from_an_approval_needs_its_approved_ts(self):
        self.legacy()
        f = self.lid() / "first-seen.json"
        doc = json.loads(f.read_text())
        doc.update(adopted_from="approval.json", approved_ts=None)
        f.write_text(json.dumps(doc))
        self.assertIn("no legacy first-sight marker", str(self.refuse()))
        doc["approved_ts"] = doc["first_seen_ts"]
        f.write_text(json.dumps(doc))
        self.migrate()


# ---------------------------------------------------------------------------
# The journal is its own commitment (review round 1)
# ---------------------------------------------------------------------------

class JournalCommitmentTests(_Legacy):

    def made(self):
        self.with_traffic()
        self.to_legacy()
        (self.lid() / "transport" / "next_req_id").write_text("6")
        self.migrate()
        return gen_state(self.state_dir, LIDS["alpha"])

    def write_raw(self, j):
        generations.journal_path(self.state_dir, LIDS["alpha"]).write_text(json.dumps(j))

    def held_both_ways(self, g):
        self.expect(generations.GenerationHeld, generations.migration_state,
                    self.state_dir, LIDS["alpha"], audit=True)
        e = self.expect(generations.GenerationHeld, generations.next_counter, g)
        self.assertEqual(e.reason, generations.HELD_COUNTER_UNVERIFIED)
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_a_lowered_counter_everywhere_but_the_commitment_holds(self):
        """The journal's legacy counter, the generation's equal record and
        the live counter all lowered together: the digest the attestation
        committed to no longer matches the body, so nothing believes it."""
        g = self.made()
        j = self.journal()
        j["legacy"]["counter"] = "2"
        self.write_raw(j)
        f = self.lid() / generations.GEN_FILE
        doc = json.loads(f.read_text())
        doc["gens"][0]["legacy"]["counter"] = "2"
        f.write_text(json.dumps(doc))
        (g / "transport" / "next_req_id").write_text("2")
        self.held_both_ways(g)

    def test_a_planned_line_that_does_not_carry_the_body_holds(self):
        """Even with the digest recomputed to the edited body, the planned
        line still says what was attested, and it must equal the body."""
        g = self.made()
        j = self.journal()
        j["reason"] = "a different reason"
        j["journal_sha256"] = generations.journal_digest(j)
        self.write_raw(j)
        self.held_both_ways(g)

    def test_a_stored_digest_that_is_not_the_bodys_holds(self):
        g = self.made()
        j = self.journal()
        j["journal_sha256"] = "0" * 64
        self.write_raw(j)
        e = self.expect(generations.GenerationHeld, generations.read_journal,
                        self.state_dir, LIDS["alpha"])
        self.assertIn("digest", str(e))

    def test_a_malformed_source_holds_and_never_escapes(self):
        self.made()
        j = self.journal()
        j["source"] = {}
        self.write_raw(j)
        e = self.expect(generations.GenerationHeld, generations.read_journal,
                        self.state_dir, LIDS["alpha"])
        self.assertIn("source", str(e))
        self.expect(generations.GenerationHeld, generations.migration_state,
                    self.state_dir, LIDS["alpha"])
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)

    def test_a_journal_for_another_identity_holds(self):
        self.made()
        j = self.journal()
        j["logical_id"] = LIDS["bravo"]
        self.write_raw(j)
        e = self.expect(generations.GenerationHeld, generations.read_journal,
                        self.state_dir, LIDS["alpha"])
        self.assertIn("another identity", str(e))

    def test_an_unexpected_member_holds(self):
        """Before `complete` (no digest yet to catch it): a member that is
        not this phase's is refused by the schema alone."""
        self.poll()
        self.to_legacy()
        with mock.patch.object(generations, "_move_paths", side_effect=Crash("after plan")):
            self.expect(Crash, self.migrate)
        j = self.journal()
        j["extra"] = 1
        self.write_raw(j)
        self.expect(generations.GenerationHeld, generations.read_journal,
                    self.state_dir, LIDS["alpha"])

    def test_a_resume_under_another_name_is_refused(self):
        self.poll()
        self.to_legacy()
        with mock.patch.object(generations, "_move_paths", side_effect=Crash("after plan")):
            self.expect(Crash, self.migrate)
        j = self.journal()
        j["name"] = "bravo-was-here"
        self.write_raw(j)
        self.assertIn("begun for", str(self.refuse()))


# ---------------------------------------------------------------------------
# First sight of an adopted generation (review round 1)
# ---------------------------------------------------------------------------

class AdoptedFirstSightTests(_Legacy):

    def test_an_approval_only_legacy_instance_adopts_and_drains(self):
        self.poll()
        self.to_legacy()
        m = json.loads((self.lid() / "first-seen.json").read_text())
        (self.lid() / "first-seen.json").unlink()
        (self.lid() / "approval.json").write_text(json.dumps(
            {"approved_ts": "2026-01-01T00:00:00Z", "declared_root": m["declared_root"],
             "outbox_snapshot": [], "mode": m.get("mode")}))
        self.migrate()
        g = gen_state(self.state_dir, LIDS["alpha"])
        marker = read_json(g / "first-seen.json")
        self.assertEqual((marker["first_seen_ts"], marker["adopted_from"]),
                         ("2026-01-01T00:00:00Z", "approval.json"))
        self.assertIsNone(self.held())
        write_request(self.cfg, "alpha", "00000004", to=[addr("bravo")], body_text="after")
        self.poll()
        self.assertIn("after", self.bodies())

    def test_the_adopted_generation_records_first_sight_taken(self):
        """So a later loss of its marker holds instead of re-snapshotting,
        even when nothing else in the generation would show it is not new."""
        self.poll()
        self.to_legacy()
        for n in ("results", "pending", "inflight", "quarantine", "held"):
            shutil.rmtree(self.lid() / n, ignore_errors=True)
        self.migrate()
        g = gen_state(self.state_dir, LIDS["alpha"])
        self.assertEqual((g / "first-sight.taken").read_text(),
                         self.journal()["first_seen"]["first_seen_ts"])
        (g / "first-seen.json").unlink()
        self.assertFalse(generations._is_fresh(g), "the adopted generation reads as fresh")


class ReviewWitnessTests(_Legacy):

    def test_a_crash_after_the_generations_file_before_the_line_resumes(self):
        self.poll()
        self.to_legacy()
        with mock.patch.object(audit_mod, "append_bytes", side_effect=OSError(5, "crash")):
            self.refuse()
        self.assertTrue((self.lid() / generations.GEN_FILE).is_file())
        self.assertEqual(self.journal()["phase"], "complete")
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
        self.migrate()
        self.assertEqual(generations.migration_state(self.state_dir, LIDS["alpha"], audit=True),
                         "done")

    def test_a_crash_part_way_through_conversion_resumes_without_misattributing(self):
        self.make_pending(body="one")
        write_request(self.cfg, "alpha", "00000003", to=[addr("bravo")], body_text="two")
        self.poll()
        self.to_legacy()
        for req in (REQ, "00000003"):
            self.to_v1(req)
        real = outbound.convert_v1_pending
        calls = []

        def convert(view, name, req_id):
            calls.append(req_id)
            if len(calls) == 2:
                raise Crash("part-way")
            return real(view, name, req_id)
        with mock.patch.object(outbound, "convert_v1_pending", convert):
            self.expect(Crash, self.migrate)
        self.assertEqual(self.journal().get("converted"),
                         {REQ: outbound.CONVERTED, "00000003": generations.CONVERTING})
        self.migrate()
        self.assertEqual(self.journal()["converted"],
                         {REQ: outbound.CONVERTED, "00000003": outbound.CONVERTED})


class MarkerSnapshotTests(_Legacy):
    """A marker adopt can stand on carries a list `outbox_snapshot`, as
    first sight requires; otherwise the adopted generation could never
    drain, so adopt refuses and points to fence-legacy (review round 2)."""

    def approval_only(self, **snapshot):
        self.poll()
        self.to_legacy()
        m = json.loads((self.lid() / "first-seen.json").read_text())
        (self.lid() / "first-seen.json").unlink()
        (self.lid() / "approval.json").write_text(json.dumps(
            {"approved_ts": "2026-01-01T00:00:00Z", "declared_root": m["declared_root"],
             **snapshot}))

    def test_an_approval_without_a_snapshot_refuses(self):
        self.approval_only()
        self.assertIn("fence-legacy", str(self.refuse()))
        self.migrate("fence-legacy")

    def test_an_approval_with_a_snapshot_that_is_not_a_list_refuses(self):
        self.approval_only(outbox_snapshot="garbage")
        self.assertIn("fence-legacy", str(self.refuse()))

    def test_a_first_seen_marker_without_a_snapshot_refuses(self):
        self.poll()
        self.to_legacy()
        f = self.lid() / "first-seen.json"
        doc = json.loads(f.read_text())
        doc.pop("outbox_snapshot")
        f.write_text(json.dumps(doc))
        self.assertIn("fence-legacy", str(self.refuse()))


class ConversionIntentTests(_Legacy):

    def test_a_crash_after_a_conversion_before_its_outcome_is_recorded(self):
        self.make_pending(body="one")
        self.to_legacy()
        self.to_v1()
        real = outbound.convert_v1_pending

        def convert(view, name, req_id):
            real(view, name, req_id)
            raise Crash("after the record changed, before its outcome was journaled")
        with mock.patch.object(outbound, "convert_v1_pending", convert):
            self.expect(Crash, self.migrate)
        self.assertEqual(self.journal().get("converted"), {REQ: generations.CONVERTING})
        self.migrate()
        self.assertEqual(self.journal()["converted"], {REQ: outbound.CONVERTED})


class SchemaRoundThreeTests(_Legacy):
    """Decision fields bound to what they decide (review round 3)."""

    def write_raw(self, j):
        generations.journal_path(self.state_dir, LIDS["alpha"]).write_text(json.dumps(j))

    def planned(self, approval_only=False):
        self.poll()
        self.to_legacy()
        if approval_only:
            m = json.loads((self.lid() / "first-seen.json").read_text())
            (self.lid() / "first-seen.json").unlink()
            (self.lid() / "approval.json").write_text(json.dumps(
                {"approved_ts": "2026-01-01T00:00:00Z", "declared_root": m["declared_root"],
                 "outbox_snapshot": []}))
        with mock.patch.object(generations, "_move_paths", side_effect=Crash("after plan")):
            self.expect(Crash, self.migrate)
        return self.journal()

    def refused_by_reader(self, j, why):
        self.write_raw(j)
        e = self.expect(generations.GenerationHeld, generations.read_journal,
                        self.state_dir, LIDS["alpha"])
        self.assertIn(why, str(e))

    def test_a_digested_file_must_carry_its_digest(self):
        j = self.planned()
        next(p for p in j["paths"] if p["name"] == "first-seen.json").pop("digest")
        self.refused_by_reader(j, "digest is planned exactly")

    def test_a_planned_marker_must_mean_the_journals_first_sight(self):
        j = self.planned(approval_only=True)
        text = json.dumps({"broken": True})
        j["first_sight"]["marker"] = {"text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        self.refused_by_reader(j, "first sight")

    def test_a_planned_marker_must_be_the_one_the_approval_makes(self):
        j = self.planned(approval_only=True)
        doc = json.loads(j["first_sight"]["marker"]["text"])
        doc["extra"] = "not from the approval"
        text = json.dumps(doc, sort_keys=True)
        j["first_sight"]["marker"] = {"text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        self.write_raw(j)
        self.assertIn("approval makes", str(self.refuse()))

    def pending_v1_stopped_before_conversion(self):
        self.make_pending()
        self.to_legacy()
        self.to_v1()
        with mock.patch.object(generations, "_convert_pending", side_effect=Crash("before")):
            self.expect(Crash, self.migrate)
        return self.journal()

    def test_a_forged_outcome_is_checked_against_the_record(self):
        j = self.pending_v1_stopped_before_conversion()
        j["converted"] = {REQ: outbound.CONVERTED}
        self.write_raw(j)
        self.assertIn("does not show it", str(self.refuse()))

    def test_outcomes_are_a_closed_vocabulary(self):
        j = self.pending_v1_stopped_before_conversion()
        j["converted"] = {REQ: "whatever"}
        self.refused_by_reader(j, "converted")

    def test_an_undecided_conversion_past_its_phase_is_refused(self):
        j = self.pending_v1_stopped_before_conversion()
        j["converted"] = {REQ: generations.CONVERTING}
        j["phase"] = "converted"
        self.refused_by_reader(j, "undecided")

    def test_every_pending_record_needs_an_outcome_before_complete(self):
        self.make_pending()
        self.to_legacy()
        self.to_v1()
        real = generations._advance

        def advance(cfg, journal, phase):
            real(cfg, journal, phase)
            if phase == "converted":
                raise Crash(phase)
        with mock.patch.object(generations, "_advance", advance):
            self.expect(Crash, self.migrate)
        j = self.journal()
        j["converted"] = {}
        self.write_raw(j)
        self.assertIn("no conversion outcome", str(self.refuse()))

    def test_the_planned_line_needs_a_timestamp(self):
        self.poll()
        self.to_legacy()
        with mock.patch.object(generations, "commit_audit", side_effect=OSError(5, "crash")):
            self.refuse()
        j = self.journal()
        line = json.loads(j["audit_line"])
        line["ts"] = None
        j["audit_line"] = json.dumps(line, sort_keys=True) + "\n"
        self.refused_by_reader(j, "carry the journal")

    def test_a_bool_root_identity_is_refused(self):
        j = self.planned()
        j["source"]["root"]["st_dev"] = True
        self.refused_by_reader(j, "source root")

    def test_manifest_lines_are_canonical(self):
        j = self.planned()
        j["manifest"] = ["not a canonical line"]
        j["legacy"].update(local=1, basis="counter",
                           manifest_sha256=generations.manifest_digest(j["manifest"]))
        self.refused_by_reader(j, "manifest")


class CompleteResumeTests(_Legacy):

    def test_a_resume_at_complete_re_verifies_the_conversions(self):
        """Stopped just after `complete`, the converted record rewritten
        back to version 1, then resumed: refused, naming the record."""
        self.make_pending()
        self.to_legacy()
        self.to_v1()
        real = generations._advance

        def advance(cfg, journal, phase):
            real(cfg, journal, phase)
            if phase == "complete":
                raise Crash(phase)
        with mock.patch.object(generations, "_advance", advance):
            self.expect(Crash, self.migrate)
        self.assertEqual(self.journal()["converted"], {REQ: outbound.CONVERTED})
        g = generations.gen_dir(self.state_dir, LIDS["alpha"], self.journal()["gen"])
        self.to_v1(d=g / outbound.PENDING_DIR)
        e = self.refuse()
        self.assertIn(REQ, str(e))
        self.assertEqual(self.journal()["phase"], "complete")
        self.assertEqual(self.held(), generations.HELD_LAYOUT_CONFLICT)
