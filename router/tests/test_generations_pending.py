"""Pending snapshots and fenced generations (`router/outbound.py`, PENDING
SNAPSHOTS and `_drain_fenced`; `router/generations.py`).

Each test pins one rule; `router/tests/mutate_generations_pending.py` breaks
each rule in the source and names the test that must go red.
"""
from __future__ import annotations

import json
import os
import shutil
from unittest import mock

from router import generations, outbound, registry
from router.tests.helpers import (
    gen_state, keyed_for_poll, list_notices, read_json, result_path, write_request,
)
from router.tests.peer_helpers import addr
from router.tests.test_generations import LIDS, _Gens, snapshot
from router.tests.test_inflight import EXT, FakeTransport, _external


class _Pending(_Gens):

    def hold_bravo(self):
        """bravo leaves the registry: deliveries to it hold."""
        self.seq += 1
        doc = snapshot(self.seq)
        doc["entries"] = [e for e in doc["entries"] if e["name"] != "bravo"]
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(doc))

    def release_bravo(self, **overrides):
        self.put(**overrides)

    def pending_dir(self, name="alpha"):
        return gen_state(self.state_dir, LIDS[name]) / outbound.PENDING_DIR

    def record(self, req_id="00000001", gen_dir=None):
        d = (gen_dir / outbound.PENDING_DIR) if gen_dir is not None else self.pending_dir()
        path = d / f"{req_id}.json"
        self.assertTrue(path.is_file(), "the pending record is gone")
        return json.loads(path.read_text())

    def listing(self, d=None):
        d = d if d is not None else self.pending_dir()
        return sorted(p.name for p in d.iterdir()) if d.is_dir() else []

    def make_pending(self, body="original"):
        self.hold_bravo()
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text=body)
        self.poll()
        self.assertTrue((self.pending_dir() / "00000001.json").is_file(), "no pending record")

    def bodies(self, name="bravo"):
        inbox = self.cfg.instances[name].inbox_root / "messages"
        return [json.loads((inbox / n).read_text())["body_text"] for n in list_notices(self.cfg, name)]


# ---------------------------------------------------------------------------
# The snapshot
# ---------------------------------------------------------------------------

class SnapshotTests(_Pending):

    def test_a_pending_record_names_a_durable_snapshot_of_the_raw_request(self):
        self.make_pending()
        rec = self.record()
        self.assertEqual(rec["v"], 2)
        snap = self.pending_dir() / f"00000001.{rec['snapshot']['nonce']}.snap"
        raw = (snap / "request").read_bytes()
        live = (self.cfg.instances["alpha"].outbox_root / "req-00000001.json").read_bytes()
        self.assertEqual(raw, live)
        self.assertEqual(rec["from_address"], addr("alpha"))
        self.assertEqual(rec["source_gen"], self.cur())

    def test_the_snapshot_is_written_before_the_record(self):
        """A crash writing the record leaves an orphan snapshot and no record:
        nothing is placed, the next poll begins again under a NEW nonce, and
        the orphan is never adopted; once answered, the sweep removes it."""
        self.hold_bravo()
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        with mock.patch.object(outbound, "_write_pending", side_effect=OSError(5, "crash")):
            self.poll()
        orphans = [n for n in self.listing() if n.endswith(".snap")]
        self.assertEqual(len(orphans), 1, "the snapshot was not written first")
        self.assertFalse((self.pending_dir() / "00000001.json").exists())
        self.poll()
        nonce = self.record()["snapshot"]["nonce"]
        self.assertNotIn(f"00000001.{nonce}.snap", orphans)
        self.release_bravo()
        self.poll()
        self.poll()
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")
        self.assertEqual(self.listing(), [], "the orphan snapshot survived the answer")

    def test_a_damaged_snapshot_holds_and_places_nothing(self):
        self.make_pending()
        rec = self.record()
        snap = self.pending_dir() / f"00000001.{rec['snapshot']['nonce']}.snap"
        (snap / "request").write_bytes(b'{"tampered": true}')
        self.release_bravo()
        self.poll()
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        self.assertEqual(self.record()["block"], outbound.BLOCK_SNAPSHOT_DAMAGED)

    def test_a_vanished_live_entry_continues_from_the_snapshot(self):
        self.make_pending(body="kept")
        (self.cfg.instances["alpha"].outbox_root / "req-00000001.json").unlink()
        self.release_bravo()
        self.poll()
        self.assertEqual(self.bodies(), ["kept"])
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")

    def test_completion_removes_record_then_snapshot(self):
        """The record goes before its snapshot; a crash between them leaves
        an orphan snapshot that the sweep removes because the anchor exists."""
        self.make_pending()
        self.release_bravo()
        real = outbound._remove_snapshot
        with mock.patch.object(outbound, "_remove_snapshot", side_effect=OSError(5, "crash")):
            self.poll()
        self.assertFalse((self.pending_dir() / "00000001.json").exists())
        self.assertEqual(len(self.listing()), 1)
        self.assertIs(outbound._remove_snapshot, real)
        self.poll()
        self.assertEqual(self.listing(), [])

    def test_a_changed_live_entry_is_audited_held_then_refused(self):
        self.make_pending()
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="CHANGED")
        self.poll()     # bravo still held: the old work cannot settle, the new file is held
        self.release_bravo()
        self.poll()     # the old work settles privately
        self.poll()     # the changed file is refused
        log = (self.state_dir / LIDS["alpha"] / "audit" / "log.jsonl").read_text().splitlines()
        states = [json.loads(l)["state"] for l in log
                  if json.loads(l)["event"] == "req_id_reused_pending"]
        self.assertEqual(states, ["held", "refused"])


# ---------------------------------------------------------------------------
# Fenced generations
# ---------------------------------------------------------------------------

class FencedTests(_Pending):

    def test_a_fenced_pending_request_completes_and_is_answered_at_the_same_root(self):
        """A rebind at the same root fences the generation; its pending work
        replays from the snapshot when the recipient resolves, and since the
        root and the live file are unchanged its Result is published. The new
        generation's first sight does NOT quarantine that file (it is the old
        generation's, already handed over)."""
        self.make_pending(body="from the old generation")
        old = gen_state(self.state_dir, LIDS["alpha"])
        self.put(alpha={"binding_seq": 9}, bravo={})     # rebind alpha; bravo back
        self.poll()
        self.assertNotEqual(gen_state(self.state_dir, LIDS["alpha"]), old)
        self.assertEqual(self.bodies(), ["from the old generation"])
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual((r["outcome"], r["reason_code"]), ("accepted", "allowlisted"))
        self.assertTrue((old / "results" / "00000001.json").is_file(), "answered outside its gen")
        self.assertFalse((old / outbound.PENDING_DIR / "00000001.json").exists())

    def test_a_fenced_generation_with_a_replaced_root_settles_privately(self):
        self.make_pending(body="old root")
        old = gen_state(self.state_dir, LIDS["alpha"])
        self.replace_root("alpha")
        self.release_bravo()
        self.poll()
        self.poll()
        self.assertEqual(self.bodies(), ["old root"])
        self.assertTrue((old / "results" / "00000001.json").is_file())
        self.assertFalse((old / outbound.PENDING_DIR / "00000001.json").exists(),
                         "the fenced work did not settle (privately)")
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual(r["reason_code"], outbound.REASON_QUARANTINED,
                         "the old generation published into the new root")

    def test_a_fenced_version_1_record_holds(self):
        self.make_pending()
        path = self.pending_dir() / "00000001.json"
        rec = json.loads(path.read_text())
        rec["v"] = 1
        for k in ("snapshot", "source_gen", "from_address"):
            rec.pop(k)
        path.write_text(json.dumps(rec))
        old = gen_state(self.state_dir, LIDS["alpha"])
        self.put(alpha={"binding_seq": 9})
        self.hold_bravo()
        self.release_bravo(alpha={"binding_seq": 9})
        self.poll()
        self.assertEqual(self.record(gen_dir=old)["block"], outbound.BLOCK_LEGACY_SNAPSHOT_MISSING)
        self.assertEqual(list_notices(self.cfg, "bravo"), [])

    def test_a_fenced_in_flight_record_settles_under_its_own_id(self):
        port = FakeTransport()
        write_request(self.cfg, "alpha", "00000001", to=[EXT])
        k = keyed_for_poll(self.cfg)
        outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
        old = gen_state(self.state_dir, LIDS["alpha"])
        generations.operator_new(self.cfg, "alpha", "counter reset")
        new = gen_state(self.state_dir, LIDS["alpha"])
        k = keyed_for_poll(self.cfg)       # the new generation's first sight, work unsettled
        outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "the fenced in-flight request was answered by the new generation")
        self.assertEqual(port.writes, ["00000001"], "drained again by the new generation")
        port.send_all()
        k = keyed_for_poll(self.cfg)
        outbound.drain_instance(k, "alpha", transport=port, cold_policy=_external)
        self.assertEqual(port.writes, ["00000001"], "the fenced record was handed over again")
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual(r["outcome"], "accepted", "the in-flight request was quarantined (C1)")
        self.assertTrue((old / "results" / "00000001.json").is_file())
        self.assertEqual((new / "transport" / "next_req_id").read_text(), "2")
        self.assertFalse((new / "first-seen.json").read_text().count("req-00000001.json"))


# ---------------------------------------------------------------------------
# The recipient's generation and root
# ---------------------------------------------------------------------------

class RecipientGenerationTests(_Pending):

    def test_a_begun_placement_holds_when_the_recipient_generation_changes(self):
        """`delivering` binds the recipient's generation; a replay after the
        recipient's generation changed holds and places nothing."""
        self.make_pending()
        self.release_bravo()
        k = keyed_for_poll(self.cfg)
        with mock.patch.object(outbound, "_place_target", side_effect=RuntimeError("crash")):
            outbound.drain_instance(k, "alpha")
        t = self.record()["targets"][0]
        self.assertEqual(t["state"], "delivering")
        self.assertEqual(t.get("recipient_gen"), self.cur("bravo"))
        self.put(bravo={"binding_seq": 7})               # bravo rebinds: a new generation
        self.poll()
        t = self.record()["targets"][0]
        self.assertEqual(t.get("reason"), outbound.HOLD_RECIPIENT_GENERATION_CHANGED)
        self.assertEqual(list_notices(self.cfg, "bravo"), [])

    def test_a_root_swapped_mid_pass_goes_pending_not_failed(self):
        """A recipient root swapped between the hold check and its write:
        the request goes pending (the recipients already done recorded as
        done) instead of ending delivery_failed, and completes next poll."""
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        k = keyed_for_poll(self.cfg)
        self.replace_root("bravo")
        # Only the up-front check misses the swap (the race): delivery's own
        # gate then sees it.
        with mock.patch.object(outbound, "_any_held", lambda cfg, recipients: False):
            outbound.drain_instance(k, "alpha")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "answered delivery_failed instead of going pending")
        self.assertTrue((self.pending_dir() / "00000001.json").is_file())
        self.poll()
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)


class PinnedListingTests(_Pending):
    """The listing and first sight reach the outbox as the reads do."""

    def symlink_outbox(self):
        outbox = self.cfg.instances["alpha"].outbox_root
        elsewhere = self.tmp / "elsewhere"
        shutil.move(str(outbox), str(elsewhere))
        os.symlink(str(elsewhere), str(outbox))
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])   # lands elsewhere
        return elsewhere

    def test_a_symlinked_outbound_lists_nothing(self):
        self.symlink_outbox()
        k = keyed_for_poll(self.cfg)
        self.assertEqual(outbound.list_outbound(k, "alpha"), ([], 0))

    def test_first_sight_is_never_taken_through_a_symlinked_outbound(self):
        from router import firstsight
        shutil.rmtree(self.state_dir / LIDS["alpha"])
        self.symlink_outbox()
        k = keyed_for_poll(self.cfg)
        try:
            firstsight.record_first_sight(k, "alpha")
            raised = None
        except Exception as e:  # noqa: BLE001
            raised = e
        self.assertIsInstance(raised, firstsight.FirstSightError,
                              "first sight was taken through a symlinked outbound")
        self.assertFalse((gen_state(self.state_dir, LIDS["alpha"]) / "first-seen.json").exists())

    def test_registry_mode_without_proc_holds(self):
        """The pinning needs /proc/self/fd: without it the drain holds with a
        clear reason instead of failing on an obscure path."""
        k = keyed_for_poll(self.cfg)
        real = os.path.isdir
        with mock.patch.object(outbound.os.path, "isdir",
                               lambda p: False if str(p).startswith("/proc/self/fd") else real(p)):
            with self.assertRaises(generations.GenerationHeld) as cm:
                outbound.drain_instance(k, "alpha")
        self.assertEqual(cm.exception.reason, generations.HELD_CONNECTOR_UNVERIFIED)
        self.assertIn("/proc", str(cm.exception))
