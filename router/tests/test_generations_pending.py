"""Pending snapshots and fenced generations (`router/outbound.py`, PENDING
SNAPSHOTS and `_drain_fenced`; `router/generations.py`).

Each test pins one rule; `router/tests/mutate_generations_pending.py` breaks
each rule in the source and names the test that must go red.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from unittest import mock

from router import deliver as deliver_mod, generations, outbound, registry, service
from router.status import StatusTracker
from router.tests.helpers import (
    attachment_descriptor, stage_outbound_sidecars, gen_state, keyed_for_poll, list_notices, read_json, result_path, write_request,
)
from router.tests.peer_helpers import addr
from router.tests.test_generations import LIDS, _Gens, snapshot
from router.tests.test_inflight import EXT, FakeTransport, _external
from router.util import DEFAULT_READ_CAP


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
        # Settled privately in this poll. A fenced generation that tried to
        # publish into the replaced root fails there, after its anchor, and
        # leaves its record for the next poll's sweep: so this is checked
        # after ONE poll, where only the private settlement has removed it.
        self.assertFalse((old / outbound.PENDING_DIR / "00000001.json").exists(),
                         "the fenced work did not settle (privately) in one poll")
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
        for k in ("snapshot", "source_gen", "from_address", "aliases"):
            rec.pop(k)
        for t in rec["targets"]:
            t.pop("address", None)
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
        # Only the up-front checks miss the swap (the race): delivery's own
        # gate then sees it. The intent record checks too (`target_hold` when
        # it is made, `_hold_reason` before each placement), so all three
        # are the race's blind spot here.
        with mock.patch.object(outbound, "_any_held", lambda cfg, recipients: False), \
                mock.patch.object(outbound, "target_hold", lambda cfg, name: None), \
                mock.patch.object(outbound, "_hold_reason", lambda cfg, target: None):
            outbound.drain_instance(k, "alpha")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "answered delivery_failed instead of going pending")
        self.assertTrue((self.pending_dir() / "00000001.json").is_file())
        self.poll()
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(),
                        "never completed after the hold resolved")
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)


    def test_a_root_swapped_mid_pass_on_a_preset_less_backend_goes_pending(self):
        """The same race through a backend that takes no pre-minted identity,
        which places directly, without an intent record: its held recipient
        goes pending too, never delivery_failed."""
        calls = []

        def preset_less(cfg, state_dir, sender, recipient, doc, attachments=None):
            calls.append(recipient)
            return deliver_mod.deliver(cfg, state_dir, sender, recipient, doc,
                                       attachments=attachments)

        self.assertIsNone(outbound._placement_origin(preset_less),
                          "control: this backend takes no preset")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        k = keyed_for_poll(self.cfg)
        self.replace_root("bravo")
        with mock.patch.object(outbound, "_any_held", lambda cfg, recipients: False):
            outbound.drain_instance(k, "alpha", deliver_backend=preset_less)
        self.assertEqual(calls, ["bravo"], "control: the backend reached the write")
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


def _notice_froms(test, name="bravo"):
    d = test.cfg.instances[name].inbox_root / "notices"
    return [json.loads((d / n).read_text())["message"]["from"] for n in list_notices(test.cfg, name)]


class ReviewRoundTests(_Pending):

    # -- R1: the pinned sender address ------------------------------------------

    def test_replay_sends_from_the_pinned_address_after_a_domain_flip(self):
        """The fleet's domain flips between pin and replay: an address derived
        now would carry the new domain. (Routing the old-domain recipient
        addresses is the alias table's job, a later step; here only the
        sender's derivation sees the flip.)"""
        from router import deliver as deliver_mod
        self.make_pending()
        pinned = self.record()["from_address"]
        real = deliver_mod.address_for
        flipped = lambda n, d=None: real(n, "flipped.example")  # noqa: E731
        self.release_bravo()
        with mock.patch.object(deliver_mod, "address_for", flipped):
            self.poll()
        self.assertEqual(_notice_froms(self), [pinned])

    def test_replay_sends_from_the_pinned_address_after_a_name_override(self):
        """The registry renames the sender between pin and replay: the
        address derived now is not the one the request was accepted under."""
        from router import deliver as deliver_mod
        self.make_pending()
        pinned = self.record()["from_address"]
        real = deliver_mod.address_for
        renamed = lambda n, d=None: real("alpha-renamed" if n == "alpha" else n, d)  # noqa: E731
        self.release_bravo()
        with mock.patch.object(deliver_mod, "address_for", renamed), \
                mock.patch.object(outbound, "address_for", renamed):
            self.poll()
        self.assertEqual(_notice_froms(self), [pinned])

    # -- R2 / R5: fenced ownership is fail-closed ---------------------------------

    def fence_with_pending(self):
        self.make_pending(body="handed over")
        old = gen_state(self.state_dir, LIDS["alpha"])
        self.seq += 1
        doc = snapshot(self.seq, alpha={"binding_seq": 9})
        doc["entries"] = [e for e in doc["entries"] if e["name"] != "bravo"]
        (self.reg / registry.SNAPSHOT).write_text(json.dumps(doc))   # rebind alpha; bravo held
        self.poll()
        self.assertNotEqual(gen_state(self.state_dir, LIDS["alpha"]), old)
        return old

    def test_an_unreadable_generations_file_on_the_second_read_holds_the_drain(self):
        """The root pin reads the generations file; the fenced enumeration
        reads it again and fails. That must hold the drain, never read as
        "no fenced generations": the current generation would deliver the
        fenced-owned file, and the fenced replay deliver it again."""
        self.fence_with_pending()
        self.release_bravo(alpha={"binding_seq": 9})
        real = generations.read_doc

        def second_read_fails(*a, **kw):
            if sys._getframe(1).f_code.co_name == "_fenced_views":
                raise generations.GenerationHeld(generations.HELD_LAYOUT_CONFLICT, "injected")
            return real(*a, **kw)

        with mock.patch.object(generations, "read_doc", second_read_fails):
            self.poll()
        self.assertEqual(self.bodies(), [], "drained past an unreadable enumeration")
        for _ in range(2):
            self.poll()
        self.assertEqual(self.bodies(), ["handed over"], "delivered twice, or not at all")

    def test_a_damaged_fenced_record_keeps_its_file(self):
        old = self.fence_with_pending()
        (old / outbound.PENDING_DIR / "00000001.json").write_text("{damaged")
        self.release_bravo(alpha={"binding_seq": 9})
        self.poll()
        self.assertEqual(list_notices(self.cfg, "bravo"), [], "the current generation took it")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists())

    def test_a_fenced_replay_error_never_releases_its_file(self):
        """A fenced settlement that errors after placing (the anchor write
        fails) keeps its claim: the current generation does not drain the
        same file that poll, so the recipient gets it ONCE."""
        self.fence_with_pending()
        self.release_bravo(alpha={"binding_seq": 9})
        real = outbound._write_anchor
        calls = []

        def fail_once(*a, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise OSError(5, "injected")
            return real(*a, **kw)
        new = gen_state(self.state_dir, LIDS["alpha"])
        with mock.patch.object(outbound, "_write_anchor", fail_once):
            self.poll()
        self.poll()
        self.assertEqual(self.bodies(), ["handed over"], "delivered twice, or not at all")
        self.assertFalse((new / "results" / "00000001.json").exists(),
                         "the current generation answered the fenced generation's request")
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(), "never answered")
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")

    def test_a_fenced_replay_error_keeps_the_file_out_of_first_sight(self):
        old = self.fence_with_pending()
        new = gen_state(self.state_dir, LIDS["alpha"])
        (new / "first-seen.json").unlink()
        (new / "first-sight.taken").unlink()
        self.release_bravo(alpha={"binding_seq": 9})
        with mock.patch.object(outbound, "_write_anchor", side_effect=OSError(5, "injected")):
            self.poll()
        path = new / "first-seen.json"
        marker = json.loads(path.read_text()) if path.exists() else {"outbox_snapshot": []}
        self.assertNotIn("req-00000001.json",
                         [e.get("filename") for e in marker["outbox_snapshot"]])
        self.assertFalse((new / "results" / "00000001.json").exists())
        self.assertTrue((old / outbound.PENDING_DIR / "00000001.json").exists())

    def test_a_fenced_in_flight_record_settled_but_not_archived_is_completed_once(self):
        """The in-flight twin: the anchor is written, the publish fails, the
        record is cleaned up next poll. The fenced verdict is still completed
        (published, archived) and the current generation never drains it."""
        port = FakeTransport()
        write_request(self.cfg, "alpha", "00000001", to=[EXT])
        outbound.drain_instance(keyed_for_poll(self.cfg), "alpha", transport=port,
                                cold_policy=_external)
        generations.operator_new(self.cfg, "alpha", "counter reset")
        port.send_all()
        with mock.patch.object(outbound, "_publish_result_and_archive",
                               side_effect=OSError(5, "injected")):
            outbound.drain_instance(keyed_for_poll(self.cfg), "alpha", transport=port,
                                    cold_policy=_external)
        for _ in range(2):
            outbound.drain_instance(keyed_for_poll(self.cfg), "alpha", transport=port,
                                    cold_policy=_external)
        self.assertEqual(port.writes, ["00000001"], "handed over twice")
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(),
                        "the fenced verdict was never completed")
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual(r["outcome"], "accepted")

    # -- R3: crash boundaries --------------------------------------------------------

    def test_a_crash_part_way_through_the_snapshot(self):
        self.hold_bravo()
        data = b"attached bytes"
        stage_outbound_sidecars(self.cfg, "alpha", "00000001", [data])
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")],
                      attachments=[attachment_descriptor(data)])
        real = outbound.atomic_write

        def crash_on_attachment(path, *a, **kw):
            if str(path).endswith("/a0"):
                raise OSError(5, "crash")
            return real(path, *a, **kw)
        with mock.patch.object(outbound, "atomic_write", crash_on_attachment):
            self.poll()
        self.assertFalse((self.pending_dir() / "00000001.json").exists())
        self.release_bravo()
        self.poll()
        self.poll()
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)
        self.assertEqual(self.listing(), [], "the partial snapshot survived")

    def test_a_crash_after_the_anchor_before_the_record_is_removed(self):
        self.make_pending()
        self.release_bravo()
        with mock.patch.object(outbound, "_remove_pending", side_effect=OSError(5, "crash")):
            self.poll()
        self.poll()
        self.assertEqual(len(list_notices(self.cfg, "bravo")), 1)
        self.assertEqual(self.listing(), [])

    # -- R4: a transient fault decides nothing --------------------------------------------

    def transient(self, code):
        import errno as errno_mod
        real = outbound._read_request_pinned

        def fault(cfg, name, filename, *a, **kw):
            if name == "alpha" and filename == "req-00000001.json":
                raise OSError(code, os.strerror(code))
            return real(cfg, name, filename, *a, **kw)
        return mock.patch.object(outbound, "_read_request_pinned", fault)

    def assert_nothing_decided(self, gen_dir):
        self.assertEqual(list_notices(self.cfg, "bravo"), [])
        self.assertFalse((gen_dir / "results" / "00000001.json").exists())
        self.assertFalse((gen_dir / "reuse-pending").exists(), "a reuse was recorded")

    def test_a_transient_fault_on_the_live_read_decides_nothing(self):
        import errno as errno_mod
        for code in (errno_mod.EIO, errno_mod.EACCES, errno_mod.EMFILE):
            for fenced in (False, True):
                with self.subTest(errno=errno_mod.errorcode[code], fenced=fenced):
                    self.setUp()
                    if fenced:
                        gdir = self.fence_with_pending()
                        self.release_bravo(alpha={"binding_seq": 9})
                    else:
                        self.make_pending()
                        gdir = gen_state(self.state_dir, LIDS["alpha"])
                        self.release_bravo()
                    with self.transient(code):
                        self.poll()
                    self.assert_nothing_decided(gdir)
                    self.poll()
                    self.assertEqual(self.bodies(), ["handed over" if fenced else "original"])


class DigestlessAnchorTests(_Pending):
    """A fenced anchor with no digest (its original was too large to read)
    owns the live file only while that file still cannot be read."""

    def settle_oversized(self, publish=True):
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")])
        live = self.cfg.instances["alpha"].outbox_root / "req-00000001.json"
        live.write_bytes(b"{" + b" " * (DEFAULT_READ_CAP + 1) + b"}")
        if publish:
            self.poll()
        else:
            with mock.patch.object(outbound, "_publish_result_and_archive",
                                   side_effect=OSError(5, "injected")):
                self.poll()
        old = gen_state(self.state_dir, LIDS["alpha"])
        anchor = old / "results" / "00000001.json"
        self.assertTrue(anchor.is_file(), "precondition: no anchor")
        self.assertIsNone(json.loads(anchor.read_text()).get("digest", "missing"),
                          "precondition: an anchor with no digest")
        generations.operator_new(self.cfg, "alpha", "connector reset")
        self.assertNotEqual(gen_state(self.state_dir, LIDS["alpha"]), old)
        return old, live

    def test_a_readable_reuse_under_a_fenced_digestless_anchor_is_answered(self):
        """The id is reused after a connector reset: the readable file is a
        new request, the current generation's to answer."""
        self.settle_oversized()
        self.poll()
        for sub in ("results", "processed"):
            shutil.rmtree(self.cfg.instances["alpha"].outbox_root / sub, ignore_errors=True)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="new")
        for _ in range(3):
            self.poll()
        self.assertEqual(self.bodies(), ["new"], "the reused id was never delivered")
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(), "never answered")
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")

    def test_a_still_oversized_file_is_completed_by_the_fenced_verdict(self):
        old, live = self.settle_oversized(publish=False)
        for _ in range(2):
            self.poll()
        new = gen_state(self.state_dir, LIDS["alpha"])
        self.assertFalse((new / "results" / "00000001.json").exists(),
                         "the current generation answered it")
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(),
                        "the fenced verdict was never completed")
        r = read_json(result_path(self.cfg, "alpha", "00000001"))
        self.assertEqual(r.get("reason_code"), "malformed_request")
        self.assertFalse(live.exists(), "never archived")
        self.assertEqual(list_notices(self.cfg, "bravo"), [])

    def test_a_damaged_fenced_anchor_keeps_its_file(self):
        old, live = self.settle_oversized(publish=False)
        (old / "results" / "00000001.json").write_text("{damaged")
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="new")
        for _ in range(2):
            self.poll()
        new = gen_state(self.state_dir, LIDS["alpha"])
        self.assertEqual(list_notices(self.cfg, "bravo"), [], "the current generation took it")
        self.assertFalse((new / "results" / "00000001.json").exists())
        self.assertTrue(live.exists())

    def test_a_damaged_fenced_anchor_is_shown_in_status_with_its_age(self):
        old, live = self.settle_oversized(publish=False)
        (old / "results" / "00000001.json").write_text("{damaged")
        tracker = StatusTracker(interval_s=5.0)
        service.poll_once(self.cfg, tracker, None)
        doc = (tracker.to_doc().get("generations") or {}).get("alpha") or {}
        shown = doc.get("fenced_damaged_anchors")
        self.assertIsNotNone(shown, "a damaged anchor holds its file silently")
        gen = old.name[len(generations.GEN_PREFIX):]
        self.assertEqual([e.get("req_id") for e in shown.get(gen, [])], ["00000001"])
        self.assertGreaterEqual(shown[gen][0].get("age_s"), 0)

    def test_a_readable_fenced_anchor_is_not_shown_as_damaged(self):
        self.settle_oversized(publish=False)
        tracker = StatusTracker(interval_s=5.0)
        service.poll_once(self.cfg, tracker, None)
        doc = (tracker.to_doc().get("generations") or {}).get("alpha") or {}
        self.assertIn("generation", doc, "precondition: no generations section")
        self.assertNotIn("fenced_damaged_anchors", doc)

    # -- transient faults and a vanished generations file fail closed -------

    def fenced_fault(self):
        """EIO on the live read, but only inside the fenced claim and
        completion scans: the current generation reads normally."""
        real = outbound._read_request_pinned

        def fault(cfg, name, filename, *a, **kw):
            f = sys._getframe(1)
            while f is not None:
                if f.f_code.co_name in ("_fenced_claims", "_settled_unarchived"):
                    raise OSError(5, "injected")
                f = f.f_back
            return real(cfg, name, filename, *a, **kw)
        return mock.patch.object(outbound, "_read_request_pinned", fault)

    def test_a_transient_fault_checking_a_fenced_anchor_keeps_its_claim(self):
        """A fenced verdict whose archive failed: a fault while checking its
        claim keeps the file from the current generation, and the next poll
        completes the fenced verdict."""
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="once")
        with mock.patch.object(outbound, "_publish_result_and_archive",
                               side_effect=OSError(5, "injected")):
            self.poll()
        # The failure after the anchor leaves the request's intent record
        # beside it; the next drain's sweep removes it. Swept here, so the
        # fenced generation holds the anchor ALONE, which is what this tests:
        # a record would claim the file without reading it.
        outbound._sweep_answered_pending(keyed_for_poll(self.cfg), "alpha")
        generations.operator_new(self.cfg, "alpha", "connector reset")
        new = gen_state(self.state_dir, LIDS["alpha"])
        with self.fenced_fault():
            self.poll()
        self.assertFalse((new / "results" / "00000001.json").exists(),
                         "the current generation answered a request the fenced one had")
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists())
        self.poll()
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(), "never completed")
        self.assertEqual(read_json(result_path(self.cfg, "alpha", "00000001"))["outcome"],
                         "accepted")
        self.assertEqual(self.bodies(), ["once"])

    def test_a_fenced_answered_record_is_swept_never_replayed(self):
        """A failure after the anchor leaves the request's intent record
        beside it, and here the generation is fenced before any drain sweeps
        it. The fenced work removes the answered record instead of replaying
        it, so the verdict is completed only by the guarded completion step:
        with that step's read faulting, nothing is published this poll."""
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="once")
        with mock.patch.object(outbound, "_publish_result_and_archive",
                               side_effect=OSError(5, "injected")):
            self.poll()
        generations.operator_new(self.cfg, "alpha", "connector reset")
        old = sorted(p for p in (self.state_dir / LIDS["alpha"]).glob("gen-*")
                     if p != gen_state(self.state_dir, LIDS["alpha"]))
        self.assertTrue(any((g / outbound.PENDING_DIR / "00000001.json").is_file() for g in old),
                        "control: the fenced generation holds the record beside its anchor")
        with self.fenced_fault():
            self.poll()
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "the fenced record was replayed past the guarded completion")
        self.assertFalse(any((g / outbound.PENDING_DIR / "00000001.json").exists() for g in old),
                         "the answered record was not swept")
        self.poll()
        self.assertTrue(result_path(self.cfg, "alpha", "00000001").exists(), "never completed")
        self.assertEqual(self.bodies(), ["once"])

    def test_a_transient_fault_under_a_digestless_anchor_publishes_nothing(self):
        """A readable request reused under a fenced digest-less anchor: a
        fault reading it is not "still the original", so the old verdict is
        never published over it."""
        old, live = self.settle_oversized(publish=False)
        write_request(self.cfg, "alpha", "00000001", to=[addr("bravo")], body_text="new")
        with self.fenced_fault():
            self.poll()
        self.assertFalse(result_path(self.cfg, "alpha", "00000001").exists(),
                         "a verdict was published on a transient fault")
        self.assertTrue(live.exists(), "archived on a transient fault")
        self.assertEqual(list_notices(self.cfg, "bravo"), [])

    def test_a_vanished_generations_file_on_the_second_read_holds_the_drain(self):
        """As an unreadable one: missing during the drain is never "no
        fenced generations"."""
        old, live = self.settle_oversized(publish=False)
        real = generations.read_doc

        def second_read_gone(*a, **kw):
            if sys._getframe(1).f_code.co_name == "_fenced_views":
                return None
            return real(*a, **kw)

        with mock.patch.object(generations, "read_doc", second_read_gone):
            self.poll()
        new = gen_state(self.state_dir, LIDS["alpha"])
        self.assertFalse((new / "results" / "00000001.json").exists(),
                         "drained past a vanished generations file")
        self.assertFalse((new / "first-seen.json").exists(),
                         "first sight taken past a vanished generations file")
        self.assertTrue(live.exists())
