"""ALPHA-2 W10, A2-15 / S10: `router peer-evidence` (design r3 §5.3-§5.4,
§5.6), on the REAL two-router round trip of `test_inbound_e2e` -- each router
loaded by `config.load`, polled through `service.run_once`, signing with the
stand-in codec, the hub emulated -- and read back through the CLI.

The S10 proof is four exact lookups (`s10` below). Every negative case is a
real record on disk made wrong in one named way, or a second real record
that a non-exact selector would pick up.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
from unittest import mock

from router import __main__ as cli
from router import hoplink, peerbind, peerjournal, peerresend
from router.tests import test_inbound_e2e as e2e
from router.tests.helpers import write_request

A_RT = e2e.A_D.split(".")[0]          # how B's config names A's runtime
B_RT = e2e.B_D.split(".")[0]          # how A's config names B's runtime


def run(host, *argv):
    """The CLI's rc, its one stdout object (or the raw lines), and stderr. A
    crash is reported as rc 99, so a wrong path FAILS a test, never errors it."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(cli, "load", lambda path: host.cfg), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(["--config", "unused", "peer-evidence", *argv])
        except Exception as e:  # noqa: BLE001
            return 99, [f"{type(e).__name__}: {e}"], err.getvalue()
    lines = out.getvalue().splitlines()
    return code, (json.loads(lines[0]) if len(lines) == 1 else lines), err.getvalue()


def ev(host, *argv):
    code, doc, err = run(host, *argv)
    assert (code, err) == (0, ""), (code, err)
    return doc


def s10(a, b, q, *, not_before=None):
    """Design r3 §5.4, verbatim, as DS's check would run it. Returns
    ("PASS", T, R) or (verdict, step, detail)."""
    nb = ["--not-before", not_before] if not_before else []
    steps = [
        ("1", a, ["sent", "--instance", a.name, "--req-id", q, *nb]),
    ]
    d1 = ev(a, *steps[0][2])
    if not d1["complete"]:
        return ("UNKNOWN", "1", d1["problems"])
    if d1["found"] != "one" or d1["record"]["kind"] != "task" or not d1["record"]["handed_ts"]:
        return ("FAIL", "1", d1["found"])
    t, sha_t = d1["record"]["id"], d1["record"]["statement_sha256"]
    d2 = ev(b, "verified", "--runtime", A_RT, "--id", t)
    if not d2["complete"]:
        return ("UNKNOWN", "2", d2["problems"])
    if d2["found"] != "one" or (d2["record"]["statement_sha256"], d2["record"]["state"],
                                d2["record"]["disposition"]) != (sha_t, "done", "placed"):
        return ("FAIL", "2", d2["found"])
    d3 = ev(b, "sent", "--instance", b.name, "--in-reply-to", t)
    if not d3["complete"]:
        return ("UNKNOWN", "3", d3["problems"])
    if d3["found"] != "one" or (d3["record"]["kind"], d3["record"]["in_reply_to"]) != ("result", t) \
            or not d3["record"]["handed_ts"]:
        return ("FAIL", "3", d3["found"])
    r, sha_r = d3["record"]["id"], d3["record"]["statement_sha256"]
    d4 = ev(a, "verified", "--runtime", B_RT, "--id", r)
    if not d4["complete"]:
        return ("UNKNOWN", "4", d4["problems"])
    if d4["found"] != "one" or (d4["record"]["statement_sha256"], d4["record"]["state"],
                                d4["record"]["disposition"]) != (sha_r, "done", "placed"):
        return ("FAIL", "4", d4["found"])
    return ("PASS", t, r)


class _RoundTrip(e2e._TwoHosts):

    def flow(self, *, extra_task=False, second_answer=False, b_task=False):
        """The e2e round trip: A's request 00000001 to B, placed, answered,
        delivered back. Optionally a second, unrelated task from A in the same
        window (00000002), and a second answer from B to the same task."""
        self.started()
        self.hub = hub = e2e._Hub()
        write_request(self.a.cfg, "planner", "00000001", to=[self.b.address],
                      subject="Run the suite", body_text="Please run the suite.\n")
        if extra_task:
            write_request(self.a.cfg, "planner", "00000002", to=[self.b.address],
                          subject="Unrelated", body_text="Something else.\n")
        self.a.poll()
        hub.carry(self.a, self.b, self.b.address)
        self.b.poll()
        placed = [n for n in e2e._notices(self.b)
                  if n["message"]["subject"] == "Run the suite"]
        self.task_id = placed[0]["message"]["id"]
        write_request(self.b.cfg, "builder", "00000001", to=[self.a.address],
                      subject="Re: Run the suite", body_text="Done: 112 passed.\n",
                      in_reply_to=self.task_id)
        if b_task:
            write_request(self.b.cfg, "builder", "00000003", to=[self.a.address],
                          subject="Unrelated from B", body_text="Please lint.\n")
        if second_answer:
            write_request(self.b.cfg, "builder", "00000002", to=[self.a.address],
                          subject="Re: Run the suite", body_text="Also: lint clean.\n",
                          in_reply_to=self.task_id)
        self.b.poll()
        hub.carry(self.b, self.a, self.a.address)
        for _ in range(2):                 # the passes that find the handed markers
            self.a.poll()
            self.b.poll()


class ProofTests(_RoundTrip):

    def test_the_four_steps_prove_the_round_trip(self):
        self.flow()
        verdict = s10(self.a, self.b, "00000001")
        self.assertEqual(verdict[0], "PASS", verdict)
        self.assertEqual(verdict[1], self.task_id)

    def test_selection_is_by_request_id_not_by_quiet(self):
        """A second, unrelated task in the same window: step 1 still selects
        exactly THIS task."""
        self.flow(extra_task=True)
        doc = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001")
        self.assertEqual((doc["found"], doc["complete"]), ("one", True))
        self.assertEqual(doc["record"]["id"], self.task_id)
        self.assertEqual(doc["record"]["req_id"], "00000001")
        self.assertEqual(s10(self.a, self.b, "00000001")[0], "PASS")

    def test_a_task_from_b_is_never_taken_for_its_answer(self):
        self.flow(b_task=True)
        doc = ev(self.b, "sent", "--instance", "builder", "--in-reply-to", self.task_id)
        self.assertEqual((doc["found"], doc["complete"]), ("one", True))
        self.assertEqual(doc["record"]["kind"], "result")
        self.assertEqual(s10(self.a, self.b, "00000001")[0], "PASS")

    def test_two_answers_to_one_task_are_ambiguous_never_one(self):
        self.flow(second_answer=True)
        doc = ev(self.b, "sent", "--instance", "builder", "--in-reply-to", self.task_id)
        self.assertEqual((doc["found"], doc["record"], doc["complete"]),
                         ("ambiguous", None, True))
        self.assertEqual(s10(self.a, self.b, "00000001")[:2], ("FAIL", "3"))

    def test_an_id_nobody_sent_is_none(self):
        self.flow()
        doc = ev(self.b, "verified", "--runtime", A_RT, "--id", "AbCdEfGhIjKlMnOpQrStUvW")
        self.assertEqual((doc["found"], doc["record"], doc["complete"]), ("none", None, True))
        doc = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000099")
        self.assertEqual((doc["found"], doc["complete"]), ("none", True))

    def test_the_output_is_closed_and_carries_no_free_text(self):
        self.flow()
        d1 = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001")
        self.assertEqual(set(d1), {"v", "form", "query", "found", "complete", "problems",
                                   "record"})
        self.assertEqual(set(d1["record"]), {"id", "kind", "in_reply_to", "instance", "req_id",
                                             "statement_sha256", "handed_ts", "settled"})
        self.assertNotIn("reason_code", json.dumps(d1))
        text = json.dumps(d1)
        for free in ("Run the suite", "Please run", self.b.address, self.a.address):
            self.assertNotIn(free, text)
        d2 = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual(set(d2["record"]), {"runtime", "id", "ts", "key_id",
                                             "statement_sha256", "state", "disposition",
                                             "done_ts"})
        self.assertEqual(d2["record"]["runtime"], A_RT)

    def test_a_restart_changes_nothing(self):
        self.flow()
        before = [run(h, *argv)[1] for h, argv in self.lookups()]
        hoplink.reset_process_state()
        after = [run(h, *argv)[1] for h, argv in self.lookups()]
        self.assertEqual(before, after)

    def lookups(self):
        t = self.task_id
        r = ev(self.b, "sent", "--instance", "builder", "--in-reply-to", t)["record"]["id"]
        return [(self.a, ["sent", "--instance", "planner", "--req-id", "00000001"]),
                (self.b, ["verified", "--runtime", A_RT, "--id", t]),
                (self.b, ["sent", "--instance", "builder", "--in-reply-to", t]),
                (self.a, ["verified", "--runtime", B_RT, "--id", r])]

    def test_a_replay_leaves_the_verified_record_unchanged(self):
        self.flow()
        before = run(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)[1]
        # The hub carries the same candidate bytes again, under a new entry.
        first = next(iter(self.b.intake.entries.values()))
        self.b.intake.entries["c9999"] = first
        self.b.poll()
        self.assertEqual(run(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)[1],
                         before)

    def test_not_before_is_a_guard_not_a_selector(self):
        self.flow()
        doc = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001",
                 "--not-before", "2999-01-01T00:00:00Z")
        self.assertEqual((doc["found"], doc["complete"], doc["problems"]), ("one", False, ["stale"]))
        self.assertEqual(s10(self.a, self.b, "00000001", not_before="2999-01-01T00:00:00Z")[:2],
                         ("UNKNOWN", "1"))
        doc = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id,
                 "--not-before", "2999-01-01T00:00:00Z")
        self.assertEqual((doc["found"], doc["problems"]), ("one", ["stale"]))


class TamperTests(_RoundTrip):
    """One durable record made wrong in one way at a time."""

    def setUp(self):
        super().setUp()
        self.flow()

    def reservation(self, host, runtime_address, ident):
        rt, idk = peerbind.replay_keys(runtime_address, ident)
        return Path(host.cfg.state_dir) / peerjournal.REPLAY_DIR / rt / (idk + ".json")

    def rewrite(self, path, data):
        os.chmod(path, 0o600)
        path.write_bytes(data)

    def b_res(self):
        return self.reservation(self.b, f"amap.router@{e2e.A_D}", self.task_id)

    def test_a_re_maced_other_sha_breaks_step_2(self):
        p = self.b_res()
        doc = json.loads(p.read_bytes())
        members = {k: v for k, v in doc.items() if k != "mac"}
        members["statement_sha256"] = "0" * 64
        key = peerbind._decision_key(Path(self.b.cfg.state_dir))
        doc = dict(members, mac=peerbind._reservation_mac(members, key))
        self.rewrite(p, json.dumps(doc).encode())
        got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual((got["found"], got["complete"]), ("one", True))
        self.assertEqual(s10(self.a, self.b, "00000001")[:2], ("FAIL", "2"))

    def test_a_re_maced_record_for_another_runtime_is_invalid(self):
        p = self.b_res()
        doc = json.loads(p.read_bytes())
        members = {k: v for k, v in doc.items() if k != "mac"}
        members["runtime"] = "amap.router@elsewhere.example"
        key = peerbind._decision_key(Path(self.b.cfg.state_dir))
        self.rewrite(p, json.dumps(dict(members, mac=peerbind._reservation_mac(members, key)))
                     .encode())
        got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual((got["found"], got["problems"]), ("none", ["invalid_field"]))

    def test_an_unmaced_change_is_mac_invalid(self):
        p = self.b_res()
        doc = json.loads(p.read_bytes())
        doc["statement_sha256"] = "0" * 64
        self.rewrite(p, json.dumps(doc).encode())
        got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("none", False, ["mac_invalid"]))

    def test_an_unreadable_decision_key_is_never_a_skipped_mac(self):
        with mock.patch.object(peerbind, "_decision_key", side_effect=OSError(5, "EIO")):
            got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual((got["found"], got["problems"]), ("none", ["read_error"]))

    def test_duplicate_keys_in_a_reservation(self):
        p = self.b_res()
        raw = p.read_bytes().decode()
        self.rewrite(p, ('{"v": 1, ' + raw.lstrip()[1:]).encode())
        got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual(got["problems"], ["duplicate_key"])

    def test_a_symlinked_reservation(self):
        p = self.b_res()
        real = Path(self.tmp) / "res-elsewhere.json"
        real.write_bytes(p.read_bytes())
        p.unlink()
        p.symlink_to(real)
        got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual(got["problems"], ["symlink"])

    def test_a_reservation_too_large(self):
        p = self.b_res()
        self.rewrite(p, b" " * (peerjournal.READER_JSON_CAP + 1))
        got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual(got["problems"], ["too_large"])

    def test_a_bad_done_marker(self):
        p = self.b_res().with_name(self.b_res().name[:-5] + ".done")
        self.rewrite(p, json.dumps({"done_ts": "2026-13-45T99:00:00Z",
                                    "disposition": "placed"}).encode())
        got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual(got["problems"], ["invalid_field"])

    def copy(self, host, lid, ident):
        return Path(host.cfg.state_dir) / lid / peerresend.PEER_SENT_DIR / ident

    def a_copy(self):
        return self.copy(self.a, e2e.LIDS["planner"], self.task_id)

    def test_an_uncommitted_copy(self):
        (self.a_copy() / peerresend.COMMIT).unlink()
        got = ev(self.a, "sent", "--instance", "planner", "--id", self.task_id)
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("none", False, ["not_committed"]))

    def test_an_uncommitted_copy_met_in_a_scan_makes_it_incomplete(self):
        """A copy still being written could be the match: the scan says so
        instead of answering a clean result."""
        import shutil
        other = self.a_copy().parent / "ZyXwVuTsRqPoNmLkJiHgFeD"
        shutil.copytree(self.a_copy(), other)      # every file present...
        (other / peerresend.COMMIT).unlink()       # ...but never committed
        got = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001")
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("one", False, ["not_committed"]))

    def test_an_unknown_member_in_origin(self):
        p = self.a_copy() / peerresend.ORIGIN
        doc = json.loads(p.read_bytes())
        doc["extra"] = 1
        self.rewrite(p, json.dumps(doc).encode())
        got = ev(self.a, "sent", "--instance", "planner", "--id", self.task_id)
        self.assertEqual((got["found"], got["problems"]), ("none", ["invalid_field"]))

    def test_an_outcome_outside_the_enum(self):
        p = self.a_copy() / peerresend.SETTLED
        doc = json.loads(p.read_bytes())
        doc["outcome"] = "delivered"
        self.rewrite(p, json.dumps(doc).encode())
        got = ev(self.a, "sent", "--instance", "planner", "--id", self.task_id)
        self.assertEqual(got["problems"], ["invalid_field"])

    def test_a_statement_for_another_id(self):
        p = self.a_copy() / peerresend.RECORD
        rec = json.loads(p.read_bytes())
        st = json.loads(base64.b64decode(rec["peer"]["statement"]))
        st["id"] = "AbCdEfGhIjKlMnOpQrStUvW"
        rec["peer"]["statement"] = base64.b64encode(json.dumps(st).encode()).decode()
        self.rewrite(p, json.dumps(rec).encode())
        got = ev(self.a, "sent", "--instance", "planner", "--id", self.task_id)
        self.assertEqual(got["problems"], ["invalid_field"])

    def test_a_copy_under_another_directory_name(self):
        other = "ZyXwVuTsRqPoNmLkJiHgFeD"
        moved = self.a_copy().parent / other
        self.a_copy().rename(moved)
        origin = json.loads((moved / peerresend.ORIGIN).read_bytes())
        origin["id"] = other
        self.rewrite(moved / peerresend.ORIGIN, json.dumps(origin).encode())
        got = ev(self.a, "sent", "--instance", "planner", "--id", other)
        self.assertEqual((got["found"], got["problems"]), ("none", ["invalid_field"]))

    # -- Codex r1 AMEND: a scanned candidate is never dropped unproved --------

    def b_result_copy(self):
        r = ev(self.b, "sent", "--instance", "builder", "--in-reply-to", self.task_id)
        self.assertEqual(r["found"], "one")
        return self.copy(self.b, e2e.LIDS["builder"], r["record"]["id"])

    def test_a_missing_origin_is_never_a_clean_none_for_req_id(self):
        (self.a_copy() / peerresend.ORIGIN).unlink()
        got = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001")
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("none", False, ["not_committed"]))

    def test_a_missing_record_is_never_a_clean_none_for_in_reply_to(self):
        d = self.b_result_copy()
        (d / peerresend.RECORD).unlink()
        got = ev(self.b, "sent", "--instance", "builder", "--in-reply-to", self.task_id)
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("none", False, ["not_committed"]))

    def test_a_statement_changed_out_of_its_binding_is_never_a_clean_none(self):
        """Only the preserved statement's in_reply_to changed, to another
        valid id: the enclosing record's binding no longer holds, so the copy
        is invalid -- not a non-match."""
        d = self.b_result_copy()
        p = d / peerresend.RECORD
        rec = json.loads(p.read_bytes())
        st = json.loads(base64.b64decode(rec["peer"]["statement"]))
        st["in_reply_to"] = "AbCdEfGhIjKlMnOpQrStUvW"
        rec["peer"]["statement"] = base64.b64encode(
            json.dumps(st, sort_keys=True, separators=(",", ":")).encode()).decode()
        self.rewrite(p, json.dumps(rec).encode())
        got = ev(self.b, "sent", "--instance", "builder", "--in-reply-to", self.task_id)
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("none", False, ["invalid_field"]))
        # The exact-id lookup of the same copy agrees.
        got = ev(self.b, "sent", "--instance", "builder", "--id", d.name)
        self.assertEqual((got["found"], got["problems"]), ("none", ["invalid_field"]))

    def test_valid_non_matching_copies_are_still_a_clean_answer(self):
        """The positive control: with every copy valid, a selector nobody
        carries is a clean none, and the real one is found."""
        got = ev(self.b, "sent", "--instance", "builder", "--in-reply-to",
                 "AbCdEfGhIjKlMnOpQrStUvW")
        self.assertEqual((got["found"], got["complete"], got["problems"]), ("none", True, []))
        got = ev(self.b, "sent", "--instance", "builder", "--in-reply-to", self.task_id)
        self.assertEqual((got["found"], got["complete"]), ("one", True))

    def test_an_invalid_entry_in_the_scanned_directory(self):
        (self.a_copy().parent / "not-an-id").mkdir()
        got = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001")
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("one", False, ["invalid_entry"]))

    def test_an_oversized_record(self):
        p = self.a_copy() / peerresend.RECORD
        with mock.patch.object(peerjournal, "EVIDENCE_RECORD_CAP", p.stat().st_size - 1):
            got = ev(self.a, "sent", "--instance", "planner", "--id", self.task_id)
        self.assertEqual(got["problems"], ["too_large"])

    def test_a_fifo_record_fails_fast(self):
        p = self.a_copy() / peerresend.HANDED
        p.unlink()
        os.mkfifo(p)
        got = ev(self.a, "sent", "--instance", "planner", "--id", self.task_id)
        self.assertEqual(got["problems"], ["not_regular"])

    def test_the_scan_cap(self):
        with mock.patch.object(peerjournal, "EVIDENCE_SCAN_CAP", 0):
            got = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001")
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("none", False, ["scan_limit"]))

    def test_a_reservation_directory_changed_mid_read(self):
        d = self.b_res().parent
        real = peerjournal.census
        calls = {"n": 0}

        def wrapped(state_dir, parts):
            got = real(state_dir, parts)
            calls["n"] += 1
            if calls["n"] == 1:
                (d / ("f" * 64 + ".json")).write_text("{}")   # another reservation lands
            return got
        with mock.patch.object(peerjournal, "census", wrapped):
            got = ev(self.b, "verified", "--runtime", A_RT, "--id", self.task_id)
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("one", False, ["concurrent_change"]))

    def test_an_entry_added_mid_scan(self):
        root = self.a_copy().parent
        real = peerjournal.census
        calls = {"n": 0}

        def wrapped(state_dir, parts):
            got = real(state_dir, parts)
            calls["n"] += 1
            if calls["n"] == 1:
                (root / "AbCdEfGhIjKlMnOpQrStUvW").mkdir()
            return got
        with mock.patch.object(peerjournal, "census", wrapped):
            got = ev(self.a, "sent", "--instance", "planner", "--req-id", "00000001")
        self.assertIn("concurrent_change", got["problems"])
        self.assertFalse(got["complete"])


class HeaderBindingTests(__import__("unittest").TestCase):
    """`peerjournal.header_binds`: the draft's field grammar (§12.6.3 check
    1) and the binding to the pinned statement, key id and signature."""

    ST, SIG, KID = b'{"id":"x"}', bytes(range(64)), "key-a.example"

    def h(self, **over):
        u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        tags = {"k": self.KID, "s": u(self.ST), "b": u(self.SIG)}
        tags.update(over)
        return "; ".join(f"{k}={v}" for k, v in tags.items() if v is not None)

    def binds(self, header, st=None):
        try:
            return peerjournal.header_binds(header, statement=st or self.ST, key_id=self.KID,
                                            signature=self.SIG)
        except Exception as e:  # noqa: BLE001 -- a crash is a wrong answer, so it FAILS
            return f"raised {type(e).__name__}"

    def test_the_exact_field_binds_whatever_the_order_and_spacing(self):
        self.assertTrue(self.binds(self.h()))
        u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        self.assertTrue(self.binds(f" b={u(self.SIG)} ;\ts={u(self.ST)};\r\nk={self.KID}"))

    def test_another_statement_does_not_bind(self):
        self.assertFalse(self.binds(self.h(), st=b'{"id":"y"}'))

    def test_another_key_or_signature_does_not_bind(self):
        u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        self.assertFalse(self.binds(self.h(k="key-b.example")))
        self.assertFalse(self.binds(self.h(b=u(bytes(64)))))

    def test_the_grammar(self):
        u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        for header in (self.h(k=None), self.h() + "; k=" + self.KID, self.h() + "; x=1",
                       self.h(s=base64.urlsafe_b64encode(self.ST).decode() + "=="),
                       self.h(s=base64.b64encode(self.ST).decode().replace("=", "") + "+"),
                       "k=" + self.KID, "", None, self.h() + "\u00e9"):
            with self.subTest(header=header):
                self.assertFalse(self.binds(header))


class ArgumentTests(_RoundTrip):

    def setUp(self):
        super().setUp()
        self.started()

    def test_bad_arguments_are_rc_2_with_no_stdout(self):
        for argv, arg in (
                (["verified", "--runtime", "nobody", "--id", "x"], "--runtime"),
                (["verified", "--runtime", B_RT, "--id=-x"], "--id"),
                (["verified", "--runtime", B_RT, "--id", "x" * 65], "--id"),
                (["sent", "--instance", "nobody", "--id", "x"], "--instance"),
                (["sent", "--instance", "planner", "--req-id", "a/b"], "--req-id"),
                (["sent", "--instance", "planner", "--in-reply-to", "a b"], "--in-reply-to"),
                (["sent", "--instance", "planner", "--id", "x", "--not-before",
                  "2026-02-30T00:00:00Z"], "--not-before")):
            with self.subTest(arg=arg, argv=argv):
                code, out, err = run(self.a, *argv)
                self.assertEqual((code, out), (2, []))
                self.assertEqual(err.strip(), f"router: peer-evidence: bad argument [{arg}]")

    def test_bad_arguments_are_refused_before_any_state_is_read(self):
        with mock.patch.object(peerjournal, "census", side_effect=AssertionError("read")), \
                mock.patch.object(peerjournal, "read_capped", side_effect=AssertionError("read")):
            code, out, _ = run(self.a, "verified", "--runtime", B_RT, "--id=-x")
        self.assertEqual((code, out), (2, []))

    def test_without_preservation_sent_is_never_a_clean_none(self):
        import dataclasses
        bare = dataclasses.replace(self.a.cfg, registry_dir=None)
        got = peerjournal.evidence_sent(bare, instance="planner", req_id="00000001")
        self.assertEqual((got["found"], got["complete"], got["problems"]),
                         ("none", False, ["not_preserved"]))


if __name__ == "__main__":
    import unittest
    unittest.main()
