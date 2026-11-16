"""ALPHA-2 W10, A2-05: `peer-store init`'s cause tokens and the read-only
`peer-store show --json` (design r3 §3).

Every state `show` reports is built by the REAL `init_store`, stopped at one
of its write points, or by a real init followed by one change; every cause
token by the real condition that produces it (a second process holding the
lock, an existing store, a signed notice in a peer root, an unwritable
state_dir).
"""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

from router import __main__ as cli
from router import peerclock, peerjournal
from router.tests import helpers

NOT_HEX_ID = "AbCdEfGhIjKlMnOpQrStUvW"      # a signed (non-32-hex) peer message id


def tree_hash(root: Path) -> str:
    """Every path, type, mode and content under `root` (lstat; a symlink by
    its target): equal hashes mean nothing was written."""
    h = hashlib.sha256()
    if not root.exists():
        return "absent"
    for dirpath, dirnames, filenames in sorted(os.walk(root)):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = Path(dirpath) / name
            st = p.lstat()
            h.update(f"{p.relative_to(root)}|{st.st_mode}|".encode())
            if p.is_symlink():
                h.update(os.readlink(p).encode())
            elif p.is_file():
                h.update(p.read_bytes())
    return h.hexdigest()


class _Cli(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": []})
        self.sd = Path(self.cfg.state_dir)

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "load", lambda path: self.cfg), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--config", "unused", *argv])
        return code, out.getvalue(), err.getvalue()

    def init(self):
        return self.cli("peer-store", "init", "--never-admitted")

    def show(self):
        code, out, err = self.cli("peer-store", "show", "--json")
        self.assertEqual((code, err), (0, ""))
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, out)
        return json.loads(lines[0])

    def hold_lock(self):
        """A SECOND PROCESS holding the drain lock until cleanup."""
        ready = self.tmp / "lock-held"
        code = ("import sys,time,pathlib; from router.lock import acquire; "
                f"lk=acquire({str(self.sd)!r}); pathlib.Path({str(ready)!r}).write_text('1'); "
                "time.sleep(60)")
        p = subprocess.Popen([sys.executable, "-B", "-c", code],
                             cwd=str(Path(__file__).resolve().parents[2]))
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        for _ in range(200):
            if ready.exists():
                return
            time.sleep(0.05)
        self.fail("the lock holder did not start")


# ---------------------------------------------------------------------------
# init: one token per cause
# ---------------------------------------------------------------------------

class InitTokenTests(_Cli):

    def test_a_clean_init_prints_one_json_line_and_nothing_on_stderr(self):
        code, out, err = self.init()
        self.assertEqual((code, err), (0, ""))
        lines = out.splitlines()
        self.assertEqual(len(lines), 1)
        doc = json.loads(lines[0])
        self.assertEqual(set(doc), {"H", "admission", "f", "p"})
        self.assertEqual(doc["admission"], "open")
        self.assertNotIn("refused", err)

    def test_lock_held_by_another_process(self):
        self.hold_lock()
        before = tree_hash(self.sd)
        code, out, err = self.init()
        self.assertEqual((code, out), (1, ""))
        self.assertRegex(err, r"^router: refusing to run 'peer-store init' \[lock_held\]: ")
        self.assertEqual(tree_hash(self.sd), before, "init under a held lock wrote something")

    def test_artefacts_exist(self):
        self.assertEqual(self.init()[0], 0)
        code, out, err = self.init()
        self.assertEqual((code, out), (1, ""))
        self.assertRegex(err, r"^router: peer-store init: refused \[artefacts_exist\]: "
                              r"peer artefacts already exist")

    def test_evidence_survives(self):
        root = self.tmp / "peer-root"
        (root / "notices").mkdir(parents=True)
        (root / "notices" / "notice-1.json").write_text(json.dumps(
            {"kind": "peer", "message": {"id": NOT_HEX_ID}}))
        with mock.patch.object(peerjournal, "peer_roots", lambda cfg: [root]):
            code, out, err = self.init()
        self.assertEqual((code, out), (1, ""))
        self.assertRegex(err, r"^router: peer-store init: refused \[evidence_survives\]: ")
        self.assertEqual(self.show()["store"], "absent")

    def test_io_error_on_an_unwritable_state_dir(self):
        self.sd.mkdir(parents=True, exist_ok=True)
        # The lock file must exist for the lock to be taken in a read-only dir.
        (self.sd / ".router.lock").touch()
        os.chmod(self.sd, 0o500)
        try:
            if os.access(self.sd, os.W_OK):
                self.skipTest("running as a user that ignores directory modes")
            code, out, err = self.init()
        finally:
            os.chmod(self.sd, 0o700)
        self.assertEqual((code, out), (1, ""))
        self.assertRegex(err, r"^router: peer-store init: refused \[io_error\]: ")

    def test_io_error_after_the_core_state_leaves_a_ready_store(self):
        """A failure after the bookkeeping but before the audit line and the
        stdout object: rc 1 with `io_error`, and `show` reports the store
        ready. That is the S8 DAN-ITEM case (never retried)."""
        with mock.patch.object(peerjournal, "_audit", side_effect=OSError(28, "No space")):
            code, out, err = self.init()
        self.assertEqual((code, out), (1, ""))
        self.assertRegex(err, r"^router: peer-store init: refused \[io_error\]: ")
        self.assertEqual(self.show()["store"], "ready")

    def test_other_verbs_keep_their_lines(self):
        self.hold_lock()
        code, _out, err = self.cli("peer-store", "declare-restored", "--evidence", "x")
        self.assertEqual(code, 1)
        self.assertRegex(err, r"^router: refusing to run 'peer-store declare-restored': ")
        self.assertNotIn("[", err.split(":")[1])


# ---------------------------------------------------------------------------
# show: every row of the table
# ---------------------------------------------------------------------------

class ShowStateTests(_Cli):

    def test_absent_on_an_empty_state_dir(self):
        self.assertEqual(self.show(), {"v": 1, "store": "absent", "artefacts": [],
                                       "clock": None, "meta": "absent", "problems": []})

    def test_absent_and_not_created_when_state_dir_is_missing(self):
        missing = self.tmp / "no-such-state"
        doc = peerjournal.peer_store_show(missing)
        self.assertEqual((doc["store"], doc["problems"]), ("absent", []))
        self.assertFalse(missing.exists())

    def test_ready_after_a_real_init(self):
        code, out, _ = self.init()
        printed = json.loads(out)
        doc = self.show()
        self.assertEqual(doc["store"], "ready")
        self.assertEqual(doc["problems"], [])
        self.assertEqual(doc["meta"], "present")
        self.assertEqual(doc["artefacts"], sorted([peerclock.CLOCK_FILE, "peer-epochs",
                                                   "peer-replay"]))
        self.assertEqual(doc["clock"], {"admission": "open", "H": printed["H"], "floor": None,
                                        "p": printed["p"], "f": printed["f"]})

    def _stopped_at(self, target, n=1):
        """Run the real init and fail the n-th call of `target`."""
        calls = {"n": 0}
        real = getattr(*target)

        def failing(*a, **k):
            calls["n"] += 1
            if calls["n"] == n:
                raise OSError(5, "stopped here")
            return real(*a, **k)
        with mock.patch.object(target[0], target[1], failing):
            code, _out, err = self.init()
        self.assertEqual(code, 1)
        self.assertIn("[io_error]", err)
        return self.show()

    def test_killed_before_the_replay_witness(self):
        doc = self._stopped_at((peerjournal, "atomic_write"), 1)
        self.assertEqual((doc["store"], doc["artefacts"], doc["problems"]),
                         ("partial", ["peer-replay"], ["clock_absent"]))

    def test_killed_before_the_epochs_witness(self):
        doc = self._stopped_at((peerjournal, "atomic_write"), 2)
        self.assertEqual((doc["store"], doc["artefacts"], doc["problems"]),
                         ("partial", ["peer-epochs", "peer-replay"], ["clock_absent"]))

    def test_killed_before_the_clock(self):
        doc = self._stopped_at((peerclock, "write_doc"), 1)
        self.assertEqual((doc["store"], doc["problems"]), ("partial", ["clock_absent"]))

    def test_killed_before_the_bookkeeping(self):
        doc = self._stopped_at((peerjournal, "_write_meta"), 1)
        self.assertEqual((doc["store"], doc["meta"], doc["problems"]),
                         ("partial", "absent", ["meta_absent"]))
        self.assertEqual(doc["clock"]["admission"], "open")

    def test_a_witness_that_differs(self):
        self.init()
        (self.sd / "peer-epochs" / peerjournal.WITNESS).write_text("0" * 64)
        doc = self.show()
        self.assertEqual((doc["store"], doc["problems"]), ("partial", ["witness_mismatch"]))

    def test_a_missing_witness(self):
        self.init()
        (self.sd / "peer-replay" / peerjournal.WITNESS).unlink()
        doc = self.show()
        self.assertEqual((doc["store"], doc["problems"]), ("partial", ["witness_mismatch"]))


class JournalArtefactTests(_Cli):

    def test_a_journal_root_alone_is_partial(self):
        owner = self.sd / "alice"
        owner.mkdir(parents=True, exist_ok=True)
        (owner / peerjournal.JOURNAL_DIR).mkdir()
        doc = self.show()
        self.assertEqual((doc["store"], doc["artefacts"], doc["problems"]),
                         ("partial", [f"alice/{peerjournal.JOURNAL_DIR}"], ["clock_absent"]))


class ShowUnknownTests(_Cli):

    def setUp(self):
        super().setUp()
        self.assertEqual(self.init()[0], 0)
        self.clock = self.sd / peerclock.CLOCK_FILE

    def assertUnknown(self, code):
        doc = self.show()
        self.assertEqual((doc["store"], doc["clock"], doc["problems"]), ("unknown", None, [code]))

    def test_a_symlinked_clock(self):
        real = self.tmp / "elsewhere.json"
        real.write_bytes(self.clock.read_bytes())
        self.clock.unlink()
        self.clock.symlink_to(real)
        self.assertUnknown("symlink")

    def test_a_symlinked_witness_directory(self):
        d = self.sd / "peer-epochs"
        moved = self.tmp / "epochs-elsewhere"
        d.rename(moved)
        d.symlink_to(moved)
        self.assertUnknown("symlink")

    def test_a_symlinked_witness_file(self):
        w = self.sd / "peer-replay" / peerjournal.WITNESS
        real = self.tmp / "witness-elsewhere"
        real.write_bytes(w.read_bytes())
        w.unlink()
        w.symlink_to(real)
        self.assertUnknown("symlink")

    def test_a_corrupt_clock(self):
        self.clock.write_bytes(b"{not json")
        self.assertUnknown("corrupt")

    def test_json_that_is_not_a_clock_record(self):
        self.clock.write_text("{}")
        self.assertUnknown("corrupt")

    def test_bookkeeping_that_is_not_the_closed_record(self):
        doc = json.loads(self.clock.read_bytes())
        doc["store"] = {"v": 99}
        self.clock.write_text(json.dumps(doc))
        self.assertUnknown("corrupt")

    def test_duplicate_keys_in_the_clock(self):
        raw = self.clock.read_bytes().decode()
        self.clock.write_text('{"admission": "closed", ' + raw.lstrip()[1:])
        self.assertUnknown("corrupt")

    def test_a_clock_that_is_a_fifo_does_not_hang(self):
        self.clock.unlink()
        os.mkfifo(self.clock)
        try:
            code = ("import json,sys; from router import peerjournal; "
                    f"print(json.dumps(peerjournal.peer_store_show({str(self.sd)!r})))")
            p = subprocess.run([sys.executable, "-B", "-c", code],
                               capture_output=True, text=True, timeout=30,
                               cwd=str(Path(__file__).resolve().parents[2]))
        except subprocess.TimeoutExpired:
            self.fail("show blocked on a FIFO")
        doc = json.loads(p.stdout)
        self.assertEqual((doc["store"], doc["problems"]), ("unknown", ["not_regular"]))

    def test_an_oversized_clock(self):
        doc = json.loads(self.clock.read_bytes())
        doc["pad"] = "x" * peerjournal.READER_JSON_CAP
        self.clock.write_text(json.dumps(doc))
        self.assertUnknown("too_large")


class ShowRaceTests(_Cli):
    """A change between the two censuses, or to a file after it was read,
    is `unknown`/`concurrent_change`, never a state."""

    def _race(self, after_call, action):
        """Run `show` with `action()` performed right after the n-th call of
        `peerjournal.census` (n = after_call)."""
        real = peerjournal.census
        calls = {"n": 0}

        def wrapped(*a, **k):
            got = real(*a, **k)
            calls["n"] += 1
            if calls["n"] == after_call:
                action()
            return got
        with mock.patch.object(peerjournal, "census", wrapped):
            return peerjournal.peer_store_show(self.sd)

    def test_a_clock_created_after_an_empty_census_is_not_absent(self):
        # alice's state dir is the only child: census 1 is the top, 2 alice.
        doc = self._race(2, lambda: (self.sd / peerclock.CLOCK_FILE).write_text("{}"))
        self.assertEqual((doc["store"], doc["problems"]), ("unknown", ["concurrent_change"]))

    def test_a_journal_added_under_an_owner_is_caught(self):
        self.init()
        owner = next(p for p in self.sd.iterdir() if p.is_dir() and p.name == "alice")
        doc = self._race(2, lambda: (owner / peerjournal.JOURNAL_DIR).mkdir())
        self.assertEqual((doc["store"], doc["problems"]), ("unknown", ["concurrent_change"]))

    def test_a_file_replaced_after_it_was_read(self):
        self.init()
        clock = self.sd / peerclock.CLOCK_FILE
        real = peerjournal.read_capped

        def wrapped(state_dir, parts, cap):
            got = real(state_dir, parts, cap)
            if parts == (peerclock.CLOCK_FILE,):
                # Rewritten IN PLACE (same inode, same directory entry set):
                # only the file's own re-stat can see it.
                data = clock.read_bytes()
                st = clock.stat()
                with open(clock, "r+b") as f:
                    f.write(data)
                os.utime(clock, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
            return got
        with mock.patch.object(peerjournal, "read_capped", wrapped):
            doc = peerjournal.peer_store_show(self.sd)
        self.assertEqual((doc["store"], doc["problems"]), ("unknown", ["concurrent_change"]))


class ShowWritesNothingTests(_Cli):

    def test_no_write_and_no_lock_file(self):
        self.init()
        (self.sd / ".router.lock").unlink(missing_ok=True)
        before = tree_hash(self.sd)
        self.show()
        self.assertEqual(tree_hash(self.sd), before)
        self.assertFalse((self.sd / ".router.lock").exists())

    def test_it_answers_while_another_process_holds_the_lock(self):
        self.init()
        self.hold_lock()
        self.assertEqual(self.show()["store"], "ready")

    def test_the_json_flag_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.cli("peer-store", "show")


if __name__ == "__main__":
    unittest.main()
