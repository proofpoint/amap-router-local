"""`router inflight list` (router/inflight.py, THE OPERATOR LISTING): every
in-flight entry, read while the router runs.

Three properties carry the verb, and each has a row here that fails when it
is broken (`router/tests/mutate_inflight_list.py` breaks each one):

  * READ-ONLY. The state tree hashes the same before and after a listing,
    taken while this test holds the drain lock the way a running router does.
    The hash's own positive control is in the same test: a one-byte change
    to the tree must change it, and the listing must have rows.
  * NO LOCK. With no lock file present, a listing leaves none behind.
  * NEVER SKIPS. A torn record, a record outside the schema, a link, a stray
    name and an orphan marker each produce a row naming why.

A wrong outcome is a FAILURE, never an error: the CLI runs inside a wrapper
that turns any exception into `self.fail`, because the mutation runner counts
only failures as red.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
from unittest import mock

from router import __main__ as cli, config as config_mod, inflight, outbound
from router.lock import LOCK_NAME, acquire as acquire_lock
from router.tests import helpers
from router.tests.helpers import gen_state, write_request
from router.tests.test_generations import LIDS, _Gens
from router.tests.test_inflight import FakeTransport, _external

EXT = "you@example.com"
TS = "2026-10-15T12:00:00Z"
N1, N2 = "00000001", "00000002"


def record(n=N1, **over):
    """A minimal record in the closed schema (`inflight.check_record`)."""
    doc = {"transport_req_id": n, "recipients": [EXT], "request": {}, "written_ts": TS}
    doc.update(over)
    return doc


def tree_digest(root):
    """Every path under `root`: its type, mode, size, mtime and, for a file,
    its bytes' sha256; for a link, its target. Directories by their entries."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            parts = [os.path.relpath(p, root), oct(st.st_mode), str(st.st_size),
                     str(st.st_mtime_ns)]
            if stat.S_ISLNK(st.st_mode):
                parts.append(os.readlink(p))
            elif stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    parts.append(hashlib.sha256(f.read()).hexdigest())
            h.update("\0".join(parts).encode() + b"\n")
    return h.hexdigest()


class _CliMixin:

    def cli(self, *argv):
        """(exit code, stdout, stderr) of `inflight ...`; any exception FAILS."""
        out, err = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(cli, "load", return_value=self.cfg), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["--config", "unused.json", "inflight", *argv])
        except BaseException as e:  # noqa: BLE001 -- a wrong outcome must be a FAILURE
            self.fail(f"`inflight {' '.join(argv)}` raised {type(e).__name__}: {e}")
        return code, out.getvalue(), err.getvalue()

    def rows(self, *argv):
        code, out, err = self.cli("list", "--json", *argv)
        self.assertEqual(code, 0, err)
        try:
            doc = json.loads(out)
        except ValueError:
            self.fail(f"stdout is not one JSON document: {out!r}")
        self.assertEqual(set(doc), {"schema", "at", "rows"})
        self.assertEqual(doc["schema"], inflight.LIST_SCHEMA)
        for row in doc["rows"]:
            self.assertEqual(set(row), set(inflight.ROW_KEYS), row)
            self.assertIn(row["state"], inflight.LIST_STATES, row)
        return doc["rows"]

    def by_entry(self, rows):
        """The rows by entry name; a missing entry FAILS (never a KeyError)."""
        test = self

        class _Rows(dict):
            def __missing__(self, entry):
                test.fail(f"no row for {entry!r}: the listing skipped it ({rows})")
        return _Rows((r["entry"], r) for r in rows)


class _Plain(_CliMixin, helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alice": [], "bob": []})
        self.d = self.state_dir / "alice" / inflight.INFLIGHT_DIR

    def put(self, name, data):
        self.d.mkdir(parents=True, exist_ok=True)
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        (self.d / name).write_bytes(raw)

    def drain_one(self):
        """One request handed over through the real drain path."""
        write_request(self.cfg, "alice", N1, to=[EXT])
        outbound.drain_instance(self.cfg, "alice", cold_policy=_external,
                                transport=FakeTransport())


class StateTests(_Plain):

    def test_a_record_the_drain_handed_over_is_listed_handed(self):
        self.drain_one()
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual((r["instance"], r["req_id"], r["state"], r["tree"]),
                         ("alice", N1, inflight.ROW_HANDED, "mail"))
        self.assertRegex(r["transport_req_id"], r"\A[0-9]{8,18}\Z")
        self.assertIsInstance(r["age_s"], int)
        self.assertIsNone(r["generation"])
        self.assertFalse(r["retransmit"])

    def test_no_marker_is_not_handed(self):
        self.put(f"{N1}.json", record())
        r = self.by_entry(self.rows())[f"{N1}.json"]
        self.assertEqual(r["state"], inflight.ROW_NOT_HANDED)
        self.assertEqual(r["reason"], "")

    def test_a_marker_naming_another_transport_id_is_not_handed(self):
        self.put(f"{N1}.json", record(N1))
        self.put(f"{N1}{inflight.HANDED_SUFFIX}", N2.encode())
        r = self.by_entry(self.rows())[f"{N1}.json"]
        self.assertEqual(r["state"], inflight.ROW_NOT_HANDED)
        self.assertIn("another transport id", r["reason"])

    def test_a_revoked_record_is_revoked_not_handed(self):
        self.put(f"{N1}.json", record(revocation_unenforceable=TS))
        self.put(f"{N1}{inflight.HANDED_SUFFIX}", N1.encode())
        r = self.by_entry(self.rows())[f"{N1}.json"]
        self.assertEqual(r["state"], inflight.ROW_REVOKED)
        self.assertIn(TS, r["reason"])

    def test_age_is_from_the_record_written_ts(self):
        self.put(f"{N1}.json", record())
        with mock.patch("router.clock.now",
                        return_value=inflight.parse_utc_ts("2026-10-15T12:01:40Z")):
            r = self.by_entry(self.rows())[f"{N1}.json"]
        self.assertEqual(r["age_s"], 100)

    def test_the_plain_form_is_one_line_per_row(self):
        self.put(f"{N1}.json", record())
        self.put("stray name\nwith newline", b"x")
        code, out, err = self.cli("list")
        self.assertEqual(code, 0, err)
        lines = out.splitlines()
        self.assertEqual(len(lines), 2, out)
        self.assertRegex(lines[0], rf"\Aalice - {N1} {N1} not_handed [0-9]+ mail\Z")
        self.assertIn("unreadable", lines[1])
        self.assertIn("\\n", lines[1])


class NeverSkipsTests(_Plain):

    def test_a_torn_record_is_unreadable_never_skipped(self):
        raw = json.dumps(record()).encode()
        self.put(f"{N1}.json", raw[: len(raw) // 2])
        r = self.by_entry(self.rows())[f"{N1}.json"]
        self.assertEqual((r["state"], r["req_id"]), (inflight.ROW_UNREADABLE, N1))
        self.assertEqual(r["reason"], "record: not JSON")

    def test_a_record_outside_the_schema_is_unreadable_with_why(self):
        self.put(f"{N1}.json", record(transport_req_id="12"))
        r = self.by_entry(self.rows())[f"{N1}.json"]
        self.assertEqual(r["state"], inflight.ROW_UNREADABLE)
        self.assertIn("transport_req_id is not 8-18 digits", r["reason"])

    def test_a_linked_record_is_reported_not_followed(self):
        target = self.tmp / "elsewhere.json"
        target.write_text(json.dumps(record()))
        self.d.mkdir(parents=True)
        os.symlink(target, self.d / f"{N1}.json")
        r = self.by_entry(self.rows())[f"{N1}.json"]
        self.assertEqual(r["state"], inflight.ROW_UNREADABLE, r)
        self.assertIsNone(r["transport_req_id"], "the link's target was read")

    def test_a_foreign_entry_is_unreadable_never_skipped(self):
        self.put("stray.txt", b"x")
        r = self.by_entry(self.rows())["stray.txt"]
        self.assertEqual(r["state"], inflight.ROW_UNREADABLE)
        self.assertEqual(r["reason"], "not a record or a handed marker")

    def test_a_marker_with_no_record_is_an_orphan_row(self):
        self.put(f"{N1}{inflight.HANDED_SUFFIX}", N1.encode())
        r = self.by_entry(self.rows())[f"{N1}{inflight.HANDED_SUFFIX}"]
        self.assertEqual((r["state"], r["transport_req_id"]),
                         (inflight.ROW_ORPHAN_MARKER, N1))

    def test_a_marker_beside_its_record_is_not_a_second_row(self):
        self.put(f"{N1}.json", record())
        self.put(f"{N1}{inflight.HANDED_SUFFIX}", N1.encode())
        rows = self.rows()
        self.assertEqual([r["entry"] for r in rows], [f"{N1}.json"])
        self.assertEqual(rows[0]["state"], inflight.ROW_HANDED)


class ReadOnlyTests(_Plain):

    def furnish(self):
        """A handed record, a torn one, a stray, an orphan marker and an
        orphan attachment snapshot (the drain's sweep would remove it)."""
        self.drain_one()
        self.put(f"{N2}.json", b"{")
        self.put("stray.txt", b"x")
        self.put(f"00000009{inflight.HANDED_SUFFIX}", b"00000009")
        snap = self.state_dir / "alice" / inflight.SNAPSHOT_DIR / "orphan"
        snap.mkdir(parents=True)
        (snap / "0").write_bytes(b"blob")

    def test_a_listing_during_a_live_drain_changes_nothing(self):
        self.furnish()
        lk = acquire_lock(self.state_dir)       # the running router holds it
        try:
            before = tree_digest(self.state_dir)
            rows = self.rows()
            plain = self.cli("list")
            after = tree_digest(self.state_dir)
        finally:
            lk.release()
        self.assertEqual(plain[0], 0, plain[2])
        self.assertGreaterEqual(len(rows), 4, rows)     # it read something
        self.assertEqual(before, after, "the listing changed the state tree")
        # The digest's positive control: a one-byte change is seen.
        (self.state_dir / "alice" / inflight.SNAPSHOT_DIR / "orphan" / "0").write_bytes(b"blobb")
        self.assertNotEqual(tree_digest(self.state_dir), after)

    def test_no_lock_file_is_created(self):
        self.furnish()
        lock = self.state_dir / LOCK_NAME
        if lock.exists():
            lock.unlink()
        self.assertGreater(len(self.rows()), 0)
        self.assertFalse(lock.exists(), "the listing created the drain lock's file")
        # Control: taking the lock is what creates it.
        acquire_lock(self.state_dir).release()
        self.assertTrue(lock.exists())


class ScopeTests(_Plain):

    def test_an_unknown_instance_is_refused(self):
        code, out, err = self.cli("list", "nobody")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("unknown instance", err)

    def test_one_instance_lists_only_it(self):
        self.put(f"{N1}.json", record())
        bob = self.state_dir / "bob" / inflight.INFLIGHT_DIR
        bob.mkdir(parents=True)
        (bob / f"{N2}.json").write_text(json.dumps(record(N2)))
        self.assertEqual({r["instance"] for r in self.rows()}, {"alice", "bob"})
        self.assertEqual([r["instance"] for r in self.rows("bob")], ["bob"])

    def test_the_runtime_namespace_is_listed_per_generation(self):
        ns = self.state_dir / config_mod.RUNTIME_NS
        cur, old = "c" * 32, "d" * 32
        for g in (cur, old):
            (ns / g / inflight.INFLIGHT_DIR).mkdir(parents=True)
        (ns / config_mod.RUNTIME_GENERATION_FILE).write_text(json.dumps({"generation": cur}))
        (ns / old / inflight.INFLIGHT_DIR / f"{N1}.json").write_bytes(b"torn")
        rows = self.rows(config_mod.RUNTIME_NS)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual((rows[0]["instance"], rows[0]["generation"], rows[0]["current"],
                          rows[0]["state"]),
                         (config_mod.RUNTIME_NS, old, False, inflight.ROW_UNREADABLE))
        self.assertIn(rows[0], self.rows())

    def test_json_stdout_is_the_document_alone(self):
        self.put(f"{N1}.json", record())
        code, out, _ = self.cli("list", "--json")
        self.assertEqual(code, 0)
        json.loads(out)     # nothing else on stdout


class RegistryTests(_CliMixin, _Gens):

    def setUp(self):
        super().setUp()
        self.poll()                         # alpha's and bravo's first generations

    def put_in(self, gen_dir, name, data):
        d = gen_dir / inflight.INFLIGHT_DIR
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(json.dumps(data))

    def test_a_fenced_generation_is_listed_beside_the_current_one(self):
        first = gen_state(self.state_dir, LIDS["alpha"])
        self.replace_root("alpha")
        self.poll()                         # a new generation; the first is fenced
        second = gen_state(self.state_dir, LIDS["alpha"])
        self.assertNotEqual(first, second)
        self.put_in(first, f"{N1}.json", record(N1))
        self.put_in(second, f"{N2}.json", record(N2))
        before = tree_digest(self.state_dir)
        rows = [r for r in self.rows("alpha") if r["entry"]]
        self.assertEqual(tree_digest(self.state_dir), before, "the listing wrote")
        got = {(r["generation"], r["current"], r["req_id"]) for r in rows}
        self.assertEqual(got, {(first.name[len("gen-"):], False, N1),
                               (second.name[len("gen-"):], True, N2)})

    def test_an_instance_the_registry_does_not_resolve_is_one_unresolved_row(self):
        with mock.patch("router.registry.report_for") as rf:
            rf.return_value = mock.Mock(known={"bravo": LIDS["bravo"]})
            rows = self.rows("alpha")
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual((rows[0]["instance"], rows[0]["state"]),
                         ("alpha", inflight.ROW_UNRESOLVED))

    def test_a_held_generations_file_is_one_unresolved_row(self):
        (self.state_dir / LIDS["alpha"] / "generations.json").write_text("{")
        rows = self.rows("alpha")
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["state"], inflight.ROW_UNRESOLVED)
        self.assertIn("not JSON", rows[0]["reason"])

    def test_the_registry_is_read_without_recording_its_seq(self):
        self.put_in(gen_state(self.state_dir, LIDS["alpha"]), f"{N1}.json", record())
        self.put()                          # a new registry seq the router has not recorded
        before = tree_digest(self.state_dir)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(tree_digest(self.state_dir), before, "the listing recorded the seq")
        # Control: a persisting read of the same registry does write.
        from router import registry
        registry.report_for(self.reg, self.state_dir, self.cfg.instances, persist=True)
        self.assertNotEqual(tree_digest(self.state_dir), before)


del _Gens   # imported for subclassing only: never collected here
