"""The ingress quarantine's frozen item format and its read-only inspection
(`router/quarantine.py`, `router quarantine list|show`).

The fixtures here are written in the frozen format by hand, because this
router has no writer yet: the step that writes items must write exactly
what these tests read."""
import contextlib
import errno
import io
import json
import os
import time
import unittest
from unittest import mock

from router import __main__ as cli, generations, ingress, quarantine, service
from router.status import StatusTracker
from router.tests.helpers import gen_state, keyed_for_poll
from router.tests.test_generations import LIDS, _Gens

ID1, ID2 = "1" * 32, "2" * 32
NOW = "2026-10-11T12:00:00Z"


def item(gen, item_id=ID1, **over):
    doc = {"schema": quarantine.SCHEMA, "id": item_id, "generation": gen,
           "arrival_ts": "2026-10-11T11:00:00Z", "causes": ["cold_fleet_mail"],
           "evidence": {"from": "x@hub2.fleet.example", "size": 1200}}
    doc.update(over)
    return doc


class _Q(_Gens):

    def setUp(self):
        super().setUp()
        self.poll()                         # begin alpha's first generation
        self.gen_dir = gen_state(self.state_dir, LIDS["alpha"])
        self.gen = self.gen_dir.name[len("gen-"):]
        self.qdir = self.gen_dir / quarantine.DIR_NAME
        self.qdir.mkdir()

    def put_item(self, doc_or_bytes=None, name=None, **over):
        doc = doc_or_bytes if doc_or_bytes is not None else item(self.gen, **over)
        raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
        item_id = doc["id"] if isinstance(doc, dict) and isinstance(doc.get("id"), str) else ID1
        (self.qdir / (name or f"{item_id}.json")).write_bytes(raw)

    def items(self, now=NOW):
        return quarantine.list_ingress(self.state_dir, LIDS["alpha"], "alpha", days=14, now=now)

    def one(self, **kw):
        items = self.items(**kw)
        self.assertEqual(len(items), 1, [i.key() for i in items])
        return items[0]

    def damaged(self, **kw):
        """The one item's reason, or a stand-in that fails every assertIn."""
        return self.one(**kw).damaged or "<not damaged>"

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "load", return_value=self.cfg), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--config", "unused.json", "quarantine", *argv])
        return code, out.getvalue(), err.getvalue()


class FormatTests(_Q):

    def test_a_valid_item(self):
        self.put_item()
        i = self.one()
        self.assertIsNone(i.damaged)
        self.assertEqual(i.key(), f"alpha ingress {self.gen} {ID1}")
        self.assertEqual(i.age_s, 3600)
        self.assertEqual(i.expires_in_s, 14 * 86400 - 3600)

    def test_every_rule_fails_visibly(self):
        big = {f"k{i}": "v" for i in range(quarantine.EVIDENCE_MAX_KEYS + 1)}
        cases = {
            "not JSON": b"{ nope",
            "a duplicate member": (b'{"schema": "a", "schema": "b"}'),
            "a non-finite number": json.dumps(item(self.gen, evidence={"n": 1})).replace(
                '"n": 1', '"n": NaN').encode(),
            "members are not exactly": item(self.gen, extra=1),
            "unknown schema": item(self.gen, schema="amap-router-local.ingress-quarantine/2"),
            "id is not 32 lowercase hex": (item(self.gen, id="A" * 32), f"{ID1}.json"),
            "id differs from the filename": (item(self.gen, id=ID2), f"{ID1}.json"),
            "generation differs": item(self.gen, generation="f" * 32),
            "arrival_ts is not a UTC timestamp": item(self.gen, arrival_ts="yesterday"),
            "in the future": item(self.gen, arrival_ts="2026-10-11T12:05:01Z"),
            "causes is not a non-empty list": item(self.gen, causes=[]),
            "causes has a duplicate": item(self.gen,
                                           causes=["cold_fleet_mail", "cold_fleet_mail"]),
            "outside the vocabulary": item(self.gen, causes=["made_up"]),
            "more than 32 members": item(self.gen, evidence=big),
            "evidence key": item(self.gen, evidence={"bad\nkey": "v"}),
            "evidence key ": item(self.gen, evidence={"k" * 65: "v"}),
            "evidence string exceeds": item(self.gen, evidence={"k": "v" * 1025}),
            "a JSON boolean": item(self.gen, evidence={"k": True}),
            "a float": item(self.gen, evidence={"k": 1.5}),
            "an unbounded integer": item(self.gen, evidence={"k": 2 ** 53}),
            "evidence exceeds": item(self.gen, evidence={f"k{i}": "v" * 1000 for i in range(17)}),
            "evidence is not an object": item(self.gen, evidence=[]),
        }
        reasons = {
            "a JSON boolean": "neither a bounded string nor an integer",
            "a float": "neither a bounded string nor an integer",
            "an unbounded integer": "neither a bounded string nor an integer",
            "evidence key ": "evidence key",
            "more than 32 members": "more than 32 members",
            "in the future": "more than 300s in the future",
        }
        for label, case in cases.items():
            with self.subTest(label):
                for p in self.qdir.iterdir():
                    p.unlink()
                if isinstance(case, tuple):
                    self.put_item(case[0], name=case[1])
                else:
                    self.put_item(case)
                i = self.one()
                self.assertIsNotNone(i.damaged, label)
                self.assertIn(reasons.get(label, label.strip()), i.damaged)

    def test_the_skew_edge(self):
        self.put_item(arrival_ts="2026-10-11T12:05:00Z")
        self.assertIsNone(self.one().damaged)

    def test_the_bounds_are_inclusive(self):
        self.put_item(evidence={"k" * 64: "v" * 1024, "n": 2 ** 53 - 1, "m": -(2 ** 53 - 1)})
        self.assertIsNone(self.one().damaged)

    def test_oversize_files(self):
        self.put_item(b"x" * (quarantine.ITEM_MAX_BYTES + 1))
        self.assertIn("larger than", self.damaged())

    def test_links_and_non_regular_entries(self):
        target = self.tmp / "elsewhere.json"
        target.write_text(json.dumps(item(self.gen)))
        os.symlink(target, self.qdir / f"{ID1}.json")
        self.assertIn("a symbolic link, never followed", self.damaged())
        (self.qdir / f"{ID1}.json").unlink()
        os.link(target, self.qdir / f"{ID1}.json")
        self.assertIn("more than one link", self.damaged())
        (self.qdir / f"{ID1}.json").unlink()
        (self.qdir / f"{ID1}.json").mkdir()
        self.assertIsNotNone(self.one().damaged)
        (self.qdir / f"{ID1}.json").rmdir()
        os.mkfifo(self.qdir / f"{ID1}.json")
        self.assertEqual(self.one().damaged, "not a regular file")

    def test_an_unexpected_name_is_listed_escaped(self):
        self.put_item(name="evil\x1b[2J.json")
        i = self.one()
        self.assertEqual(i.damaged, "an unexpected name")
        self.assertNotIn("\x1b", i.key())
        self.assertIn("\\u001b", i.key())

    def test_a_linked_quarantine_directory_is_damaged(self):
        os.rmdir(self.qdir)
        real = self.tmp / "realq"
        real.mkdir()
        os.symlink(real, self.qdir)
        i = self.one()
        self.assertEqual(i.id, "-")
        self.assertIn("reachable without a link", i.damaged or "<not damaged>")

    def test_every_generation_is_read(self):
        self.put_item()
        generations.operator_new(self.cfg, "alpha", "test")
        keyed_for_poll(self.cfg)
        new = gen_state(self.state_dir, LIDS["alpha"])
        new_gen = new.name[len("gen-"):]
        (new / quarantine.DIR_NAME).mkdir()
        (new / quarantine.DIR_NAME / f"{ID2}.json").write_text(
            json.dumps(item(new_gen, item_id=ID2)))
        self.assertEqual(sorted((i.generation, i.id) for i in self.items()),
                         sorted([(self.gen, ID1), (new_gen, ID2)]))

    def test_no_state_lists_nothing(self):
        self.assertEqual(quarantine.list_ingress(self.state_dir, "f" * 32, "x", days=14), [])

    def test_the_vocabulary_is_closed(self):
        """Three causes today; anything else, including a §5 cause name not
        yet published to this repository, is outside it."""
        self.assertEqual(quarantine.CAUSES, ("cold_fleet_mail", "late_inbound",
                                             "notice_invalid"))
        self.put_item(causes=["notice_invalid"])
        self.assertIsNone(self.one().damaged, "notice_invalid is in the vocabulary")
        self.put_item(causes=["cold_fleet_mail"])
        self.assertIsNone(self.one().damaged)
        self.put_item(causes=["late_inbound"])
        self.assertIsNone(self.one().damaged, "late_inbound is in the vocabulary")
        self.put_item(causes=["cold_fleet_mail", "late_inbound"])
        self.assertIsNone(self.one().damaged)
        self.put_item(causes=["policy"])
        self.assertIn("outside the vocabulary", self.damaged())


class CliTests(_Q):

    def test_list_and_show(self):
        self.put_item(evidence={"subject": "hi\x1b[2Jthere\u202eevil", "size": 3})
        code, out, _ = self.run_cli("list", "alpha")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(f"alpha ingress {self.gen} {ID1} age="))
        self.assertIn("causes=cold_fleet_mail", out)
        code, out, _ = self.run_cli("show", "alpha", "ingress", self.gen, ID1)
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out, "evidence printed raw")
        self.assertNotIn("\u202e", out, "a bidi override printed raw")
        doc = json.loads(out)
        self.assertEqual(doc["item"]["evidence"]["subject"], "hi\x1b[2Jthere\u202eevil")
        self.assertEqual(doc["status"], "held")

    def test_list_without_a_name_covers_every_instance(self):
        self.put_item()
        code, out, _ = self.run_cli("list")
        self.assertEqual((code, out.count("\n")), (0, 1))

    def test_show_of_a_damaged_item_shows_its_reason_only(self):
        self.put_item(item(self.gen, evidence={"k": True, "secret": "do-not-print"}))
        code, out, _ = self.run_cli("show", "alpha", "ingress", self.gen, ID1)
        self.assertEqual(code, 0)
        self.assertNotIn("do-not-print", out)
        self.assertEqual(json.loads(out)["status"], "damaged")
        code, out, _ = self.run_cli("list", "alpha")
        self.assertIn(" DAMAGED ", out)

    def test_retention_follows_the_config(self):
        from dataclasses import replace
        self.cfg = replace(self.cfg, ingress_quarantine_days=1)
        self.put_item(arrival_ts="2026-10-01T00:00:00Z")
        code, out, _ = self.run_cli("list", "alpha")
        self.assertIn("expired (awaiting its sweep)", out)

    def test_unknown_instance_and_unknown_item(self):
        code, _, err = self.run_cli("list", "nobody")
        self.assertEqual(code, 1)
        self.assertIn("unknown instance", err)
        code, _, err = self.run_cli("show", "alpha", "ingress", self.gen, ID2)
        self.assertEqual(code, 1)
        code, _, _ = self.run_cli("show", "alpha", "ingress", "f" * 32, ID1)
        self.assertEqual(code, 1)

    def test_the_registry_seq_is_not_recorded(self):
        """Read-only toward the registry too: the CLI reads it without
        persisting the seq it saw (a poll does that)."""
        from router import registry
        seq = registry.seq_path(self.state_dir)
        self.assertTrue(seq.exists())
        seq.unlink()
        self.run_cli("list")
        self.assertFalse(seq.exists())

    def test_read_only(self):
        self.put_item()
        before = sorted(str(p) for p in self.tmp.rglob("*"))
        seq = (self.state_dir / "registry").exists() and sorted(
            p.read_bytes() for p in (self.state_dir / "registry").rglob("*") if p.is_file())
        self.run_cli("list")
        self.run_cli("show", "alpha", "ingress", self.gen, ID1)
        self.assertEqual(sorted(str(p) for p in self.tmp.rglob("*")), before)
        self.assertEqual((self.state_dir / "registry").exists() and sorted(
            p.read_bytes() for p in (self.state_dir / "registry").rglob("*") if p.is_file()),
            seq)

    def test_status_counts_per_agent(self):
        self.put_item()
        self.put_item(item(self.gen, item_id=ID2, causes=[]))
        tracker = StatusTracker(interval_s=5.0)
        service.poll_once(self.cfg, tracker)
        counts = (tracker.to_doc().get("classification") or {}).get("ingress_quarantine", {})
        self.assertEqual(counts.get("alpha"), {"items": 2, "damaged": 1})
        self.assertEqual(counts.get("bravo"), {"items": 0, "damaged": 0})
        from router.status import render
        text = render(tracker.to_doc())
        self.assertIn("alpha: ingress quarantine holds 2 item(s), 1 DAMAGED", text)
        self.assertNotIn("bravo: ingress quarantine", text)


class ControlTests(_Q):

    def setUp(self):
        super().setUp()
        self.control = self.tmp / ".control"
        self.control.mkdir()

    def candidate(self, name, data=b'{"x": 1}'):
        d = self.control / name
        d.mkdir()
        (d / "candidate.json").write_bytes(data)
        return d

    def test_listed_with_metadata_only(self):
        self.candidate(ID1, b'{"secret": "do-not-print"}')
        code, out, _ = self.run_cli("list", "--control-dir", str(self.control))
        self.assertEqual(code, 0)
        self.assertIn(f"- control - {ID1} candidate age=", out)
        code, out, _ = self.run_cli("show", "-", "control", "-", ID1,
                                    "--control-dir", str(self.control))
        self.assertEqual(code, 0)
        self.assertNotIn("do-not-print", out)
        doc = json.loads(out)
        self.assertEqual(doc["candidate_bytes"], 26)
        self.assertEqual(len(doc["candidate_sha256"]), 64)

    def test_damaged_entries(self):
        self.candidate("not-hex")
        d = self.candidate(ID1)
        (d / "candidate.json").unlink()
        os.symlink(self.tmp / "x", d / "candidate.json")
        self.candidate(ID2, b"x" * (quarantine.CANDIDATE_MAX_BYTES + 1))
        items = {i.id: i.damaged for i in quarantine.list_control(self.control)}
        self.assertEqual(items["not-hex"], "an unexpected name")
        self.assertEqual(items[ID1], "candidate.json: a symbolic link, never followed")
        self.assertIn("larger than", items[ID2])

    def test_a_commit_caught_in_progress_is_in_flight_not_damaged(self):
        d = self.candidate(ID1)
        os.link(d / "candidate.json", self.tmp / "staged")      # two links
        [i] = quarantine.list_control(self.control)
        self.assertIsNone(i.damaged)
        self.assertIn("IN FLIGHT", quarantine.render_line(i))
        os.link(d / "candidate.json", self.tmp / "third")       # three: damaged
        [i] = quarantine.list_control(self.control)
        self.assertIn("more than one link", i.damaged or "<not damaged>")

    def test_the_writers_stage_is_not_listed(self):
        (self.control / ".stage").mkdir()
        self.candidate(ID1)
        self.assertEqual([i.id for i in quarantine.list_control(self.control)], [ID1])
        (self.control / ".stagex").mkdir()       # only that exact name
        items = {i.id: i.damaged for i in quarantine.list_control(self.control)}
        self.assertEqual(items[".stagex"], "an unexpected name")

    def test_a_directory_without_its_candidate_is_not_yet_an_item(self):
        d = self.control / ID1
        d.mkdir()
        (d / "body").write_bytes(b"leaf written before the sentinel")
        [i] = quarantine.list_control(self.control)
        self.assertIsNone(i.damaged)
        self.assertEqual(quarantine.render_line(i),
                         f"- control - {ID1} IN FLIGHT (no committed candidate.json yet)")
        code, out, _ = self.run_cli("show", "-", "control", "-", ID1,
                                    "--control-dir", str(self.control))
        self.assertEqual(code, 0)
        self.assertEqual((json.loads(out)["status"], json.loads(out)["why"]),
                         ("in_flight", "no committed candidate.json yet"))
        self.assertNotIn("leaf written", out)

    @unittest.skipIf(os.geteuid() == 0, "root reads a mode-0 file")
    def test_an_unreadable_candidate_names_its_own_error(self):
        d = self.candidate(ID1)
        (d / "candidate.json").chmod(0)
        [i] = quarantine.list_control(self.control)
        self.assertEqual(i.damaged, f"candidate.json: cannot be opened ({os.strerror(errno.EACCES)})")

    def test_nothing_is_moved_or_written(self):
        self.candidate(ID1)
        before = sorted((str(p), p.stat().st_mtime_ns) for p in self.control.rglob("*"))
        self.run_cli("list", "--control-dir", str(self.control))
        self.assertEqual(sorted((str(p), p.stat().st_mtime_ns)
                                for p in self.control.rglob("*")), before)

    def test_show_control_needs_dashes_and_the_dir(self):
        self.candidate(ID1)
        for argv in (("show", "alpha", "control", "-", ID1, "--control-dir", str(self.control)),
                     ("show", "-", "control", self.gen, ID1, "--control-dir", str(self.control)),
                     ("show", "-", "control", "-", ID1)):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_cli(*argv)[0], 1)


class DerivedControlTests(_Q):
    """With `hop`, the `.control/` intake is `<hop.root>/.control/`: listed
    without any option, `--control-dir` refused beside it, an item past the
    report threshold reported `expired` (never removed), and counted in the
    ingress status, count-only."""

    def setUp(self):
        super().setUp()
        from dataclasses import replace
        from router import config as config_mod
        from router.tests import helpers
        hop_root = self.tmp / "hop"
        self.control = hop_root / ".control"
        self.control.mkdir(parents=True)
        self.cfg = replace(self.cfg, hop=config_mod.HopConfig(
            root=str(hop_root), peer_uid=0, version_write=1,
            caps=tuple(helpers.TEST_HOP_CAPS.items())))

    def candidate(self, name, age_s=0):
        d = self.control / name
        d.mkdir()
        (d / "candidate.json").write_bytes(b'{"x": 1}')
        if age_s:
            t = time.time() - age_s
            os.utime(d / "candidate.json", (t, t))

    def test_listed_from_the_derived_path_without_an_option(self):
        self.candidate(ID1)
        code, out, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn(f"- control - {ID1} candidate age=", out)
        code, out, _ = self.run_cli("show", "-", "control", "-", ID1)
        self.assertEqual(code, 0, "show needs no option with hop")

    def test_the_option_is_refused_beside_hop_naming_the_derived_path(self):
        code, _out, err = self.run_cli("list", "--control-dir", str(self.tmp / "elsewhere"))
        self.assertEqual(code, 1)
        self.assertIn(str(self.control), err)

    def test_past_the_threshold_it_is_reported_expired_and_left(self):
        threshold = self.cfg.ingress_quarantine_days * 86400
        self.candidate(ID1, age_s=threshold + 60)
        self.candidate(ID2, age_s=60)
        _code, out, _ = self.run_cli("list")
        lines = {line.split()[3]: line for line in out.splitlines() if " control " in line}
        self.assertIn("expired", lines[ID1])
        self.assertIn("expires_in=", lines[ID2])
        self.assertTrue((self.control / ID1).exists(), "an expired item was removed")
        doc = ingress.status_doc(self.cfg)["control"]
        self.assertEqual((doc["items"], doc["expired"], doc["report_threshold_s"]),
                         (2, 1, threshold))
        self.assertNotIn(ID1, json.dumps(doc), "an item id reached status")
