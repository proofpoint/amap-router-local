"""Every validator regex is anchored with `\\Z` and applied with `fullmatch`.

`$` also matches just before a trailing newline, so `^req-1\\.json$` with
`.match` accepts the directory entry `req-1.json\\n`. Each site below gets a
behavioural witness: a name (or value) ending in a newline is refused where
its newline-free twin is accepted. With both defences in place, restoring
only one of them is still safe, so no behavioural test can see it; the
structural tests at the bottom pin both rules across the package instead.
"""
from __future__ import annotations

import ast
import importlib
import json
import os
import pkgutil
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import router
from router import binding, exposure, firstsight, outbound, outcomes
from router.config import ConfigError, load_obj
from router.tests import helpers

NID = "0123456789abcdef0123456789abcdef"
ROUTER_DIR = Path(router.__file__).resolve().parent


class OutboundRequestNameTests(helpers.RouterTestCase):
    """`outbound.REQ_NAME_RE`: the drain never opens `req-<id>.json\\n`."""

    def test_a_trailing_newline_is_skipped_and_never_drained(self):
        cfg = self.make_config({"alpha": []})
        helpers.write_request(cfg, "alpha", "00000001", filename="req-00000001.json\n")
        helpers.write_request(cfg, "alpha", "00000002")             # the twin
        summary = outbound.drain_instance(cfg, "alpha")
        self.assertEqual(summary["outbound_skipped_bad_name"], 1)
        self.assertEqual(summary["drained"], 1)
        self.assertTrue(helpers.result_path(cfg, "alpha", "00000002").is_file())
        self.assertFalse(helpers.result_path(cfg, "alpha", "00000001").exists())

    def test_a_prefixed_name_is_skipped_and_never_drained(self):
        """A pattern applied with `.search` would find `req-<id>.json` inside
        `junk-req-<id>.json`; the whole name must match."""
        cfg = self.make_config({"alpha": []})
        helpers.write_request(cfg, "alpha", "00000001", filename="junk-req-alpha.json")
        helpers.write_request(cfg, "alpha", "00000002")             # the twin
        summary = outbound.drain_instance(cfg, "alpha")
        self.assertEqual((summary["outbound_skipped_bad_name"], summary["drained"]), (1, 1))
        results = cfg.instances["alpha"].outbox_root / "results"
        self.assertEqual(sorted(p.name for p in results.iterdir()), ["00000002.json"])


class FirstSightRequestNameTests(unittest.TestCase):
    """`firstsight._REQ_NAME_RE`: the snapshot lists only names the drain
    would open."""

    def test_a_trailing_newline_is_not_snapshotted(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "req-00000001.json\n").write_text("{}")
            (Path(d) / "junk-req-gamma.json").write_text("{}")
            (Path(d) / "req-00000002.json").write_text("{}")         # the twin
            names = [e["filename"] for e in firstsight._snapshot_outbox(Path(d))]
        self.assertEqual(names, ["req-00000002.json"])


class OutcomeFileNameTests(helpers.RouterTestCase):
    """`outcomes.OUTCOME_NAME_RE`: an outcome file named with a trailing
    newline is never opened."""

    def test_a_trailing_newline_is_never_consumed(self):
        cfg = self.make_config({"alpha": []})
        seen = []
        real = outcomes._consume_one

        def spy(cfg_, name, dir_fd, filename, nid, summary):
            seen.append(filename)

        d = self.tmp / "outcomes-dir"
        d.mkdir()
        (d / f"peer-{NID}.json\n").write_text("{}")
        (d / f"x-peer-{NID}.json").write_text("{}")
        (d / f"peer-{'f' * 32}.json").write_text("{}")                # the twin
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            summary = {"peer_outcomes_seen": 0, "peer_outcome_errored": 0}
            outcomes._consume_one = spy
            outcomes._consume_names(cfg, "alpha", fd, summary, 0)
        finally:
            outcomes._consume_one = real
            os.close(fd)
        self.assertEqual(seen, [f"peer-{'f' * 32}.json"])


class OutcomeRecordNameTests(helpers.RouterTestCase):
    """`outcomes._RECORD_NAME_RE`: a record file named with a trailing
    newline is not one this router wrote."""

    def _plant(self, cfg, suffix):
        ledger = binding.ledger_path(cfg.state_dir, "alpha", NID)
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(json.dumps({"tree": "peer", "from_instance": "beta"}))
        recs = cfg.state_dir / "alpha" / "outcomes"
        recs.mkdir(parents=True, exist_ok=True)
        (recs / f"peer-{NID}.denied.json{suffix}").write_text(json.dumps(
            {"outcome": "denied", "recorded_ts": "2026-10-11T00:00:00Z"}))

    def test_a_trailing_newline_is_not_a_record(self):
        cfg = self.make_config({"alpha": []})
        self._plant(cfg, "\n")
        self.assertEqual(outcomes.placed_but_denied(cfg, "alpha"), [])

    def test_the_twin_is_a_record(self):
        cfg = self.make_config({"alpha": []})
        self._plant(cfg, "")
        self.assertEqual([r["notice_id"] for r in outcomes.placed_but_denied(cfg, "alpha")], [NID])


class ExposureNoticeFileTests(helpers.RouterTestCase):
    """`exposure._NOTICE_FILE_RE`, at both of its sites."""

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alpha": []})
        now = datetime.now(timezone.utc)
        self.start, self.end = now - timedelta(days=1), now + timedelta(days=1)

    def test_the_ledger_scan_skips_a_trailing_newline(self):
        d = binding.ledger_dir(self.cfg.state_dir, "alpha")
        d.mkdir(parents=True)
        (d / "notice-abc.json\n").write_text("{}")
        (d / "x-notice-ghi.json").write_text("{}")
        (d / "notice-def.json").write_text("{}")                     # the twin
        ids, _ = exposure._scan_ledger(self.cfg.state_dir, "alpha", self.start, self.end)
        self.assertEqual(ids, {"def"})

    def test_the_notice_scan_skips_a_trailing_newline(self):
        notices = self.cfg.instances["alpha"].inbox_root / "notices"
        notices.mkdir(parents=True, exist_ok=True)
        (notices / "notice-abc.json\n").write_text("{}")
        assessed, latest = exposure._scan_unledgered_notices(
            self.cfg, "alpha", set(), self.start, self.end)
        self.assertTrue(assessed)
        self.assertIsNone(latest)
        (notices / "notice-def.json").write_text("{}")               # the twin
        assessed, latest = exposure._scan_unledgered_notices(
            self.cfg, "alpha", set(), self.start, self.end)
        self.assertIsNotNone(latest)


class NoticeIdTests(unittest.TestCase):
    """`binding._NOTICE_ID_RE`: an in_reply_to ending in a newline never
    becomes a path, even when a file by that name exists."""

    def test_a_trailing_newline_never_resolves(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            for nid in ("abc\n", "abc"):
                p = binding.ledger_path(state, "alpha", nid)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps({"from_instance": "beta"}))
            self.assertIsNone(binding.read_ledger_record(state, "alpha", "abc\n"))
            self.assertIsNotNone(binding.read_ledger_record(state, "alpha", "abc"))


class FleetDomainTests(unittest.TestCase):
    """`config._FLEET_DOMAIN_RE`: a domain ending in a newline is refused at
    load, where it would otherwise become every address's suffix."""

    def doc(self, base, domain):
        root = base / "alpha"
        root.mkdir(exist_ok=True)
        return {"state_dir": str(base / "state"), "fleet_domain": domain,
                "instances": {"alpha": {"namespace": str(root), "peers": []}}}

    def test_a_trailing_newline_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            self.assertEqual(load_obj(self.doc(base, "example.org")).fleet_domain, "example.org")
            with self.assertRaises(ConfigError) as cm:
                load_obj(self.doc(base, "example.org\n"))
            self.assertIn("config.fleet_domain", str(cm.exception))


def _router_modules():
    for info in pkgutil.iter_modules(router.__path__):
        yield info.name, importlib.import_module("router." + info.name)


def dollar_anchors(pattern):
    """Offsets of every `$` used as an ANCHOR in `pattern`: not escaped (an
    odd run of backslashes before it) and not inside a character class.
    Tracks escape parity and class state character by character, so
    `\\\\$` (an escaped backslash, then an anchor) is found and `\\$` and
    `[$]` are not."""
    out, i, in_class = [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2                      # the escaped character, whatever it is
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if pattern[i + 1:i + 2] == "^":
                i += 1
            if pattern[i + 1:i + 2] == "]":
                i += 1                  # a leading ] is literal
        elif c == "$":
            out.append(i)
        i += 1
    return out


class StructuralTests(unittest.TestCase):
    """The two rules, across the package, so that restoring either one alone
    (which no behavioural test can see) still goes red."""

    def test_no_module_level_pattern_anchors_with_dollar(self):
        checked = 0
        for mod_name, mod in _router_modules():
            for attr, value in vars(mod).items():
                if isinstance(value, re.Pattern):
                    checked += 1
                    with self.subTest(pattern=f"{mod_name}.{attr}"):
                        self.assertEqual(dollar_anchors(value.pattern), [],
                                         "anchor with \\Z: `$` matches before a trailing newline")
        self.assertGreater(checked, 20, "the sweep found too few patterns to be checking anything")

    def test_the_anchor_scanner(self):
        """Controls for `dollar_anchors` itself."""
        for pattern, want in ((r"a$", [1]), (r"a\$", []), (r"a\\$", [3]),
                              (r"a\\\$", []), (r"[$]", []), (r"[^$]$", [4]),
                              (r"[\]$]", []), (r"[]$]x$", [5]), (r"(?=.{1}$)", [7]),
                              (r"a\Z", [])):
            with self.subTest(pattern=pattern):
                self.assertEqual(dollar_anchors(pattern), want)

    def test_patterns_are_applied_with_fullmatch(self):
        """No `.match(` or `.search(` call in production code, on a compiled
        pattern or on `re`: a validator states the whole value it accepts."""
        calls = 0
        for path in sorted(ROUTER_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "fullmatch":
                        calls += 1
                    with self.subTest(at=f"{path.name}:{node.lineno}"):
                        self.assertNotIn(node.func.attr, ("match", "search"),
                                         "use fullmatch (and anchor with \\Z)")
        self.assertGreater(calls, 20, "the sweep found too few fullmatch calls to be checking anything")


if __name__ == "__main__":
    unittest.main()
