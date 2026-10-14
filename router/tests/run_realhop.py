"""The real-plugin matrix for the runtime capability at PLUGIN_API (3, 5):
this router's verbs and control pass against the transport plugin's REAL
runtime sender and lister, over this router's REAL filesystem port, in a
throwaway hop root. Not a test module (its name keeps it out of discovery):
the plugin is not part of this repository, so the matrix runs where a copy
of it is available, and its evidence is the run, recorded with the plugin
file's sha256. Continuous integration does not run it.

Run from the repository root:

    python3 -B router/tests/run_realhop.py --plugin <path to the plugin file>

The plugin file must hash to `ARTIFACT_SHA256`, and it is loaded through
this router's own loader with that digest as the pin. Without `--plugin`,
or with a file of another digest, the run is REFUSED (exit 2) by name: it
never skips and never passes vacuously. Each row prints PASS or FAIL, then
the total; exit 0 only when every row passes.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import types
import unittest
from pathlib import Path
from typing import Any, List, Optional, Sequence
from unittest import mock

#: The plugin artifact this router's re-point is pinned to: PLUGIN_API (3, 5).
ARTIFACT_SHA256 = "f15855c974df021c2ae5c551aff2448d934725a6796fb03434e573305d24fe93"
PLUGIN_API = (3, 5)
#: The hop caps the real plugin requires (positive byte counts, exactly these).
REAL_CAPS = {"document": 1 << 16, "request": 1 << 16, "attachment": 1 << 12, "total": 1 << 20}
#: The matrix, by row name, in order (the PR body names the same rows).
ROWS = (
    "adopt", "retire", "new", "restore_listed_live", "restore_unlisted",
    "adopt_after_unlisted_restore", "abandon_attempt", "abandon_plan",
    "settle_generation_retired", "hold_before_hand_over",
    "crash_adopt_audited_once", "crash_retire_audited_once", "crash_new_audited_once",
)

_PLUGIN_PATH: Optional[str] = None


class Refused(Exception):
    """The run cannot start: named, exit 2."""


def check_plugin(path: Optional[str]) -> str:
    """The canonical plugin path, or `Refused` naming why not."""
    if not path:
        raise Refused("no --plugin given: the matrix needs the real plugin file")
    p = os.path.realpath(path)
    try:
        digest = hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError as e:
        raise Refused(f"the plugin file cannot be read: {e}") from None
    if digest != ARTIFACT_SHA256:
        raise Refused(f"digest mismatch: the plugin file is {digest}, the pin is "
                      f"{ARTIFACT_SHA256}")
    return p


def load(path: str) -> Any:
    """Through this router's own loader, with the pinned digest. The harness
    owns the file, so it trusts its own uid as well as root."""
    from router import transport as transport_mod
    plugin = transport_mod.load_plugin(path, ARTIFACT_SHA256, trusted_uids=(0, os.geteuid()))
    if tuple(plugin.api) != PLUGIN_API:
        raise Refused(f"the plugin declares PLUGIN_API {tuple(plugin.api)}, not {PLUGIN_API}")
    if not transport_mod.runtime_capability_declared(plugin):
        raise Refused("the plugin does not declare the runtime capability")
    return plugin


def _cases():
    """The matrix's TestCase, built late so importing this module for its
    refusal checks needs no test fixtures."""
    from router import config as config_mod
    from router import fsops as fsops_mod
    from router import inflight, peercontrol
    from router import transport as transport_mod
    from router.tests import test_peercontrol as tpc

    NOW, AT = tpc.NOW, tpc.AT
    LATER = NOW.replace(minute=30)
    LATER_AT = LATER.strftime("%Y-%m-%dT%H:%M:%SZ")

    class Matrix(tpc._Control):

        def setUp(self):
            super().setUp()
            root = self.tmp / "hop"
            root.mkdir(mode=0o750)
            self.cfg.hop.caps = dict(REAL_CAPS)
            self.plugin = load(_PLUGIN_PATH)
            self.fsops = fsops_mod.FsOps(hop_root=str(root))
            self.runtime = types.SimpleNamespace(plugin=self.plugin, fsops=self.fsops)
            self.addCleanup(self.fsops.close)

        # -- helpers ---------------------------------------------------------
        def cap(self):
            return peercontrol.capability(self.cfg, self.runtime)

        def listed(self):
            return dict(self.cap().generations())

        def raw_sender(self, gen):
            """The plugin's runtime sender, built as this router builds one."""
            settings = {"hop_root": str(self.cfg.hop.root), "generation": gen,
                        "peer_uid": self.cfg.hop.peer_uid,
                        "address": peercontrol.runtime_address(self.cfg),
                        "version_write": 1, "caps": dict(REAL_CAPS)}
            return transport_mod.runtime_factory(self.plugin, "factory")(settings, self.fsops)

        def downstream(self, gen):
            """The receiving side's first sight of the generation, as the
            hub does it, through the plugin's own marker store."""
            store = self.plugin.namespace["make_marker_store"](
                {"hop_root": str(self.cfg.hop.root), "logical_id": ".runtime",
                 "generation": gen, "peer_uid": self.cfg.hop.peer_uid}, self.fsops)
            store.first_sight()
            store.write_versions([1], version_write=1)

        def admitted_out_of_band(self, gen, at=AT):
            self.assertEqual(self.raw_sender(gen).admit(at), "admitted")
            self.downstream(gen)

        def handed(self, key):
            n = self.record(key)["control"]["attempt"]["n"]
            gen = self.record(key)["control"]["attempt"]["gen"]
            return self.raw_sender(gen).has_pending(n)

        def frozen(self):
            """A pending notice whose attempt froze before its record."""
            key = self.refused()
            with mock.patch.object(inflight, "begin_reserved", side_effect=RuntimeError("crash")):
                self.send()
            return key, self.record(key)["control"]["attempt"]["gen"]

        def lose_record(self):
            (peercontrol.runtime_dir(self.cfg) / config_mod.RUNTIME_GENERATION_FILE).unlink()

        def acts(self, verb):
            return [a for a in peercontrol._audit_lines(self.state_dir) if a.get("act") == verb]

        def send_and_hand(self, key):
            """A first pass admits; the hub's first sight; a second pass hands over."""
            self.send()
            gen = self.record(key)["control"]["attempt"]["gen"]
            if not (Path(self.cfg.hop.root) / ".runtime" / gen / "down").exists():
                self.downstream(gen)
            self.send()
            self.assertTrue(self.handed(key), "handed over through the real port")

        # -- rows ------------------------------------------------------------
        def test_adopt(self):
            gen = "a" * 32
            self.admitted_out_of_band(gen, at="2026-10-01T09:00:00Z")
            peercontrol.operator_adopt(self.cfg, self.cap(), gen, now=NOW, evidence="row")
            self.assertEqual(peercontrol.recorded_admitted_at(self.cfg),
                             (gen, "2026-10-01T09:00:00Z"))
            self.assertEqual(peercontrol.runtime_pin(self.cfg, gen)["admitted_at"],
                             "2026-10-01T09:00:00Z")
            self.send_and_hand(self.refused())

        def test_retire(self):
            gen = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(gen, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            peercontrol.operator_retire(self.cfg, self.cap(), gen, now=NOW, evidence="row")
            self.assertEqual(self.listed()[gen], "retired")
            self.assertIsNone(peercontrol.recorded_admitted_at(self.cfg))

        def test_new(self):
            old = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(old, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            out = peercontrol.operator_new(self.cfg, self.cap(), now=NOW, evidence="row")
            new, at = peercontrol.recorded_admitted_at(self.cfg)
            self.assertNotEqual(new, old)
            self.assertEqual(self.listed()[old], "retired")
            self.assertEqual(at, AT, "the plan's time")
            key = self.refused()
            self.send_and_hand(key)
            self.assertEqual(self.raw_sender(new).identity()["admitted_at"], AT, out)

        def test_restore_listed_live(self):
            key, gen = self.frozen()
            self.admitted_out_of_band(gen, at="2026-10-02T09:00:00Z")
            self.lose_record()
            self.send()
            self.assertEqual(peercontrol.recorded_admitted_at(self.cfg),
                             (gen, "2026-10-02T09:00:00Z"))
            self.assertTrue(self.handed(key))

        def unlisted_restore(self):
            key, gen = self.frozen()
            self.assertNotIn(gen, self.listed(), "never admitted")
            self.lose_record()
            (peercontrol.runtime_dir(self.cfg) / gen / "transport" / "hop.json").unlink()
            self.send(now=LATER)
            self.assertEqual(peercontrol.recorded_admitted_at(self.cfg), (gen, LATER_AT))
            self.assertEqual(self.raw_sender(gen).identity()["admitted_at"], LATER_AT)
            return key, gen

        def test_restore_unlisted(self):
            key, gen = self.unlisted_restore()
            self.downstream(gen)
            self.send(now=LATER)
            self.assertTrue(self.handed(key))

        def test_adopt_after_unlisted_restore(self):
            key, gen = self.unlisted_restore()
            d = peercontrol.runtime_dir(self.cfg)
            before = ((d / config_mod.RUNTIME_GENERATION_FILE).read_bytes(),
                      (d / gen / "transport" / "hop.json").read_bytes())
            peercontrol.operator_adopt(self.cfg, self.cap(), gen, now=NOW.replace(hour=15),
                                       evidence="row")
            after = ((d / config_mod.RUNTIME_GENERATION_FILE).read_bytes(),
                     (d / gen / "transport" / "hop.json").read_bytes())
            self.assertEqual(after, before, "a byte-equal no-op")

        def test_abandon_attempt(self):
            key, gen = self.frozen()
            self.admitted_out_of_band(gen)
            self.raw_sender(gen).retire(AT)
            self.lose_record()
            roles = []
            real = transport_mod.runtime_factory

            def spy(plugin, role):
                roles.append(role)
                return real(plugin, role)
            with mock.patch.object(transport_mod, "runtime_factory", spy):
                peercontrol.operator_abandon_attempt(self.cfg, self.cap(), key, now=NOW,
                                                     evidence="row")
            self.assertEqual(self.record(key)["control"]["suppressed"],
                             peercontrol.SUPPRESS_ABANDONED)
            self.assertEqual(set(roles), {"lister"}, "lister-only")

        def test_abandon_plan(self):
            live = "b" * 32
            self.admitted_out_of_band(live)
            peercontrol.record_generation(self.cfg, "c" * 32, admitted_at=AT)
            peercontrol._begin_verb_audit(self.cfg, peercontrol.NEW_VERB, NOW,
                                          retired="c" * 32, minted="d" * 32, evidence="row")
            out = peercontrol.operator_abandon_plan(self.cfg, self.cap(), now=NOW,
                                                    evidence="row")
            self.assertFalse(peercontrol._verb_marker_path(self.cfg).exists(), out)
            self.assertNotIn("d" * 32, self.listed())
            # The PLAN's own audit line, once, saying it was abandoned.
            lines = self.acts(peercontrol.NEW_VERB)
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].get("result", "").startswith("abandoned"), lines)

        def frozen_unhanded(self):
            """An attempt whose generation is admitted (admit runs before the
            first port call) and which crashed before its first hand-over:
            no handed marker."""
            key = self.refused()
            with mock.patch.object(inflight, "advance", side_effect=RuntimeError("crash")):
                self.send()
            gen = self.record(key)["control"]["attempt"]["gen"]
            self.assertIsNotNone(self.raw_sender(gen).identity(), "admitted")
            self.assertEqual(peercontrol._inflight_entries(self.cfg, gen),
                             [f"{self.record(key)['control']['attempt']['id']}.json"],
                             "a record and no handed marker")
            self.downstream(gen)
            return key, gen

        def test_settle_generation_retired(self):
            key, gen = self.frozen_unhanded()
            if self.handed(key):
                self.skipTest("handed before the crash point")   # never reached: FAIL below
            self.raw_sender(gen).retire(AT)
            with mock.patch.object(peercontrol, "_require_writable"):   # the plugin's backstop
                self.send()
            c = self.record(key)["control"]
            self.assertEqual((c.get("sent"), (c.get("settled") or {}).get("outcome"),
                              (c.get("settled") or {}).get("reason_code")),
                             (True, "rejected", "generation_retired"))
            self.assertFalse(self.handed(key), "the plugin wrote nothing")
            self.assertEqual(peercontrol._inflight_entries(self.cfg, gen), [])

        def test_hold_before_hand_over(self):
            key, gen = self.frozen_unhanded()
            self.raw_sender(gen).retire(AT)
            self.assertEqual(self.send(), {peercontrol.UNAVAILABLE: 1})
            self.assertFalse(self.record(key)["control"].get("sent"), "held, not settled")

        def crash_after_effect(self, verb, effect, run):
            real = getattr(peercontrol, effect)

            def then_crash(*a, **k):
                real(*a, **k)
                raise SystemExit("crash right after the effect")
            with mock.patch.object(peercontrol, effect, then_crash):
                with self.assertRaises(SystemExit):
                    run()
            self.assertEqual(self.acts(verb), [], "the audit is owed")
            peercontrol.repair_audits(self.cfg, self.cap())
            peercontrol.repair_audits(self.cfg, self.cap())
            self.assertEqual(len(self.acts(verb)), 1, "exactly once")

        def test_crash_adopt_audited_once(self):
            gen = "e" * 32
            self.admitted_out_of_band(gen)
            self.crash_after_effect(peercontrol.ADOPT_VERB, "record_generation", lambda:
                                    peercontrol.operator_adopt(self.cfg, self.cap(), gen,
                                                               now=NOW, evidence="row"))

        def test_crash_retire_audited_once(self):
            gen = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(gen, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            self.crash_after_effect(peercontrol.RETIRE_VERB, "_retire_idempotent", lambda:
                                    peercontrol.operator_retire(self.cfg, self.cap(), gen,
                                                                now=NOW, evidence="row"))

        def test_crash_new_audited_once(self):
            old = peercontrol.generation(self.cfg, self.cap(), now=NOW)
            self.admitted_out_of_band(old, at=peercontrol.recorded_admitted_at(self.cfg)[1])
            self.crash_after_effect(peercontrol.NEW_VERB, "record_generation", lambda:
                                    peercontrol.operator_new(self.cfg, self.cap(), now=NOW,
                                                             evidence="row"))

    return Matrix


class _Result(unittest.TextTestResult):

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.rows: List[tuple] = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.rows.append((test._testMethodName[5:], "PASS", ""))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows.append((test._testMethodName[5:], "FAIL", self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        super().addError(test, err)
        self.rows.append((test._testMethodName[5:], "FAIL", self._exc_info_to_string(err, test)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows.append((test._testMethodName[5:], "FAIL", f"skipped: {reason}"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    global _PLUGIN_PATH
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plugin", help="the plugin file (must hash to the pinned digest)")
    args = ap.parse_args(argv)
    try:
        _PLUGIN_PATH = check_plugin(args.plugin)
        load(_PLUGIN_PATH)
    except Refused as e:
        print(f"run_realhop: REFUSED: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 -- the loader's refusal, named
        print(f"run_realhop: REFUSED: the loader refused the plugin: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 2
    matrix = _cases()
    suite = unittest.TestSuite(matrix(f"test_{row}") for row in ROWS)
    runner = unittest.TextTestRunner(stream=open(os.devnull, "w"), resultclass=_Result,
                                     verbosity=0)
    result = runner.run(suite)
    print(f"plugin sha256 {ARTIFACT_SHA256} PLUGIN_API {PLUGIN_API}")
    for name, verdict, detail in result.rows:
        print(f"{verdict} {name}")
        if detail:
            print("    " + detail.strip().splitlines()[-1])
    passed = sum(1 for _n, v, _d in result.rows if v == "PASS")
    print(f"{passed}/{len(ROWS)} rows PASS")
    return 0 if passed == len(ROWS) == len(result.rows) else 1


if __name__ == "__main__":
    # Run as a script from the repository root: the package is beside it.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    sys.exit(main())
