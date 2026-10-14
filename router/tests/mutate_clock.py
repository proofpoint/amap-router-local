"""Single-rule mutants for the one production wall-clock read
(`router/clock.py`), each run against the test that names it:
`test_one_clock.py` (the tripwire), `test_clock_child.py` (an installed source
is what the driven paths observe), `test_clock.py` and `test_process_reset.py`
(the source's lifecycle).

Run from the repository root:

    AMAP_SPEC_REPO=<amap-spec checkout> python3 -B router/tests/mutate_clock.py

Same discipline as `mutate_reuse.py`: one rule per mutant, bytecode caching
OFF and `__pycache__` cleared before each run, the file restored after, and a
mutant is RED only when unittest reports the named test as a FAILURE (an
ERROR is not red). Exit 0 only when the named tests are green unmutated and
every mutant turns every named test red. Not a test module itself (its name
keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

ONE = "router.tests.test_one_clock.OneClockTests.test_no_module_reads_the_wall_clock_but_clock"
SCAN = "router.tests.test_one_clock.OneClockTests.test_the_scan_sees_the_package"
ALLOW = "router.tests.test_one_clock.OneClockTests.test_the_monotonic_allowance_is_exact_and_in_use"
W2 = "router.tests.test_clock_child.InstalledSourceTests."
LIFE = "router.tests.test_clock_child.LifecycleTests.test_a_modelled_restart_keeps_the_source_and_reset_removes_it"
UNIT = "router.tests.test_clock."
RESET = "router.tests.test_process_reset.CompletenessTests.test_every_container_is_process_state_or_a_constant"

M = [
 ("C1 R1 utc_ts reads the wall clock itself", "router/util.py",
  "    return format_utc_ts(clock.now())\n",
  "    return datetime.now(timezone.utc).strftime(_UTC_TS_FORMAT)\n",
  [ONE, W2 + "test_every_written_time_is_one_the_source_emitted"]),
 ("C2 R1 peer_startup reads the wall clock", "router/service.py",
  "peerjournal.apply_window(cfg.state_dir, clock.now(), cfg.delegation)",
  "peerjournal.apply_window(cfg.state_dir, datetime.now(timezone.utc), cfg.delegation)",
  [ONE]),
 ("C3 R1 the datetime.datetime.now chain", "router/status.py",
  "    return (clock.now() - then).total_seconds()\n",
  "    import datetime as _dtm\n    return (_dtm.datetime.now(timezone.utc) - then).total_seconds()\n",
  [ONE]),
 ("C4 R1 a re-export: util.datetime.now", "router/console.py",
  "    return (clock.now() - parsed).total_seconds()\n",
  "    from . import util\n    return (util.datetime.now(timezone.utc) - parsed).total_seconds()\n",
  [ONE]),
 ("C5 R1 time.clock_gettime(CLOCK_REALTIME)", "router/generations.py",
  "from . import clock\n",
  "from . import clock\n\n\ndef _wall():\n    import time\n"
  "    return time.clock_gettime(time.CLOCK_REALTIME)\n",
  [ONE]),
 ("C6 R1 email.utils.formatdate()", "router/deliver.py",
  "class PeerLaneUnavailable(Exception):",
  "def _date():\n    import email.utils\n    return email.utils.formatdate()\n\n\n"
  "class PeerLaneUnavailable(Exception):",
  [ONE]),
 ("C7 R1 uuid.uuid1()", "router/util.py",
  "def mint_notice_id() -> str:",
  "def _uid():\n    import uuid\n    return uuid.uuid1()\n\n\ndef mint_notice_id() -> str:",
  [ONE]),
 ("C8 R1 a second monotonic read", "router/inflight.py",
  "class Recheck:",
  "def _mono():\n    import time\n    return time.monotonic()\n\n\nclass Recheck:",
  [ONE]),
 ("C9 R2 a bare alias, referenced not called", "router/ingress.py",
  "from . import clock\n",
  "from . import clock\nfrom time import time as _t\n_f = _t\n",
  [ONE]),
 ("C10 R3 getattr(time, 'time')", "router/hoplink.py",
  "_clock = time.monotonic\n",
  "_clock = time.monotonic\n_wall = getattr(time, 'time')\n",
  [ONE]),
 ("C11 R3 importlib.import_module", "router/outcomes.py",
  "def outcomes_rel(connector_id: str) -> Path:",
  "def _mod():\n    import importlib\n    return importlib.import_module('time')\n\n\n"
  "def outcomes_rel(connector_id: str) -> Path:",
  [ONE]),
 ("C12 R4 from .util import datetime", "router/roster.py",
  "def roster_dir(cfg: RouterConfig) -> Optional[Path]:",
  "from .util import datetime  # noqa: E402\n\n\ndef roster_dir(cfg: RouterConfig) -> Optional[Path]:",
  [ONE]),
 ("C13 R4 the time module rebound", "router/firstsight.py",
  "def marker_path(state_dir: Path, name: str, *, state_key: Optional[str] = None) -> Path:",
  "def _t():\n    import time\n    t = time\n    return t\n\n\n"
  "def marker_path(state_dir: Path, name: str, *, state_key: Optional[str] = None) -> Path:",
  [ONE]),
 ("C14 R5 a module-level cached read used by utc_ts", "router/util.py",
  "    return format_utc_ts(clock.now())\n",
  "    return _START\n\n\n_START = format_utc_ts(clock.now())\n",
  [ONE, W2 + "test_times_never_go_backwards_and_more_than_one_is_seen"]),
 ("C15 R5 a default argument reads the clock", "router/service.py",
  "from . import clock\n",
  "from . import clock\n\n\ndef _at(now=clock.now()):\n    return now\n",
  [ONE]),
 ("C16 isolation: the router installs a source", "router/service.py",
  "peerjournal.apply_window(cfg.state_dir, clock.now(), cfg.delegation)",
  "clock.install(clock.fixed(clock.now()))\n"
  "        peerjournal.apply_window(cfg.state_dir, clock.now(), cfg.delegation)",
  [ONE]),
 ("C17 the scan glob matches nothing", "router/tests/test_one_clock.py",
  '    return sorted(p for p in ROUTER.rglob("*.py")',
  '    return sorted(p for p in ROUTER.rglob("*.pyx")',
  [SCAN]),
 ("C18 now() ignores the installed source", "router/clock.py",
  "    if _INSTALLED:\n",
  "    if False:\n",
  [UNIT + "ReadTests.test_an_installed_source_is_what_every_read_returns",
   W2 + "test_every_written_time_is_one_the_source_emitted"]),
 ("C19 a naive source accepted", "router/clock.py",
  "        if not isinstance(t, datetime) or t.utcoffset() is None:\n",
  "        if not isinstance(t, datetime):\n",
  [UNIT + "ReadTests.test_a_naive_source_is_refused"]),
 ("C20 the source registered as process state", "router/hoplink.py",
  '    "hoplink": ("_SENDERS",',
  '    "clock": ("_INSTALLED",),\n    "hoplink": ("_SENDERS",',
  [RESET, UNIT + "LifecycleTests.test_the_source_survives_reset_process_state", LIFE]),
 ("C21 strict falls back to the real clock", "router/clock.py",
  "    if _STRICT:\n",
  "    if False:\n",
  [UNIT + "StrictTests.test_strict_raises_when_the_source_is_lost_other_than_by_reset"]),
 ("C22 R2 a router re-export referenced, not called", "router/generations.py",
  "from . import clock\n",
  "from . import clock\nfrom . import util as _u\n_g = _u.datetime.now\n",
  [ONE]),
 ("C23 R3 sys.modules['time']", "router/firstsight.py",
  "def marker_path(state_dir: Path, name: str, *, state_key: Optional[str] = None) -> Path:",
  "def _m():\n    import sys\n    return sys.modules['time'].time\n\n\n"
  "def marker_path(state_dir: Path, name: str, *, state_key: Optional[str] = None) -> Path:",
  [ONE]),
 ("C24 R3 from time import *", "router/roster.py",
  "def roster_dir(cfg: RouterConfig) -> Optional[Path]:",
  "from time import *  # noqa: E402,F401,F403\n\n\ndef roster_dir(cfg: RouterConfig) -> Optional[Path]:",
  [ONE]),
 ("C25 R3 operator.attrgetter over a re-export", "router/outcomes.py",
  "def outcomes_rel(connector_id: str) -> Path:",
  "def _a():\n    import operator\n    from . import util\n"
  "    return operator.attrgetter('now')(util.datetime)\n\n\n"
  "def outcomes_rel(connector_id: str) -> Path:",
  [ONE]),
 ("C26 isolation: getattr(clock, 'install')", "router/service.py",
  "peerjournal.apply_window(cfg.state_dir, clock.now(), cfg.delegation)",
  "getattr(clock, 'install')(clock.fixed(clock.now()))\n"
  "        peerjournal.apply_window(cfg.state_dir, clock.now(), cfg.delegation)",
  [ONE]),
 ("C27 the reset rule accepts a reset anywhere", "router/tests/test_one_clock.py",
  "and _raw_qual(n, aliases) == f\"{CLOCK_OWN}.reset\" and always_runs(n)]",
  "and _raw_qual(n, aliases) == f\"{CLOCK_OWN}.reset\"]",
  ["router.tests.test_one_clock.TestsResetWhatTheyInstallTests."
   "test_the_rule_finds_each_bad_form_and_passes_each_good_one"]),
 ("C28 re-exports not resolved", "router/tests/test_one_clock.py",
  "    return _resolve(_raw_qual(node, aliases))",
  "    return _raw_qual(node, aliases)",
  ["router.tests.test_one_clock.ControlTests.test_each_banned_form_is_found"]),
 ("C29 a write inside one operation goes backwards", "router/util.py",
  "    return format_utc_ts(clock.now())\n",
  "    _H.append(clock.now())\n"
  "    return format_utc_ts(_H[-3] if len(_H) % 2 == 0 and len(_H) > 2 else _H[-1])\n\n\n"
  "_H = []\n",
  [W2 + "test_writes_within_an_operation_never_go_backwards"]),
 ("C30 a read held back, then written after a later one", "router/util.py",
  "    return format_utc_ts(clock.now())\n",
  "    a, b = clock.now(), clock.now()\n    _Q.append(a)\n"
  "    return format_utc_ts(b if len(_Q) % 2 else _Q[-2])\n\n\n_Q = []\n",
  [W2 + "test_writes_within_an_operation_never_go_backwards"]),
 ("C31 an append repeats a stamp from an earlier operation", "router/peerjournal.py",
  "    line = json.dumps(dict(fields, ts=format_utc_ts(now), act=act, by=peerclock.operator_by()),\n",
  "    first = globals().setdefault(\"_FIRST_TS\", format_utc_ts(now))\n"
  "    line = json.dumps(dict(fields, ts=first, act=act, by=peerclock.operator_by()),\n",
  [W2 + "test_writes_within_an_operation_never_go_backwards"]),
 ("C32 the judge keeps the lowest stamp as its high-water", "router/tests/test_clock_child.py",
  "            high = max(vals) if high is None else max(high, max(vals))\n",
  "            high = min(vals) if high is None else max(high, min(vals))\n",
  ["router.tests.test_clock_child.BackwardsTests."
   "test_a_multi_valued_write_then_an_earlier_one_is_backwards"]),
 ("C33 appended lines diffed as a set, hiding a repeat", "router/tests/clock_child_flows.py",
  "        return len(lines), [v for line in lines[old:] for _k, v in _pairs(_parse(line))]\n",
  "        seen = {v for line in lines[:old] for _k, v in _pairs(_parse(line))}\n"
  "        return len(lines), [v for line in lines[old:] for _k, v in _pairs(_parse(line))\n"
  "                            if v not in seen]\n",
  ["router.tests.test_clock_child.BackwardsTests."
   "test_an_append_repeating_an_older_stamp_on_the_same_path_is_backwards"]),
 ("C34 the reset rule accepts a conditional reset", "router/tests/test_one_clock.py",
  "        if not isinstance(stmt, ast.Expr):\n            return False\n",
  "        while stmt is not None and not isinstance(stmt, ast.Expr):\n"
  "            stmt = parents.get(id(stmt))\n"
  "        owner = parents.get(id(stmt))\n"
  "        while owner is not None and not isinstance(\n"
  "                owner, (ast.Try, ast.FunctionDef, ast.AsyncFunctionDef)):\n"
  "            stmt, owner = owner, parents.get(id(owner))\n",
  ["router.tests.test_one_clock.TestsResetWhatTheyInstallTests."
   "test_the_rule_finds_each_bad_form_and_passes_each_good_one"]),
 ("C35 a dynamic importer taken as a value", "router/outcomes.py",
  "def outcomes_rel(connector_id: str) -> Path:",
  "def _imp():\n    import importlib\n    return importlib.import_module\n\n\n"
  "def outcomes_rel(connector_id: str) -> Path:",
  [ONE]),
]


def _red(r) -> bool:
    """RED only when the named test FAILED (an assertion in it did not
    hold); an ERROR proves the mutant broke something, not that the test
    pins the rule."""
    out = r.stdout + r.stderr
    return (r.returncode != 0 and "\nFAIL: " in "\n" + out
            and "FAILED (failures=" in out)


def _clear() -> None:
    for d in pathlib.Path("router").rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    ok = True
    _clear()
    named = sorted({t for *_, tests in M for t in tests} | {ALLOW})
    clean = subprocess.run([sys.executable, "-B", "-m", "unittest", *named],
                           capture_output=True, text=True)
    if clean.returncode != 0:
        print("the named tests are not green on unmutated code:\n" + clean.stderr[-2000:])
        return 1
    for label, f, old, new, tests in M:
        path = pathlib.Path(f)
        orig = path.read_text()
        if orig.count(old) != 1:
            print(f"{label}: ANCHOR FOUND {orig.count(old)} TIMES")
            ok = False
            continue
        path.write_text(orig.replace(old, new))
        _clear()
        try:
            for t in tests:
                r = subprocess.run([sys.executable, "-B", "-m", "unittest", t],
                                   capture_output=True, text=True)
                red = _red(r)
                ok &= red
                verdict = "RED" if red else ("ERROR only (not RED)" if r.returncode
                                             else "GREEN (survived)")
                print(f"{label:52s} {t.split('.')[-1][:58]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
