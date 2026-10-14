"""No production module reads the wall clock except through `router.clock`.

`clock.now()` is the one production wall-clock read (`router/clock.py`), and
`util.utc_ts()` formats it. This scans every module under `router/` except
`tests/` and `clock.py` itself, and fails on any other read, under five rules:

- R1, banned NAMES whatever the base: a call of `now`, `utcnow`, `today`,
  `time_ns`, `clock_gettime`, `clock_gettime_ns`, `gmtime`, `localtime`,
  `ctime`, `asctime`, `formatdate`, `make_msgid`, `uuid1`, `monotonic`,
  `monotonic_ns`, `perf_counter` or `perf_counter_ns`, or a call of `time` with
  no arguments. Re-exports (`util.datetime.now(...)`) and chains
  (`datetime.datetime.now(...)`) need no resolving to be caught. The one
  allowed call is `clock.now()`, resolved to this package's `clock` module.
- R2, banned MEMBERS on a resolved stdlib base, as any reference, call or not:
  `BANNED_MEMBERS` below, reached through `import x as y`,
  `from x import y as z` or a bare imported name (`from time import time as
  _t; f = _t`). `time.strftime` is among them: with one argument it formats
  the local time now; a datetime's own `strftime` is not.
- R3, reflective and dynamic access: `getattr`/`setattr`/`hasattr`/`delattr`/
  `vars` on a clock base or naming a banned member, `__dict__` of a clock
  base, and any `importlib.import_module` or `__import__` call.
- R4, re-export imports and rebinding: `from .<module> import datetime|date|
  time` from this package, and a clock base (the `time`, `datetime`,
  `email.utils` or `uuid` module, or the `datetime`/`date` class) assigned,
  returned, stored in a container or passed as an argument (other than to
  `isinstance`/`issubclass`).
- R5, import-time reads: any clock call, `clock.now()` and `utc_ts()`
  included, at module scope, in a default, a decorator or a class body, which
  would run before a test installs its source and stay real for the process.
  This reuses the test modules' import-time scanner.

Allowed, exactly: the one `time.monotonic` reference in `hoplink` (its
`_clock`, whose consumers are status ages and log levels). What is not a
clock read at all: a time passed in as data and a file time (`st_mtime`).

Also: no router module but `clock.py` references `clock.install`,
`clock.reset`, `_INSTALLED` or `_STRICT`; and a test that installs a clock
also resets it, in the same class or function.

A tripwire, not a certificate: it sees names in source. The controls prove
each form is found and each allowed form is not, and the scan's file count
proves it is looking at the package."""
from __future__ import annotations

import ast
import collections
import pathlib
import unittest

import router
from router.tests.test_no_import_time_clocks import import_time_clocks

ROUTER = pathlib.Path(router.__file__).parent

BANNED_NAMES = frozenset({
    "now", "utcnow", "today", "time_ns", "clock_gettime", "clock_gettime_ns", "gmtime",
    "localtime", "ctime", "asctime", "formatdate", "make_msgid", "uuid1", "monotonic",
    "monotonic_ns", "perf_counter", "perf_counter_ns"})

BANNED_MEMBERS = frozenset({
    "time.time", "time.time_ns", "time.clock_gettime", "time.clock_gettime_ns",
    "time.gmtime", "time.localtime", "time.ctime", "time.asctime", "time.strftime",
    "time.monotonic", "time.monotonic_ns", "time.perf_counter", "time.perf_counter_ns",
    "datetime.datetime.now", "datetime.datetime.utcnow", "datetime.datetime.today",
    "datetime.date.today", "email.utils.formatdate", "email.utils.localtime",
    "email.utils.make_msgid", "uuid.uuid1"})

#: Modules and classes whose members the rules guard.
CLOCK_BASES = frozenset({"time", "datetime", "datetime.datetime", "datetime.date",
                         "email.utils", "uuid"})

#: (module, qualified name): the exact number of references allowed.
ALLOWED = {("hoplink", "time.monotonic"): 1}

CLOCK_OWN = "router.clock"
ISOLATED = frozenset({"install", "reset", "_INSTALLED", "_STRICT"})


def _aliases(tree: ast.AST, package: str = "router") -> dict:
    """Local name -> the dotted name it is bound to, from every import."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    out[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package if not node.module else f"{package}.{node.module}"
            else:
                base = node.module or ""
            for a in node.names:
                out[a.asname or a.name] = f"{base}.{a.name}"
    return out


def _qual(node: ast.AST, aliases: dict):
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _qual(node.value, aliases)
        return f"{base}.{node.attr}" if base else None
    return None


def _call_name(func: ast.AST):
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def scan(source: str, module: str, package: str = "router"):
    """Every `(line, rule, text)` finding in `source`, with no allowance."""
    tree = ast.parse(source)
    aliases = _aliases(tree, package)
    seg = lambda n: ast.get_source_segment(source, n) or ast.dump(n)  # noqa: E731
    found = []

    def hit(node, rule):
        found.append((node.lineno, rule, seg(node)))

    # Name nodes that are an Attribute's base are judged with the Attribute.
    bases = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    # A tuple or list inside a subscript is a type (`Tuple[datetime, str]`).
    typed = {id(n.slice) for n in ast.walk(tree) if isinstance(n, ast.Subscript)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in BANNED_NAMES and _qual(node.func, aliases) != f"{CLOCK_OWN}.now":
                hit(node, "R1")
            elif name == "time" and not node.args and not node.keywords:
                hit(node, "R1")
            q = _qual(node.func, aliases)
            if name == "__import__" or q == "importlib.import_module" or (
                    isinstance(node.func, ast.Name) and q is None and name == "import_module"):
                hit(node, "R3")
            if isinstance(node.func, ast.Name) and node.func.id in (
                    "getattr", "setattr", "hasattr", "delattr", "vars") and node.args:
                target = _qual(node.args[0], aliases)
                named = (len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                         and node.args[1].value in BANNED_NAMES | {"time", "strftime"})
                if target in CLOCK_BASES or named:
                    hit(node, "R3")
            if not (isinstance(node.func, ast.Name) and node.func.id in ("isinstance", "issubclass")):
                for a in list(node.args) + [k.value for k in node.keywords]:
                    if isinstance(a, ast.Name) and _qual(a, aliases) in CLOCK_BASES:
                        hit(a, "R4")
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load) \
                and id(node) not in bases:
            q = _qual(node, aliases)
            if q in BANNED_MEMBERS:
                hit(node, "R2:" + q)
        if isinstance(node, ast.Attribute) and node.attr == "__dict__" \
                and _qual(node.value, aliases) in CLOCK_BASES:
            hit(node, "R3")
        if isinstance(node, ast.ImportFrom):
            pkg = node.level or (node.module or "").split(".")[0] == package
            if pkg and any(a.name in ("datetime", "date", "time") for a in node.names):
                hit(node, "R4")
            src_mod = (f"{package}.{node.module}" if node.level and node.module
                       else node.module if not node.level else package)
            if src_mod == CLOCK_OWN and any(a.name in ISOLATED for a in node.names):
                hit(node, "isolation")
        values = []
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return)) \
                and node.value is not None:
            values.append(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and id(node) not in typed:
            values.extend(node.elts)
        if isinstance(node, ast.Dict):
            values.extend(v for v in node.values if v is not None)
        for v in values:
            if isinstance(v, ast.Name) and _qual(v, aliases) in CLOCK_BASES:
                hit(v, "R4")
        if isinstance(node, (ast.Name, ast.Attribute)):
            q = _qual(node, aliases)
            if q and q.startswith(CLOCK_OWN + ".") and q.split(".")[-1] in ISOLATED:
                hit(node, "isolation")
    for line, text in import_time_clocks(source, module):
        found.append((line, "R5", text))
    return found


def production_modules():
    return sorted(p for p in ROUTER.rglob("*.py")
                  if "tests" not in p.relative_to(ROUTER).parts and p.name != "clock.py")


def violations():
    """Findings over the real package, after the exact allowances."""
    out, used = [], collections.Counter()
    for path in production_modules():
        module = ".".join(path.relative_to(ROUTER).with_suffix("").parts)
        for line, rule, text in scan(path.read_text(encoding="utf-8"), module):
            key = (module, rule[3:]) if rule.startswith("R2:") else None
            if key in ALLOWED:
                used[key] += 1
                if used[key] <= ALLOWED[key]:
                    continue
            out.append(f"{module}:{line}: {rule}: {text}")
    return out, used


class OneClockTests(unittest.TestCase):

    def test_no_module_reads_the_wall_clock_but_clock(self):
        bad, _used = violations()
        self.assertEqual(bad, [], "a wall-clock read outside router.clock:\n" + "\n".join(bad))

    def test_the_monotonic_allowance_is_exact_and_in_use(self):
        _bad, used = violations()
        self.assertEqual(dict(used), ALLOWED,
                         "an allowance that matches nothing is a stale exemption")

    def test_the_scan_sees_the_package(self):
        mods = production_modules()
        self.assertGreaterEqual(len(mods), 30, "the scan found almost nothing: it is not scanning")
        self.assertEqual(len(mods), len(list(ROUTER.glob("*.py"))) - 1,
                         "every top-level module but clock.py is scanned")
        self.assertIn(ROUTER / "util.py", mods)
        self.assertNotIn(ROUTER / "clock.py", mods)


def _rules(src):
    return [r.split(":")[0] for _l, r, _t in scan(src, "synthetic")]


class ControlTests(unittest.TestCase):
    """Each banned form is found; each allowed form is not."""

    FOUND = {
        "direct now": ("from datetime import datetime, timezone\n"
                       "def f():\n    return datetime.now(timezone.utc)\n", "R1"),
        "utcnow": "import datetime\ndef f():\n    return datetime.datetime.utcnow()\n",
        "chain": "import datetime\ndef f():\n    return datetime.datetime.now()\n",
        "re-export": "from . import util\ndef f():\n    return util.datetime.now()\n",
        "date.today": "from datetime import date\ndef f():\n    return date.today()\n",
        "time.time": "import time\ndef f():\n    return time.time()\n",
        "bare time()": "from time import time\ndef f():\n    return time()\n",
        "time_ns": "import time\ndef f():\n    return time.time_ns()\n",
        "clock_gettime": ("import time\ndef f():\n"
                          "    return time.clock_gettime(time.CLOCK_REALTIME)\n"),
        "gmtime": "import time\ndef f():\n    return time.gmtime()\n",
        "strftime": "import time\ndef f():\n    return time.strftime('%Y')\n",
        "formatdate": "import email.utils\ndef f():\n    return email.utils.formatdate()\n",
        "from email import utils": "from email import utils\ndef f():\n    return utils.localtime()\n",
        "make_msgid": "from email.utils import make_msgid\ndef f():\n    return make_msgid()\n",
        "uuid1": "import uuid\ndef f():\n    return uuid.uuid1()\n",
        "monotonic": "import time\ndef f():\n    return time.monotonic()\n",
        "perf_counter": "import time\ndef f():\n    return time.perf_counter()\n",
        "reference": "import time\n_clock = time.time\n",
        "alias + reference": "from time import time as _t\ndef f():\n    g = _t\n    return g\n",
        "module alias": "import time as t\ndef f():\n    return t.time()\n",
        "getattr": "import time\ndef f():\n    return getattr(time, 'time')()\n",
        "getattr by name": "def f(m):\n    return getattr(m, 'now')()\n",
        "vars": "import time\ndef f():\n    return vars(time)['time']()\n",
        "__dict__": "import time\ndef f():\n    return time.__dict__['time']()\n",
        "import_module": "import importlib\ndef f():\n    return importlib.import_module('time')\n",
        "__import__": "def f():\n    return __import__('time')\n",
        "from-package import": "from .util import datetime\n",
        "rebinding": "import time\ndef f():\n    t = time\n    return t\n",
        "passed as argument": "import time\ndef f(g):\n    return g(time)\n",
        "in a container": "from datetime import datetime\nX = None\ndef f():\n    return [datetime]\n",
        "module level clock.now": "from . import clock\nSTART = clock.now()\n",
        "default clock.now": "from . import clock\ndef f(now=clock.now()):\n    return now\n",
        "class body utc_ts": "from .util import utc_ts\nclass C:\n    T = utc_ts()\n",
        "isolation": "from . import clock\ndef f():\n    clock.install(lambda: None)\n",
        "isolation from-import": "from .clock import reset\n",
    }

    NOT_FOUND = {
        "clock.now in a body": "from . import clock\ndef f():\n    return clock.now()\n",
        "from clock import now": "from .clock import now\ndef f():\n    return now()\n",
        "utc_ts in a body": "from .util import utc_ts\ndef f():\n    return utc_ts()\n",
        "file time": ("import os\nfrom datetime import datetime, timezone\n"
                      "def f(p):\n    st = os.stat(p)\n"
                      "    return datetime.fromtimestamp(int(st.st_mtime), tz=timezone.utc)\n"),
        "datetime.strftime": "def f(dt):\n    return dt.strftime('%Y')\n",
        "parsing": "from datetime import datetime\ndef f(s):\n    return datetime.strptime(s, '%Y')\n",
        "isinstance": "from datetime import datetime\ndef f(x):\n    return isinstance(x, datetime)\n",
        "an attribute named now": "def f(ctx):\n    return ctx.now\n",
        "time with arguments": "def f(dt):\n    return dt.replace(hour=1).time\n",
        "sleep": "import time\ndef f():\n    time.sleep(1)\n",
        "annotation": "from datetime import datetime\ndef f(x: datetime) -> datetime:\n    return x\n",
    }

    def test_each_banned_form_is_found(self):
        for label, case in self.FOUND.items():
            src = case[0] if isinstance(case, tuple) else case
            with self.subTest(label):
                self.assertTrue(_rules(src), f"{label!r} was not found")

    def test_each_allowed_form_is_not_found(self):
        for label, src in self.NOT_FOUND.items():
            with self.subTest(label):
                self.assertEqual(scan(src, "synthetic"), [], label)

    def test_a_module_level_monotonic_reference_is_allowed_only_once_in_hoplink(self):
        src = "import time\n_clock = time.monotonic\n"
        self.assertEqual(_rules(src), ["R2"])     # found; only ALLOWED forgives it


class TestsResetWhatTheyInstallTests(unittest.TestCase):
    """A test that installs a clock resets it: the source survives
    `reset_process_state`, so nothing else would."""

    def test_every_install_has_a_reset_beside_it(self):
        bad = []
        tests = ROUTER / "tests"
        for path in sorted(tests.glob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for top in tree.body:
                if not isinstance(top, (ast.ClassDef, ast.FunctionDef)):
                    continue
                attrs = {n.attr for n in ast.walk(top) if isinstance(n, ast.Attribute)}
                calls = {_call_name(n.func) for n in ast.walk(top) if isinstance(n, ast.Call)}
                if "install" in attrs and "clock" in {
                        n.value.id for n in ast.walk(top)
                        if isinstance(n, ast.Attribute) and n.attr == "install"
                        and isinstance(n.value, ast.Name)} and "reset" not in attrs \
                        and "install_clock" not in calls:
                    bad.append(f"{path.name}:{top.lineno}: {top.name}")
        self.assertEqual(bad, [], "a clock installed with no reset:\n" + "\n".join(bad))


if __name__ == "__main__":
    unittest.main()
