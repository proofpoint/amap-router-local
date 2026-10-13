"""No test module reads a clock at IMPORT time.

A time taken at import is stale by however long the run takes to reach the
test that uses it, so a margin that holds on a fast machine fails on a slow
one (`test_ingress_pump.later` is the case that did). This scans every test
module's import-time code (module level, class bodies, decorators and default
arguments; never a function or lambda body) for a call to a clock.

A tripwire, not a certificate: it sees only calls by these names, made
directly in that code. The positive control proves the scanner can find one,
so a green run is not the scan silently finding nothing to look at."""
import ast
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).parent
CLOCKS = frozenset({"now", "utcnow", "time", "time_ns", "monotonic", "monotonic_ns",
                    "perf_counter", "utc_ts", "today", "gmtime", "localtime"})


def _name(func):
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _import_time_nodes(body):
    for st in body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield from st.decorator_list
            yield from st.args.defaults
            yield from (d for d in st.args.kw_defaults if d is not None)
        elif isinstance(st, ast.ClassDef):
            yield from st.decorator_list
            yield from st.bases
            yield from _import_time_nodes(st.body)
        else:
            yield st


def import_time_clocks(source: str, filename: str = "<src>"):
    """`(line, call)` for every clock call `source` makes at import."""
    tree = ast.parse(source, filename)
    hits = []
    for node in _import_time_nodes(tree.body):
        deferred = {id(x) for lam in ast.walk(node) if isinstance(lam, ast.Lambda)
                    for x in ast.walk(lam.body)}
        for n in ast.walk(node):
            if (isinstance(n, ast.Call) and _name(n.func) in CLOCKS
                    and id(n) not in deferred):
                hits.append((n.lineno, ast.get_source_segment(source, n)))
    return hits


class ImportTimeClockTests(unittest.TestCase):

    def test_the_scanner_finds_each_import_time_form(self):
        src = ("from datetime import datetime\nimport time\n"
               "A = datetime.now()\n"
               "class C:\n    B = time.time()\n"
               "def f(x=time.monotonic()):\n    return datetime.now()\n"
               "G = lambda: time.time()\n")
        self.assertEqual([line for line, _ in import_time_clocks(src)], [3, 5, 6])

    def test_no_test_module_reads_a_clock_at_import(self):
        modules = sorted(TESTS_DIR.glob("*.py"))
        self.assertGreater(len(modules), 100, "the scan found nothing to look at")
        found = [f"{p.name}:{line}: {call}" for p in modules
                 for line, call in import_time_clocks(p.read_text(encoding="utf-8"), str(p))]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
