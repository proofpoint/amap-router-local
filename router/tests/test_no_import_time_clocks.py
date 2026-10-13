"""No test module reads a clock at IMPORT time.

A time taken at import is stale by however long the run takes to reach the
test that uses it, so a margin that holds on a fast machine fails on a slow
one (`test_ingress_pump.later` is the case that did). This scans every test
module's import-time code for a call to a clock.

Import-time code is what runs when the module is imported: module-level
statements, including everything nested in a module-level `if`, `try`,
`for` or `with`; each class body, with its bases, keywords and decorators;
and, for every function, async function and lambda, its decorators, its
defaults and keyword-only defaults, and its annotations. Never a function or
lambda BODY, at any depth.

Annotations are scanned always, even under `from __future__ import
annotations` (where they are not evaluated): over-reporting a clock in an
annotation costs nothing, and nobody writes one.

A tripwire, not a certificate: it sees only calls by these names, made
directly in that code. The controls prove the scanner finds each import-time
form and skips each deferred one, so a green run is not the scan silently
finding nothing to look at."""
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


class _ImportTime(ast.NodeVisitor):
    """Visits only what is evaluated at import (module docstring)."""

    def __init__(self):
        self.hits = []

    def visit_Call(self, node):
        if _name(node.func) in CLOCKS:
            self.hits.append(node)
        self.generic_visit(node)

    def _arguments(self, args, annotations=True):
        for d in list(args.defaults) + [d for d in args.kw_defaults if d is not None]:
            self.visit(d)
        if annotations:
            for a in (list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
                      + [args.vararg, args.kwarg]):
                if a is not None and a.annotation is not None:
                    self.visit(a.annotation)

    def visit_FunctionDef(self, node):
        for d in node.decorator_list:
            self.visit(d)
        self._arguments(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        # The body runs at call time: not visited.

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        self._arguments(node.args, annotations=False)
        # The body runs at call time: not visited.

    def visit_ClassDef(self, node):
        for x in list(node.decorator_list) + list(node.bases):
            self.visit(x)
        for k in node.keywords:
            self.visit(k.value)
        for st in node.body:
            self.visit(st)


def import_time_clocks(source: str, filename: str = "<src>"):
    """`(line, call)` for every clock call `source` makes at import."""
    v = _ImportTime()
    v.visit(ast.parse(source, filename))
    return [(n.lineno, ast.get_source_segment(source, n)) for n in v.hits]


class ImportTimeClockTests(unittest.TestCase):

    def lines(self, src):
        return [line for line, _ in import_time_clocks(src)]

    def test_the_scanner_finds_each_import_time_form(self):
        cases = {
            "module level": "A = datetime.now()\n",
            "class body": "class C:\n    B = time.time()\n",
            "default": "def f(x=time.monotonic()):\n    pass\n",
            "kw-only default": "def f(*, x=time.time()):\n    pass\n",
            "decorator": "@deco(time.time())\ndef f():\n    pass\n",
            "class decorator": "@deco(time.time())\nclass C:\n    pass\n",
            "class keyword": "class C(Base, flag=time.time()):\n    pass\n",
            "base": "class C(pick(time.time())):\n    pass\n",
            "annotation": "def f(x: time.time()):\n    pass\n",
            "return annotation": "def f() -> time.time():\n    pass\n",
            "lambda default": "G = lambda x=time.time(): x\n",
            "under a module-level if": "if True:\n    A = utc_ts()\n",
            "under a module-level try": "try:\n    A = utc_ts()\nexcept Exception:\n    pass\n",
            "async default": "async def f(x=time.time()):\n    pass\n",
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertEqual(len(self.lines(src)), 1, src)

    def test_the_scanner_skips_every_deferred_body(self):
        cases = {
            "function body": "def f():\n    return datetime.now()\n",
            "lambda body": "G = lambda: time.time()\n",
            "function under an if": "if True:\n    def f():\n        return time.time()\n",
            "lambda under a try":
                "try:\n    G = lambda: time.time()\nexcept Exception:\n    pass\n",
            "function under a try":
                "try:\n    pass\nexcept Exception:\n    def f():\n        return utc_ts()\n",
            "method body": "class C:\n    def m(self):\n        return time.time()\n",
            "async body": "async def f():\n    return time.time()\n",
            "nested function": "def f():\n    def g(x=time.time()):\n        pass\n",
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertEqual(self.lines(src), [], src)

    def test_no_test_module_reads_a_clock_at_import(self):
        modules = sorted(TESTS_DIR.glob("*.py"))
        self.assertGreater(len(modules), 100, "the scan found nothing to look at")
        found = [f"{p.name}:{line}: {call}" for p in modules
                 for line, call in import_time_clocks(p.read_text(encoding="utf-8"), str(p))]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
