"""The declared public surface, held to what it declares.

`router/__init__.py` names three module classes. Naming them is only worth
something if the names cannot silently go stale, so this file asserts four
things that a declaration-by-docstring cannot:

1. The classification PARTITIONS the package. A new module cannot be added
   without landing in exactly one class, and a name in a class cannot survive
   the module being renamed away underneath it.
2. Public modules import with NO side effects — nothing written, no
   environment variable read, nothing on stdout or stderr. Importing the
   surface is never itself an action, which is what makes it safe for another
   repo to import a piece of this one without inheriting a runtime.
3. The three places the split is written down — `router/__init__.py`,
   `README.md`, `pyproject.toml` — agree. Three copies of a list drift.
4. `import router` loads no submodule. If the package's `__init__` grew an
   `from . import config`, importing the *name* would drag the whole closure
   in behind it and (2) would be a claim about nothing.

Side effects are measured in a CHILD interpreter, not this one: by the time a
test runs, `router.config` and friends are already in `sys.modules` and a
second `import` is a no-op that could not observe an effect if it wanted to.
The child gets `PYTHONDONTWRITEBYTECODE=1` — without it every import writes
`__pycache__` and the file-write assertion is a permanent false positive —
and `HOME`, `TMPDIR` and its cwd all point at one empty sandbox directory, so
a write to any of the three obvious places shows up in one tree listing.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import router

# NOT `.resolve()` — this repo is reached through a workspace symlink and
# resolving lands the path arithmetic somewhere unexpected; see the same note
# on `AMP_ROOT` in helpers.py. `.absolute()` only normalizes cwd-relativeness.
_REPO = Path(__file__).absolute().parents[2]
_PKG = _REPO / "router"

# Imports only the three stdlib modules it needs, then swaps `os.environ` for
# a recorder before importing the module under test. `os.getenv` resolves the
# module global `environ`, so replacing it catches that spelling too.
_CHILD = r"""
import json, os, sys

class _Recorder:
    def __init__(self, real):
        self._real, self.reads = real, []
    def __getitem__(self, k):
        self.reads.append(k); return self._real[k]
    def get(self, k, default=None):
        self.reads.append(k); return self._real.get(k, default)
    def __contains__(self, k):
        self.reads.append(k); return k in self._real
    def __iter__(self):
        self.reads.append("*"); return iter(self._real)
    def __len__(self):
        return len(self._real)
    def keys(self):
        self.reads.append("*"); return self._real.keys()
    def items(self):
        self.reads.append("*"); return self._real.items()
    def values(self):
        self.reads.append("*"); return self._real.values()
    def setdefault(self, k, default=None):
        self.reads.append(k); return self._real.setdefault(k, default)
    def copy(self):
        self.reads.append("*"); return self._real.copy()

_rec = _Recorder(os.environ)
os.environ = _rec
target, report = sys.argv[1], sys.argv[2]
__import__(target)
os.environ = _rec._real
loaded = sorted(m for m in sys.modules if m == "router" or m.startswith("router."))
with open(report, "w") as fh:
    json.dump({"reads": _rec.reads, "loaded": loaded}, fh)
"""


def _tree(root: Path) -> set:
    """Every path under `root`, repo-relative, `__pycache__` excluded. A live
    `router/__pycache__` exists on disk and is not evidence of anything."""
    out = set()
    for p in root.rglob("*"):
        if "__pycache__" in p.parts:
            continue
        out.add(str(p.relative_to(root)))
    return out


class _Probe:
    """One child import. `.reads`, `.loaded`, `.stdout`, `.stderr`, `.wrote`."""

    def __init__(self, module: str):
        with TemporaryDirectory() as sandbox_s, TemporaryDirectory() as report_s:
            sandbox, report = Path(sandbox_s), Path(report_s) / "r.json"
            env = {
                "PATH": os.environ.get("PATH", ""),
                # Constraint 4, and without it __pycache__ writes are a false
                # positive on every single module.
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(_REPO),
                "HOME": str(sandbox),
                "TMPDIR": str(sandbox),
            }
            before_pkg = _tree(_PKG)
            proc = subprocess.run(
                [sys.executable, "-c", _CHILD, module, str(report)],
                cwd=str(sandbox), env=env, capture_output=True, text=True,
            )
            self.stdout, self.stderr, self.rc = proc.stdout, proc.stderr, proc.returncode
            self.wrote = _tree(sandbox) | (_tree(_PKG) - before_pkg)
            if report.is_file():
                doc = json.loads(report.read_text())
                self.reads, self.loaded = doc["reads"], doc["loaded"]
            else:
                # ABSENT IS NOT EMPTY: the child never got far enough to
                # answer, which is not the same as answering "none".
                self.reads = self.loaded = None


class ClassificationPartitionsThePackageTests(unittest.TestCase):
    """The assertion that makes a NEW module impossible to add without
    classifying it. That is the whole point of declaring a surface: an
    unclassified module is how internals become an API by accident."""

    def _on_disk(self):
        return {p.stem if p.name != "__main__.py" else "__main__"
                for p in _PKG.glob("*.py") if p.name != "__init__.py"}

    def test_every_module_is_classified_exactly_once(self):
        declared = (list(router.PUBLIC_MODULES) + list(router.INTERNAL_MODULES)
                    + list(router.UNCLASSIFIED_MODULES))
        self.assertEqual(
            len(declared), len(set(declared)),
            msg="a module name appears in more than one class")
        self.assertEqual(
            set(declared), self._on_disk(),
            msg="every router/*.py must be in exactly one of PUBLIC_MODULES, "
                "INTERNAL_MODULES or UNCLASSIFIED_MODULES")

    def test_every_declared_name_exists_on_disk(self):
        for name in (list(router.PUBLIC_MODULES) + list(router.INTERNAL_MODULES)
                     + list(router.UNCLASSIFIED_MODULES)):
            with self.subTest(module=name):
                self.assertTrue(
                    (_PKG / f"{name}.py").is_file(),
                    msg=f"{name} is declared but router/{name}.py does not exist")


class DeclaredTestSurfaceTests(unittest.TestCase):
    """`router/tests/` has an out-of-package consumer, so the two names it
    uses are declared and defended HERE.

    Without this, a rename in the fixtures is an error in someone else's
    repository, discovered when their suite runs. That already nearly
    happened: `make_config(approve=...)` became `make_config(seen=...)`,
    which is a call-time `TypeError` rather than an import error, and it
    survived only because the external caller did not pass the keyword.
    """

    def test_every_declared_name_exists_and_is_importable(self):
        """Resolved the way a caller resolves it — dotted, through the class
        — rather than by looking for a flat module attribute. The first
        version of this test did the latter and failed immediately on a
        declaration that named a method as though it were a function. That
        is the check working: a surface tuple nobody resolves is a list of
        hopeful strings."""
        import router.tests as tests_pkg
        from router.tests import helpers
        for dotted in tests_pkg.PUBLIC_TEST_SURFACE:
            with self.subTest(name=dotted):
                obj = helpers
                for part in dotted.split("."):
                    self.assertTrue(
                        hasattr(obj, part),
                        msg=f"{dotted} is declared in PUBLIC_TEST_SURFACE but "
                            f"{part!r} does not exist on {obj!r}")
                    obj = getattr(obj, part)

    def test_make_config_keeps_the_keywords_the_declaration_names(self):
        """The assertion the `approve=` -> `seen=` rename would have tripped.
        Pinning the NAME alone is not enough: `make_config` kept its name
        through that rename and an external call still broke."""
        import inspect
        from router.tests import helpers
        import router.tests as tests_pkg

        params = inspect.signature(helpers.RouterTestCase.make_config).parameters
        for kw in tests_pkg.PUBLIC_MAKE_CONFIG_KWARGS:
            with self.subTest(kwarg=kw):
                self.assertIn(
                    kw, params,
                    msg=f"make_config no longer accepts {kw!r} — that is a "
                        f"cross-repo break, and it owes notice before the commit")
                self.assertIs(
                    params[kw].kind, inspect.Parameter.KEYWORD_ONLY,
                    msg=f"{kw!r} must stay keyword-only: an external caller "
                        f"passes it by name")

    def test_router_test_case_is_a_test_case_with_the_temp_dir_lifecycle(self):
        """What the external consumer actually leans on, named rather than
        assumed: the base class and its per-test temp dir."""
        from router.tests.helpers import RouterTestCase
        self.assertTrue(issubclass(RouterTestCase, unittest.TestCase))
        for method in ("setUp", "tearDown", "make_config"):
            with self.subTest(member=method):
                self.assertTrue(hasattr(RouterTestCase, method))

    def test_reset_py_still_exists_as_a_checkout_sentinel(self):
        """Not about imports at all. A host adapter confirms it has found a
        router checkout by testing for `router/reset.py` ON DISK, so the file
        may be re-homed internally but not renamed or deleted without giving
        that caller a new sentinel first. `_open_child` moving to `util` was
        exactly such a re-homing, and this is why an alias was left rather
        than the file emptied."""
        self.assertTrue((_PKG / "reset.py").is_file())

    def test_the_pin_alias_is_the_same_object_not_a_copy(self):
        """`reset._open_child` is an alias for `util.open_child_pinned`. If it
        ever becomes a wrapper — or worse, a second implementation — there
        are two versions of a security primitive to audit and only one of
        them is being tested."""
        from router import reset, util
        self.assertIs(reset._open_child, util.open_child_pinned)


class PublicModulesImportWithoutSideEffectsTests(unittest.TestCase):
    """A public module that acts on import makes `import` a decision. These
    run one child interpreter per module — six of them, ~40ms each."""

    def test_no_output_on_bare_import(self):
        for name in router.PUBLIC_MODULES:
            with self.subTest(module=name):
                p = _Probe(f"router.{name}")
                self.assertEqual(p.rc, 0, msg=f"child failed: {p.stderr}")
                self.assertEqual(p.stdout, "", msg=f"router.{name} printed on import")
                self.assertEqual(p.stderr, "", msg=f"router.{name} wrote to stderr on import")

    def test_no_environment_read_on_bare_import(self):
        for name in router.PUBLIC_MODULES:
            with self.subTest(module=name):
                p = _Probe(f"router.{name}")
                self.assertIsNotNone(
                    p.reads, msg=f"the probe of router.{name} produced no answer")
                self.assertEqual(
                    p.reads, [],
                    msg=f"router.{name} read the environment on import: {p.reads}")

    def test_nothing_written_on_bare_import(self):
        for name in router.PUBLIC_MODULES:
            with self.subTest(module=name):
                p = _Probe(f"router.{name}")
                self.assertEqual(
                    p.wrote, set(),
                    msg=f"router.{name} wrote on import: {sorted(p.wrote)}")


class ImportingThePackageLoadsNoSubmoduleTests(unittest.TestCase):
    """`router/__init__.py` must import nothing from its own package. An
    `from . import config` there would make `import router` an import of the
    whole closure, and every no-side-effect claim above a claim about
    nothing."""

    def test_import_router_pulls_in_no_submodule(self):
        p = _Probe("router")
        self.assertEqual(p.rc, 0, msg=f"child failed: {p.stderr}")
        self.assertIsNotNone(p.loaded, msg="the probe produced no answer")
        self.assertEqual(
            p.loaded, ["router"],
            msg="`import router` loaded submodules: "
                f"{[m for m in p.loaded if m != 'router']}")


class ThreeDeclarationsAgreeTests(unittest.TestCase):
    """README.md, pyproject.toml and `router/__init__.py` each name the public
    modules. Three copies of a list drift, and they drift quietly."""

    def test_readme_public_row_matches(self):
        text = (_REPO / "README.md").read_text(encoding="utf-8")
        rows = [ln for ln in text.splitlines()
                if ln.startswith("|") and "**Public**" in ln]
        self.assertEqual(len(rows), 1, msg="README has no single Public row")
        names = re.findall(r"`([a-z_]+)`", rows[0].split("|")[2])
        self.assertEqual(sorted(names), sorted(router.PUBLIC_MODULES))

    def test_pyproject_comment_matches(self):
        text = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
        head = text.split("[build-system]")[0]
        joined = " ".join(ln.lstrip("#").strip() for ln in head.splitlines())
        m = re.search(r"policy core\s*--\s*(.*?)\s*--\s*instead", joined)
        self.assertIsNotNone(
            m, msg="pyproject.toml's header no longer names the policy core")
        names = re.findall(r"`([a-z_]+)`", m.group(1))
        self.assertEqual(sorted(names), sorted(router.PUBLIC_MODULES))


class LockIsOnThePublicSurfaceTests(unittest.TestCase):
    """Round 3, item 4: the combined runtime takes THIS router's single-
    drainer lock at startup, so `lock` is public and its acquire function
    and error are the names it imports. Semantics are `test_single_drainer`'s
    business; this only pins the surface."""

    def test_lock_is_public_and_exports_acquire_and_the_held_error(self):
        self.assertIn("lock", router.PUBLIC_MODULES)
        self.assertNotIn("lock", router.INTERNAL_MODULES)
        from router import lock
        self.assertTrue(callable(lock.acquire))
        self.assertTrue(issubclass(lock.LockHeldError, Exception))
        with TemporaryDirectory() as d:
            held = lock.acquire(d)
            try:
                # A second holder in this process would share the fd table;
                # a child answers the question honestly, through the public
                # name the combined runtime will use.
                proc = subprocess.run(
                    [sys.executable, "-c",
                     "import sys; from router import lock; lock.acquire(sys.argv[1])", d],
                    env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(_REPO),
                         "PYTHONDONTWRITEBYTECODE": "1"},
                    capture_output=True, text=True,
                )
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("LockHeldError", proc.stderr)
                self.assertIn("refusing to run concurrently", proc.stderr)
            finally:
                held.release()

if __name__ == "__main__":
    unittest.main()
