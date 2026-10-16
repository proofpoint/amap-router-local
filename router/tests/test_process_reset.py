"""`hoplink.reset_process_state`, the process-end reset the hop fixture's
restart calls: every module-level container that holds per-process state is
in `hoplink.PROCESS_STATE`, every other one is a named constant here, and a
container in neither fails. The reset empties each in place and closes every
hop object first.

And two "only here" rules, checked on the source: nothing in the package
assigns the test-only `service.FENCE_STOP_AT` but its own `None`, and only
`hoplink.write_lost_acks` writes a lost tree's acknowledgement, called only
through `LostAcks.ack`, which only the CLI's `generation new` builds."""
from __future__ import annotations

import ast
import importlib
import os
import pathlib
import pkgutil
import unittest
from types import SimpleNamespace

import router
from router import fsops as fsops_mod
from router import hoplink
from router.tests.test_fsops import GEN, LID, _HopCase

#: Module-level containers that are constants (read-only tables), never
#: process state. A new container lands in one list or the other.
CONSTANTS = {
    "aliases": {"HOLD_HINT"},
    "config": {"_TOP_KEYS", "_INSTANCE_KEYS", "LANE_LEAVES", "_ROOT_KEY_MODE"},
    "console": {"KNOWN_PHASES"},
    "fsops": {"_BAD_NAMES"},
    "generations": {"_UNKNOWN_BINDING", "_OUTCOME_VERSION"},
    "hoplink": {"LATCHED_WRITE_REASONS", "SETTLE_WRITE_REASONS", "RETRY_WRITE_REASONS", "RETRY_HINTS",
                "NOT_WRITE_REASONS", "PROCESS_STATE", "HOLD_HINTS"},
    "inflight": {"_RECORD_KEYS", "_DAMAGE_ERRNO"},
    "ingress": {"TRANSITIONS", "_STATUS_DETAIL", "_V1_REQUIRED", "_V1_OPTIONAL",
                "WAITING_REMOVE", "FAILURE_SUBJECT", "_STATUS_SUBJECT"},
    "outcomes": {"_DSN_MEANING"},
    "peercontrol": {"CAUSES", "FAILURE_TEXT"},
    "peerjournal": {"TRANSITIONS", "_DONE_DISPOSITION", "_TOMBSTONE_DISPOSITION",
                    "PENDING_OP_FORMS"},
    "provision": {"LANE_LEAVES"},
    "registry": {"_CONFUSABLES"},
    "transport": {"OPTIONAL_FACTORIES", "HOPFSOPS_OPTIONAL_METHODS", "FACTORY_PORTS",
                  "CODEC_OPTIONAL_METHODS", "CODEC_OPTIONAL_ATTRIBUTES", "RUNTIME_CAPABILITY"},
    "validate": {"_TOP_KEYS", "_DRAFT_KEYS", "_ATTACHMENT_KEYS"},
}

#: Module-level containers that are ENVIRONMENT: they survive a modelled
#: restart, as the filesystem does, so the reset must NOT empty them. The
#: installed clock source is the one: `reset_process_state` models a process
#: end in the middle of a scenario, and a fixed clock dropped there would put
#: the recovery half of every crash case back on real time. Only
#: `clock.reset()` clears it.
ENVIRONMENT = {
    "clock": {"_INSTALLED", "_STRICT"},
}

ROUTER = pathlib.Path(router.__file__).parent


def _containers():
    found = {}
    for info in pkgutil.iter_modules(router.__path__):
        if info.name == "__main__":
            continue
        mod = importlib.import_module(f"router.{info.name}")
        names = {k for k, v in vars(mod).items()
                 if isinstance(v, (dict, set, list)) and not k.startswith("__")}
        if names:
            found[info.name] = names
    return found


class CompletenessTests(unittest.TestCase):

    def test_every_container_is_process_state_or_a_constant(self):
        found = _containers()
        self.assertGreater(sum(len(v) for v in found.values()), 30,
                           "the scan found almost nothing: it is not scanning")
        declared = {m: set(n) for m, n in hoplink.PROCESS_STATE.items()}
        for module, names in found.items():
            with self.subTest(module=module):
                unclassified = (names - declared.get(module, set()) - CONSTANTS.get(module, set())
                                - ENVIRONMENT.get(module, set()))
                self.assertEqual(unclassified, set(),
                                 "a container in neither PROCESS_STATE, CONSTANTS nor ENVIRONMENT")
        for module, names in declared.items():
            with self.subTest(declared=module):
                self.assertEqual(names - found.get(module, set()), set(),
                                 "PROCESS_STATE names a container that does not exist")
                self.assertEqual(names & CONSTANTS.get(module, set()), set())
                self.assertEqual(names & ENVIRONMENT.get(module, set()), set(),
                                 "an ENVIRONMENT container registered as process state: "
                                 "a modelled restart would drop it")
        for module, names in ENVIRONMENT.items():
            with self.subTest(environment=module):
                self.assertEqual(names - found.get(module, set()), set(),
                                 "ENVIRONMENT names a container that does not exist")


class ResetTests(unittest.TestCase):

    def test_the_reset_empties_every_container_and_closes_the_objects(self):
        closed = []

        class Obj:
            def __init__(self):
                self.port = self              # a cached reader's shape

            def close(self):
                closed.append(self)
        sender, store = Obj(), Obj()
        planted = Obj()
        hoplink._SENDERS[("k",)] = sender
        hoplink._STORES[("k",)] = store
        filled = []
        for module, names in hoplink.PROCESS_STATE.items():
            mod = importlib.import_module(f"router.{module}")
            for attr in names:
                container = getattr(mod, attr)
                if isinstance(container, dict):
                    container.setdefault(("planted",), planted)
                elif isinstance(container, set):
                    container.add(("planted",))
                else:
                    container.append(("planted",))
                filled.append((module, attr, container))
        self.addCleanup(hoplink.reset_process_state)
        hoplink.reset_process_state()
        for module, attr, container in filled:
            with self.subTest(container=f"{module}.{attr}"):
                self.assertEqual(len(container), 0, "not emptied")
                self.assertIs(getattr(importlib.import_module(f"router.{module}"), attr),
                              container, "replaced rather than emptied in place")
        for obj in (sender, store):
            self.assertIn(obj, closed, "a hop object was dropped without being closed")


class FsOpsResetTests(_HopCase):
    """A real FsOps: the reset closes the runtime's port, so its pinned stage
    descriptor is released and a new port validates the stage again."""

    def test_the_reset_closes_the_port_and_a_new_one_revalidates(self):
        def fds():
            return len(os.listdir("/proc/self/fd"))
        baseline = fds()
        ops = fsops_mod.FsOps(hop_root=self.hop, private_roots=[self.priv])
        root = ops.open_root_nofollow(str(self.hop))
        tree = ops.descend_pinned(root, f"{LID}/{GEN}")
        ops.open_stage_dir(tree, "up")
        for fd in (tree, root):                   # a plugin object's own, closed by it
            os.close(fd)
        self.assertEqual(fds(), baseline + 1, "control: the port pins one stage descriptor")
        stage = self.hop / LID / GEN / "up" / "stage"
        os.chmod(stage, 0o750)                    # no longer a valid stage
        self.addCleanup(hoplink.reset_process_state)
        hoplink.reset_process_state(SimpleNamespace(fsops=ops))
        self.assertEqual(fds(), baseline, "the port's stage descriptor outlived the reset")
        with self.assertRaises(fsops_mod.BindingError):
            ops.open_root_nofollow(str(self.hop))  # a closed port binds nothing
        fresh = fsops_mod.FsOps(hop_root=self.hop, private_roots=[self.priv])
        root = fresh.open_root_nofollow(str(self.hop))
        try:
            tree = fresh.descend_pinned(root, f"{LID}/{GEN}")
            try:
                with self.assertRaises(fsops_mod.FsOpsError):
                    fresh.open_stage_dir(tree, "up")   # validated again, and refused
            finally:
                os.close(tree)
        finally:
            os.close(root)
            fresh.close()
        self.assertEqual(fds(), baseline, "the second port's descriptors outlived the test")


def _tree(name):
    return ast.parse((ROUTER / name).read_text(encoding="utf-8"))


class OnlyHereTests(unittest.TestCase):

    def test_nothing_assigns_the_fence_hook_but_its_none(self):
        sites = []
        for path in sorted(ROUTER.glob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    targets = [node.target]
                for t in targets:
                    name = getattr(t, "id", None) or getattr(t, "attr", None)
                    if name == "FENCE_STOP_AT":
                        sites.append((path.name, getattr(node, "value", None)))
        self.assertEqual(len(sites), 1, f"FENCE_STOP_AT assigned at {[s[0] for s in sites]}")
        [(where, value)] = sites
        self.assertEqual(where, "service.py")
        self.assertIsInstance(value, ast.Constant)
        self.assertIsNone(value.value)

    def test_only_the_verb_writes_a_lost_ack(self):
        refs = {}
        for path in sorted(ROUTER.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for word in ("LOST_ACK_FILE", "write_lost_acks", "LostAcks("):
                if word in text:
                    refs.setdefault(word, set()).add(path.name)
        self.assertEqual(refs["LOST_ACK_FILE"], {"hoplink.py"})
        self.assertEqual(refs["write_lost_acks"], {"hoplink.py"})
        self.assertEqual(refs["LostAcks("], {"__main__.py"})
        # In hoplink: written by `write_lost_acks` alone (the other uses read it).
        writers = set()
        for node in ast.walk(_tree("hoplink.py")):
            if isinstance(node, ast.FunctionDef):
                body = ast.unparse(node)
                if "LOST_ACK_FILE" in body and "atomic_write" in body:
                    writers.add(node.name)
        self.assertEqual(writers, {"write_lost_acks"})
        calls = {node.name for node in ast.walk(_tree("hoplink.py"))
                 if isinstance(node, ast.FunctionDef)
                 and "write_lost_acks(" in ast.unparse(node) and node.name != "write_lost_acks"}
        self.assertEqual(calls, {"ack"})


if __name__ == "__main__":
    unittest.main()
