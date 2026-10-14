"""A TEST-ONLY stand-in for the plugin's runtime capability
(`transport.RUNTIME_CAPABILITY`, provisional until the runtime identity unit
freezes): a plugin-like object declaring `make_runtime_sender` and
`make_runtime_lister`, and an in-memory runtime tree they share. Never
selected in production: no production module imports it.

- The lister is READ-ONLY and its settings are closed; an absent tree lists
  empty. It never admits, creates or writes.
- A runtime sender is bound to one generation and is the in-flight sender
  (`test_inflight.FakeTransport`) plus `retire`, `retired`, `retired_at` and
  `identity`. Constructing one admits its generation here; the router under
  test must depend on neither that nor an explicit admission.
- `calls` records every factory call's role and settings, so a test can show
  which (if any) factory the router called.
"""
from __future__ import annotations

import types
from typing import Any, Dict, List, Tuple

from router.tests.test_inflight import FakeTransport

SENDER_SETTINGS = frozenset({"hop_root", "generation", "peer_uid", "address"})
LISTER_SETTINGS = frozenset({"hop_root", "peer_uid"})


class Tree:
    """The runtime tree: generation -> state ("live", "retired",
    "unreadable"), and each generation's sender."""

    def __init__(self):
        self.gens: Dict[str, str] = {}
        self.retired_at: Dict[str, str] = {}
        self.senders: Dict[str, "RuntimeSender"] = {}
        self.calls: List[Tuple[str, Dict[str, Any]]] = []


class RuntimeSender(FakeTransport):

    def __init__(self, tree: Tree, settings: Dict[str, Any]):
        super().__init__()
        self.tree, self.settings = tree, dict(settings)
        tree.gens.setdefault(settings["generation"], "live")

    @property
    def generation(self) -> str:
        return self.settings["generation"]

    def retire(self, retired_at: str) -> str:
        if self.tree.gens.get(self.generation) == "retired":
            return "exists"
        self.tree.gens[self.generation] = "retired"
        self.tree.retired_at[self.generation] = retired_at
        return "created"

    def retired(self) -> bool:
        return self.tree.gens.get(self.generation) == "retired"

    def retired_at(self):
        return self.tree.retired_at.get(self.generation)

    def identity(self) -> Dict[str, str]:
        return {"logical_id": "runtime", "address": self.settings["address"]}


class Lister:

    def __init__(self, tree: Tree):
        self.tree = tree

    def generations(self) -> List[Tuple[str, str]]:
        return sorted(self.tree.gens.items())


def plugin(tree: Tree) -> Any:
    """The loaded-plugin-like object: `optional_capabilities` and a
    `namespace` with both runtime factories."""

    def make_runtime_sender(settings, fsops):
        tree.calls.append(("sender", dict(settings)))
        if set(settings) != SENDER_SETTINGS:
            raise ValueError(f"runtime sender settings are closed: {sorted(settings)}")
        gen = settings["generation"]
        if gen not in tree.senders:
            tree.senders[gen] = RuntimeSender(tree, settings)
        return tree.senders[gen]

    def make_runtime_lister(settings, fsops):
        tree.calls.append(("lister", dict(settings)))
        if set(settings) != LISTER_SETTINGS:
            raise ValueError(f"runtime lister settings are closed: {sorted(settings)}")
        return Lister(tree)

    ns = {"make_runtime_sender": make_runtime_sender, "make_runtime_lister": make_runtime_lister}
    return types.SimpleNamespace(
        api=(3, 5), namespace=types.MappingProxyType(ns),
        optional_capabilities=frozenset(ns))


def runtime(tree: Tree, fsops: Any = None) -> Any:
    """What the service hands the control pass: a plugin and an fsops."""
    return types.SimpleNamespace(plugin=plugin(tree), fsops=fsops if fsops is not None else object())
