"""A TEST-ONLY stand-in for the plugin's runtime capability, in the frozen
shape of PLUGIN_API (3, 5) (`transport.RUNTIME_CAPABILITY`): a plugin-like
object declaring `make_runtime_sender` and `make_runtime_lister`, and an
in-memory runtime tree they share. Never selected in production: no
production module imports it. The real plugin's rows run in
`router/tests/run_realhop.py`.

- The lister is READ-ONLY and its settings are closed; an absent tree lists
  empty. It never admits, creates or writes.
- A runtime sender is bound to one generation. Its settings are closed
  (`SENDER_SETTINGS`); construction NEVER admits. `admit(admitted_at)` is
  the explicit admission: "admitted" for a new tree, "exists" only for the
  byte-equal identity (a retired tree included), else `exists_different`.
  Before admission every port method refuses with `layout`. `identity()`
  is None for an absent tree; `retire` on an absent tree is "absent" and
  creates nothing, and on an unreadable one refuses.
- `write_request` of a NEW request in a retired generation raises
  `RuntimeRetired` (reason `generation_retired`) and writes nothing; a
  request already there goes the in-flight sender's way.
- `calls` records every factory call's role and settings, and `admits`
  every admission's `(generation, admitted_at)`, so a test can show which
  factory the router called and with what.
"""
from __future__ import annotations

import types
from typing import Any, Dict, List, Optional, Tuple

from router.tests.test_inflight import FakeTransport

SENDER_SETTINGS = frozenset({"hop_root", "generation", "peer_uid", "address", "version_write",
                             "caps"})
LISTER_SETTINGS = frozenset({"hop_root", "peer_uid"})


class Anomaly(Exception):
    """The plugin's anomaly: a `.reason` from the closed vocabulary."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


class RuntimeRetired(Anomaly):
    """A NEW request refused in a retired runtime generation."""

    def __init__(self, detail: str = ""):
        super().__init__("generation_retired", detail)


class Tree:
    """The runtime tree: generation -> state ("live", "retired",
    "unreadable"), each admitted generation's identity, and each
    generation's sender. A generation a test puts in `gens` directly is
    taken as admitted at `DEFAULT_AT` (the suite's `NOW`), so its identity
    agrees with a record written at that time."""

    DEFAULT_AT = "2026-10-13T12:00:00Z"

    def __init__(self):
        self.gens: Dict[str, str] = {}
        self.identities: Dict[str, Dict[str, str]] = {}
        self.retired_at: Dict[str, str] = {}
        self.senders: Dict[str, "RuntimeSender"] = {}
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.admits: List[Tuple[str, str]] = []
        #: A lister anomaly to raise on every `generations()` call, or None.
        self.lister_anomaly: Optional[Anomaly] = None

    def admit(self, gen: str, admitted_at: str, address: str = "amap.router@example.org") -> None:
        """A generation admitted out of band (by a test), as a real tree
        holds it."""
        self.gens[gen] = "live"
        self.identities[gen] = {"address": address, "admitted_at": admitted_at,
                                "generation": gen, "logical_id": "runtime"}


class RuntimeSender(FakeTransport):

    RuntimeRetired = RuntimeRetired

    def __init__(self, tree: Tree, settings: Dict[str, Any]):
        super().__init__()
        self.tree, self.settings = tree, dict(settings)

    @property
    def generation(self) -> str:
        return self.settings["generation"]

    def admit(self, admitted_at: str) -> str:
        self.tree.admits.append((self.generation, admitted_at))
        want = {"address": self.settings["address"], "admitted_at": admitted_at,
                "generation": self.generation, "logical_id": "runtime"}
        state = self.tree.gens.get(self.generation)
        if state is None:
            self.tree.gens[self.generation] = "live"
            self.tree.identities[self.generation] = want
            return "admitted"
        if state == "unreadable":
            raise Anomaly("marker_unreadable", "identity.json")
        if self._identity_of() != want:
            raise Anomaly("exists_different", f"{self.generation}: another identity")
        return "exists"

    def _identity_of(self) -> Dict[str, str]:
        return self.tree.identities.setdefault(self.generation, {
            "address": self.settings["address"], "admitted_at": Tree.DEFAULT_AT,
            "generation": self.generation, "logical_id": "runtime"})

    def identity(self) -> Optional[Dict[str, str]]:
        state = self.tree.gens.get(self.generation)
        if state is None:
            return None
        if state == "unreadable":
            raise Anomaly("marker_unreadable", "identity.json")
        return dict(self._identity_of())

    def retire(self, retired_at: str) -> str:
        if self.identity() is None:
            return "absent"
        if self.tree.gens[self.generation] == "retired":
            return "exists"
        self.tree.gens[self.generation] = "retired"
        self.tree.retired_at[self.generation] = retired_at
        return "created"

    def retired(self) -> bool:
        return self.retired_at() is not None

    def retired_at(self):
        if self.tree.gens.get(self.generation) is None:
            raise Anomaly("layout", f"no generation .runtime/{self.generation}")
        return self.tree.retired_at.get(self.generation)

    def _admitted(self) -> None:
        if self.identity() is None:
            raise Anomaly("layout", f".runtime/{self.generation}: not admitted")

    def has_result(self, n):
        self._admitted()
        return super().has_result(n)

    def has_pending(self, n):
        self._admitted()
        return super().has_pending(n)

    def has_archived(self, n):
        self._admitted()
        return super().has_archived(n)

    def read_result(self, n):
        self._admitted()
        return super().read_result(n)

    def write_request(self, n, data):
        self._admitted()
        exists = n in self.pending or n in self.archived or n in self.results
        if not exists and self.tree.gens.get(self.generation) == "retired":
            raise RuntimeRetired(f"req-{n}: generation {self.generation} is retired")
        if exists and self.pending.get(n) == data:
            return None        # handed over already: the in-flight sender's no-op
        return super().write_request(n, data)

    def withdraw_request(self, n):
        self._admitted()
        return super().withdraw_request(n)


class Lister:

    def __init__(self, tree: Tree):
        self.tree = tree

    def generations(self) -> List[Tuple[str, str]]:
        if self.tree.lister_anomaly is not None:
            raise self.tree.lister_anomaly
        return sorted(self.tree.gens.items())


def plugin(tree: Tree) -> Any:
    """The loaded-plugin-like object: `optional_capabilities` and a
    `namespace` with both runtime factories."""

    def make_runtime_sender(settings, fsops):
        tree.calls.append(("sender", dict(settings)))
        if set(settings) != SENDER_SETTINGS:
            raise Anomaly("settings_invalid",
                          f"runtime sender settings are closed: {sorted(settings)}")
        gen = settings["generation"]
        if gen not in tree.senders:
            tree.senders[gen] = RuntimeSender(tree, settings)
        return tree.senders[gen]

    def make_runtime_lister(settings, fsops):
        tree.calls.append(("lister", dict(settings)))
        if set(settings) != LISTER_SETTINGS:
            raise Anomaly("settings_invalid",
                          f"runtime lister settings are closed: {sorted(settings)}")
        return Lister(tree)

    ns = {"make_runtime_sender": make_runtime_sender, "make_runtime_lister": make_runtime_lister}
    return types.SimpleNamespace(
        api=(3, 5), namespace=types.MappingProxyType(ns),
        optional_capabilities=frozenset(ns))


def runtime(tree: Tree, fsops: Any = None) -> Any:
    """What the service hands the control pass: a plugin and an fsops."""
    return types.SimpleNamespace(plugin=plugin(tree), fsops=fsops if fsops is not None else object())
