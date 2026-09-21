"""The config extension hook — a CALLER may declare extra instance keys.

Why this exists: the loader rejects unknown instance keys, and that strictness
is load-bearing (a typo'd key must never be silently ignored). A downstream
runtime that needs its own per-instance config must therefore be able to widen
the permitted set from OUTSIDE, without forking this loader and without this
repo learning what those keys mean. Every test below pins one half of that
bargain: the hook widens who may DEFINE a key, never how strict the loader is,
and a caller's key can never reach the loader's own security-relevant handling
(roots, peers).

The example key here is deliberately neutral (`quota`) — this module defines no
key and this repo interprets none.
"""

import json
import tempfile
import unittest
from pathlib import Path

from router.binding import check_cold
from router.config import (
    MODE_NAMESPACE, ConfigError, InstanceConfig, derive_matrix, load, load_obj,
    loads,
)


def _doc(alice_spec=None, **instances):
    spec = {"namespace": "/x/alice", "peers": []}
    if alice_spec:
        spec = dict(spec, **alice_spec)
    doc = {"state_dir": "/x/state", "instances": {"alice": spec}}
    doc["instances"].update(instances)
    return doc


class ExtensionHookTests(unittest.TestCase):
    def test_default_still_strict(self):
        """No hook supplied -> an undeclared key is still refused, whether the
        caller omits the arguments or passes them as None."""
        with self.assertRaises(ConfigError):
            load_obj(_doc({"quota": 1}))
        with self.assertRaises(ConfigError):
            load_obj(_doc({"quota": 1}), extra_instance_keys=None, validate_extra=None)

    def test_declared_key_validated_and_surfaced(self):
        """The VALIDATOR'S RETURN VALUE is what lands in `extra` — the hook
        normalizes, it does not merely permit."""
        cfg = load_obj(
            _doc({"quota": 3}),
            extra_instance_keys=["quota"],
            validate_extra=lambda n, k, v: v * 2,
        )
        self.assertEqual(dict(cfg.instances["alice"].extra), {"quota": 6})

    def test_validator_failure_names_instance_and_key(self):
        for exc in (ValueError("nope"), ConfigError("nope")):
            with self.subTest(exc=type(exc).__name__):
                def boom(n, k, v, _e=exc):
                    raise _e

                with self.assertRaises(ConfigError) as ctx:
                    load_obj(
                        _doc({"quota": 1}),
                        extra_instance_keys=["quota"],
                        validate_extra=boom,
                    )
                self.assertIn("alice", str(ctx.exception))
                self.assertIn("quota", str(ctx.exception))

    def test_extras_never_reach_peers(self):
        """A peer-shaped extra value must stay inert. If extras could leak into
        peers resolution, a caller's config key would silently grant cold-send
        permission — the one thing `peers` exists to gate."""
        cfg = load_obj(
            _doc({"quota": ["bob"]}, bob={"namespace": "/x/bob", "peers": ["alice"]}),
            extra_instance_keys=["quota"],
            validate_extra=lambda n, k, v: v,
        )
        self.assertEqual(cfg.instances["alice"].peers, frozenset())
        self.assertIs(check_cold(cfg, "alice", "bob"), False)
        self.assertIs(derive_matrix(cfg)["alice"]["bob"], False)

    def test_reserved_keys_undeclarable(self):
        """A declared key can never shadow one the loader defines itself, and
        that is checked before the document is parsed at all."""
        for key in ("peers", "namespace", "handoff_dir"):
            with self.subTest(key=key):
                with self.assertRaises(ConfigError) as ctx:
                    load_obj(
                        {"state_dir": "/x/state", "instances": {}},
                        extra_instance_keys=[key],
                        validate_extra=lambda n, k, v: v,
                    )
                self.assertIn(key, str(ctx.exception))
                # Proves ordering: an outright invalid document still reports
                # the caller's mistake, not the document's.
                with self.assertRaises(ConfigError) as ctx:
                    load_obj(
                        [1, 2, 3],
                        extra_instance_keys=[key],
                        validate_extra=lambda n, k, v: v,
                    )
                self.assertIn(key, str(ctx.exception))

    def test_declared_key_needs_validator(self):
        """Declaring a key without a validator would put an unchecked value on
        `InstanceConfig.extra`; refuse instead.

        THE ASSERTION IS THE DECLARATION-TIME ONE, on purpose. Asserting merely
        that *some* ConfigError is raised for an instance that USES the key
        cannot fail: delete the guard and `validate_extra(...)` raises
        `TypeError: 'NoneType' object is not callable`, which the per-key
        wrapper converts into a ConfigError anyway. The whole suite stayed
        green with the guard deleted. Refusing when NO instance declares the
        key is reachable only through the guard itself -- an absent key is
        never validated (see the test below), so nothing else can raise.
        """
        with self.assertRaises(ConfigError) as caught:
            load_obj(_doc(), extra_instance_keys=["quota"])
        self.assertIn("validator", str(caught.exception))

        # And still refused in the using case, for the same reason.
        with self.assertRaises(ConfigError):
            load_obj(_doc({"quota": 1}), extra_instance_keys=["quota"])

    def test_instance_config_is_hashable(self):
        """`extra` holds a MappingProxyType, which is unhashable, so adding it
        silently made this frozen dataclass unhashable -- a real behaviour
        change on a module now declared public API, invisible to every test
        because nothing in-repo hashes an InstanceConfig. A consumer putting
        instances in a set would have found it instead."""
        def mk():
            return InstanceConfig(
                name="alice", mode="handoff", root=Path("/x"),
                inbox_root=Path("/x/inbox"), outbox_root=Path("/x/outbox"))
        self.assertEqual(len({mk(), mk()}), 1)
        self.assertEqual(mk(), mk())

    def test_absent_declared_key_is_not_called_and_not_present(self):
        """ABSENT IS NOT EMPTY: a permitted key the instance does not declare
        is not validated and does not appear as a None-valued entry."""
        seen = []

        def recorder(n, k, v):
            seen.append((n, k, v))
            return v

        cfg = load_obj(
            _doc(), extra_instance_keys=["quota"], validate_extra=recorder
        )
        self.assertEqual(seen, [])
        self.assertEqual(dict(cfg.instances["alice"].extra), {})
        self.assertNotIn("quota", cfg.instances["alice"].extra)

    def test_extra_is_always_a_mapping(self):
        cfg = load_obj(_doc())
        extra = cfg.instances["alice"].extra
        self.assertIsNotNone(extra)
        self.assertEqual(dict(extra), {})
        with self.assertRaises(TypeError):
            extra["x"] = 1

        # `config` is a public module, so an InstanceConfig built directly —
        # by a downstream runtime, not by this loader — must get the same
        # empty read-only mapping rather than None.
        direct = InstanceConfig(
            name="alice", mode=MODE_NAMESPACE, root=Path("/x/alice"),
            inbox_root=Path("/x/alice/inbound"), outbox_root=Path("/x/alice/outbound"),
        )
        self.assertIsNotNone(direct.extra)
        self.assertEqual(dict(direct.extra), {})
        with self.assertRaises(TypeError):
            direct.extra["x"] = 1

        cfg = load_obj(
            _doc({"quota": 1}, bob={"namespace": "/x/bob", "peers": []}),
            extra_instance_keys=["quota"],
            validate_extra=lambda n, k, v: v,
        )
        self.assertEqual(dict(cfg.instances["alice"].extra), {"quota": 1})
        self.assertEqual(dict(cfg.instances["bob"].extra), {})
        with self.assertRaises(TypeError):
            cfg.instances["bob"].extra["x"] = 1

    def test_load_and_loads_thread_the_hook(self):
        doc = _doc({"quota": 1})
        kw = dict(extra_instance_keys=["quota"], validate_extra=lambda n, k, v: v + 1)

        cfg = loads(json.dumps(doc), **kw)
        self.assertEqual(dict(cfg.instances["alice"].extra), {"quota": 2})

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            cfg = load(p, **kw)
        self.assertEqual(dict(cfg.instances["alice"].extra), {"quota": 2})


if __name__ == "__main__":
    unittest.main()


class ExtraKeysShapeGuardTests(unittest.TestCase):
    """The guard exists to report a CALLER's mistake as a ConfigError rather
    than as a config error about somebody's instance. It missed the mistake
    most likely to reach it."""

    def _doc(self):
        return {"state_dir": "/tmp/sd",
                "instances": {"alice": {"handoff_dir": "/tmp/a", "peers": []}}}

    def test_mixed_types_are_a_config_error_not_a_raw_type_error(self):
        """`sorted()` over a mixed-type set raises before any isinstance check
        runs, so this input used to escape as a bare TypeError."""
        with self.assertRaises(ConfigError) as caught:
            load_obj(self._doc(), extra_instance_keys=["quota", 1],
                     validate_extra=lambda n, k, v: v)
        self.assertIn("non-empty strings", str(caught.exception))

    def test_the_other_shapes_still_refuse(self):
        for bad in ([""], [None], [b"quota"]):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError):
                    load_obj(self._doc(), extra_instance_keys=bad,
                             validate_extra=lambda n, k, v: v)
