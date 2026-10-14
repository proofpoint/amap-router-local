"""Cross-host signed peer traffic, this router's side (`router/peerlane.py`,
`router/peerverify.py`, the `delegation` config, `transport.check_delegation`,
and the signed kind through `outbound` and `inflight`).

The plugin's peer seam is the stand-in in `router/tests/peer_standin.py`
(synthetic crypto, the plugin's Protocol and vocabularies). What was handed
over is read off `port.pending`; refusals off the agent's result; "nothing
allocated" off the transport counter, which only `inflight.begin` writes."""
import base64
import dataclasses
import datetime
import hashlib
import json
import os
import types
import unittest
from pathlib import Path
from unittest import mock

from router import (classify, config as config_mod, exposure, hoplink, inflight, outbound,
                    peerlane, peerverify, reset as reset_mod, transport)
from router.config import ConfigError
from router.tests import helpers, peer_standin as si
from router.tests.helpers import read_json, result_path, write_request
from router.tests.test_classify import FD, OLD_ENOUGH, STAMP, T1, T2, make_cfg, with_age
from router.tests.test_inflight import FakeTransport

KEY_ID = "rl-key-1"
PEER_KEY_ID = "peer-key-1"
TRUSTED = f"carol@{T1}"
NOW = datetime.datetime(2026, 10, 13, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _seed(tag: bytes) -> bytes:
    return hashlib.sha256(b"seed" + tag).digest()


class _Base(helpers.RouterTestCase):
    """A config with `delegation`, its seed file written 0400 in a private
    directory, and the stand-in plugin."""

    def setUp(self):
        super().setUp()
        peerlane.forget_all()
        self.addCleanup(peerlane.forget_all)
        self.keys = self.tmp / "keys"
        self.keys.mkdir(mode=0o700)
        self.seed = _seed(b"rl")
        self.seed_path = self.keys / "seed"
        self.seed_path.write_bytes(self.seed)
        os.chmod(self.seed_path, 0o400)
        self.peer_pub = si.public_key(_seed(b"peer"))
        self.calls = []
        self.sign_fails, self.verify_fails = [False], [False]
        self.plugin = si.Plugin(si.namespace(calls=self.calls, sign_fails=self.sign_fails,
                                             verify_fails=self.verify_fails))

    def dconf(self, **over) -> config_mod.DelegationConfig:
        fields = dict(
            partition_verified="probe-evidence-1", signing_key_path=str(self.seed_path),
            signing_key_id=KEY_ID, signing_public_key=si.public_key(self.seed).hex(),
            runtimes=(config_mod.DelegationRuntime(
                name="host-a", runtime=f"amap.router@{T1}", domains=(T1,),
                keys=(types.MappingProxyType({"key_id": PEER_KEY_ID,
                                              "public_key": self.peer_pub.hex()}),)),),
            crypto_backend="pyca", openssl_path=None,
            forbidden_roots=(str(self.state_dir),))
        fields.update(over)
        return config_mod.DelegationConfig(**fields)

    def cfg(self, *, alice=None, **over):
        cfg = make_cfg(self, alice=alice)
        cfg = dataclasses.replace(cfg, delegation=self.dconf(**over))
        return with_age(cfg, OLD_ENOUGH)

    def activate(self, cfg):
        d = peerlane.activate(cfg, self.plugin, now=NOW)
        peerlane.install(cfg, d)
        return d


# ---------------------------------------------------------------------------
# The config block (lexical checks)
# ---------------------------------------------------------------------------

class DelegationConfigTests(helpers.RouterTestCase):

    def doc(self, **over):
        root = self.tmp / "alice"
        root.mkdir(exist_ok=True)
        keys = self.tmp / "keys"
        keys.mkdir(exist_ok=True)
        doc = helpers.with_hop({
            "state_dir": str(self.state_dir), "fleet_domain": FD,
            "trusted_fleet_hosts": [T1], "fleet_hosts": [T1],
            "instances": {"alice": {"namespace": str(root)}},
            "transport_plugin": {"path": "/opt/p.py", "sha256": "a" * 64}}, self.tmp)
        doc["delegation"] = {
            "partition_verified": "evidence",
            "signing_key": {"path": str(keys / "seed"), "key_id": KEY_ID,
                            "public_key": "ab" * 32},
            "runtimes": [{"name": "host-a", "runtime": f"amap.router@{T1}", "domains": [T1],
                          "keys": [{"key_id": PEER_KEY_ID, "public_key": "cd" * 32}]}],
            "crypto": {"crypto_backend": "pyca"}}
        for k, v in over.items():
            doc["delegation"][k] = v
        return doc

    def refused(self, doc, phrase):
        try:
            config_mod.load_obj(doc)
        except ConfigError as e:
            self.assertIn(phrase, str(e))
            return
        except Exception as e:  # noqa: BLE001
            self.fail(f"expected a ConfigError, got {type(e).__name__}: {e}")
        self.fail("loaded; expected a ConfigError")

    def test_the_valid_twin_loads(self):
        cfg = config_mod.load_obj(self.doc())
        self.assertEqual(cfg.delegation.signing_key_id, KEY_ID)
        self.assertEqual(cfg.delegation.crypto_settings(), {"crypto_backend": "pyca"})
        self.assertEqual(cfg.delegation.key_table_input()[0]["domains"], [T1])

    def test_a_domain_belongs_to_exactly_one_runtime(self):
        """A peer domain belongs to exactly one configured runtime (the
        profile's addressing section): a second runtime listing it, in any
        case, is refused, and the distinct-domain twin loads."""
        def runtimes(second_domains):
            return [{"name": "host-a", "runtime": f"amap.router@{T1}", "domains": [T1],
                     "keys": [{"key_id": PEER_KEY_ID, "public_key": "cd" * 32}]},
                    {"name": "host-b", "runtime": f"amap.router@{T2}", "domains": second_domains,
                     "keys": [{"key_id": "peer-key-b", "public_key": "ef" * 32}]}]
        def doc(second_domains):
            d = self.doc(runtimes=runtimes(second_domains))
            d["trusted_fleet_hosts"] = d["fleet_hosts"] = [T1, T2]
            return d
        cfg = config_mod.load_obj(doc([T2]))
        self.assertEqual([r.domains for r in cfg.delegation.runtimes], [(T1,), (T2,)])
        for shared in ([T2, T1], [T2, T1.upper()]):
            with self.subTest(domains=shared):
                self.refused(doc(shared), "domain_shared")

    def test_the_attachment_basis(self):
        """Absent: None (every signed attachment unscanned). The one value
        is "closed_fleet"; anything else is refused at load."""
        self.assertIsNone(config_mod.load_obj(self.doc()).delegation.attachment_basis)
        cfg = config_mod.load_obj(self.doc(attachment_basis="closed_fleet"))
        self.assertEqual(cfg.delegation.attachment_basis, "closed_fleet")
        for bad in ("clean", "", None, True, "CLOSED_FLEET"):
            with self.subTest(value=bad):
                self.refused(self.doc(attachment_basis=bad), "attachment_basis")

    def test_partition_evidence_is_required(self):
        """The fail-stop: delegation without the deploy's partition evidence."""
        for bad in ("", "   ", None, 7):
            with self.subTest(value=bad):
                self.refused(self.doc(partition_verified=bad), "partition_verified")

    def test_delegation_needs_the_hop_and_the_plugin(self):
        doc = self.doc()
        del doc["hop"], doc["transport_plugin"]
        self.refused(doc, "requires config.transport_plugin and config.hop")

    def test_the_key_path_must_be_in_normal_form(self):
        base = str(self.tmp / "keys")
        for bad in ("relative/seed", base + "/", base + "//seed", base + "/./seed",
                    base + "/../keys/seed", ""):
            with self.subTest(path=bad):
                sk = {"path": bad, "key_id": KEY_ID, "public_key": "ab" * 32}
                self.refused(self.doc(signing_key=sk), "signing_key.path")

    def test_a_non_normal_path_is_refused_for_its_spelling_first(self):
        """The spelling check runs BEFORE containment: a path that would be
        "inside" a forbidden root only by its `..` is refused as not normal."""
        bad = str(self.state_dir) + "/x/../../keys/seed"
        sk = {"path": bad, "key_id": KEY_ID, "public_key": "ab" * 32}
        self.refused(self.doc(signing_key=sk), "a '.' or '..' component")

    def test_the_key_path_stays_outside_every_forbidden_root_by_components(self):
        doc = self.doc()
        inside = {"path": str(self.state_dir / "seed"), "key_id": KEY_ID,
                  "public_key": "ab" * 32}
        self.refused(self.doc(signing_key=inside), "which the signing key must stay outside")
        trap = self.tmp / (self.state_dir.name + "x")   # a string prefix, not a component
        trap.mkdir()
        sk = {"path": str(trap / "seed"), "key_id": KEY_ID, "public_key": "ab" * 32}
        try:
            config_mod.load_obj(self.doc(signing_key=sk))
        except ConfigError as e:
            self.fail(f"a string-prefix neighbour was refused as inside the root: {e}")
        del doc

    def test_a_symlinked_alias_of_a_forbidden_root_is_caught(self):
        real = self.tmp / "real-state"
        real.mkdir()
        alias = self.tmp / "alias-state"
        alias.symlink_to(real)
        doc = self.doc(signing_key={"path": str(real / "seed"), "key_id": KEY_ID,
                                    "public_key": "ab" * 32})
        doc["state_dir"] = str(alias)
        self.refused(doc, "which the signing key must stay outside")

    def test_the_public_key_is_64_lower_hex(self):
        for bad in ("AB" * 32, "ab" * 31, "zz" * 32, 7):
            with self.subTest(value=bad):
                sk = {"path": str(self.tmp / "keys" / "seed"), "key_id": KEY_ID,
                      "public_key": bad}
                self.refused(self.doc(signing_key=sk), "public_key")

    def test_runtime_shapes_are_refused_before_the_gate(self):
        good = {"name": "host-a", "runtime": f"amap.router@{T1}", "domains": [T1],
                "keys": [{"key_id": PEER_KEY_ID, "public_key": "cd" * 32}]}
        cases = {
            "not an object": ["x"],
            "extra member": [dict(good, extra=1)],
            "keys not a list": [dict(good, keys={})],
            "a key not an object": [dict(good, keys=["x"])],
            "a key missing public_key": [dict(good, keys=[{"key_id": "k"}])],
            "a non-string key value": [dict(good, keys=[{"key_id": "k", "public_key": 7}])],
        }
        for why, runtimes in cases.items():
            with self.subTest(why=why):
                self.refused(self.doc(runtimes=runtimes), "key_malformed")

    def test_a_runtime_is_a_trusted_host_at_its_own_router_address(self):
        good = {"name": "host-a", "runtime": f"amap.router@{T1}", "domains": [T1],
                "keys": []}
        self.refused(self.doc(runtimes=[dict(good, domains=["other.example"],
                                             runtime="amap.router@other.example")]),
                     "not in config.trusted_fleet_hosts")
        self.refused(self.doc(runtimes=[dict(good, runtime=f"x@{T1}")]), "runtime: must be")
        self.refused(self.doc(runtimes=[dict(good, domains=[FD], runtime=f"amap.router@{FD}")]),
                     "own domain")

    def test_the_crypto_settings(self):
        self.refused(self.doc(crypto={"crypto_backend": "rot13"}), "crypto_backend")
        self.refused(self.doc(crypto={"crypto_backend": "openssl"}), "openssl_path")
        cfg = config_mod.load_obj(self.doc(crypto={"crypto_backend": "openssl",
                                                   "openssl_path": "/usr/bin/openssl"}))
        self.assertEqual(cfg.delegation.crypto_settings(),
                         {"crypto_backend": "openssl", "openssl_path": "/usr/bin/openssl"})


# ---------------------------------------------------------------------------
# Activation: the plugin seam, the key, the gate, the probe
# ---------------------------------------------------------------------------

class CheckDelegationTests(unittest.TestCase):

    def check(self, ns):
        return transport.check_delegation(si.Plugin(ns))

    def refused(self, ns, phrase):
        with self.assertRaises(transport.PluginRefused) as cm:
            self.check(ns)
        self.assertEqual(cm.exception.reason, "delegation_capability_missing")
        self.assertIn(phrase, cm.exception.detail)

    def test_a_3_3_plugin_with_the_metadata_passes(self):
        caps = self.check(si.namespace())
        self.assertEqual(set(caps.errors), set(transport.PEER_ERROR_NAMES))
        self.assertIs(caps.errors["CodecError"], si.CodecError)

    def test_a_3_2_plugin_with_every_name_injected_is_refused(self):
        self.refused(si.namespace(api=(3, 2)), "below (3, 3)")

    def test_each_factory_must_be_callable(self):
        for name in transport.DELEGATION_FACTORIES:
            with self.subTest(name=name):
                ns = si.namespace()
                ns[name] = 7
                self.refused(ns, name)

    def test_the_plugin_metadata_must_declare_both_names_at_3_3(self):
        for name in ("make_peer_codec", "make_peer_errors"):
            for bad in (None, (3, 2), "3.3", (3, True)):
                with self.subTest(name=name, value=bad):
                    ns = si.namespace()
                    meta = dict(ns["OPTIONAL_FACTORIES"])
                    if bad is None:
                        del meta[name]
                    else:
                        meta[name] = bad
                    ns["OPTIONAL_FACTORIES"] = meta
                    self.refused(ns, name)
        ns = si.namespace()
        ns["OPTIONAL_FACTORIES"] = types.MappingProxyType(ns["OPTIONAL_FACTORIES"])
        self.refused(ns, "not a dict")

    def test_the_errors_mapping_is_exact_and_its_classes_validated(self):
        class Sub(si.CodecError):
            pass
        cases = {
            "an extra key": dict(si.namespace()["make_peer_errors"](), HopAnomaly=ValueError),
            "a missing key": {k: v for k, v in si.namespace()["make_peer_errors"]().items()
                              if k != "ConfigError"},
            "a built-in class": dict(si.namespace()["make_peer_errors"](),
                                     ConfigError=ValueError),
            "a subclass of another": dict(si.namespace()["make_peer_errors"](),
                                          ConfigError=Sub),
            "not a class": dict(si.namespace()["make_peer_errors"](), ConfigError="x"),
        }
        for why, mapping in cases.items():
            with self.subTest(why=why):
                ns = si.namespace()
                ns["make_peer_errors"] = lambda m=mapping: m
                with self.assertRaises(transport.PluginRefused):
                    self.check(ns)

    def test_make_peer_errors_is_called_with_no_arguments_exactly_once(self):
        calls = []
        self.check(si.namespace(calls=calls))
        self.assertEqual(calls, [("make_peer_errors", ())])


class ActivationTests(_Base):

    def activate_ok(self, cfg):
        """Activation that must succeed: any refusal is a FAILURE."""
        try:
            return peerlane.activate(cfg, self.plugin, now=NOW)
        except peerlane.DelegationRefused as e:
            self.fail(f"activation refused: {e}")

    def test_a_matching_seed_and_public_key_activate(self):
        """The POSITIVE exact path: the configured public key is proved to
        be the seed's by the probe, with the 32 bytes the gate validated."""
        d = self.activate_ok(self.cfg())
        self.assertEqual(d.key_id, KEY_ID)
        self.assertEqual(d.reasons, si.REASONS)

    def test_the_factories_are_called_with_exactly_their_declared_arguments(self):
        """`make_peer_codec(settings={})`, `make_peer_errors()`, and the
        signer and verifier with exactly the crypto settings."""
        self.activate_ok(self.cfg())
        self.assertEqual(self.calls, [("make_peer_errors", ()), ("make_peer_codec", {}),
                                      ("make_signer", {"crypto_backend": "pyca"}),
                                      ("make_verifier", {"crypto_backend": "pyca"})])

    def test_a_public_key_of_another_seed_is_a_mismatch(self):
        other = si.public_key(_seed(b"someone-else")).hex()
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(signing_public_key=other), self.plugin, now=NOW)
        self.assertEqual(cm.exception.reason, "signing_key_mismatch")

    def test_our_key_id_may_not_be_a_peers(self):
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(signing_key_id=PEER_KEY_ID), self.plugin, now=NOW)
        self.assertEqual(cm.exception.reason, "duplicate_key_id")

    def test_the_key_gate_refuses_with_its_token(self):
        bad = si.public_key(_seed(b"small"))
        si.SMALL_ORDER.add(bad)
        self.addCleanup(si.SMALL_ORDER.discard, bad)
        runtimes = (config_mod.DelegationRuntime(
            name="host-a", runtime=f"amap.router@{T1}", domains=(T1,),
            keys=(types.MappingProxyType({"key_id": PEER_KEY_ID, "public_key": bad.hex()}),)),)
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(runtimes=runtimes), self.plugin, now=NOW)
        self.assertEqual(cm.exception.reason, "key_small_order")

    def test_our_own_key_goes_through_the_same_gate(self):
        pub = si.public_key(self.seed)
        si.NON_CANONICAL.add(pub)
        self.addCleanup(si.NON_CANONICAL.discard, pub)
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(), self.plugin, now=NOW)
        self.assertEqual(cm.exception.reason, "key_not_canonical")

    def test_a_local_fault_in_the_probe_is_never_a_mismatch(self):
        self.verify_fails[0] = True
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(), self.plugin, now=NOW)
        self.assertEqual(cm.exception.reason, "backend")

    def test_the_seed_file_rules(self):
        cases = {}
        os.chmod(self.seed_path, 0o600)
        cases["mode 0600"] = "0400 required"
        for why, phrase in cases.items():
            with self.subTest(why=why):
                with self.assertRaises(peerlane.DelegationRefused) as cm:
                    peerlane.activate(self.cfg(), self.plugin, now=NOW)
                self.assertIn(phrase, cm.exception.detail)
        os.chmod(self.seed_path, 0o400)

    def test_a_seed_of_the_wrong_size_is_refused(self):
        short = self.keys / "short"
        short.write_bytes(b"x" * 31)
        os.chmod(short, 0o400)
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(signing_key_path=str(short)), self.plugin, now=NOW)
        self.assertIn("exactly 32 bytes", cm.exception.detail)

    def test_a_hard_linked_seed_is_refused(self):
        os.link(self.seed_path, self.keys / "second")
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(), self.plugin, now=NOW)
        self.assertIn("2 links", cm.exception.detail)

    def test_a_symlink_anywhere_on_the_path_is_refused(self):
        link = self.tmp / "keys-link"
        link.symlink_to(self.keys)
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(signing_key_path=str(link / "seed")), self.plugin,
                              now=NOW)
        self.assertIn("a symlink", cm.exception.detail)
        final = self.keys / "seed-link"
        final.symlink_to(self.seed_path)
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(self.cfg(signing_key_path=str(final)), self.plugin, now=NOW)
        self.assertIn("a symlink", cm.exception.detail)

    def test_a_group_writable_ancestor_is_refused(self):
        os.chmod(self.keys, 0o770)
        try:
            with self.assertRaises(peerlane.DelegationRefused) as cm:
                peerlane.activate(self.cfg(), self.plugin, now=NOW)
        finally:
            os.chmod(self.keys, 0o700)
        self.assertIn("writable by group or others", cm.exception.detail)

    def test_a_forbidden_root_swapped_into_the_path_is_refused(self):
        """Step 4, the identity check: a forbidden root renamed into the
        key's path after the lexical check is caught by its (dev, ino)."""
        forbidden = self.tmp / "forbidden"
        forbidden.mkdir(mode=0o700)
        (forbidden / "seed").write_bytes(self.seed)
        os.chmod(forbidden / "seed", 0o400)
        swapped = self.tmp / "swapped"
        os.rename(forbidden, swapped)
        cfg = self.cfg(signing_key_path=str(swapped / "seed"),
                       forbidden_roots=(str(swapped),))
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            peerlane.activate(cfg, self.plugin, now=NOW)
        self.assertIn("a forbidden root", cm.exception.detail)


class ErrorKindTests(_Base):

    def test_only_the_exact_classes_with_a_known_reason_count(self):
        d = peerlane.activate(self.cfg(), self.plugin, now=NOW)

        class Impostor(Exception):
            reason = "signature"

        class Sub(si.CodecError):
            pass
        self.assertEqual(peerlane.error_kind(d, si.CodecError("codec", "signature")), "CodecError")
        self.assertIsNone(peerlane.error_kind(d, Impostor()))
        self.assertIsNone(peerlane.error_kind(d, Sub("codec", "signature")))
        self.assertIsNone(peerlane.error_kind(d, si.CodecError("codec", "nope")))
        self.assertEqual(peerlane.error_kind(d, si.KeyConfigError("key_malformed")),
                         "KeyConfigError")
        self.assertIsNone(peerlane.error_kind(d, si.KeyConfigError("key_id_not_fingerprint")))
        self.assertEqual(peerlane.error_kind(d, si.BackendError()), "BackendError")
        self.assertEqual(peerlane.error_kind(d, si.ConfigError()), "ConfigError")


class ReasonPinTests(unittest.TestCase):
    """The plugin's published vocabularies, pinned (13 and 5). The stand-in
    must use exactly these, so every test here exercises the real sets."""

    def test_the_pinned_sets(self):
        self.assertEqual(len(si.REASONS), 13)
        self.assertEqual(len(si.KEY_CONFIG_REASONS), 5)
        self.assertIs(si.PeerCodec.REASONS, si.REASONS)
        self.assertIs(si.PeerCodec.KEY_CONFIG_REASONS, si.KEY_CONFIG_REASONS)
        self.assertNotIn("key_id_not_fingerprint", si.KEY_CONFIG_REASONS)


# ---------------------------------------------------------------------------
# Sending: the signed task through the drain
# ---------------------------------------------------------------------------

class _Send(_Base):

    def setUp(self):
        super().setUp()
        self.port = FakeTransport()
        p = mock.patch.object(exposure, "assess", return_value=STAMP)
        p.start()
        self.addCleanup(p.stop)

    def drain(self, cfg, **kw):
        return outbound.drain_instance(cfg, "alice", transport=self.port, **kw)

    def result(self, cfg, req_id="00000001"):
        p = result_path(cfg, "alice", req_id)
        return read_json(p) if p.exists() else None

    def answered(self, cfg, req_id="00000001"):
        r = self.result(cfg, req_id)
        self.assertIsNotNone(r, "the request was not answered")
        return r

    def handover(self, n="00000001"):
        self.assertIn(n, self.port.pending, "nothing was handed over")
        return json.loads(self.port.pending[n])

    def nothing_allocated(self, cfg):
        self.assertFalse(inflight.counter_path(cfg, "alice").exists())
        self.assertEqual(inflight.list_records(cfg, "alice"), [])
        self.assertEqual(self.port.writes, [])
        self.assertFalse((self.state_dir / "alice" / peerlane.PEER_LEDGER_DIR).exists())


class SendTests(_Send):

    def test_a_signed_peer_task_is_handed_over(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED], body_text="a\r\nb")
        self.drain(cfg)
        doc = self.handover()
        env = doc["envelope"]
        self.assertEqual(env["kind"], "peer")
        peer = env["peer"]
        self.assertEqual(set(peer), set(hoplink.PEER_MEMBERS))
        self.assertIsNone(peer["in_reply_to"])
        self.assertEqual(peer["references"], [])
        self.assertTrue(peer["message_id"].endswith(f"@{FD}>"))
        kind, k, statement, signature = si.check1([(peerlane.STATEMENT_FIELD,
                                                    peer["statement_header"])])
        self.assertEqual((kind, k), ("statement", KEY_ID))
        st = json.loads(statement)
        self.assertEqual((st["from"], st["to"], st["kind"], st["v"]),
                         (f"alice@{FD}", TRUSTED, "peer", 1))
        self.assertEqual(st["body_sha256"], hashlib.sha256(b"a\nb").hexdigest())
        self.assertEqual(st["sender_exposure"], STAMP)
        self.assertEqual(st["sender_since"], OLD_ENOUGH)
        self.assertEqual(peer["message_id"], f"<{st['id']}@{FD}>")
        self.assertTrue(si.Verifier([False]).verify(si.public_key(self.seed), statement,
                                                    signature))
        self.assertEqual(doc["request"]["draft"]["to"], [TRUSTED])
        self.assertEqual(doc["request"]["draft"]["body_text"], "a\nb")
        self.assertIsNone(self.result(cfg))

    def test_the_issued_ledger_record_is_closed_and_keyed_by_logical_id(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(cfg)
        record = inflight.read_record(cfg, "alice", "00000001")
        led = peerlane.read_ledger(cfg, "alice", record["peer"]["id"])
        self.assertEqual(set(led), set(peerlane.LEDGER_MEMBERS))
        self.assertEqual((led["direction"], led["local"], led["remote"], led["local_address"]),
                         ("issued", "alice", TRUSTED, f"alice@{FD}"))
        self.assertEqual(led["generation"], "alice")

    def test_the_ledger_write_is_durable_from_state_dir(self):
        cfg = self.cfg()
        self.activate(cfg)
        with mock.patch.object(peerlane, "atomic_write", wraps=peerlane.atomic_write) as aw:
            write_request(cfg, "alice", "00000001", to=[TRUSTED])
            self.drain(cfg)
        self.assertEqual(aw.call_count, 1)
        self.assertEqual(aw.call_args.kwargs.get("durable_root"), cfg.state_dir)

    def test_the_ledger_is_durable_before_the_hand_over(self):
        """At the transport write the issued record already exists."""
        cfg = self.cfg()
        self.activate(cfg)
        seen = []
        real = self.port.write_request

        def write(n, data):
            hdr = json.loads(data)["envelope"]["peer"]["statement_header"]
            pid = json.loads(si.check1([(peerlane.STATEMENT_FIELD, hdr)])[2])["id"]
            seen.append(peerlane.read_ledger(cfg, "alice", pid) is not None)
            real(n, data)
        self.port.write_request = write
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(cfg)
        self.assertEqual(seen, [True])

    def test_the_ledger_is_written_before_the_in_flight_record(self):
        """A crash between the ledger and the record leaves the ledger and no
        record: the request is re-processed under a new id later."""
        cfg = self.cfg()
        self.activate(cfg)
        order = []
        real = inflight._effect

        def effect(label, fn, *a, **kw):
            order.append(label)
            return real(label, fn, *a, **kw)
        with mock.patch.object(inflight, "_effect", effect):
            write_request(cfg, "alice", "00000001", to=[TRUSTED])
            self.drain(cfg)
        self.assertLess(order.index("ledger"), order.index("record"))
        self.assertLess(order.index("counter"), order.index("ledger"))

    def test_retries_hand_over_byte_identical_bytes(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        record = inflight.read_record(cfg, "alice", "00000001")
        a = inflight.transport_request_bytes(cfg, "alice", record, req_id="00000001")
        b = inflight.transport_request_bytes(cfg, "alice", record, req_id="00000001")
        self.assertEqual(a, b)

    def test_a_local_signer_fault_holds_unconsumed(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.sign_fails[0] = True
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        summary = self.drain(cfg)
        self.assertEqual(summary["outbound_errored"], 0,
                         "a local signer fault is a hold, never an isolated error")
        self.assertIsNone(self.result(cfg))
        self.nothing_allocated(cfg)
        self.sign_fails[0] = False
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_a_statement_the_codec_refuses_is_never_signed(self):
        cfg = self.cfg()
        d = self.activate(cfg)
        with mock.patch.object(si.PeerCodec, "decode_statement",
                               staticmethod(lambda raw, k: (_ for _ in ()).throw(
                                   si.CodecError("schema", "statement_schema")))):
            write_request(cfg, "alice", "00000001", to=[TRUSTED])
            self.drain(cfg)
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]), ("queued_for_human",
                                                            "transport_anomaly"))
        self.nothing_allocated(cfg)
        del d

    def test_the_exact_8192_and_8193_byte_boundary(self):
        """The size check is exact, before anything is allocated: a statement
        of exactly 8192 bytes is begun, one of 8193 is refused."""
        cfg = self.cfg()
        d = self.activate(cfg)
        base = len(classify.peer_statement(cfg, "alice", {"subject": ""}, TRUSTED, STAMP, d,
                                           peer_id=peerlane.SIZE_ID, ts=peerlane.SIZE_TS))
        for total, req_id, ok in ((8192, "00000001", True), (8193, "00000002", False)):
            with self.subTest(total=total):
                subject = "s" * (total - base)
                self.assertEqual(len(classify.peer_statement(
                    cfg, "alice", {"subject": subject}, TRUSTED, STAMP, d,
                    peer_id=peerlane.mint_peer_id(), ts="2026-10-13T12:00:00Z")), total)
                write_request(cfg, "alice", req_id, to=[TRUSTED], subject=subject)
                self.drain(cfg)
                if ok:
                    self.assertIsNone(self.result(cfg, req_id))
                    self.assertIn(req_id, inflight.list_records(cfg, "alice"))
                else:
                    r = self.answered(cfg, req_id)
                    self.assertEqual(r["reason_code"], "peer_statement_too_large")
                    self.assertNotIn(req_id, inflight.list_records(cfg, "alice"))

    def test_without_delegation_item_5e_refuses(self):
        cfg = self.cfg()
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(cfg)
        self.assertEqual(self.answered(cfg)["reason_code"], "recipient_unknown")
        self.nothing_allocated(cfg)


class PublicationRecheckTests(_Send):

    def stage(self, cfg):
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        self.assertEqual(inflight.list_records(cfg, "alice"), ["00000001"])
        self.assertEqual(self.port.writes, [])

    def refused(self, cfg, detail):
        self.assertEqual(self.port.writes, [])
        r = self.answered(cfg)
        self.assertEqual((r["outcome"], r["reason_code"]),
                         ("queued_for_human", "recipient_not_allowlisted"))
        self.assertEqual(r["detail"], f"policy changed before publication: {detail}")

    def test_an_unchanged_policy_publishes(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.stage(cfg)
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])

    def test_a_rotated_signing_key_refuses_an_unpublished_task(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.stage(cfg)
        rotated = self.cfg(signing_key_id="rl-key-2")
        self.activate(rotated)
        self.drain(rotated)
        self.refused(cfg, outbound.DETAIL_KEY_ROTATED)

    def test_rotation_never_marks_a_handed_task(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(cfg)
        self.assertEqual(self.port.writes, ["00000001"])
        rotated = self.cfg(signing_key_id="rl-key-2")
        self.activate(rotated)
        self.drain(rotated)
        record = inflight.read_record(rotated, "alice", "00000001")
        self.assertNotIn("revocation_unenforceable", record)

    def test_a_task_deny_refuses(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.stage(cfg)
        denied = self.cfg(alice={"task_deny": [TRUSTED]})
        self.activate(denied)
        self.drain(denied)
        self.refused(cfg, "now peer_denied")

    def test_a_recipient_no_longer_trusted_refuses(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.stage(cfg)
        moved = dataclasses.replace(cfg, trusted_fleet_hosts=(T2,))
        self.drain(moved)
        self.refused(cfg, "route changed from trusted_fleet_host to fleet_host")

    def test_delegation_removed_refuses(self):
        cfg = self.cfg()
        self.activate(cfg)
        self.stage(cfg)
        peerlane.forget_all()
        self.drain(cfg)
        self.refused(cfg, "delegation is not active")


class RecordSchemaTests(_Send):

    def staged(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        return cfg, inflight.read_record(cfg, "alice", "00000001")

    def test_an_unknown_signed_kind_has_no_producer(self):
        _cfg, record = self.staged()
        record["peer"]["kind"] = "bogus"
        with self.assertRaisesRegex(inflight.RecordDamaged, "no production producer"):
            inflight.check_record(record, runtime=True)
        with self.assertRaisesRegex(inflight.RecordDamaged, "no production producer"):
            inflight.check_record(record)

    def test_a_control_pin_is_damage_outside_the_runtime_namespace(self):
        _cfg, record = self.staged()
        record["peer"]["kind"] = "control"
        # The kind check runs before the statement's own kind is compared,
        # so the namespace rule is what refuses it.
        with self.assertRaisesRegex(inflight.RecordDamaged, "kind|namespace"):
            inflight.check_record(record)
        with self.assertRaisesRegex(inflight.RecordDamaged, "wrong namespace"):
            inflight.check_record(self.staged()[1], runtime=True)

    def test_a_pin_naming_another_recipient_is_damage(self):
        _cfg, record = self.staged()
        record["recipients"] = [f"dave@{T1}"]
        with self.assertRaisesRegex(inflight.RecordDamaged, "other than the evaluated one"):
            inflight.check_record(record)

    def test_a_header_not_carrying_the_pinned_statement_is_never_handed_over(self):
        cfg, record = self.staged()
        other = peerlane.Signed(b"{}", b"\0" * 64, si.format_field(KEY_ID, b"{}", b"\0" * 64))
        record["peer"]["statement_header"] = other.header
        with self.assertRaisesRegex(inflight.HandoverUnavailable, "does not carry"):
            inflight.transport_request_bytes(cfg, "alice", record, req_id="00000001")


class ResetKeepsTheLedgerTests(_Send):

    def test_reset_keeps_the_peer_ledger(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(cfg)
        pid = inflight.read_record(cfg, "alice", "00000001")["peer"]["id"]
        self.assertTrue(reset_mod._kept(cfg, peerlane.PEER_LEDGER_DIR))
        reset_mod.reset_instance(cfg, "alice")
        self.assertIsNotNone(peerlane.read_ledger(cfg, "alice", pid),
                             "a reply to an issued task must still resolve after a reset")


class ControlKindTests(_Base):

    def test_a_control_handover_is_well_formed(self):
        d = peerlane.activate(self.cfg(), self.plugin, now=NOW)
        signed = peerlane.sign_control(d, {"kind": "control", "v": 1, "id": "x"})
        doc = json.loads(hoplink.build_handover(
            {}, from_address=f"amap.router@{FD}", version_write=1, attachments=(),
            settled_through=0, kind="control",
            peer={"statement_header": signed.header, "message_id": f"<x@{FD}>",
                  "in_reply_to": None, "references": []}))
        self.assertEqual(doc["envelope"]["kind"], "control")

    def test_q9_the_message_id_domain_is_the_from_address_domain(self):
        peer = {"statement_header": "k=a; s=b; b=c", "message_id": "<x@other.example>",
                "in_reply_to": None, "references": []}
        self.assertEqual(hoplink.peer_problem(peer, f"alice@{FD}"),
                         "message_id's domain is not from_address's")
        with self.assertRaises(ValueError):
            hoplink.build_handover({}, from_address=f"alice@{FD}", version_write=1,
                                   attachments=(), settled_through=0, kind="peer", peer=peer)
        with self.assertRaises(ValueError):
            hoplink.build_handover({}, from_address=f"alice@{FD}", version_write=1,
                                   attachments=(), settled_through=0, kind="peer", peer=None)


# ---------------------------------------------------------------------------
# Verification (checks 1, 3, 4, 5; check 2 is the caller's)
# ---------------------------------------------------------------------------

class VerifyTests(_Base):

    def setUp(self):
        super().setUp()
        self.d = peerlane.activate(self.cfg(), self.plugin, now=NOW)
        self.peer_seed = _seed(b"peer")

    def statement(self, **over):
        doc = {"v": 1, "key_id": PEER_KEY_ID, "kind": "peer", "id": "abc"}
        doc.update(over)
        return json.dumps(doc).encode()

    def field(self, statement, seed=None, k=PEER_KEY_ID):
        sig = si._sign(seed or self.peer_seed, statement)
        return (peerlane.STATEMENT_FIELD, si.format_field(k, statement, sig))

    def verify(self, fields, known=lambda k, s: False, now=NOW):
        return peerverify.verify(fields, delegation=self.d, now=now, known=known)

    def test_a_good_statement_verifies(self):
        v = self.verify([self.field(self.statement())])
        self.assertIsInstance(v, peerverify.Verified)
        self.assertEqual(v.kind, "statement")

    def test_forged_stripped_and_duplicate_headers(self):
        s = self.statement()
        self.assertEqual(self.verify([self.field(s, seed=_seed(b"forger"))]),
                         peerverify.Refused("signature"))
        self.assertEqual(self.verify([("Subject", "x")]), peerverify.Refused("no_statement"))
        self.assertEqual(self.verify([self.field(s), self.field(s)]),
                         peerverify.Refused("header_count"))
        both = [self.field(s), (peerlane.CONTROL_FIELD, self.field(s)[1])]
        self.assertEqual(self.verify(both), peerverify.Refused("header_count"))

    def test_check_2_runs_before_the_key(self):
        s = self.statement(key_id="removed-key")
        self.assertEqual(self.verify([self.field(s, k="removed-key")], known=lambda k, st: True),
                         peerverify.Refused("duplicate"))

    def test_an_unknown_key(self):
        s = self.statement(key_id="nobody")
        self.assertEqual(self.verify([self.field(s, k="nobody")]),
                         peerverify.Refused("unknown_key"))

    def test_live_revocation_at_not_after_with_no_reload(self):
        runtimes = (config_mod.DelegationRuntime(
            name="host-a", runtime=f"amap.router@{T1}", domains=(T1,),
            keys=(types.MappingProxyType({"key_id": PEER_KEY_ID,
                                          "public_key": self.peer_pub.hex(),
                                          "not_after": "2026-10-13T12:00:00Z"}),)),)
        d = peerlane.activate(self.cfg(runtimes=runtimes), self.plugin, now=NOW)
        f = [self.field(self.statement())]
        self.assertIsInstance(peerverify.verify(f, delegation=d, now=NOW,
                                                known=lambda k, s: False), peerverify.Verified)
        later = NOW + datetime.timedelta(seconds=1)
        self.assertEqual(peerverify.verify(f, delegation=d, now=later, known=lambda k, s: False),
                         peerverify.Refused("key_validity"))

    def test_a_local_backend_fault_propagates(self):
        self.verify_fails[0] = True
        with self.assertRaises(si.BackendError):
            self.verify([self.field(self.statement())])

    def test_an_impostor_exception_propagates(self):
        class Impostor(Exception):
            reason = "signature"

        def boom(fields):
            raise Impostor()
        with mock.patch.object(si.PeerCodec, "check1", staticmethod(boom)):
            with self.assertRaises(Impostor):
                self.verify([self.field(self.statement())])


# ---------------------------------------------------------------------------
# The tombstone's bytes
# ---------------------------------------------------------------------------

class TombstoneBytesTests(unittest.TestCase):

    def good(self, **over):
        kw = dict(intake=".unresolved", ident="a" * 32, candidate_sha256="b" * 64,
                  disposition="placed", disposed_at="2026-10-13T12:00:00Z")
        kw.update(over)
        return kw

    def test_the_exact_form(self):
        raw = peerlane.tombstone_bytes(**self.good())
        doc = json.loads(raw)
        self.assertEqual(set(doc), {"v", "intake", "id", "candidate_sha256", "disposition",
                                    "disposed_at"})
        self.assertEqual(doc["v"], 1)
        self.assertRegex(doc["disposed_at"], r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
                                             r"[0-9]{2}Z\Z")
        self.assertEqual(raw, hoplink.canonical(doc))

    def test_each_member_outside_its_form(self):
        for key, bad in (("intake", ".other"), ("ident", "A" * 32), ("ident", "a" * 31),
                         ("candidate_sha256", "B" * 64), ("disposition", "kept"),
                         ("disposed_at", "2026-10-13T12:00:00+00:00"),
                         ("disposed_at", "2026-10-13T12:00:00.5Z")):
            with self.subTest(key=key, value=bad):
                with self.assertRaises(ValueError):
                    peerlane.tombstone_bytes(**self.good(**{key: bad}))


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Reload never raises; re-activation only on change; the remaining guards
# ---------------------------------------------------------------------------

import errno as _errno  # noqa: E402

from router import service  # noqa: E402


class ReloadNeverRaisesTests(_Base):
    """`service.reload_config` NEVER raises: an unclassified fault in
    delegation activation, or an I/O error reading the seed, refuses the
    reload and keeps the last good config and delegation."""

    def reload(self, current, fresh):
        runtime = types.SimpleNamespace(plugin=self.plugin)
        with mock.patch.object(service, "load", return_value=fresh):
            try:
                return service.reload_config("cfg.json", current, runtime=runtime)
            except Exception as e:  # noqa: BLE001
                self.fail(f"reload_config raised {type(e).__name__}: {e}")

    def test_an_unclassified_activation_fault_refuses_the_reload(self):
        current = self.cfg()
        kept = self.activate(current)
        fresh = self.cfg(partition_verified="new-evidence")
        with mock.patch.object(peerlane, "activate", side_effect=TypeError("a bug")):
            got = self.reload(current, fresh)
        self.assertTrue(got.reload_failed)
        self.assertEqual(got.delegation, current.delegation)
        self.assertIs(peerlane.current(current), kept, "the last good delegation stays")
        service._RELOAD_FAILURE.clear()

    def test_an_io_error_reading_the_seed_is_a_refusal(self):
        current = self.cfg()
        self.activate(current)
        fresh = self.cfg(partition_verified="new-evidence")
        real_read = os.read

        def eio(fd, n):
            if n == peerlane.SEED_BYTES + 1:
                raise OSError(_errno.EIO, "Input/output error")
            return real_read(fd, n)
        with mock.patch.object(peerlane.os, "read", eio):
            try:
                peerlane.activate(fresh, self.plugin, now=NOW)
            except peerlane.DelegationRefused as e:
                self.assertEqual(e.reason, "signing_key_path")
            except OSError as e:
                self.fail(f"the seed read's OSError escaped: {e}")
            else:
                self.fail("activation succeeded over an unreadable seed")
            got = self.reload(current, fresh)
        self.assertTrue(got.reload_failed)
        service._RELOAD_FAILURE.clear()


class CodecFactoryErrorTests(_Base):
    """`make_peer_codec({})` failing: only the plugin's own `ConfigError`,
    by EXACT type, is a refusal. Anything else, a subclass included, is a
    bug and propagates out of `activate`: at startup that stops the router
    loudly; at reload `reload_config` logs it with its traceback and keeps
    the last good config and delegation."""

    def plugin_raising(self, exc):
        ns = si.namespace(calls=self.calls)

        def make_peer_codec(settings):
            raise exc
        ns["make_peer_codec"] = make_peer_codec
        return si.Plugin(ns)

    def test_the_plugins_config_error_is_a_codec_refusal(self):
        try:
            peerlane.activate(self.cfg(), self.plugin_raising(si.ConfigError("no")), now=NOW)
        except peerlane.DelegationRefused as e:
            self.assertEqual(e.reason, "codec")
        except Exception as e:  # noqa: BLE001
            self.fail(f"the plugin's ConfigError escaped as {type(e).__name__}: {e}")
        else:
            self.fail("activation succeeded")

    def test_any_other_class_propagates(self):
        class Sub(si.ConfigError):
            pass
        for exc in (RuntimeError("a bug"), Sub("a look-alike"), ValueError("built-in")):
            with self.subTest(exc=type(exc).__name__):
                try:
                    peerlane.activate(self.cfg(), self.plugin_raising(exc), now=NOW)
                except peerlane.DelegationRefused as e:
                    self.fail(f"{type(exc).__name__} became a refusal: {e}")
                except Exception as e:  # noqa: BLE001
                    self.assertIs(e, exc)
                else:
                    self.fail("activation succeeded")

    def test_at_startup_it_propagates(self):
        bug = RuntimeError("a bug")
        runtime = types.SimpleNamespace(plugin=self.plugin_raising(bug))
        try:
            service.activate_delegation(self.cfg(), runtime)
        except Exception as e:  # noqa: BLE001
            self.assertIs(e, bug, f"startup turned the bug into {type(e).__name__}: {e}")
        else:
            self.fail("startup activation succeeded")

    def test_at_reload_it_is_logged_and_the_last_good_stays(self):
        current = self.cfg()
        kept = self.activate(current)
        fresh = self.cfg(partition_verified="new-evidence")
        runtime = types.SimpleNamespace(plugin=self.plugin_raising(RuntimeError("a bug")))
        with mock.patch.object(service, "load", return_value=fresh), \
                self.assertLogs(service.logger, "ERROR") as logs:
            try:
                got = service.reload_config("cfg.json", current, runtime=runtime)
            except Exception as e:  # noqa: BLE001
                self.fail(f"reload_config raised {type(e).__name__}: {e}")
        self.assertTrue(got.reload_failed)
        self.assertIs(peerlane.current(current), kept, "the last good delegation stays")
        self.assertEqual(service._RELOAD_FAILURE[str(self.state_dir)]["error"],
                         "delegation activation failed unexpectedly")
        self.assertTrue(any(r.exc_info and r.exc_info[0] is RuntimeError for r in logs.records),
                        "logged with its traceback")
        service._RELOAD_FAILURE.clear()


class ReactivationTests(_Base):

    def test_an_unchanged_delegation_is_not_reactivated(self):
        cfg = self.cfg()
        runtime = types.SimpleNamespace(plugin=self.plugin)
        service.activate_delegation(cfg, runtime)
        service.activate_delegation(cfg, runtime)
        self.assertEqual([c for c, _ in self.calls].count("make_signer"), 1)

    def test_a_changed_seed_file_is_reactivated(self):
        cfg = self.cfg()
        runtime = types.SimpleNamespace(plugin=self.plugin)
        service.activate_delegation(cfg, runtime)
        os.chmod(self.seed_path, 0o600)
        try:
            with self.assertRaises(peerlane.DelegationRefused):
                service.activate_delegation(cfg, runtime)
        finally:
            os.chmod(self.seed_path, 0o400)


class StatementFieldsTests(unittest.TestCase):

    def test_exposure_and_sender_since_are_mandatory(self):
        base = dict(key_id=KEY_ID, peer_id=peerlane.SIZE_ID, from_address=f"alice@{FD}",
                    to_address=TRUSTED, ts="2026-10-13T12:00:00Z", subject="", body_text="",
                    attachments=[], sender_exposure=STAMP, sender_since=OLD_ENOUGH)
        peerlane.build_statement(**base)
        for missing in ("sender_exposure", "sender_since"):
            with self.subTest(missing=missing):
                with self.assertRaises(peerlane.StatementRefused):
                    peerlane.build_statement(**dict(base, **{missing: None}))


class MintTests(unittest.TestCase):
    """The peer id is at least 128 bits and spelled under the notice_id
    charset, so it never starts with `-`: 17 random bytes, unpadded
    base64url (23 characters), re-drawn while the first is `-`."""

    def test_a_leading_dash_is_redrawn(self):
        dash = b"\xf8" + b"\x00" * 16          # base64url "-" first
        plain = b"\x00" * 17
        self.assertTrue(base64.urlsafe_b64encode(dash).decode().startswith("-"))
        with mock.patch.object(peerlane.secrets, "token_bytes", side_effect=[dash, plain]) as tb:
            got = peerlane.mint_peer_id()
        self.assertEqual(got, base64.urlsafe_b64encode(plain).rstrip(b"=").decode())
        self.assertEqual([c.args for c in tb.call_args_list], [(17,), (17,)])
        self.assertEqual(len(got), 23)

    def test_every_mint_matches_the_issued_grammar(self):
        for _ in range(10000):
            peer_id = peerlane.mint_peer_id()
            self.assertEqual(len(peer_id), 23)
            self.assertIsNotNone(peerlane.PEER_ID_RE.fullmatch(peer_id), peer_id)
            self.assertNotEqual(peer_id[0], "-")

    def test_the_size_stand_in_is_the_length_of_a_mint(self):
        self.assertEqual(len(peerlane.SIZE_ID), len(peerlane.mint_peer_id()))
        self.assertIsNotNone(peerlane.PEER_ID_RE.fullmatch(peerlane.SIZE_ID))


class IssuedIdGrammarTests(_Send):
    """`write_issued` and `read_ledger` accept a record id in the statement
    id grammar (`^[A-Za-z0-9_-]+$`, at most 128 characters): this router's
    own mints, and the foreign shapes a seeded record carries. Only the mint
    is held to `PEER_ID_RE`."""

    def record(self, peer_id):
        return peerlane.issued_record(peer_id=peer_id, logical_id="alice",
                                      local_address=f"alice@{FD}", remote=TRUSTED,
                                      generation="0" * 32, expires_at="2026-10-20T00:00:00Z")

    def test_a_real_mint_and_foreign_shapes_are_written_and_read_back(self):
        cfg = self.cfg()
        for peer_id in (peerlane.mint_peer_id(), "0123456789abcdef" * 2, "A" * 24, "x" * 128):
            with self.subTest(peer_id=peer_id):
                try:
                    peerlane.write_issued(cfg, self.record(peer_id))
                except ValueError as e:
                    self.fail(f"an id in the statement grammar was refused: {e}")
                self.assertEqual(peerlane.read_ledger(cfg, "alice", peer_id)["id"], peer_id)

    def test_outside_the_statement_grammar_is_refused_and_never_read(self):
        cfg = self.cfg()
        for why, peer_id in (("empty", ""), ("a dot", "."), ("a slash", "a/b"),
                             ("129 characters", "x" * 129), ("a trailing newline", "abc\n"),
                             ("a space", "a b")):
            with self.subTest(why=why):
                with self.assertRaises(ValueError):
                    peerlane.write_issued(cfg, self.record(peer_id))
                if peer_id in ("", ".", "a/b"):
                    continue    # not a plantable single path component
                # A well-formed record planted at that id's path: only the
                # grammar can make read_ledger refuse it.
                path = peerlane.ledger_path(cfg, "alice", peer_id)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(self.record(peer_id)), encoding="utf-8")
                self.assertIsNone(peerlane.read_ledger(cfg, "alice", peer_id))

    def test_the_mint_grammar_is_exactly_23_characters_without_a_leading_dash(self):
        good = "A" * 23
        self.assertIsNotNone(peerlane.PEER_ID_RE.fullmatch(good))
        for bad in (good[:22], good + "A", "-" + good[1:], good + "\n"):
            with self.subTest(bad=bad):
                self.assertIsNone(peerlane.PEER_ID_RE.fullmatch(bad))


class LedgerPathTests(_Send):

    def test_the_ledger_is_keyed_by_logical_id_not_generation(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(cfg)
        pid = inflight.read_record(cfg, "alice", "00000001")["peer"]["id"]
        self.assertTrue((self.state_dir / "alice" / "peer-ledger" / f"{pid}.json").is_file())


class DeferredHandoverTests(_Send):

    def test_an_inactive_delegation_defers_and_never_latches(self):
        cfg = self.cfg()
        self.activate(cfg)
        write_request(cfg, "alice", "00000001", to=[TRUSTED])
        self.drain(dataclasses.replace(cfg, reload_failed=True))
        record = inflight.read_record(cfg, "alice", "00000001")
        peerlane.forget_all()
        try:
            inflight.transport_request_bytes(cfg, "alice", record, req_id="00000001")
        except inflight.HandoverDeferred:
            pass
        except inflight.HandoverUnavailable as e:
            self.fail(f"an inactive delegation latched the generation: {e}")
        else:
            self.fail("handed over with no active delegation")
