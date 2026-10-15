"""RL to RL across one EMULATED hop: a signed peer task from host A's agent
to host B's agent, placed on B by the production profile, answered by B's
agent, and delivered back to A's agent as an endpoint-bound result
(RL-INBOUND-LIFT design v1.3 §3, W1 and W2).

WHAT THIS IS. Wiring, policy, placement and endpoint-bound handling over
SYNTHETIC crypto and an EMULATED hub. Each router is loaded by
`config.load` from a JSON config, polls through the real service entry
(`service.run_once`, the transport given through its own `transport`
argument), and decides with its own `production_hooks`: nothing in config,
peerpolicy, its hooks or the policy is patched, and the sender's exposure
stamp is the real assessment of a real, listable inbox.

WHAT THIS IS NOT. Not Ed25519 (the peer seam is the stand-in `si.Plugin`),
not the s5-r4 vectors (RELIFT), not the real hop tree (the ports are this
module's in-memory doubles), and not RE. It carries NO attachment. NOT
exercised of [2], all HAR-14's: the MIME round trip (folding, transfer
encoding, body reduce), the hub prefix and admission, the registry
resolve, the carriage switch, the reduce/encode refusals that park, and
on the Result leg [2]'s sender gate and single-recipient check.

THE FIXTURES are this module's own (`_plugin`, `_Sender`, `_Intake`,
`_Hub`) plus RL's stand-in peer seam; none replaces a production default.
The test hub builds each candidate the way [2] does, from [2]'s field set
and never from the sent request's bytes; what it fabricates is named in
`_Hub.FABRICATED`."""
from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from router import config as config_mod
from router import peerjournal, peerlane, registry, service
from router.tests import peer_standin as si
from router.tests.helpers import TEST_HOP_CAPS, write_request

A_D, B_D = "host-a.fleet.example", "host-b.fleet.example"
LIDS = {"planner": "a1" * 16, "builder": "b2" * 16}
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "registry"


def _seed(tag: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(b"inbound-e2e-" + tag).digest()


class _Intake:
    """The candidate intake one generation's reader lists: committed entries
    by id, the candidate view's bytes as [2]'s writer would commit them."""

    class NoticeRefused(Exception):
        def __init__(self, reason):
            super().__init__(reason)
            self.reason = reason

    def __init__(self):
        self.entries = {}

    def list_entries(self, kind, *, limit, after=None):
        if kind != "candidate":
            return [], False
        ids = sorted(i for i in self.entries if after is None or i > after)
        return ids[:limit], len(ids) > limit

    def read_entry(self, kind, entry_id):
        return self.entries[entry_id]

    def remove_entry(self, kind, entry_id):
        return "removed" if self.entries.pop(entry_id, None) is not None else "absent"

    def close(self):
        pass


class _Sender:
    """One generation's sender: what the router hands over, and the result
    the downstream runtime ([2], here the test hub) writes back."""

    def __init__(self):
        self.pending, self.results, self.archived, self.writes = {}, {}, {}, []

    def has_result(self, n):
        return n in self.results

    def has_pending(self, n):
        return n in self.pending

    def has_archived(self, n):
        return n in self.archived

    def read_result(self, n):
        return self.results[n]

    def write_request(self, n, data):
        self.writes.append(n)
        assert n not in self.pending and n not in self.archived and n not in self.results, \
            f"transport request {n} rewritten"
        self.pending[n] = data

    def withdraw_request(self, n):
        raise FileNotFoundError(n)

    def close(self):
        pass


def _plugin(sender: "_Sender", intake: "_Intake") -> si.Plugin:
    """The plugin object `run_once` receives: RL's stand-in peer seam at
    PLUGIN_API (3, 4) (the candidate view), plus one sender and one
    candidate intake per host, handed out by the factories the real plugin
    has."""
    ns = dict(si.namespace(api=(3, 4)))
    ns["make_sender"] = lambda settings, fsops: sender
    ns["make_intake_reader"] = lambda settings, fsops: intake
    ns["make_intake_remover"] = lambda settings, fsops: intake
    return si.Plugin(ns)


class _Host:
    """One router: its own state, registry, agent, key and config."""

    def __init__(self, base: Path, *, name: str, domain: str, other: str, other_seed: bytes,
                 seed: bytes, inbound: bool = True, plugin=None, crypto=None, public_key=None):
        """`plugin`, `crypto` and `public_key` default to RL's stand-in seam
        (W1); `run_realhop` passes the real plugin, the openssl backend and
        the real Ed25519 public key (row (b)). `plugin`, when given, is the
        plugin object itself, and this host's in-memory sender and intake
        then go unused."""
        public_key = public_key or (lambda s: si.public_key(s).hex())
        self.base, self.name, self.domain = base, name, domain
        for d in ("state", "registry", "hop", "keys", f"instances/{name}/inbox",
                  f"instances/{name}/outbox"):
            (base / d).mkdir(parents=True, exist_ok=True)
        # DIRECT TEST WRITE (the deploy's): the host intakes and their
        # disposal trees, which the deployment creates and the router never
        # does (peer_startup reports them missing otherwise).
        for intake in (".unresolved", ".control"):
            (base / "hop" / ".disposed" / intake).mkdir(parents=True, exist_ok=True)
            (base / "hop" / intake).mkdir(parents=True, exist_ok=True)
        os.chmod(base / "keys", 0o700)
        self.seed_path = base / "keys" / "seed"
        self.seed_path.write_bytes(seed)
        os.chmod(self.seed_path, 0o400)
        self.write_registry()
        doc = {
            "state_dir": str(base / "state"), "fleet_domain": domain,
            "fleet_hosts": [other], "trusted_fleet_hosts": [other],
            "registry_dir": str(base / "registry"),
            "instances": {name: {"handoff_dir": str(base / "instances" / name)}},
            "transport_plugin": {"path": "/opt/amap-hop/plugin.py", "sha256": "0" * 64},
            "hop": {"root": str(base / "hop"), "peer_uid": os.geteuid(), "version_write": 1,
                    "caps": dict(TEST_HOP_CAPS), "link": "hub"},
            "delegation": {
                "partition_verified": "inbound-e2e fixture",
                "signing_key": {"path": str(self.seed_path), "key_id": f"key-{domain}",
                                "public_key": public_key(seed)},
                "runtimes": [{"name": other.split(".")[0], "runtime": f"amap.router@{other}",
                              "domains": [other],
                              "keys": [{"key_id": f"key-{other}",
                                        "public_key": public_key(other_seed)}]}],
                "crypto": dict(crypto or {"crypto_backend": "pyca"})}}
        if inbound is not None:
            doc["delegation"]["inbound"] = inbound
        path = base / "router.json"
        path.write_text(json.dumps(doc))
        self.cfg = config_mod.load(path)
        self.sender, self.intake = _Sender(), _Intake()
        # The router's own filesystem port over the real (empty) hop root, as
        # `start_transport` builds it; only the plugin is this module's.
        from router import fsops as fsops_mod
        fsops = fsops_mod.FsOps(hop_root=self.cfg.hop.root)
        self.fsops = fsops
        self.runtime = service.HopRuntime(
            plugin=plugin if plugin is not None else _plugin(self.sender, self.intake),
            fsops=fsops, hop=self.cfg.hop)

    def write_registry(self):
        doc = json.loads((FIXTURES / "snapshot.json").read_text())
        proto = next(e for e in doc["entries"] if e["state"] == "active")
        e = json.loads(json.dumps(proto))
        e.update(logical_id=LIDS[self.name], name=self.name, stable_key=f"/srv/work/{self.name}")
        e["names"][0]["name"] = self.name
        e["bindings"][0]["stable_key"] = f"/srv/work/{self.name}"
        doc["entries"], doc["seq"] = [e], 3
        (self.base / "registry" / registry.SNAPSHOT).write_text(json.dumps(doc))

    def start(self):
        """The operator's first enable, then `run_forever`'s own startup, in
        its order: `peer-store init --never-admitted` (the runbook), then
        `activate_delegation` and `peer_startup` with the transport."""
        from router import clock
        peerjournal.operator_init(self.cfg, clock.now(), acknowledge_surviving=None)
        service.activate_delegation(self.cfg, self.runtime)
        service.peer_startup(self.cfg, self.runtime)

    def poll(self):
        return service.run_once(self.cfg, self.runtime)

    @property
    def address(self):
        return f"{self.name}@{self.domain}"


class _Hub:
    """[2], emulated: what a hub does between one host's up/outbound and the
    other's candidate intake. It builds each candidate the way [2] does,
    from [2]'s field set (the received header fields, the first text/plain
    body decoded), NEVER from the sent request's bytes, and then writes the
    sender's transport Result, as [2] does after the hub accepted it."""

    #: What the hub makes up rather than carries, with its value (design
    #: v1.2 Δ1). The stand-in candidate form is a verifier view (fields,
    #: body, attachments): [2]'s encode_candidate arguments that are not
    #: fields (received_at, admission, admission_rule) have no place in it,
    #: and are exercised by row (b) over the real plugin.
    FABRICATED = {"Delivered-To": "the recipient's address, as the hub prefix's Delivered-To",
                  "Date": "the hub's receive time",
                  "transport Result": "accepted / allowlisted, message_id = the peer Message-ID"}

    def __init__(self):
        self.carried = []

    def carry(self, src: "_Host", dst: "_Host", recipient: str):
        """Every request src handed over and not yet carried: B's candidate
        from its header fields and decoded body, then src's Result."""
        from router import clock
        for n in sorted(src.sender.pending):
            doc = json.loads(src.sender.pending[n])
            peer, draft = doc["envelope"]["peer"], doc["request"]["draft"]
            # From: [2] sends from the sender's gated address, which the
            # signed statement names.
            _k, _kid, statement, _sig = si.check1([("AMAP-Peer-Statement",
                                                     peer["statement_header"])])
            sender_addr = json.loads(statement)["from"]
            fields = [["From", sender_addr], ["To", ", ".join(draft["to"])],
                      ["Subject", draft["subject"]], ["Message-ID", peer["message_id"]],
                      ["Delivered-To", recipient],
                      ["Date", clock.now().strftime("%a, %d %b %Y %H:%M:%S +0000")],
                      ["AMAP-Peer-Statement", peer["statement_header"]]]
            if peer.get("in_reply_to"):
                fields.append(["In-Reply-To", peer["in_reply_to"]])
            body = draft["body_text"].encode("utf-8")
            view = {"fields": fields,
                    "body": {"charset": "utf-8", "octets_b64": base64.b64encode(body).decode()},
                    "attachments": []}
            entry = f"c{len(dst.intake.entries) + 1:04d}"
            dst.intake.entries[entry] = json.dumps(view, sort_keys=True).encode()
            src.sender.results[n] = json.dumps({
                "contract_version": "2", "req_id": n, "outcome": "accepted",
                "reason_code": "allowlisted", "detail": None,
                "message_id": peer["message_id"]}).encode()
            src.sender.archived[n] = src.sender.pending.pop(n)
            self.carried.append((src.name, n, dst.name, entry, peer["message_id"]))


class _TwoHosts(unittest.TestCase):

    def setUp(self):
        from router import hoplink
        hoplink.reset_process_state()
        self.addCleanup(hoplink.reset_process_state)
        peerlane.forget_all()
        self.addCleanup(peerlane.forget_all)
        td = tempfile.mkdtemp(prefix="e2e.")
        self.addCleanup(shutil.rmtree, td, ignore_errors=True)
        self.tmp = Path(os.path.realpath(td))
        sa, sb = _seed(b"a"), _seed(b"b")
        self.a = _Host(self.tmp / "a", name="planner", domain=A_D, other=B_D, seed=sa,
                       other_seed=sb)
        self.b = _Host(self.tmp / "b", name="builder", domain=B_D, other=A_D, seed=sb,
                       other_seed=sa)


    def started(self):
        for h in (self.a, self.b):
            h.start()
            h.poll()                       # first sight: an empty outbox snapshot


def _notices(host):
    d = host.cfg.instances[host.name].peer_root / "notices"
    return [json.loads(p.read_text()) for p in sorted(d.glob("notice-*.json"))] if d.is_dir() else []


def _statement(handed: bytes):
    """The signed statement inside a hand-over, as the stand-in decodes it."""
    peer = json.loads(handed)["envelope"]["peer"]
    _k, _kid, statement, _sig = si.check1([("AMAP-Peer-Statement", peer["statement_header"])])
    return json.loads(statement)


class RoundTripTests(_TwoHosts):
    """W1: the task, placed by B's production profile; the answer, delivered
    to A's agent as the endpoint-bound result of THIS issued task."""

    def test_a_task_is_placed_on_b_and_its_result_is_returned_to_a(self):
        from router import generations
        self.started()
        hub = _Hub()
        # 1-2. A's agent submits; A signs with the stand-in and hands over.
        write_request(self.a.cfg, "planner", "00000001", to=[self.b.address],
                      subject="Run the suite", body_text="Please run the suite.\n")
        self.a.poll()
        self.assertEqual(self.a.sender.writes, ["00000001"])
        task = _statement(self.a.sender.pending["00000001"])
        # 3. The hub builds B's candidate from [2]'s field set.
        hub.carry(self.a, self.b, self.b.address)
        entry = hub.carried[-1][3]
        # 4. B takes it, checks it and decides with its production hooks.
        self.b.poll()
        b_gen = generations.read_doc(self.b.cfg.state_dir, LIDS["builder"])["current"]
        key = peerjournal.record_key(intake="candidates", gen=b_gen, owner=LIDS["builder"],
                                     entry_id=entry)
        rec = peerjournal.read_record(self.b.cfg.state_dir, LIDS["builder"], key)
        self.assertEqual((rec["state"], rec["disposed"]), ("done", "placed"),
                         "THIS candidate, placed by the production profile")
        placed = _notices(self.b)
        self.assertEqual(len(placed), 1, "exactly one placement")
        self.assertEqual((placed[0]["message"]["id"], placed[0]["message"]["from"]),
                         (task["id"], self.a.address), "THIS statement, from A's agent")
        # 5-6. B's agent answers THAT notice; B signs and hands over.
        write_request(self.b.cfg, "builder", "00000001", to=[self.a.address],
                      subject="Re: Run the suite", body_text="Done: 112 passed.\n",
                      in_reply_to=placed[0]["message"]["id"])
        self.b.poll()
        self.assertEqual(self.b.sender.writes, ["00000001"])
        answer = _statement(self.b.sender.pending["00000001"])
        # 7. The hub carries the answer back, again from [2]'s field set.
        hub.carry(self.b, self.a, self.a.address)
        # 8. A delivers it as the endpoint-bound result of THIS issued task.
        self.a.poll()
        result = json.loads((self.a.cfg.instances["planner"].outbox_root / "results"
                             / "00000001.json").read_text())
        self.assertEqual((result["req_id"], result["outcome"]), ("00000001", "accepted"),
                         "THIS request's anchor")
        led = self.a.cfg.state_dir / LIDS["planner"] / peerlane.PEER_LEDGER_DIR / f"{task['id']}.json"
        self.assertTrue(led.is_file(), "A's issued record for THIS task")
        issued = json.loads(led.read_text())
        self.assertEqual((issued["direction"], issued["remote"], issued["local_address"]),
                         ("issued", self.b.address, self.a.address),
                         "THIS issued task, to THIS endpoint")
        got = _notices(self.a)
        self.assertEqual(len(got), 1, "one result placed on A")
        self.assertEqual((got[0]["message"]["id"], got[0]["message"].get("in_reply_to"),
                          got[0]["message"]["from"]),
                         (answer["id"], task["id"], self.b.address),
                         "the endpoint-bound result: B's answer, resolved to THIS issued id")
        # No second hand-over anywhere.
        self.a.poll()
        self.b.poll()
        self.assertEqual((self.a.sender.writes, self.b.sender.writes),
                         (["00000001"], ["00000001"]))
        self.assertEqual((len(_notices(self.a)), len(_notices(self.b))), (1, 1))


class DefaultOffTests(unittest.TestCase):
    """W2: the same receiver, otherwise valid (an initialised store, a
    trusted clock, a candidate present), with `inbound` absent, then false:
    nothing is taken."""

    def run_with(self, inbound):
        from router import hoplink
        hoplink.reset_process_state()
        self.addCleanup(hoplink.reset_process_state)
        peerlane.forget_all()
        self.addCleanup(peerlane.forget_all)
        td = tempfile.mkdtemp(prefix="e2e.")
        self.addCleanup(shutil.rmtree, td, ignore_errors=True)
        tmp = Path(os.path.realpath(td))
        sa, sb = _seed(b"a"), _seed(b"b")
        a = _Host(tmp / "a", name="planner", domain=A_D, other=B_D, seed=sa, other_seed=sb)
        b = _Host(tmp / "b", name="builder", domain=B_D, other=A_D, seed=sb, other_seed=sa,
                  inbound=inbound)
        for h in (a, b):
            h.start()
            h.poll()
        write_request(a.cfg, "planner", "00000001", to=[b.address], body_text="Run it.\n")
        a.poll()
        _Hub().carry(a, b, b.address)
        self.assertEqual(len(b.intake.entries), 1, "a candidate is present")
        self.assertEqual(peerjournal.read_meta(b.cfg.state_dir)["take_seq"], 0,
                         "the store is initialised")
        b.poll()
        return b

    def assert_untaken(self, b):
        self.assertEqual(len(b.intake.entries), 1, "the candidate stays in the intake")
        self.assertEqual(peerjournal.all_records(b.cfg.state_dir), [], "nothing taken")
        self.assertFalse(peerjournal.open_dir(b.cfg.state_dir, LIDS["builder"]).exists())
        self.assertEqual(_notices(b), [])

    def test_inbound_absent_takes_nothing(self):
        b = self.run_with(None)
        self.assertFalse(b.cfg.delegation.inbound)
        self.assert_untaken(b)

    def test_inbound_false_takes_nothing(self):
        b = self.run_with(False)
        self.assertFalse(b.cfg.delegation.inbound)
        self.assert_untaken(b)

    def test_the_companion_inbound_true_takes_it(self):
        b = self.run_with(True)
        self.assertEqual(len(peerjournal.all_records(b.cfg.state_dir)), 1)
        self.assertEqual(len(_notices(b)), 1)


if __name__ == "__main__":
    unittest.main()
