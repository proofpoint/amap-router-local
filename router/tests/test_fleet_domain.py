"""Step 1 of the peer-lane build: `fleet_domain`, the `amap.router@` address,
addressing switched on BOTH lanes when the domain is set, and `peers --json`.

One identity per agent is the property under test: with a domain, a mail
notice's `from`, a peer notice's `from`, `draft.to` on a submit and every
key of `peers --json` are the same string, and the legacy `agent.<name>@local`
spelling stops parsing entirely rather than living on as an alias."""

import contextlib
import io
import json
import unittest

from router import outbound
from router.__main__ import main
from router.config import (
    ConfigError, address_for, instance_for, load_obj, router_address,
)
from router.peers import render_peers, render_peers_json
from router.tests.helpers import (
    RouterTestCase, list_notices, notices_dir, read_json, result_path, write_request,
)
from router.tests.peer_helpers import FLEET_DOMAIN, addr, make_peer_config


def _doc(**top):
    d = {
        "state_dir": "/x/state",
        "instances": {"alice": {"handoff_dir": "/x/alice"}, "bob": {"handoff_dir": "/x/bob"}},
    }
    d.update(top)
    return d


class FleetDomainConfigTests(unittest.TestCase):
    def test_absent_means_no_domain_and_legacy_addressing(self):
        cfg = load_obj(_doc())
        self.assertIsNone(cfg.fleet_domain)
        self.assertEqual(address_for("alice", cfg.fleet_domain), "agent.alice@local")
        self.assertIsNone(router_address(cfg.fleet_domain))

    def test_valid_domains_load(self):
        for d in ("example.invalid", "local", "a-b.c1.example", "x"):
            with self.subTest(domain=d):
                self.assertEqual(load_obj(_doc(fleet_domain=d)).fleet_domain, d)

    def test_uppercase_refused_not_folded(self):
        """The adapter diffs addresses byte for byte against the daemons'
        files; two spellings of one domain would make a correct fleet look
        misconfigured. Refused, like an uppercase instance name."""
        with self.assertRaises(ConfigError) as ctx:
            load_obj(_doc(fleet_domain="Example.Invalid"))
        self.assertIn("fleet_domain", str(ctx.exception))

    def test_malformed_refused(self):
        for bad in ("", "a..b", ".a", "a.", "a_b", "example.invalid ", "@x", 7, None, ["a"]):
            with self.subTest(domain=bad):
                with self.assertRaises(ConfigError):
                    load_obj(_doc(fleet_domain=bad))


class AddressingTests(unittest.TestCase):
    def test_address_for_uses_the_domain(self):
        self.assertEqual(address_for("alice", "example.invalid"), "alice@example.invalid")

    def test_router_address_is_derived_and_never_an_instance(self):
        ra = router_address("example.invalid")
        self.assertEqual(ra, "amap.router@example.invalid")
        # The `.` is outside the instance-name charset: cannot parse, cannot collide.
        self.assertIsNone(instance_for(ra, "example.invalid"))

    def test_instance_for_round_trips_and_lowercases(self):
        self.assertEqual(instance_for("Alice@Example.Invalid", "example.invalid"), "alice")
        self.assertEqual(instance_for(" bob@example.invalid ", "example.invalid"), "bob")

    def test_legacy_form_does_not_parse_under_a_domain(self):
        self.assertIsNone(instance_for("agent.alice@local", "example.invalid"))
        # And the domain form does not parse without one.
        self.assertIsNone(instance_for("alice@example.invalid"))
        self.assertEqual(instance_for("agent.alice@local"), "alice")

    def test_wrong_domain_and_display_names_rejected(self):
        for bad in ("alice@example.invalids", "alice@other.internal", "alice@example.invalid.x",
                    '"alice" <alice@example.invalid>', "alice", "@example.invalid",
                    "alice@agents_internal"):
            with self.subTest(address=bad):
                self.assertIsNone(instance_for(bad, "example.invalid"))

    def test_a_dot_in_the_local_part_is_a_name_now_not_a_rejection(self):
        """`Alice.B@…` used to be in the list above, rejected for containing a
        `.`. It is a legitimate name under sandy's slug alphabet — real slugs
        carry dots, `finance-1a2b3c4d.bak` being the shape — so it parses.

        Moved rather than deleted: the address did not stop being interesting,
        it stopped being wrong, and a reader of the rejected list should not
        have to wonder where it went."""
        self.assertEqual(
            instance_for("Alice.B@example.invalid", "example.invalid"), "alice.b")

    def test_the_canonical_spelling_comes_back_when_the_names_are_known(self):
        """Local parts are case-insensitive, but the name is also a directory
        under state_dir and a key in `cfg.instances`, where exactly one
        spelling exists. Given the configured names, the canonical one is
        what is returned — folding it instead would resolve to a key that is
        not there."""
        known = ["Mixed-Case_name-0badcafe", "plain-deadbeef"]
        self.assertEqual(
            instance_for("mixed-case_name-0badcafe@example.invalid",
                         "example.invalid", known),
            "Mixed-Case_name-0badcafe")
        self.assertIsNone(
            instance_for("stranger-c0ffee01@example.invalid", "example.invalid", known))


class AddressingSwitchesOnTheMailLaneTests(RouterTestCase):
    """With a domain, the MAIL lane speaks the fleet addresses too — one
    identity, not one per lane."""

    def test_mail_send_uses_fleet_addresses_end_to_end(self):
        cfg = make_peer_config(self, {"alice": {"peers": ["bob"]}, "bob": {"peers": ["alice"]}})
        write_request(cfg, "alice", "00000001", to=[addr("bob")], body_text="hi")
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]), ("accepted", "allowlisted"))
        self.assertEqual(result["recipients"], ["bob@example.invalid"])

        names = list_notices(cfg, "bob")
        self.assertEqual(len(names), 1)
        notice = read_json(notices_dir(cfg, "bob") / names[0])
        self.assertEqual(notice["kind"], "deliver")
        self.assertEqual(notice["message"]["from"], "alice@example.invalid")

    def test_legacy_address_is_recipient_unknown_under_a_domain(self):
        cfg = make_peer_config(self, {"alice": {"peers": ["bob"]}, "bob": {"peers": ["alice"]}})
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual((result["outcome"], result["reason_code"]),
                         ("rejected", outbound.REASON_RECIPIENT_UNKNOWN))
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_reply_binding_survives_the_domain(self):
        """The ledger binds on `from_instance`, an instance name — so a
        reply resolves whatever the addresses look like."""
        cfg = make_peer_config(self, {"alice": {"peers": ["bob"]}, "bob": {"peers": ["alice"]}})
        write_request(cfg, "alice", "00000001", to=[addr("bob")])
        outbound.drain_instance(cfg, "alice")
        nid = list_notices(cfg, "bob")[0][len("notice-"):-len(".json")]
        write_request(cfg, "bob", "00000001", in_reply_to=nid, to=["nobody@example.org"])
        outbound.drain_instance(cfg, "bob")
        result = read_json(result_path(cfg, "bob", "00000001"))
        self.assertEqual(result["reason_code"], "recipient_bound")
        self.assertEqual(result["recipients"], ["alice@example.invalid"])


class PeersJsonTests(RouterTestCase):
    def test_json_is_the_directed_graph_as_addr_specs_every_instance_present(self):
        cfg = make_peer_config(self, {
            "analyst": {"peer_senders": ["coder"]},
            "mail-reader": {"peer_senders": ["analyst"]},
            "coder": {"peer_senders": ["analyst"]},
            "loner": {},
        }, provision=False)
        doc = json.loads(render_peers_json(cfg))
        self.assertEqual(doc, {
            "analyst@example.invalid": ["coder@example.invalid"],
            "coder@example.invalid": ["analyst@example.invalid"],
            "loner@example.invalid": [],
            "mail-reader@example.invalid": ["analyst@example.invalid"],
        })
        # Deterministic: keys sorted, and a second render is byte-identical.
        self.assertEqual(render_peers_json(cfg), render_peers_json(cfg))
        self.assertEqual(list(doc), sorted(doc))

    def test_json_carries_nothing_but_the_graph(self):
        cfg = make_peer_config(self, {
            "alice": {"peers": ["bob"]}, "bob": {"peers": ["alice"]}, "carol": {"peer_senders": ["alice"]},
        }, provision=False)
        doc = json.loads(render_peers_json(cfg))
        # The mutual mail pair is NOT in the graph; the router's own address never appears.
        self.assertEqual(doc["alice@example.invalid"], [])
        self.assertEqual(doc["bob@example.invalid"], [])
        self.assertEqual(doc["carol@example.invalid"], ["alice@example.invalid"])
        self.assertNotIn("amap.router@example.invalid", json.dumps(doc))

    def test_text_render_shows_both_declarations(self):
        cfg = make_peer_config(self, {
            "alice": {"peers": ["bob"]}, "bob": {"peers": ["alice"]}, "carol": {"peer_senders": ["alice"]},
        }, provision=False)
        out = render_peers(cfg)
        self.assertIn("peer task graph", out)
        self.assertIn(f"fleet_domain: {FLEET_DOMAIN}", out)
        self.assertRegex(out, r"carol\s+<- alice")
        self.assertRegex(out, r"alice\s+<- \(none\)")

    def test_text_render_omits_the_graph_without_a_domain(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        self.assertNotIn("peer task graph", render_peers(cfg))


class PeersJsonCLITests(RouterTestCase):
    def _run(self, cfg_path, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--config", str(cfg_path), *args])
        return code, out.getvalue(), err.getvalue()

    def test_peers_json_prints_only_json(self):
        cfg_path = self.tmp / "router.json"
        for n in ("alice", "bob"):
            for leaf in ("inbox", "outbox"):
                (self.tmp / n / leaf).mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps({
            "state_dir": str(self.state_dir),
            "fleet_domain": FLEET_DOMAIN,
            "instances": {
                "alice": {"handoff_dir": str(self.tmp / "alice")},
                "bob": {"handoff_dir": str(self.tmp / "bob"), "peer_senders": ["alice"]},
            },
        }))
        code, out, _ = self._run(cfg_path, "peers", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {
            "alice@example.invalid": [], "bob@example.invalid": ["alice@example.invalid"],
        })
        code2, out2, _ = self._run(cfg_path, "matrix", "--json")
        self.assertEqual((code2, out2), (0, out))


if __name__ == "__main__":
    unittest.main()
