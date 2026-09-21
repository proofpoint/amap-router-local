import unittest

from router import outbound
from router.binding import check_cold
from router.config import ALLOW_ANY
from router.tests.helpers import (
    RouterTestCase, list_notices, processed_path, read_json, result_path, write_request,
)


class TestColdRefused(RouterTestCase):
    def test_non_mutual_queued_for_human_and_held(self):
        # alice allows bob, but bob does NOT allow alice back -> not mutual.
        cfg = self.make_config({"alice": ["bob"], "bob": []})
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], "recipient_not_allowlisted")

        # Nothing delivered.
        self.assertEqual(list_notices(cfg, "bob"), [])
        # Request archived (drained), and held router-side for operator visibility.
        self.assertTrue(processed_path(cfg, "alice", "00000001").is_file())
        held = cfg.state_dir / "alice" / "held" / "req-00000001.json"
        self.assertTrue(held.is_file())

    def test_unknown_recipient_rejected(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000001", to=["agent.mallory@local"])
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "recipient_unknown")

    def test_malformed_address_rejected_as_malformed(self):
        # `to` items are pinned to a bare addr-spec by the AMAP schema, so a
        # string that is not an address at all fails SHAPE validation and
        # never reaches allowlist evaluation. It used to fall through to
        # policy and come back `recipient_unknown`; `malformed_request` is
        # both more accurate and strictly less informative about the peer
        # set, so the refusal leaks no more than it did before.
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000001", to=["not-an-address-at-all"])
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "malformed_request")

    def test_display_name_spoof_rejected_as_malformed(self):
        # `"agent.bob@local" <agent.mallory@local>` — an allowlisted address
        # quoted as the DISPLAY NAME of one that is not. A policy layer
        # matching the wrong half of that string would send to mallory.
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(
            cfg, "alice", "00000001", to=['"agent.bob@local" <agent.mallory@local>']
        )
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "malformed_request")
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_self_send_refused(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000001", to=["agent.alice@local"])
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["reason_code"], "self_send")
        self.assertEqual(list_notices(cfg, "alice"), [])

    def test_mixed_known_and_non_mutual_queues_whole_request(self):
        # to has one mutual peer and one known-but-non-mutual peer -> the
        # WHOLE request queues, never a partial delivery.
        cfg = self.make_config({
            "alice": ["bob"],
            "bob": ["alice"],
            "carol": [],
        })
        write_request(cfg, "alice", "00000001", to=["agent.bob@local", "agent.carol@local"])
        outbound.drain_instance(cfg, "alice")

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], "recipient_not_allowlisted")
        self.assertEqual(list_notices(cfg, "bob"), [])
        self.assertEqual(list_notices(cfg, "carol"), [])

    def test_allow_any_never_waives_mutuality_on_the_other_side(self):
        # alice declares ALLOW_ANY. bob declares no peers at all. ALLOW_ANY
        # relaxes ONLY alice's own side of the check — it must never make
        # the router treat bob (who never listed alice) as having
        # consented. Pin the enforcement unit directly...
        cfg = self.make_config({"alice": [ALLOW_ANY], "bob": []})
        self.assertFalse(check_cold(cfg, "alice", "bob"))
        self.assertFalse(check_cold(cfg, "bob", "alice"))

        # ...and the end-to-end drain path: refused, nothing delivered.
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "queued_for_human")
        self.assertEqual(result["reason_code"], "recipient_not_allowlisted")
        self.assertEqual(list_notices(cfg, "bob"), [])

    def test_allow_any_does_accept_when_other_side_lists_back(self):
        # alice declares ALLOW_ANY; carol explicitly lists alice back ->
        # mutual, so this direction (unlike the sibling test above) must
        # succeed. Confirms the fix isn't a blanket "ALLOW_ANY never
        # helps" regression.
        cfg = self.make_config({"alice": [ALLOW_ANY], "carol": ["alice"]})
        self.assertTrue(check_cold(cfg, "alice", "carol"))
        self.assertTrue(check_cold(cfg, "carol", "alice"))

        write_request(cfg, "alice", "00000001", to=["agent.carol@local"])
        outbound.drain_instance(cfg, "alice")
        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(len(list_notices(cfg, "carol")), 1)


if __name__ == "__main__":
    unittest.main()
