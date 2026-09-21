"""The conformance proof: alice -> bob cold send (mutual allowlist).
Checks the router's own outcome AND that every artifact it produced
validates against AMAP's own schema engine (fixtures/validate.py, loaded
via importlib — the same pattern `gate/inbound.py:load_engine` uses)."""

import importlib.util
import re
import unittest

from router import outbound
from router.tests.helpers import (
    AMP_ROOT, RouterTestCase, list_notices, messages_dir, notices_dir,
    processed_path, read_json, result_path, write_request,
)

_HEX32_RE = re.compile(r"^[0-9a-f]{32}$")


def _load_amp_validate():
    module_path = AMP_ROOT / "fixtures" / "validate.py"
    spec = importlib.util.spec_from_file_location("amp_fixtures_validate", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestHappyPath(RouterTestCase):
    def setUp(self):
        super().setUp()
        self.amp_validate = _load_amp_validate()

    def _assert_conforms(self, fixture_name, doc):
        errs = self.amp_validate.check_document(fixture_name, doc)
        self.assertEqual(errs, [], f"{fixture_name} failed AMAP schema validation: {errs}")

    def test_cold_send_delivers_and_conforms(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(
            cfg, "alice", "00000001",
            to=["agent.bob@local"], subject="hello", body_text="hi bob",
        )

        summary = outbound.drain_instance(cfg, "alice")
        self.assertEqual(summary["drained"], 1)

        result = read_json(result_path(cfg, "alice", "00000001"))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["reason_code"], "allowlisted")
        self.assertEqual(result["recipients"], ["agent.bob@local"])
        self._assert_conforms("result-produced.json", result)

        self.assertTrue(processed_path(cfg, "alice", "00000001").is_file())
        self.assertFalse(
            (cfg.instances["alice"].outbox_root / "req-00000001.json").exists()
        )

        notice_names = list_notices(cfg, "bob")
        self.assertEqual(len(notice_names), 1)
        notice_id = notice_names[0][len("notice-"):-len(".json")]
        self.assertRegex(notice_id, _HEX32_RE)

        notice_doc = read_json(notices_dir(cfg, "bob") / notice_names[0])
        self.assertEqual(notice_doc["kind"], "deliver")
        self.assertEqual(notice_doc["message"]["provenance"], "internal")
        self.assertEqual(notice_doc["message"]["from"], "agent.alice@local")
        self._assert_conforms("notice-produced.json", notice_doc)

        message_path = messages_dir(cfg, "bob") / notice_names[0]
        self.assertTrue(message_path.is_file())
        message_doc = read_json(message_path)
        self.assertEqual(message_doc["notice_id"], notice_id)
        self.assertEqual(message_doc["body_text"], "hi bob")
        self._assert_conforms("message-produced.json", message_doc)

    def test_notice_ids_nonsequential_across_sends(self):
        cfg = self.make_config({"alice": ["bob"], "bob": ["alice"]})
        write_request(cfg, "alice", "00000001", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")
        write_request(cfg, "alice", "00000002", to=["agent.bob@local"])
        outbound.drain_instance(cfg, "alice")

        names = list_notices(cfg, "bob")
        self.assertEqual(len(names), 2)
        ids = [n[len("notice-"):-len(".json")] for n in names]
        self.assertNotEqual(ids[0], ids[1])
        for i in ids:
            self.assertRegex(i, _HEX32_RE)


if __name__ == "__main__":
    unittest.main()
