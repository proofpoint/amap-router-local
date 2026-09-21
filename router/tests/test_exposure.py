"""`exposure.assess` — the `sender_exposure` stamp, asserted `false` in this
fleet, computed honestly when it is not."""

import json
import os
import unittest
from datetime import timedelta
from unittest import mock

from router import binding, exposure, firstsight
from router.tests.helpers import RouterTestCase, notices_dir
from router.tests.peer_helpers import make_peer_config
from router.util import format_utc_ts, parse_utc_ts, utc_ts

NOW = "2026-09-03T12:00:00Z"


def _set_first_seen_ts(cfg, name, ts):
    path = firstsight.marker_path(cfg.state_dir, name)
    doc = json.loads(path.read_text())
    doc["first_seen_ts"] = ts
    path.write_text(json.dumps(doc))


class ExposureTests(RouterTestCase):
    def _cfg(self, **top):
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}}, top=top or None)
        # A first sight older than any window, so clamping does not interfere
        # unless a test asks for it.
        _set_first_seen_ts(cfg, "a", "2020-01-01T00:00:00Z")
        return cfg

    def test_false_over_the_full_window_when_nothing_external_exists(self):
        cfg = self._cfg()
        stamp = exposure.assess(cfg, "a", now=NOW)
        self.assertEqual(stamp, {
            "asserted_by": "amap.router@example.invalid",
            "external_mail_delivered": False,
            "window_start": "2026-09-02T12:00:00Z",
            "window_end": NOW,
        })

    def test_window_start_clamped_forward_to_a_younger_first_sight(self):
        cfg = self._cfg()
        _set_first_seen_ts(cfg, "a", "2026-09-03T11:00:00Z")
        stamp = exposure.assess(cfg, "a", now=NOW)
        self.assertEqual(stamp["window_start"], "2026-09-03T11:00:00Z")
        self.assertEqual(stamp["window_end"], NOW)

    def test_configured_window_is_honoured(self):
        cfg = self._cfg(sender_exposure_window_seconds=600)
        stamp = exposure.assess(cfg, "a", now=NOW)
        self.assertEqual(stamp["window_start"], "2026-09-03T11:50:00Z")

    def test_unledgered_notice_in_the_senders_inbox_is_external(self):
        """Source 2: a notice this router did not write can only be another
        deliverer's — the open transport."""
        cfg = self._cfg()
        now = utc_ts()
        foreign = notices_dir(cfg, "a") / ("notice-" + "e" * 32 + ".json")
        foreign.write_text("{}")
        stamp = exposure.assess(cfg, "a", now=now)
        self.assertIs(stamp["external_mail_delivered"], True)
        self.assertIn("last_external_delivery_ts", stamp)
        # mtime now is within a 24 h window ending now.
        self.assertGreaterEqual(parse_utc_ts(stamp["last_external_delivery_ts"]),
                                parse_utc_ts(stamp["window_start"]))

    def test_unledgered_notice_older_than_the_window_does_not_count(self):
        cfg = self._cfg()
        foreign = notices_dir(cfg, "a") / ("notice-" + "e" * 32 + ".json")
        foreign.write_text("{}")
        old = parse_utc_ts(utc_ts()) - timedelta(days=3)
        os.utime(foreign, (old.timestamp(), old.timestamp()))
        stamp = exposure.assess(cfg, "a", now=utc_ts())
        self.assertIs(stamp["external_mail_delivered"], False)

    def test_ledgered_notices_this_router_wrote_are_internal(self):
        cfg = self._cfg()
        from router import deliver
        # A mail notice from b, and a DSN from the router, both into a's inbox.
        cfg2 = make_peer_config(self, {"a": {"peers": ["c"]}, "c": {"peers": ["a"]},
                                       "b": {"peer_senders": ["a"]}})
        _set_first_seen_ts(cfg2, "a", "2020-01-01T00:00:00Z")
        deliver.deliver(cfg2, cfg2.state_dir, "c", "a",
                        {"req_id": "1", "draft": {"to": [], "subject": "s", "body_text": "b"}})
        deliver.deliver_router_notice(cfg2, cfg2.state_dir, "a", subject="Not delivered: denied",
                                      body_text="x", in_reply_to="0" * 32)
        self.assertEqual(len(list(notices_dir(cfg2, "a").iterdir())), 2)
        stamp = exposure.assess(cfg2, "a", now=utc_ts())
        self.assertIs(stamp["external_mail_delivered"], False)

    def test_demotion_marked_ledger_record_is_external(self):
        cfg = self._cfg()
        nid = "d" * 32
        ts = "2026-09-03T11:30:00Z"
        rec = json.loads(binding.record_delivery(
            cfg.state_dir, notice_id=nid, from_instance=None, from_address="x@elsewhere.example",
            to_instance="a", ts=ts, req_id="", message_id=nid, transport="local", tree="inbox",
        ))
        rec["origin"] = exposure.ORIGIN_EXTERNAL
        path = binding.ledger_path(cfg.state_dir, "a", nid)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rec))
        stamp = exposure.assess(cfg, "a", now=NOW)
        self.assertIs(stamp["external_mail_delivered"], True)
        self.assertEqual(stamp["last_external_delivery_ts"], ts)

    def test_no_stamp_without_a_domain(self):
        cfg = make_peer_config(self, {"a": {}}, fleet_domain=None)
        self.assertIsNone(exposure.assess(cfg, "a", now=NOW))

    def test_listing_overflow_means_not_assessed_never_a_false_false(self):
        cfg = self._cfg()
        for i in range(3):
            (notices_dir(cfg, "a") / f"notice-{i:032x}.json").write_text("{}")
        with mock.patch.object(exposure, "MAX_NOTICE_LISTING", 2):
            self.assertIsNone(exposure.assess(cfg, "a", now=utc_ts()))

    def test_missing_notices_dir_is_an_assessed_nothing(self):
        cfg = self._cfg()
        import shutil
        shutil.rmtree(notices_dir(cfg, "a"))
        stamp = exposure.assess(cfg, "a", now=NOW)
        self.assertIs(stamp["external_mail_delivered"], False)


if __name__ == "__main__":
    unittest.main()
