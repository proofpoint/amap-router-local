"""A local placement happens once, even when a write after it fails.

`_finish` writes the private anchor AFTER the notice is placed. If that write
raises, `drain_instance` isolates the failure and the request stays in
`outbound/`, so the next poll processes it again. Every direct placement path
(cold mail, a bound reply, a peer route) goes through the request's intent
record (`outbound.ORIGIN_DIRECT`), written before anything is placed, so the
next poll finds the placement it already made instead of minting a second
notice id. Each case runs with and without a registry."""

import json
import logging
from unittest import mock

from router import deliver as deliver_mod, outbound, service
from router.tests.helpers import RouterTestCase, list_notices, read_json, result_path, write_request
from router.tests.peer_helpers import addr, list_peer_notices, make_peer_config
from router.tests.test_held_local import _Fleet

REQ = "00000001"


class _RaiseOnce:
    """Wraps a function: the first call raises, every later call is real."""

    def __init__(self, real):
        self.real = real
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise OSError(5, "Input/output error (injected)")
        return self.real(*args, **kwargs)


class _MailCases:
    """The mail-lane witnesses. A subclass supplies `self.cfg` (alpha may mail
    bravo and charlie), `addr(name)`, and `keyed()`, the config as a poll
    keys it."""

    def addr(self, name):
        return addr(name)

    def poll(self):
        log = logging.getLogger("amap_router_local")
        log.disabled = True
        try:
            return service.run_once(self.cfg, None)
        finally:
            log.disabled = False

    def notice_ids(self, name):
        return [n[len("notice-"):-len(".json")] for n in list_notices(self.cfg, name)]

    def two_polls_with_one_anchor_failure(self, sender):
        fail = _RaiseOnce(outbound._write_anchor)
        with mock.patch.object(outbound, "_write_anchor", fail):
            self.poll()
            self.assertEqual(fail.calls, 1, "control: the anchor write was reached and failed")
            self.assertFalse(result_path(self.cfg, sender, REQ).exists(),
                             "control: the first poll did not answer the request")
            self.poll()
        self.assertGreaterEqual(fail.calls, 2, "control: the second poll wrote the anchor")
        self.assertTrue(result_path(self.cfg, sender, REQ).exists())

    # -- W1: an anchor failure after placement -------------------------------

    def test_cold_mail_to_two_recipients_places_each_once(self):
        write_request(self.cfg, "alpha", REQ, to=[self.addr("bravo"), self.addr("charlie")])
        self.two_polls_with_one_anchor_failure("alpha")
        self.assertEqual(len(self.notice_ids("bravo")), 1)
        self.assertEqual(len(self.notice_ids("charlie")), 1)
        self.assertEqual(read_json(result_path(self.cfg, "alpha", REQ))["outcome"], "accepted")

    def test_a_bound_reply_places_once(self):
        write_request(self.cfg, "alpha", "00000009", to=[self.addr("bravo")])
        self.poll()
        (nid,) = self.notice_ids("bravo")
        write_request(self.cfg, "bravo", REQ, to=[self.addr("alpha")], in_reply_to=nid)
        self.two_polls_with_one_anchor_failure("bravo")
        self.assertEqual(len(self.notice_ids("alpha")), 1)


    # -- after an anchor failure, the request is answered from the record ------

    def request_file(self, sender):
        return self.cfg.instances[sender].outbox_root / f"req-{REQ}.json"

    def first_poll_loses_the_anchor(self):
        """One poll whose anchor write fails: the notice is placed, the
        request unanswered, and its record left with every target done."""
        write_request(self.cfg, "alpha", REQ, to=[self.addr("bravo")])
        fail = _RaiseOnce(outbound._write_anchor)
        with mock.patch.object(outbound, "_write_anchor", fail):
            self.poll()
        self.assertEqual(fail.calls, 1, "control: the anchor write was reached and failed")
        self.assertFalse(result_path(self.cfg, "alpha", REQ).exists())
        self.assertEqual(outbound._pending_ids(self.keyed(), "alpha"), [REQ],
                         "control: the record outlived the failed anchor")
        self.assertEqual(len(self.notice_ids("bravo")), 1)

    def test_a_request_gone_after_an_anchor_failure_is_answered_from_its_record(self):
        self.first_poll_loses_the_anchor()
        self.request_file("alpha").unlink()
        self.poll()
        self.assertTrue(result_path(self.cfg, "alpha", REQ).exists(),
                        "a request whose live file vanished was never answered")
        self.assertEqual(read_json(result_path(self.cfg, "alpha", REQ))["outcome"], "accepted")
        self.assertEqual(len(self.notice_ids("bravo")), 1)

    def test_a_record_with_any_other_origin_is_damaged_and_holds(self):
        self.first_poll_loses_the_anchor()
        path = outbound._pending_path(self.keyed(), "alpha", REQ)
        for origin in ("held", "Direct", None):
            with self.subTest(origin=origin):
                rec = read_json(path)
                rec["origin"] = origin
                path.write_text(json.dumps(rec))
                with self.assertRaises(outbound.PendingDamaged):
                    outbound._read_pending(path, REQ)
                self.poll()
                self.assertFalse(result_path(self.cfg, "alpha", REQ).exists(),
                                 "a record with a foreign origin was acted on")
                self.assertTrue(path.is_file())
                self.assertEqual(len(self.notice_ids("bravo")), 1)

    # -- a failure after the anchor: the record is swept, nothing re-placed ----

    def test_a_failure_after_the_anchor_leaves_no_record_and_places_once(self):
        write_request(self.cfg, "alpha", REQ, to=[self.addr("bravo")])
        fail = _RaiseOnce(outbound._publish_result_and_archive)
        with mock.patch.object(outbound, "_publish_result_and_archive", fail):
            self.poll()
            self.assertEqual(fail.calls, 1, "control: the publish was reached and failed")
            self.assertTrue(outbound._private_result_path(self.keyed(), "alpha", REQ).is_file(),
                            "control: the anchor was written before the failure")
            self.assertEqual(outbound._pending_ids(self.keyed(), "alpha"), [REQ],
                             "control: the record outlived the failure")
            self.poll()
        self.assertEqual(outbound._pending_ids(self.keyed(), "alpha"), [],
                         "an answered request's record was left behind")
        self.assertTrue(result_path(self.cfg, "alpha", REQ).exists())
        self.assertEqual(len(self.notice_ids("bravo")), 1)

    # -- W2: a crash after placement, before the "delivered" mark -------------

    def test_a_crash_before_the_delivered_mark_replays_the_same_identity(self):
        real = outbound._write_pending
        state = {"raised": False}

        def crash_on_delivered(cfg, path, rec):
            if not state["raised"] and any(t["state"] == "delivered" for t in rec["targets"]):
                state["raised"] = True
                raise OSError(5, "Input/output error (injected)")
            return real(cfg, path, rec)

        write_request(self.cfg, "alpha", REQ, to=[self.addr("bravo")])
        with mock.patch.object(outbound, "_write_pending", crash_on_delivered):
            self.poll()
        self.assertTrue(state["raised"], "control: the crash point was reached")
        first = self.notice_ids("bravo")
        self.assertEqual(len(first), 1, "control: the notice was placed before the crash")
        self.assertFalse(result_path(self.cfg, "alpha", REQ).exists())
        self.poll()
        self.assertEqual(self.notice_ids("bravo"), first, "a replay minted a second identity")
        self.assertTrue(result_path(self.cfg, "alpha", REQ).exists(), "the replay never answered")
        self.assertEqual(read_json(result_path(self.cfg, "alpha", REQ))["outcome"], "accepted")

    # -- W3: a permanently failing recipient is still answered ----------------

    def test_a_failing_recipient_on_a_direct_path_is_answered_failed(self):
        real = deliver_mod.deliver

        def charlie_fails(cfg, state_dir, sender, recipient, *a, **kw):
            if recipient == "charlie":
                raise RuntimeError("injected permanent failure")
            return real(cfg, state_dir, sender, recipient, *a, **kw)

        write_request(self.cfg, "alpha", REQ, to=[self.addr("bravo"), self.addr("charlie")])
        with mock.patch.object(deliver_mod, "deliver", charlie_fails):
            self.poll()
        self.assertTrue(result_path(self.cfg, "alpha", REQ).exists(),
                        "a direct request with a failing recipient was left unanswered")
        result = read_json(result_path(self.cfg, "alpha", REQ))
        self.assertEqual((result["outcome"], result["reason_code"]),
                         ("accepted", "partial_delivery"))
        self.assertIn("charlie", result["detail"])
        self.assertEqual(len(self.notice_ids("bravo")), 1)
        self.assertEqual(self.notice_ids("charlie"), [])
        self.assertEqual(outbound._pending_ids(self.keyed(), "alpha"), [],
                         "an answered request left its intent record")


class _PeerCase:
    """The peer-route witness: alpha may task delta."""

    def test_a_peer_route_places_once(self):
        write_request(self.cfg, "alpha", REQ, to=[addr("delta")])
        self.two_polls_with_one_anchor_failure("alpha")
        self.assertEqual(len(list_peer_notices(self.cfg, "delta")), 1)


class WithoutARegistry(_MailCases, _PeerCase, RouterTestCase):

    def keyed(self):
        return self.cfg

    def setUp(self):
        super().setUp()
        self.cfg = make_peer_config(self, {
            "alpha": {"peers": ["bravo", "charlie"]},
            "bravo": {"peers": ["alpha"]},
            "charlie": {"peers": ["alpha"]},
            "delta": {"peer_senders": ["alpha"]},
        })


class UnderARegistry(_MailCases, _PeerCase, _Fleet):
    pass


class WithoutAFleetDomain(_MailCases, RouterTestCase):
    """The legacy addresses (`agent.<name>@local`): the record must accept its
    own targets in that form, or a replay holds instead of answering."""

    def addr(self, name):
        return f"agent.{name}@local"

    def keyed(self):
        return self.cfg

    def setUp(self):
        super().setUp()
        self.cfg = self.make_config({"alpha": ["bravo", "charlie"], "bravo": ["alpha"],
                                     "charlie": ["alpha"]})


del _Fleet   # imported only as a base: not collected here a second time
