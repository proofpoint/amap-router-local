"""ALPHA-2 W10, A2-15: status `peer_store.signed` and the sender's
`signed sent:` line (design r3 §5.2, §5.5).

These are LIVENESS counters. The tests pin each counter's commit point on
the real producers -- the receiver's evaluation of real candidates (signed
by the stand-in codec), and the sender's real drain under a registry and a
hop -- and the cases where a counter must NOT move (a duplicate, a codec
demotion, a re-linked marker, a second pass over a handed copy).
"""
import json
import logging
import re
from unittest import mock

from router import hoplink, peerjournal, peerresend, service
from router.status import StatusTracker
from router.tests import test_peerevaluate as tpe
from router.tests.test_peercontrol_in import CID2, _ControlIn
from router.tests.test_peerlane import _Base as _LaneBase
from router.tests.test_peerresend import _Resend

ZEROS = {"v": 1, "since": "S",
         "sent": {"task": 0, "result": 0},
         "verified": {"task": 0, "result": 0, "control": 0},
         "decided": {"placed": 0, "refused": 0, "dropped": 0, "demoted": 0, "mail": 0},
         "duplicate": 0, "codec_demoted": 0}
OTHER_ID = "ZyXwVuTsRqPoNmLkJiHgFeD"          # a statement id (23 chars)


def counts(state_dir, **expect):
    """ZEROS with `expect` applied ("verified.task": 1, "duplicate": 1)."""
    want = json.loads(json.dumps(ZEROS))
    for key, n in expect.items():
        group, _, kind = key.replace("__", ".").partition(".")
        if kind:
            want[group][kind] = n
        else:
            want[group] = n
    return want, peerjournal.signed_status(state_dir, "S")


class _Clean:
    def setUp(self):
        super().setUp()
        peerjournal.SIGNED_COUNTS.clear()
        self.addCleanup(peerjournal.SIGNED_COUNTS.clear)


class ReceiverCountTests(_Clean, tpe._Eval):

    def assertCounts(self, **expect):
        want, got = counts(self.state_dir, **expect)
        self.assertEqual(got, want)

    def test_zero_before_anything(self):
        self.assertCounts()

    def test_a_placed_task_is_verified_then_decided_placed(self):
        rec = self.evaluate(self.take(self.raw()))
        self.assertEqual(rec["disposed"], "placed")
        self.assertCounts(verified__task=1, decided__placed=1)

    def test_a_replay_is_a_duplicate_and_never_a_second_verified(self):
        self.evaluate(self.take(self.raw()))
        rec = self.evaluate(self.take(self.raw()))
        self.assertEqual((rec["disposed"], rec["cause"]), ("dropped", "duplicate"))
        self.assertCounts(verified__task=1, decided__placed=1, duplicate=1)

    def test_verified_but_refused_is_decided_refused_not_placed(self):
        rec = self.evaluate(self.take(self.raw()), hk=tpe.hooks(
            policy=lambda _p, _h, _r: peerjournal.Refuse("policy", "not_today")))
        self.assertEqual(rec["disposed"], "refused")
        self.assertCounts(verified__task=1, decided__refused=1)

    def test_a_codec_demotion_is_never_verified(self):
        def bad_sig(raw):
            v = json.loads(raw)
            v["fields"][1][1] = v["fields"][1][1][:-4] + "AAAA"
            return v
        rec = self.evaluate(self.take(self.raw()), view=bad_sig)
        self.assertEqual((rec["disposed"], rec["cause"]), ("demoted", "signature"))
        self.assertCounts(codec_demoted=1)

    def test_a_statement_answering_one_is_counted_as_a_result(self):
        self.evaluate(self.take(self.raw(in_reply_to=OTHER_ID)))
        got = peerjournal.signed_status(self.state_dir, "S")
        self.assertEqual(got["verified"], {"task": 0, "result": 1, "control": 0})

    def test_a_done_marker_linked_again_is_not_counted_again(self):
        rec = self.evaluate(self.take(self.raw()))
        rt, idk = rec["replay_ref"].split("/")
        peerjournal.mark_done(self.state_dir, rt, idk, disposition="placed", now=tpe.NOW)
        self.assertCounts(verified__task=1, decided__placed=1)

    def test_a_new_process_starts_at_zero(self):
        self.evaluate(self.take(self.raw()))
        hoplink.reset_process_state()
        self.assertCounts()


class ControlCountTests(_Clean, _ControlIn):

    def test_a_reserved_control_is_verified_control(self):
        self.issued()
        self.entry(self.control_raw())
        self.poll()
        got = peerjournal.signed_status(self.state_dir, "S")
        self.assertEqual(got["verified"], {"task": 0, "result": 0, "control": 1})

    def test_a_replayed_control_is_a_duplicate(self):
        self.issued()
        raw = self.control_raw()
        self.entry(raw)
        self.poll()
        self.entry(raw, ident=CID2)
        self.poll()
        got = peerjournal.signed_status(self.state_dir, "S")
        self.assertEqual((got["verified"]["control"], got["duplicate"]), (1, 1))


class SenderCountTests(_Clean, _Resend):

    LINE = re.compile(r"signed sent: instance alpha id [A-Za-z0-9_-]{23} kind task in_reply_to -\Z")

    def test_a_handed_task_is_sent_once_with_one_line(self):
        # `handed.json` is linked by the pass that FINDS the handed marker:
        # the send hands over, the next drain records it.
        with self.assertLogs("amap_router_local.peerresend", logging.INFO) as cm:
            self.send()
            self.drain()
            self.drain()
        lines = [r.getMessage() for r in cm.records if r.getMessage().startswith("signed sent:")]
        self.assertEqual(len(lines), 1, lines)
        self.assertRegex(lines[0], self.LINE)
        got = peerjournal.signed_status(self.state_dir, "S")
        self.assertEqual(got["sent"], {"task": 1, "result": 0})

    def test_another_pass_over_a_handed_copy_does_not_count(self):
        self.send()
        k, _ = self.drain()
        d = next(peerresend.sent_root(self.state_dir, tpe_lid(self)).iterdir())
        self.assertTrue((d / peerresend.HANDED).is_file())
        rec = json.loads((d / peerresend.RECORD).read_text())
        self.assertFalse(peerresend.note_handed(k, "alpha", rec))
        self.assertEqual(peerjournal.signed_status(self.state_dir, "S")["sent"],
                         {"task": 1, "result": 0})

    def test_a_lost_link_race_is_not_counted(self):
        real = peerresend._link_once

        def lost(path, *a, **k):
            if path.name == peerresend.HANDED:
                return False                    # EEXIST: another pass linked it
            return real(path, *a, **k)
        with mock.patch.object(peerresend, "_link_once", lost):
            self.send()
            self.drain()
        self.assertEqual(peerjournal.signed_status(self.state_dir, "S")["sent"],
                         {"task": 0, "result": 0})

    def test_a_result_is_counted_and_logged_with_what_it_answers(self):
        import base64
        st = json.dumps({"id": OTHER_ID, "in_reply_to": "AbCdEfGhIjKlMnOpQrStUvW"}).encode()
        rec = {"peer": {"id": OTHER_ID, "statement": base64.b64encode(st).decode()}}
        with self.assertLogs("amap_router_local.peerresend", logging.INFO) as cm:
            peerresend._note_sent(self.cfg, "alpha", rec)
        self.assertEqual([r.getMessage() for r in cm.records],
                         [f"signed sent: instance alpha id {OTHER_ID} kind result "
                          "in_reply_to AbCdEfGhIjKlMnOpQrStUvW"])
        self.assertEqual(peerjournal.signed_status(self.state_dir, "S")["sent"],
                         {"task": 0, "result": 1})

    def test_an_id_outside_the_grammar_is_never_logged(self):
        rec = {"peer": {"id": "not an id\nsigned sent: forged", "statement": "!!"}}
        with self.assertLogs("amap_router_local.peerresend", logging.INFO) as cm:
            peerresend._note_sent(self.cfg, "alpha", rec)
        msgs = [r.getMessage() for r in cm.records]
        self.assertIn("signed sent: instance alpha id <invalid> kind task in_reply_to -", msgs)
        self.assertTrue(any(r.levelno == logging.ERROR for r in cm.records))
        self.assertFalse(any("forged" in m for m in msgs))


def tpe_lid(case):
    from router.tests.test_generations import LIDS
    return LIDS["alpha"]


class StatusSectionTests(_Clean, _LaneBase):
    """`peer_store.signed` is in every poll's document with delegation,
    zeros included, bound to this process's start."""

    def test_present_with_zeros(self):
        cfg = self.cfg()
        self.activate(cfg)
        tracker = StatusTracker(process_started_ts="2026-11-16T03:00:00.000001Z")
        with mock.patch.object(service, "run_once", return_value={}):
            service.poll_once(cfg, tracker)
        got = (tracker.to_doc().get("peer_store") or {}).get("signed")
        self.assertEqual(got, dict(ZEROS, since="2026-11-16T03:00:00.000001Z"))


if __name__ == "__main__":
    import unittest
    unittest.main()
