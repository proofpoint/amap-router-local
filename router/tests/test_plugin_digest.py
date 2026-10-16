"""status.json's `transport_plugin`: the plugin THIS PROCESS loaded, as
`{path, sha256}` from `transport.load_plugin`'s own single fd read
(`service.plugin_status`), recorded once at startup (`run_forever`) and never
again.

What a reader may rely on, each pinned by a row here and broken by
`router/tests/mutate_plugin_digest.py`:

  * the digest is of the bytes the loader read and executed, not of whatever
    the file holds when status is written;
  * a reload that changes `transport_plugin` is refused, and the published
    digest stays the loaded one; the refusal itself is in status.json
    (`classification.config_reload_failed`, error "transport_plugin changed");
  * a new process publishes its own, and none when it loads no plugin.
"""
from __future__ import annotations

import hashlib
import json
import os
from unittest import mock

import re
import time
from datetime import datetime, timedelta, timezone

from router import __main__ as cli, clock, config as config_mod, service, status as status_mod, transport
from router.tests import helpers
from router.tests.test_transport import GOOD, ME, _PluginDir

OTHER = GOOD + b"\n# a different plugin\n"


class _Digest(_PluginDir):

    def setUp(self):
        super().setUp()
        self.base = self.dir.parent
        (self.base / "alice").mkdir()
        self.state = self.base / "state"
        self.state.mkdir()
        service._RELOAD_FAILURE.clear()
        self.addCleanup(service._RELOAD_FAILURE.clear)

    def doc(self, path=None, sha=None):
        return helpers.with_hop({
            "state_dir": str(self.state),
            "instances": {"alice": {"namespace": str(self.base / "alice")}},
            "transport_plugin": {"path": str(path or self.path), "sha256": sha or self.sha}},
            self.base)

    def trusting(self):
        real = transport.load_plugin
        return mock.patch.object(transport, "load_plugin",
                                 lambda p, h, **kw: real(p, h, **dict(kw, trusted_uids=ME)))

    def start(self, doc=None):
        cfg = config_mod.load_obj(doc or self.doc())
        with self.trusting():
            return cfg, service.start_transport(cfg)

    def status_of(self, runtime):
        """`service.plugin_status`; an exception FAILS (mutants count failures only)."""
        try:
            return service.plugin_status(runtime)
        except Exception as e:  # noqa: BLE001
            self.fail(f"plugin_status raised {type(e).__name__}: {e}")

    def published(self):
        return json.loads((self.state / status_mod.STATUS_FILENAME).read_text()).get("transport_plugin")


class PublishedDigestTests(_Digest):

    def test_it_is_the_loaded_bytes_digest_and_path(self):
        _, rt = self.start()
        self.assertEqual(self.status_of(rt),
                         {"path": str(self.path), "sha256": hashlib.sha256(GOOD).hexdigest()})

    def test_it_is_not_recomputed_from_the_file_afterwards(self):
        """The file changes on disk after the load: the published digest is
        still the loaded bytes', never the file's now."""
        loaded = self.sha
        _, rt = self.start()
        self.write(OTHER)
        self.assertNotEqual(self.sha, loaded)
        self.assertEqual(self.status_of(rt)["sha256"], loaded)

    def test_no_loaded_plugin_publishes_nothing(self):
        self.assertIsNone(self.status_of(None))
        stand_in = service.HopRuntime(plugin=object(), fsops=None, hop=None)
        self.assertIsNone(self.status_of(stand_in),
                          "a stand-in loaded no bytes and carries no digest")

    def test_the_tracker_records_it_once(self):
        t = status_mod.StatusTracker(interval_s=5.0)
        t.record_transport_plugin({"path": "/p", "sha256": "a" * 64})
        with self.assertRaises(ValueError):
            t.record_transport_plugin({"path": "/q", "sha256": "b" * 64})
        self.assertEqual(t.to_doc()["transport_plugin"], {"path": "/p", "sha256": "a" * 64})

    def test_a_none_record_latches_too(self):
        t = status_mod.StatusTracker(interval_s=5.0)
        t.record_transport_plugin(None)
        with self.assertRaises(ValueError):
            t.record_transport_plugin({"path": "/p", "sha256": "a" * 64})
        self.assertNotIn("transport_plugin", t.to_doc())

    def test_absent_from_the_document_without_a_plugin(self):
        t = status_mod.StatusTracker(interval_s=5.0)
        t.record_transport_plugin(None)
        self.assertNotIn("transport_plugin", t.to_doc())


class _Loop(_Digest):
    """`run_forever` itself, driven: the poll body is replaced by one that only
    writes status (each write's document kept in `self.writes`), and the loop
    ends at the second sleep."""

    def run_loop(self, cfg_path, rt, *, between=lambda: None, process_started=None):
        self.writes = []
        sleeps = []

        def sleep(_):
            sleeps.append(1)
            if len(sleeps) == 1:
                between()
                return
            raise KeyboardInterrupt

        def poll(cfg, tracker, *a, **kw):
            tracker.record_poll({})
            tracker.write(cfg.state_dir)
            self.writes.append(json.loads(
                (self.state / status_mod.STATUS_FILENAME).read_text()))

        cfg = config_mod.load(cfg_path)
        with mock.patch.object(service, "start_transport", return_value=rt), \
                mock.patch.object(service, "peer_startup", return_value=None), \
                mock.patch.object(service, "poll_once", side_effect=poll), \
                mock.patch.object(service.time, "sleep", side_effect=sleep):
            service.run_forever(cfg, 5.0, config_path=str(cfg_path),
                                process_started=process_started)

    def cfg_file(self, doc):
        p = self.base / "router.json"
        p.write_text(json.dumps(doc))
        return p


class RunningProcessTests(_Loop):
    """The record is made from the loaded runtime, and a refused reload leaves
    it alone."""

    def test_the_running_process_publishes_its_loaded_digest(self):
        _, rt = self.start()
        self.run_loop(self.cfg_file(self.doc()), rt)
        self.assertEqual(self.published(), {"path": str(self.path), "sha256": rt.plugin.sha256})

    def test_a_refused_reload_of_a_changed_plugin_leaves_the_old_digest(self):
        _, rt = self.start()
        old = rt.plugin.sha256
        other = self.dir / "other.py"
        other.write_bytes(OTHER)
        os.chmod(other, 0o644)
        cfg_path = self.cfg_file(self.doc())
        changed = self.doc(other, hashlib.sha256(OTHER).hexdigest())
        self.run_loop(cfg_path, rt, between=lambda: cfg_path.write_text(json.dumps(changed)))
        doc = json.loads((self.state / status_mod.STATUS_FILENAME).read_text())
        self.assertEqual(doc["polls"], 2, "the second poll ran after the refused reload")
        self.assertEqual((service._RELOAD_FAILURE.get(str(self.state)) or {}).get("error"),
                         "transport_plugin changed", "the reload was not refused")
        self.assertEqual(doc["transport_plugin"], {"path": str(self.path), "sha256": old})

    def test_a_new_process_publishes_its_own(self):
        _, first = self.start()
        self.run_loop(self.cfg_file(self.doc()), first)
        self.write(OTHER)
        _, second = self.start()
        self.run_loop(self.cfg_file(self.doc()), second)
        self.assertEqual(self.published(),
                         {"path": str(self.path), "sha256": hashlib.sha256(OTHER).hexdigest()})

    def test_a_process_without_a_plugin_publishes_none(self):
        doc = self.doc()
        del doc["transport_plugin"], doc["hop"]
        self.run_loop(self.cfg_file(doc), None)
        self.assertIsNone(self.published())


class RefusalIsRecordedTests(_Digest):
    """A reload refused for a startup-only field is recorded like any other
    refusal, so status.json shows it (the classification section)."""

    def kept(self, changed_doc):
        cfg, _ = self.start()
        with mock.patch.object(service, "load", return_value=config_mod.load_obj(changed_doc)):
            return service.reload_config("/unused", cfg)

    def assert_recorded(self, kept, error):
        self.assertTrue(kept.reload_failed)
        doc = service.classification_status(kept, None, None)
        self.assertIs(doc["config_reload_failed"], True)
        self.assertEqual(doc["config_reload_failure"]["error"], error)

    def test_a_changed_transport_plugin_is_recorded(self):
        other = self.dir / "other.py"
        other.write_bytes(OTHER)
        os.chmod(other, 0o644)
        self.assert_recorded(self.kept(self.doc(other, hashlib.sha256(OTHER).hexdigest())),
                             "transport_plugin changed")

    def test_a_changed_state_dir_is_recorded(self):
        moved = self.base / "state2"
        moved.mkdir()
        self.assert_recorded(self.kept(dict(self.doc(), state_dir=str(moved))),
                             "state_dir changed")


US_TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z")


class ProcessStartedTests(_Loop):
    """`process_started_ts`: this process's start at full resolution, taken
    once before the plugin is loaded, on every write, never re-read. A clock
    source that advances one second per read makes every re-read visible."""

    def setUp(self):
        super().setUp()
        self.reads = []
        t0 = datetime(2026, 10, 16, 1, 0, 0, 123456, tzinfo=timezone.utc)

        def source():
            self.reads.append(1)
            return t0 + timedelta(seconds=len(self.reads))
        clock.install(source)
        self.addCleanup(clock.reset)

    def test_present_with_a_fraction_on_every_write(self):
        _, rt = self.start()
        self.run_loop(self.cfg_file(self.doc()), rt)
        self.assertEqual(len(self.writes), 2)
        for doc in self.writes:
            self.assertRegex(doc.get("process_started_ts") or "", US_TS)

    def test_unchanged_across_a_reload(self):
        _, rt = self.start()
        cfg_path = self.cfg_file(self.doc())
        self.run_loop(cfg_path, rt, between=lambda: cfg_path.write_text(json.dumps(self.doc())))
        values = [d.get("process_started_ts") for d in self.writes]
        self.assertEqual(len(values), 2)
        self.assertIsNotNone(values[0])
        self.assertEqual(values[0], values[1], "process_started_ts was re-read")

    def test_a_new_process_gets_a_new_value(self):
        _, rt = self.start()
        self.run_loop(self.cfg_file(self.doc()), rt)
        first = self.writes[-1].get("process_started_ts")
        self.run_loop(self.cfg_file(self.doc()), rt)
        second = self.writes[-1].get("process_started_ts")
        self.assertIsNotNone(first)
        self.assertNotEqual(first, second)

    def test_taken_before_the_plugin_is_loaded(self):
        """With no value passed in, run_forever takes it before start_transport."""
        _, rt = self.start()
        loaded_at = []

        def start(cfg):
            loaded_at.append(clock.now())
            return rt
        cfg_path = self.cfg_file(self.doc())
        cfg = config_mod.load(cfg_path)
        self.writes = []

        def poll(cfg, tracker, *a, **kw):
            tracker.record_poll({})
            tracker.write(cfg.state_dir)
            self.writes.append(json.loads((self.state / status_mod.STATUS_FILENAME).read_text()))
        with mock.patch.object(service, "start_transport", side_effect=start), \
                mock.patch.object(service, "peer_startup", return_value=None), \
                mock.patch.object(service, "poll_once", side_effect=poll), \
                mock.patch.object(service.time, "sleep", side_effect=KeyboardInterrupt):
            service.run_forever(cfg, 5.0)
        taken = datetime.strptime(self.writes[0]["process_started_ts"], "%Y-%m-%dT%H:%M:%S.%fZ"
                                  ).replace(tzinfo=timezone.utc)
        self.assertEqual(len(loaded_at), 1)
        self.assertLess(taken, loaded_at[0], "taken after the plugin was loaded")

    def test_main_takes_it_first_and_passes_it(self):
        """`main` reads the clock before it loads the config, and hands that
        value to run_forever."""
        seen = {}
        load_at = []

        def load(path):
            load_at.append(clock.now())
            return config_mod.load_obj(self.doc())

        def run(cfg, interval, config_path=None, process_started=None):
            seen["process_started"] = process_started
        with mock.patch.object(cli, "load", side_effect=load), \
                mock.patch.object(cli, "run_forever", side_effect=run):
            cli.main(["--config", "unused.json", "run", "--interval", "5"])
        self.assertIsInstance(seen.get("process_started"), datetime)
        self.assertLess(seen["process_started"], load_at[0], "taken after the config was loaded")


class ProcessStartedValueTests(_Loop):
    """The VALUE, not only its shape: a known instant with a non-zero
    microsecond, under a non-UTC local zone, must come out as that exact UTC
    string. Local time with a `Z`, or a zeroed fraction, would pass a shape
    check and fail this one."""

    WHEN = datetime(2026, 10, 16, 1, 42, 19, 453920, tzinfo=timezone.utc)

    def setUp(self):
        super().setUp()
        old = os.environ.get("TZ")

        def restore():
            if old is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old
            time.tzset()
        os.environ["TZ"] = "America/Denver"
        time.tzset()
        self.addCleanup(restore)

    def test_the_exact_utc_string_with_its_microseconds(self):
        _, rt = self.start()
        self.run_loop(self.cfg_file(self.doc()), rt, process_started=self.WHEN)
        self.assertEqual([d.get("process_started_ts") for d in self.writes],
                         ["2026-10-16T01:42:19.453920Z"] * 2)
