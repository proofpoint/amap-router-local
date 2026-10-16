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

from router import config as config_mod, service, status as status_mod, transport
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

    def test_absent_from_the_document_without_a_plugin(self):
        t = status_mod.StatusTracker(interval_s=5.0)
        t.record_transport_plugin(None)
        self.assertNotIn("transport_plugin", t.to_doc())


class RunningProcessTests(_Digest):
    """`run_forever` itself: the record is made from the loaded runtime, and a
    refused reload leaves it alone. The poll body is replaced by one that only
    writes status, and the loop ends at the second sleep."""

    def run_loop(self, cfg_path, rt, *, between=lambda: None):
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

        cfg = config_mod.load(cfg_path)
        with mock.patch.object(service, "start_transport", return_value=rt), \
                mock.patch.object(service, "peer_startup", return_value=None), \
                mock.patch.object(service, "poll_once", side_effect=poll), \
                mock.patch.object(service.time, "sleep", side_effect=sleep):
            service.run_forever(cfg, 5.0, config_path=str(cfg_path))

    def cfg_file(self, doc):
        p = self.base / "router.json"
        p.write_text(json.dumps(doc))
        return p

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
