"""The host intakes this router reads but never writes (`.unresolved/`,
`.control/`), its disposal tombstones for them (`.disposed/<intake>/`), and
the delegation reload refusal.

`quarantine list` and status report `.unresolved/` under the same threshold
as `.control/` (`ingress_quarantine_days`); an entry this router has
disposed of, proved by a valid tombstone, is reported apart and never as an
item or expired. `fsops` binds `.disposed/<intake>/` as this writer's own
kind, rooted at the hop root, with a writer-private stage."""
import datetime
import hashlib
import json
import os
import types
import unittest
from pathlib import Path
from unittest import mock

from router import fsops as fsops_mod, peerlane, quarantine, service
from router.tests import helpers

ID = "0123456789abcdef0123456789abcdef"
NOW = "2026-10-13T12:00:00Z"
NOW_TS = int(datetime.datetime(2026, 10, 13, 12, 0, 0,
                               tzinfo=datetime.timezone.utc).timestamp())
DAYS = 14


class _Hop(helpers.RouterTestCase):

    def setUp(self):
        super().setUp()
        self.hop = self.tmp / "hop"
        self.hop.mkdir()
        self.cfg = types.SimpleNamespace(hop=types.SimpleNamespace(root=str(self.hop)))

    def entry(self, source, ident=ID, age=0, body=b'{"c":1}'):
        d = self.hop / quarantine.INTAKES[source] / ident
        d.mkdir(parents=True)
        c = d / "candidate.json"
        c.write_bytes(body)
        os.utime(c, (NOW_TS - age, NOW_TS - age))
        return hashlib.sha256(body).hexdigest()

    def tombstone(self, source, ident=ID, digest="", mode=0o640, **over):
        doc = {"v": 1, "intake": quarantine.INTAKES[source], "id": ident,
               "candidate_sha256": digest, "disposition": "placed",
               "disposed_at": "2026-10-13T11:00:00Z"}
        doc.update(over)
        d = self.hop / quarantine.DISPOSED_DIR / quarantine.INTAKES[source]
        d.mkdir(parents=True, exist_ok=True)
        p = d / ident
        p.write_bytes(json.dumps(doc).encode())
        os.chmod(p, mode)
        return p

    def listed(self, source):
        return quarantine.list_control(
            quarantine.intake_dir_for(self.cfg, source), now=NOW, days=DAYS, source=source,
            disposed_dir=quarantine.disposed_dir_for(self.cfg, source))


class UnresolvedReportTests(_Hop):

    def test_the_threshold_boundary(self):
        """`ingress_quarantine_days` applies to `.unresolved/` exactly as to
        `.control/`: days*86400 - 1 is not expired, days*86400 is."""
        for source in quarantine.INTAKES:
            for age, expired in ((DAYS * 86400 - 1, False), (DAYS * 86400, True)):
                with self.subTest(source=source, age=age):
                    self.setUp()
                    self.entry(source, age=age)
                    [item] = self.listed(source)
                    self.assertEqual(item.source, source)
                    self.assertEqual(item.expires_in_s <= 0, expired)
                    self.tearDown()

    def test_a_valid_tombstone_marks_the_entry_disposed(self):
        digest = self.entry(quarantine.SOURCE_UNRESOLVED, age=DAYS * 86400 + 5)
        self.tombstone(quarantine.SOURCE_UNRESOLVED, digest=digest)
        [item] = self.listed(quarantine.SOURCE_UNRESOLVED)
        self.assertTrue(item.meta.get("disposed"))
        self.assertIsNone(item.expires_in_s, "a disposed entry never counts as expired")
        self.assertIn("disposed", quarantine.render_line(item))

    def test_an_invalid_tombstone_disposes_nothing(self):
        cases = {
            "another digest": dict(digest="f" * 64),
            "another intake": dict(intake=".control"),
            "another id": dict(id="f" * 32),
            "an extra member": dict(extra=1),
            "another v": dict(v=2),
            "a +00:00 instant": dict(disposed_at="2026-10-13T11:00:00+00:00"),
            "a mode wider than 0640": dict(mode=0o644),
        }
        for why, over in cases.items():
            with self.subTest(why=why):
                self.setUp()
                digest = self.entry(quarantine.SOURCE_UNRESOLVED)
                kw = {"digest": over.pop("digest", digest), "mode": over.pop("mode", 0o640)}
                self.tombstone(quarantine.SOURCE_UNRESOLVED, **kw, **over)
                [item] = self.listed(quarantine.SOURCE_UNRESOLVED)
                self.assertFalse(item.meta.get("disposed"), why)
                self.tearDown()

    def test_a_tombstone_at_two_links_is_a_commit_in_progress(self):
        digest = self.entry(quarantine.SOURCE_UNRESOLVED)
        p = self.tombstone(quarantine.SOURCE_UNRESOLVED, digest=digest)
        os.link(p, self.tmp / "second-link")
        [item] = self.listed(quarantine.SOURCE_UNRESOLVED)
        self.assertFalse(item.meta.get("disposed"))

    def test_a_symlinked_tombstone_disposes_nothing(self):
        digest = self.entry(quarantine.SOURCE_UNRESOLVED)
        real = self.tombstone(quarantine.SOURCE_UNRESOLVED, digest=digest)
        moved = self.tmp / "elsewhere"
        os.rename(real, moved)
        real.symlink_to(moved)
        [item] = self.listed(quarantine.SOURCE_UNRESOLVED)
        self.assertFalse(item.meta.get("disposed"))


class DisposedBindingTests(_Hop):

    def ops(self):
        ops = fsops_mod.FsOps(hop_root=str(self.hop))
        self.addCleanup(ops.close)
        return ops

    def test_a_tombstone_commits_under_the_hop_rooted_tag(self):
        """`.disposed/<intake>/` is this writer's own kind, rooted at the hop
        root: the destination tag is `9-.disposed.8-.control`, and the stage
        is `.disposed/<intake>/.stage/` 0700."""
        (self.hop / ".disposed" / ".control").mkdir(parents=True)
        ops = self.ops()
        root = ops.open_root_nofollow(str(self.hop))
        dest = ops.descend_pinned(root, ".disposed/.control")
        b = ops.binding(dest)
        self.assertEqual((b.kind, b.rel), (fsops_mod.DISPOSED, (".disposed", ".control")))
        self.assertEqual(b.tag, "9-.disposed.8-.control")
        stage = ops.open_disposed_stage_dir(dest)
        self.assertEqual(os.stat(self.hop / ".disposed" / ".control" / ".stage").st_mode & 0o777,
                         0o700)
        data = peerlane.tombstone_bytes(intake=".control", ident=ID, candidate_sha256="b" * 64,
                                        disposition="dropped", disposed_at=NOW)
        self.assertEqual(ops.commit_durable(stage, dest, ID, data, 0o640), "created")
        self.assertEqual(ops.commit_durable(stage, dest, ID, data, 0o640), "exists_same")
        self.assertEqual((self.hop / ".disposed" / ".control" / ID).read_bytes(), data)

    def test_a_disposed_directory_owned_by_another_uid_is_refused(self):
        (self.hop / ".disposed" / ".control").mkdir(parents=True)
        ops = self.ops()
        root = ops.open_root_nofollow(str(self.hop))
        with mock.patch.object(fsops_mod.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(fsops_mod.BindingError):
                ops.descend_pinned(root, ".disposed/.control")

    def test_only_the_two_intakes_live_under_disposed(self):
        (self.hop / ".disposed" / "elsewhere").mkdir(parents=True)
        ops = self.ops()
        root = ops.open_root_nofollow(str(self.hop))
        with self.assertRaises(fsops_mod.BindingError):
            ops.descend_pinned(root, ".disposed/elsewhere")


class ReloadRefusalTests(helpers.RouterTestCase):
    """A reload whose delegation cannot be activated is refused: the last
    good config stays, `reload_failed` is set, and status says since when
    and why."""

    def test_a_refused_delegation_refuses_the_reload(self):
        current = types.SimpleNamespace(state_dir=self.state_dir, delegation=object(),
                                        reload_failed=False, transport_plugin=None, hop=None,
                                        min_sender_age_s=86400)
        fresh = types.SimpleNamespace(state_dir=self.state_dir, delegation=object(),
                                      transport_plugin=None, hop=None, min_sender_age_s=86400,
                                      reload_failed=False)
        refused = peerlane.DelegationRefused("signing_key_mismatch", "no")
        with mock.patch.object(service, "load", return_value=fresh), \
                mock.patch.object(service, "activate_delegation", side_effect=refused), \
                mock.patch.object(service, "replace",
                                  side_effect=lambda c, **kw: types.SimpleNamespace(
                                      **{**vars(c), **kw})):
            got = service.reload_config("cfg.json", current, runtime=object())
        self.assertTrue(got.reload_failed)
        self.assertIs(got.delegation, current.delegation)
        self.assertEqual(service._RELOAD_FAILURE[str(self.state_dir)]["error"],
                         "delegation could not be activated")
        service._RELOAD_FAILURE.clear()

    def test_a_good_reload_clears_the_failure(self):
        service._RELOAD_FAILURE[str(self.state_dir)] = {"since": NOW, "error": "x"}
        current = types.SimpleNamespace(state_dir=self.state_dir, delegation=None,
                                        reload_failed=True, transport_plugin=None, hop=None,
                                        min_sender_age_s=86400)
        fresh = types.SimpleNamespace(state_dir=self.state_dir, delegation=None,
                                      transport_plugin=None, hop=None, min_sender_age_s=86400)
        with mock.patch.object(service, "load", return_value=fresh):
            got = service.reload_config("cfg.json", current)
        self.assertIs(got, fresh)
        self.assertNotIn(str(self.state_dir), service._RELOAD_FAILURE)


if __name__ == "__main__":
    unittest.main()
