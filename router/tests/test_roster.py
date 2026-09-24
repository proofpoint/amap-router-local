"""The fleet roster (`router/roster.py`): who exists, published for agents.

Each class pins one property the module docstring states, on the surface
where that property is the ONLY thing that could produce what is asserted —
and each carries the companion check that fails when nothing happened, since
"no file", "no read" and "no log line" are all also what a no-op produces.

Built on `test_discovery._Tree`, whose layout is the host adapter's:
`features/amap/{instances/, selected.json}`, so the roster directory this
side derives is the one the adapter's install creates and its manifest
mounts.
"""

import builtins
import json
import logging
import os
import stat
import unittest
from pathlib import Path
from unittest import mock

from router import roster, service
from router.config import load_obj
from router.status import StatusTracker
from router.tests.test_discovery import _Tree
from router.util import atomic_write

DOMAIN = "agents.internal"


class _RosterTree(_Tree):
    """A discovery fleet with a fleet domain and the adapter's roster dir."""

    def setUp(self):
        super().setUp()
        self.roster_dir = self.feat / "roster"
        self.roster_dir.mkdir()
        self.roster_file = self.roster_dir / "roster.json"

    def fleet(self, selected=("alice-deadbeef", "bravo-0badcafe"), **top):
        for slug in selected:
            self.dir_for(slug)
        self.verdict(selected=selected)
        return self.load(fleet_domain=DOMAIN, **top)

    def written(self):
        return json.loads(self.roster_file.read_text())


class LocationConventionTests(_RosterTree):
    """`dirname(selected_json)/roster/roster.json` — the convention the host
    adapter pins from ITS side. Between the two tests the convention cannot
    drift silently from either end."""

    def test_the_target_is_beside_selected_json(self):
        cfg = self.fleet()
        self.assertEqual(roster.roster_dir(cfg), self.feat / "roster")
        self.assertEqual(cfg.selected_json.parent, self.feat)

    def test_publishing_lands_exactly_there(self):
        """End to end, not just the helper: the FILE appears at the path the
        adapter mounts. Asserted on the file, because a helper that returns
        the right path and a writer that ignores it would pass the test above."""
        self.assertFalse(self.roster_file.exists())

        self.assertEqual(roster.publish(self.fleet(), 5.0), roster.WRITTEN)

        self.assertTrue(self.roster_file.is_file())

    def test_an_authored_config_has_no_roster(self):
        """Option (b) is defined for discovery only: an authored `instances`
        object has no `selected_json` to derive from. Skipped, not refused."""
        cfg = load_obj({"state_dir": str(self.state), "fleet_domain": DOMAIN,
                        "instances": {"alice": {"handoff_dir": str(self.root / "h")}}})
        self.assertIsNone(cfg.selected_json)
        self.assertIsNone(roster.roster_dir(cfg))
        self.assertEqual(roster.publish(cfg, 5.0), roster.SKIP_AUTHORED)


class ContentTests(_RosterTree):

    def test_members_are_the_ADMITTED_set_not_the_discovered_one(self):
        """Three directories, one of each fate. Only the selected one is a
        member: a not-selected directory and one with no verdict are
        discovered, never admitted, and must not be announced."""
        for slug in ("alice-deadbeef", "bravo-0badcafe", "carol-c0ffee01"):
            self.dir_for(slug)
        self.verdict(selected=["alice-deadbeef"], not_selected=["bravo-0badcafe"])
        cfg = self.load(fleet_domain=DOMAIN)

        roster.publish(cfg, 5.0)

        self.assertEqual([m["address"].split("@")[0] for m in self.written()["members"]],
                         ["alice-deadbeef"])

    def test_a_member_carries_address_and_state_and_nothing_else(self):
        """No edges, no evidence, no slug, no basename split from it. Pinned
        as the EXACT key set: the schema's envelope is OPEN, so it would
        accept a `may_task` or a delivery timestamp without complaint, and
        emitting a member the spec does not define is still producer
        non-conformance. This test is the gate the schema cannot be."""
        roster.publish(self.fleet(selected=("alice-deadbeef",)), 5.0)

        self.assertEqual(self.written()["members"], [{
            "address": "alice-deadbeef@agents.internal",
            "state": "admitted",
        }])

    def test_the_top_level_keys_are_exactly_the_v1_set(self):
        roster.publish(self.fleet(), 5.0)

        doc = self.written()
        self.assertEqual(set(doc), {"contract_version", "router", "written_at",
                                    "interval_s", "members"})
        self.assertEqual(doc["contract_version"], "2")
        self.assertEqual(doc["router"], "amap.router@agents.internal")
        self.assertEqual(doc["interval_s"], 5.0)

    def test_members_are_sorted_by_ADDRESS_not_by_slug(self):
        """The schema says "sorted by address", and for most fleets that is
        the same order as sorting by instance name — which is exactly why a
        test built on ordinary names cannot tell them apart. This pair is
        chosen so the two orders DISAGREE: `-` (0x2d) sorts before `@` (0x40),
        so `alice-deadbeef@…` precedes `alice@…` by address, while `alice`
        precedes `alice-deadbeef` by name. The control asserts the
        disagreement itself, so this cannot pass on a pair that no longer
        distinguishes the two."""
        names = ("alice", "alice-deadbeef")
        self.assertEqual(sorted(names), ["alice", "alice-deadbeef"])
        self.assertEqual(sorted(f"{n}@{DOMAIN}" for n in names),
                         ["alice-deadbeef@agents.internal", "alice@agents.internal"])

        roster.publish(self.fleet(selected=names), 5.0)

        self.assertEqual([m["address"] for m in self.written()["members"]],
                         ["alice-deadbeef@agents.internal", "alice@agents.internal"])

    def test_an_unknown_interval_is_OMITTED_not_defaulted(self):
        """A reader computes a freshness bound from it, so an invented value
        is a wrong bound asserted confidently. Same rule as status.json."""
        roster.publish(self.fleet(), None)
        self.assertNotIn("interval_s", self.written())


class SkipTests(_RosterTree):

    def test_an_unavailable_verdict_writes_NOTHING_and_leaves_the_old_roster(self):
        """Empty-because-unknown is not empty-because-nobody. `members: []`
        here would tell every agent the fleet is empty.

        The old file is the positive control: it is proved to exist first
        and to be byte-identical after, so "no roster written" cannot be the
        writer silently failing on a directory it could not reach."""
        self.dir_for("alice-deadbeef")          # a directory, but no verdict file
        cfg = self.load(fleet_domain=DOMAIN)
        self.assertTrue(cfg.discovery.verdict_unavailable)
        self.roster_file.write_text('{"previous": true}\n')

        outcome = roster.publish(cfg, 5.0)

        self.assertEqual(outcome, roster.SKIP_VERDICT_UNAVAILABLE)
        self.assertEqual(self.roster_file.read_text(), '{"previous": true}\n')

    def test_an_answered_empty_verdict_IS_published_as_empty(self):
        """The control that gives the test above its meaning: when the host
        answered "nobody", `members: []` is true and is written."""
        cfg = self.fleet(selected=())
        self.assertFalse(cfg.discovery.verdict_unavailable)

        self.assertEqual(roster.publish(cfg, 5.0), roster.WRITTEN)
        self.assertEqual(self.written()["members"], [])

    def test_an_absent_roster_dir_is_NOT_created(self):
        """It is the adapter's directory. Creating it would hide the
        adapter's install failure and put the file where nothing mounts.

        The parent exists and is writable — proved by writing to it — so
        the directory's continued absence is the writer declining, not the
        writer being unable to."""
        cfg = self.fleet()
        self.roster_dir.rmdir()
        (self.feat / "probe").write_text("x")

        outcome = roster.publish(cfg, 5.0)

        self.assertTrue(outcome.startswith("skipped: roster directory absent"), outcome)
        self.assertFalse(self.roster_dir.exists())

    def test_no_fleet_domain_is_skipped(self):
        for slug in ("alice-deadbeef",):
            self.dir_for(slug)
        self.verdict(selected=["alice-deadbeef"])
        cfg = self.load()

        self.assertEqual(roster.publish(cfg, 5.0), roster.SKIP_NO_DOMAIN)
        self.assertFalse(self.roster_file.exists())


class FileModeTests(_RosterTree):

    def test_the_roster_is_world_readable(self):
        """`mkstemp` creates 0600. For this file that is the failure spec §10
        names for `directory.json`: the write succeeds, the content is right,
        and the agent's uid gets EACCES. Asserted on the permission bits
        themselves, since reading the file back as the SAME uid would succeed
        at 0600 and prove nothing."""
        roster.publish(self.fleet(), 5.0)
        self.assertEqual(stat.S_IMODE(self.roster_file.stat().st_mode), 0o644)


class NeverReadBackTests(_RosterTree):
    """`roster.json` is write-only from this side, for ANY purpose — not as a
    cache, not for recovery, not as a cross-check."""

    def test_publishing_never_opens_the_roster_for_reading(self):
        """The direct form. Every read path a later change might reach for —
        `open`, `Path.read_text`, `Path.read_bytes`, `Path.open` — is watched,
        and any read of a `roster.json` is recorded.

        The watch is proved live before it is trusted: a deliberate read of
        the roster through each path IS recorded, so an empty record after
        publishing means "nothing read it", not "the watch was not attached"."""
        cfg = self.fleet()
        roster.publish(cfg, 5.0)          # a file now exists to be read
        reads = []
        real_open, real_rt, real_rb, real_popen = (
            builtins.open, Path.read_text, Path.read_bytes, Path.open)

        def is_roster(p):
            return Path(str(p)).name == roster.ROSTER_FILENAME

        def w_open(file, mode="r", *a, **k):
            if isinstance(file, (str, os.PathLike)) and is_roster(file) and "r" in mode:
                reads.append(("open", str(file)))
            return real_open(file, mode, *a, **k)

        def w_rt(self_, *a, **k):
            if is_roster(self_):
                reads.append(("read_text", str(self_)))
            return real_rt(self_, *a, **k)

        def w_rb(self_, *a, **k):
            if is_roster(self_):
                reads.append(("read_bytes", str(self_)))
            return real_rb(self_, *a, **k)

        def w_popen(self_, mode="r", *a, **k):
            if is_roster(self_) and "r" in mode:
                reads.append(("Path.open", str(self_)))
            return real_popen(self_, mode, *a, **k)

        with mock.patch.object(builtins, "open", w_open), \
             mock.patch.object(Path, "read_text", w_rt), \
             mock.patch.object(Path, "read_bytes", w_rb), \
             mock.patch.object(Path, "open", w_popen):
            # Positive control: the watch sees each kind of read.
            with open(self.roster_file):
                pass
            self.roster_file.read_text()
            self.roster_file.read_bytes()
            with self.roster_file.open():
                pass
            # A SET, not a sequence: on some Pythons `read_text` and
            # `read_bytes` go through `Path.open` internally, so one read is
            # recorded twice. The control's job is that every path is SEEN.
            self.assertEqual({k for k, _ in reads},
                             {"open", "read_text", "read_bytes", "Path.open"})
            reads.clear()

            roster.publish(cfg, 5.0)

        self.assertEqual(reads, [])

    def test_a_previous_roster_contributes_nothing(self):
        """The rot the prohibition exists for, in its most innocent form: a
        merge. A ghost member in the previous file must be gone, and the
        output must be exactly what `build` makes from the admitted set."""
        cfg = self.fleet(selected=("alice-deadbeef",))
        self.roster_file.write_text(json.dumps({
            "contract_version": "2", "members": [
                {"address": "ghost-deadbeef@agents.internal", "state": "admitted"}]}))

        roster.publish(cfg, 5.0)

        self.assertEqual([m["address"].split("@")[0] for m in self.written()["members"]],
                         ["alice-deadbeef"])


class PollIntegrationTests(_RosterTree):
    """Through `service.poll_once` — the loop body, which every caller of the
    loop runs. The roster is published THERE rather than in `run_forever`."""

    def test_poll_once_publishes_the_roster(self):
        """The companion to every skip test above: the real loop body, not
        the helper, produces a file. Without this, a `publish` nobody calls
        passes every other class in this module."""
        cfg = self.fleet()
        self.assertFalse(self.roster_file.exists())

        service.poll_once(cfg, StatusTracker(interval_s=5.0))

        self.assertEqual(len(self.written()["members"]), 2)
        self.assertEqual(self.written()["interval_s"], 5.0)

    def test_the_roster_is_written_AFTER_the_drain(self):
        """A newcomer's first-sight snapshot is taken during the drain, so
        publishing before it would announce an address the router has not
        yet adopted. Pinned as call ORDER, which only the placement of the
        call in `poll_once` can produce."""
        cfg = self.fleet()
        order = []
        real_run_once, real_publish = service.run_once, roster.publish

        def run_once(c):
            order.append("drain")
            return real_run_once(c)

        def publish(c, i):
            order.append("roster")
            return real_publish(c, i)

        with mock.patch.object(service, "run_once", run_once), \
             mock.patch.object(roster, "publish", publish):
            service.poll_once(cfg, StatusTracker(interval_s=5.0))

        self.assertEqual(order, ["drain", "roster"])

    def test_a_standing_skip_is_logged_ONCE_not_every_poll(self):
        """Three polls with the directory absent, one warning. Asserted as
        exactly one — not "at least one" — so a regression to per-poll
        logging goes red; and the count must be one rather than zero, so a
        logger that never fires cannot pass either."""
        cfg = self.fleet()
        self.roster_dir.rmdir()
        tracker = StatusTracker(interval_s=5.0)

        with self.assertLogs("amap_router_local", level="WARNING") as logs:
            for _ in range(3):
                service.poll_once(cfg, tracker)

        roster_lines = [r for r in logs.output if "roster:" in r]
        self.assertEqual(len(roster_lines), 1, logs.output)
        self.assertIn("roster directory absent", roster_lines[0])

    def test_a_roster_failure_does_not_take_down_the_poll(self):
        """status.json still written, the summary still returned. The
        control: status.json is proved absent before, so its presence after
        is this poll's doing."""
        cfg = self.fleet()
        status_path = self.state / "status.json"
        self.assertFalse(status_path.exists())

        with mock.patch.object(roster, "publish", side_effect=PermissionError("ro")), \
             self.assertLogs("amap_router_local", level="ERROR"):
            summary = service.poll_once(cfg, StatusTracker(interval_s=5.0))

        self.assertIsInstance(summary, dict)
        self.assertTrue(status_path.is_file())


class AtomicWriteOptionsTests(unittest.TestCase):
    """The two keyword-only options `roster` needed from `util.atomic_write`.
    Tested at the primitive as well as through the roster, because `util`
    has an out-of-package dependent and its defaults must not move."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_default_still_creates_parents(self):
        """Every existing caller relies on this; the new option must not
        have moved the default."""
        target = self.root / "a" / "b" / "f.json"
        atomic_write(target, b"x")
        self.assertEqual(target.read_bytes(), b"x")

    def test_make_parents_false_raises_and_creates_nothing(self):
        target = self.root / "absent" / "f.json"
        with self.assertRaises(FileNotFoundError):
            atomic_write(target, b"x", make_parents=False)
        self.assertFalse((self.root / "absent").exists())

    def test_default_mode_is_still_private(self):
        """status.json and the ledgers rely on 0600; `mode` must be opt-in."""
        target = self.root / "f.json"
        atomic_write(target, b"x")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_mode_is_applied(self):
        target = self.root / "f.json"
        atomic_write(target, b"x", mode=0o644)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
