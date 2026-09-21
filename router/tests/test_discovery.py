"""Discovery (item 2): the instance set is found, not authored.

`instances_dir` replaces `instances`. The directories under it are
CANDIDATES; the host's `selected.json` verdict is what ADMITS them. Both
halves are required — a directory with no verdict is not an instance, and a
verdict with no directory is broken state.

ADMISSION IS NOT VALIDATION, and that is the whole difference from an
authored `instances` object. An authored config is checked all-or-nothing: a
contradiction is the author's to fix, and refusing is safe because nothing is
running. A discovered set is supplied by the filesystem, so ONE BAD
DIRECTORY MUST NOT STOP A RUNNING FLEET. Every rejection here is a skip plus
a report entry, never an exception.

Which makes `DiscoveryReport` load-bearing rather than decorative: it is the
only place a skipped instance exists at all. A silent skip and a clean fleet
are indistinguishable from outside.
"""

import json
import tempfile
import os
import shutil
import unittest
from pathlib import Path

from router.config import LANES, ConfigError, load_obj

_REPO = Path(__file__).absolute().parents[2]


class _Tree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.feat = self.root / "features" / "amap"
        self.inst = self.feat / "instances"
        self.state = self.root / "state"
        self.inst.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def dir_for(self, slug):
        for lane in LANES:
            (self.inst / slug / lane).mkdir(parents=True, exist_ok=True)

    def verdict(self, selected=(), not_selected=(), raw=None):
        p = self.feat / "selected.json"
        if raw is not None:
            p.write_text(raw)
            return p
        p.write_text(json.dumps({
            "schema": 1, "note": "…",
            "selected": [{"slug": s, "at": "2026-09-18T20:00:00Z"} for s in selected],
            "not_selected": [{"slug": s, "why": "no agents include matched",
                              "at": "2026-09-18T20:00:00Z"} for s in not_selected],
        }))
        return p

    def load(self, **top):
        return load_obj({"state_dir": str(self.state),
                         "instances_dir": str(self.inst),
                         "selected_json": str(self.feat / "selected.json"),
                         **top})


class AdmissionTests(_Tree):
    def test_a_directory_with_a_verdict_is_an_instance(self):
        self.dir_for("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef"])
        self.assertTrue(cfg.discovery.is_clean())

    def test_a_directory_with_no_verdict_is_reported_never_drained(self):
        """Every workspace rename produces one. NEVER deleted — a directory
        this router did not create is not its to remove — and never drained,
        because the host has not said it is a member."""
        self.dir_for("alice-deadbeef")
        self.dir_for("orphan-0badcafe")
        self.verdict(selected=["alice-deadbeef"])
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef"])
        self.assertEqual(cfg.discovery.no_verdict, ("orphan-0badcafe",))
        self.assertTrue((self.inst / "orphan-0badcafe").is_dir(),
                        "the directory must still be there — never deleted")

    def test_a_verdict_with_no_directory_is_reported_not_tolerated(self):
        """A verdict exists only after a launch and the launch creates the
        directory, so this cannot happen in normal operation. Which is
        exactly why it is REPORTED: a tolerated impossibility removes the
        report that would have found the bug."""
        self.dir_for("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef", "ghost-1a2b3c4d"])
        cfg = self.load()
        self.assertEqual(cfg.discovery.verdict_without_directory, ("ghost-1a2b3c4d",))

    def test_an_explicitly_not_selected_directory_is_not_admitted(self):
        self.dir_for("denied-c0ffee01")
        self.verdict(selected=[], not_selected=["denied-c0ffee01"])
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), [])


class VerdictUnavailableTests(_Tree):
    def test_a_missing_verdict_admits_NOBODY_and_says_so(self):
        """ABSENT IS NOT AN EMPTY VERDICT. Absent means the host has not
        answered; empty means it answered and selected nobody. Collapsing
        them would turn a missing file into a full fleet."""
        self.dir_for("alice-deadbeef")
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), [])
        self.assertTrue(cfg.discovery.verdict_unavailable)

    def test_a_corrupt_verdict_is_unavailable_not_empty(self):
        self.dir_for("alice-deadbeef")
        self.verdict(raw="{not json at all")
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), [])
        self.assertTrue(cfg.discovery.verdict_unavailable)

    def test_an_empty_verdict_is_available_and_admits_nobody(self):
        """The control that gives the two above their meaning: an answered
        'nobody' is reported differently from an unanswered one."""
        self.dir_for("alice-deadbeef")
        self.verdict(selected=[])
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), [])
        self.assertFalse(cfg.discovery.verdict_unavailable)


class SkipNeverRaiseTests(_Tree):
    def test_a_bad_name_is_skipped_and_the_fleet_still_loads(self):
        self.dir_for("has space-1a2b3c4d")
        self.dir_for("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef", "has space-1a2b3c4d"])
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef"])
        self.assertIn("has space-1a2b3c4d", cfg.discovery.skipped)

    def test_the_routers_own_local_part_is_skipped(self):
        self.dir_for("amap.router")
        self.dir_for("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef", "amap.router"])
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef"])
        self.assertIn("amap.router", cfg.discovery.skipped)

    def test_a_symlinked_directory_is_not_an_instance(self):
        """`is_dir(follow_symlinks=False)`. A symlink pointing out of the tree
        is not an instance root, and following it would hand the rest of the
        loader a path outside everything `state_dir` containment was checked
        against."""
        self.dir_for("alice-deadbeef")
        outside = self.root / "outside"
        outside.mkdir()
        (self.inst / "sneaky-deadbeef").symlink_to(outside)
        self.verdict(selected=["alice-deadbeef", "sneaky-deadbeef"])
        cfg = self.load()
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef"])


def _filesystem_is_case_insensitive() -> bool:
    """PROBED, never inferred from the platform name.

    `sys.platform == "darwin"` would be the obvious test and it is wrong in
    both directions: APFS can be formatted case-SENSITIVE, and a
    case-insensitive volume can be mounted under Linux. The question is a
    property of the filesystem this test's temp dir lands on, so it is asked
    of that directory.
    """
    d = tempfile.mkdtemp()
    try:
        os.mkdir(os.path.join(d, "A"))
        return os.path.isdir(os.path.join(d, "a"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


@unittest.skipIf(_filesystem_is_case_insensitive(),
                 "casefold incumbency needs a case-sensitive filesystem: the "
                 "two instance directories collide into one here, so there is "
                 "no loser to skip and no incumbency to decide")
class CasefoldIncumbencyTests(_Tree):
    """THE INCUMBENT KEEPS THE LEDGER — and the incumbent is the one with
    router-private state, not the one that sorts first.

    An authored config refuses the whole document for a casefold collision.
    A discovered set must not: one `mkdir` would take down a running fleet.

    SKIPPED, NOT FAILED, ON A CASE-INSENSITIVE FILESYSTEM — and the
    distinction is the same one this fleet spent a week establishing between
    `unrunnable` and a check that ran and returned the bad answer.

    This class builds `alice-deadbeef` and `Alice-deadbeef` as two
    directories. On APFS the second `mkdir` collides with the first, ONE
    directory exists, and the assertions fail with
    `'Alice-deadbeef' not found in {'alice-deadbeef': ...}` — which reads as
    "the router dropped the instance holding router-private state". That is a
    substantive claim about the router and it is FALSE: the instance was never
    created. A test that cannot run must say so in its own words rather than
    impersonate a failure of the thing it was checking.

    Found by the fleet's release script running this suite on the operator's
    macOS host. It had passed on every Linux sandbox for the whole of its
    life, including in a control run performed specifically to decide whether
    the failure was environmental — an experiment run on the wrong side of the
    only variable that mattered, and therefore one that could not falsify.

    DO NOT WEAKEN THE ASSERTIONS TO MAKE THIS PASS ON macOS. The defect they
    pin — `sorted()[0]` choosing the alphabetical winner rather than the one
    holding state — is real, and a case-sensitive host must keep testing it.
    """

    def _both(self, incumbent=None):
        self.dir_for("alice-deadbeef")
        self.dir_for("Alice-deadbeef")
        if incumbent:
            (self.state / incumbent).mkdir(parents=True, exist_ok=True)
        self.verdict(selected=["alice-deadbeef", "Alice-deadbeef"])
        return self.load()

    def test_the_one_holding_state_wins_whichever_way_it_sorts(self):
        """The defect this pins: the first implementation took `sorted()[0]`,
        which is deterministic and WRONG — it made the winner depend on
        CAPITALISATION, so an incumbent whose name sorts second was dropped
        and its ledger stranded. Both directions are asserted because only
        one of them fails under that bug."""
        for incumbent in ("alice-deadbeef", "Alice-deadbeef"):
            with self.subTest(incumbent=incumbent):
                # A fresh tree per case, torn down properly — re-calling
                # setUp() would leak the previous TemporaryDirectory.
                self.tearDown()
                self.setUp()
                cfg = self._both(incumbent)
                self.assertIn(incumbent, cfg.instances,
                              "the instance holding router-private state was dropped")
                self.assertEqual(len(cfg.instances), 1)

    def test_the_loser_is_skipped_with_a_reason_naming_the_winner(self):
        cfg = self._both("alice-deadbeef")
        self.assertIn("Alice-deadbeef", cfg.discovery.skipped)
        self.assertIn("alice-deadbeef", cfg.discovery.skipped["Alice-deadbeef"])

    def test_with_no_incumbent_exactly_one_is_admitted(self):
        """Neither has state, so either may win — but never both, because
        both would share one `state_dir` entry."""
        cfg = self._both(None)
        self.assertEqual(len(cfg.instances), 1)


class SourceExclusivityTests(_Tree):
    def test_authored_and_discovered_together_is_refused(self):
        """This one IS a refusal, not a skip: it is a contradiction in the
        AUTHORED document, which is the operator's to fix."""
        with self.assertRaises(ConfigError) as ctx:
            load_obj({"state_dir": str(self.state),
                      "instances_dir": str(self.inst),
                      "selected_json": str(self.feat / "selected.json"),
                      "instances": {"a-deadbeef": {"handoff_dir": "/tmp/x"}}})
        self.assertIn("never both", str(ctx.exception))

    def test_instances_dir_without_a_verdict_path_is_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({"state_dir": str(self.state), "instances_dir": str(self.inst)})
        self.assertIn("selected_json", str(ctx.exception))

    def test_neither_source_is_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({"state_dir": str(self.state)})
        self.assertIn("instances_dir", str(ctx.exception))

    def test_state_dir_inside_the_discovered_tree_is_refused(self):
        """`state_dir` is router-private and must stay unreachable from the
        tree the host writes."""
        with self.assertRaises(ConfigError) as ctx:
            load_obj({"state_dir": str(self.inst / "state"),
                      "instances_dir": str(self.inst),
                      "selected_json": str(self.feat / "selected.json")})
        self.assertIn("state_dir", str(ctx.exception))


class EmptyFleetTests(_Tree):
    def test_an_empty_discovered_fleet_loads(self):
        """NOT an error. A fleet whose sandboxes have not launched is a fleet
        with nothing to drain, and refusing would take down a router that is
        correctly idle. An authored `instances: {}` IS refused — there the
        emptiness is a document someone wrote."""
        self.verdict(selected=[])
        cfg = self.load()
        self.assertEqual(cfg.instances, {})

    def test_an_empty_authored_instances_object_is_still_refused(self):
        with self.assertRaises(ConfigError):
            load_obj({"state_dir": str(self.state), "instances": {}})


class PolicyStillAppliesTests(_Tree):
    def test_the_wildcards_expand_over_the_DISCOVERED_set(self):
        """The whole point of a word rather than a rendered map: a map is
        expanded by whoever wrote it, over the instances they knew about. The
        word is expanded here, over the instances that actually exist."""
        for slug in ("alice-deadbeef", "bob-c0ffee01"):
            self.dir_for(slug)
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])
        cfg = self.load(fleet_domain="example.invalid", task_graph="all")
        self.assertEqual(sorted(cfg.instances["alice-deadbeef"].peer_senders),
                         ["bob-c0ffee01"])

    def test_an_unadmitted_directory_is_not_in_the_mesh(self):
        """The control: expansion follows ADMISSION, not the directory
        listing. Without this, a wildcard could grant edges to a slug the
        host never selected."""
        for slug in ("alice-deadbeef", "bob-c0ffee01", "orphan-0badcafe"):
            self.dir_for(slug)
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])
        cfg = self.load(fleet_domain="example.invalid", task_graph="all")
        for inst in cfg.instances.values():
            self.assertNotIn("orphan-0badcafe", inst.peer_senders)


if __name__ == "__main__":
    unittest.main()


class ExplicitGraphMapTests(_Tree):
    """Item 3: the top-level `peer_senders` / `peers` maps.

    They are TOP-LEVEL because under discovery there is no per-instance config
    section — instances are directories. The per-instance spelling is
    unchanged for an authored config; these are the same fields addressed
    from the other end.
    """

    def _fleet(self, **top):
        for slug in ("alice-deadbeef", "bob-c0ffee01"):
            self.dir_for(slug)
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"],
                     not_selected=["later-1a2b3c4d"])
        return self.load(**top)

    def test_a_map_declares_the_edges(self):
        cfg = self._fleet(fleet_domain="example.invalid",
                          peer_senders={"bob-c0ffee01": ["alice-deadbeef"]})
        self.assertEqual(sorted(cfg.instances["bob-c0ffee01"].peer_senders),
                         ["alice-deadbeef"])
        self.assertEqual(sorted(cfg.instances["alice-deadbeef"].peer_senders), [])

    def test_a_mail_map_declares_mutual_pairs(self):
        cfg = self._fleet(peers={"alice-deadbeef": ["bob-c0ffee01"],
                                 "bob-c0ffee01": ["alice-deadbeef"]})
        from router.binding import check_cold
        self.assertTrue(check_cold(cfg, "alice-deadbeef", "bob-c0ffee01"))

    def test_a_map_beside_its_wildcard_is_refused(self):
        """NAMES THE GUARD. Two refusals in `_graph_map` both end "one or the
        other, never both" — the wildcard-exclusivity one and the
        top-level-versus-per-instance one — and with a non-empty fleet the
        second fires anyway, because the wildcard has already expanded into
        the per-instance sets. An assertion on the shared suffix passed with
        the first guard deleted. Found by mutation; it is the same
        two-satisfier defect this repo keeps finding, in a test written an
        hour after writing that sentence down."""
        with self.assertRaises(ConfigError) as ctx:
            self._fleet(fleet_domain="example.invalid", task_graph="all",
                        peer_senders={"bob-c0ffee01": ["alice-deadbeef"]})
        self.assertIn("config.task_graph", str(ctx.exception),
                      "refused by the wrong guard — the wildcard-exclusivity "
                      "check is what should reject this")

    def test_a_map_beside_its_wildcard_on_an_EMPTY_fleet_is_still_refused(self):
        """The case the wildcard-exclusivity guard uniquely catches, and the
        reason it is not redundant. With no instances the wildcard expands to
        nothing, so the per-instance guard sees nothing declared and cannot
        fire — only the direct check remains."""
        self.verdict(selected=[])
        with self.assertRaises(ConfigError) as ctx:
            self.load(fleet_domain="example.invalid", task_graph="all",
                      peer_senders={"bob-c0ffee01": ["alice-deadbeef"]})
        self.assertIn("config.task_graph", str(ctx.exception))


class InertEndpointTests(_Tree):
    """An endpoint this router has not admitted is INERT, never a refusal —
    and never silent.

    Inert adds no risk because it is already the behaviour: a message is only
    drained from an ADMITTED outbox and a recipient only resolves against the
    ADMITTED set, so such an edge cannot be exercised. What it COSTS is the
    typo guard an authored config has, which is why the report exists.
    """

    def _fleet(self, **top):
        for slug in ("alice-deadbeef", "bob-c0ffee01"):
            self.dir_for(slug)
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"],
                     not_selected=["later-1a2b3c4d"])
        return self.load(fleet_domain="example.invalid", **top)

    def test_an_unknown_endpoint_does_not_refuse_the_load(self):
        """One un-launched sandbox in a fleet-wide map must not make the whole
        fleet unloadable — the map is rendered before anything launches."""
        cfg = self._fleet(peer_senders={"later-1a2b3c4d": ["alice-deadbeef"]})
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef", "bob-c0ffee01"])

    def test_a_slug_the_host_knows_reads_as_PENDING(self):
        cfg = self._fleet(peer_senders={"later-1a2b3c4d": ["alice-deadbeef"]})
        self.assertIn("pending", cfg.discovery.inert_edges["later-1a2b3c4d"])

    def test_a_slug_the_host_has_NEVER_issued_a_verdict_for_reads_as_TYPO(self):
        """The tier that earns the report. A slug in neither of the host's
        lists is a name nobody has ever used — as close to "this is a typo"
        as a machine can honestly get, and it recovers most of what the
        load-time refusal did, at report time."""
        cfg = self._fleet(peer_senders={"typoo-0badcafe": ["alice-deadbeef"]})
        self.assertIn("typo", cfg.discovery.inert_edges["typoo-0badcafe"])

    def test_the_two_tiers_are_distinguishable(self):
        """The control. Without it, a reason string that said the same thing
        for both would satisfy each test above on its own."""
        cfg = self._fleet(peer_senders={"later-1a2b3c4d": ["alice-deadbeef"],
                                        "typoo-0badcafe": ["alice-deadbeef"]})
        self.assertNotEqual(cfg.discovery.inert_edges["later-1a2b3c4d"],
                            cfg.discovery.inert_edges["typoo-0badcafe"])

    def test_an_inert_endpoint_grants_nothing(self):
        """Inert means inert: the edge is not merely unreported, it is not
        there. `check_peer_edge` must not find it by any route."""
        from router.binding import check_peer_edge
        cfg = self._fleet(peer_senders={"bob-c0ffee01": ["typoo-0badcafe"]})
        self.assertEqual(sorted(cfg.instances["bob-c0ffee01"].peer_senders), [])
        self.assertFalse(check_peer_edge(cfg, "typoo-0badcafe", "bob-c0ffee01"))

    def test_an_authored_config_still_REFUSES_an_unknown_endpoint(self):
        """The rule is scoped to discovery and must not leak. An authored
        document naming an unknown instance is a typo its author can fix, and
        refusing is safe because nothing is running."""
        with self.assertRaises(ConfigError):
            load_obj({"state_dir": str(self.state), "fleet_domain": "example.invalid",
                      "instances": {"a-deadbeef": {"handoff_dir": "/tmp/a",
                                                   "peer_senders": ["ghost-1a2b3c4d"]}}})

    def test_a_top_level_map_on_an_authored_config_is_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            load_obj({"state_dir": str(self.state),
                      "instances": {"a-deadbeef": {"handoff_dir": "/tmp/a"}},
                      "peers": {"a-deadbeef": []}})
        self.assertIn("discovered fleet", str(ctx.exception))


class ProvisionCreatesNothingTests(_Tree):
    """Item 4: under discovery the host owns the whole instance tree.

    `provision` keeps its OTHER job — printing the four connector env vars —
    because nothing else answers "what do I wire into this sandbox". Only
    creation retires, and only inside the instance root.
    """

    LEAVES = {"inbox": ("notices", "messages"),
              "peer": ("notices", "messages"),
              "outbox": ("results", "processed")}

    def _fleet(self, lanes=LANES, full=False):
        slug = "alice-deadbeef"
        for lane in lanes:
            (self.inst / slug / lane).mkdir(parents=True, exist_ok=True)
            if full:
                for leaf in self.LEAVES[lane]:
                    (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        (self.inst / slug).mkdir(parents=True, exist_ok=True)
        self.verdict(selected=[slug])
        return self.load(fleet_domain="example.invalid"), slug

    def test_it_creates_nothing_inside_the_instance_root(self):
        from router.provision import provision
        cfg, slug = self._fleet(full=True)
        before = sorted(p.relative_to(self.inst).as_posix()
                        for p in (self.inst / slug).rglob("*"))
        provision(cfg, slug, create=True)
        after = sorted(p.relative_to(self.inst).as_posix()
                       for p in (self.inst / slug).rglob("*"))
        self.assertEqual(before, after,
                         "provision created something the host owns")

    def test_a_lane_present_but_EMPTY_is_still_refused(self):
        """THE CASE A LANE-ONLY CHECK PASSES, and it is the one that happened
        on a real host. A 2.0 sandbox reset PRESERVED the relay shim and
        DESTROYED the tree, so the daemon started before the leaves existed
        and refused with "mail notice dir ... is not a directory", exit 2,
        failing the launch. The lane directories were there; `notices/` and
        `messages/` were not.

        So the check is to the LEAF. Everything the daemon opens is a leaf."""
        from router.provision import ProvisionError, provision
        cfg, slug = self._fleet()          # all three lanes, no leaves
        with self.assertRaises(ProvisionError) as ctx:
            provision(cfg, slug, create=True)
        msg = str(ctx.exception)
        for leaf in ("inbox/notices", "inbox/messages",
                     "peer/notices", "peer/messages",
                     "outbox/results", "outbox/processed"):
            with self.subTest(leaf=leaf):
                self.assertIn(leaf, msg,
                              "every missing leaf must be named — the fix is "
                              "one edit to the manifest, not six")

    def test_a_fully_created_tree_provisions_cleanly(self):
        """The control. Without it, a check that refused unconditionally
        would pass every test above."""
        from router.provision import provision
        cfg, slug = self._fleet(full=True)
        env = provision(cfg, slug, create=True)
        self.assertEqual(env["MAILBOX_AGENT_ID"], slug)

    def test_a_missing_lane_is_refused_and_names_every_one(self):
        """THE RULE DID NOT GET AN EXCEPTION — THE EXCEPTION LOST ITS REASON.
        `peer/` was router-owned because it was "not a sandy mount source".
        Under a manifest the host declares `peer` as a mount and creates it,
        so creating it here would yield a directory that is not mounted into
        the container: this router would write peer notices no agent can
        ever see, and the wiring would look perfect."""
        from router.provision import ProvisionError, provision
        cfg, slug = self._fleet(lanes=("inbox",))
        with self.assertRaises(ProvisionError) as ctx:
            provision(cfg, slug, create=True)
        msg = str(ctx.exception)
        self.assertIn("peer", msg)
        self.assertIn("outbox", msg)
        self.assertNotIn("/inbox'", msg, "inbox exists and must not be named")

    def test_the_env_var_printout_still_works(self):
        """The half that does NOT retire: something still has to answer
        'what do I wire into this sandbox'."""
        from router.provision import provision
        cfg, slug = self._fleet(full=True)
        env = provision(cfg, slug, create=False)
        self.assertEqual(env["MAILBOX_AGENT_ID"], slug)
        self.assertTrue(env["INBOX_NOTICE_DIR"].endswith("/inbox/notices"))

    def test_an_authored_handoff_config_still_creates_its_skeleton(self):
        """The rule is scoped to discovery and must not leak: an authored
        fleet still gets its leaves and its router-owned `peer/`."""
        from router.provision import provision
        root = self.root / "authored" / "alice-deadbeef"
        (root / "inbox").mkdir(parents=True)
        (root / "outbox").mkdir(parents=True)
        cfg = load_obj({"state_dir": str(self.state), "fleet_domain": "example.invalid",
                        "instances": {"alice-deadbeef": {"handoff_dir": str(root)}}})
        provision(cfg, "alice-deadbeef", create=True)
        self.assertTrue((root / "inbox" / "notices").is_dir())
        self.assertTrue((root / "peer" / "notices").is_dir(),
                        "peer/ is still router-owned for an authored fleet")


class LaneLeafConstantsTests(unittest.TestCase):
    """`config.LANE_LEAVES` is the SINGLE SOURCE for the lane skeleton.

    A host adapter renders its manifest's `create` block from it, `provision`
    builds its skeleton from it, and discovery's presence check requires it.
    Three readers, one list — the alternative is three lists that agree until
    one of them changes.
    """

    def test_provisions_skeleton_is_derived_not_re_listed(self):
        """Pins the derivation rather than the values, because pinning the
        values here would BE the second list this exists to prevent."""
        from router.config import (LANE_INBOX, LANE_LEAVES, LANE_OUTBOX,
                                   LANE_PEER)
        from router.provision import (_INBOX_SKELETON_LEAVES,
                                      _OUTBOX_SKELETON_LEAVES,
                                      _PEER_SKELETON_LEAVES)
        self.assertEqual([p.as_posix() for p in _INBOX_SKELETON_LEAVES],
                         list(LANE_LEAVES[LANE_INBOX]))
        self.assertEqual([p.as_posix() for p in _PEER_SKELETON_LEAVES],
                         list(LANE_LEAVES[LANE_PEER]))
        # The outbox carries one extra entry, the lane ROOT, created here
        # because under `namespace` mode nothing else makes it.
        self.assertEqual([p.as_posix() for p in _OUTBOX_SKELETON_LEAVES],
                         ["."] + list(LANE_LEAVES[LANE_OUTBOX]))

    def test_the_exported_constant_carries_no_lane_root(self):
        """`"."` is a creation detail of `provision`, not a leaf. An adapter
        rendering a `create` block from this would otherwise emit
        `instances/<slug>/outbox/.`, and the lane root is implied anyway —
        creating `<lane>/<leaf>` creates `<lane>`."""
        from router.config import LANE_LEAVES
        for lane, leaves in LANE_LEAVES.items():
            with self.subTest(lane=lane):
                self.assertNotIn(".", leaves)
                self.assertNotIn("", leaves)

    def test_every_lane_has_leaves_declared(self):
        from router.config import LANE_LEAVES, LANES
        self.assertEqual(sorted(LANE_LEAVES), sorted(LANES))

    def test_discovery_requires_exactly_those_leaves(self):
        """The third reader. If `LANE_LEAVES` grew an entry, the presence
        check must require it too — otherwise the adapter creates something
        this router never verifies."""
        from router.config import LANE_LEAVES
        import inspect
        from router import provision as prov
        src = inspect.getsource(prov.provision)
        self.assertIn("_INBOX_SKELETON_LEAVES", src)
        self.assertIn("_OUTBOX_SKELETON_LEAVES", src)
        self.assertIn("_PEER_SKELETON_LEAVES", src)


class DiscoveryIsRenderedTests(_Tree):
    """The report is the whole point of admission-not-validation, and a report
    nothing prints is a silence with extra steps.

    Every assertion here exists because the alternative was an instance that
    was skipped, an orphan that was found, or an edge that was dropped — and
    no way for an operator to know.
    """

    def _messy(self):
        from router.config import LANE_LEAVES
        for slug in ("alice-deadbeef", "bob-c0ffee01", "orphan-0badcafe"):
            for lane in LANES:
                for leaf in LANE_LEAVES[lane]:
                    (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        (self.inst / "has space-1a2b3c4d").mkdir()
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01", "ghost-c0ffee01"],
                     not_selected=["later-1a2b3c4d"])
        return self.load(fleet_domain="example.invalid",
                         peer_senders={"bob-c0ffee01": ["alice-deadbeef"],
                                       "later-1a2b3c4d": ["alice-deadbeef"],
                                       "typoo-0badcafe": ["alice-deadbeef"]})

    def test_a_clean_fleet_prints_nothing(self):
        """No news is no lines. A header that always appeared would make the
        messy case look like the normal one."""
        from router.status import render_discovery
        for slug in ("alice-deadbeef",):
            self.dir_for(slug)
        self.verdict(selected=["alice-deadbeef"])
        cfg = self.load()
        self.assertTrue(cfg.discovery.is_clean())
        self.assertEqual(render_discovery(cfg.discovery), [])

    def test_an_authored_config_has_no_report_at_all(self):
        from router.status import render_discovery
        cfg = load_obj({"state_dir": str(self.state),
                        "instances": {"a-deadbeef": {"handoff_dir": "/tmp/a"}}})
        self.assertIsNone(cfg.discovery)
        self.assertEqual(render_discovery(None), [])

    def test_every_finding_reaches_the_output(self):
        """Each of the five kinds, by the slug it concerns. A report that
        computed a finding and dropped it on the floor is the exact failure
        the report exists to prevent."""
        from router.status import render_discovery
        out = "\n".join(render_discovery(self._messy().discovery))
        for slug, kind in (("has space-1a2b3c4d", "SKIPPED"),
                           ("orphan-0badcafe", "NO VERDICT"),
                           ("ghost-c0ffee01", "NO DIRECTORY"),
                           ("later-1a2b3c4d", "INERT EDGE"),
                           ("typoo-0badcafe", "INERT EDGE")):
            with self.subTest(slug=slug):
                self.assertIn(slug, out)
                self.assertIn(kind, out)

    def test_the_two_inert_tiers_are_visibly_different(self):
        """Both are INERT EDGE lines. The probable-typo one is marked loud and
        the pending one is not — otherwise the tier distinction exists in the
        data and dies in the rendering."""
        from router.status import render_discovery
        lines = render_discovery(self._messy().discovery)
        pending = next(l for l in lines if "later-1a2b3c4d" in l)
        typo = next(l for l in lines if "typoo-0badcafe" in l)
        self.assertIn("**", typo)
        self.assertNotIn("**", pending)

    def test_an_unavailable_verdict_says_it_is_UNANSWERED(self):
        """The distinction that decides whether an operator looks at the host
        or at the policy: absent is not 'nobody selected'."""
        from router.status import render_discovery
        self.dir_for("alice-deadbeef")
        out = "\n".join(render_discovery(self.load().discovery))
        self.assertIn("VERDICT UNAVAILABLE", out)
        self.assertIn("has not answered", out)


class DiscoveryOutputIsWireTests(_Tree):
    """The heading and the loud marker are WIRE, pinned by name here.

    A host adapter's bringup greps this output: any `** `-wrapped line under
    `discovery:` is a FAIL whose remedy names the line, plain lines are
    warnings, and the heading's ABSENCE is how it recognises an authored
    config. It asked for both to be treated as names this repo has chosen
    rather than prose it may reword.

    The reason is precise and it is the reason this class exists: a
    COSMETIC RENAME HERE TURNS THEIR CHECK INTO A DEAD GREEN. A heading
    changed to "discovered:" makes every `** ` line invisible to a grep
    anchored on the old one, their FAIL stops firing, and nothing anywhere
    reports that the check stopped working. The test that would have caught
    it is this one.
    """

    HEADING = "discovery:"
    LOUD = "** "

    def _messy(self):
        from router.config import LANE_LEAVES
        for lane in LANES:
            for leaf in LANE_LEAVES[lane]:
                (self.inst / "alice-deadbeef" / lane / leaf).mkdir(parents=True, exist_ok=True)
        (self.inst / "has space-1a2b3c4d").mkdir()
        self.verdict(selected=["alice-deadbeef", "ghost-c0ffee01"])
        return self.load()

    def test_the_heading_is_exactly_this_string(self):
        from router.status import render_discovery
        lines = render_discovery(self._messy().discovery)
        self.assertEqual(lines[0], self.HEADING,
                         "the heading is wire — a rename breaks an external "
                         "grep silently")

    def test_the_loud_marker_is_exactly_this_string(self):
        """`** ` opens every line that needs a human. Changing the marker
        would leave the lines present and the severity unreadable."""
        from router.status import render_discovery
        loud = [l for l in render_discovery(self._messy().discovery)
                if "NO DIRECTORY" in l]
        self.assertTrue(loud)
        self.assertIn(self.LOUD, loud[0])

    def test_plain_lines_carry_no_loud_marker(self):
        """The half that makes the marker mean something. If every line were
        loud, the consumer's FAIL/warning split would classify everything as
        a failure — including a renamed workspace, which is routine."""
        from router.status import render_discovery
        plain = [l for l in render_discovery(self._messy().discovery)
                 if "SKIPPED" in l]
        self.assertTrue(plain)
        self.assertNotIn("**", plain[0])

    def test_the_heading_is_ABSENT_for_an_authored_config(self):
        """Their bringup distinguishes layouts by this absence, so an empty
        report must print nothing at all rather than an empty heading."""
        from router.status import render_discovery
        cfg = load_obj({"state_dir": str(self.state),
                        "instances": {"a-deadbeef": {"handoff_dir": "/tmp/a"}}})
        self.assertEqual(render_discovery(cfg.discovery), [])


class ReplyBindingSurvivesARootChangeTests(_Tree):
    """A reply binds by `state_dir` + instance NAME + notice id — NO ROOT.

    WHY THIS IS PINNED RATHER THAN LEFT TRUE. A host adapter's flag-day
    migration moves every instance from one root to another in a single act,
    carrying the spooled bodies and the unconsumed notices with them, and it
    RELIES on a reply to a notice placed under the OLD root resolving after
    the switch. That property holds by construction today —
    `read_ledger_record(state_dir, sender_instance, in_reply_to)` takes no
    root — and by construction is exactly the kind of thing that stops being
    true when someone adds a root component for a good local reason.

    Nothing would report it. The reply would fail closed as
    `unresolved_reply`, which is a correct-looking refusal, on the one day a
    fleet is mid-migration and everything is suspect anyway.
    """

    def _fleet_at(self, base):
        """A two-instance fleet rooted under `base`, sharing this test's
        `state_dir` — the migration's only two constants."""
        from router.config import LANE_LEAVES
        for slug in ("alice-deadbeef", "bob-c0ffee01"):
            for lane in LANES:
                for leaf in LANE_LEAVES[lane]:
                    (base / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        sel = base.parent / "selected.json"
        sel.write_text(json.dumps({
            "schema": 1,
            "selected": [{"slug": s, "at": "2026-09-18T20:00:00Z"}
                         for s in ("alice-deadbeef", "bob-c0ffee01")],
            "not_selected": []}))
        return load_obj({"state_dir": str(self.state),
                         "instances_dir": str(base),
                         "selected_json": str(sel),
                         "fleet_domain": "example.invalid",
                         "task_graph": "all"})

    def test_a_reply_resolves_after_every_root_has_changed(self):
        from router import outbound
        from router.binding import read_ledger_record

        # OLD roots: alice delegates to bob; the notice is placed and ledgered.
        old = self.root / "old" / "instances"
        cfg_old = self._fleet_at(old)
        # First sight BEFORE staging anything — a request written before the
        # first poll is in the snapshot and is quarantined, which is the
        # feature working and was this fixture's first bug.
        outbound.drain_instance(cfg_old, "alice-deadbeef")
        (cfg_old.instances["alice-deadbeef"].outbox_root / "req-00000001.json").write_text(
            json.dumps({"contract_version": "2", "req_id": "00000001",
                        "draft": {"to": ["bob-c0ffee01@example.invalid"],
                                  "subject": "s", "body_text": "b"}}))
        outbound.drain_instance(cfg_old, "alice-deadbeef")
        placed = sorted((cfg_old.instances["bob-c0ffee01"].peer_root / "notices").iterdir())
        self.assertEqual(len(placed), 1, "the delegation was not placed")
        # `notice-<id>.json`. NOT `peer-<id>.json`, which is the OUTCOME
        # file's name — the first version of this test assumed the latter and
        # silently extracted a mangled id, so the lookup failed for a reason
        # that had nothing to do with roots.
        self.assertTrue(placed[0].name.startswith("notice-"))
        notice_id = placed[0].stem.split("-", 1)[1]

        # THE FLAG DAY: every root moves. Same state_dir, same slugs.
        new = self.root / "new" / "instances"
        cfg_new = self._fleet_at(new)
        self.assertNotEqual(cfg_old.instances["bob-c0ffee01"].root,
                            cfg_new.instances["bob-c0ffee01"].root)

        # The ledger still resolves the notice placed under the OLD root.
        record = read_ledger_record(self.state, "bob-c0ffee01", notice_id)
        self.assertIsNotNone(record, "the reply key stopped resolving across "
                                     "the root change — a migration relies on this")
        self.assertEqual(record.get("from_instance"), "alice-deadbeef")

    def test_the_lookup_takes_no_root_argument(self):
        """The structural half. A signature that cannot see a root cannot
        depend on one, and this fails the moment someone adds a parameter —
        which is the change the test above would only catch by behaviour."""
        import inspect
        from router.binding import read_ledger_record
        params = list(inspect.signature(read_ledger_record).parameters)
        self.assertEqual(params, ["state_dir", "sender_instance", "in_reply_to"])


class PeersJsonAbsentIsNotEmptyTests(_Tree):
    """`peers --json` must not print a graph it cannot compute.

    FOUND BY A PEER'S WORKBENCH, as a red test today and a silent pass later.
    With no readable verdict nothing is admitted, so the renderer printed
    `{}` — which is ALSO exactly what a fleet whose verdict admits nobody
    prints. A consumer reading stdout and discarding stderr (which is every
    JSON consumer) could not tell "the host has not answered" from "nobody
    has a peer", and on the day a fleet legitimately rendered an empty graph
    the comparison would PASS while nothing was admitted and nothing drained.

    Absent-is-not-empty, on the wire, in the one place this repo publishes a
    machine-readable answer.
    """

    def _run(self, *args):
        import subprocess
        import sys
        cfg = self.root / "router.json"
        cfg.write_text(json.dumps({
            "state_dir": str(self.state), "instances_dir": str(self.inst),
            "selected_json": str(self.feat / "selected.json"),
            "fleet_domain": "example.invalid", "task_graph": "all"}))
        p = subprocess.run(
            [sys.executable, "-m", "router", "--config", str(cfg), *args],
            capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(_REPO),
                 "PYTHONDONTWRITEBYTECODE": "1"})
        return p.returncode, p.stdout.strip(), p.stderr

    def _fleet(self):
        from router.config import LANE_LEAVES
        for slug in ("alice-deadbeef", "bob-c0ffee01"):
            for lane in LANES:
                for leaf in LANE_LEAVES[lane]:
                    (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)

    def test_an_unavailable_verdict_prints_NO_graph_and_exits_nonzero(self):
        self._fleet()                       # no selected.json at all
        rc, out, err = self._run("peers", "--json")
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "", "printed a graph it could not compute")
        self.assertIn("UNKNOWN rather than", err)

    def test_a_verdict_admitting_NOBODY_prints_an_empty_graph_and_exits_zero(self):
        """The state that makes the one above necessary. These two printed
        the same bytes with the same exit code."""
        self._fleet()
        self.verdict(selected=[])
        rc, out, err = self._run("peers", "--json")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out), {})

    def test_a_populated_fleet_is_unaffected(self):
        """The shape is NOT wrapped. A `{graph, verdict}` object would have
        fixed this by changing what every existing consumer diffs element for
        element, to answer a question an exit code already answers."""
        self._fleet()
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])
        rc, out, err = self._run("peers", "--json")
        self.assertEqual(rc, 0, err)
        graph = json.loads(out)
        self.assertEqual(sorted(graph), ["alice-deadbeef@example.invalid",
                                         "bob-c0ffee01@example.invalid"])
        self.assertIsInstance(graph["alice-deadbeef@example.invalid"], list)

    def test_stdout_is_a_graph_or_stdout_is_NOTHING(self):
        """The contract in one line, and the reason it beats a wrapper: a
        consumer that ignores the exit code gets a parse error rather than a
        wrong answer."""
        self._fleet()
        rc, out, _ = self._run("peers", "--json")
        self.assertNotEqual(rc, 0)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(out)


class ConsoleExplainsAnEmptyFleetTests(_Tree):
    """The console is the surface most able to lie about this.

    With no readable verdict nothing is admitted, so every other section
    renders CORRECTLY and says nothing: an empty instance table, empty
    traffic, no excluded agents, no alerts. A healthy-looking page for a
    fleet with real sandboxes on disk that is delivering nothing.

    Found by generalising `peers --json`'s defect rather than by a test,
    because no test of a renderer catches a renderer that is right.
    """

    def _unavailable(self):
        from router.config import LANE_LEAVES
        for slug in ("alice-deadbeef", "bob-c0ffee01"):
            for lane in LANES:
                for leaf in LANE_LEAVES[lane]:
                    (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        return self.load(fleet_domain="example.invalid", task_graph="all")

    def test_an_unassemblable_fleet_says_so_on_the_page(self):
        from router import console
        cfg = self._unavailable()
        self.assertEqual(sorted(cfg.instances), [],
                         "fixture precondition: nothing admitted")
        html = console.render_html(cfg, source="router.json")
        self.assertIn("<h2>Discovery</h2>", html)
        self.assertIn("VERDICT UNAVAILABLE", html)

    def test_the_two_sandboxes_on_disk_are_named(self):
        """Not just 'something is wrong' — WHICH directories were seen and
        not admitted. An operator staring at an empty console needs the
        slugs, because those are what they will go and look at."""
        from router import console
        html = console.render_html(self._unavailable(), source="router.json")
        for slug in ("alice-deadbeef", "bob-c0ffee01"):
            with self.subTest(slug=slug):
                self.assertIn(slug, html)

    def test_a_clean_discovered_fleet_shows_no_section(self):
        """No news is no section. A "discovery: clean" banner on every page
        would make the page that matters look like every other page."""
        from router import console
        from router.config import LANE_LEAVES
        for lane in LANES:
            for leaf in LANE_LEAVES[lane]:
                (self.inst / "alice-deadbeef" / lane / leaf).mkdir(parents=True, exist_ok=True)
        self.verdict(selected=["alice-deadbeef"])
        cfg = self.load()
        self.assertTrue(cfg.discovery.is_clean())
        self.assertNotIn("<h2>Discovery</h2>",
                         console.render_html(cfg, source="router.json"))

    def test_an_AUTHORED_fleet_shows_no_section(self):
        """Absent, not empty. There is nothing to report because discovery
        did not happen, and a section saying "clean" would be a claim about
        a process that never ran."""
        from router import console
        cfg = load_obj({"state_dir": str(self.state),
                        "instances": {"a-deadbeef": {"handoff_dir": str(self.root / "a")}}})
        self.assertNotIn("<h2>Discovery</h2>",
                         console.render_html(cfg, source="router.json"))

    def test_the_loud_lines_are_marked_differently_from_the_warnings(self):
        """The `** ` distinction survives into HTML. A page that rendered
        every finding identically would lose the severity the report went to
        trouble to carry."""
        import re
        from router import console
        html = console.render_html(self._unavailable(), source="router.json")
        sec = html[html.index("<h2>Discovery</h2>"):]

        # Matched on the CLASS ATTRIBUTE ALONE, not on the cell's contents.
        # The previous form was `<td class="(\w+)">([^<]+)</td>`, which
        # required the cell to hold bare text — true when each row was one
        # rendered wire line, false the moment the section grouped by
        # condition and the cell gained `<b>` and a `<div class='note'>`.
        # It then matched NOTHING and failed both assertions, reporting a lost
        # severity distinction that had not moved. The severity is the claim;
        # the DOM shape is not.
        cells = re.findall(r'<td class="(\w+)">(.*?)</td>', sec, re.S)
        classes = {c for c, _ in cells}
        self.assertIn("bad", classes)
        self.assertIn("warn", classes)

        # And the PAIRING, which the old form could not see: the loud
        # condition must be in the loud cell. Both classes merely existing
        # somewhere on the page would pass with the severities swapped.
        loud_text = " ".join(body for cls, body in cells if cls == "bad")
        self.assertIn("VERDICT UNAVAILABLE", loud_text)


class ConfigIsReReadEveryPollTests(_Tree):
    """The reload, and why its absence was the whole project's defect.

    The instance set is DISCOVERED at load. Without a reload it is frozen for
    the process lifetime, so a sandbox launched after the router started is
    never drained until someone restarts it — which is EXACTLY the
    restart-per-enrolment defect discovery exists to remove, alive inside the
    feature built to remove it.

    It survived because every test drives `poll_once` directly with a config
    it built itself, and `run_forever` is the only caller that would have
    noticed. Found when a peer asked whether the POLICY was re-read; the
    answer turned out to be about more than the policy.
    """

    def _paths(self):
        cfgp = self.root / "router.json"
        base = {"state_dir": str(self.state), "instances_dir": str(self.inst),
                "selected_json": str(self.feat / "selected.json"),
                "fleet_domain": "example.invalid", "task_graph": "all"}
        return cfgp, base

    def _launch(self, slug):
        from router.config import LANE_LEAVES
        for lane in LANES:
            for leaf in LANE_LEAVES[lane]:
                (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)

    def test_a_sandbox_launched_after_start_is_picked_up(self):
        from router.config import load
        from router.service import reload_config
        cfgp, base = self._paths()
        cfgp.write_text(json.dumps(base))
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)
        self.assertEqual(sorted(cfg.instances), ["alice-deadbeef"])

        self._launch("bob-c0ffee01")                      # the host launches it
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])
        cfg = reload_config(cfgp, cfg)

        self.assertEqual(sorted(cfg.instances),
                         ["alice-deadbeef", "bob-c0ffee01"],
                         "a sandbox launched after start was not discovered — "
                         "this is restart-per-enrolment, which discovery exists "
                         "to remove")

    def test_a_broken_config_keeps_the_LAST_GOOD_one(self):
        """A config caught between a renderer's write and its rename must not
        take down a fleet that is draining correctly. Loud, not fatal."""
        from router.config import load
        from router.service import reload_config
        cfgp, base = self._paths()
        cfgp.write_text(json.dumps(base))
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)

        cfgp.write_text("{not json at all")
        with self.assertLogs("amap_router_local", level="ERROR") as logs:
            kept = reload_config(cfgp, cfg)
        self.assertIs(kept, cfg)
        self.assertIn("last good", "\n".join(logs.output))

    def test_an_unreadable_config_keeps_the_last_good_one(self):
        from router.config import load
        from router.service import reload_config
        cfgp, base = self._paths()
        cfgp.write_text(json.dumps(base))
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)
        cfgp.unlink()
        with self.assertLogs("amap_router_local", level="ERROR"):
            self.assertIs(reload_config(cfgp, cfg), cfg)

    def test_a_CHANGED_state_dir_is_refused_not_adopted(self):
        """This process holds that directory's drain lock, and its ledgers,
        markers and quarantine all live under it. Adopting a new one mid-run
        would strand every one of them and leave the lock held on a directory
        nothing is using. That is a restart, and it should look like one."""
        from router.config import load
        from router.service import reload_config
        cfgp, base = self._paths()
        cfgp.write_text(json.dumps(base))
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)

        cfgp.write_text(json.dumps({**base, "state_dir": str(self.root / "ELSEWHERE")}))
        with self.assertLogs("amap_router_local", level="ERROR") as logs:
            kept = reload_config(cfgp, cfg)
        self.assertIs(kept, cfg)
        self.assertEqual(kept.state_dir, self.state)
        self.assertIn("REFUSED", "\n".join(logs.output))

    def test_a_good_reload_is_adopted_wholesale(self):
        """The control. Without it, a `reload_config` that returned `current`
        unconditionally would satisfy all three refusal tests above."""
        from router.config import load
        from router.service import reload_config
        cfgp, base = self._paths()
        cfgp.write_text(json.dumps(base))
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)
        cfgp.write_text(json.dumps({**base, "peer_reply_window_seconds": 999}))
        fresh = reload_config(cfgp, cfg)
        self.assertIsNot(fresh, cfg)
        self.assertEqual(fresh.peer_reply_window_seconds, 999)


class RunForeverIsActuallyDrivenTests(_Tree):
    """`run_forever` itself, driven — the gap the reload defect came through.

    Every other test drives `poll_once` with a config it built. `run_forever`
    is the only caller that reloads, and its docstring said "not used by the
    test suite directly, deployment only" — so the one function no test
    exercised was the one holding the loop the whole design depends on. The
    reload defect lived there, and `reload_config` tests alone would NOT have
    caught it: a correct helper that nothing calls is still a fleet that
    never rediscovers.

    So this drives the real loop. The reload is proven THROUGH it, not beside
    it.
    """

    def _cfg_file(self):
        cfgp = self.root / "router.json"
        cfgp.write_text(json.dumps({
            "state_dir": str(self.state), "instances_dir": str(self.inst),
            "selected_json": str(self.feat / "selected.json"),
            "fleet_domain": "example.invalid", "task_graph": "all"}))
        return cfgp

    def _launch(self, slug):
        from router.config import LANE_LEAVES
        for lane in LANES:
            for leaf in LANE_LEAVES[lane]:
                (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)

    def _run_two_polls(self, cfgp, cfg, between):
        """Drive `run_forever` for exactly two polls, doing `between()` in the
        gap, then stop it the way a Ctrl-C does."""
        from unittest import mock
        from router import service
        seen = []
        calls = {"n": 0}

        real_poll = service.poll_once

        def spy(cfg_, tracker):
            seen.append(sorted(cfg_.instances))
            return real_poll(cfg_, tracker)

        def fake_sleep(_):
            calls["n"] += 1
            if calls["n"] == 1:
                between()
            else:
                raise KeyboardInterrupt

        with mock.patch.object(service, "poll_once", spy), \
             mock.patch.object(service.time, "sleep", fake_sleep):
            service.run_forever(cfg, 0.0, config_path=cfgp)
        return seen

    def test_the_loop_rediscovers_between_polls(self):
        """The defect, through the real loop: a sandbox launched after start
        must be drained without a restart."""
        from router.config import load
        cfgp = self._cfg_file()
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)

        def launch_bob():
            self._launch("bob-c0ffee01")
            self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])

        seen = self._run_two_polls(cfgp, cfg, launch_bob)
        self.assertEqual(seen[0], ["alice-deadbeef"])
        self.assertEqual(seen[1], ["alice-deadbeef", "bob-c0ffee01"],
                         "the loop did not rediscover — a sandbox launched "
                         "after start is never drained")

    def test_the_loop_survives_a_config_that_breaks_mid_run(self):
        """Loud, not fatal: the loop keeps draining the last good fleet."""
        from router.config import load
        cfgp = self._cfg_file()
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)

        seen = self._run_two_polls(
            cfgp, cfg, lambda: cfgp.write_text("{not json"))
        self.assertEqual(seen[1], ["alice-deadbeef"],
                         "a broken config stopped the loop draining")

    def test_run_forever_without_a_config_path_still_polls(self):
        """The old signature still works — `config_path` is optional, so an
        embedder driving `run_forever(cfg, interval)` keeps its behaviour and
        simply never reloads."""
        from router.config import load
        cfgp = self._cfg_file()
        self._launch("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        cfg = load(cfgp)
        from unittest import mock
        from router import service
        calls = {"n": 0}

        def fake_sleep(_):
            calls["n"] += 1
            raise KeyboardInterrupt

        with mock.patch.object(service.time, "sleep", fake_sleep):
            service.run_forever(cfg, 0.0)
        self.assertEqual(calls["n"], 1)


class TheAdmittedSetIsAnnouncedOnChangeTests(_Tree):
    """The log names the fleet's membership when it changes — not only once.

    Before this, the startup line was the ONLY line that ever named the
    admitted set. A sandbox that appeared was visible solely through its own
    first-sight line (which never recurs) and one that DISAPPEARED was
    entirely silent: de-enrolment, a revoked verdict, a deleted tree — all
    invisible.

    Added because a peer's bringup wanted to compare "the last logged
    instance set" against current discovery. There was no such thing after
    startup, so that check would have failed on every correctly-enrolled
    fleet — a false FAIL on the ordinary case.
    """

    def _drive(self, steps):
        """Run the real loop, performing `steps[i]` in the gap after poll i."""
        import logging
        from unittest import mock
        from router.config import LANE_LEAVES, load
        from router import service

        cfgp = self.root / "router.json"
        cfgp.write_text(json.dumps({
            "state_dir": str(self.state), "instances_dir": str(self.inst),
            "selected_json": str(self.feat / "selected.json"),
            "fleet_domain": "example.invalid", "task_graph": "all"}))
        cfg = load(cfgp)
        n = {"i": 0}

        def sleep(_):
            i = n["i"]
            n["i"] += 1
            if i < len(steps):
                steps[i]()
            else:
                raise KeyboardInterrupt

        with self.assertLogs("amap_router_local", level="INFO") as logs, \
             mock.patch.object(service.time, "sleep", sleep):
            service.run_forever(cfg, 0.0, config_path=cfgp)
        return [l for l in logs.output if "instance set changed" in l]

    def _mk(self, slug):
        from router.config import LANE_LEAVES
        for lane in LANES:
            for leaf in LANE_LEAVES[lane]:
                (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)

    def test_an_arrival_is_announced_with_what_was_added(self):
        self._mk("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])

        def arrive():
            self._mk("bob-c0ffee01")
            self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])

        lines = self._drive([arrive])
        self.assertEqual(len(lines), 1)
        self.assertIn("added=['bob-c0ffee01']", lines[0])

    def test_a_DEPARTURE_is_announced_too(self):
        """The half that was completely silent. A fleet losing a member with
        nothing in the log is the shape this repo keeps finding."""
        self._mk("alice-deadbeef")
        self._mk("bob-c0ffee01")
        self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])

        lines = self._drive([lambda: self.verdict(selected=["alice-deadbeef"])])
        self.assertEqual(len(lines), 1)
        self.assertIn("removed=['bob-c0ffee01']", lines[0])

    def test_an_unchanged_set_is_NOT_announced(self):
        """Announced on CHANGE. A line every poll is how an operator learns
        to stop reading the log — the same reasoning that announces first
        sight once."""
        self._mk("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])
        self.assertEqual(self._drive([lambda: None, lambda: None]), [])

    def test_the_line_carries_the_WHOLE_set_not_only_the_delta(self):
        """A consumer comparing "the last logged set" to current discovery
        needs the set. A delta alone would make it reconstruct membership by
        replaying every line since startup."""
        self._mk("alice-deadbeef")
        self.verdict(selected=["alice-deadbeef"])

        def arrive():
            self._mk("bob-c0ffee01")
            self.verdict(selected=["alice-deadbeef", "bob-c0ffee01"])

        line = self._drive([arrive])[0]
        self.assertIn("instances=['alice-deadbeef', 'bob-c0ffee01']", line)


class JsonStdoutIsTheDocumentAloneTests(_Tree):
    """`--json`'s stdout carries the document and nothing else.

    FOUND ON A LIVE FLEET. `docker/run.sh --config … -- status --json` put 38
    discovery lines ahead of the JSON, `json.loads(stdout)` failed, and a
    bringup check read UNKNOWN against a router that was perfectly healthy.

    The log was ALREADY going to stderr, so "send it to stderr" would have
    fixed nothing. `run.sh` gated docker's `-t` on STDIN alone, and `-t`
    merges the container's stderr INTO its stdout — an operator with a
    terminal on stdin and a pipe on stdout, which is how `status --json` is
    actually used, got them interleaved.

    Two independent fixes, and this class pins the one that does not depend
    on stream separation: the report is a HUMAN surface and is withheld
    entirely when a machine-readable document is asked for. A document that
    is only clean while nobody merges the streams is a document that will be
    dirty eventually, and the consumer obeying the rule is the one who pays.
    """

    def _fleet_with_status(self):
        import subprocess
        import sys
        from router.config import LANE_LEAVES, load
        from router.service import poll_once
        from router.status import StatusTracker
        for i in range(3):
            slug = f"box{i}-0badcafe"
            for lane in LANES:
                for leaf in LANE_LEAVES[lane]:
                    (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        self.verdict(selected=["box0-0badcafe"])     # two directories unadmitted
        cfgp = self.root / "router.json"
        cfgp.write_text(json.dumps({
            "state_dir": str(self.state), "instances_dir": str(self.inst),
            "selected_json": str(self.feat / "selected.json"),
            "fleet_domain": "example.invalid", "task_graph": "all"}))
        tracker = StatusTracker()
        poll_once(load(cfgp), tracker)
        tracker.write(self.state)
        return cfgp

    def _run(self, cfgp, args, merge=False):
        import subprocess
        import sys
        return subprocess.run(
            [sys.executable, "-m", "router", "--config", str(cfgp), *args],
            stdout=subprocess.PIPE,
            stderr=(subprocess.STDOUT if merge else subprocess.PIPE),
            text=True, env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(_REPO),
                            "PYTHONDONTWRITEBYTECODE": "1"})

    def test_status_json_stdout_parses(self):
        cfgp = self._fleet_with_status()
        p = self._run(cfgp, ["status", "--json"])
        self.assertEqual(p.returncode, 0, p.stderr)
        json.loads(p.stdout)                      # raises if anything precedes it
        self.assertNotIn("discovery:", p.stdout)

    def test_it_parses_EVEN_WITH_THE_STREAMS_MERGED(self):
        """The `-t` case, which is what actually happened. If the report were
        merely redirected to stderr this would fail — and stderr is where it
        already was."""
        cfgp = self._fleet_with_status()
        p = self._run(cfgp, ["status", "--json"], merge=True)
        json.loads(p.stdout)

    def test_plain_status_STILL_shows_the_report(self):
        """The half that must not be lost. The report is wanted on `status`'s
        table and in the log — only the JSON stream needs to be clean."""
        cfgp = self._fleet_with_status()
        p = self._run(cfgp, ["status"])
        self.assertIn("discovery:", p.stdout + p.stderr,
                      "suppressing the report for --json also silenced the "
                      "human surfaces it exists for")

    def test_a_NON_STATUS_command_still_LOGS_the_report(self):
        """PINS THE LOGGING, which the test above does not.

        `status` PRINTS the report itself, so asserting it appears anywhere
        for `status` is satisfied by that printing whether or not the log
        line survives — mutation showed exactly that: deleting the logging
        entirely left the test above green. The same two-satisfier defect
        this repo keeps finding, in the test written to pin the fix for it.

        `peers` prints no report, so the only way it can reach stderr is the
        log — which is the thing being guarded."""
        cfgp = self._fleet_with_status()
        p = self._run(cfgp, ["peers"])
        self.assertIn("discovery:", p.stderr,
                      "the report is no longer logged at all")
        self.assertNotIn("discovery:", p.stdout,
                         "the log must not be on stdout")

    def test_the_report_would_otherwise_be_non_empty(self):
        """The control that gives the three above their meaning: this fixture
        HAS findings, so a clean `--json` stdout is the suppression working
        rather than there being nothing to suppress."""
        from router.config import load
        from router.status import render_discovery
        cfgp = self._fleet_with_status()
        self.assertTrue(render_discovery(load(cfgp).discovery))


class OnceJsonTests(_Tree):
    """`once --json` — the summary `run_once` already computes, printed.

    Without it `once` reports NOTHING a script can read: empty stdout, an
    exit code that says only whether it crashed, and one log line whose
    payload is a Python dict repr. A host adapter's bringup was therefore
    obliged to match that line's prefix and `ast.literal_eval` the rest,
    which made the prefix, the repr format and four counter NAMES cross-repo
    wire — adding a counter here stopped being a private change.

    The log line is unchanged and stays. This is a path off it.
    """

    def _fleet(self):
        from router.config import LANE_LEAVES
        for slug in ("box-0badcafe", "other-c0ffee01"):
            for lane in LANES:
                for leaf in LANE_LEAVES[lane]:
                    (self.inst / slug / lane / leaf).mkdir(parents=True, exist_ok=True)
        self.verdict(selected=["box-0badcafe"])      # one admitted, one not
        cfgp = self.root / "router.json"
        cfgp.write_text(json.dumps({
            "state_dir": str(self.state), "instances_dir": str(self.inst),
            "selected_json": str(self.feat / "selected.json"),
            "fleet_domain": "example.invalid", "task_graph": "all"}))
        return cfgp

    def _run(self, cfgp, args, merge=False):
        import subprocess
        import sys
        return subprocess.run(
            [sys.executable, "-m", "router", "--config", str(cfgp), *args],
            stdout=subprocess.PIPE,
            stderr=(subprocess.STDOUT if merge else subprocess.PIPE),
            text=True, env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(_REPO),
                            "PYTHONDONTWRITEBYTECODE": "1"})

    def test_it_prints_the_per_instance_summary(self):
        cfgp = self._fleet()
        p = self._run(cfgp, ["once", "--json"])
        self.assertEqual(p.returncode, 0, p.stderr)
        doc = json.loads(p.stdout)
        self.assertEqual(sorted(doc), ["box-0badcafe"])
        self.assertEqual(doc["box-0badcafe"]["first_sight"], 1)

    def test_stdout_parses_EVEN_WITH_THE_STREAMS_MERGED(self):
        """Unlike `status`, `once` DRAINS — so it emits `FIRST SIGHT` and
        `drained <name>: {...}` at INFO. The first version of this flag
        produced a clean stdout and an unparseable `2>&1`, which is the same
        half-fix this repo has now caught three times.

        Both INFO lines carry exactly what the document carries, so a
        `--json` caller loses nothing when they are withheld."""
        cfgp = self._fleet()
        p = self._run(cfgp, ["once", "--json"], merge=True)
        json.loads(p.stdout)

    def test_plain_once_KEEPS_its_log(self):
        """The half that must not be lost. An operator running `once` by hand
        wants the drain lines; only the JSON stream goes quiet.

        MATCHES THE LINE'S SHAPE, NOT THE WORD "drained". The bare substring
        is satisfied by the discovery report's own WARNING line — "a
        directory with no entry ... — NOT DRAINED, NOT deleted" — which this
        fixture always emits because it has an unadmitted directory. So
        quieting INFO globally left the assertion green while the line it
        names was gone: a second producer of the same observable, in a test
        written an hour after that rule went into CLAUDE.md.

        `drained <name>: {` can only come from `run_all`'s INFO line."""
        import re
        cfgp = self._fleet()
        p = self._run(cfgp, ["once"])
        self.assertEqual(p.stdout, "", "plain `once` must print nothing")
        self.assertRegex(p.stderr, r"drained \S+: \{",
                         "the INFO drain line is gone — note that a bare "
                         "'drained' match would still pass here, because the "
                         "discovery report says 'not drained'")

    def test_warnings_still_speak_under_json(self):
        """WARNING and above are NOT redundant with the document — a warning
        during a `--json` drain says something the summary does not. Quieting
        them to make a merged stream parse would be buying a clean parse with
        the operator's only notice."""
        import logging
        cfgp = self._fleet()
        p = self._run(cfgp, ["once", "--json"])
        # The fleet has an unadmitted directory, so the discovery report has
        # a finding — proving the fixture could produce output at all.
        from router.config import load
        from router.status import render_discovery
        self.assertTrue(render_discovery(load(cfgp).discovery))
        # ...and it is withheld from BOTH streams for --json, by design.
        self.assertNotIn("discovery:", p.stdout)

    def test_the_summary_matches_what_the_log_line_carries(self):
        """The document and the log line are the SAME fact. If they ever
        diverge, a consumer migrating from one to the other silently changes
        what it is asserting."""
        import ast
        import re
        cfgp = self._fleet()
        doc = json.loads(self._run(cfgp, ["once", "--json"]).stdout)

        # A second, fresh fleet so the log line describes a first sight too.
        self.tearDown(); self.setUp()
        cfgp2 = self._fleet()
        err = self._run(cfgp2, ["once"]).stderr
        m = re.search(r"drained (\S+): (\{.*\})", err)
        self.assertIsNotNone(m, err)
        self.assertEqual(ast.literal_eval(m.group(2)), doc[m.group(1)])
