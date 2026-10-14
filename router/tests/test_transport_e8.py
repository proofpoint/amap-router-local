"""API (3, 0), amendment E8 (`router/transport.py`): the ports' new shape,
the pinned vocabularies, this runtime's checks on what a plugin hands it,
and the one classifier for what a plugin raises.

Interface only, as `test_transport_ports.py`: the tests pin the INTERFACE
and the runtime-side rules. The plugin's implementation is witnessed by its
own conformance suite at this runtime's pin. `_RefInbound` is a reference
of the paging contract written here so its rules can be shown to bite,
never a second implementation of the port.
"""
from __future__ import annotations

import inspect
import typing
import unittest

from router import transport
from router.fsops import FsOpsError, UnsafeRead


def _methods(proto):
    return {n for n, v in vars(proto).items() if callable(v) and not n.startswith("_")}


class ShapeTests(unittest.TestCase):

    def test_the_version(self):
        self.assertEqual(transport.PLUGIN_API, (3, 4))
        self.assertEqual(transport.REQUIRED_MINOR, 0)
        self.assertEqual(dict(transport.OPTIONAL_FACTORIES),
                         {"make_intake_remover": ((3, 1), "HopFsOps"),
                          "make_peer_codec": ((3, 3), None),
                          "make_peer_errors": ((3, 3), transport.NO_ARGUMENTS),
                          # Provisional until the runtime identity unit freezes.
                          "make_runtime_sender": ((3, 5), "HopFsOps"),
                          "make_runtime_lister": ((3, 5), "HopFsOps")})
        for name, (since, _port) in transport.OPTIONAL_FACTORIES.items():
            self.assertGreater(since[1], transport.REQUIRED_MINOR, name)
        self.assertEqual(transport.REQUIRED_FACTORIES,
                         ("make_sender", "make_intake_reader", "make_upstream_marker_store"))
        self.assertEqual(transport.FACTORY_PORTS["make_upstream_marker_store"], "HopFsOps")

    def test_each_port_has_exactly_its_methods(self):
        self.assertEqual(_methods(transport.TransportPort),
                         {"has_result", "has_pending", "has_archived", "read_result",
                          "write_request", "withdraw_request", "close"})
        self.assertEqual(_methods(transport.InboundPort), {"list_entries", "read_entry", "close"})
        self.assertEqual(_methods(transport.UpstreamMarkers), {"retire", "retired", "close"})
        self.assertIn("list_pinned", _methods(transport.HopFsOps))

    def test_the_paging_parameters_are_keyword_only(self):
        for fn, first in ((transport.HopFsOps.list_pinned, "dir_fd"),
                          (transport.InboundPort.list_entries, "kind")):
            with self.subTest(fn=fn.__qualname__):
                ps = inspect.signature(fn).parameters
                self.assertEqual([p for p in ps if p != "self"], [first, "limit", "after"])
                self.assertIs(ps["limit"].kind, inspect.Parameter.KEYWORD_ONLY)
                self.assertIs(ps["limit"].default, inspect.Parameter.empty)
                self.assertIs(ps["after"].kind, inspect.Parameter.KEYWORD_ONLY)
                self.assertIsNone(ps["after"].default)
                self.assertEqual(typing.get_type_hints(fn)["return"],
                                 typing.Tuple[typing.List[str], bool])

    def test_the_attributes(self):
        self.assertEqual(tuple(transport.InboundPort.__annotations__),
                         transport.INBOUNDPORT_ATTRIBUTES)
        self.assertEqual(transport.INBOUNDPORT_ATTRIBUTES, ("NoticeRefused",))
        self.assertEqual(tuple(transport.UpstreamMarkers.__annotations__),
                         transport.UPSTREAM_MARKER_ATTRIBUTES)
        self.assertEqual(transport.UPSTREAM_MARKER_ATTRIBUTES, ("GenerationAbsent",))

    def test_the_vocabularies_are_pinned(self):
        self.assertEqual(transport.LIST_LIMIT_MAX, 1024)
        self.assertEqual(transport.LIST_SCAN_MAX, 65536)
        self.assertEqual(transport.NOTICE_REFUSAL_REASONS, ("notice_incomplete", "notice_invalid"))
        self.assertEqual(transport.NOTICE_BUNDLE_SCHEMA, "amap-hop-notice-entry/2")
        self.assertEqual(transport.HOP_FACTS_MAX, 64 * 1024)
        self.assertEqual(transport.WITHDRAW_RESULTS, ("withdrawn", "too_late"))
        self.assertEqual(typing.get_args(transport.WithdrawResult), transport.WITHDRAW_RESULTS)
        self.assertEqual(transport.RETIRE_RESULTS, ("created", "exists_same", "exists", "absent"))
        self.assertEqual(typing.get_args(transport.RetireResult), transport.RETIRE_RESULTS)
        self.assertEqual(typing.get_type_hints(transport.UpstreamMarkers.retire)["return"],
                         transport.RetireResult)
        self.assertEqual(typing.get_type_hints(transport.TransportPort.withdraw_request)["return"],
                         transport.WithdrawResult)
        self.assertEqual(transport.TRANSPORT_REASONS, (
            "request_exists_different", "request_exists_withdrawn", "request_exists_settled",
            "handover_invalid", "below_frontier",
            "layout", "owner", "version",
            "exists_different", "reconcile", "sidecars", "sidecars_orphaned", "heal_state",
            "protocol_violation", "marker_unreadable",
            "settings_invalid", "closed",
            "generation_retired"))

    def test_the_reason_tuples_are_pairwise_disjoint(self):
        """The classifier's order no longer depends on it, but a later
        addition that collides fails here first."""
        tuples = {"TRANSPORT_REASONS": transport.TRANSPORT_REASONS,
                  "UNSAFE_READ_REASONS": transport.UNSAFE_READ_REASONS,
                  "NOTICE_REFUSAL_REASONS": transport.NOTICE_REFUSAL_REASONS}
        names = sorted(tuples)
        for i, a in enumerate(names):
            self.assertEqual(len(set(tuples[a])), len(tuples[a]), f"{a} repeats a member")
            for b in names[i + 1:]:
                self.assertFalse(set(tuples[a]) & set(tuples[b]), f"{a} and {b} overlap")

    def test_the_rules_are_stated(self):
        mod = " ".join(transport.__doc__.split())
        for phrase in ("a `(3, x)` runtime refuses every `(2, x)` plugin",
                       "Nothing at `(2, x)` was ever deployed",
                       "ORDER IS NEVER TAKEN FROM A LISTING",
                       "nothing may compare entry ids to page",
                       "`int(n)`, never its name",
                       "API 3.1: THE OPTIONAL INTAKE REMOVER, by the owner's decision",
                       "never in `REQUIRED_FACTORIES` or `FACTORY_PORTS`"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, mod)
        tp = " ".join(transport.TransportPort.__doc__.split())
        for phrase in ("decided by the no-replace rename", "never by a pre-check",
                       "never either verdict", "(i) never published",
                       "(ii) a request at link count 2", "Allowed on a retired generation",
                       "never closed by a plugin object", "Idempotent",
                       "THE FACTORY CLEANUP RULE"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, tp)
        ip = " ".join(transport.InboundPort.__doc__.split())
        for phrase in ("never over the id", "fewer than `limit` entries only when `truncated` is False",
                       "`limit + 1` committed entries", "a BOUND, not an exact count",
                       "propagates UNCHANGED", "IS listed, never hidden", "A `/1` bundle is refused",
                       "whose facts, spool or sidecars are missing",
                       "The caller captures the class once, at construction "
                       "(`capture_verdict_class`: two-way disjoint from `OSError` and both of "
                       "the runtime's own classes, `UnsafeRead` and `ListingTooLarge`), and "
                       "dispatches on the captured class for kind `\"notice\"` only.",
                       "An `OSError`, `UnsafeRead` or `ListingTooLarge` raised while reading "
                       "or listing notices propagates as itself and is never a verdict.",
                       "REQUIRED and never null"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, ip)
        um = " ".join(transport.UpstreamMarkers.__doc__.split())
        for phrase in ("never admits", "`\"absent\"` ONLY on an owner-checked ENOENT",
                       "creating nothing", "never `False`", "EXACTLY the canonical",
                       "The caller captures `GenerationAbsent` once, at construction "
                       "(`capture_verdict_class`: two-way disjoint from `OSError` and both of "
                       "the runtime's own classes, `UnsafeRead` and `ListingTooLarge`)."):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, um)
        fs = " ".join(transport.HopFsOps.__doc__.split())
        for phrase in ("a FRESH open description", "never a dup", "surrogateescape",
                       "stops at once and raises", "never returns an empty list for an error"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, fs)

    def test_remove_entry_is_optional_at_3_1(self):
        """Decided (an optional factory): never required, never a 3.0 port's
        method, present only in OPTIONAL_FACTORIES at (3, 1)."""
        self.assertNotIn("make_intake_remover", transport.FACTORY_PORTS)
        self.assertNotIn("make_intake_remover", transport.REQUIRED_FACTORIES)
        self.assertEqual(transport.OPTIONAL_FACTORIES["make_intake_remover"][0], (3, 1))
        for proto in (transport.InboundPort, transport.TransportPort, transport.HopFsOps):
            self.assertNotIn("remove_entry", _methods(proto))
        self.assertEqual(_methods(transport.IntakeRemover), {"remove_entry", "close"})
        self.assertNotIn("PENDING", transport.__doc__)

    def test_the_null_plugin_and_the_loaded_plugin_have_the_store(self):
        self.assertIsNone(transport.NullTransport().make_upstream_marker_store({}, None))
        self.assertTrue(callable(transport.LoadedPlugin.make_upstream_marker_store))


class _Markers:
    GenerationAbsent = type("GenerationAbsent", (Exception,), {})
    def retire(self, retired_at): return "created"
    def retired(self): return False
    def close(self): return None


class _Port:
    def has_result(self, n): return False
    def has_pending(self, n): return False
    def has_archived(self, n): return False
    def read_result(self, n): return b""
    def write_request(self, n, data): return None
    def withdraw_request(self, n): return "withdrawn"
    def close(self): return None


class _Reader:
    NoticeRefused = type("NoticeRefused", (Exception,), {})
    def list_entries(self, kind, *, limit, after=None): return ([], False)
    def read_entry(self, kind, entry_id): return b""
    def close(self): return None


class ConformanceTests(unittest.TestCase):
    """Each Protocol accepts a complete stand-in and refuses one missing any
    member: a check that accepted everything would pass the first alone."""

    def test_complete_and_each_member_missing(self):
        for proto, cls in ((transport.UpstreamMarkers, _Markers),
                           (transport.TransportPort, _Port),
                           (transport.InboundPort, _Reader)):
            self.assertIsInstance(cls(), proto)
            members = sorted(_methods(proto)) + list(getattr(proto, "__annotations__", {}))
            for name in members:
                with self.subTest(proto=proto.__name__, missing=name):
                    partial = type("Partial", (), {k: v for k, v in vars(cls).items()
                                                   if k != name})
                    self.assertNotIsInstance(partial(), proto)


class ListArgsTests(unittest.TestCase):

    def test_accepted(self):
        for limit in (1, 2, transport.LIST_LIMIT_MAX):
            for after in (None, "", "notice-a.json"):
                transport.check_list_args(limit, after)

    def test_refused_never_clamped(self):
        for limit in (0, -1, True, False, transport.LIST_LIMIT_MAX + 1, 1.0, "1", None):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    transport.check_list_args(limit, None)
        for after in (3, b"x", ["a"]):
            with self.subTest(after=after):
                with self.assertRaises(ValueError):
                    transport.check_list_args(1, after)


class RetiredAtTests(unittest.TestCase):

    def test_the_grammar_is_ascii_only(self):
        good = "2026-10-12T13:47:08Z"
        self.assertEqual(transport.check_retired_at(good), good)
        for i, ch in enumerate(good):
            if ch.isdigit():
                bad = good[:i] + "٣" + good[i + 1:]   # ARABIC-INDIC DIGIT THREE
                with self.subTest(bad=bad):
                    with self.assertRaises(ValueError):
                        transport.check_retired_at(bad)

    def test_other_refusals(self):
        for bad in ("2026-10-12T13:47:08Z\n", "2026-10-12 13:47:08Z", "2026-10-12T13:47:08",
                    "2026-13-40T25:61:61Z", "", None, 20261012):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    transport.check_retired_at(bad)


class _HasClass:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)


class DisjointnessTests(unittest.TestCase):
    """A verdict class must be neither an ancestor nor a descendant of
    `OSError` or the runtime's `UnsafeRead`: otherwise one exception is both
    a verdict and a no-verdict I/O failure, and the outcome depends on the
    order of the `except` clauses."""

    TOO_LARGE = type("ListingTooLarge", (Exception,), {})
    FSOPS = _HasClass(UnsafeRead=UnsafeRead, ListingTooLarge=TOO_LARGE)

    def refused(self, cls):
        obj = _HasClass(NoticeRefused=cls)
        with self.assertRaises(transport.SeamRefused) as cm:
            transport.capture_verdict_class(obj, "NoticeRefused", self.FSOPS, "reader_vocabulary")
        self.assertEqual(cm.exception.reason, "reader_vocabulary")

    def test_a_disjoint_class_is_captured(self):
        cls = type("NoticeRefused", (Exception,), {})
        got = transport.capture_verdict_class(_HasClass(NoticeRefused=cls), "NoticeRefused",
                                              self.FSOPS, "reader_vocabulary")
        self.assertIs(got, cls)

    def test_each_forbidden_shape_is_refused(self):
        cases = {
            "not a class": "NoticeRefused",
            "Exception itself (an OSError ancestor)": Exception,
            "BaseException-derived": type("X", (BaseException,), {}),
            "an OSError descendant": type("X", (FileNotFoundError,), {}),
            "an UnsafeRead ancestor": FsOpsError,
            "an UnsafeRead descendant": type("X", (UnsafeRead,), {}),
            "a ListingTooLarge descendant": type("X", (self.TOO_LARGE,), {}),
        }
        for why, cls in cases.items():
            with self.subTest(why=why):
                self.refused(cls)

    def test_an_ancestor_of_the_runtimes_listing_class_is_refused(self):
        """The COMPLETE captured set: a verdict class above ListingTooLarge
        would make `classify` (verdicts first) read a runtime
        ListingTooLarge as that verdict."""
        base = type("Base", (Exception,), {})
        too_large = type("ListingTooLarge", (base,), {})
        fsops = _HasClass(UnsafeRead=UnsafeRead, ListingTooLarge=too_large)
        with self.assertRaises(transport.SeamRefused):
            transport.capture_verdict_class(_HasClass(NoticeRefused=base), "NoticeRefused",
                                            fsops, "reader_vocabulary")
        with self.assertRaises(transport.SeamRefused):
            transport.capture_verdict_class(_HasClass(GenerationAbsent=base), "GenerationAbsent",
                                            fsops, "marker_vocabulary")

    def test_a_missing_attribute_is_refused(self):
        with self.assertRaises(transport.SeamRefused):
            transport.capture_verdict_class(_HasClass(), "NoticeRefused", self.FSOPS,
                                            "reader_vocabulary")

    def test_the_marker_store_uses_its_own_reason(self):
        with self.assertRaises(transport.SeamRefused) as cm:
            transport.capture_verdict_class(_HasClass(GenerationAbsent=OSError),
                                            "GenerationAbsent", self.FSOPS, "marker_vocabulary")
        self.assertEqual(cm.exception.reason, "marker_vocabulary")

    def test_listing_too_large_is_checked_the_same_way(self):
        good = type("ListingTooLarge", (Exception,), {})
        self.assertEqual(transport.check_fsops_classes(
            _HasClass(UnsafeRead=UnsafeRead, ListingTooLarge=good)),
            ((UnsafeRead, "unsafe_read"), (good, "listing_too_large")))
        self.assertEqual(transport.RUNTIME_ROLES, ("unsafe_read", "listing_too_large"))
        for bad in (type("X", (OSError,), {}), type("X", (UnsafeRead,), {}), FsOpsError):
            with self.subTest(bad=bad):
                with self.assertRaises(transport.SeamRefused) as cm:
                    transport.check_fsops_classes(_HasClass(UnsafeRead=UnsafeRead,
                                                            ListingTooLarge=bad))
                self.assertEqual(cm.exception.reason, "fsops_vocabulary")


class _Reasoned(Exception):
    """A plugin-defined exception: a class this runtime never imports."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class _ReasonedOSError(OSError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class ClassifyTests(unittest.TestCase):

    def setUp(self):
        self.refused = type("NoticeRefused", (Exception,), {})
        self.absent = type("GenerationAbsent", (Exception,), {})
        self.too_large = type("ListingTooLarge", (Exception,), {})
        self.verdicts = ((self.refused, transport.NOTICE_REFUSAL_REASONS), (self.absent, None))
        self.runtime = ((UnsafeRead, "unsafe_read"), (self.too_large, "listing_too_large"))

    def classify(self, e):
        return transport.classify(e, verdicts=self.verdicts, runtime=self.runtime)

    def test_every_transport_reason(self):
        for reason in transport.TRANSPORT_REASONS:
            with self.subTest(reason=reason):
                self.assertEqual(self.classify(_Reasoned(reason)), ("reason", reason))

    def test_verdicts(self):
        e = self.refused()
        e.reason = "notice_invalid"
        self.assertEqual(self.classify(e), ("verdict", "notice_invalid"))
        self.assertEqual(self.classify(self.absent()), ("verdict", None))

    def test_a_verdict_with_an_unknown_reason_is_no_verdict(self):
        e = self.refused()
        e.reason = "notice_strange"
        self.assertEqual(self.classify(e), ("other", None))

    def test_the_runtimes_own_classes_win_over_a_colliding_reason(self):
        """THE ORDER. Another implementer's UnsafeRead may carry a reason
        that equals a TRANSPORT_REASONS member; it is still an unsafe read,
        never a plugin verdict and never a hold."""
        for reason in ("owner", "settings_invalid", "layout"):
            e = UnsafeRead.__new__(UnsafeRead)
            Exception.__init__(e, reason)
            e.reason = reason
            with self.subTest(reason=reason):
                self.assertEqual(self.classify(e), ("runtime", "unsafe_read"))
        self.assertEqual(self.classify(self.too_large()), ("runtime", "listing_too_large"))

    def test_the_runtime_role_never_depends_on_the_class_name(self):
        """The Protocol fixes the attribute's ROLE; a conforming FsOps may
        name its class anything, or the same as another role's."""
        for name in ("HugeDirectory", "ListingTooLarge", "UnsafeRead"):
            with self.subTest(name=name):
                cls = type(name, (Exception,), {})
                fsops = _HasClass(UnsafeRead=UnsafeRead, ListingTooLarge=cls)
                runtime = transport.check_fsops_classes(fsops)
                self.assertEqual(transport.classify(cls(), runtime=runtime),
                                 ("runtime", "listing_too_large"))

    def test_a_plugin_oserror_with_a_reason_is_classified_by_its_reason(self):
        self.assertEqual(self.classify(_ReasonedOSError("below_frontier")),
                         ("reason", "below_frontier"))

    def test_oserror_and_anything_else(self):
        self.assertEqual(self.classify(FileNotFoundError(2, "x")), ("oserror", "ENOENT"))
        self.assertEqual(self.classify(OSError("no errno")), ("oserror", None))
        self.assertEqual(self.classify(ValueError("bare")), ("other", None))
        self.assertEqual(self.classify(_Reasoned("not_a_reason")), ("other", None))
        e = ValueError("x")
        e.reason = 3
        self.assertEqual(self.classify(e), ("other", None))

    def test_a_class_swapped_after_capture_changes_nothing(self):
        obj = _HasClass(NoticeRefused=self.refused)
        captured = transport.capture_verdict_class(obj, "NoticeRefused",
                                                   _HasClass(UnsafeRead=UnsafeRead,
                                                             ListingTooLarge=self.too_large),
                                                   "reader_vocabulary")
        obj.NoticeRefused = OSError   # the plugin swaps it afterwards
        e = self.refused()
        e.reason = "notice_incomplete"
        got = transport.classify(e, verdicts=((captured, transport.NOTICE_REFUSAL_REASONS),))
        self.assertEqual(got, ("verdict", "notice_incomplete"))
        self.assertEqual(transport.classify(FileNotFoundError(2, "x"),
                                            verdicts=((captured, transport.NOTICE_REFUSAL_REASONS),)),
                         ("oserror", "ENOENT"))


class BundleSchemaTests(unittest.TestCase):

    def test_only_2_is_current(self):
        self.assertTrue(transport.is_current_bundle_schema("amap-hop-notice-entry/2"))
        for bad in ("amap-hop-notice-entry/1", "amap-hop-notice-entry/3", None, ""):
            with self.subTest(bad=bad):
                self.assertFalse(transport.is_current_bundle_schema(bad))


class _RefInbound:
    """A REFERENCE of the paging contract over a sorted list of NAMES,
    through a `list_pinned` that counts its calls. It shows the frozen rules
    bite; the plugin's own implementation is witnessed by its suite."""

    def __init__(self, names, *, inner_limit=transport.LIST_LIMIT_MAX, lookahead=True,
                 fill=True, cursor_by_id=False):
        self.names = sorted(names)
        self.inner_limit, self.lookahead, self.fill = inner_limit, lookahead, fill
        self.cursor_by_id = cursor_by_id
        self.calls = 0

    @staticmethod
    def entry_id(name):
        if name.startswith("notice-") and name.endswith(".json"):
            return name[len("notice-"):-len(".json")]
        return None

    @staticmethod
    def name_of(entry_id):
        return f"notice-{entry_id}.json"

    def list_pinned(self, *, limit, after=None):
        self.calls += 1
        rest = [n for n in self.names if after is None or n > after]
        return rest[:limit], len(rest) > limit

    def list_entries(self, kind, *, limit, after=None):
        transport.check_list_args(limit, after)
        want = limit + 1 if self.lookahead else limit
        got, cursor = [], None if after is None else self.name_of(after)
        while True:
            names, truncated = self.list_pinned(limit=self.inner_limit, after=cursor)
            for n in names:
                eid = self.entry_id(n)
                if eid is None:
                    continue
                if self.cursor_by_id and after is not None and eid <= after:
                    continue
                got.append(eid)
            if names:
                cursor = names[-1]
            if len(got) >= want or not truncated or not self.fill:
                break
        return got[:limit], len(got) > limit if self.lookahead else truncated


class PagingContractTests(unittest.TestCase):

    def walk(self, port, limit, max_calls=100):
        seen, after, calls = [], None, 0
        while calls < max_calls:
            ids, truncated = port.list_entries("notice", limit=limit, after=after)
            calls += 1
            seen.extend(ids)
            if not truncated:
                return seen, calls
            after = ids[-1]
        self.fail(f"no end after {max_calls} calls")

    def test_id_order_is_not_name_order_and_nothing_is_skipped(self):
        names = [f"notice-{i}.json" for i in ("a", "a.b", "a-x", "ab")]
        for limit in (1, 2, 4):
            with self.subTest(limit=limit):
                seen, calls = self.walk(_RefInbound(names), limit)
                self.assertEqual(sorted(seen), ["a", "a-x", "a.b", "ab"])
                self.assertEqual(len(seen), 4)
                self.assertLessEqual(calls, -(-4 // limit) + 1)

    def test_a_cursor_in_id_space_skips_entries(self):
        """The mutant the ruling names: compare `after` to ids."""
        names = [f"notice-{i}.json" for i in ("a", "a.b", "a-x", "ab")]
        seen, _ = self.walk(_RefInbound(names, cursor_by_id=True), 1)
        self.assertNotEqual(sorted(seen), ["a", "a-x", "a.b", "ab"])

    def test_trailing_junk_alone_gives_truncated_false(self):
        names = ["notice-e1.json"] + [f"zz-junk-{i:05d}" for i in range(50)]
        ids, truncated = _RefInbound(names).list_entries("notice", limit=1)
        self.assertEqual((ids, truncated), (["e1"], False))
        ids, truncated = _RefInbound(names, lookahead=False).list_entries("notice", limit=1)
        self.assertEqual(ids, ["e1"])

    def test_one_entry_junk_then_a_second(self):
        names = ["notice-e1.json", "notice-z9.json"] + [f"notice-m{i}.tmp" for i in range(5)]
        port = _RefInbound(names)
        self.assertEqual(port.list_entries("notice", limit=1), (["e1"], True))
        self.assertEqual(port.list_entries("notice", limit=1, after="e1"), (["z9"], False))

    def test_fill_or_exhaust_past_two_windows_of_junk(self):
        junk = [f"notice-{i:05d}.tmp" for i in range(2 * transport.LIST_LIMIT_MAX)]
        names = junk + ["notice-zzz.json"]
        port = _RefInbound(names)
        self.assertEqual(port.list_entries("notice", limit=1), (["zzz"], False))
        stall = _RefInbound(names, fill=False, lookahead=False)   # the pre-fix shape
        self.assertEqual(stall.list_entries("notice", limit=1), ([], True),
                         "control: a single inner call returns an empty, truncated page")

    def test_inner_call_counts_are_within_the_bound(self):
        """The formula is a BOUND; the counts are asserted exactly."""
        def count(j, entries, limit):
            names = [f"a-junk-{i:06d}" for i in range(j)] + \
                    [f"notice-e{i:06d}.json" for i in range(entries)]
            port = _RefInbound(names)
            port.list_entries("notice", limit=limit)
            return port.calls
        for j, entries, limit, exact in ((0, 2, 1, 1), (1023, 1, 1, 1), (1024, 1, 1, 2),
                                         (4096, 1, 1, 5), (0, 1025, 1024, 2)):
            with self.subTest(j=j, entries=entries, limit=limit):
                got = count(j, entries, limit)
                self.assertEqual(got, exact)
                bound = -(-(j + limit + 1) // transport.LIST_LIMIT_MAX) + 1
                self.assertLessEqual(got, bound)

    def test_held_entries_never_starve_a_fresh_one(self):
        held = [f"notice-h{i:04d}.json" for i in range(4)]
        port = _RefInbound(held + ["notice-z-fresh.json"])
        seen, calls = self.walk(port, 1)
        self.assertIn("z-fresh", seen)
        self.assertLessEqual(calls, 5 + 1)


if __name__ == "__main__":
    unittest.main()
