"""The candidate view's gate (`transport` API 3.4, `peerlane.candidate_view_of`):
an optional codec method and an optional codec attribute, ignored below
their minor, OFF when absent, refused when present but malformed."""
import unittest
from unittest import mock

from router import peerlane, transport
from router.tests import peer_standin as si
from router.tests.test_peerlane import _Base


def codec_with(**members):
    """A stand-in codec class with `members` set, or removed when None."""
    attrs = {k: v for k, v in vars(si.PeerCodec).items()
             if not k.startswith("__") or k == "__slots__"}
    for k, v in members.items():
        if v is None:
            attrs.pop(k, None)
        else:
            attrs[k] = v
    return type("PeerCodec", (), attrs)


class GateTests(_Base):

    def activate_with(self, api=(3, 4), **members):
        self.plugin = si.Plugin(si.namespace(api=api, calls=self.calls))
        with mock.patch.object(si, "PeerCodec", codec_with(**members)):
            return peerlane.activate(self.cfg(), self.plugin, now=_now())

    def refused(self, phrase, **kw):
        with self.assertRaises(peerlane.DelegationRefused) as cm:
            self.activate_with(**kw)
        self.assertIn(phrase, str(cm.exception))

    def test_both_present_at_3_4_turn_the_view_on(self):
        d = self.activate_with()
        self.assertIs(d.candidate_view, si.PeerCodec.candidate_view)

    def test_below_3_4_both_names_are_ignored(self):
        try:
            d = self.activate_with(api=(3, 3), CANDIDATE_REASONS=frozenset({"x"}))
        except peerlane.DelegationRefused as e:
            self.fail(f"a (3, 4) name was consulted below its minor: {e}")
        self.assertIsNone(d.candidate_view)

    def test_an_absent_view_is_off(self):
        self.assertIsNone(self.activate_with(candidate_view=None).candidate_view)

    def test_a_view_without_its_vocabulary_is_off(self):
        self.assertIsNone(self.activate_with(CANDIDATE_REASONS=None).candidate_view)

    def test_a_malformed_vocabulary_is_refused(self):
        for bad in (frozenset({"candidate_json", "candidate_schema"}),
                    frozenset({"candidate_json", "candidate_schema", "over_cap", "new"}),
                    {"candidate_json", "candidate_schema", "over_cap"},
                    ("candidate_json", "candidate_schema", "over_cap")):
            with self.subTest(bad=bad):
                self.refused("CANDIDATE_REASONS", CANDIDATE_REASONS=bad)

    def test_a_malformed_vocabulary_is_refused_even_without_the_view(self):
        self.refused("CANDIDATE_REASONS", candidate_view=None,
                     CANDIDATE_REASONS=frozenset({"x"}))

    def test_a_view_that_is_not_callable_is_refused(self):
        self.refused("candidate_view is not callable", candidate_view="not callable")


class PinTests(unittest.TestCase):

    def test_the_stand_in_carries_exactly_the_3_4_set(self):
        self.assertEqual(transport.CANDIDATE_REASONS_3_4,
                         frozenset({"candidate_json", "candidate_schema", "over_cap"}))
        self.assertEqual(si.CANDIDATE_REASONS, transport.CANDIDATE_REASONS_3_4)
        self.assertIs(si.PeerCodec.CANDIDATE_REASONS, si.CANDIDATE_REASONS)
        self.assertEqual(si.CANDIDATE_REASONS & si.REASONS, frozenset())

    def test_the_tables_name_the_3_4_minor(self):
        self.assertEqual(dict(transport.CODEC_OPTIONAL_METHODS), {"candidate_view": (3, 4)})
        self.assertEqual(dict(transport.CODEC_OPTIONAL_ATTRIBUTES), {"CANDIDATE_REASONS": (3, 4)})
        self.assertEqual(transport.PLUGIN_API, (3, 4))


def _now():
    from router.tests.test_peerlane import NOW
    return NOW


if __name__ == "__main__":
    unittest.main()
