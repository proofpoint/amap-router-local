"""The listing_entries_high proxy (its text fixed by the transport design): cumulative
over one complete cursor traversal, evaluated only on the completing page,
reset without evaluating when the traversal restarts. The numbers are the
real ones: 16,384 is a quarter of LIST_SCAN_MAX, over 17 pages of 1024."""
from __future__ import annotations

import unittest

from router import ingress, transport

KEY = ("/state", "a" * 32, "1" * 32)


def traverse(total, *, page=transport.LIST_LIMIT_MAX):
    """Feed one traversal of `total` entries; return what each page gave."""
    out = []
    while True:
        n = min(page, total)
        total -= n
        out.append(ingress.listing_proxy(KEY, n, truncated=total > 0))
        if total <= 0:
            return out


class ListingProxyTests(unittest.TestCase):

    def setUp(self):
        for d in (ingress._CYCLE, ingress.LISTING_ENTRIES_HIGH, ingress._CURSORS):
            d.clear()

    def test_the_threshold_is_a_quarter_of_the_scan_cap(self):
        self.assertEqual(ingress.LISTING_PROXY_THRESHOLD, 16384)
        self.assertEqual(ingress.LISTING_PROXY_LABEL,
                         "proxy: committed entries, not directory names; junk and "
                         "per-notice extra names are not counted")

    def test_16383_across_17_pages_never_warns(self):
        pages = traverse(16383)
        self.assertEqual(len(pages), 16)
        self.assertEqual(pages, [None] * 16)
        self.assertNotIn(KEY, ingress.LISTING_ENTRIES_HIGH)

    def test_16384_warns_on_the_completing_page_and_not_before(self):
        pages = traverse(16384 + 1)
        self.assertEqual(len(pages), 17)
        self.assertEqual(pages[:-1], [None] * 16)
        self.assertEqual(pages[-1], 16385)
        self.assertEqual(ingress.LISTING_ENTRIES_HIGH[KEY], 16385)
        traverse(16384)
        self.assertEqual(ingress.LISTING_ENTRIES_HIGH[KEY], 16384)

    def test_a_later_complete_traversal_under_the_threshold_clears_it(self):
        traverse(20000)
        self.assertIn(KEY, ingress.LISTING_ENTRIES_HIGH)
        traverse(16383)
        self.assertNotIn(KEY, ingress.LISTING_ENTRIES_HIGH)

    def test_a_truncated_page_alone_never_sets_or_clears(self):
        traverse(20000)
        ingress.listing_proxy(KEY, 1, truncated=True)
        self.assertIn(KEY, ingress.LISTING_ENTRIES_HIGH)
        self.setUp()
        for _ in range(40):
            self.assertIsNone(ingress.listing_proxy(KEY, 1024, truncated=True))
        self.assertNotIn(KEY, ingress.LISTING_ENTRIES_HIGH)

    def test_a_restart_mid_traversal_counts_afresh(self):
        for _ in range(10):
            ingress.listing_proxy(KEY, 1024, truncated=True)
        ingress.reset_traversal(KEY)
        pages = traverse(16383 - 10 * 1024 + 10 * 1024)
        self.assertNotIn(KEY, ingress.LISTING_ENTRIES_HIGH,
                         "the pages before the restart were counted")


if __name__ == "__main__":
    unittest.main()
