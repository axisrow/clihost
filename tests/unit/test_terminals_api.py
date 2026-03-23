"""Tests for terminal routing patterns from ttyd_proxy.py."""
import unittest
import re

# Copied from ttyd_proxy.py
TTYD_ROUTE_PATTERN = re.compile(r'^/ttyd(\d+)(/.*)?$')


class TestTTYDRoutePattern(unittest.TestCase):
    """Test the regex pattern for /ttyd<N> routes."""

    def test_ttyd1(self):
        m = TTYD_ROUTE_PATTERN.match("/ttyd1")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "1")
        self.assertIsNone(m.group(2))

    def test_ttyd1_slash(self):
        m = TTYD_ROUTE_PATTERN.match("/ttyd1/")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "1")
        self.assertEqual(m.group(2), "/")

    def test_ttyd1_ws(self):
        m = TTYD_ROUTE_PATTERN.match("/ttyd1/ws")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "1")
        self.assertEqual(m.group(2), "/ws")

    def test_ttyd100(self):
        m = TTYD_ROUTE_PATTERN.match("/ttyd100")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "100")

    def test_ttyd_no_number(self):
        """Plain /ttyd should NOT match (no terminal ID)."""
        m = TTYD_ROUTE_PATTERN.match("/ttyd")
        self.assertIsNone(m)

    def test_ttyd_slash_no_number(self):
        """Plain /ttyd/ should NOT match."""
        m = TTYD_ROUTE_PATTERN.match("/ttyd/")
        self.assertIsNone(m)

    def test_ttyd_alpha(self):
        """/ttydabc should NOT match (not a number)."""
        m = TTYD_ROUTE_PATTERN.match("/ttydabc")
        self.assertIsNone(m)

    def test_ttyd0(self):
        """/ttyd0 should match (0 is a valid digit)."""
        m = TTYD_ROUTE_PATTERN.match("/ttyd0")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0")

    def test_nested_path(self):
        m = TTYD_ROUTE_PATTERN.match("/ttyd5/token?arg=1")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "5")
        self.assertEqual(m.group(2), "/token?arg=1")

    def test_no_match_other_routes(self):
        self.assertIsNone(TTYD_ROUTE_PATTERN.match("/terminals"))
        self.assertIsNone(TTYD_ROUTE_PATTERN.match("/login"))
        self.assertIsNone(TTYD_ROUTE_PATTERN.match("/health"))
        self.assertIsNone(TTYD_ROUTE_PATTERN.match("/"))


if __name__ == "__main__":
    unittest.main()
