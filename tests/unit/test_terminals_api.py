"""Tests for terminal routing patterns."""
import unittest

from ttydproxy.config import TTYD_ROUTE_PATTERN


class TestTTYDRoutePattern(unittest.TestCase):
    def test_valid_routes(self):
        for path, terminal_id, suffix in (
            ("/ttyd1", "1", None),
            ("/ttyd1/", "1", "/"),
            ("/ttyd1/ws", "1", "/ws"),
            ("/ttyd100", "100", None),
            ("/ttyd0", "0", None),
            ("/ttyd5/token?arg=1", "5", "/token?arg=1"),
        ):
            with self.subTest(path=path):
                match = TTYD_ROUTE_PATTERN.match(path)
                self.assertIsNotNone(match)
                self.assertEqual(match.group(1), terminal_id)
                self.assertEqual(match.group(2), suffix)

    def test_invalid_routes(self):
        for path in ("/ttyd", "/ttyd/", "/ttydabc", "/terminals", "/login", "/health", "/"):
            with self.subTest(path=path):
                self.assertIsNone(TTYD_ROUTE_PATTERN.match(path))


if __name__ == "__main__":
    unittest.main()

