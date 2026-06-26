"""Routing must not crash on an over-long numeric terminal id (B7/B8).

GET /ttyd<N> and DELETE /terminals/<N> reach int() on the id BEFORE any auth.
Python 3.11+ caps int(str) at sys.get_int_max_str_digits() (default 4300), so a
>4300-digit id raises ValueError. An unauthenticated request must yield a clean
404, never an unhandled exception. The fix bounds the digit count at the routing
layer (regex \\d{1,9} for GET; len cap for DELETE) so the id simply fails to
match and falls through to the existing 404.
"""
import unittest
from unittest.mock import patch

from ttydproxy.config import TTYD_ROUTE_PATTERN

from tests.unit.handler_stubs import RecordingHandler


OVERLONG = "9" * 4301  # passes str.isdigit() but exceeds int()'s 4300-digit cap


class TestRoutePattern(unittest.TestCase):
    def test_overlong_id_does_not_match_pattern(self):
        self.assertIsNone(TTYD_ROUTE_PATTERN.match("/ttyd" + OVERLONG))

    def test_normal_id_matches_pattern(self):
        match = TTYD_ROUTE_PATTERN.match("/ttyd7")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "7")


class TestGetRouting(unittest.TestCase):
    def test_overlong_ttyd_id_returns_404(self):
        handler = RecordingHandler()
        handler.path = "/ttyd" + OVERLONG
        # Must not raise (the bug raised ValueError pre-auth).
        handler.do_GET()
        self.assertEqual(handler.response, (404, {"error": "Not found"}))

    def test_normal_ttyd_id_routes_to_handle_ttyd(self):
        handler = RecordingHandler()
        handler.path = "/ttyd3"
        with patch.object(RecordingHandler, "handle_ttyd") as mock_ttyd:
            handler.do_GET()
        mock_ttyd.assert_called_once_with(3)

    def test_normal_ttyd_subpath_routes_to_proxy(self):
        handler = RecordingHandler()
        handler.path = "/ttyd3/ws"
        with patch.object(RecordingHandler, "handle_ttyd_proxy") as mock_proxy:
            handler.do_GET()
        mock_proxy.assert_called_once_with(3)


class TestDeleteRouting(unittest.TestCase):
    def test_overlong_delete_id_returns_404(self):
        handler = RecordingHandler()
        handler.path = "/terminals/" + OVERLONG
        # Must not raise (the bug raised ValueError pre-auth).
        handler.do_DELETE()
        self.assertEqual(handler.response, (404, {"error": "Not found"}))

    def test_normal_delete_id_routes(self):
        handler = RecordingHandler()
        handler.path = "/terminals/5"
        with patch.object(RecordingHandler, "handle_terminals_delete") as mock_del:
            handler.do_DELETE()
        mock_del.assert_called_once_with(5)


if __name__ == "__main__":
    unittest.main()
