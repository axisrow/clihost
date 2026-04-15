"""Tests for cleanup API handlers."""
import unittest
from unittest.mock import patch

from ttydproxy.app import TTYDProxyHandler


class RecordingCleanupHandler(TTYDProxyHandler):
    def __init__(self):
        self.response = None

    def send_json(self, status, data, extra_headers=None):
        del extra_headers
        self.response = (status, data)

    def _check_auth(self, redirect=False):
        del redirect
        return "alice"

    def _check_csrf(self):
        return True


class TestCleanupAPI(unittest.TestCase):
    @patch("ttydproxy.app.summarize_cleanup_targets")
    @patch("ttydproxy.app.list_cleanup_targets")
    def test_handle_cleanup_list(self, mock_list_cleanup_targets, mock_summarize_cleanup_targets):
        mock_list_cleanup_targets.return_value = [{"id": "cache-home", "label": "~/.cache"}]
        mock_summarize_cleanup_targets.return_value = {"count": 1, "total_size_bytes": 128, "total_size_human": "128 B"}

        handler = RecordingCleanupHandler()
        handler.handle_cleanup_list()

        self.assertEqual(
            handler.response,
            (
                200,
                {
                    "targets": [{"id": "cache-home", "label": "~/.cache"}],
                    "summary": {"count": 1, "total_size_bytes": 128, "total_size_human": "128 B"},
                },
            ),
        )

    @patch("ttydproxy.app.delete_cleanup_targets")
    def test_handle_cleanup_delete(self, mock_delete_cleanup_targets):
        mock_delete_cleanup_targets.return_value = {"deleted": [{"id": "cache-home", "label": "~/.cache"}], "skipped": [], "errors": []}

        handler = RecordingCleanupHandler()
        handler._load_json_payload = lambda: {"ids": ["cache-home"]}
        handler.handle_cleanup_delete()

        self.assertEqual(
            handler.response,
            (200, {"deleted": [{"id": "cache-home", "label": "~/.cache"}], "skipped": [], "errors": []}),
        )

    def test_handle_cleanup_delete_rejects_invalid_ids(self):
        handler = RecordingCleanupHandler()
        handler._load_json_payload = lambda: {"ids": "cache-home"}
        handler.handle_cleanup_delete()

        self.assertEqual(handler.response, (400, {"error": "ids must be a non-empty array"}))

    def test_handle_cleanup_delete_rejects_too_many_ids(self):
        handler = RecordingCleanupHandler()
        handler._load_json_payload = lambda: {"ids": [f"id-{index}" for index in range(51)]}
        handler.handle_cleanup_delete()

        self.assertEqual(handler.response, (400, {"error": "ids must contain at most 50 items"}))

    def test_handle_cleanup_delete_rejects_too_long_ids(self):
        handler = RecordingCleanupHandler()
        handler._load_json_payload = lambda: {"ids": ["x" * 129]}
        handler.handle_cleanup_delete()

        self.assertEqual(
            handler.response,
            (400, {"error": "ids must be at most 128 characters long"}),
        )

    @patch("ttydproxy.app.delete_cleanup_targets")
    def test_handle_cleanup_delete_allows_duplicate_ids(self, mock_delete_cleanup_targets):
        mock_delete_cleanup_targets.return_value = {"deleted": [{"id": "cache-home", "label": "~/.cache"}], "skipped": [], "errors": []}

        handler = RecordingCleanupHandler()
        handler._load_json_payload = lambda: {"ids": ["cache-home", "cache-home"]}
        handler.handle_cleanup_delete()

        mock_delete_cleanup_targets.assert_called_once_with(["cache-home", "cache-home"], unittest.mock.ANY, unittest.mock.ANY)


if __name__ == "__main__":
    unittest.main()
