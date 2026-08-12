"""Tests for the POST /upload handler and binary body reading."""
import io
import unittest
from unittest.mock import patch

from tests.unit.handler_stubs import RecordingHandler
from ttydproxy.config import TTYD_USER, UPLOAD_DIR

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


class TestReadBinaryRequestBody(unittest.TestCase):
    def _handler(self, body=b"", content_length=None):
        handler = RecordingHandler()
        handler.headers = {} if content_length is None else {"Content-Length": content_length}
        handler.rfile = io.BytesIO(body)
        return handler

    def test_missing_content_length_returns_empty(self):
        handler = self._handler(b"ignored")
        self.assertEqual(handler._read_binary_request_body(100), b"")
        self.assertIsNone(handler.response)

    def test_invalid_content_length(self):
        handler = self._handler(content_length="abc")
        self.assertIsNone(handler._read_binary_request_body(100))
        self.assertEqual(handler.response, (400, {"error": "Invalid Content-Length"}))

    def test_negative_content_length(self):
        handler = self._handler(content_length="-1")
        self.assertIsNone(handler._read_binary_request_body(100))
        self.assertEqual(handler.response, (413, {"error": "Request too large"}))

    def test_oversized_body(self):
        handler = self._handler(b"x" * 101, content_length="101")
        self.assertIsNone(handler._read_binary_request_body(100))
        self.assertEqual(handler.response, (413, {"error": "Request too large"}))

    def test_body_at_exact_limit(self):
        handler = self._handler(b"x" * 100, content_length="100")
        self.assertEqual(handler._read_binary_request_body(100), b"x" * 100)

    def test_returns_raw_bytes(self):
        handler = self._handler(PNG_BYTES, content_length=str(len(PNG_BYTES)))
        self.assertEqual(handler._read_binary_request_body(100), PNG_BYTES)


class TestHandleUpload(unittest.TestCase):
    def _handler(self, body):
        handler = RecordingHandler()
        handler._read_binary_request_body = lambda max_size: body
        return handler

    def _assert_rejected_before_body(self, **overrides):
        """handle_upload must bail before reading the body or saving."""
        handler = RecordingHandler()
        for name, stub in overrides.items():
            setattr(handler, name, stub)

        def fail_read(max_size):
            self.fail("body must not be read before auth/CSRF pass")

        handler._read_binary_request_body = fail_read
        with patch("ttydproxy.app.save_upload") as mock_save:
            handler.handle_upload()
        mock_save.assert_not_called()

    def test_requires_auth_and_never_reads_body(self):
        self._assert_rejected_before_body(_check_auth=lambda redirect=False: None)

    def test_requires_csrf(self):
        self._assert_rejected_before_body(_check_csrf=lambda: False)

    @patch("ttydproxy.app.save_upload")
    def test_body_error_already_responded(self, mock_save):
        handler = self._handler(None)
        handler.handle_upload()
        self.assertIsNone(handler.response)
        mock_save.assert_not_called()

    @patch("ttydproxy.app.save_upload")
    def test_empty_body(self, mock_save):
        handler = self._handler(b"")
        handler.handle_upload()
        self.assertEqual(handler.response, (400, {"error": "Empty upload"}))
        mock_save.assert_not_called()

    @patch("ttydproxy.app.save_upload", side_effect=ValueError("Unsupported image type"))
    def test_non_image_rejected(self, mock_save):
        # save_upload is the single validator; its ValueError maps to 415.
        handler = self._handler(b"not an image")
        handler.handle_upload()
        self.assertEqual(handler.response, (415, {"error": "Unsupported image type"}))

    @patch("ttydproxy.app.save_upload")
    def test_valid_png_saved(self, mock_save):
        mock_save.return_value = "/home/hapi/uploads/img-20260611-120000-deadbeef.png"
        handler = self._handler(PNG_BYTES)
        handler.handle_upload()
        self.assertEqual(
            handler.response,
            (201, {"path": "/home/hapi/uploads/img-20260611-120000-deadbeef.png"}),
        )
        mock_save.assert_called_once_with(PNG_BYTES, UPLOAD_DIR, TTYD_USER)

    @patch("ttydproxy.app.save_upload", side_effect=OSError("disk full"))
    def test_save_failure(self, mock_save):
        handler = self._handler(PNG_BYTES)
        handler.handle_upload()
        self.assertEqual(handler.response, (500, {"error": "Failed to save upload"}))


class TestUploadRouting(unittest.TestCase):
    def test_post_upload_dispatches_to_handler(self):
        handler = RecordingHandler()
        handler.path = "/upload"
        called = []
        handler.handle_upload = lambda: called.append(True)
        handler.do_POST()
        self.assertEqual(called, [True])


class TestTerminalPageCsrfRefresh(unittest.TestCase):
    """handle_ttyd must refresh the csrf_token cookie so long-lived terminal
    tabs can keep uploading images after the original token expires."""

    @patch("ttydproxy.app.render_terminal_page", return_value="<html></html>")
    def test_terminal_page_sets_csrf_cookie(self, _mock_render):
        handler = RecordingHandler()
        handler.manager.get_terminal.return_value = {"id": 1, "port": 7681}
        handler.path = "/ttyd1"
        captured = {}

        def record_html(status, html, extra_headers=None, csp=None):
            captured["status"] = status
            captured["extra_headers"] = extra_headers

        handler.send_html = record_html
        handler.handle_ttyd(1)

        self.assertEqual(captured["status"], 200)
        headers = captured["extra_headers"] or {}
        self.assertTrue(
            headers.get("Set-Cookie", "").startswith("csrf_token="),
            f"csrf_token cookie not refreshed: {headers}",
        )


if __name__ == "__main__":
    unittest.main()
