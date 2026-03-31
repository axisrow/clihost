"""Tests for shared HTTP response headers."""
import io
import unittest

from server import COMMON_SECURITY_HEADERS, DEFAULT_HTML_CSP, BaseHTTPHandler


class RecordingHandler(BaseHTTPHandler):
    def __init__(self):
        self.headers_sent = []
        self.wfile = io.BytesIO()

    def send_response(self, status, message=None):
        self.status = status

    def send_header(self, key, value):
        self.headers_sent.append((key, value))

    def end_headers(self):
        self.finished = True


class TestSendHTML(unittest.TestCase):
    def test_send_html_includes_common_headers_and_extra_headers(self):
        handler = RecordingHandler()
        handler.send_html(200, "<p>ok</p>", extra_headers={"Set-Cookie": "csrf_token=abc"})

        headers = dict(handler.headers_sent)
        self.assertEqual(handler.status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Content-Security-Policy"], DEFAULT_HTML_CSP)
        self.assertEqual(headers["Set-Cookie"], "csrf_token=abc")
        for key, value in COMMON_SECURITY_HEADERS.items():
            self.assertEqual(headers[key], value)

    def test_send_json_includes_common_headers(self):
        handler = RecordingHandler()
        handler.send_json(201, {"ok": True})

        headers = dict(handler.headers_sent)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Cache-Control"], "no-cache")


if __name__ == "__main__":
    unittest.main()
