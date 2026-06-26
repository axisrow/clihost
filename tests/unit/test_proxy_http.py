"""Tests for proxy_ttyd_http: request-body framing (B4) and case-insensitive
Content-Type handling (B6).

These exercise the real proxy_ttyd_http against a fake upstream HTTPConnection
so we can observe (a) whether a client body is dropped/forwarded and which 4xx
is returned, and (b) which response headers (CSP) the proxy sends.
"""
import io
import unittest
from unittest.mock import patch

from ttydproxy import proxy
from ttydproxy.proxy import TTYD_PROXY_HTML_CSP


class FakeResponse:
    def __init__(self, status=200, reason="OK", headers=None, body=b""):
        self.status = status
        self.reason = reason
        self._headers = headers or []
        self._body = body

    def read(self):
        return self._body

    def getheaders(self):
        return self._headers


class FakeConn:
    """Captures the body/method/path passed to conn.request(...)."""

    last_body = "UNSET"
    last_method = None
    last_path = None
    response = None

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port

    def request(self, method, path, body=None, headers=None):
        FakeConn.last_body = body
        FakeConn.last_method = method
        FakeConn.last_path = path

    def getresponse(self):
        return FakeConn.response

    def close(self):
        pass


class StubHandler:
    """Minimal BaseHTTPRequestHandler surface used by proxy_ttyd_http."""

    def __init__(self, headers=None, body=b"", command="POST"):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)
        self.command = command
        self.client_address = ("127.0.0.1", 12345)
        self.request_version = "HTTP/1.1"
        self.json_response = None
        self.status_line = None
        self.sent_headers = []
        self.ended = False
        self.wfile = io.BytesIO()

    def send_json(self, status, data):
        self.json_response = (status, data)

    def send_response(self, status, reason=None):
        self.status_line = (status, reason)

    def send_header(self, key, value):
        self.sent_headers.append((key, value))

    def end_headers(self):
        self.ended = True

    def headers_named(self, name):
        return [v for k, v in self.sent_headers if k.lower() == name.lower()]


def _reset_conn(response):
    FakeConn.last_body = "UNSET"
    FakeConn.last_method = None
    FakeConn.last_path = None
    FakeConn.response = response


class TestRequestBodyFraming(unittest.TestCase):
    """B4: a client-supplied body must never be silently dropped."""

    def setUp(self):
        _reset_conn(FakeResponse(headers=[("Content-Type", "text/plain")], body=b"ok"))

    def _run(self, handler):
        with patch.object(proxy.http.client, "HTTPConnection", FakeConn):
            proxy.proxy_ttyd_http(handler, "/", 7681)

    def test_non_numeric_content_length_returns_400(self):
        handler = StubHandler(headers={"Content-Length": "abc"}, body=b"BODYDATA")
        self._run(handler)
        self.assertEqual(handler.json_response, (400, {"error": "Invalid Content-Length"}))
        # The body must NOT have been forwarded to ttyd.
        self.assertEqual(FakeConn.last_body, "UNSET")

    def test_oversize_content_length_returns_413(self):
        handler = StubHandler(headers={"Content-Length": "20000000"}, body=b"x")
        self._run(handler)
        self.assertEqual(handler.json_response, (413, {"error": "Request too large"}))
        self.assertEqual(FakeConn.last_body, "UNSET")

    def test_chunked_without_content_length_returns_411(self):
        handler = StubHandler(
            headers={"Transfer-Encoding": "chunked"}, body=b"BODYDATA"
        )
        self._run(handler)
        self.assertEqual(handler.json_response, (411, {"error": "Length required"}))
        self.assertEqual(FakeConn.last_body, "UNSET")

    def test_valid_body_is_forwarded(self):
        handler = StubHandler(headers={"Content-Length": "8"}, body=b"BODYDATA")
        self._run(handler)
        self.assertIsNone(handler.json_response)
        self.assertEqual(FakeConn.last_body, b"BODYDATA")

    def test_no_body_no_content_length_is_forwarded(self):
        # A plain GET-like request with no body must still proxy (body=None).
        handler = StubHandler(headers={}, body=b"", command="GET")
        self._run(handler)
        self.assertIsNone(handler.json_response)
        self.assertIsNone(FakeConn.last_body)


class TestContentTypeCaseInsensitivity(unittest.TestCase):
    """B6: Content-Type matching must be case-insensitive for CSP + injection."""

    def _run_with_content_type(self, ctype):
        html = b"<html><head></head><body>x</body></html>"
        _reset_conn(
            FakeResponse(
                headers=[
                    ("Content-Type", ctype),
                    ("Content-Security-Policy", "default-src *"),
                ],
                body=html,
            )
        )
        handler = StubHandler(headers={}, command="GET")
        with patch.object(proxy.http.client, "HTTPConnection", FakeConn):
            proxy.proxy_ttyd_http(handler, "/", 7681)
        return handler

    def test_lowercase_content_type_applies_hardened_csp(self):
        handler = self._run_with_content_type("text/html; charset=utf-8")
        csps = handler.headers_named("Content-Security-Policy")
        self.assertIn(TTYD_PROXY_HTML_CSP, csps)
        self.assertNotIn("default-src *", csps)

    def test_uppercase_content_type_applies_hardened_csp(self):
        handler = self._run_with_content_type("Text/HTML; charset=utf-8")
        csps = handler.headers_named("Content-Security-Policy")
        self.assertIn(TTYD_PROXY_HTML_CSP, csps)
        self.assertNotIn("default-src *", csps)


if __name__ == "__main__":
    unittest.main()
