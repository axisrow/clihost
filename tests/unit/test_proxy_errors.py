"""Regression tests for diagnostic handling in ttyd proxy failure paths."""
import contextlib
import gzip
import http.client
import io
import socket
import unittest
from unittest.mock import patch

from ttydproxy import proxy


class StubWebSocketHandler:
    command = "GET"
    request_version = "HTTP/1.1"
    client_address = ("127.0.0.1", 12345)
    headers = {"Upgrade": "websocket", "Cookie": "ttyd_session=secret"}

    def __init__(self):
        self.close_connection = False
        self.json_response = None

    def send_json(self, status, data):
        self.json_response = (status, data)


class FailingHandshakeSocket:
    def sendall(self, _data):
        raise RuntimeError("Cookie: ttyd_session=do-not-log")

    def shutdown(self, _how):
        pass

    def close(self):
        pass


class FailingCloseConnection:
    def request(self, _method, _path, body=None, headers=None):
        pass

    def getresponse(self):
        response = type("Response", (), {})()
        response.status = 200
        response.reason = "OK"
        response.read = lambda: b"ok"
        response.getheaders = lambda: [("Content-Type", "text/plain")]
        return response

    def close(self):
        raise RuntimeError("Authorization: Bearer do-not-log")


class MalformedResponseConnection:
    """Simulates ttyd sending a response so malformed http.client raises
    HTTPException while reading it. HTTPException does NOT subclass OSError,
    so it needs its own handling alongside the existing OSError catch."""

    def request(self, _method, _path, body=None, headers=None):
        pass

    def getresponse(self):
        raise http.client.LineTooLong("Authorization: Bearer do-not-log")

    def close(self):
        pass


class TestProxyUnexpectedErrors(unittest.TestCase):
    def test_html_injection_logs_unexpected_error_without_exception_text(self):
        original = gzip.compress(b"<html><head></head></html>")
        stderr = io.StringIO()

        with patch.object(
            proxy.gzip,
            "compress",
            side_effect=RuntimeError("Cookie: ttyd_session=do-not-log"),
        ), contextlib.redirect_stderr(stderr):
            self.assertEqual(proxy.inject_tab_fix_script(original), original)

        log = stderr.getvalue()
        self.assertIn("operation=html-injection", log)
        self.assertIn("RuntimeError", log)
        self.assertNotIn("do-not-log", log)

    def test_tunnel_logs_unexpected_error_with_route_and_port(self):
        client, client_peer = socket.socketpair()
        upstream, upstream_peer = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(client_peer.close)
        self.addCleanup(upstream.close)
        self.addCleanup(upstream_peer.close)
        handler = type("Handler", (), {"connection": client})()
        stderr = io.StringIO()

        with patch.object(
            proxy.select,
            "select",
            side_effect=RuntimeError("token=do-not-log"),
        ), contextlib.redirect_stderr(stderr):
            proxy.tunnel_sockets(
                handler, upstream, upstream_path="/ws?token=secret", port=7681
            )

        log = stderr.getvalue()
        self.assertIn("operation=websocket-tunnel", log)
        self.assertIn("route=/ws", log)
        self.assertIn("port=7681", log)
        self.assertNotIn("secret", log)
        self.assertNotIn("do-not-log", log)

    def test_websocket_handshake_logs_unexpected_error(self):
        handler = StubWebSocketHandler()
        stderr = io.StringIO()

        with patch.object(
            proxy.socket, "create_connection", return_value=FailingHandshakeSocket()
        ), contextlib.redirect_stderr(stderr):
            proxy.proxy_ttyd_websocket(handler, "/ws?token=secret", 7681)

        log = stderr.getvalue()
        self.assertIn("operation=websocket-unexpected", log)
        self.assertIn("route=/ws", log)
        self.assertIn("port=7681", log)
        self.assertNotIn("secret", log)
        self.assertNotIn("do-not-log", log)

    def test_http_close_logs_unexpected_error_without_exception_text(self):
        handler = type(
            "Handler",
            (),
            {
                "headers": {},
                "command": "GET",
                "client_address": ("127.0.0.1", 12345),
                "rfile": io.BytesIO(),
                "wfile": io.BytesIO(),
                "send_response": lambda self, status, reason=None: None,
                "send_header": lambda self, key, value: None,
                "end_headers": lambda self: None,
            },
        )()
        stderr = io.StringIO()

        with patch.object(
            proxy.http.client,
            "HTTPConnection",
            return_value=FailingCloseConnection(),
        ), contextlib.redirect_stderr(stderr):
            proxy.proxy_ttyd_http(handler, "/?token=secret", 7681)

        log = stderr.getvalue()
        self.assertIn("operation=http-close", log)
        self.assertIn("route=/", log)
        self.assertIn("port=7681", log)
        self.assertNotIn("secret", log)
        self.assertNotIn("do-not-log", log)

    def test_http_malformed_upstream_response_returns_502_without_exception_text(self):
        handler = type(
            "Handler",
            (),
            {
                "headers": {},
                "command": "GET",
                "client_address": ("127.0.0.1", 12345),
                "rfile": io.BytesIO(),
                "wfile": io.BytesIO(),
                "json_response": None,
                "send_json": lambda self, status, data: setattr(
                    self, "json_response", (status, data)
                ),
            },
        )()
        stderr = io.StringIO()

        with patch.object(
            proxy.http.client,
            "HTTPConnection",
            return_value=MalformedResponseConnection(),
        ), contextlib.redirect_stderr(stderr):
            proxy.proxy_ttyd_http(handler, "/?token=secret", 7681)

        self.assertEqual(handler.json_response, (502, {"error": "TTYD unavailable"}))

        log = stderr.getvalue()
        self.assertIn("operation=http-upstream", log)
        self.assertIn("route=/", log)
        self.assertIn("port=7681", log)
        self.assertNotIn("secret", log)
        self.assertNotIn("do-not-log", log)


if __name__ == "__main__":
    unittest.main()
