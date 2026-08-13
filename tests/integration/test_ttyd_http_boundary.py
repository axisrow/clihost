"""Socket-level coverage for the real ttyd proxy auth/CSRF boundary."""
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from ttydproxy.app import AppLimiters, AppSettings, create_app
from ttydproxy.ratelimit import RateLimiter
from ttydproxy.security import build_csrf_token, build_session_token


class FakeManager:
    def __init__(self):
        self.create_calls = 0

    def list_terminals(self):
        return []

    def create_terminal(self, wait=False):
        self.create_calls += 1
        return {"id": 1, "port": 7681}


class TTYDHTTPBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.settings = AppSettings(password_secret="socket-test-secret")
        self.manager = FakeManager()
        limiters = AppLimiters(
            login=RateLimiter(max_attempts=5, window_seconds=60),
            account=RateLimiter(max_attempts=5, window_seconds=300),
        )
        handler = create_app(self.settings, self.manager, limiters)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, *, headers=None, body=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        result = response.status, dict(response.getheaders()), payload
        connection.close()
        return result

    def test_browser_route_redirects_without_session(self):
        status, headers, _body = self.request("GET", "/")
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], "/login")

    def test_api_route_rejects_missing_session(self):
        status, _headers, body = self.request("GET", "/terminals")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"error": "Authentication required"})

    def test_login_rejects_missing_csrf_at_http_boundary(self):
        body = b"username=alice&password=irrelevant"
        status, _headers, response_body = self.request(
            "POST",
            "/login",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(response_body), {"error": "CSRF token missing"})

    def test_mutating_route_rejects_missing_csrf_before_manager_call(self):
        session = build_session_token(
            "alice", self.settings.password_secret, self.settings.session_timeout
        )
        with patch("ttydproxy.app.user_exists", return_value=True):
            status, _headers, body = self.request(
                "POST", "/terminals", headers={"Cookie": f"ttyd_session={session}"}
            )

        self.assertEqual(status, 419)
        self.assertEqual(
            json.loads(body), {"error": "CSRF token missing — please refresh the page"}
        )
        self.assertEqual(self.manager.create_calls, 0)

    def test_mutating_route_accepts_matching_signed_csrf_token(self):
        session = build_session_token(
            "alice", self.settings.password_secret, self.settings.session_timeout
        )
        csrf = build_csrf_token(self.settings.password_secret)
        headers = {
            "Cookie": f"ttyd_session={session}; csrf_token={csrf}",
            "X-CSRF-Token": csrf,
        }
        with patch("ttydproxy.app.user_exists", return_value=True):
            status, _headers, body = self.request("POST", "/terminals", headers=headers)

        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"id": 1, "port": 7681})
        self.assertEqual(self.manager.create_calls, 1)


if __name__ == "__main__":
    unittest.main()
