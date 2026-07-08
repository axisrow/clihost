"""Tests for TTYDProxyHandler._check_auth redirect semantics (#101/#5).

A valid session cookie whose backing account was since removed/renamed must, on
a browser navigation (redirect=True), be sent to /login like the no-token case —
not handed a raw 403 JSON blob. The no-token branch already redirected; the
removed-user branch used to ignore the flag.
"""
import unittest
from unittest.mock import patch

from ttydproxy import app
from ttydproxy.app import TTYDProxyHandler


class AuthProbeHandler(TTYDProxyHandler):
    """Bare handler exercising the REAL _check_auth, recording every response."""

    def __init__(self, username):
        self._username = username
        self.json_response = None
        self.status = None
        self.headers_sent = {}
        self.ended = False

    def _session_username(self):
        return self._username

    def send_json(self, status, data, extra_headers=None):
        del extra_headers
        self.json_response = (status, data)

    def send_response(self, status, message=None):
        self.status = status

    def send_header(self, key, value):
        self.headers_sent[key] = value

    def end_headers(self):
        self.ended = True


class CheckAuthRedirectTest(unittest.TestCase):
    def test_removed_user_redirects_when_redirect_true(self):
        handler = AuthProbeHandler("ghost")
        with patch.object(app, "user_exists", return_value=False):
            result = handler._check_auth(redirect=True)
        self.assertIsNone(result)
        self.assertEqual(handler.status, 302)
        self.assertEqual(handler.headers_sent.get("Location"), "/login")
        self.assertTrue(handler.ended)
        self.assertIsNone(handler.json_response, "must not emit 403 JSON on a browser nav")

    def test_removed_user_returns_403_json_when_redirect_false(self):
        handler = AuthProbeHandler("ghost")
        with patch.object(app, "user_exists", return_value=False):
            result = handler._check_auth(redirect=False)
        self.assertIsNone(result)
        self.assertEqual(handler.json_response, (403, {"error": "Invalid session"}))
        self.assertIsNone(handler.status, "must not redirect for a non-browser (API) call")

    def test_valid_user_returns_username(self):
        handler = AuthProbeHandler("alice")
        with patch.object(app, "user_exists", return_value=True):
            self.assertEqual(handler._check_auth(redirect=True), "alice")

    def test_no_token_still_redirects(self):
        # The pre-existing no-token behavior must be unchanged.
        handler = AuthProbeHandler(None)
        result = handler._check_auth(redirect=True)
        self.assertIsNone(result)
        self.assertEqual(handler.status, 302)
        self.assertEqual(handler.headers_sent.get("Location"), "/login")

    def test_no_token_returns_401_json_when_redirect_false(self):
        handler = AuthProbeHandler(None)
        result = handler._check_auth(redirect=False)
        self.assertIsNone(result)
        self.assertEqual(handler.json_response, (401, {"error": "Authentication required"}))


if __name__ == "__main__":
    unittest.main()
