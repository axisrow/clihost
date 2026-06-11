"""Shared test stubs for TTYDProxyHandler-based API tests."""
from ttydproxy.app import TTYDProxyHandler


class RecordingHandler(TTYDProxyHandler):
    """Handler stub that skips socket setup, passes auth/CSRF, and records
    the JSON response as (status, data)."""

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
