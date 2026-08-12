"""Shared test stubs for TTYDProxyHandler-based API tests."""
import time
from unittest.mock import MagicMock

from ttydproxy.app import AppContext, AppLimiters, AppSettings, TTYDProxyHandler


class RecordingHandler(TTYDProxyHandler):
    """Handler stub that skips socket setup, passes auth/CSRF, and records
    the JSON response as (status, data)."""

    def __init__(self):
        self.response = None
        self.context = AppContext(
            settings=AppSettings(),
            manager=MagicMock(),
            limiters=AppLimiters(login=MagicMock(), account=MagicMock()),
            server_start_time=time.time(),
        )

    def send_json(self, status, data, extra_headers=None):
        del extra_headers
        self.response = (status, data)

    def _check_auth(self, redirect=False):
        del redirect
        return "alice"

    def _check_csrf(self):
        return True
