"""TTL config settings must be floored to a sane minimum (B1).

A negative SESSION_TIMEOUT (operator typo) otherwise produces session tokens
that are already expired at issue time, locking out every successful login. The
fix applies minimum=1 to the TTL settings in config.py, so a non-positive value
is clamped UP to the minimum (1s) — fail-closed: the access window shrinks to
almost nothing rather than silently expanding to the week-long default.
"""
import importlib
import os
import unittest
from unittest.mock import patch

from ttydproxy import security


class TestConfigTimeoutFloor(unittest.TestCase):
    def _reload_config_with(self, **env):
        with patch.dict(os.environ, env, clear=False):
            config = importlib.import_module("ttydproxy.config")
            return importlib.reload(config)

    def tearDown(self):
        # Restore module to a pristine (env-free) state for other tests.
        config = importlib.import_module("ttydproxy.config")
        with patch.dict(os.environ, {}, clear=False):
            for key in ("SESSION_TIMEOUT", "CSRF_TOKEN_TTL", "REQUEST_TIMEOUT"):
                os.environ.pop(key, None)
            importlib.reload(config)

    def test_negative_session_timeout_clamps_to_minimum(self):
        # Fail-closed: a non-positive auth TTL shrinks to 1s, NOT the week-long
        # default — a typo must not silently widen the access window.
        config = self._reload_config_with(SESSION_TIMEOUT="-1")
        self.assertEqual(config.SESSION_TIMEOUT, 1)

    def test_zero_csrf_ttl_clamps_to_minimum(self):
        config = self._reload_config_with(CSRF_TOKEN_TTL="0")
        self.assertEqual(config.CSRF_TOKEN_TTL, 1)

    def test_positive_values_are_kept(self):
        config = self._reload_config_with(
            SESSION_TIMEOUT="3600", CSRF_TOKEN_TTL="7200"
        )
        self.assertEqual(config.SESSION_TIMEOUT, 3600)
        self.assertEqual(config.CSRF_TOKEN_TTL, 7200)


class TestRequestTimeout(unittest.TestCase):
    """Slowloris guard: the per-connection read timeout must be set + fail-closed."""

    def _reload_config_with(self, **env):
        with patch.dict(os.environ, env, clear=False):
            config = importlib.import_module("ttydproxy.config")
            return importlib.reload(config)

    def tearDown(self):
        config = importlib.import_module("ttydproxy.config")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REQUEST_TIMEOUT", None)
            importlib.reload(config)

    def test_default_request_timeout_is_positive(self):
        config = self._reload_config_with()
        self.assertEqual(config.REQUEST_TIMEOUT, 30)

    def test_zero_request_timeout_clamps_to_minimum(self):
        # 0 would mean "block forever" — the very slowloris condition the timeout
        # exists to prevent. A non-positive value must clamp up, not disable it.
        config = self._reload_config_with(REQUEST_TIMEOUT="0")
        self.assertEqual(config.REQUEST_TIMEOUT, 1)

    def test_handler_applies_the_timeout(self):
        # BaseHTTPRequestHandler.setup() calls connection.settimeout(self.timeout);
        # the proxy handler must carry a positive class-level timeout so slow
        # clients cannot pin a ThreadingHTTPServer worker forever (#101/#2).
        # Assert it is wired to the config value (not merely positive) so a
        # regression that hard-codes or drops the wiring is caught.
        from ttydproxy import app, config
        self.assertIsNotNone(app.TTYDProxyHandler.timeout)
        self.assertGreater(app.TTYDProxyHandler.timeout, 0)
        self.assertEqual(app.TTYDProxyHandler.timeout, config.REQUEST_TIMEOUT)


class TestSessionTokenSurvivesFlooredTimeout(unittest.TestCase):
    """End-to-end contract: a token built with the floored default round-trips."""

    def test_roundtrip_with_default_timeout(self):
        secret = "secret"
        token = security.build_session_token("alice", secret, 604800)
        self.assertEqual(security.parse_session_token(token, secret), "alice")


if __name__ == "__main__":
    unittest.main()
