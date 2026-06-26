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
            for key in ("SESSION_TIMEOUT", "CSRF_TOKEN_TTL"):
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


class TestSessionTokenSurvivesFlooredTimeout(unittest.TestCase):
    """End-to-end contract: a token built with the floored default round-trips."""

    def test_roundtrip_with_default_timeout(self):
        secret = "secret"
        token = security.build_session_token("alice", secret, 604800)
        self.assertEqual(security.parse_session_token(token, secret), "alice")


if __name__ == "__main__":
    unittest.main()
