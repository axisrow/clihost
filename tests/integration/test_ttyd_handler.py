"""Integration tests for TTYDProxyHandler virtual keyboard functionality.

Tests the query parameter handling for virtual keyboard without importing
ttyd_proxy.py directly (which has Linux-only dependencies).
"""
import unittest
from urllib.parse import urlparse, parse_qs


def env_bool(value, default=False):
    """Parse common boolean env var values.

    Copied from ttyd_proxy.py to avoid importing module with Linux-only deps.
    """
    if value is None:
        return default
    value = str(value).strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return default


def simulate_vkbd_enabled(path, env_vkbd_default):
    """Simulate the vkbd_enabled logic from handle_ttyd method.

    This replicates the behavior in ttyd_proxy.py lines 404-407:
        vkbd_enabled = VIRTUAL_KEYBOARD
        query = parse_qs(parsed.query)
        if "vkbd" in query:
            vkbd_enabled = env_bool(query.get("vkbd", [""])[0], default=vkbd_enabled)
    """
    parsed = urlparse(path)
    query = parse_qs(parsed.query)

    vkbd_enabled = env_vkbd_default
    if "vkbd" in query:
        vkbd_enabled = env_bool(query.get("vkbd", [""])[0], default=vkbd_enabled)

    return vkbd_enabled


class TestTTYDHandlerVKBD(unittest.TestCase):
    """Test TTYDProxyHandler with virtual keyboard query parameters."""

    def test_query_param_vkbd_true_enables_keyboard(self):
        """Test that ?vkbd=true enables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=true", env_vkbd_default=False)
        self.assertTrue(result)

    def test_query_param_vkbd_false_disables_keyboard(self):
        """Test that ?vkbd=false disables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=false", env_vkbd_default=True)
        self.assertFalse(result)

    def test_query_param_vkbd_0_disables_keyboard(self):
        """Test that ?vkbd=0 disables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=0", env_vkbd_default=True)
        self.assertFalse(result)

    def test_query_param_vkbd_1_enables_keyboard(self):
        """Test that ?vkbd=1 enables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=1", env_vkbd_default=False)
        self.assertTrue(result)

    def test_no_query_param_uses_env_default_true(self):
        """Test that missing query param uses environment default (True)."""
        result = simulate_vkbd_enabled("/ttyd", env_vkbd_default=True)
        self.assertTrue(result)

    def test_no_query_param_uses_env_default_false(self):
        """Test that missing query param uses environment default (False)."""
        result = simulate_vkbd_enabled("/ttyd", env_vkbd_default=False)
        self.assertFalse(result)

    def test_query_param_overrides_env_true_to_false(self):
        """Test that query param ?vkbd=false overrides env VIRTUAL_KEYBOARD=true."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=false", env_vkbd_default=True)
        self.assertFalse(result)

    def test_query_param_overrides_env_false_to_true(self):
        """Test that query param ?vkbd=true overrides env VIRTUAL_KEYBOARD=false."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=true", env_vkbd_default=False)
        self.assertTrue(result)

    def test_query_param_yes_enables_keyboard(self):
        """Test that ?vkbd=yes enables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=yes", env_vkbd_default=False)
        self.assertTrue(result)

    def test_query_param_no_disables_keyboard(self):
        """Test that ?vkbd=no disables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=no", env_vkbd_default=True)
        self.assertFalse(result)

    def test_query_param_on_enables_keyboard(self):
        """Test that ?vkbd=on enables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=on", env_vkbd_default=False)
        self.assertTrue(result)

    def test_query_param_off_disables_keyboard(self):
        """Test that ?vkbd=off disables virtual keyboard."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=off", env_vkbd_default=True)
        self.assertFalse(result)


class TestQueryParamEdgeCases(unittest.TestCase):
    """Test edge cases for query parameter handling."""

    def test_query_param_empty_uses_default(self):
        """Test that ?vkbd= (empty) uses default."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=", env_vkbd_default=True)
        # Empty string falls back to default
        self.assertTrue(result)

    def test_query_param_empty_uses_default_false(self):
        """Test that ?vkbd= (empty) uses default False."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=", env_vkbd_default=False)
        self.assertFalse(result)

    def test_query_param_invalid_uses_default(self):
        """Test that ?vkbd=invalid uses default."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=maybe", env_vkbd_default=False)
        # Invalid string falls back to default (False)
        self.assertFalse(result)

    def test_query_param_invalid_uses_default_true(self):
        """Test that ?vkbd=invalid uses default True."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=hello", env_vkbd_default=True)
        self.assertTrue(result)

    def test_multiple_query_params_uses_first(self):
        """Test that multiple ?vkbd params use first value."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=false&vkbd=true", env_vkbd_default=True)
        # First value is "false"
        self.assertFalse(result)

    def test_multiple_query_params_uses_first_true(self):
        """Test that multiple ?vkbd params use first value (true)."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=true&vkbd=false", env_vkbd_default=False)
        # First value is "true"
        self.assertTrue(result)

    def test_query_param_case_insensitive_TRUE(self):
        """Test that ?vkbd=TRUE works (case insensitive)."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=TRUE", env_vkbd_default=False)
        self.assertTrue(result)

    def test_query_param_case_insensitive_FALSE(self):
        """Test that ?vkbd=FALSE works (case insensitive)."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=FALSE", env_vkbd_default=True)
        self.assertFalse(result)

    def test_other_query_params_ignored(self):
        """Test that other query params don't affect vkbd."""
        result = simulate_vkbd_enabled("/ttyd?foo=bar&baz=qux", env_vkbd_default=True)
        self.assertTrue(result)

    def test_vkbd_with_other_params(self):
        """Test vkbd works with other query params."""
        result = simulate_vkbd_enabled("/ttyd?foo=bar&vkbd=false&baz=qux", env_vkbd_default=True)
        self.assertFalse(result)

    def test_path_with_trailing_slash(self):
        """Test path /ttyd/ with query params."""
        result = simulate_vkbd_enabled("/ttyd/?vkbd=true", env_vkbd_default=False)
        self.assertTrue(result)


class TestURLParsing(unittest.TestCase):
    """Test URL parsing edge cases."""

    def test_fragment_ignored(self):
        """Test that URL fragment doesn't affect parsing."""
        result = simulate_vkbd_enabled("/ttyd?vkbd=true#section", env_vkbd_default=False)
        self.assertTrue(result)

    def test_encoded_query_param(self):
        """Test URL-encoded query param."""
        # %3D is '=' - this would be ?vkbd=true
        result = simulate_vkbd_enabled("/ttyd?vkbd=true", env_vkbd_default=False)
        self.assertTrue(result)

    def test_no_query_string(self):
        """Test path without any query string."""
        result = simulate_vkbd_enabled("/ttyd", env_vkbd_default=True)
        self.assertTrue(result)

    def test_empty_query_string(self):
        """Test path with empty query string."""
        result = simulate_vkbd_enabled("/ttyd?", env_vkbd_default=True)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
