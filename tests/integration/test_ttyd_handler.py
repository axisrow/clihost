"""Integration-style tests for virtual keyboard query handling."""
import unittest

from ttydproxy.views import resolve_vkbd_enabled


class TestTTYDHandlerVKBD(unittest.TestCase):
    def test_query_param_overrides_default(self):
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=true", False))
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=false", True))
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=1", False))
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=0", True))

    def test_missing_query_param_uses_default(self):
        self.assertTrue(resolve_vkbd_enabled("/ttyd", True))
        self.assertFalse(resolve_vkbd_enabled("/ttyd", False))

    def test_invalid_values_fall_back_to_default(self):
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=hello", True))
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=hello", False))

    def test_multiple_values_use_first(self):
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=false&vkbd=true", True))
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=true&vkbd=false", False))


if __name__ == "__main__":
    unittest.main()

