"""Tests for env_bool() from production code."""
import unittest

from ttydproxy.security import env_bool


class TestEnvBoolTruthy(unittest.TestCase):
    def test_truthy_values(self):
        for value in ("1", "true", "yes", "on", "TRUE", "True", "YES", "ON", "TrUe", 1):
            with self.subTest(value=value):
                self.assertTrue(env_bool(value))


class TestEnvBoolFalsy(unittest.TestCase):
    def test_falsy_values(self):
        for value in ("0", "false", "no", "off", "FALSE", "False", "NO", "OFF", "FaLsE", 0):
            with self.subTest(value=value):
                self.assertFalse(env_bool(value))


class TestEnvBoolDefault(unittest.TestCase):
    def test_default_fallbacks(self):
        self.assertFalse(env_bool(None))
        self.assertTrue(env_bool(None, default=True))
        self.assertFalse(env_bool(""))
        self.assertTrue(env_bool("", default=True))

    def test_invalid_explicit_value_raises(self):
        for value in ("invalid", "maybe", "2"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "expected 1/true/yes/on"):
                    env_bool(value, default=True, name="FEATURE_ENABLED")


class TestEnvBoolWhitespace(unittest.TestCase):
    def test_whitespace_is_trimmed(self):
        self.assertTrue(env_bool("  true  "))
        self.assertFalse(env_bool("  false  "))
        self.assertTrue(env_bool(" 1 "))
        self.assertFalse(env_bool(" 0 "))


if __name__ == "__main__":
    unittest.main()
