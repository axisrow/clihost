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
        self.assertFalse(env_bool("invalid"))
        self.assertTrue(env_bool("maybe", default=True))


class TestEnvBoolWhitespace(unittest.TestCase):
    def test_whitespace_is_trimmed(self):
        self.assertTrue(env_bool("  true  "))
        self.assertFalse(env_bool("  false  "))
        self.assertTrue(env_bool(" 1 "))
        self.assertFalse(env_bool(" 0 "))


if __name__ == "__main__":
    unittest.main()

