"""Tests for env_int() from production code."""
import io
import unittest
from contextlib import redirect_stderr

from ttydproxy.security import env_int


class TestEnvIntValid(unittest.TestCase):
    def test_valid_values(self):
        self.assertEqual(env_int("8080", 1), 8080)
        self.assertEqual(env_int("0", 1), 0)
        self.assertEqual(env_int("-5", 1), -5)
        self.assertEqual(env_int(42, 1), 42)

    def test_whitespace_is_trimmed(self):
        self.assertEqual(env_int("  100  ", 1), 100)


class TestEnvIntDefault(unittest.TestCase):
    def test_none_returns_default(self):
        self.assertEqual(env_int(None, 8080), 8080)

    def test_empty_returns_default(self):
        self.assertEqual(env_int("", 8080), 8080)

    def test_invalid_returns_default(self):
        for value in ("abc", "12.5", "1e3", "0x10", "--1"):
            with self.subTest(value=value):
                self.assertEqual(env_int(value, 7), 7)

    def test_invalid_warns_to_stderr(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            env_int("abc", 7, name="MAX_TERMINALS")
        message = buf.getvalue()
        self.assertIn("MAX_TERMINALS", message)
        self.assertIn("abc", message)
        self.assertIn("7", message)

    def test_none_does_not_warn(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            env_int(None, 7, name="PORT")
        self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
