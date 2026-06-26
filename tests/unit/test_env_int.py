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


class TestEnvIntMinimum(unittest.TestCase):
    """A lower bound for time-to-live settings: a non-positive value must not be
    accepted verbatim (it would issue already-expired tokens / lock out logins).
    """

    def test_below_minimum_returns_default(self):
        self.assertEqual(env_int("-1", 604800, minimum=1), 604800)

    def test_zero_below_minimum_returns_default(self):
        self.assertEqual(env_int("0", 100, minimum=1), 100)

    def test_at_minimum_is_kept(self):
        self.assertEqual(env_int("1", 100, minimum=1), 1)

    def test_above_minimum_is_kept(self):
        self.assertEqual(env_int("5000", 100, minimum=1), 5000)

    def test_below_minimum_warns_to_stderr(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            env_int("-1", 604800, name="SESSION_TIMEOUT", minimum=1)
        message = buf.getvalue()
        self.assertIn("SESSION_TIMEOUT", message)
        self.assertIn("604800", message)

    def test_no_minimum_keeps_negative(self):
        # Backwards compatible: without a minimum, a negative value is returned
        # verbatim (e.g. settings where negative is meaningful).
        self.assertEqual(env_int("-5", 1), -5)


if __name__ == "__main__":
    unittest.main()
