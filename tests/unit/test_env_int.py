"""Tests for env_int() from production code."""
import unittest

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

    def test_invalid_explicit_value_raises(self):
        for value in ("abc", "12.5", "1e3", "0x10", "--1"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "Invalid integer"):
                    env_int(value, 7, name="MAX_TERMINALS")


class TestEnvIntRange(unittest.TestCase):

    def test_below_minimum_clamps(self):
        self.assertEqual(env_int("-1", 604800, minimum=1), 1)

    def test_zero_below_minimum_clamps(self):
        self.assertEqual(env_int("0", 100, minimum=1), 1)

    def test_at_minimum_is_kept(self):
        self.assertEqual(env_int("1", 100, minimum=1), 1)

    def test_above_minimum_is_kept(self):
        self.assertEqual(env_int("5000", 100, minimum=1), 5000)

    def test_no_minimum_keeps_negative(self):
        # Backwards compatible: without a minimum, a negative value is returned
        # verbatim (e.g. settings where negative is meaningful).
        self.assertEqual(env_int("-5", 1), -5)

    def test_invalid_default_is_range_checked(self):
        self.assertEqual(env_int(None, 0, minimum=1), 1)

    def test_strict_minimum_raises(self):
        with self.assertRaisesRegex(ValueError, "below minimum 1"):
            env_int("0", 100, minimum=1, clamp_minimum=False)

    def test_above_maximum_raises(self):
        with self.assertRaisesRegex(ValueError, "above maximum 65535"):
            env_int("65536", 8080, name="PORT", maximum=65535)


if __name__ == "__main__":
    unittest.main()
