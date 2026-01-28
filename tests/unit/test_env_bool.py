"""Tests for env_bool() function from ttyd_proxy.py."""
import unittest


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


class TestEnvBoolTruthy(unittest.TestCase):
    """Test truthy values for env_bool()."""

    def test_truthy_1(self):
        self.assertTrue(env_bool("1"))

    def test_truthy_true_lower(self):
        self.assertTrue(env_bool("true"))

    def test_truthy_yes(self):
        self.assertTrue(env_bool("yes"))

    def test_truthy_on(self):
        self.assertTrue(env_bool("on"))

    def test_truthy_TRUE_upper(self):
        self.assertTrue(env_bool("TRUE"))

    def test_truthy_True_mixed(self):
        self.assertTrue(env_bool("True"))

    def test_truthy_YES_upper(self):
        self.assertTrue(env_bool("YES"))

    def test_truthy_ON_upper(self):
        self.assertTrue(env_bool("ON"))


class TestEnvBoolFalsy(unittest.TestCase):
    """Test falsy values for env_bool()."""

    def test_falsy_0(self):
        self.assertFalse(env_bool("0"))

    def test_falsy_false_lower(self):
        self.assertFalse(env_bool("false"))

    def test_falsy_no(self):
        self.assertFalse(env_bool("no"))

    def test_falsy_off(self):
        self.assertFalse(env_bool("off"))

    def test_falsy_FALSE_upper(self):
        self.assertFalse(env_bool("FALSE"))

    def test_falsy_False_mixed(self):
        self.assertFalse(env_bool("False"))

    def test_falsy_NO_upper(self):
        self.assertFalse(env_bool("NO"))

    def test_falsy_OFF_upper(self):
        self.assertFalse(env_bool("OFF"))


class TestEnvBoolDefault(unittest.TestCase):
    """Test default values for env_bool()."""

    def test_none_returns_default_false(self):
        self.assertFalse(env_bool(None))

    def test_none_returns_default_true(self):
        self.assertTrue(env_bool(None, default=True))

    def test_empty_string_returns_default(self):
        self.assertFalse(env_bool(""))

    def test_empty_string_returns_custom_default(self):
        self.assertTrue(env_bool("", default=True))

    def test_invalid_value_returns_default(self):
        self.assertFalse(env_bool("invalid"))

    def test_invalid_value_returns_custom_default(self):
        self.assertTrue(env_bool("maybe", default=True))

    def test_random_string_returns_default(self):
        self.assertFalse(env_bool("hello"))


class TestEnvBoolEdgeCases(unittest.TestCase):
    """Test edge cases for env_bool()."""

    def test_whitespace_true(self):
        self.assertTrue(env_bool("  true  "))

    def test_whitespace_false(self):
        self.assertFalse(env_bool("  false  "))

    def test_whitespace_1(self):
        self.assertTrue(env_bool(" 1 "))

    def test_whitespace_0(self):
        self.assertFalse(env_bool(" 0 "))

    def test_mixed_case_TrUe(self):
        self.assertTrue(env_bool("TrUe"))

    def test_mixed_case_FaLsE(self):
        self.assertFalse(env_bool("FaLsE"))

    def test_mixed_case_YeS(self):
        self.assertTrue(env_bool("YeS"))

    def test_mixed_case_nO(self):
        self.assertFalse(env_bool("nO"))

    def test_integer_type_1(self):
        # env_bool converts to string first
        self.assertTrue(env_bool(1))

    def test_integer_type_0(self):
        self.assertFalse(env_bool(0))


if __name__ == '__main__':
    unittest.main()
