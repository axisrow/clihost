"""Tests for verify_pam_password shadow-hash handling."""
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from ttydproxy import security


VALID_HASH = "$6$saltsalt$hashedpasswordvalue"


def _fake_modules(password_hash, crypt_func, getspnam_error=None):
    """Build fake spwd/crypt modules for sys.modules injection.

    password_hash=None simulates a missing shadow entry (getspnam raises
    KeyError); getspnam_error simulates an unreadable /etc/shadow (e.g.
    PermissionError under an unprivileged proxy). Both send
    verify_pam_password down the su fallback path.
    """
    def getspnam(username):
        if getspnam_error is not None:
            raise getspnam_error
        if password_hash is None:
            raise KeyError(username)
        return SimpleNamespace(sp_pwdp=password_hash)

    return {
        "spwd": SimpleNamespace(getspnam=getspnam),
        "crypt": SimpleNamespace(crypt=crypt_func),
    }


class VerifyPamPasswordTest(unittest.TestCase):
    def _verify(self, password_hash, crypt_func, password="secret"):
        modules = _fake_modules(password_hash, crypt_func)
        with mock.patch.dict(sys.modules, modules):
            with mock.patch.object(security, "user_exists", return_value=True):
                return security.verify_pam_password("hapi", password)

    def test_locked_and_empty_hashes_rejected_without_crypt(self):
        crypt_mock = mock.Mock()
        for password_hash in ("", "!", "!!", "!$6$abc$def", "*", "*LK*", "*NP*"):
            with self.subTest(password_hash=password_hash):
                self.assertFalse(self._verify(password_hash, crypt_mock))
        crypt_mock.assert_not_called()

    def test_correct_password_accepted(self):
        self.assertTrue(
            self._verify(VALID_HASH, lambda password, salt: VALID_HASH)
        )

    def test_wrong_password_rejected(self):
        self.assertFalse(
            self._verify(VALID_HASH, lambda password, salt: "$6$saltsalt$other")
        )

    def test_crypt_returning_none_rejected(self):
        self.assertFalse(self._verify(VALID_HASH, lambda password, salt: None))

    def _su_fallback(self, modules, su_returncode):
        """Run verify_pam_password with mocked su; assert su was consulted."""
        su_result = SimpleNamespace(returncode=su_returncode)
        with mock.patch.dict(sys.modules, modules):
            with mock.patch.object(security, "user_exists", return_value=True):
                with mock.patch.object(
                    security.subprocess, "run", return_value=su_result
                ) as run_mock:
                    result = security.verify_pam_password("hapi", "secret")
        run_mock.assert_called_once()
        return result

    def test_missing_shadow_entry_falls_back_to_su(self):
        self.assertTrue(self._su_fallback(_fake_modules(None, mock.Mock()), 0))

    def test_unreadable_shadow_falls_back_to_su(self):
        # Unprivileged proxy: spwd.getspnam raises PermissionError (EACCES on
        # /etc/shadow); the su fallback must take over instead of crashing.
        modules = _fake_modules(
            None, mock.Mock(), getspnam_error=PermissionError(13, "Permission denied")
        )
        self.assertTrue(self._su_fallback(modules, 0))

    def test_unreadable_shadow_su_rejects_wrong_password(self):
        modules = _fake_modules(
            None, mock.Mock(), getspnam_error=PermissionError(13, "Permission denied")
        )
        self.assertFalse(self._su_fallback(modules, 1))

    def test_unknown_user_rejected(self):
        with mock.patch.object(security, "user_exists", return_value=False):
            self.assertFalse(security.verify_pam_password("ghost", "secret"))


if __name__ == "__main__":
    unittest.main()
