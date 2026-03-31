"""Tests for signed CSRF and session token helpers."""
import base64
import secrets
import time
import unittest

from ttydproxy.security import (
    build_csrf_token,
    build_session_token,
    parse_csrf_token,
    parse_session_token,
)


PASSWORD_SECRET = "test-secret-key"
CSRF_TOKEN_TTL = 600
SESSION_TIMEOUT = 600


class TestCSRFToken(unittest.TestCase):
    def test_roundtrip(self):
        token = build_csrf_token(PASSWORD_SECRET)
        self.assertTrue(parse_csrf_token(token, PASSWORD_SECRET, CSRF_TOKEN_TTL))

    def test_different_tokens_are_unique(self):
        self.assertNotEqual(build_csrf_token(PASSWORD_SECRET), build_csrf_token(PASSWORD_SECRET))

    def test_invalid_tokens(self):
        self.assertFalse(parse_csrf_token("", PASSWORD_SECRET, CSRF_TOKEN_TTL))
        self.assertFalse(parse_csrf_token(None, PASSWORD_SECRET, CSRF_TOKEN_TTL))
        self.assertFalse(parse_csrf_token("not-valid-base64!!!", PASSWORD_SECRET, CSRF_TOKEN_TTL))

    def test_tampered_signature(self):
        token = build_csrf_token(PASSWORD_SECRET)
        decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
        parts = decoded.rsplit(":", 3)
        tampered = ":".join(parts[:-1] + ["a" * 64])
        tampered_token = base64.urlsafe_b64encode(tampered.encode()).decode().rstrip("=")
        self.assertFalse(parse_csrf_token(tampered_token, PASSWORD_SECRET, CSRF_TOKEN_TTL))

    def test_expired_token(self):
        nonce = secrets.token_urlsafe(24)
        old_time = int(time.time()) - CSRF_TOKEN_TTL - 10
        payload = f"csrf:{nonce}:{old_time}"
        signature = __import__("hmac").new(
            PASSWORD_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            __import__("hashlib").sha256,
        ).hexdigest()
        token = base64.urlsafe_b64encode(f"{payload}:{signature}".encode()).decode().rstrip("=")
        self.assertFalse(parse_csrf_token(token, PASSWORD_SECRET, CSRF_TOKEN_TTL))

    def test_token_with_whitespace(self):
        token = build_csrf_token(PASSWORD_SECRET)
        self.assertTrue(parse_csrf_token(f"  {token}  ", PASSWORD_SECRET, CSRF_TOKEN_TTL))


class TestSessionToken(unittest.TestCase):
    def test_roundtrip(self):
        token = build_session_token("alice", PASSWORD_SECRET, SESSION_TIMEOUT)
        self.assertEqual(parse_session_token(token, PASSWORD_SECRET), "alice")

    def test_invalid_base64(self):
        self.assertIsNone(parse_session_token("invalid!!!", PASSWORD_SECRET))

    def test_tampered_signature(self):
        token = build_session_token("alice", PASSWORD_SECRET, SESSION_TIMEOUT)
        decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
        parts = decoded.rsplit(":", 3)
        tampered = ":".join(parts[:-1] + ["b" * 64])
        tampered_token = base64.urlsafe_b64encode(tampered.encode()).decode().rstrip("=")
        self.assertIsNone(parse_session_token(tampered_token, PASSWORD_SECRET))


if __name__ == "__main__":
    unittest.main()

