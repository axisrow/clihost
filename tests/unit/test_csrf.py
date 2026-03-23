"""Tests for CSRF token functions from ttyd_proxy.py."""
import unittest
import hmac
import hashlib
import base64
import time
import secrets


# Copied from ttyd_proxy.py to avoid importing module with Linux-only deps
PASSWORD_SECRET = "test-secret-key"
CSRF_TOKEN_TTL = 600


def build_csrf_token():
    """Create a signed CSRF token with timestamp."""
    nonce = secrets.token_urlsafe(24)
    issued_at = int(time.time())
    payload = f"{nonce}:{issued_at}"
    signature = hmac.new(
        PASSWORD_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = f"{payload}:{signature}"
    encoded = base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def parse_csrf_token(token):
    """Parse and validate CSRF token. Returns True if valid and not expired."""
    if not token:
        return False
    token = token.strip()
    padding = "=" * (-len(token) % 4)
    try:
        decoded = base64.urlsafe_b64decode(token + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    parts = decoded.rsplit(":", 2)
    if len(parts) != 3:
        return False
    nonce, issued_at_str, signature = parts
    try:
        issued_at = int(issued_at_str)
    except ValueError:
        return False
    if int(time.time()) - issued_at > CSRF_TOKEN_TTL:
        return False
    payload = f"{nonce}:{issued_at}"
    expected = hmac.new(
        PASSWORD_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


class TestBuildParseCSRFToken(unittest.TestCase):
    """Test CSRF token round-trip."""

    def test_roundtrip(self):
        token = build_csrf_token()
        self.assertTrue(parse_csrf_token(token))

    def test_different_tokens_are_unique(self):
        t1 = build_csrf_token()
        t2 = build_csrf_token()
        self.assertNotEqual(t1, t2)

    def test_empty_token(self):
        self.assertFalse(parse_csrf_token(""))
        self.assertFalse(parse_csrf_token(None))

    def test_invalid_base64(self):
        self.assertFalse(parse_csrf_token("not-valid-base64!!!"))

    def test_tampered_signature(self):
        token = build_csrf_token()
        padding = "=" * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode(token + padding).decode("utf-8")
        parts = decoded.rsplit(":", 2)
        # Replace signature with garbage
        tampered = f"{parts[0]}:{parts[1]}:{'a' * 64}"
        tampered_token = base64.urlsafe_b64encode(tampered.encode()).decode().rstrip("=")
        self.assertFalse(parse_csrf_token(tampered_token))

    def test_expired_token(self):
        nonce = secrets.token_urlsafe(24)
        old_time = int(time.time()) - CSRF_TOKEN_TTL - 10  # expired
        payload = f"{nonce}:{old_time}"
        signature = hmac.new(
            PASSWORD_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        token = f"{payload}:{signature}"
        encoded = base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")
        self.assertFalse(parse_csrf_token(encoded))

    def test_token_with_whitespace(self):
        token = build_csrf_token()
        self.assertTrue(parse_csrf_token(f"  {token}  "))


class TestCSRFTokenEdgeCases(unittest.TestCase):
    """Test edge cases for CSRF tokens."""

    def test_wrong_number_of_parts(self):
        bad = base64.urlsafe_b64encode(b"only:two").decode().rstrip("=")
        self.assertFalse(parse_csrf_token(bad))

    def test_non_integer_timestamp(self):
        bad = base64.urlsafe_b64encode(b"nonce:notanint:sig").decode().rstrip("=")
        self.assertFalse(parse_csrf_token(bad))


if __name__ == "__main__":
    unittest.main()
