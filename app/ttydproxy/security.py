"""Security helpers: cookies, signed tokens, CSRF, and auth validation."""
import base64
import hashlib
import hmac
import secrets
import subprocess
import time
import re
import pwd


USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")


def env_bool(value, default=False):
    """Parse common boolean env var values."""
    if value is None:
        return default
    value = str(value).strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return default


def parse_cookie_header(cookie_header):
    """Parse a Cookie header into a flat dict."""
    cookies = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


def is_valid_username(username):
    """Validate username to prevent command injection and traversal."""
    if not username:
        return False
    if not USERNAME_PATTERN.match(username):
        return False
    if ".." in username or username.startswith(("-", ".")):
        return False
    return True


def user_exists(username):
    """Return True when the local system account exists."""
    if not is_valid_username(username):
        return False
    try:
        pwd.getpwnam(username)
    except KeyError:
        return False
    return True


def _urlsafe_encode(data):
    return base64.urlsafe_b64encode(data.encode("utf-8")).decode("ascii").rstrip("=")


def _urlsafe_decode(token):
    padding = "=" * (-len(token) % 4)
    decoded = base64.urlsafe_b64decode(token + padding)
    return decoded.decode("utf-8")


def _sign_payload(payload, secret):
    signature = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}:{signature}"


def _verify_signed_token(token, secret, parts):
    if not token:
        return None
    token = token.strip()
    try:
        decoded = _urlsafe_decode(token)
    except (ValueError, UnicodeDecodeError):
        return None
    fields = decoded.rsplit(":", parts)
    if len(fields) != parts + 1:
        return None
    payload = ":".join(fields[:-1])
    signature = fields[-1]
    expected = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    return fields[:-1]


def build_session_token(username, secret, session_timeout):
    """Create a signed session token for a username."""
    expiration = int(time.time()) + session_timeout
    payload = f"session:{username}:{expiration}"
    return _urlsafe_encode(_sign_payload(payload, secret))


def parse_session_token(token, secret):
    """Parse and validate a signed session token. Returns username or None."""
    fields = _verify_signed_token(token, secret, parts=3)
    if not fields:
        return None
    scope, username, expiration_str = fields
    if scope != "session":
        return None
    try:
        expiration = int(expiration_str)
    except ValueError:
        return None
    if int(time.time()) > expiration:
        return None
    if not is_valid_username(username):
        return None
    return username


def build_csrf_token(secret):
    """Create a signed CSRF token with timestamp."""
    nonce = secrets.token_urlsafe(24)
    issued_at = int(time.time())
    payload = f"csrf:{nonce}:{issued_at}"
    return _urlsafe_encode(_sign_payload(payload, secret))


def parse_csrf_token(token, secret, ttl):
    """Parse and validate a CSRF token. Returns True if valid and unexpired."""
    fields = _verify_signed_token(token, secret, parts=3)
    if not fields:
        return False
    scope, _nonce, issued_at_str = fields
    if scope != "csrf":
        return False
    try:
        issued_at = int(issued_at_str)
    except ValueError:
        return False
    return int(time.time()) - issued_at <= ttl


def verify_pam_password(username, password):
    """Verify the user's password against local system auth."""
    if not user_exists(username):
        return False

    shadow_info = None
    crypt_module = None
    try:
        import spwd  # type: ignore
        import crypt as crypt_import  # type: ignore

        shadow_info = spwd.getspnam(username)
        crypt_module = crypt_import
    except (ImportError, KeyError, FileNotFoundError):
        shadow_info = None

    if shadow_info and crypt_module:
        password_hash = shadow_info.sp_pwdp
        if password_hash in ("*", "!"):
            return False
        crypted = crypt_module.crypt(password, password_hash)
        return crypted == password_hash

    try:
        result = subprocess.run(
            ["su", "-", username, "-c", "exit"],
            input=password.encode(),
            timeout=5,
            capture_output=True,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

