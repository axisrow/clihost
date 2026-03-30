#!/usr/bin/env python3
"""
TTYD HTTP Proxy Server
Proxies HTTP/WebSocket traffic to multiple TTYD processes on 127.0.0.1
"""
import os
import sys
import socket
import select
import hmac
import hashlib
import base64
import http.client
import time
import signal
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.parse import parse_qs as parse_form_qs
from collections import defaultdict
import pwd
import spwd
import crypt
import subprocess
import re
import secrets
import html as html_module

# Import base HTTP server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server import BaseHTTPHandler as BaseHandler

# Configuration
PORT = int(os.environ.get("PORT", "8080"))
TTYD_USER = os.environ.get("TTYD_USER", "hapi")
TTYD_PASSWORD = os.environ.get("TTYD_PASSWORD", "")
PASSWORD_SECRET = os.environ.get("PASSWORD_SECRET", "default-secret-change-me")
TTYD_BASE_PORT = 7681  # Starting port for TTYD instances
MAX_TERMINALS = int(os.environ.get("MAX_TERMINALS", "100"))
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "604800"))  # 1 week (168 hours) default
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

VIRTUAL_KEYBOARD = env_bool(os.environ.get("VIRTUAL_KEYBOARD"), default=True)
CSRF_TOKEN_TTL = int(os.environ.get("CSRF_TOKEN_TTL", "604800"))  # 7 days default
SECURE_COOKIES = env_bool(os.environ.get("SECURE_COOKIES"), default=False)

# Load templates
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# Username validation pattern - only alphanumeric, underscore, hyphen, dot
# Max length 32 chars per Linux username limits
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]{1,32}$')

# Route pattern for multi-terminal endpoints: /ttyd1, /ttyd1/, /ttyd1/ws
TTYD_ROUTE_PATTERN = re.compile(r'^/ttyd(\d+)(/.*)?$')


class TTYDManager:
    """Manages multiple TTYD process instances."""

    def __init__(self):
        self.terminals = {}  # {terminal_id: {"port": int, "pid": int, "process": Popen}}
        self.next_id = 1
        self.lock = threading.Lock()

    def _allocate_port(self):
        """Find next available port, reusing freed ports. Returns port or None."""
        used_ports = {t["port"] for t in self.terminals.values()}
        max_port = TTYD_BASE_PORT + MAX_TERMINALS
        port = TTYD_BASE_PORT
        while port in used_ports:
            port += 1
            if port >= max_port:
                return None
        return port

    def create_terminal(self, wait=False):
        """Spawn a new TTYD process. Returns terminal info dict, "limit", or None."""
        with self.lock:
            if len(self.terminals) >= MAX_TERMINALS:
                return "limit"
            terminal_id = self.next_id
            port = self._allocate_port()
            if port is None:
                return "limit"

            tmux_session = f"ttyd-{terminal_id}"
            try:
                process = subprocess.Popen(
                    [
                        "runuser", "-u", TTYD_USER, "--",
                        "/usr/local/bin/ttyd",
                        "-p", str(port),
                        "-i", "127.0.0.1",
                        "-W",
                        "/bin/tmux-wrapper.sh", tmux_session,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as e:
                print(f"Failed to start TTYD on port {port}: {e}", file=sys.stderr, flush=True)
                return None

            # Register immediately to prevent race conditions on ID/port
            info = {"id": terminal_id, "port": port, "pid": process.pid, "process": process}
            self.terminals[terminal_id] = info
            self.next_id += 1

        if wait:
            if not self._wait_for_ready(port):
                self.delete_terminal(terminal_id)
                return None

        print(f"Started terminal ttyd{terminal_id} on port {port} (PID {process.pid})", flush=True)
        return {"id": terminal_id, "port": port}

    def delete_terminal(self, terminal_id):
        """Kill a TTYD process and its tmux session. Returns True if deleted."""
        with self.lock:
            info = self.terminals.pop(terminal_id, None)
        if not info:
            return False

        # Kill TTYD process
        process = info.get("process")
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    process.wait(timeout=3)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            except OSError:
                pass

        # Kill tmux session
        tmux_session = f"ttyd-{terminal_id}"
        try:
            subprocess.run(
                ["runuser", "-u", TTYD_USER, "--", "tmux", "kill-session", "-t", tmux_session],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

        print(f"Deleted terminal ttyd{terminal_id}", flush=True)
        return True

    def _cleanup_dead(self, terminal_id, info):
        """Clean up a dead terminal: reap zombie, kill tmux session."""
        process = info.get("process")
        if process:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        tmux_session = f"ttyd-{terminal_id}"
        try:
            subprocess.run(
                ["runuser", "-u", TTYD_USER, "--", "tmux", "kill-session", "-t", tmux_session],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
        print(f"Terminal ttyd{terminal_id} died, cleaned up", flush=True)

    def list_terminals(self):
        """Return list of active terminals sorted by id."""
        dead = []
        with self.lock:
            for tid, info in self.terminals.items():
                process = info.get("process")
                if process and process.poll() is not None:
                    dead.append((tid, info))
            for tid, _info in dead:
                del self.terminals[tid]

            result = sorted(
                [{"id": t["id"], "port": t["port"]} for t in self.terminals.values()],
                key=lambda x: x["id"],
            )

        # Clean up dead terminals outside the lock
        for tid, info in dead:
            self._cleanup_dead(tid, info)

        return result

    def get_terminal(self, terminal_id):
        """Get terminal info by id, or None."""
        dead_info = None
        with self.lock:
            info = self.terminals.get(terminal_id)
            if info:
                process = info.get("process")
                if process and process.poll() is not None:
                    dead_info = self.terminals.pop(terminal_id)
                    info = None
                else:
                    return {"id": info["id"], "port": info["port"]}

        # Clean up dead terminal outside the lock
        if dead_info:
            self._cleanup_dead(terminal_id, dead_info)

        return None

    def _wait_for_ready(self, port, timeout=15):
        """Wait until TTYD is responding on the given port."""
        for _ in range(timeout):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                sock.close()
                return True
            except OSError:
                time.sleep(1)
        print(f"TTYD on port {port} failed to start within {timeout}s", file=sys.stderr, flush=True)
        return False


# Global TTYD manager instance
ttyd_manager = TTYDManager()


class RateLimiter:
    """Simple rate limiter for login attempts."""
    def __init__(self, max_attempts=5, window_seconds=60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(list)
        self.lock = threading.Lock()
        self._call_count = 0
        self._cleanup_interval = 100

    def is_allowed(self, key):
        """Check if the request is allowed for the given key."""
        with self.lock:
            current_time = int(time.time())

            # Periodically purge stale keys to prevent memory leak
            self._call_count += 1
            if self._call_count >= self._cleanup_interval:
                self._call_count = 0
                stale_keys = [
                    k for k, timestamps in self.attempts.items()
                    if all(current_time - t >= self.window_seconds for t in timestamps)
                ]
                for k in stale_keys:
                    del self.attempts[k]

            # Remove old attempts outside the time window
            self.attempts[key] = [
                attempt_time for attempt_time in self.attempts[key]
                if current_time - attempt_time < self.window_seconds
            ]

            # Check if limit exceeded
            if len(self.attempts[key]) >= self.max_attempts:
                return False

            # Record this attempt
            self.attempts[key].append(current_time)
            return True


# Global rate limiter instance
login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60)
account_rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)


def is_valid_username(username):
    """Validate username to prevent command injection."""
    if not username:
        return False
    if not USERNAME_PATTERN.match(username):
        return False
    # Additional safety: prevent path traversal attempts
    if '..' in username or username.startswith(('-', '.')):
        return False
    return True

def load_template(filename):
    """Load HTML template from file."""
    template_path = os.path.join(TEMPLATE_DIR, filename)
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return f"<html><body><h1>Template {filename} not found</h1></body></html>"


def build_ttyd_session(username, port):
    """Create signed session token with username, port, and expiration time."""
    expiration = int(time.time()) + SESSION_TIMEOUT
    payload = f"{username}:{port}:{expiration}"
    signature = hmac.new(
        PASSWORD_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    full_payload = f"{payload}:{signature}"
    encoded = base64.urlsafe_b64encode(full_payload.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def parse_ttyd_session(token):
    """Parse and validate session token. Returns (username, port) or (None, None)."""
    if not token:
        return None, None
    token = token.strip()
    padding = "=" * (-len(token) % 4)
    try:
        decoded = base64.urlsafe_b64decode(token + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None, None
    parts = decoded.rsplit(":", 3)
    if len(parts) != 4:
        return None, None
    username, port_str, expiration_str, signature = parts
    try:
        port = int(port_str)
        expiration = int(expiration_str)
    except ValueError:
        return None, None

    # Check expiration
    current_time = int(time.time())
    if current_time > expiration:
        return None, None

    payload = f"{username}:{port}:{expiration}"
    expected = hmac.new(
        PASSWORD_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None, None
    return username, port


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


def verify_pam_password(username, password):
    """Verify user password using PAM (shadow authentication)."""
    # Validate username first to prevent command injection
    if not is_valid_username(username):
        return False

    try:
        # Check if user exists
        pwd.getpwnam(username)
    except KeyError:
        return False

    try:
        # Get shadow password hash
        shadow_info = spwd.getspnam(username)
        password_hash = shadow_info.sp_pwdp

        # Verify password
        if password_hash in ("*", "!"):
            return False  # Account locked or no password

        # Use crypt to verify
        crypted = crypt.crypt(password, password_hash)
        return crypted == password_hash
    except (KeyError, FileNotFoundError):
        # Shadow file might not be accessible in container
        # Fall back to subprocess verification with validated username
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


# Script injected into TTYD HTML to fix Tab key handling
# Intercepts WebSocket creation to capture the connection, then sends Tab
# character directly through WebSocket using TTYD protocol ('0' prefix = INPUT)
TAB_FIX_SCRIPT = b'''
<script>
(function() {
  // Intercept WebSocket creation to capture TTYD's socket
  // Store in window for global access
  window._ttydSocket = null;
  var OrigWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    var ws = protocols ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
    // TTYD creates WebSocket to ws:// or wss:// with /ws path
    if (url && url.indexOf('/ws') !== -1) {
      window._ttydSocket = ws;
    }
    return ws;
  };
  window.WebSocket.prototype = OrigWebSocket.prototype;
  window.WebSocket.CONNECTING = OrigWebSocket.CONNECTING;
  window.WebSocket.OPEN = OrigWebSocket.OPEN;
  window.WebSocket.CLOSING = OrigWebSocket.CLOSING;
  window.WebSocket.CLOSED = OrigWebSocket.CLOSED;

  // Helper to get active socket
  function getSocket() {
    return window._ttydSocket || window.socket || window.ws;
  }

  // Wait for terminal to be ready
  function waitForTerm(cb) {
    if (window.term) { cb(window.term); return; }
    var i = setInterval(function() {
      if (window.term) { clearInterval(i); cb(window.term); }
    }, 50);
  }

  // Send data via WebSocket with TTYD protocol
  // '0' prefix = Command.INPUT in TTYD protocol
  function sendToTTYD(data) {
    var socket = getSocket();
    if (socket && socket.readyState === 1) {
      socket.send('0' + data);
      return true;
    }
    return false;
  }

  waitForTerm(function(term) {
    // Intercept Tab before browser handles it
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Tab') {
        e.preventDefault();
        e.stopPropagation();

        var data = e.shiftKey ? '\\x1b[Z' : '\\t';

        // Method 1: Direct WebSocket send with TTYD protocol
        if (sendToTTYD(data)) return;

        // Method 2: Use xterm.js internal API
        if (term._core && term._core.coreService) {
          term._core.coreService.triggerDataEvent(data);
          return;
        }

        // Method 3: Fallback to term.input()
        if (term.input) {
          term.input(data);
        }
      }
    }, true);

    // Expose sendTab function for virtual keyboard
    window.sendTabKey = function(shift) {
      var data = shift ? '\\x1b[Z' : '\\t';
      if (sendToTTYD(data)) return true;
      if (term._core && term._core.coreService) {
        term._core.coreService.triggerDataEvent(data);
        return true;
      }
      if (term.input) {
        term.input(data);
        return true;
      }
      return false;
    };
  });
})();
</script>
'''


class TTYDProxyHandler(BaseHandler):
    """HTTP request handler for TTYD proxy."""

    def parse_cookie_header(self, cookie_header):
        """Parse Cookie header into dict."""
        cookies = {}
        if not cookie_header:
            return cookies
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.handle_menu()
        elif parsed.path == "/login":
            self.handle_login_page()
        elif parsed.path == "/health":
            self.handle_health()
        elif parsed.path == "/terminals":
            self.handle_terminals_list()
        else:
            # Match /ttyd<N> or /ttyd<N>/...
            match = TTYD_ROUTE_PATTERN.match(parsed.path)
            if match:
                terminal_id = int(match.group(1))
                sub_path = match.group(2)
                if sub_path:
                    self.handle_ttyd_proxy(terminal_id)
                else:
                    self.handle_ttyd(terminal_id)
            else:
                self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)

        if parsed.path == "/login":
            self.handle_login()
        elif parsed.path == "/terminals":
            self.handle_terminals_create()
        else:
            self.send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        """Handle DELETE requests."""
        parsed = urlparse(self.path)

        match = re.match(r'^/terminals/(\d+)$', parsed.path)
        if match:
            terminal_id = int(match.group(1))
            self.handle_terminals_delete(terminal_id)
        else:
            self.send_json(404, {"error": "Not found"})

    def handle_login_page(self):
        """Show login form."""
        csrf_token = build_csrf_token()
        html = load_template('login.html')
        html = html.replace('{{CSRF_TOKEN}}', csrf_token)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'",
        )
        secure_flag = " Secure;" if SECURE_COOKIES else ""
        self.send_header(
            "Set-Cookie",
            f"csrf_token={csrf_token}; Path=/; SameSite=Lax;{secure_flag}",
        )
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def handle_health(self):
        """Health check endpoint."""
        terminals = ttyd_manager.list_terminals()
        self.send_json(200, {
            "status": "ok",
            "ttyd": "running" if terminals else "no terminals",
            "terminals": len(terminals),
        })

    def _check_auth(self, redirect=False):
        """Check session auth. Returns username or None (sends error/redirect response)."""
        cookies = self.parse_cookie_header(self.headers.get("Cookie", ""))
        token = cookies.get("ttyd_session")
        username, port = parse_ttyd_session(token)
        if not username or not port:
            if redirect:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            else:
                self.send_json(401, {"error": "Authentication required"})
            return None
        if not is_valid_username(username):
            self.send_json(403, {"error": "Invalid session"})
            return None
        try:
            pwd.getpwnam(username)
        except KeyError:
            self.send_json(403, {"error": "Invalid session"})
            return None
        return username

    def handle_terminals_list(self):
        """GET /terminals - list active terminals."""
        username = self._check_auth()
        if not username:
            return
        terminals = ttyd_manager.list_terminals()
        self.send_json(200, {"terminals": terminals})

    def _check_csrf(self):
        """Validate CSRF token from request header against cookie. Returns True if valid."""
        csrf_header = self.headers.get("X-CSRF-Token", "")
        csrf_cookie = self.parse_cookie_header(self.headers.get("Cookie", "")).get("csrf_token", "")
        if not csrf_header or not csrf_cookie:
            self.send_json(419, {"error": "CSRF token missing — please refresh the page"})
            return False
        if csrf_header != csrf_cookie or not parse_csrf_token(csrf_header):
            self.send_json(419, {"error": "CSRF token expired — please refresh the page"})
            return False
        return True

    def handle_terminals_create(self):
        """POST /terminals - create a new terminal."""
        username = self._check_auth()
        if not username:
            return
        if not self._check_csrf():
            return
        result = ttyd_manager.create_terminal(wait=True)
        if result == "limit":
            self.send_json(429, {"error": f"Terminal limit reached (max {MAX_TERMINALS})"})
            return
        if not result:
            self.send_json(500, {"error": "Failed to create terminal"})
            return
        self.send_json(201, result)

    def handle_terminals_delete(self, terminal_id):
        """DELETE /terminals/<id> - delete a terminal."""
        username = self._check_auth()
        if not username:
            return
        if not self._check_csrf():
            return
        if ttyd_manager.delete_terminal(terminal_id):
            self.send_json(200, {"deleted": terminal_id})
        else:
            self.send_json(404, {"error": f"Terminal {terminal_id} not found"})

    def handle_login(self):
        """Handle login POST request."""
        # Get client IP for rate limiting
        client_ip = self.client_address[0]

        # Check rate limit
        if not login_rate_limiter.is_allowed(client_ip):
            self.send_json(429, {"error": "Too many login attempts. Please try again later."})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        # Limit POST request size to prevent memory exhaustion
        if content_length > 1048576:  # 1MB max
            self.send_json(413, {"error": "Request too large"})
            return

        try:
            post_data = self.rfile.read(content_length).decode("utf-8")
        except UnicodeDecodeError:
            self.send_json(400, {"error": "Invalid encoding"})
            return
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()

        username = ""
        password = ""
        csrf_token = ""

        if content_type == "application/json":
            try:
                import json
                data = json.loads(post_data)
                username = data.get("username", "").strip()
                password = data.get("password", "")
                csrf_token = data.get("csrf_token", "")
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
                return
        elif content_type == "application/x-www-form-urlencoded":
            form = parse_form_qs(post_data, keep_blank_values=True)
            username = (form.get("username", [""])[0]).strip()
            password = form.get("password", [""])[0]
            csrf_token = form.get("csrf_token", [""])[0]
        else:
            self.send_json(415, {"error": "Unsupported content type"})
            return

        # CSRF protection (double-submit token)
        csrf_header = self.headers.get("X-CSRF-Token", "")
        csrf_cookie = self.parse_cookie_header(self.headers.get("Cookie", "")).get("csrf_token", "")
        provided_token = (csrf_header or csrf_token).strip()
        if not provided_token or not csrf_cookie:
            self.send_json(403, {"error": "CSRF token missing"})
            return
        if provided_token != csrf_cookie or not parse_csrf_token(provided_token):
            self.send_json(403, {"error": "Invalid CSRF token"})
            return

        if not username:
            self.send_json(400, {"error": "Username required"})
            return

        if not account_rate_limiter.is_allowed(f"{client_ip}:{username}"):
            self.send_json(429, {"error": "Too many login attempts. Please try again later."})
            return

        # Validate username to prevent command injection
        if not is_valid_username(username):
            self.send_json(400, {"error": "Invalid username format"})
            return

        # Check optional global password
        if TTYD_PASSWORD and password != TTYD_PASSWORD:
            time.sleep(0.5)
            self.send_json(401, {"error": "Invalid password"})
            return

        # Verify user exists
        try:
            pwd.getpwnam(username)
        except KeyError:
            time.sleep(0.5)
            self.send_json(401, {"error": "Invalid credentials"})
            return

        # If TTYD_PASSWORD is not set, verify system password
        if not TTYD_PASSWORD:
            if not password:
                self.send_json(400, {"error": "Password required"})
                return
            if not verify_pam_password(username, password):
                time.sleep(0.5)
                self.send_json(401, {"error": "Invalid credentials"})
                return

        # Create session token
        session_token = build_ttyd_session(username, TTYD_BASE_PORT)

        # Set secure cookie flags - don't trust X-Forwarded-* headers for security
        # Use Lax by default for same-origin requests
        # Only set Secure flag if we're confident it's HTTPS (configured by admin)
        self.send_response(302)
        self.send_header("Location", "/")
        secure_flag = " Secure;" if SECURE_COOKIES else ""
        self.send_header(
            "Set-Cookie",
            f"ttyd_session={session_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TIMEOUT};{secure_flag}",
        )
        self.end_headers()

    def handle_menu(self):
        """Return HTML page with main menu (after authentication)."""
        cookies = self.parse_cookie_header(self.headers.get("Cookie", ""))
        token = cookies.get("ttyd_session")
        username, port = parse_ttyd_session(token)

        if not username or not port:
            # Redirect to login page
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        # Validate username from session token
        if not is_valid_username(username):
            self.send_json(403, {"error": "Invalid session"})
            return

        # Verify user still exists
        try:
            pwd.getpwnam(username)
        except KeyError:
            self.send_json(403, {"error": "Invalid session"})
            return

        # Read tunnel URL from file
        hapi_url = None
        hapi_url_file = "/home/hapi/url"
        try:
            with open(hapi_url_file, 'r', encoding='utf-8') as f:
                hapi_url = f.read().strip()
        except (FileNotFoundError, IOError):
            pass

        # Validate URL scheme - only allow http:// and https://
        if hapi_url:
            parsed_url = urlparse(hapi_url)
            if parsed_url.scheme not in ('http', 'https'):
                hapi_url = None

        # Load and render menu template
        html = load_template('index.html')
        html = html.replace('{{USERNAME}}', html_module.escape(username))

        if hapi_url:
            escaped_url = html_module.escape(hapi_url, quote=True)
            hapi_link = f'<a href="{escaped_url}" target="_blank" class="menu-link">HAPI Server</a>'
        else:
            hapi_link = '<span class="menu-link disabled">HAPI Server (not available)</span>'

        html = html.replace('{{HAPI_LINK}}', hapi_link)

        # Set CSRF cookie for terminal create/delete API calls
        csrf_token = build_csrf_token()
        secure_flag = " Secure;" if SECURE_COOKIES else ""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'",
        )
        self.send_header(
            "Set-Cookie",
            f"csrf_token={csrf_token}; Path=/; SameSite=Lax;{secure_flag}",
        )
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def handle_ttyd(self, terminal_id):
        """Return HTML page with terminal iframe for given terminal_id."""
        parsed = urlparse(self.path)
        username = self._check_auth(redirect=True)
        if not username:
            return

        # Verify terminal exists
        terminal = ttyd_manager.get_terminal(terminal_id)
        if not terminal:
            self.send_json(404, {"error": f"Terminal ttyd{terminal_id} not found"})
            return

        # Return terminal iframe page with optional virtual keyboard
        ttyd_url = f"/ttyd{terminal_id}/"
        vkbd_enabled = VIRTUAL_KEYBOARD
        query = parse_qs(parsed.query)
        if "vkbd" in query:
            vkbd_enabled = env_bool(query.get("vkbd", [""])[0], default=vkbd_enabled)

        # Tab key handler for parent page - blocks browser Tab navigation
        # when focus is in terminal iframe. The actual Tab handling is done
        # by injected script inside TTYD iframe (TAB_FIX_SCRIPT).
        tab_handler_script = '''
  <script>
    (function() {
      var iframe = document.getElementById('terminal');

      // Block Tab at parent level to prevent browser focus navigation
      document.addEventListener('keydown', function(e) {
        if (e.key !== 'Tab') return;

        // If focus is in iframe or on iframe element - block browser navigation
        if (document.activeElement === iframe ||
            (iframe && iframe.contains && iframe.contains(document.activeElement))) {
          e.preventDefault();
          e.stopPropagation();
        }
      }, true);

      // Focus iframe content when iframe receives focus
      if (iframe) {
        iframe.addEventListener('focus', function() {
          try {
            iframe.contentWindow.focus();
          } catch(e) {}
        });
      }
    })();
  </script>'''

        # Virtual keyboard HTML (only included if VIRTUAL_KEYBOARD=true)
        if vkbd_enabled:
            vkbd_style = '''
    .vkbd { display: none; background: #1a1a2e; padding: 8px; gap: 6px; flex-wrap: wrap; justify-content: center; }
    .vkbd button {
      background: #16213e; color: #e8e8e8; border: 1px solid #0f3460;
      padding: 12px 16px; font-size: 14px; font-family: monospace;
      border-radius: 4px; min-width: 44px; touch-action: manipulation;
    }
    .vkbd button:active { background: #0f3460; }
    @media (max-width: 768px) {
      .vkbd { display: flex; }
      body { height: calc(100vh - 60px); }
    }'''
            vkbd_html = '''
  <div class="vkbd" id="vkbd">
    <button data-key="esc">ESC</button>
    <button data-key="tab">Tab</button>
    <button data-key="shift-tab">Shift+Tab</button>
    <button data-key="ctrl-c">Ctrl+C</button>
    <button data-key="ctrl-b">Ctrl+B</button>
    <button data-key="up">&#8593;</button>
    <button data-key="left">&#8592;</button>
    <button data-key="down">&#8595;</button>
    <button data-key="right">&#8594;</button>
    <button data-key="ctrl-v">Ctrl+V</button>
  </div>
  <script>
    (function() {
      var iframe = document.getElementById('terminal');

      function focusTerminal() {
        try {
          if (iframe.contentWindow) iframe.contentWindow.focus();
          var doc = iframe.contentWindow && iframe.contentWindow.document;
          if (doc) {
            var textarea = doc.querySelector('.xterm-helper-textarea');
            if (textarea) textarea.focus();
          }
        } catch (e) {}
      }

      function sendKey(key) {
        focusTerminal();

        // For Tab keys, use the injected sendTabKey function
        if (key === 'tab' || key === 'shift-tab') {
          try {
            var win = iframe.contentWindow;
            if (win && win.sendTabKey) {
              win.sendTabKey(key === 'shift-tab');
              return;
            }
          } catch (e) {}
        }

        // Special handling for Ctrl+V (paste from clipboard)
        if (key === 'ctrl-v') {
          navigator.clipboard.readText().then(function(text) {
            if (text) {
              try {
                var win = iframe.contentWindow;
                var socket = win && (win._ttydSocket || win.socket || win.ws);
                if (socket && socket.readyState === 1) {
                  socket.send('0' + text);
                }
              } catch (e) {}
            }
          }).catch(function(err) {
            console.log('Clipboard read failed:', err);
          });
          return;
        }

        // For other keys, use WebSocket directly via TTYD protocol
        try {
          var win = iframe.contentWindow;
          var socket = win && (win._ttydSocket || win.socket || win.ws);
          if (socket && socket.readyState === 1) {
            var data = null;
            var ESC = String.fromCharCode(27);
            switch (key) {
              case 'esc': data = ESC; break;
              case 'ctrl-c': data = String.fromCharCode(3); break;
              case 'ctrl-b': data = String.fromCharCode(2); break;
              case 'up': data = ESC + '[A'; break;
              case 'down': data = ESC + '[B'; break;
              case 'right': data = ESC + '[C'; break;
              case 'left': data = ESC + '[D'; break;
            }
            if (data) {
              socket.send('0' + data);
              return;
            }
          }
        } catch (e) {}
      }

      document.getElementById('vkbd').addEventListener('click', function(e) {
        if (e.target.tagName === 'BUTTON') {
          sendKey(e.target.dataset.key);
        }
      });
      iframe.addEventListener('load', function() {
        focusTerminal();
      });
    })();
  </script>'''
        else:
            vkbd_style = ''
            vkbd_html = ''

        html = f'''<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
  <title>ttyd{terminal_id} - {html_module.escape(username)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 0; height: 100vh; background: #0f131a; display: flex; flex-direction: column; }}
    #terminal {{ flex: 1; width: 100%; border: none; }}{vkbd_style}
  </style>
</head>
<body>
  <iframe id="terminal" src="{ttyd_url}" allow="clipboard-write; clipboard-read"></iframe>
  {tab_handler_script}{vkbd_html}
</body>
</html>'''

        self.send_html(200, html)

    def handle_ttyd_proxy(self, terminal_id):
        """Reverse proxy for TTYD (HTTP + WebSocket)."""
        username = self._check_auth()
        if not username:
            return

        # Look up terminal port
        terminal = ttyd_manager.get_terminal(terminal_id)
        if not terminal:
            self.send_json(404, {"error": f"Terminal ttyd{terminal_id} not found"})
            return
        port = terminal["port"]

        # Build upstream path - strip /ttyd<N> prefix
        parsed = urlparse(self.path)
        prefix = f"/ttyd{terminal_id}"
        if parsed.path.startswith(prefix + "/"):
            upstream_path = parsed.path[len(prefix):] + ("?" + parsed.query if parsed.query else "")
        else:
            upstream_path = "/"

        # Check if WebSocket upgrade request
        if self.is_websocket_request():
            self.proxy_ttyd_websocket(upstream_path, port)
        else:
            self.proxy_ttyd_http(upstream_path, port)

    def is_websocket_request(self):
        """Check if this is a WebSocket upgrade request."""
        upgrade = self.headers.get("Upgrade", "").lower()
        return upgrade == "websocket"

    def build_ttyd_headers(self, port):
        """Build headers for proxying to TTYD."""
        hop_by_hop = {
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "trailers", "transfer-encoding", "upgrade",
            "content-length", "authorization",
        }
        headers = {}
        for key, value in self.headers.items():
            if key.lower() in hop_by_hop:
                continue
            headers[key] = value
        headers["Host"] = f"127.0.0.1:{port}"
        headers["X-Forwarded-For"] = self.client_address[0]
        return headers

    def proxy_ttyd_websocket(self, upstream_path, port):
        """Proxy WebSocket to TTYD process."""
        upstream = None
        try:
            upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
        except OSError as exc:
            print(f"TTYD proxy error: {exc}", file=sys.stderr, flush=True)
            self.send_json(502, {"error": "TTYD unavailable"})
            return

        try:
            headers = self.build_ttyd_headers(port)
            headers["Connection"] = "Upgrade"
            headers["Upgrade"] = "websocket"

            request_lines = [f"{self.command} {upstream_path} {self.request_version}"]
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
            request_lines.append("")
            request_lines.append("")
            upstream.sendall("\r\n".join(request_lines).encode("utf-8"))

            self.close_connection = True
            self.tunnel_sockets(upstream)
        except Exception:
            # Error handling is done in tunnel_sockets
            pass
        finally:
            if upstream:
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except (OSError, ConnectionError):
                    pass
                upstream.close()

    def tunnel_sockets(self, upstream):
        """Bidirectional socket tunneling."""
        client = self.connection
        client.setblocking(False)
        upstream.setblocking(False)
        sockets = [client, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 60)
                if not readable:
                    continue
                for sock in readable:
                    try:
                        data = sock.recv(8192)
                    except BlockingIOError:
                        continue
                    except (OSError, ConnectionError):
                        return
                    if not data:
                        return
                    target = upstream if sock is client else client
                    try:
                        target.sendall(data)
                    except (OSError, ConnectionError):
                        return
        except Exception:
            # Silently handle exceptions during tunneling
            pass
        # Note: cleanup is handled by caller (proxy_ttyd_websocket)

    def inject_tab_fix_script(self, data, is_gzipped=False):
        """Inject Tab fix script into TTYD HTML response.

        IMPORTANT: Script MUST be injected at the START of <head> to intercept
        WebSocket creation BEFORE TTYD's main script runs. If injected at the
        end, the WebSocket is already created and cannot be intercepted.

        Injection priority:
        1. After <head> - intercepts WebSocket before TTYD loads
        2. After <html> - fallback, still early enough
        3. Prepend to start - last resort
        """
        import gzip
        try:
            # Handle gzip-compressed content
            if is_gzipped or (len(data) >= 2 and data[0:2] == b'\x1f\x8b'):
                try:
                    data = gzip.decompress(data)
                    is_gzipped = True
                except Exception:
                    return data

            html = data.decode('utf-8')
            script = TAB_FIX_SCRIPT.decode('utf-8')

            # Inject at the START of head to run before TTYD scripts
            if '<head>' in html:
                html = html.replace('<head>', '<head>' + script, 1)
            elif '<head ' in html:
                # Handle <head with attributes
                idx = html.find('<head ')
                end_idx = html.find('>', idx)
                if end_idx != -1:
                    html = html[:end_idx+1] + script + html[end_idx+1:]
            elif '<html>' in html:
                html = html.replace('<html>', '<html>' + script, 1)
            elif html.strip():
                # Fallback: prepend to start
                html = script + html

            result = html.encode('utf-8')

            # Re-compress if originally gzipped
            if is_gzipped:
                result = gzip.compress(result)

            return result
        except Exception:
            pass
        return data

    def proxy_ttyd_http(self, upstream_path, port):
        """Proxy HTTP request to TTYD process."""
        body = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                length = 0
            if length > 0 and length <= 10485760:  # Max 10MB
                body = self.rfile.read(length)

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            headers = self.build_ttyd_headers(port)
            conn.request(self.command, upstream_path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()

            # Check content type for HTML injection
            content_type = ''
            for key, value in resp.getheaders():
                if key.lower() == 'content-type':
                    content_type = value
                    break

            # Inject Tab fix script into HTML responses
            if 'text/html' in content_type and data:
                data = self.inject_tab_fix_script(data)

            self.send_response(resp.status, resp.reason)

            # Add cache control headers for HTML to prevent browser caching
            # This ensures the Tab fix script is always loaded fresh
            if 'text/html' in content_type:
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")

            # Headers to skip from upstream (hop-by-hop + CSP override for HTML)
            skip_headers = {
                "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailer", "trailers",
                "transfer-encoding", "upgrade", "content-length",
            }
            if 'text/html' in content_type:
                skip_headers.add("content-security-policy")

            for key, value in resp.getheaders():
                if key.lower() in skip_headers:
                    continue
                self.send_header(key, value)

            # Override CSP for TTYD HTML — needs unsafe-eval for TTYD's JS
            if 'text/html' in content_type:
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; "
                    "base-uri 'none'; "
                    "frame-ancestors 'self'; "
                    "object-src 'none'; "
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                    "style-src 'self' 'unsafe-inline'",
                )
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)
        except OSError as exc:
            print(f"TTYD proxy error: {exc}", file=sys.stderr, flush=True)
            self.send_json(502, {"error": "TTYD unavailable"})
        finally:
            try:
                conn.close()
            except Exception:
                pass


def main():
    """Start the TTYD proxy server."""
    server_address = ("0.0.0.0", PORT)
    print(f"Starting TTYD HTTP proxy on {server_address}...", flush=True)

    # Create first terminal automatically
    info = ttyd_manager.create_terminal(wait=True)
    if info:
        print(f"Auto-created terminal ttyd{info['id']} on port {info['port']}", flush=True)
    else:
        print("WARNING: Failed to auto-create first terminal", file=sys.stderr, flush=True)

    try:
        httpd = ThreadingHTTPServer(server_address, TTYDProxyHandler)
        httpd.daemon_threads = True  # don't block shutdown on open WebSocket threads
    except OSError as e:
        print(f"ERROR: Cannot bind to port {PORT}: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        print(f"Received signal {signum}, shutting down gracefully...", flush=True)
        # Kill all terminal processes
        with ttyd_manager.lock:
            tids = list(ttyd_manager.terminals.keys())
        for tid in tids:
            ttyd_manager.delete_terminal(tid)
        httpd.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    print(f"TTYD HTTP proxy listening on port {PORT}", flush=True)
    try:
        httpd.serve_forever()
    except Exception as e:
        print(f"HTTP Server error: {e}", file=sys.stderr, flush=True)
        raise
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
