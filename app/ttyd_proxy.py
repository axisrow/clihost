#!/usr/bin/env python3
"""
TTYD HTTP Proxy Server
Proxies HTTP/WebSocket traffic to TTYD process on 127.0.0.1:7681
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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
import pwd
import spwd
import crypt
import subprocess
import re

# Import base HTTP server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server import BaseHTTPHandler as BaseHandler

# Configuration
PORT = int(os.environ.get("PORT", "8080"))
TTYD_USER = os.environ.get("TTYD_USER", "hapi")
TTYD_PASSWORD = os.environ.get("TTYD_PASSWORD", "")
PASSWORD_SECRET = os.environ.get("PASSWORD_SECRET", "default-secret-change-me")
TTYD_TTYD_PORT = 7681  # Hardcoded internal TTYD port
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "86400"))  # 24 hours default

# Load templates
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# Username validation pattern - only alphanumeric, underscore, hyphen, dot
# Max length 32 chars per Linux username limits
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]{1,32}$')


class RateLimiter:
    """Simple rate limiter for login attempts."""
    def __init__(self, max_attempts=5, window_seconds=60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, key):
        """Check if the request is allowed for the given key."""
        with self.lock:
            current_time = int(time.time())
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
            # Root - show main menu (after auth)
            self.handle_menu()
        elif parsed.path == "/login":
            # Login page
            self.handle_login_page()
        elif parsed.path == "/health":
            self.handle_health()
        elif parsed.path == "/ttyd":
            self.handle_ttyd()
        elif parsed.path.startswith("/ttyd/"):
            self.handle_ttyd_proxy()
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)

        if parsed.path == "/login":
            self.handle_login()
        else:
            self.send_json(404, {"error": "Not found"})

    def handle_login_page(self):
        """Show login form."""
        html = load_template('login.html')
        self.send_html(200, html)

    def handle_health(self):
        """Health check endpoint."""
        # Check if TTYD process is accessible
        try:
            sock = socket.create_connection(("127.0.0.1", TTYD_TTYD_PORT), timeout=1)
            sock.close()
            ttyd_status = "running"
        except OSError:
            ttyd_status = "unavailable"

        self.send_json(200, {"status": "ok", "ttyd": ttyd_status})

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

        post_data = self.rfile.read(content_length).decode("utf-8")

        try:
            import json
            data = json.loads(post_data)
            username = data.get("username", "").strip()
            password = data.get("password", "")
        except json.JSONDecodeError:
            self.send_json(400, {"error": "Invalid JSON"})
            return

        if not username:
            self.send_json(400, {"error": "Username required"})
            return

        # Validate username to prevent command injection
        if not is_valid_username(username):
            self.send_json(400, {"error": "Invalid username format"})
            return

        # Check optional global password
        if TTYD_PASSWORD and password != TTYD_PASSWORD:
            self.send_json(401, {"error": "Invalid password"})
            return

        # Verify user exists
        try:
            pwd.getpwnam(username)
        except KeyError:
            self.send_json(401, {"error": "Invalid credentials"})
            return

        # If TTYD_PASSWORD is not set, verify system password
        if not TTYD_PASSWORD:
            if not password:
                self.send_json(400, {"error": "Password required"})
                return
            if not verify_pam_password(username, password):
                self.send_json(401, {"error": "Invalid credentials"})
                return

        # Create session token
        session_token = build_ttyd_session(username, TTYD_TTYD_PORT)

        # Set secure cookie flags - don't trust X-Forwarded-* headers for security
        # Use Lax by default for same-origin requests
        # Only set Secure flag if we're confident it's HTTPS (configured by admin)
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"ttyd_session={session_token}; Path=/; HttpOnly; SameSite=Lax",
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

        # Load and render menu template
        html = load_template('index.html')
        html = html.replace('{{USERNAME}}', username)

        if hapi_url:
            hapi_link = f'<a href="{hapi_url}" target="_blank" class="menu-link">HAPI Server</a>'
        else:
            hapi_link = '<span class="menu-link disabled">HAPI Server (not available)</span>'

        html = html.replace('{{HAPI_LINK}}', hapi_link)
        self.send_html(200, html)

    def handle_ttyd(self):
        """Return HTML page with login form or terminal iframe."""
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

        # Return terminal iframe page
        ttyd_url = "/ttyd/"
        html = f'''<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Terminal - {username}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 0; height: 100vh; background: #0f131a; }}
    #terminal {{ width: 100%; height: 100%; border: none; }}
  </style>
</head>
<body>
  <iframe id="terminal" src="{ttyd_url}" allow="clipboard-write; clipboard-read"></iframe>
</body>
</html>'''

        self.send_html(200, html)

    def handle_ttyd_proxy(self):
        """Reverse proxy for TTYD (HTTP + WebSocket)."""
        # Get session from cookie
        cookies = self.parse_cookie_header(self.headers.get("Cookie", ""))
        token = cookies.get("ttyd_session")
        username, port = parse_ttyd_session(token)

        if not username or not port:
            self.send_json(403, {"error": "Authentication required"})
            return

        # Validate username from session token
        if not is_valid_username(username):
            self.send_json(403, {"error": "Invalid session"})
            return

        # Verify user exists
        try:
            pwd.getpwnam(username)
        except KeyError:
            self.send_json(403, {"error": "Invalid session"})
            return

        # Verify port matches expected TTYD port
        if port != TTYD_TTYD_PORT:
            self.send_json(403, {"error": "Session expired"})
            return

        # Build upstream path
        parsed = urlparse(self.path)
        if parsed.path.startswith("/ttyd/"):
            upstream_path = parsed.path[len("/ttyd"):] + ("?" + parsed.query if parsed.query else "")
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
            self.send_json(502, {"error": "TTYD unavailable", "detail": str(exc)})
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

            self.send_response(resp.status, resp.reason)
            for key, value in resp.getheaders():
                key_lower = key.lower()
                if key_lower in {
                    "connection", "keep-alive", "proxy-authenticate",
                    "proxy-authorization", "te", "trailer", "trailers",
                    "transfer-encoding", "upgrade", "content-length",
                }:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)
        except OSError as exc:
            self.send_json(502, {"error": "TTYD unavailable", "detail": str(exc)})
        finally:
            try:
                conn.close()
            except Exception:
                pass


def main():
    """Start the TTYD proxy server."""
    server_address = ("0.0.0.0", PORT)
    print(f"Starting TTYD HTTP proxy on {server_address}...", flush=True)

    try:
        httpd = HTTPServer(server_address, TTYDProxyHandler)
    except OSError as e:
        print(f"ERROR: Cannot bind to port {PORT}: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        print(f"Received signal {signum}, shutting down gracefully...", flush=True)
        httpd.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    print(f"TTYD HTTP proxy listening on port {PORT}", flush=True)
    print(f"Proxying to TTYD on 127.0.0.1:{TTYD_TTYD_PORT}", flush=True)
    try:
        httpd.serve_forever()
    except Exception as e:
        print(f"HTTP Server error: {e}", file=sys.stderr, flush=True)
        raise
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
