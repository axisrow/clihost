"""HTTP handler and process wiring for the ttyd proxy application."""
import json
import sys
import signal
import time
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from server import BaseHTTPHandler as BaseHandler
from ttydproxy.config import (
    PORT,
    TTYD_USER,
    TTYD_PASSWORD,
    PASSWORD_SECRET,
    TTYD_BASE_PORT,
    MAX_TERMINALS,
    SESSION_TIMEOUT,
    VIRTUAL_KEYBOARD,
    CSRF_TOKEN_TTL,
    SECURE_COOKIES,
    HAPI_URL_FILE,
    TTYD_ROUTE_PATTERN,
)
from ttydproxy.manager import TTYDManager
from ttydproxy.proxy import is_websocket_request, proxy_ttyd_http, proxy_ttyd_websocket
from ttydproxy.ratelimit import RateLimiter
from ttydproxy.security import (
    build_csrf_token,
    build_session_token,
    is_valid_username,
    parse_cookie_header,
    parse_csrf_token,
    parse_session_token,
    user_exists,
    verify_pam_password,
)
from ttydproxy.views import load_hapi_url, render_login_page, render_menu_page, render_terminal_page, resolve_vkbd_enabled


_SERVER_START_TIME = time.time()
ttyd_manager = TTYDManager(
    base_port=TTYD_BASE_PORT,
    max_terminals=MAX_TERMINALS,
    ttyd_user=TTYD_USER,
)
login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60)
account_rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)


def _get_memory_rss_mb():
    """Read process RSS memory from /proc/self/status. Returns float or None."""
    try:
        with open("/proc/self/status") as status_file:
            for line in status_file:
                if line.startswith("VmRSS:"):
                    kb = int(line.split()[1])
                    return round(kb / 1024, 1)
    except OSError:
        return None
    return None


class TTYDProxyHandler(BaseHandler):
    """HTTP request handler for ttyd proxy routes."""

    def do_GET(self):
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
            match = TTYD_ROUTE_PATTERN.match(parsed.path)
            if not match:
                self.send_json(404, {"error": "Not found"})
                return
            terminal_id = int(match.group(1))
            sub_path = match.group(2)
            if sub_path:
                self.handle_ttyd_proxy(terminal_id)
            else:
                self.handle_ttyd(terminal_id)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self.handle_login()
        elif parsed.path == "/terminals":
            self.handle_terminals_create()
        else:
            self.send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = parsed.path.split("/")
        if len(parts) == 3 and parts[1] == "terminals" and parts[2].isdigit():
            self.handle_terminals_delete(int(parts[2]))
            return
        self.send_json(404, {"error": "Not found"})

    def _secure_flag(self):
        return " Secure;" if SECURE_COOKIES else ""

    def _auth_cookie_headers(self):
        csrf_token = build_csrf_token(PASSWORD_SECRET)
        return {
            "Set-Cookie": f"csrf_token={csrf_token}; Path=/; SameSite=Lax;{self._secure_flag()}",
        }, csrf_token

    def _session_username(self):
        cookies = parse_cookie_header(self.headers.get("Cookie", ""))
        token = cookies.get("ttyd_session")
        return parse_session_token(token, PASSWORD_SECRET)

    def _check_auth(self, redirect=False):
        username = self._session_username()
        if not username:
            if redirect:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            else:
                self.send_json(401, {"error": "Authentication required"})
            return None
        if not user_exists(username):
            self.send_json(403, {"error": "Invalid session"})
            return None
        return username

    def _check_csrf(self):
        csrf_header = self.headers.get("X-CSRF-Token", "")
        csrf_cookie = parse_cookie_header(self.headers.get("Cookie", "")).get("csrf_token", "")
        if not csrf_header or not csrf_cookie:
            self.send_json(419, {"error": "CSRF token missing — please refresh the page"})
            return False
        if csrf_header != csrf_cookie or not parse_csrf_token(csrf_header, PASSWORD_SECRET, CSRF_TOKEN_TTL):
            self.send_json(419, {"error": "CSRF token expired — please refresh the page"})
            return False
        return True

    def _load_login_payload(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 1048576:
            self.send_json(413, {"error": "Request too large"})
            return None
        try:
            post_data = self.rfile.read(content_length).decode("utf-8")
        except UnicodeDecodeError:
            self.send_json(400, {"error": "Invalid encoding"})
            return None

        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type == "application/json":
            try:
                data = json.loads(post_data)
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
                return None
            return {
                "username": data.get("username", "").strip(),
                "password": data.get("password", ""),
                "csrf_token": data.get("csrf_token", ""),
            }

        if content_type == "application/x-www-form-urlencoded":
            form = parse_qs(post_data, keep_blank_values=True)
            return {
                "username": (form.get("username", [""])[0]).strip(),
                "password": form.get("password", [""])[0],
                "csrf_token": form.get("csrf_token", [""])[0],
            }

        self.send_json(415, {"error": "Unsupported content type"})
        return None

    def handle_login_page(self):
        extra_headers, csrf_token = self._auth_cookie_headers()
        self.send_html(200, render_login_page(csrf_token), extra_headers=extra_headers)

    def handle_health(self):
        terminals = ttyd_manager.list_terminals()
        response = {
            "status": "ok",
            "uptime": int(time.time() - _SERVER_START_TIME),
            "ttyd": "running" if terminals else "no terminals",
            "terminal_count": len(terminals),
            "terminals": [{"id": terminal["id"], "alive": True} for terminal in terminals],
        }
        mem_mb = _get_memory_rss_mb()
        if mem_mb is not None:
            response["memory_mb"] = mem_mb
        self.send_json(200, response)

    def handle_terminals_list(self):
        username = self._check_auth()
        if not username:
            return
        self.send_json(200, {"terminals": ttyd_manager.list_terminals()})

    def handle_terminals_create(self):
        username = self._check_auth()
        if not username or not self._check_csrf():
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
        username = self._check_auth()
        if not username or not self._check_csrf():
            return
        if ttyd_manager.delete_terminal(terminal_id):
            self.send_json(200, {"deleted": terminal_id})
        else:
            self.send_json(404, {"error": f"Terminal {terminal_id} not found"})

    def handle_login(self):
        client_ip = self.client_address[0]
        if not login_rate_limiter.is_allowed(client_ip):
            self.send_json(429, {"error": "Too many login attempts. Please try again later."})
            return

        payload = self._load_login_payload()
        if payload is None:
            return

        csrf_header = self.headers.get("X-CSRF-Token", "")
        csrf_cookie = parse_cookie_header(self.headers.get("Cookie", "")).get("csrf_token", "")
        provided_token = (csrf_header or payload["csrf_token"]).strip()
        if not provided_token or not csrf_cookie:
            self.send_json(403, {"error": "CSRF token missing"})
            return
        if provided_token != csrf_cookie or not parse_csrf_token(provided_token, PASSWORD_SECRET, CSRF_TOKEN_TTL):
            self.send_json(403, {"error": "Invalid CSRF token"})
            return

        username = payload["username"]
        password = payload["password"]
        if not username:
            self.send_json(400, {"error": "Username required"})
            return
        if not account_rate_limiter.is_allowed(f"{client_ip}:{username}"):
            self.send_json(429, {"error": "Too many login attempts. Please try again later."})
            return
        if not is_valid_username(username):
            self.send_json(400, {"error": "Invalid username format"})
            return
        if TTYD_PASSWORD and password != TTYD_PASSWORD:
            time.sleep(0.5)
            self.send_json(401, {"error": "Invalid password"})
            return
        if not user_exists(username):
            time.sleep(0.5)
            self.send_json(401, {"error": "Invalid credentials"})
            return
        if not TTYD_PASSWORD:
            if not password:
                self.send_json(400, {"error": "Password required"})
                return
            if not verify_pam_password(username, password):
                time.sleep(0.5)
                self.send_json(401, {"error": "Invalid credentials"})
                return

        session_token = build_session_token(username, PASSWORD_SECRET, SESSION_TIMEOUT)
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"ttyd_session={session_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TIMEOUT};{self._secure_flag()}",
        )
        self.end_headers()

    def handle_menu(self):
        username = self._check_auth(redirect=True)
        if not username:
            return
        extra_headers, _csrf_token = self._auth_cookie_headers()
        hapi_url = load_hapi_url(HAPI_URL_FILE)
        self.send_html(200, render_menu_page(username, hapi_url), extra_headers=extra_headers)

    def handle_ttyd(self, terminal_id):
        username = self._check_auth(redirect=True)
        if not username:
            return
        terminal = ttyd_manager.get_terminal(terminal_id)
        if not terminal:
            self.send_json(404, {"error": f"Terminal ttyd{terminal_id} not found"})
            return
        vkbd_enabled = resolve_vkbd_enabled(self.path, VIRTUAL_KEYBOARD)
        self.send_html(200, render_terminal_page(terminal_id, username, vkbd_enabled))

    def handle_ttyd_proxy(self, terminal_id):
        username = self._check_auth()
        if not username:
            return
        terminal = ttyd_manager.get_terminal(terminal_id)
        if not terminal:
            self.send_json(404, {"error": f"Terminal ttyd{terminal_id} not found"})
            return
        port = terminal["port"]
        parsed = urlparse(self.path)
        prefix = f"/ttyd{terminal_id}"
        if parsed.path.startswith(prefix + "/"):
            upstream_path = parsed.path[len(prefix):] + ("?" + parsed.query if parsed.query else "")
        else:
            upstream_path = "/"

        if is_websocket_request(self):
            proxy_ttyd_websocket(self, upstream_path, port)
        else:
            proxy_ttyd_http(self, upstream_path, port)


def main():
    """Start the ttyd proxy server."""
    server_address = ("0.0.0.0", PORT)
    print(f"Starting TTYD HTTP proxy on {server_address}...", flush=True)

    info = ttyd_manager.create_terminal(wait=True)
    if info:
        print(f"Auto-created terminal ttyd{info['id']} on port {info['port']}", flush=True)
    else:
        print("WARNING: Failed to auto-create first terminal", file=sys.stderr, flush=True)

    try:
        httpd = ThreadingHTTPServer(server_address, TTYDProxyHandler)
        httpd.daemon_threads = True
    except OSError as exc:
        print(f"ERROR: Cannot bind to port {PORT}: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    def signal_handler(signum, _frame):
        print(f"Received signal {signum}, shutting down gracefully...", flush=True)
        with ttyd_manager.lock:
            terminal_ids = list(ttyd_manager.terminals.keys())
        for terminal_id in terminal_ids:
            ttyd_manager.delete_terminal(terminal_id)
        httpd.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    print(f"TTYD HTTP proxy listening on port {PORT}", flush=True)
    try:
        httpd.serve_forever()
    except Exception as exc:
        print(f"HTTP Server error: {exc}", file=sys.stderr, flush=True)
        raise
    finally:
        httpd.server_close()
