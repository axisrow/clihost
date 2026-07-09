"""HTTP handler and process wiring for the ttyd proxy application."""
import hmac
import json
import os
import pwd
import sys
import signal
import time
from http.server import ThreadingHTTPServer
from shutil import which
from urllib.parse import parse_qs, urlparse

from server import BaseHTTPHandler as BaseHandler
from ttydproxy import assets
from ttydproxy.cleanup import delete_cleanup_targets, list_cleanup_targets, summarize_cleanup_targets
from ttydproxy.config import (
    CLEANUP_ROOT,
    HAPI_HOME,
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
    SSH_URL_FILE,
    MAX_UPLOAD_SIZE,
    UPLOAD_DIR,
    TTYD_ROUTE_PATTERN,
    MAX_TERMINAL_ID_DIGITS,
    REQUEST_TIMEOUT,
)
from ttydproxy.manager import TTYDManager
from ttydproxy.proxy import is_websocket_request, proxy_ttyd_http, proxy_ttyd_websocket
from ttydproxy.ratelimit import RateLimiter
from ttydproxy.uploads import save_upload
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
from ttydproxy.views import load_dashboard_hapi_url, load_ssh_url, render_login_page, render_menu_page, render_terminal_page, resolve_vkbd_enabled


_SERVER_START_TIME = time.time()
ttyd_manager = TTYDManager(
    base_port=TTYD_BASE_PORT,
    max_terminals=MAX_TERMINALS,
    ttyd_user=TTYD_USER,
)
login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60)
account_rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
MAX_CLEANUP_DELETE_IDS = 50
MAX_CLEANUP_TARGET_ID_LENGTH = 128
# A favicon that failed to load (None) is dropped from the routes so one
# missing decorative PNG never takes down login/terminal (B18).
FAVICON_ROUTES = {
    icon.path: (icon.content_type, icon.body)
    for icon in assets.FAVICONS
    if icon.body is not None
}
_HAPI_AVAILABLE = which("hapi") is not None


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

    # Socket read timeout applied per connection by BaseHTTPRequestHandler
    # (setup() calls self.connection.settimeout(self.timeout)). Caps slow-client
    # (slowloris) threads that would otherwise block header parsing and body
    # reads forever on a ThreadingHTTPServer worker (#101/#2).
    timeout = REQUEST_TIMEOUT

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.handle_menu()
        elif parsed.path in FAVICON_ROUTES:
            self.handle_favicon(parsed.path)
        elif parsed.path == "/login":
            self.handle_login_page()
        elif parsed.path == "/health":
            self.handle_health()
        elif parsed.path == "/cleanup":
            self.handle_cleanup_list()
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
        elif parsed.path == "/cleanup/delete":
            self.handle_cleanup_delete()
        elif parsed.path == "/terminals":
            self.handle_terminals_create()
        elif parsed.path == "/upload":
            self.handle_upload()
        else:
            self.send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = parsed.path.split("/")
        # Bound the digit count (same cap as the GET route regex) so int() can
        # never hit Python's 4300-digit string-conversion limit on this
        # unauthenticated path (B8); an over-long id falls through to a 404.
        if (
            len(parts) == 3
            and parts[1] == "terminals"
            and parts[2].isdigit()
            and len(parts[2]) <= MAX_TERMINAL_ID_DIGITS
        ):
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

    def _cookie(self, name):
        """Return a single cookie value from the request, or '' if absent."""
        return parse_cookie_header(self.headers.get("Cookie", "")).get(name, "")

    def _session_username(self):
        token = self._cookie("ttyd_session")
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
            # A valid cookie whose account was since removed/renamed must, for a
            # browser navigation (redirect=True), land on /login like the
            # no-token branch above — not a raw 403 JSON blob (#101/#5).
            if redirect:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            else:
                self.send_json(403, {"error": "Invalid session"})
            return None
        return username

    def _check_csrf(
        self,
        payload=None,
        status=419,
        missing_error="CSRF token missing — please refresh the page",
        invalid_error="CSRF token expired — please refresh the page",
    ):
        """Validate the CSRF double-submit token.

        Uses the X-CSRF-Token header, falling back to the request payload's
        ``csrf_token`` field when ``payload`` is provided (form login). The
        status code and error messages are parameters so the login flow can
        return 403 with its own wording while API routes return 419.
        """
        provided_token = (
            self.headers.get("X-CSRF-Token", "") or (payload or {}).get("csrf_token", "")
        ).strip()
        csrf_cookie = self._cookie("csrf_token")
        if not provided_token or not csrf_cookie:
            self.send_json(status, {"error": missing_error})
            return False
        if not hmac.compare_digest(provided_token, csrf_cookie) or not parse_csrf_token(
            provided_token, PASSWORD_SECRET, CSRF_TOKEN_TTL
        ):
            self.send_json(status, {"error": invalid_error})
            return False
        return True

    def _read_binary_request_body(self, max_size):
        """Read the raw request body. Returns bytes or None on error."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self.send_json(400, {"error": "Invalid Content-Length"})
            return None
        if content_length < 0 or content_length > max_size:
            self.send_json(413, {"error": "Request too large"})
            return None
        return self.rfile.read(content_length)

    def _read_request_body(self):
        """Read and UTF-8 decode the request body. Returns text or None on error."""
        data = self._read_binary_request_body(1048576)
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            self.send_json(400, {"error": "Invalid encoding"})
            return None

    def _content_type(self):
        return self.headers.get_content_type()

    def _load_login_payload(self):
        raw_data = self._read_request_body()
        if raw_data is None:
            return None

        content_type = self._content_type()
        if content_type == "application/json":
            try:
                data = json.loads(raw_data or "{}")
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
                return None
            return {
                "username": data.get("username", "").strip(),
                "password": data.get("password", ""),
                "csrf_token": data.get("csrf_token", ""),
            }

        if content_type == "application/x-www-form-urlencoded":
            form = parse_qs(raw_data, keep_blank_values=True)
            return {
                "username": (form.get("username", [""])[0]).strip(),
                "password": form.get("password", [""])[0],
                "csrf_token": form.get("csrf_token", [""])[0],
            }

        self.send_json(415, {"error": "Unsupported content type"})
        return None

    def _load_json_payload(self):
        raw_data = self._read_request_body()
        if raw_data is None:
            return None
        if self._content_type() != "application/json":
            self.send_json(415, {"error": "Unsupported content type"})
            return None
        try:
            return json.loads(raw_data or "{}")
        except json.JSONDecodeError:
            self.send_json(400, {"error": "Invalid JSON"})
            return None

    def handle_login_page(self):
        extra_headers, csrf_token = self._auth_cookie_headers()
        self.send_html(200, render_login_page(csrf_token), extra_headers=extra_headers)

    def handle_favicon(self, path):
        """Serve fixed favicon assets without requiring authentication."""
        content_type, body = FAVICON_ROUTES[path]
        self.send_binary(200, body, content_type)

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

    def handle_cleanup_list(self):
        username = self._check_auth()
        if not username:
            return
        targets = list_cleanup_targets(CLEANUP_ROOT, HAPI_HOME)
        self.send_json(200, {"targets": targets, "summary": summarize_cleanup_targets(targets)})

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

    def handle_upload(self):
        username = self._check_auth()
        if not username or not self._check_csrf():
            return
        data = self._read_binary_request_body(MAX_UPLOAD_SIZE)
        if data is None:
            return
        if not data:
            self.send_json(400, {"error": "Empty upload"})
            return
        try:
            path = save_upload(data, UPLOAD_DIR, TTYD_USER)
        except ValueError as exc:
            # save_upload is the single validator and owns the message.
            self.send_json(415, {"error": str(exc)})
            return
        except OSError:
            self.send_json(500, {"error": "Failed to save upload"})
            return
        self.send_json(201, {"path": path})

    def handle_cleanup_delete(self):
        username = self._check_auth()
        if not username or not self._check_csrf():
            return

        payload = self._load_json_payload()
        if payload is None:
            return

        target_ids = payload.get("ids")
        if not isinstance(target_ids, list) or not target_ids:
            self.send_json(400, {"error": "ids must be a non-empty array"})
            return
        if len(target_ids) > MAX_CLEANUP_DELETE_IDS:
            self.send_json(400, {"error": f"ids must contain at most {MAX_CLEANUP_DELETE_IDS} items"})
            return
        if any(not isinstance(target_id, str) or not target_id for target_id in target_ids):
            self.send_json(400, {"error": "ids must contain non-empty strings"})
            return
        if any(len(target_id) > MAX_CLEANUP_TARGET_ID_LENGTH for target_id in target_ids):
            self.send_json(400, {"error": f"ids must be at most {MAX_CLEANUP_TARGET_ID_LENGTH} characters long"})
            return

        self.send_json(200, delete_cleanup_targets(target_ids, CLEANUP_ROOT, HAPI_HOME))

    def handle_login(self):
        client_ip = self.client_address[0]
        if not login_rate_limiter.is_allowed(client_ip):
            self.send_json(429, {"error": "Too many login attempts. Please try again later."})
            return

        payload = self._load_login_payload()
        if payload is None:
            return

        if not self._check_csrf(
            payload=payload,
            status=403,
            missing_error="CSRF token missing",
            invalid_error="Invalid CSRF token",
        ):
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
        hapi_url = load_dashboard_hapi_url(
            HAPI_HOME,
            HAPI_URL_FILE,
            hapi_available=_HAPI_AVAILABLE,
        )
        ssh_conn = load_ssh_url(SSH_URL_FILE)
        self.send_html(200, render_menu_page(username, hapi_url, ssh_conn), extra_headers=extra_headers)

    def handle_ttyd(self, terminal_id):
        username = self._check_auth(redirect=True)
        if not username:
            return
        terminal = ttyd_manager.get_terminal(terminal_id)
        if not terminal:
            self.send_json(404, {"error": f"Terminal ttyd{terminal_id} not found"})
            return
        vkbd_enabled = resolve_vkbd_enabled(self.path, VIRTUAL_KEYBOARD)
        # Refresh the CSRF cookie: image uploads from a long-lived terminal
        # tab must not outlive the token minted on the last dashboard visit.
        extra_headers, _csrf_token = self._auth_cookie_headers()
        self.send_html(
            200,
            render_terminal_page(terminal_id, username, vkbd_enabled),
            extra_headers=extra_headers,
        )

    def handle_ttyd_proxy(self, terminal_id):
        username = self._check_auth()
        if not username:
            return
        terminal = ttyd_manager.get_terminal(terminal_id)
        if not terminal:
            self.send_json(404, {"error": f"Terminal ttyd{terminal_id} not found"})
            return
        # NOTE (#101/#8, deferred): the lock is released inside get_terminal(),
        # so this `port` is not revalidated at connect time. If terminal_id is
        # deleted and its port reused (lowest-free, see _allocate_port) before
        # the connect below, an in-flight request could reach a different
        # terminal's ttyd. The window is narrow (usually ECONNREFUSED->502) and
        # not a security boundary; a proper fix (a per-terminal lease/refcount
        # holding the port until the request completes) is tracked separately.
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


def _warn_on_user_mismatch():
    """Warn when running unprivileged as a user other than TTYD_USER."""
    if os.geteuid() == 0:
        return
    try:
        current_user = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        current_user = f"uid {os.geteuid()}"
    if current_user != TTYD_USER:
        print(
            f"WARNING: proxy running as {current_user}, not root; cannot switch to "
            f"TTYD_USER={TTYD_USER} — terminals will run as {current_user}",
            file=sys.stderr,
            flush=True,
        )


def main():
    """Start the ttyd proxy server."""
    _warn_on_user_mismatch()
    server_address = ("0.0.0.0", PORT)
    print(f"Starting TTYD HTTP proxy on {server_address}...", flush=True)

    info = ttyd_manager.create_terminal(wait=True)
    if info:
        print(f"Auto-created terminal ttyd{info['id']} on port {info['port']}", flush=True)
    else:
        print("WARNING: Failed to auto-create first terminal", file=sys.stderr, flush=True)

    # Background reaper: a ttyd that dies while no one lists/gets it (or polls
    # /health) would otherwise stay a defunct zombie holding its PID slot (#7).
    ttyd_manager.start_reaper()

    try:
        httpd = ThreadingHTTPServer(server_address, TTYDProxyHandler)
        httpd.daemon_threads = True
    except OSError as exc:
        print(f"ERROR: Cannot bind to port {PORT}: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    def signal_handler(signum, _frame):
        print(f"Received signal {signum}, shutting down gracefully...", flush=True)
        ttyd_manager.stop_reaper()
        with ttyd_manager.lock:
            terminal_ids = list(ttyd_manager.terminals.keys())
        for terminal_id in terminal_ids:
            ttyd_manager.delete_terminal(terminal_id)
        # Never call httpd.shutdown() here: the handler runs in the main
        # thread, which is inside serve_forever(); shutdown() waits for
        # serve_forever() to exit and deadlocks. SystemExit unwinds
        # serve_forever() and the finally clause closes the server.
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
