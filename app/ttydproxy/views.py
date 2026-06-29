"""HTML rendering and template helpers for ttyd proxy pages."""
import html as html_module
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from ttydproxy import assets
from ttydproxy.security import env_bool


APP_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = APP_ROOT

# Only advertise a <link> for a favicon that actually loaded, so a missing
# decorative PNG is not referenced by a dead route (B18).
FAVICON_LINKS = "\n  ".join(
    icon.link for icon in assets.FAVICONS if icon.body is not None
)

# Neutral dashboard title (issue #63) — shown whether or not hapi is present.
DEFAULT_TITLE = "clihost"

# Placeholders substituted into every rendered page. {{TITLE}} defaults to the
# neutral title here; pages that need a dynamic title (e.g. terminals) override it.
BASE_REPLACEMENTS = {"{{FAVICON}}": FAVICON_LINKS, "{{TITLE}}": DEFAULT_TITLE}

# Allowlist for the SSH connection string shown on the dashboard (issue #80).
# The string is pasted into a shell by the user, so we accept ONLY two exact
# grammars the tunnel writes (chisel / cloudflared). Anything else - arbitrary
# ProxyCommand, -F, LocalCommand, extra options, non-numeric port, host with / or
# :, shell metacharacters - fails to match and is rejected. re.fullmatch anchors
# both ends, so no trailing/leading payload survives.
_SSH_USER = r"[A-Za-z0-9._-]+"
_SSH_HOST = r"[A-Za-z0-9.-]+"
# 1. chisel: ssh -p <PORT> <USER>@<HOST>
_SSH_CHISEL_RE = re.compile(rf"ssh -p [0-9]{{1,5}} {_SSH_USER}@{_SSH_HOST}")
# 2. cloudflared: the ProxyCommand value is pinned to exactly this string, so a
#    hostile ProxyCommand (executed locally by ssh before connecting) cannot ride it.
_SSH_CLOUDFLARED_RE = re.compile(
    rf'ssh -o ProxyCommand="cloudflared access ssh --hostname %h" {_SSH_USER}@{_SSH_HOST}'
)
_HAPI_RELAY_URL_RE = re.compile(r"https://[A-Za-z0-9-]+\.relay\.hapi\.run")
_HAPI_CLI_TOKEN_RE = re.compile(r'"cliApiToken"\s*:\s*"([^"]+)"')


@lru_cache(maxsize=None)
def load_template(filename):
    """Load an HTML template from disk."""
    template_path = TEMPLATE_DIR / filename
    try:
        return template_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"<html><body><h1>Template {filename} not found</h1></body></html>"


def render_template(filename, replacements):
    """Render a template using plain placeholder replacement.

    Base replacements shared by every page (e.g. the favicon links) are applied
    automatically; callers only pass page-specific values.
    """
    content = load_template(filename)
    for key, value in {**BASE_REPLACEMENTS, **replacements}.items():
        content = content.replace(key, value)
    return content


def resolve_vkbd_enabled(path, default_enabled):
    """Resolve whether the virtual keyboard should be enabled for a request path."""
    query = parse_qs(urlparse(path).query)
    vkbd_enabled = default_enabled
    if "vkbd" in query:
        vkbd_enabled = env_bool(query.get("vkbd", [""])[0], default=vkbd_enabled)
    return vkbd_enabled


def render_login_page(csrf_token):
    """Render the login page with a CSRF token."""
    return render_template("login.html", {"{{CSRF_TOKEN}}": csrf_token})


def render_menu_page(username, hapi_url, ssh_conn=None):
    """Render the main dashboard menu."""
    if hapi_url:
        escaped_url = html_module.escape(hapi_url, quote=True)
        hapi_link = f'<a href="{escaped_url}" target="_blank" class="menu-link">HAPI Server</a>'
    else:
        hapi_link = ""  # without hapi the menu item disappears entirely (issue #63)
    if ssh_conn:
        escaped_conn = html_module.escape(ssh_conn, quote=True)
        ssh_link = f'<code class="ssh-link">{escaped_conn}</code>'
    else:
        ssh_link = ""  # no tunnel -> no SSH block, like HAPI item disappears
    return render_template(
        "index.html",
        {
            "{{USERNAME}}": html_module.escape(username),
            "{{HAPI_LINK}}": hapi_link,
            "{{SSH_LINK}}": ssh_link,
        },
    )


def render_terminal_page(terminal_id, username, vkbd_enabled):
    """Render the ttyd iframe page."""
    replacements = {
        "{{TITLE}}": f"ttyd{terminal_id} - {html_module.escape(username)}",
        "{{TTYD_URL}}": f"/ttyd{terminal_id}/",
        "{{TAB_HANDLER_SCRIPT}}": assets.TERMINAL_PARENT_TAB_HANDLER,
        "{{VKBD_STYLE}}": assets.VIRTUAL_KEYBOARD_STYLE if vkbd_enabled else "",
        "{{VKBD_HTML}}": assets.VIRTUAL_KEYBOARD_HTML if vkbd_enabled else "",
    }
    return render_template("terminal.html", replacements)


def load_hapi_url(url_file):
    """Read and validate the HAPI relay URL file."""
    try:
        hapi_url = Path(url_file).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    parsed_url = urlparse(hapi_url)
    if parsed_url.scheme not in ("http", "https"):
        return None
    return hapi_url


def build_hapi_url_from_runtime(server_log_text, settings_text):
    """Build a HAPI app URL from the live relay log and hapi settings text."""
    relay_urls = _HAPI_RELAY_URL_RE.findall(server_log_text or "")
    token_match = _HAPI_CLI_TOKEN_RE.search(settings_text or "")
    if not relay_urls or not token_match:
        return None
    relay_url = relay_urls[-1]
    token = token_match.group(1)
    if not token:
        return None
    encoded_relay_url = quote(relay_url, safe="")
    encoded_token = quote(token, safe="")
    return f"https://app.hapi.run/?hub={encoded_relay_url}&token={encoded_token}"


def load_runtime_hapi_url(server_log_file, settings_file):
    """Read live hapi runtime files and build the dashboard URL if available."""
    try:
        server_log_text = Path(server_log_file).read_text(encoding="utf-8", errors="replace")
        settings_text = Path(settings_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return build_hapi_url_from_runtime(server_log_text, settings_text)


def load_dashboard_hapi_url(hapi_home, url_file, hapi_available=True):
    """Resolve the dashboard HAPI link from live runtime files, then fallback file."""
    if not hapi_available:
        return None
    runtime_url = load_runtime_hapi_url(
        Path(hapi_home) / "server.log",
        Path(hapi_home) / "settings.json",
    )
    return runtime_url or load_hapi_url(url_file)


def load_ssh_url(url_file):
    """Read and validate the SSH connection-string file written by the tunnel.

    The user copies this string into a shell, so it is accepted ONLY when it
    matches one of two exact grammars (re.fullmatch, both ends anchored):
      1. chisel:     ssh -p <PORT> <USER>@<HOST>
      2. cloudflared: ssh -o ProxyCommand="cloudflared access ssh --hostname %h"
                        <USER>@<HOST>
    The cloudflared ProxyCommand value is pinned verbatim, so an arbitrary
    ProxyCommand - which ssh executes locally before connecting (RCE) - cannot
    pass. Any other option (-F, LocalCommand, extra flags), non-numeric port,
    host containing / or :, and any shell metacharacter simply fail to match and
    are rejected. Newlines/CR/NUL/control chars are rejected too (none are in the
    allowed character classes). We never interpret the string, only display it.
    """
    try:
        raw = Path(url_file).read_text(encoding="utf-8")
    except OSError:
        return None
    candidate = raw.strip()
    if not candidate:
        return None
    if _SSH_CHISEL_RE.fullmatch(candidate) or _SSH_CLOUDFLARED_RE.fullmatch(candidate):
        return candidate
    return None
