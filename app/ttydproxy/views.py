"""HTML rendering and template helpers for ttyd proxy pages."""
import html as html_module
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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


def load_ssh_url(url_file):
    """Read and validate the SSH connection-string file written by the tunnel.

    Unlike load_hapi_url the content is not an HTTP URL but a single shell
    command (e.g. 'ssh -p 2222 hapi@host' or 'ssh -o ProxyCommand=... ...').
    We never interpret it - only surface it for display. Reject anything that is
    not a single non-empty line starting with 'ssh ' (no embedded newlines,
    carriage returns, NULs, or other control chars that could smuggle a second
    command past the copy-paste path).
    """
    try:
        raw = Path(url_file).read_text(encoding="utf-8")
    except OSError:
        return None
    candidate = raw.strip()
    if not candidate:
        return None
    if not candidate.startswith("ssh "):
        return None
    if "\n" in candidate or "\r" in candidate or "\x00" in candidate:
        return None
    return candidate
