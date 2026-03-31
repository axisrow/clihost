"""HTML rendering and template helpers for ttyd proxy pages."""
import html as html_module
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ttydproxy import assets
from ttydproxy.security import env_bool


APP_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = APP_ROOT


@lru_cache(maxsize=None)
def load_template(filename):
    """Load an HTML template from disk."""
    template_path = TEMPLATE_DIR / filename
    try:
        return template_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"<html><body><h1>Template {filename} not found</h1></body></html>"


def render_template(filename, replacements):
    """Render a template using plain placeholder replacement."""
    content = load_template(filename)
    for key, value in replacements.items():
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


def render_menu_page(username, hapi_url):
    """Render the main dashboard menu."""
    if hapi_url:
        escaped_url = html_module.escape(hapi_url, quote=True)
        hapi_link = f'<a href="{escaped_url}" target="_blank" class="menu-link">HAPI Server</a>'
    else:
        hapi_link = '<span class="menu-link disabled">HAPI Server (not available)</span>'
    return render_template(
        "index.html",
        {
            "{{USERNAME}}": html_module.escape(username),
            "{{HAPI_LINK}}": hapi_link,
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

