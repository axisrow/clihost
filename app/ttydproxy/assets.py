"""Static asset loading for terminal HTML and injected scripts.

The contract mirrors views.load_template's robustness, differentiated by how
critical the asset is (B18):
  - required assets (injected scripts, virtual keyboard) fail fast at import
    with a clear error naming the file, instead of a bare deep traceback;
  - decorative assets (favicons) degrade: a missing file yields None so the
    caller can drop the route/link rather than abort the whole proxy.
"""
from collections import namedtuple
from functools import lru_cache
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parent.parent
ASSET_DIR = APP_ROOT / "assets"


@lru_cache(maxsize=None)
def load_asset(filename):
    """Load a static asset from disk."""
    path = ASSET_DIR / filename
    return path.read_text(encoding="utf-8")


@lru_cache(maxsize=None)
def load_asset_bytes(filename):
    """Load a binary static asset from disk."""
    path = ASSET_DIR / filename
    return path.read_bytes()


def _load_required(filename):
    """Eager-load a required asset; fail fast with a file-naming error."""
    try:
        return load_asset(filename)
    except (FileNotFoundError, OSError) as exc:
        raise RuntimeError(f"Required asset missing: {ASSET_DIR / filename}") from exc


def _load_optional_bytes(filename):
    """Eager-load a decorative asset; return None if it can't be read."""
    try:
        return load_asset_bytes(filename)
    except (FileNotFoundError, OSError):
        return None


# Required assets: a missing one is a real outage, surfaced clearly.
TAB_FIX_SCRIPT = _load_required("tab_fix_script.html")
TERMINAL_PARENT_TAB_HANDLER = _load_required("terminal_parent_tab_handler.html")
VIRTUAL_KEYBOARD_STYLE = _load_required("virtual_keyboard_style.css")
VIRTUAL_KEYBOARD_HTML = _load_required("virtual_keyboard.html")

# Single favicon registry: one row per icon carries everything its consumers
# need — the HTTP route (path, content_type), the page <link>, and the loaded
# bytes (None if the decorative file is missing). app.py builds FAVICON_ROUTES
# and views.py builds FAVICON_LINKS from this, so adding/removing an icon is a
# one-line change with no risk of the route/link lists drifting apart (B18).
Favicon = namedtuple("Favicon", "path content_type link body")
FAVICONS = (
    Favicon("/favicon.ico", "image/x-icon",
            '<link rel="icon" href="/favicon.ico" sizes="any">',
            _load_optional_bytes("favicon.ico")),
    Favicon("/favicon-16x16.png", "image/png",
            '<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">',
            _load_optional_bytes("favicon-16x16.png")),
    Favicon("/favicon-32x32.png", "image/png",
            '<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">',
            _load_optional_bytes("favicon-32x32.png")),
    Favicon("/apple-touch-icon.png", "image/png",
            '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
            _load_optional_bytes("apple-touch-icon.png")),
)

# Back-compat aliases for direct byte access (e.g. tests asserting magic bytes).
FAVICON_ICO = FAVICONS[0].body
FAVICON_16_PNG = FAVICONS[1].body
FAVICON_32_PNG = FAVICONS[2].body
APPLE_TOUCH_ICON_PNG = FAVICONS[3].body
