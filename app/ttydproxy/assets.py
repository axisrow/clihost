"""Static asset loading for terminal HTML and injected scripts."""
from functools import lru_cache
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parent.parent
ASSET_DIR = APP_ROOT / "assets"


@lru_cache(maxsize=None)
def load_asset(filename):
    """Load a static asset from disk."""
    path = ASSET_DIR / filename
    return path.read_text(encoding="utf-8")


TAB_FIX_SCRIPT = load_asset("tab_fix_script.html")
TERMINAL_PARENT_TAB_HANDLER = load_asset("terminal_parent_tab_handler.html")
VIRTUAL_KEYBOARD_STYLE = load_asset("virtual_keyboard_style.css")
VIRTUAL_KEYBOARD_HTML = load_asset("virtual_keyboard.html")

