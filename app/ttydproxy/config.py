"""Runtime configuration for the ttyd proxy application."""
import os
import re

from ttydproxy.security import env_bool


PORT = int(os.environ.get("PORT", "8080"))
TTYD_USER = os.environ.get("TTYD_USER", "hapi")
TTYD_PASSWORD = os.environ.get("TTYD_PASSWORD", "")
PASSWORD_SECRET = os.environ.get("PASSWORD_SECRET", "default-secret-change-me")
TTYD_BASE_PORT = 7681
CLEANUP_ROOT = os.environ.get("CLEANUP_ROOT", "/home/hapi")
HAPI_HOME = os.environ.get("HAPI_HOME", f"{CLEANUP_ROOT}/.hapi")
MAX_TERMINALS = int(os.environ.get("MAX_TERMINALS", "100"))
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "604800"))
VIRTUAL_KEYBOARD = env_bool(os.environ.get("VIRTUAL_KEYBOARD"), default=True)
CSRF_TOKEN_TTL = int(os.environ.get("CSRF_TOKEN_TTL", "604800"))
SECURE_COOKIES = env_bool(os.environ.get("SECURE_COOKIES"), default=False)
HAPI_URL_FILE = os.environ.get("HAPI_URL_FILE", "/home/hapi/url")

TTYD_ROUTE_PATTERN = re.compile(r"^/ttyd(\d+)(/.*)?$")
