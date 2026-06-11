"""Runtime configuration for the ttyd proxy application."""
import os
import re

from ttydproxy.security import env_bool, env_int, env_secret


PORT = env_int(os.environ.get("PORT"), 8080, name="PORT")
TTYD_USER = os.environ.get("TTYD_USER", "hapi")
TTYD_PASSWORD = os.environ.get("TTYD_PASSWORD", "")
PASSWORD_SECRET = env_secret("PASSWORD_SECRET", "default-secret-change-me")
TTYD_BASE_PORT = 7681
CLEANUP_ROOT = os.environ.get("CLEANUP_ROOT", "/home/hapi")
HAPI_HOME = os.environ.get("HAPI_HOME", f"{CLEANUP_ROOT}/.hapi")
MAX_TERMINALS = env_int(os.environ.get("MAX_TERMINALS"), 100, name="MAX_TERMINALS")
SESSION_TIMEOUT = env_int(os.environ.get("SESSION_TIMEOUT"), 604800, name="SESSION_TIMEOUT")
VIRTUAL_KEYBOARD = env_bool(os.environ.get("VIRTUAL_KEYBOARD"), default=True)
CSRF_TOKEN_TTL = env_int(os.environ.get("CSRF_TOKEN_TTL"), 604800, name="CSRF_TOKEN_TTL")
SECURE_COOKIES = env_bool(os.environ.get("SECURE_COOKIES"), default=False)
HAPI_URL_FILE = os.environ.get("HAPI_URL_FILE", "/home/hapi/url")
MAX_UPLOAD_SIZE = env_int(os.environ.get("MAX_UPLOAD_SIZE"), 10485760, name="MAX_UPLOAD_SIZE")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", f"{CLEANUP_ROOT}/.uploads")

TTYD_ROUTE_PATTERN = re.compile(r"^/ttyd(\d+)(/.*)?$")
