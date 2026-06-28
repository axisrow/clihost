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
# minimum=1: a non-positive TTL would issue already-expired tokens and lock out
# every login / reject every CSRF check. A bad value clamps to 1s (fail-closed),
# never expands to the week-long default (B1).
SESSION_TIMEOUT = env_int(os.environ.get("SESSION_TIMEOUT"), 604800, name="SESSION_TIMEOUT", minimum=1)
VIRTUAL_KEYBOARD = env_bool(os.environ.get("VIRTUAL_KEYBOARD"), default=True)
CSRF_TOKEN_TTL = env_int(os.environ.get("CSRF_TOKEN_TTL"), 604800, name="CSRF_TOKEN_TTL", minimum=1)
SECURE_COOKIES = env_bool(os.environ.get("SECURE_COOKIES"), default=False)
HAPI_URL_FILE = os.environ.get("HAPI_URL_FILE", "/home/hapi/url")
# SSH connection string written by the tunnel (#79/#82); default matches the
# path entrypoint.sh writes. Rendered on the dashboard only when present (#80).
SSH_URL_FILE = os.environ.get("SSH_URL_FILE", "/home/hapi/ssh-url")
MAX_UPLOAD_SIZE = env_int(os.environ.get("MAX_UPLOAD_SIZE"), 10485760, name="MAX_UPLOAD_SIZE")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", f"{CLEANUP_ROOT}/.uploads")

# Single source of truth for the terminal-id digit cap. Bounding the length
# keeps int() from ever hitting Python's 4300-digit string-conversion limit on
# an unauthenticated path; an over-long id fails to match / fails the guard and
# falls through to a 404. Used by both the GET route regex and do_DELETE (B7/B8).
MAX_TERMINAL_ID_DIGITS = 9
TTYD_ROUTE_PATTERN = re.compile(rf"^/ttyd(\d{{1,{MAX_TERMINAL_ID_DIGITS}}})(/.*)?$")
