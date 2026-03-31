#!/usr/bin/env python3
"""Backward-compatible entrypoint for the refactored ttyd proxy server."""

from ttydproxy.app import TTYDProxyHandler, main, ttyd_manager
from ttydproxy.config import (
    PORT,
    TTYD_BASE_PORT,
    TTYD_PASSWORD,
    TTYD_ROUTE_PATTERN,
    TTYD_USER,
    VIRTUAL_KEYBOARD,
    CSRF_TOKEN_TTL,
    SECURE_COOKIES,
    MAX_TERMINALS,
    SESSION_TIMEOUT,
)
from ttydproxy.manager import TTYDManager
from ttydproxy.proxy import inject_tab_fix_script
from ttydproxy.assets import TAB_FIX_SCRIPT
from ttydproxy.security import (
    build_csrf_token,
    build_session_token,
    env_bool,
    is_valid_username,
    parse_cookie_header,
    parse_csrf_token,
    parse_session_token,
    verify_pam_password,
)


def build_ttyd_session(username, port):
    """Backward-compatible session builder wrapper."""
    del port
    from ttydproxy.config import PASSWORD_SECRET

    return build_session_token(username, PASSWORD_SECRET, SESSION_TIMEOUT)


def parse_ttyd_session(token):
    """Backward-compatible session parser wrapper."""
    from ttydproxy.config import PASSWORD_SECRET

    username = parse_session_token(token, PASSWORD_SECRET)
    if not username:
        return None, None
    return username, TTYD_BASE_PORT


__all__ = [
    "CSRF_TOKEN_TTL",
    "MAX_TERMINALS",
    "PORT",
    "SECURE_COOKIES",
    "SESSION_TIMEOUT",
    "TAB_FIX_SCRIPT",
    "TTYDManager",
    "TTYDProxyHandler",
    "TTYD_BASE_PORT",
    "TTYD_PASSWORD",
    "TTYD_ROUTE_PATTERN",
    "TTYD_USER",
    "VIRTUAL_KEYBOARD",
    "build_csrf_token",
    "build_ttyd_session",
    "env_bool",
    "inject_tab_fix_script",
    "is_valid_username",
    "main",
    "parse_cookie_header",
    "parse_csrf_token",
    "parse_ttyd_session",
    "ttyd_manager",
    "verify_pam_password",
]


if __name__ == "__main__":
    main()
