#!/usr/bin/env python3
"""Backward-compatible entrypoint for the refactored ttyd proxy server.

The implementation now lives in the ``ttydproxy`` package. This module remains
as the process entry point referenced by entrypoint.sh (``python3 /app/ttyd_proxy.py``).
"""
from ttydproxy.app import main


if __name__ == "__main__":
    main()
