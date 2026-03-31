#!/usr/bin/env python3
"""
Base HTTP Server
Provides common HTTP server functionality
"""
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


COMMON_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

DEFAULT_HTML_CSP = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'"
)


class BaseHTTPHandler(BaseHTTPRequestHandler):
    """Base HTTP request handler with common utilities."""

    def log_message(self, format, *args):
        """Silence default logging."""
        pass

    def _write_response(self, status, body, content_type, cache_control, extra_headers=None):
        """Write a common HTTP response body with shared security headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", cache_control)
        for key, value in COMMON_SECURITY_HEADERS.items():
            self.send_header(key, value)
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data, extra_headers=None):
        """Send JSON response."""
        self._write_response(
            status,
            json.dumps(data).encode("utf-8"),
            "application/json",
            "no-cache",
            extra_headers=extra_headers,
        )

    def send_html(self, status, html, extra_headers=None, csp=None):
        """Send HTML response."""
        headers = {"Content-Security-Policy": csp or DEFAULT_HTML_CSP}
        if extra_headers:
            headers.update(extra_headers)
        self._write_response(
            status,
            html.encode("utf-8"),
            "text/html; charset=utf-8",
            "no-store",
            extra_headers=headers,
        )


class BaseJSONServer:
    """Base HTTP server class."""

    def __init__(self, port, handler_class):
        self.port = port
        self.handler_class = handler_class
        self.httpd = None

    def start(self):
        """Start the HTTP server."""
        server_address = ("0.0.0.0", self.port)
        self.httpd = ThreadingHTTPServer(server_address, self.handler_class)
        self.httpd.daemon_threads = True  # don't block shutdown on open connections
        print(f"HTTP server listening on port {self.port}")
        self.httpd.serve_forever()


def create_server(port, handler_class):
    """Factory function to create and start HTTP server."""
    server = BaseJSONServer(port, handler_class)
    server.start()
