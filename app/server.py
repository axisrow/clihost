#!/usr/bin/env python3
"""
Base HTTP Server
Provides common HTTP server functionality
"""
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler


class BaseHTTPHandler(BaseHTTPRequestHandler):
    """Base HTTP request handler with common utilities."""

    def log_message(self, format, *args):
        """Silence default logging."""
        pass

    def send_json(self, status, data):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def send_html(self, status, html):
        """Send HTML response."""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'",
        )
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))


class BaseJSONServer:
    """Base HTTP server class."""

    def __init__(self, port, handler_class):
        self.port = port
        self.handler_class = handler_class
        self.httpd = None

    def start(self):
        """Start the HTTP server."""
        server_address = ("0.0.0.0", self.port)
        self.httpd = HTTPServer(server_address, self.handler_class)
        print(f"HTTP server listening on port {self.port}")
        self.httpd.serve_forever()


def create_server(port, handler_class):
    """Factory function to create and start HTTP server."""
    server = BaseJSONServer(port, handler_class)
    server.start()
