"""Integration-style tests for virtual keyboard query handling."""
import threading
import unittest
from unittest.mock import MagicMock, patch

from ttydproxy import app
from ttydproxy.manager import TTYDManager
from ttydproxy.views import resolve_vkbd_enabled


class TestTTYDHandlerVKBD(unittest.TestCase):
    def test_query_param_overrides_default(self):
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=true", False))
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=false", True))
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=1", False))
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=0", True))

    def test_missing_query_param_uses_default(self):
        self.assertTrue(resolve_vkbd_enabled("/ttyd", True))
        self.assertFalse(resolve_vkbd_enabled("/ttyd", False))

    def test_invalid_values_fall_back_to_default(self):
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=hello", True))
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=hello", False))

    def test_multiple_values_use_first(self):
        self.assertFalse(resolve_vkbd_enabled("/ttyd?vkbd=false&vkbd=true", True))
        self.assertTrue(resolve_vkbd_enabled("/ttyd?vkbd=true&vkbd=false", False))


class DeadTerminalPageTest(unittest.TestCase):
    """A browser navigation to a dead /ttydN page must redirect to the
    dashboard — like an expired session does — not serve a raw JSON blob."""

    class _Probe(app.TTYDProxyHandler):
        def __init__(self, terminal):
            self._terminal = terminal
            self.path = "/ttyd7"
            self.json_response = None
            self.status = None
            self.headers_sent = {}
            self.ended = False
            self.rendered = None

        def _check_auth(self, redirect=False):
            del redirect
            return "alice"

        def send_json(self, status, data, extra_headers=None):
            del extra_headers
            self.json_response = (status, data)

        def send_response(self, status, message=None):
            self.status = status

        def send_header(self, key, value):
            self.headers_sent[key] = value

        def end_headers(self):
            self.ended = True

        def send_html(self, status, html, extra_headers=None, csp=None):
            self.rendered = (status, html)

    def _run(self, terminal):
        handler = self._Probe(terminal)
        handler.context = app.AppContext(
            settings=app.AppSettings(), manager=MagicMock(),
            limiters=MagicMock(), server_start_time=0.0,
        )
        handler.context.manager.get_terminal.return_value = terminal
        handler.handle_ttyd(7)
        return handler

    def test_dead_terminal_redirects_to_dashboard(self):
        handler = self._run(None)
        self.assertEqual(handler.status, 302)
        self.assertEqual(handler.headers_sent.get("Location"), "/")
        self.assertTrue(handler.ended)
        self.assertIsNone(handler.json_response, "must not emit JSON on a browser nav")

    def test_live_terminal_renders_page(self):
        handler = self._run({"id": 7, "port": 7687})
        self.assertIsNone(handler.status)
        self.assertIsNotNone(handler.rendered)


class TestTTYDProxyPortLease(unittest.TestCase):
    @patch("ttydproxy.manager.subprocess.run")
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_inflight_proxy_prevents_port_reuse(self, mock_popen, _mock_run):
        processes = []

        def make_process(*_args, **_kwargs):
            process = MagicMock()
            process.pid = 100 + len(processes)
            process.poll.return_value = None
            processes.append(process)
            return process

        mock_popen.side_effect = make_process
        manager = TTYDManager(base_port=9000, max_terminals=2)
        first = manager.create_terminal()
        proxy_started = threading.Event()
        allow_proxy_to_finish = threading.Event()
        proxied_ports = []

        def blocked_proxy(_handler, _path, port):
            proxied_ports.append(port)
            proxy_started.set()
            self.assertTrue(allow_proxy_to_finish.wait(timeout=5))

        handler = MagicMock()
        handler._check_auth.return_value = "alice"
        handler.path = "/ttyd1/"
        handler.context = app.AppContext(app.AppSettings(), manager, MagicMock(), 0.0)
        handler.manager = manager

        with patch.object(
            app, "is_websocket_request", return_value=False
        ), patch.object(app, "proxy_ttyd_http", side_effect=blocked_proxy):
            request = threading.Thread(
                target=app.TTYDProxyHandler.handle_ttyd_proxy,
                args=(handler, first["id"]),
            )
            request.start()
            self.assertTrue(proxy_started.wait(timeout=5))
            try:
                self.assertTrue(manager.delete_terminal(first["id"]))
                replacement = manager.create_terminal()
                self.assertEqual(replacement["port"], 9001)
            finally:
                allow_proxy_to_finish.set()
                request.join(timeout=5)

        self.assertFalse(request.is_alive())
        self.assertEqual(proxied_ports, [9000])
        self.assertTrue(manager.delete_terminal(replacement["id"]))
        self.assertEqual(manager.create_terminal()["port"], 9000)


if __name__ == "__main__":
    unittest.main()
