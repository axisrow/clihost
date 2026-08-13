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
