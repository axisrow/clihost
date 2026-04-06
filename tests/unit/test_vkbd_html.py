"""Tests for production virtual keyboard HTML rendering."""
import unittest

from ttydproxy.views import render_terminal_page


class TestVKBDEnabled(unittest.TestCase):
    def setUp(self):
        self.html = render_terminal_page(1, "testuser", vkbd_enabled=True)

    def test_vkbd_buttons_present(self):
        for key in ("esc", "tab", "shift-tab", "ctrl-c", "ctrl-b", "ctrl-l",
                     "ctrl-v", "up", "left", "down", "right",
                     "1", "2", "3", "4", "5",
                     "slash", "bang", "backspace", "enter"):
            with self.subTest(key=key):
                self.assertIn(f'data-key="{key}"', self.html)

    def test_arrow_grid_present(self):
        self.assertIn("arrow-grid", self.html)

    def test_mobile_styles_present(self):
        self.assertIn("@media (max-width: 768px)", self.html)
        self.assertIn("touch-action: manipulation", self.html)
        self.assertIn("overflow: hidden", self.html)
        self.assertIn("overscroll-behavior: none", self.html)
        self.assertIn("touch-action: none", self.html)

    def test_updated_javascript_present(self):
        self.assertIn("function sendKey(key)", self.html)
        self.assertIn("navigator.clipboard.readText()", self.html)
        self.assertIn("socket.send('0' + data)", self.html)
        self.assertIn("win.sendTabKey", self.html)
        self.assertIn("win.scrollTerminalLines", self.html)

    def test_new_key_sequences(self):
        self.assertIn("String.fromCharCode(127)", self.html)  # backspace
        self.assertIn("String.fromCharCode(12)", self.html)   # ctrl-l
        self.assertIn("'\\r'", self.html)                      # enter
        self.assertIn("case 'slash'", self.html)               # /
        self.assertIn("case 'bang'", self.html)                # !

    def test_iframe_points_to_terminal(self):
        self.assertIn('id="terminal-shell"', self.html)
        self.assertIn('id="terminal"', self.html)
        self.assertIn('src="/ttyd1/"', self.html)


class TestVKBDDisabled(unittest.TestCase):
    def test_vkbd_markup_absent(self):
        html = render_terminal_page(1, "testuser", vkbd_enabled=False)
        self.assertNotIn('id="vkbd"', html)
        self.assertNotIn("navigator.clipboard.readText()", html)
        self.assertNotIn("@media (max-width: 768px)", html)
        self.assertIn('src="/ttyd1/"', html)


if __name__ == "__main__":
    unittest.main()
