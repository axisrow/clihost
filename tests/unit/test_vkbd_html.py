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

    def test_nav_cluster_present(self):
        self.assertIn("vkbd-bottom", self.html)

    def test_vkbd_rows_present(self):
        self.assertIn('class="vkbd-row"', self.html)
        self.assertIn('class="vkbd-bottom"', self.html)

    def test_mobile_styles_present(self):
        self.assertIn("body.vkbd-open .vkbd", self.html)
        self.assertIn("touch-action: manipulation", self.html)
        self.assertIn("overflow: hidden", self.html)
        self.assertIn("overscroll-behavior: none", self.html)
        self.assertIn("touch-action: none", self.html)

    def test_toggle_button_present(self):
        self.assertIn('id="vkbd-toggle"', self.html)
        self.assertIn('aria-label="Toggle virtual keyboard"', self.html)
        self.assertIn("clihost:vkbd-open", self.html)
        self.assertIn("dispatchEvent(new Event('resize'))", self.html)
        # Static keyboard height was replaced by flex-driven layout.
        self.assertNotIn("calc(100vh - 140px)", self.html)

    def test_updated_javascript_present(self):
        self.assertIn("function sendKey(key)", self.html)
        self.assertIn("navigator.clipboard.readText()", self.html)
        # Keys are now sent through the iframe's shared __sendToTTYD helper (owns
        # socket discovery + the '0' INPUT prefix) instead of an inline
        # socket.send('0' + data) copy (#101/#14).
        self.assertIn("win.__sendToTTYD(data)", self.html)
        self.assertNotIn("socket.send('0' + data)", self.html)
        self.assertIn("win.sendTabKey", self.html)

    def test_ctrl_v_uses_term_paste_with_socket_fallback(self):
        # ^V must deliver pasted text through term.paste (bracketed-paste safe),
        # falling back to the raw socket only when term.paste is unavailable
        # (regression #66). The previous raw socket.send('0'+text) bypassed
        # bracketed paste entirely.
        self.assertIn("function pasteIntoTerminal(text)", self.html)
        self.assertIn("win.term.paste(text)", self.html)
        self.assertIn("pasteIntoTerminal(text)", self.html)

    def test_ctrl_v_surfaces_clipboard_failure(self):
        # A readText() rejection (common on mobile: focus left the iframe or
        # permission denied) must warn, not be silently swallowed.
        self.assertIn("'^V: clipboard read failed:'", self.html)

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
        self.assertNotIn('id="vkbd-toggle"', html)
        self.assertIn('src="/ttyd1/"', html)


if __name__ == "__main__":
    unittest.main()
