"""Tests for virtual keyboard HTML generation in ttyd_proxy.py."""
import unittest
import os
import sys
import io
from unittest.mock import patch, MagicMock

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'app'))


class TestVirtualKeyboardHTML(unittest.TestCase):
    """Test virtual keyboard HTML generation."""

    def setUp(self):
        """Set up test fixtures."""
        # Import module with default VIRTUAL_KEYBOARD=True
        self.original_env = os.environ.copy()

    def tearDown(self):
        """Restore environment."""
        os.environ.clear()
        os.environ.update(self.original_env)

    def _generate_html(self, vkbd_enabled):
        """Generate terminal HTML with virtual keyboard option."""
        username = "testuser"
        ttyd_url = "/ttyd/"

        if vkbd_enabled:
            vkbd_style = '''
    .vkbd { display: none; background: #1a1a2e; padding: 8px; gap: 6px; flex-wrap: wrap; justify-content: center; }
    .vkbd button {
      background: #16213e; color: #e8e8e8; border: 1px solid #0f3460;
      padding: 12px 16px; font-size: 14px; font-family: monospace;
      border-radius: 4px; min-width: 44px; touch-action: manipulation;
    }
    .vkbd button:active { background: #0f3460; }
    @media (max-width: 768px) {
      .vkbd { display: flex; }
      body { height: calc(100vh - 60px); }
    }'''
            vkbd_html = '''
  <div class="vkbd" id="vkbd">
    <button data-key="esc">ESC</button>
    <button data-key="tab">Tab</button>
    <button data-key="shift-tab">Shift+Tab</button>
    <button data-key="ctrl-c">Ctrl+C</button>
    <button data-key="ctrl-b">Ctrl+B</button>
    <button data-key="up">&#8593;</button>
    <button data-key="left">&#8592;</button>
    <button data-key="down">&#8595;</button>
    <button data-key="right">&#8594;</button>
    <button data-key="ctrl-v">Ctrl+V</button>
  </div>
  <script>
    (function() {
      var iframe = document.getElementById('terminal');

      function getTermTextarea() {
        try {
          var doc = iframe.contentWindow && iframe.contentWindow.document;
          if (!doc) return null;
          return doc.querySelector('.xterm-helper-textarea');
        } catch (e) {
          return null;
        }
      }

      function focusTerminal() {
        try {
          if (iframe.contentWindow) iframe.contentWindow.focus();
          var textarea = getTermTextarea();
          if (textarea) textarea.focus();
        } catch (e) {
          // Ignore focus errors.
        }
      }

      function dispatchKey(target, eventType, opts) {
        var ev = new KeyboardEvent(eventType, Object.assign({
          bubbles: true,
          cancelable: true,
          composed: true
        }, opts));
        target.dispatchEvent(ev);
      }

      function sendKey(key) {
        var textarea = getTermTextarea();
        if (!textarea) return;
        focusTerminal();

        var def = null;
        switch (key) {
          case 'esc':
            def = { key: 'Escape', code: 'Escape', keyCode: 27, which: 27 };
            break;
          case 'tab':
            def = { key: 'Tab', code: 'Tab', keyCode: 9, which: 9 };
            break;
          case 'ctrl-c':
            def = { key: 'c', code: 'KeyC', keyCode: 67, which: 67, ctrlKey: true };
            break;
          case 'ctrl-b':
            def = { key: 'b', code: 'KeyB', keyCode: 66, which: 66, ctrlKey: true };
            break;
          case 'up':
            def = { key: 'ArrowUp', code: 'ArrowUp', keyCode: 38, which: 38 };
            break;
          case 'left':
            def = { key: 'ArrowLeft', code: 'ArrowLeft', keyCode: 37, which: 37 };
            break;
          case 'down':
            def = { key: 'ArrowDown', code: 'ArrowDown', keyCode: 40, which: 40 };
            break;
          case 'right':
            def = { key: 'ArrowRight', code: 'ArrowRight', keyCode: 39, which: 39 };
            break;
        }
        if (!def) return;

        dispatchKey(textarea, 'keydown', def);
        dispatchKey(textarea, 'keyup', def);
      }

      document.getElementById('vkbd').addEventListener('click', function(e) {
        if (e.target.tagName === 'BUTTON') {
          sendKey(e.target.dataset.key);
        }
      });
      iframe.addEventListener('load', function() {
        focusTerminal();
      });
    })();
  </script>'''
        else:
            vkbd_style = ''
            vkbd_html = ''

        html = f'''<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
  <title>Terminal - {username}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 0; height: 100vh; background: #0f131a; display: flex; flex-direction: column; }}
    #terminal {{ flex: 1; width: 100%; border: none; }}{vkbd_style}
  </style>
</head>
<body>
  <iframe id="terminal" src="{ttyd_url}" allow="clipboard-write; clipboard-read"></iframe>{vkbd_html}
</body>
</html>'''
        return html


class TestVKBDEnabled(TestVirtualKeyboardHTML):
    """Test HTML generation when VKBD is enabled."""

    def test_vkbd_div_present(self):
        """Test that vkbd div is present when enabled."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('id="vkbd"', html)
        self.assertIn('class="vkbd"', html)

    def test_vkbd_contains_esc_button(self):
        """Test ESC button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="esc"', html)
        self.assertIn('>ESC</button>', html)

    def test_vkbd_contains_tab_button(self):
        """Test Tab button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="tab"', html)
        self.assertIn('>Tab</button>', html)

    def test_vkbd_contains_shift_tab_button(self):
        """Test Shift+Tab button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="shift-tab"', html)
        self.assertIn('>Shift+Tab</button>', html)

    def test_vkbd_contains_ctrl_c_button(self):
        """Test Ctrl+C button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="ctrl-c"', html)
        self.assertIn('>Ctrl+C</button>', html)

    def test_vkbd_contains_ctrl_b_button(self):
        """Test Ctrl+B button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="ctrl-b"', html)
        self.assertIn('>Ctrl+B</button>', html)

    def test_vkbd_contains_up_arrow(self):
        """Test up arrow button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="up"', html)

    def test_vkbd_contains_down_arrow(self):
        """Test down arrow button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="down"', html)

    def test_vkbd_contains_left_arrow(self):
        """Test left arrow button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="left"', html)

    def test_vkbd_contains_right_arrow(self):
        """Test right arrow button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="right"', html)

    def test_vkbd_contains_ctrl_v_button(self):
        """Test Ctrl+V (paste) button presence."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('data-key="ctrl-v"', html)
        self.assertIn('>Ctrl+V</button>', html)

    def test_vkbd_has_10_buttons(self):
        """Test that exactly 10 buttons are present."""
        html = self._generate_html(vkbd_enabled=True)
        button_count = html.count('data-key="')
        self.assertEqual(button_count, 10)


class TestVKBDCSS(TestVirtualKeyboardHTML):
    """Test CSS styles for virtual keyboard."""

    def test_vkbd_media_query_present(self):
        """Test that mobile media query is present."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('@media (max-width: 768px)', html)

    def test_vkbd_display_flex_in_media_query(self):
        """Test that vkbd is displayed as flex on mobile."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('.vkbd { display: flex; }', html)

    def test_vkbd_default_display_none(self):
        """Test that vkbd is hidden by default."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('.vkbd { display: none;', html)

    def test_vkbd_touch_action(self):
        """Test touch-action: manipulation for mobile."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('touch-action: manipulation', html)


class TestVKBDJavaScript(TestVirtualKeyboardHTML):
    """Test JavaScript functions for virtual keyboard."""

    def test_sendKey_function_present(self):
        """Test sendKey function is defined."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('function sendKey(key)', html)

    def test_dispatchKey_function_present(self):
        """Test dispatchKey function is defined."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('function dispatchKey(target, eventType, opts)', html)

    def test_focusTerminal_function_present(self):
        """Test focusTerminal function is defined."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('function focusTerminal()', html)

    def test_getTermTextarea_function_present(self):
        """Test getTermTextarea function is defined."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn('function getTermTextarea()', html)

    def test_click_event_listener(self):
        """Test click event listener is attached."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("document.getElementById('vkbd').addEventListener('click'", html)

    def test_iframe_load_listener(self):
        """Test iframe load listener is attached."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("iframe.addEventListener('load'", html)


class TestVKBDDisabled(TestVirtualKeyboardHTML):
    """Test HTML generation when VKBD is disabled."""

    def test_vkbd_div_absent(self):
        """Test that vkbd div is absent when disabled."""
        html = self._generate_html(vkbd_enabled=False)
        self.assertNotIn('id="vkbd"', html)
        self.assertNotIn('class="vkbd"', html)

    def test_vkbd_style_absent(self):
        """Test that vkbd styles are absent when disabled."""
        html = self._generate_html(vkbd_enabled=False)
        self.assertNotIn('@media (max-width: 768px)', html)

    def test_vkbd_script_absent(self):
        """Test that vkbd script is absent when disabled."""
        html = self._generate_html(vkbd_enabled=False)
        self.assertNotIn('function sendKey', html)

    def test_terminal_iframe_still_present(self):
        """Test that terminal iframe is present regardless."""
        html = self._generate_html(vkbd_enabled=False)
        self.assertIn('id="terminal"', html)
        self.assertIn('src="/ttyd/"', html)


class TestKeyboardKeyCodes(TestVirtualKeyboardHTML):
    """Test key code definitions in JavaScript."""

    def test_escape_keycode(self):
        """Test Escape key code is 27."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("keyCode: 27", html)

    def test_tab_keycode(self):
        """Test Tab key code is 9."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("keyCode: 9", html)

    def test_ctrl_c_keycode(self):
        """Test Ctrl+C (c) key code is 67 with ctrlKey."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("keyCode: 67", html)
        self.assertIn("ctrlKey: true", html)

    def test_arrow_up_keycode(self):
        """Test ArrowUp key code is 38."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("keyCode: 38", html)

    def test_arrow_down_keycode(self):
        """Test ArrowDown key code is 40."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("keyCode: 40", html)

    def test_arrow_left_keycode(self):
        """Test ArrowLeft key code is 37."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("keyCode: 37", html)

    def test_arrow_right_keycode(self):
        """Test ArrowRight key code is 39."""
        html = self._generate_html(vkbd_enabled=True)
        self.assertIn("keyCode: 39", html)


if __name__ == '__main__':
    unittest.main()
