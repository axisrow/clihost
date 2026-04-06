"""Tests for the parent terminal iframe handler asset."""
import unittest

from ttydproxy.assets import TERMINAL_PARENT_TAB_HANDLER


class TestTerminalParentTabHandler(unittest.TestCase):
    def setUp(self):
        self.script = TERMINAL_PARENT_TAB_HANDLER

    def test_touch_listeners_present(self):
        for event_name in ("touchstart", "touchmove", "touchend", "touchcancel"):
            with self.subTest(event_name=event_name):
                self.assertIn(f"addEventListener('{event_name}'", self.script)

    def test_touchmove_listener_is_non_passive(self):
        touchmove_section = self.script[self.script.index("addEventListener('touchmove'"):]
        self.assertIn("passive: false", touchmove_section)
        self.assertIn("capture: true", touchmove_section)

    def test_touchmove_uses_iframe_helpers(self):
        touchmove_section = self.script[self.script.index("addEventListener('touchmove'"):]
        self.assertIn("win.isTerminalAlternateScreen", touchmove_section)
        self.assertIn("win.scrollTerminalLines(-lineSteps);", touchmove_section)

    def test_terminal_shell_is_used_for_gestures(self):
        self.assertIn("document.getElementById('terminal-shell')", self.script)


if __name__ == "__main__":
    unittest.main()
