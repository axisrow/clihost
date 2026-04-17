"""Tests for the parent terminal iframe handler asset."""
import unittest

from ttydproxy.assets import TERMINAL_PARENT_TAB_HANDLER


class TestTerminalParentTabHandler(unittest.TestCase):
    def setUp(self):
        self.script = TERMINAL_PARENT_TAB_HANDLER

    def test_tab_keydown_handler_present(self):
        self.assertIn("addEventListener('keydown'", self.script)
        self.assertIn("e.key !== 'Tab'", self.script)

    def test_iframe_focus_handler_present(self):
        self.assertIn("iframe.addEventListener('focus'", self.script)

    def test_touch_handlers_moved_to_iframe(self):
        for event_name in ("touchstart", "touchmove", "touchend", "touchcancel"):
            with self.subTest(event_name=event_name):
                self.assertNotIn(f"addEventListener('{event_name}'", self.script)


if __name__ == "__main__":
    unittest.main()
