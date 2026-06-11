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


class TestImageUploadForwarding(unittest.TestCase):
    """Paste/drop on the parent page must forward image files into the iframe,
    where the injected script owns the actual upload."""

    def setUp(self):
        self.script = TERMINAL_PARENT_TAB_HANDLER

    def test_paste_drop_dragover_listeners_present(self):
        for event_name in ("paste", "dragover", "drop"):
            with self.subTest(event_name=event_name):
                self.assertIn(f"addEventListener('{event_name}'", self.script)

    def test_delegates_to_iframe_upload_api(self):
        # The full triage (image → upload, text → type, other → skip) lives
        # in the iframe's injected script; the parent must not duplicate it,
        # only forward the transfer.
        self.assertIn("__handleDataTransfer(dataTransfer)", self.script)
        self.assertNotIn("function extractImageFiles", self.script)
        self.assertNotIn("fetch('/upload'", self.script)

    def test_forwarding_is_defensive(self):
        # Same try/catch style as focusTerminal: the iframe may not have the
        # injected script yet.
        api_start = self.script.index("function forwardDataTransfer")
        section = self.script[api_start : self.script.index("return false;", api_start)]
        self.assertIn("try {", section)
        self.assertIn("console.warn", section)


if __name__ == "__main__":
    unittest.main()
