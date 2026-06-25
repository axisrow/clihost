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

    def test_delegates_image_only_to_iframe(self):
        # The parent forwards ONLY images into the iframe's uploader. Plain text
        # must NOT be forwarded — it has to reach xterm's native paste/drop
        # handling, or the iOS empty-getData paste loses the text (regression
        # #66). The actual upload still lives in the iframe; the parent does not
        # duplicate it.
        self.assertIn("__handleImageTransfer(dataTransfer)", self.script)
        self.assertNotIn("__handleDataTransfer", self.script)
        self.assertNotIn("function extractImageFiles", self.script)
        self.assertNotIn("fetch('/upload'", self.script)

    def test_paste_prevents_default_only_when_image_handled(self):
        # Text paste must fall through (no preventDefault); only a handled image
        # suppresses the native path.
        start = self.script.index("addEventListener('paste'")
        section = self.script[start : self.script.index("}, true);", start)]
        self.assertIn("if (forwardImageTransfer(e.clipboardData))", section)

    def test_drop_prevents_default_only_for_files(self):
        # A text drop falls through to xterm; only an image (uploaded) or some
        # other file (which would navigate the page away) is suppressed.
        start = self.script.index("addEventListener('drop'")
        section = self.script[start : self.script.index("}, true);", start)]
        self.assertIn("forwardImageTransfer(source) || containsFiles(source)", section)

    def test_forwarding_is_defensive(self):
        # Same try/catch style as focusTerminal: the iframe may not have the
        # injected script yet.
        api_start = self.script.index("function forwardImageTransfer")
        section = self.script[api_start : self.script.index("return false;", api_start)]
        self.assertIn("try {", section)
        self.assertIn("console.warn", section)


if __name__ == "__main__":
    unittest.main()
