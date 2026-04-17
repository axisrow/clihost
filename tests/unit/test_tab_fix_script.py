"""Regression tests for TAB_FIX_SCRIPT scroll fix."""
import unittest

from ttydproxy.assets import TAB_FIX_SCRIPT


class TestScrollFixOrder(unittest.TestCase):
    def setUp(self):
        self.script = TAB_FIX_SCRIPT

    def test_wheel_always_scrolls_buffer(self):
        wheel_start = self.script.index("addEventListener('wheel'")
        wheel_end = self.script.index("{ passive: false, capture: true });", wheel_start)
        wheel_section = self.script[wheel_start:wheel_end]
        # Wheel handler must not early-return on alternate screen — doing so
        # sent events to tmux which required `set -g mouse on` and broke
        # native text selection (#40).
        self.assertNotIn("if (isAlternateScreen(term)) return", wheel_section)

    def test_wheel_prevent_default_and_stop_propagation(self):
        wheel_section_end = self.script.index("term.scrollLines(lines);")
        wheel_section = self.script[self.script.index("addEventListener('wheel'"):wheel_section_end]
        self.assertIn("e.preventDefault()", wheel_section)
        self.assertIn("e.stopPropagation()", wheel_section)

    def test_wheel_listener_options(self):
        wheel_section = self.script[self.script.index("addEventListener('wheel'"):]
        self.assertIn("passive: false", wheel_section)
        self.assertIn("capture: true", wheel_section)

    def test_alternate_screen_helper_present(self):
        self.assertIn("function isAlternateScreen(term)", self.script)
        self.assertIn("window.isTerminalAlternateScreen = function()", self.script)

    def test_scroll_helper_present(self):
        self.assertIn("window.scrollTerminalLines = function(lines)", self.script)
        self.assertIn("term.scrollLines(lines);", self.script)

    def test_script_wrapped_in_script_tag(self):
        self.assertIn("<script>", self.script)
        self.assertIn("</script>", self.script)


if __name__ == "__main__":
    unittest.main()
