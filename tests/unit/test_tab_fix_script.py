"""Regression tests for TAB_FIX_SCRIPT scroll fix."""
import unittest

from ttydproxy.assets import TAB_FIX_SCRIPT


class TestScrollFixOrder(unittest.TestCase):
    def setUp(self):
        self.script = TAB_FIX_SCRIPT

    def test_wheel_skips_alternate_screen(self):
        wheel_start = self.script.index("addEventListener('wheel'")
        wheel_end = self.script.index("{ passive: false, capture: true });", wheel_start)
        wheel_section = self.script[wheel_start:wheel_end]
        # Wheel handler must pass through to xterm.js for alternate-screen
        # apps (less, vim, htop) so they receive scroll events. Tmux mouse
        # mode is off, so native text selection works regardless.
        self.assertIn("if (isAlternateScreen(term)) return", wheel_section)

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


class TestWaitForTermTimeout(unittest.TestCase):
    """waitForTerm must stop polling if window.term never appears."""

    def setUp(self):
        start = TAB_FIX_SCRIPT.index("function waitForTerm")
        end = TAB_FIX_SCRIPT.index("}", TAB_FIX_SCRIPT.index("}, 50);", start))
        self.section = TAB_FIX_SCRIPT[start:end]

    def test_has_attempt_counter(self):
        self.assertIn("attempts", self.section)

    def test_clears_interval_on_timeout(self):
        # Two clearInterval calls: one on success, one when giving up.
        self.assertEqual(self.section.count("clearInterval(i)"), 2)


if __name__ == "__main__":
    unittest.main()
