"""Regression tests for TAB_FIX_SCRIPT scroll fix."""
import unittest

from ttydproxy.assets import TAB_FIX_SCRIPT


class TestScrollFixOrder(unittest.TestCase):
    def setUp(self):
        self.script = TAB_FIX_SCRIPT

    def test_wheel_prevent_default_before_alt_check(self):
        wheel_section = self.script[self.script.index("addEventListener('wheel'"):]
        self.assertLess(
            wheel_section.index("e.preventDefault()"),
            wheel_section.index("if (isAlternateScreen(term)) return"),
        )

    def test_wheel_stop_propagation_after_alt_check(self):
        wheel_section = self.script[self.script.index("addEventListener('wheel'"):]
        self.assertGreater(
            wheel_section.index("e.stopPropagation()"),
            wheel_section.index("if (isAlternateScreen(term)) return"),
        )

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
