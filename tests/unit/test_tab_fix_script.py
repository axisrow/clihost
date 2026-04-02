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

    def test_touch_listeners_present(self):
        for event_name in ("touchstart", "touchmove", "touchend", "touchcancel"):
            with self.subTest(event_name=event_name):
                self.assertIn(f"addEventListener('{event_name}'", self.script)

    def test_touchmove_listener_is_non_passive(self):
        touchmove_section = self.script[self.script.index("addEventListener('touchmove'"):]
        self.assertIn("passive: false", touchmove_section)
        self.assertIn("capture: true", touchmove_section)

    def test_touchmove_uses_alt_screen_guard(self):
        touchmove_section = self.script[self.script.index("addEventListener('touchmove'"):]
        self.assertIn("if (isAlternateScreen(term)) return", touchmove_section)

    def test_touchmove_scrolls_terminal_buffer(self):
        touchmove_section = self.script[self.script.index("addEventListener('touchmove'"):]
        self.assertIn("term.scrollLines(-lineSteps);", touchmove_section)

    def test_script_wrapped_in_script_tag(self):
        self.assertIn("<script>", self.script)
        self.assertIn("</script>", self.script)


if __name__ == "__main__":
    unittest.main()
