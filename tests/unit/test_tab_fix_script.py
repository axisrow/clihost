"""Regression tests for TAB_FIX_SCRIPT scroll fix."""
import unittest

from ttydproxy.assets import TAB_FIX_SCRIPT


class TestScrollFixOrder(unittest.TestCase):
    def setUp(self):
        self.script = TAB_FIX_SCRIPT

    def test_prevent_default_before_isalt_check(self):
        self.assertLess(self.script.index("e.preventDefault()"), self.script.index("if (isAlt) return"))

    def test_stop_propagation_after_isalt_check(self):
        wheel_section = self.script[self.script.index("addEventListener('wheel'"):]
        self.assertGreater(wheel_section.index("e.stopPropagation()"), wheel_section.index("if (isAlt) return"))

    def test_wheel_listener_options(self):
        self.assertIn("passive: false", self.script)
        self.assertIn("capture: true", self.script)

    def test_script_wrapped_in_script_tag(self):
        self.assertIn("<script>", self.script)
        self.assertIn("</script>", self.script)


if __name__ == "__main__":
    unittest.main()

