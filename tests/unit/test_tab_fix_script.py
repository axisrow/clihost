"""
Regression tests for TAB_FIX_SCRIPT scroll fix.

Bug: e.preventDefault() was called AFTER the isAlt check, so when Claude Code
(or vim/less/htop) is running in alternate screen mode, the handler returned early
without preventing the browser's default scroll action -- causing the textarea at
the bottom of the screen to scroll instead of the terminal viewport.

Fix: e.preventDefault() is now called BEFORE the isAlt check so the browser can
never scroll the textarea, regardless of screen mode. stopPropagation() is still
placed after the check so xterm.js can handle scroll events in alternate screen.

Note: ttyd_proxy.py has Linux-only deps (spwd, crypt) so we extract TAB_FIX_SCRIPT
by reading the source file directly, following the pattern used elsewhere in this
test suite (see test_csrf.py, test_ttyd_manager.py, test_terminals_api.py).
"""
import re
import unittest
import os


def _load_tab_fix_script() -> bytes:
    """Extract TAB_FIX_SCRIPT bytes from ttyd_proxy.py source without importing it."""
    src = os.path.join(os.path.dirname(__file__), '..', '..', 'app', 'ttyd_proxy.py')
    with open(src, 'rb') as f:
        content = f.read()
    # Match:  TAB_FIX_SCRIPT = b'''\n...\n'''
    m = re.search(rb"TAB_FIX_SCRIPT\s*=\s*b'''(.*?)'''", content, re.DOTALL)
    if not m:
        raise RuntimeError("TAB_FIX_SCRIPT not found in ttyd_proxy.py")
    return m.group(1)


TAB_FIX_SCRIPT = _load_tab_fix_script()


class TestScrollFixOrder(unittest.TestCase):
    """Verify e.preventDefault() order in the wheel event handler."""

    def setUp(self):
        self.script = TAB_FIX_SCRIPT.decode('utf-8')

    def test_prevent_default_before_isalt_check(self):
        """e.preventDefault() must come BEFORE if (isAlt) return.

        Regression: if preventDefault() is after the isAlt return, the browser
        scrolls the textarea when Claude Code / vim / less is running in
        alternate screen mode.
        """
        idx_prevent = self.script.index('e.preventDefault()')
        idx_isalt = self.script.index('if (isAlt) return')
        self.assertLess(
            idx_prevent, idx_isalt,
            "e.preventDefault() must be called before the isAlt check -- "
            "otherwise the browser scrolls the textarea in alternate screen mode "
            "(Claude Code, vim, less, htop)"
        )

    def test_stop_propagation_after_isalt_check(self):
        """e.stopPropagation() in the wheel handler must come AFTER if (isAlt) return.

        xterm.js needs to receive the wheel event in alternate screen mode so it
        can send the correct scroll sequences to vim/htop/less. stopPropagation()
        must NOT be called before the isAlt early-return in the wheel handler.
        """
        # Locate the wheel handler section to avoid matching stopPropagation()
        # from the Tab keydown handler which appears earlier in the script.
        idx_wheel = self.script.index("addEventListener('wheel'")
        wheel_section = self.script[idx_wheel:]

        idx_isalt = wheel_section.index('if (isAlt) return')
        idx_stop = wheel_section.index('e.stopPropagation()')
        self.assertGreater(
            idx_stop, idx_isalt,
            "e.stopPropagation() must come after the isAlt check in the wheel "
            "handler so xterm.js can still handle scroll in vim/less/htop "
            "(alternate screen)"
        )

    def test_wheel_listener_options(self):
        """Wheel listener must use passive:false and capture:true."""
        self.assertIn("addEventListener('wheel'", self.script)
        self.assertIn('passive: false', self.script)
        self.assertIn('capture: true', self.script)

    def test_script_wrapped_in_script_tag(self):
        """TAB_FIX_SCRIPT must be wrapped in <script> tags for HTML injection."""
        self.assertIn('<script>', self.script)
        self.assertIn('</script>', self.script)

    def test_script_contains_prevent_default(self):
        """TAB_FIX_SCRIPT must call e.preventDefault() in the wheel handler."""
        self.assertIn('e.preventDefault()', self.script)


if __name__ == '__main__':
    unittest.main()
