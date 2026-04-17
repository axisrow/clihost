"""Tests for inject_tab_fix_script() injection pipeline."""
import gzip
import unittest

from ttydproxy.assets import TAB_FIX_SCRIPT
from ttydproxy.proxy import inject_tab_fix_script


SIMPLE_HTML = b"<html><head><title>Test</title></head><body>hello</body></html>"
TTYD_LIKE_HTML = (
    b"<!DOCTYPE html><html><head><meta charset='utf-8'><title>ttyd - Terminal</title>"
    b"<script src='auth_token.js'></script></head><body><div id='terminal'></div>"
    b"<script src='main.js'></script></body></html>"
)


class TestInjectPlainHTML(unittest.TestCase):
    def test_inject_into_head_tag(self):
        result = inject_tab_fix_script(SIMPLE_HTML).decode("utf-8")
        self.assertIn("<head><script>", result)
        self.assertIn("<title>Test</title>", result)

    def test_script_before_original_content(self):
        result = inject_tab_fix_script(SIMPLE_HTML).decode("utf-8")
        self.assertLess(result.index("<script>"), result.index("<title>"))

    def test_wheel_handler_scrolls_unconditionally(self):
        # Wheel handler must always call term.scrollLines — no early return
        # on alternate screen (#40: tmux mouse mode was the only reason that
        # early return existed, and it broke native text selection).
        result = inject_tab_fix_script(SIMPLE_HTML).decode("utf-8")
        wheel_section = result[result.index("addEventListener('wheel'"):result.index("term.scrollLines(lines);")]
        self.assertIn("e.preventDefault()", wheel_section)
        self.assertIn("e.stopPropagation()", wheel_section)
        self.assertNotIn("if (isAlternateScreen(term)) return", wheel_section)

    def test_terminal_scroll_helpers_in_output(self):
        result = inject_tab_fix_script(SIMPLE_HTML).decode("utf-8")
        self.assertIn("window.isTerminalAlternateScreen = function()", result)
        self.assertIn("window.scrollTerminalLines = function(lines)", result)


class TestInjectGzip(unittest.TestCase):
    def setUp(self):
        self.compressed = gzip.compress(SIMPLE_HTML)

    def test_gzip_round_trip(self):
        html = gzip.decompress(inject_tab_fix_script(self.compressed)).decode("utf-8")
        self.assertIn("e.preventDefault()", html)
        self.assertIn("<title>Test</title>", html)

    def test_gzip_output_is_valid(self):
        gzip.decompress(inject_tab_fix_script(self.compressed))


class TestInjectFallbacks(unittest.TestCase):
    def test_head_with_attributes(self):
        html = b"<html><head lang='en'><title>T</title></head></html>"
        result = inject_tab_fix_script(html).decode("utf-8")
        self.assertIn("lang='en'><script>", result)

    def test_html_tag_fallback(self):
        html = b"<html><body>hi</body></html>"
        result = inject_tab_fix_script(html).decode("utf-8")
        self.assertIn("<html><script>", result)

    def test_prepend_fallback(self):
        result = inject_tab_fix_script(b"<body>hi</body>").decode("utf-8")
        self.assertTrue(result.startswith("<script>"))


class TestInjectSilentFailure(unittest.TestCase):
    def test_empty_data(self):
        self.assertEqual(inject_tab_fix_script(b""), b"")

    def test_non_utf8(self):
        data = b"\x80\x81\x82\x83"
        self.assertEqual(inject_tab_fix_script(data), data)

    def test_corrupt_gzip(self):
        data = b"\x1f\x8b" + b"\x00" * 10
        self.assertEqual(inject_tab_fix_script(data), data)


class TestInjectTTYDRealistic(unittest.TestCase):
    def test_script_before_ttyd_scripts(self):
        result = inject_tab_fix_script(TTYD_LIKE_HTML).decode("utf-8")
        self.assertLess(result.index("window._ttydSocket"), result.index("main.js"))

    def test_script_constant_has_tags(self):
        self.assertIn("<script>", TAB_FIX_SCRIPT)
        self.assertIn("</script>", TAB_FIX_SCRIPT)


class TestInjectTouchScroll(unittest.TestCase):
    """Touch scroll is handled inside the iframe so iOS (which doesn't bubble
    touch events out of iframes) works, and so registration happens after term
    is ready (fixes #36 race after reconnect)."""

    def test_touch_listeners_present(self):
        for event_name in ("touchstart", "touchmove", "touchend", "touchcancel"):
            with self.subTest(event_name=event_name):
                self.assertIn(f"addEventListener('{event_name}'", TAB_FIX_SCRIPT)

    def test_touchmove_is_non_passive_and_captured(self):
        section = TAB_FIX_SCRIPT[TAB_FIX_SCRIPT.index("addEventListener('touchmove'"):]
        self.assertIn("passive: false", section)
        self.assertIn("capture: true", section)

    def test_touchmove_skips_alternate_screen(self):
        section = TAB_FIX_SCRIPT[TAB_FIX_SCRIPT.index("addEventListener('touchmove'"):]
        self.assertIn("isAlternateScreen(term)", section)

    def test_touchmove_calls_term_scroll_lines(self):
        section = TAB_FIX_SCRIPT[TAB_FIX_SCRIPT.index("addEventListener('touchmove'"):]
        self.assertIn("term.scrollLines(", section)

    def test_touchend_restores_textarea_focus(self):
        # Regression guard for commit 79cda5b (iOS keyboard flash fix):
        # touchend must refocus .xterm-helper-textarea after a swipe so the
        # soft keyboard reopens on the next tap.
        section = TAB_FIX_SCRIPT[TAB_FIX_SCRIPT.index("addEventListener('touchend'"):]
        end = section.index("addEventListener('touchcancel'")
        touchend_section = section[:end]
        self.assertIn(".xterm-helper-textarea", touchend_section)
        self.assertIn(".focus()", touchend_section)


if __name__ == "__main__":
    unittest.main()
