"""
Tests for inject_tab_fix_script() injection pipeline.

Verifies that TAB_FIX_SCRIPT is correctly injected into TTYD HTML responses,
including gzip round-trip, fallback injection points, and silent failure cases.

The critical check: e.preventDefault() must appear before if (isAlt) return
in the FINAL OUTPUT of the injection function, not just in the source constant.

Note: ttyd_proxy.py has Linux-only deps (spwd, crypt) so we extract TAB_FIX_SCRIPT
by reading the source file and copy inject_tab_fix_script() inline.
"""
import gzip
import os
import re
import unittest


# ---------------------------------------------------------------------------
# Helpers: extract TAB_FIX_SCRIPT and inject function without importing module
# ---------------------------------------------------------------------------

def _load_tab_fix_script() -> bytes:
    """Extract TAB_FIX_SCRIPT bytes from ttyd_proxy.py source without importing it."""
    src = os.path.join(os.path.dirname(__file__), '..', '..', 'app', 'ttyd_proxy.py')
    with open(src, 'rb') as f:
        content = f.read()
    m = re.search(rb"TAB_FIX_SCRIPT\s*=\s*b'''(.*?)'''", content, re.DOTALL)
    if not m:
        raise RuntimeError("TAB_FIX_SCRIPT not found in ttyd_proxy.py")
    return m.group(1)


TAB_FIX_SCRIPT = _load_tab_fix_script()


def inject_tab_fix_script(data, is_gzipped=False):
    """Inject Tab fix script into TTYD HTML response.

    Copied from TTYDProxyHandler.inject_tab_fix_script() in ttyd_proxy.py
    (lines 1249-1298) to avoid importing module with Linux-only deps.
    Only change: removed ``self`` parameter.
    """
    import gzip as _gzip
    try:
        if is_gzipped or (len(data) >= 2 and data[0:2] == b'\x1f\x8b'):
            try:
                data = _gzip.decompress(data)
                is_gzipped = True
            except Exception:
                return data

        html = data.decode('utf-8')
        script = TAB_FIX_SCRIPT.decode('utf-8')

        if '<head>' in html:
            html = html.replace('<head>', '<head>' + script, 1)
        elif '<head ' in html:
            idx = html.find('<head ')
            end_idx = html.find('>', idx)
            if end_idx != -1:
                html = html[:end_idx + 1] + script + html[end_idx + 1:]
        elif '<html>' in html:
            html = html.replace('<html>', '<html>' + script, 1)
        elif html.strip():
            html = script + html

        result = html.encode('utf-8')

        if is_gzipped:
            result = _gzip.compress(result)

        return result
    except Exception:
        pass
    return data


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

SIMPLE_HTML = b"<html><head><title>Test</title></head><body>hello</body></html>"

TTYD_LIKE_HTML = b"""<!DOCTYPE html><html><head>
  <meta charset="utf-8"><title>ttyd - Terminal</title>
  <script src="auth_token.js"></script>
</head><body><div id="terminal"></div><script src="main.js"></script></body></html>"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInjectPlainHTML(unittest.TestCase):
    """Injection into plain (uncompressed) HTML."""

    def test_inject_into_head_tag(self):
        result = inject_tab_fix_script(SIMPLE_HTML).decode('utf-8')
        # TAB_FIX_SCRIPT starts with \n, so injected form is <head>\n<script>
        self.assertIn('<head>\n<script>', result)
        self.assertIn('<title>Test</title>', result)

    def test_script_before_original_content(self):
        result = inject_tab_fix_script(SIMPLE_HTML).decode('utf-8')
        idx_script = result.index('<script>')
        idx_title = result.index('<title>')
        self.assertLess(idx_script, idx_title)

    def test_fix_order_in_output(self):
        """e.preventDefault() must come before if (isAlt) return in output."""
        result = inject_tab_fix_script(SIMPLE_HTML).decode('utf-8')
        idx_prevent = result.index('e.preventDefault()')
        idx_isalt = result.index('if (isAlt) return')
        self.assertLess(
            idx_prevent, idx_isalt,
            "e.preventDefault() must precede isAlt check in injected output"
        )

    def test_content_length_increases(self):
        result = inject_tab_fix_script(SIMPLE_HTML)
        self.assertGreater(len(result), len(SIMPLE_HTML))


class TestInjectGzip(unittest.TestCase):
    """Gzip compression round-trip."""

    def setUp(self):
        self.compressed = gzip.compress(SIMPLE_HTML)

    def test_gzip_round_trip(self):
        result = inject_tab_fix_script(self.compressed)
        html = gzip.decompress(result).decode('utf-8')
        self.assertIn('e.preventDefault()', html)
        self.assertIn('<title>Test</title>', html)

    def test_gzip_auto_detection(self):
        result = inject_tab_fix_script(self.compressed)
        self.assertTrue(result[:2] == b'\x1f\x8b', "Output must be gzip")

    def test_gzip_output_is_valid(self):
        result = inject_tab_fix_script(self.compressed)
        try:
            gzip.decompress(result)
        except Exception as e:
            self.fail(f"Output is not valid gzip: {e}")

    def test_fix_order_in_gzip_output(self):
        result = inject_tab_fix_script(self.compressed)
        html = gzip.decompress(result).decode('utf-8')
        idx_prevent = html.index('e.preventDefault()')
        idx_isalt = html.index('if (isAlt) return')
        self.assertLess(
            idx_prevent, idx_isalt,
            "e.preventDefault() must precede isAlt check after gzip round-trip"
        )


class TestInjectFallbacks(unittest.TestCase):
    """Fallback injection points when <head> is missing."""

    def test_head_with_attributes(self):
        html = b"<html><head lang='en'><title>T</title></head></html>"
        result = inject_tab_fix_script(html).decode('utf-8')
        idx_head_close = result.index("lang='en'>") + len("lang='en'>")
        idx_script = result.index('<script>', idx_head_close - 20)
        self.assertLessEqual(idx_head_close, idx_script + len('<script>'))
        self.assertIn('e.preventDefault()', result)

    def test_html_tag_fallback(self):
        html = b"<html><body>hi</body></html>"
        result = inject_tab_fix_script(html).decode('utf-8')
        self.assertIn('<html>\n<script>', result)
        self.assertIn('e.preventDefault()', result)

    def test_prepend_fallback(self):
        html = b"<body>hi</body>"
        result = inject_tab_fix_script(html).decode('utf-8')
        self.assertTrue(result.lstrip('\n').startswith('<script>'))
        self.assertIn('e.preventDefault()', result)


class TestInjectSilentFailure(unittest.TestCase):
    """Silent failure: function must return original data on error."""

    def test_empty_data(self):
        result = inject_tab_fix_script(b"")
        self.assertEqual(result, b"")

    def test_non_utf8(self):
        data = b'\x80\x81\x82\x83'
        result = inject_tab_fix_script(data)
        self.assertEqual(result, data)

    def test_corrupt_gzip(self):
        data = b'\x1f\x8b' + b'\x00' * 10
        result = inject_tab_fix_script(data)
        self.assertEqual(result, data)


class TestInjectTTYDRealistic(unittest.TestCase):
    """Injection into realistic TTYD-like HTML."""

    def test_script_before_ttyd_scripts(self):
        result = inject_tab_fix_script(TTYD_LIKE_HTML).decode('utf-8')
        idx_our = result.index('window._ttydSocket')
        idx_ttyd = result.index('src="main.js"')
        self.assertLess(
            idx_our, idx_ttyd,
            "Our script must load before TTYD's main.js"
        )

    def test_fix_order_realistic(self):
        result = inject_tab_fix_script(TTYD_LIKE_HTML).decode('utf-8')
        idx_prevent = result.index('e.preventDefault()')
        idx_isalt = result.index('if (isAlt) return')
        self.assertLess(
            idx_prevent, idx_isalt,
            "e.preventDefault() must precede isAlt check in TTYD-like HTML output"
        )


if __name__ == '__main__':
    unittest.main()
