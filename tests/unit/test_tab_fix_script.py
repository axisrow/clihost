"""Regression tests for TAB_FIX_SCRIPT scroll fix."""
import unittest

from ttydproxy.assets import TAB_FIX_SCRIPT


def script_section(script, start_marker, end_marker="}, true);"):
    """Slice script from start_marker up to the following end_marker."""
    start = script.index(start_marker)
    return script[start:script.index(end_marker, start)]


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


class TestImageUpload(unittest.TestCase):
    """Pasted/dropped images upload via POST /upload, path typed into the terminal."""

    def setUp(self):
        self.script = TAB_FIX_SCRIPT

    def _section(self, start_marker, end_marker="}, true);"):
        return script_section(self.script, start_marker, end_marker)

    def test_paste_listener_in_capture_phase(self):
        # The slice ends at the listener's own "}, true);" (the capture flag);
        # if the flag is lost, the slice runs into the next listener and the
        # single-registration assertion below fails.
        section = self._section("addEventListener('paste'")
        self.assertEqual(section.count("addEventListener"), 1)

    def test_paste_ignores_text_only_clipboard(self):
        section = self._section("addEventListener('paste'")
        # Only images are consumed on the iframe paste path; pasted text
        # stays on xterm's default handling (bracketed paste, IME, etc.).
        self.assertIn("if (handleImageTransfer(e.clipboardData))", section)
        self.assertNotIn("handleDataTransfer", section)

    def test_image_gate_checks_mime_prefix(self):
        self.assertIn("indexOf('image/') === 0", self.script)

    def test_extract_covers_items_and_files(self):
        extract = self._section("function extractImageFiles", "function uploadImageFile")
        self.assertIn(".items", extract)
        self.assertIn("getAsFile()", extract)
        self.assertIn(".files", extract)

    def test_dragover_and_drop_prevent_default(self):
        for event_name in ("dragover", "drop"):
            with self.subTest(event=event_name):
                section = self._section(f"addEventListener('{event_name}'")
                self.assertIn("e.preventDefault()", section)

    def test_drop_prevents_default_only_for_files(self):
        section = self._section("addEventListener('drop'")
        # Drop suppresses the default only for an image (uploaded) or any other
        # file (which would navigate the iframe away). A plain-text drop falls
        # through to xterm's native handling — preventing it would swallow the
        # text with nothing to replace it (regression #66).
        self.assertIn("handleImageTransfer(source) || containsFiles(source)", section)
        self.assertNotIn("handleDataTransfer(e.dataTransfer)", section)

    def test_upload_posts_with_csrf(self):
        self.assertIn("fetch('/upload'", self.script)
        self.assertIn("method: 'POST'", self.script)
        self.assertIn("'X-CSRF-Token': csrfToken", self.script)
        # The token is read once per gesture, not once per file.
        self.assertIn("var csrfToken = getCsrfToken();", self.script)

    def test_success_types_path_with_trailing_space(self):
        self.assertIn("sendToTTYD(path + ' ')", self.script)

    def test_failure_warns_without_typing(self):
        self.assertIn("console.warn('image upload failed", self.script)

    def test_upload_count_capped(self):
        self.assertIn("var MAX_UPLOAD_FILES = 5", self.script)
        self.assertIn("slice(0, MAX_UPLOAD_FILES)", self.script)

    def test_upload_api_exposed_for_parent_page(self):
        # The parent forwards ONLY images (text stays on xterm's native path),
        # so the image-only entry point is the one exposed (regression #66).
        # The old full-triage __handleDataTransfer export was removed with the
        # dead text-typing path it fronted.
        self.assertIn("window.__handleImageTransfer = handleImageTransfer", self.script)
        self.assertNotIn("__handleDataTransfer", self.script)
        self.assertNotIn("function handleDataTransfer", self.script)
        self.assertNotIn("function pasteTextToTerminal", self.script)


class TestFileGating(unittest.TestCase):
    """Images upload; any other file is blocked from navigating; text is left
    entirely to xterm (the iframe never types pasted/dropped text itself)."""

    def setUp(self):
        self.script = TAB_FIX_SCRIPT

    def test_contains_files_covers_items_and_files(self):
        # The gate must share extractImageFiles' items/files coverage, or a
        # files-via-items-only transfer (Safari quirk) slips through.
        body = script_section(
            self.script, "function containsFiles", "function handleImageTransfer"
        )
        self.assertIn(".files", body)
        self.assertIn(".items", body)

    def test_contains_files_has_no_mime_filter(self):
        # Invariant: containsFiles must NOT filter by image/ MIME — any file
        # (including a PDF) is blocked from navigating the iframe away.
        body = script_section(
            self.script, "function containsFiles", "function handleImageTransfer"
        )
        self.assertNotIn("image/", body)

    def test_iframe_never_types_pasted_text(self):
        # Regression #66: the iframe must not read text off the transfer and
        # type it — that fragile path is what broke mobile paste. Text is left
        # to xterm's native handling. (A comment may still mention getData; the
        # ban is on the actual call .getData(.)
        self.assertNotIn(".getData(", self.script)
        self.assertNotIn("term.paste(text)", self.script)

    def test_upload_pipeline_has_catch(self):
        # The parallel Promise.all chain needs a terminal .catch so a throw in
        # the then-callback (e.g. sendToTTYD) is logged, not an unhandled
        # rejection in the console.
        body = script_section(
            self.script, "function uploadImageFiles", "function containsFiles"
        )
        self.assertIn("Promise.all(", body)
        self.assertIn(".catch(", body[body.index("Promise.all("):])


if __name__ == "__main__":
    unittest.main()
