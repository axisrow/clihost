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

    def test_drop_reads_data_transfer(self):
        section = self._section("addEventListener('drop'")
        # Drop always prevents the default (a file drop would navigate away),
        # so the full triage runs to type dropped text into the terminal.
        self.assertIn("handleDataTransfer(e.dataTransfer)", section)

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
        self.assertIn("window.__handleDataTransfer = handleDataTransfer", self.script)


class TestTransferTriage(unittest.TestCase):
    """Text types into the prompt, images upload, anything else silently skips."""

    def setUp(self):
        self.script = TAB_FIX_SCRIPT
        self.triage = script_section(
            self.script, "function handleDataTransfer", "window.__handleDataTransfer"
        )

    def test_text_typed_via_bracketed_paste_with_socket_fallback(self):
        # term.paste honours bracketed-paste mode (safe multi-line text);
        # the raw socket send stays as the fallback.
        body = script_section(
            self.script, "function pasteTextToTerminal", "function containsFiles"
        )
        self.assertIn("term.paste(text)", body)
        self.assertIn("sendToTTYD(text)", body)

    def test_images_win_over_text(self):
        self.assertIn("if (handleImageTransfer(source)) return true;", self.triage)
        self.assertLess(
            self.triage.index("handleImageTransfer(source)"),
            self.triage.index("getData('text/plain')"),
        )

    def test_non_image_files_silently_skipped(self):
        # Pin the actual gate: a non-image file transfer never reaches the
        # text branch, even when it exposes a text representation.
        self.assertIn(
            "if (!source || containsFiles(source) || !source.getData) return false;",
            self.triage,
        )

    def test_contains_files_covers_items_and_files(self):
        # The gate must share extractImageFiles' items/files coverage, or a
        # files-via-items-only transfer (Safari quirk) slips into text typing.
        body = script_section(
            self.script, "function containsFiles", "function handleImageTransfer"
        )
        self.assertIn(".files", body)
        self.assertIn(".items", body)

    def test_contains_files_has_no_mime_filter(self):
        # Invariant: containsFiles must NOT filter by image/ MIME — any file
        # (including a PDF) blocks the text branch, which is what makes a
        # non-image drop a silent skip rather than its text being typed.
        body = script_section(
            self.script, "function containsFiles", "function handleImageTransfer"
        )
        self.assertNotIn("image/", body)

    def test_upload_pipeline_has_catch(self):
        # The parallel Promise.all chain needs a terminal .catch so a throw in
        # the then-callback (e.g. sendToTTYD) is logged, not an unhandled
        # rejection in the console.
        body = script_section(
            self.script, "function uploadImageFiles", "function pasteTextToTerminal"
        )
        self.assertIn("Promise.all(", body)
        self.assertIn(".catch(", body[body.index("Promise.all("):])


if __name__ == "__main__":
    unittest.main()
