"""Tests for load_hapi_url — the relay-URL contract behind hapi menu gating (issue #63)."""
import os
import tempfile
import unittest
from pathlib import Path

from ttydproxy.views import load_hapi_url


class TestLoadHapiUrl(unittest.TestCase):
    def _write(self, content):
        with tempfile.NamedTemporaryFile("w", suffix=".url", delete=False) as f:
            f.write(content)
            path = f.name
        self.addCleanup(os.unlink, path)
        return path

    def test_missing_file_returns_none(self):
        path = Path(tempfile.gettempdir()) / "clihost-nonexistent-url-file"
        if path.exists():
            path.unlink()
        self.assertIsNone(load_hapi_url(str(path)))

    def test_empty_file_returns_none(self):
        self.assertIsNone(load_hapi_url(self._write("")))

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(load_hapi_url(self._write("   \n\t  \n")))

    def test_non_http_url_returns_none(self):
        self.assertIsNone(load_hapi_url(self._write("ftp://example.com/x")))

    def test_valid_https_url_returned(self):
        url = "https://app.hapi.run/?token=abc"
        self.assertEqual(load_hapi_url(self._write(url + "\n")), url)

    def test_valid_http_url_returned(self):
        url = "http://localhost:8080/x"
        self.assertEqual(load_hapi_url(self._write(url)), url)


if __name__ == "__main__":
    unittest.main()
