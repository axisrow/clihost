"""Tests for HAPI URL loading and runtime relay discovery."""
import os
import tempfile
import unittest
from pathlib import Path

from ttydproxy.views import (
    build_hapi_url_from_runtime,
    load_dashboard_hapi_url,
    load_hapi_url,
    load_runtime_hapi_url,
)


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


class TestBuildHapiUrlFromRuntime(unittest.TestCase):
    def test_relay_url_and_token_build_connection_url(self):
        url = build_hapi_url_from_runtime(
            "ready at https://my-sub-01.relay.hapi.run\n",
            '{\n  "cliApiToken": "token-123"\n}\n',
        )
        self.assertEqual(
            url,
            "https://app.hapi.run/?hub=https%3A%2F%2Fmy-sub-01.relay.hapi.run&token=token-123",
        )

    def test_latest_relay_url_wins_when_log_contains_restarts(self):
        url = build_hapi_url_from_runtime(
            "\n".join(
                [
                    "old https://first.relay.hapi.run",
                    "new https://second-02.relay.hapi.run",
                ]
            ),
            '{"cliApiToken": "token-123"}',
        )
        self.assertIn("second-02.relay.hapi.run", url)
        self.assertNotIn("first.relay.hapi.run", url)

    def test_relay_url_without_token_returns_none(self):
        self.assertIsNone(
            build_hapi_url_from_runtime(
                "ready at https://my-sub-01.relay.hapi.run\n",
                "{}",
            )
        )

    def test_token_without_relay_url_returns_none(self):
        self.assertIsNone(
            build_hapi_url_from_runtime(
                "hapi server listening without relay yet\n",
                '{"cliApiToken": "token-123"}',
            )
        )

    def test_missing_runtime_data_returns_none(self):
        self.assertIsNone(build_hapi_url_from_runtime("", ""))


class TestLoadRuntimeHapiUrl(unittest.TestCase):
    def test_reads_runtime_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            server_log = root / "server.log"
            settings = root / "settings.json"
            server_log.write_text(
                "ready at https://my-sub-01.relay.hapi.run\n",
                encoding="utf-8",
            )
            settings.write_text('{"cliApiToken": "token-123"}', encoding="utf-8")

            self.assertEqual(
                load_runtime_hapi_url(server_log, settings),
                "https://app.hapi.run/?hub=https%3A%2F%2Fmy-sub-01.relay.hapi.run&token=token-123",
            )

    def test_missing_files_return_none_without_exception(self):
        path = Path(tempfile.gettempdir()) / "clihost-missing-hapi-runtime"
        self.assertIsNone(load_runtime_hapi_url(path / "server.log", path / "settings.json"))

    def test_headless_hapi_absent_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hapi_home = Path(tmpdir) / ".hapi"
            self.assertIsNone(load_runtime_hapi_url(hapi_home / "server.log", hapi_home / "settings.json"))


class TestLoadDashboardHapiUrl(unittest.TestCase):
    def test_hapi_absent_ignores_stale_runtime_and_legacy_url_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hapi_home = root / ".hapi"
            hapi_home.mkdir()
            (hapi_home / "server.log").write_text(
                "old https://stale.relay.hapi.run\n",
                encoding="utf-8",
            )
            (hapi_home / "settings.json").write_text(
                '{"cliApiToken": "stale-token"}',
                encoding="utf-8",
            )
            legacy_url = root / "url"
            legacy_url.write_text(
                "https://app.hapi.run/?hub=https%3A%2F%2Fstale.relay.hapi.run&token=stale-token",
                encoding="utf-8",
            )

            self.assertIsNone(load_dashboard_hapi_url(hapi_home, legacy_url, hapi_available=False))


if __name__ == "__main__":
    unittest.main()
