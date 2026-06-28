"""Tests for load_ssh_url - the SSH connection-string contract behind the
dashboard SSH block (issue #80). Mirrors test_load_hapi_url but the file holds a
shell command, not an HTTP URL."""
import os
import tempfile
import unittest
from pathlib import Path

from ttydproxy.views import load_ssh_url


class TestLoadSshUrl(unittest.TestCase):
    def _write(self, content):
        with tempfile.NamedTemporaryFile("w", suffix=".ssh", delete=False) as f:
            f.write(content)
            path = f.name
        self.addCleanup(os.unlink, path)
        return path

    def test_missing_file_returns_none(self):
        path = Path(tempfile.gettempdir()) / "clihost-nonexistent-ssh-file"
        if path.exists():
            path.unlink()
        self.assertIsNone(load_ssh_url(str(path)))

    def test_empty_file_returns_none(self):
        self.assertIsNone(load_ssh_url(self._write("")))

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(load_ssh_url(self._write("   \n\t  \n")))

    def test_non_ssh_prefix_returns_none(self):
        self.assertIsNone(load_ssh_url(self._write("nc example.com 22")))
        self.assertIsNone(load_ssh_url(self._write("telnet example.com 22")))

    def test_bare_ssh_without_args_returns_none(self):
        # "ssh" alone is not a usable command; require "ssh " (with args).
        self.assertIsNone(load_ssh_url(self._write("ssh")))

    def test_valid_chisel_command_returned(self):
        cmd = "ssh -p 2222 hapi@example.com"
        self.assertEqual(load_ssh_url(self._write(cmd + "\n")), cmd)

    def test_valid_cloudflared_command_returned(self):
        cmd = 'ssh -o ProxyCommand="cloudflared access ssh --hostname %h" hapi@tunnel.example.com'
        self.assertEqual(load_ssh_url(self._write(cmd)), cmd)

    def test_newline_injection_rejected(self):
        # A second line must not survive; the copy-paste path must stay a single
        # command (no command chaining / shell smuggling).
        injected = "ssh -p 2222 hapi@example.com\nrm -rf /"
        self.assertIsNone(load_ssh_url(self._write(injected)))

    def test_carriage_return_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@example.com\recho pwned")))

    def test_nul_byte_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@example.com\x00rm -rf /")))


if __name__ == "__main__":
    unittest.main()
