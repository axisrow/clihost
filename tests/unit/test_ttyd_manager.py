"""Tests for TTYDManager class from ttyd_proxy.py."""
import unittest
from unittest.mock import patch, MagicMock
import subprocess
import threading


# Inline TTYDManager to avoid importing ttyd_proxy.py (Linux-only deps: spwd, crypt)
import socket
import time
import sys
import os


class TTYDManager:
    """Manages multiple TTYD process instances. Copied from ttyd_proxy.py for testing."""

    def __init__(self, base_port=7681, max_terminals=100, ttyd_user="hapi"):
        self.terminals = {}
        self.next_id = 1
        self.lock = threading.Lock()
        self.base_port = base_port
        self.max_terminals = max_terminals
        self.ttyd_user = ttyd_user

    def _allocate_port(self):
        """Find next available port, reusing freed ports. Returns port or None."""
        used_ports = {t["port"] for t in self.terminals.values()}
        max_port = self.base_port + self.max_terminals
        port = self.base_port
        while port in used_ports:
            port += 1
            if port >= max_port:
                return None
        return port

    def create_terminal(self, wait=False):
        """Spawn a new TTYD process. Returns terminal info dict, 'limit', or None."""
        with self.lock:
            if len(self.terminals) >= self.max_terminals:
                return "limit"
            terminal_id = self.next_id
            port = self._allocate_port()
            if port is None:
                return "limit"

            tmux_session = f"ttyd-{terminal_id}"
            try:
                process = subprocess.Popen(
                    [
                        "runuser", "-u", self.ttyd_user, "--",
                        "/usr/local/bin/ttyd",
                        "-p", str(port),
                        "-i", "127.0.0.1",
                        "-W",
                        "/bin/tmux-wrapper.sh", tmux_session,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as e:
                return None

            info = {"id": terminal_id, "port": port, "pid": process.pid, "process": process}
            self.terminals[terminal_id] = info
            self.next_id += 1

        if wait:
            if not self._wait_for_ready(port):
                self.delete_terminal(terminal_id)
                return None

        return {"id": terminal_id, "port": port}

    def delete_terminal(self, terminal_id):
        """Kill a TTYD process and its tmux session. Returns True if deleted."""
        with self.lock:
            info = self.terminals.pop(terminal_id, None)
        if not info:
            return False

        process = info.get("process")
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    process.wait(timeout=3)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            except OSError:
                pass

        # Kill tmux session
        tmux_session = f"ttyd-{terminal_id}"
        try:
            subprocess.run(
                ["runuser", "-u", self.ttyd_user, "--", "tmux", "kill-session", "-t", tmux_session],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
        return True

    def _cleanup_dead(self, terminal_id, info):
        """Clean up a dead terminal: reap zombie, kill tmux session."""
        process = info.get("process")
        if process:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        tmux_session = f"ttyd-{terminal_id}"
        try:
            subprocess.run(
                ["runuser", "-u", self.ttyd_user, "--", "tmux", "kill-session", "-t", tmux_session],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    def list_terminals(self):
        """Return list of active terminals sorted by id."""
        dead = []
        with self.lock:
            for tid, info in self.terminals.items():
                process = info.get("process")
                if process and process.poll() is not None:
                    dead.append((tid, info))
            for tid, _info in dead:
                del self.terminals[tid]

            result = sorted(
                [{"id": t["id"], "port": t["port"]} for t in self.terminals.values()],
                key=lambda x: x["id"],
            )

        # Clean up dead terminals outside the lock
        for tid, info in dead:
            self._cleanup_dead(tid, info)

        return result

    def get_terminal(self, terminal_id):
        """Get terminal info by id, or None."""
        dead_info = None
        with self.lock:
            info = self.terminals.get(terminal_id)
            if info:
                process = info.get("process")
                if process and process.poll() is not None:
                    dead_info = self.terminals.pop(terminal_id)
                    info = None
                else:
                    return {"id": info["id"], "port": info["port"]}

        # Clean up dead terminal outside the lock
        if dead_info:
            self._cleanup_dead(terminal_id, dead_info)

        return None

    def _wait_for_ready(self, port, timeout=15):
        """Wait until TTYD is responding on the given port."""
        for _ in range(timeout):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                sock.close()
                return True
            except OSError:
                time.sleep(1)
        return False


class TestCreateTerminal(unittest.TestCase):
    """Tests for TTYDManager.create_terminal()."""

    @patch("subprocess.Popen")
    def test_create_terminal_success(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        result = mgr.create_terminal()

        self.assertEqual(result, {"id": 1, "port": 9000})
        self.assertIn(1, mgr.terminals)
        self.assertEqual(mgr.terminals[1]["port"], 9000)
        self.assertEqual(mgr.terminals[1]["pid"], 12345)
        self.assertEqual(mgr.next_id, 2)

    @patch("subprocess.Popen")
    def test_create_terminal_increments_id(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        r1 = mgr.create_terminal()
        r2 = mgr.create_terminal()

        self.assertEqual(r1["id"], 1)
        self.assertEqual(r2["id"], 2)
        self.assertEqual(r1["port"], 9000)
        self.assertEqual(r2["port"], 9001)

    @patch("subprocess.Popen")
    def test_create_terminal_limit_by_count(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000, max_terminals=2)
        mgr.create_terminal()
        mgr.create_terminal()
        result = mgr.create_terminal()

        self.assertEqual(result, "limit")

    @patch("subprocess.Popen")
    def test_create_terminal_popen_failure(self, mock_popen):
        mock_popen.side_effect = OSError("No such file")

        mgr = TTYDManager(base_port=9000)
        result = mgr.create_terminal()

        self.assertIsNone(result)
        self.assertEqual(len(mgr.terminals), 0)


class TestDeleteTerminal(unittest.TestCase):
    """Tests for TTYDManager.delete_terminal()."""

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_delete_terminal_success(self, mock_popen, mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        mgr.create_terminal()
        self.assertIn(1, mgr.terminals)

        result = mgr.delete_terminal(1)
        self.assertTrue(result)
        self.assertNotIn(1, mgr.terminals)
        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_called()

    def test_delete_terminal_not_found(self):
        mgr = TTYDManager(base_port=9000)
        result = mgr.delete_terminal(999)
        self.assertFalse(result)

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_delete_terminal_kill_on_timeout(self, mock_popen, mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        # First wait (after terminate) times out, second wait (after kill) succeeds
        mock_proc.wait.side_effect = [subprocess.TimeoutExpired("ttyd", 5), None]
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        mgr.create_terminal()
        result = mgr.delete_terminal(1)

        self.assertTrue(result)
        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()
        self.assertEqual(mock_proc.wait.call_count, 2)

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_delete_terminal_kills_tmux_session(self, mock_popen, mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        mgr.create_terminal()
        mgr.delete_terminal(1)

        # Verify tmux kill-session was called with correct session name
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn("tmux", call_args)
        self.assertIn("kill-session", call_args)
        self.assertIn("ttyd-1", call_args)


class TestListTerminals(unittest.TestCase):
    """Tests for TTYDManager.list_terminals()."""

    @patch("subprocess.Popen")
    def test_list_empty(self, mock_popen):
        mgr = TTYDManager(base_port=9000)
        self.assertEqual(mgr.list_terminals(), [])

    @patch("subprocess.Popen")
    def test_list_returns_sorted(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_proc.poll.return_value = None  # alive
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        mgr.create_terminal()
        mgr.create_terminal()

        result = mgr.list_terminals()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["id"], 1)
        self.assertEqual(result[1]["id"], 2)

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_list_filters_dead_processes(self, mock_popen, mock_run):
        mock_proc_alive = MagicMock()
        mock_proc_alive.pid = 100
        mock_proc_alive.poll.return_value = None  # alive

        mock_proc_dead = MagicMock()
        mock_proc_dead.pid = 101
        mock_proc_dead.poll.return_value = 1  # dead (exit code 1)

        mock_popen.side_effect = [mock_proc_alive, mock_proc_dead]

        mgr = TTYDManager(base_port=9000)
        mgr.create_terminal()  # id=1, alive
        mgr.create_terminal()  # id=2, dead

        result = mgr.list_terminals()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], 1)
        self.assertNotIn(2, mgr.terminals)


class TestGetTerminal(unittest.TestCase):
    """Tests for TTYDManager.get_terminal()."""

    @patch("subprocess.Popen")
    def test_get_existing(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        mgr.create_terminal()

        result = mgr.get_terminal(1)
        self.assertEqual(result, {"id": 1, "port": 9000})

    def test_get_nonexistent(self):
        mgr = TTYDManager(base_port=9000)
        self.assertIsNone(mgr.get_terminal(999))

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_get_dead_process_returns_none(self, mock_popen, mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_proc.poll.return_value = 1  # dead
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000)
        mgr.create_terminal()

        result = mgr.get_terminal(1)
        self.assertIsNone(result)
        self.assertNotIn(1, mgr.terminals)


class TestAllocatePort(unittest.TestCase):
    """Tests for TTYDManager._allocate_port()."""

    def test_first_port(self):
        mgr = TTYDManager(base_port=9000)
        self.assertEqual(mgr._allocate_port(), 9000)

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_port_reuse_after_delete(self, mock_popen, mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000, max_terminals=5)
        mgr.create_terminal()  # port 9000
        mgr.create_terminal()  # port 9001
        mgr.delete_terminal(1)  # free port 9000

        port = mgr._allocate_port()
        self.assertEqual(port, 9000)  # reused

    @patch("subprocess.Popen")
    def test_all_ports_exhausted(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        mgr = TTYDManager(base_port=9000, max_terminals=2)
        mgr.create_terminal()  # port 9000
        mgr.create_terminal()  # port 9001

        port = mgr._allocate_port()
        self.assertIsNone(port)


if __name__ == "__main__":
    unittest.main()
