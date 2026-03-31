"""Tests for the production TTYDManager."""
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from ttydproxy.manager import TTYDManager


class TestCreateTerminal(unittest.TestCase):
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_create_terminal_success(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000)
        result = manager.create_terminal()

        self.assertEqual(result, {"id": 1, "port": 9000})
        self.assertEqual(manager.terminals[1]["pid"], 12345)
        self.assertEqual(manager.next_id, 2)

    @patch("ttydproxy.manager.subprocess.Popen")
    def test_create_terminal_increments_id(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000)
        self.assertEqual(manager.create_terminal()["id"], 1)
        self.assertEqual(manager.create_terminal()["id"], 2)

    @patch("ttydproxy.manager.subprocess.Popen")
    def test_create_terminal_limit_by_count(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000, max_terminals=2)
        manager.create_terminal()
        manager.create_terminal()
        self.assertEqual(manager.create_terminal(), "limit")

    @patch("ttydproxy.manager.subprocess.Popen")
    def test_create_terminal_popen_failure(self, mock_popen):
        mock_popen.side_effect = OSError("No such file")
        manager = TTYDManager(base_port=9000)
        self.assertIsNone(manager.create_terminal())


class TestDeleteTerminal(unittest.TestCase):
    @patch("ttydproxy.manager.subprocess.run")
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_delete_terminal_success(self, mock_popen, mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000)
        manager.create_terminal()
        self.assertTrue(manager.delete_terminal(1))
        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_called()
        mock_run.assert_called_once()

    @patch("ttydproxy.manager.subprocess.run")
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_delete_terminal_kill_on_timeout(self, mock_popen, _mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_proc.wait.side_effect = [subprocess.TimeoutExpired("ttyd", 5), None]
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000)
        manager.create_terminal()
        self.assertTrue(manager.delete_terminal(1))
        mock_proc.kill.assert_called_once()

    def test_delete_terminal_not_found(self):
        self.assertFalse(TTYDManager(base_port=9000).delete_terminal(999))


class TestListAndGet(unittest.TestCase):
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_list_returns_sorted(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000)
        manager.create_terminal()
        manager.create_terminal()
        terminals = manager.list_terminals()
        self.assertEqual([terminal["id"] for terminal in terminals], [1, 2])

    @patch("ttydproxy.manager.subprocess.run")
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_list_filters_dead_processes(self, mock_popen, _mock_run):
        alive = MagicMock()
        alive.pid = 100
        alive.poll.return_value = None
        dead = MagicMock()
        dead.pid = 101
        dead.poll.return_value = 1
        mock_popen.side_effect = [alive, dead]

        manager = TTYDManager(base_port=9000)
        manager.create_terminal()
        manager.create_terminal()
        self.assertEqual([terminal["id"] for terminal in manager.list_terminals()], [1])

    @patch("ttydproxy.manager.subprocess.Popen")
    def test_get_existing(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000)
        manager.create_terminal()
        self.assertEqual(manager.get_terminal(1), {"id": 1, "port": 9000})

    @patch("ttydproxy.manager.subprocess.run")
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_get_dead_process_returns_none(self, mock_popen, _mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_proc.poll.return_value = 1
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000)
        manager.create_terminal()
        self.assertIsNone(manager.get_terminal(1))


class TestAllocatePort(unittest.TestCase):
    def test_first_port(self):
        self.assertEqual(TTYDManager(base_port=9000)._allocate_port(), 9000)

    @patch("ttydproxy.manager.subprocess.run")
    @patch("ttydproxy.manager.subprocess.Popen")
    def test_port_reuse_after_delete(self, mock_popen, _mock_run):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000, max_terminals=5)
        manager.create_terminal()
        manager.create_terminal()
        manager.delete_terminal(1)
        self.assertEqual(manager._allocate_port(), 9000)

    @patch("ttydproxy.manager.subprocess.Popen")
    def test_all_ports_exhausted(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.pid = 100
        mock_popen.return_value = mock_proc

        manager = TTYDManager(base_port=9000, max_terminals=2)
        manager.create_terminal()
        manager.create_terminal()
        self.assertIsNone(manager._allocate_port())


if __name__ == "__main__":
    unittest.main()

