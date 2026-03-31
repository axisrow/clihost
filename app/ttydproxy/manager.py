"""Lifecycle management for ttyd child processes."""
import socket
import subprocess
import sys
import threading
import time


class TTYDManager:
    """Manage multiple ttyd process instances."""

    def __init__(
        self,
        base_port=7681,
        max_terminals=100,
        ttyd_user="hapi",
        ttyd_binary="/usr/local/bin/ttyd",
        tmux_wrapper="/bin/tmux-wrapper.sh",
    ):
        self.terminals = {}
        self.next_id = 1
        self.lock = threading.Lock()
        self.base_port = base_port
        self.max_terminals = max_terminals
        self.ttyd_user = ttyd_user
        self.ttyd_binary = ttyd_binary
        self.tmux_wrapper = tmux_wrapper

    def _allocate_port(self):
        """Find the next available port, reusing freed ports."""
        used_ports = {terminal["port"] for terminal in self.terminals.values()}
        max_port = self.base_port + self.max_terminals
        port = self.base_port
        while port in used_ports:
            port += 1
            if port >= max_port:
                return None
        return port

    def _tmux_session_name(self, terminal_id):
        return f"ttyd-{terminal_id}"

    def _start_ttyd_process(self, terminal_id, port):
        tmux_session = self._tmux_session_name(terminal_id)
        return subprocess.Popen(
            [
                "runuser", "-u", self.ttyd_user, "--",
                self.ttyd_binary,
                "-p", str(port),
                "-i", "127.0.0.1",
                "-W",
                self.tmux_wrapper, tmux_session,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _stop_process(self, process):
        if not process:
            return
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

    def _kill_tmux_session(self, terminal_id):
        try:
            subprocess.run(
                [
                    "runuser", "-u", self.ttyd_user, "--",
                    "tmux", "kill-session", "-t", self._tmux_session_name(terminal_id),
                ],
                capture_output=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    def _cleanup_terminal(self, terminal_id, info, log_message):
        process = info.get("process")
        if process:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._stop_process(process)
        self._kill_tmux_session(terminal_id)
        if log_message:
            print(log_message, flush=True)

    def _collect_dead_terminals(self):
        dead = []
        for terminal_id, info in self.terminals.items():
            process = info.get("process")
            if process and process.poll() is not None:
                dead.append((terminal_id, info))
        return dead

    def create_terminal(self, wait=False):
        """Spawn a new ttyd process. Returns terminal info dict, 'limit', or None."""
        with self.lock:
            if len(self.terminals) >= self.max_terminals:
                return "limit"
            terminal_id = self.next_id
            port = self._allocate_port()
            if port is None:
                return "limit"
            try:
                process = self._start_ttyd_process(terminal_id, port)
            except OSError as exc:
                print(f"Failed to start TTYD on port {port}: {exc}", file=sys.stderr, flush=True)
                return None

            info = {"id": terminal_id, "port": port, "pid": process.pid, "process": process}
            self.terminals[terminal_id] = info
            self.next_id += 1

        if wait and not self._wait_for_ready(port):
            self.delete_terminal(terminal_id)
            return None

        print(f"Started terminal ttyd{terminal_id} on port {port} (PID {process.pid})", flush=True)
        return {"id": terminal_id, "port": port}

    def delete_terminal(self, terminal_id):
        """Kill a ttyd process and its tmux session."""
        with self.lock:
            info = self.terminals.pop(terminal_id, None)
        if not info:
            return False
        self._stop_process(info.get("process"))
        self._kill_tmux_session(terminal_id)
        print(f"Deleted terminal ttyd{terminal_id}", flush=True)
        return True

    def list_terminals(self):
        """Return active terminals sorted by id."""
        with self.lock:
            dead = self._collect_dead_terminals()
            for terminal_id, _info in dead:
                del self.terminals[terminal_id]
            result = sorted(
                [
                    {"id": terminal["id"], "port": terminal["port"], "pid": terminal["pid"]}
                    for terminal in self.terminals.values()
                ],
                key=lambda terminal: terminal["id"],
            )

        for terminal_id, info in dead:
            self._cleanup_terminal(terminal_id, info, f"Terminal ttyd{terminal_id} died, cleaned up")
        return result

    def get_terminal(self, terminal_id):
        """Get a terminal by id, or None."""
        dead_info = None
        with self.lock:
            info = self.terminals.get(terminal_id)
            if info:
                process = info.get("process")
                if process and process.poll() is not None:
                    dead_info = self.terminals.pop(terminal_id)
                else:
                    return {"id": info["id"], "port": info["port"]}

        if dead_info:
            self._cleanup_terminal(terminal_id, dead_info, f"Terminal ttyd{terminal_id} died, cleaned up")
        return None

    def _wait_for_ready(self, port, timeout=15):
        """Wait until ttyd is responding on the given port."""
        for _ in range(timeout):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                sock.close()
                return True
            except OSError:
                time.sleep(1)
        print(f"TTYD on port {port} failed to start within {timeout}s", file=sys.stderr, flush=True)
        return False

