"""Lifecycle management for ttyd child processes."""
from contextlib import contextmanager
import os
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
        self._port_leases = {}
        self.next_id = 1
        self.lock = threading.Lock()
        self.base_port = base_port
        self.max_terminals = max_terminals
        self.ttyd_user = ttyd_user
        self.ttyd_binary = ttyd_binary
        self.tmux_wrapper = tmux_wrapper
        # Background reaper state (#101/#7). Without it, a dead ttyd is only
        # reaped lazily inside list_terminals()/get_terminal(); with no
        # list/get/health traffic a defunct zombie would pin its PID slot
        # forever. The reaper thread polls periodically as a safety net.
        self._reaper_thread = None
        self._reaper_stop = threading.Event()

    def _allocate_port(self):
        """Find the next port not owned by a terminal or in-flight proxy."""
        used_ports = {
            terminal["port"] for terminal in self.terminals.values()
        } | self._port_leases.keys()
        max_port = self.base_port + self.max_terminals
        port = self.base_port
        while port in used_ports:
            port += 1
            if port >= max_port:
                return None
        return port

    def _tmux_session_name(self, terminal_id):
        return f"ttyd-{terminal_id}"

    def _as_ttyd_user(self, command):
        """Wrap a command with runuser when root; unprivileged proxies run it directly."""
        if os.geteuid() == 0:
            return ["runuser", "-u", self.ttyd_user, "--", *command]
        return command

    def _start_ttyd_process(self, terminal_id, port):
        tmux_session = self._tmux_session_name(terminal_id)
        return subprocess.Popen(
            self._as_ttyd_user([
                self.ttyd_binary,
                "-p", str(port),
                "-i", "127.0.0.1",
                "-W",
                self.tmux_wrapper, tmux_session,
            ]),
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
                self._as_ttyd_user(
                    ["tmux", "kill-session", "-t", self._tmux_session_name(terminal_id)]
                ),
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

    def reap_dead_terminals(self):
        """Collect dead ttyd processes under the lock, then clean them up
        outside it (tmux kill can block). Returns the number reaped. Safe to
        call from the background reaper or any request path (#101/#7)."""
        with self.lock:
            dead = self._collect_dead_terminals()
            for terminal_id, _info in dead:
                del self.terminals[terminal_id]
        for terminal_id, info in dead:
            self._cleanup_terminal(
                terminal_id, info, f"Terminal ttyd{terminal_id} died, reaped"
            )
        return len(dead)

    def _reaper_loop(self, interval):
        # Poll until stop() is signalled. Event.wait doubles as the sleep so a
        # shutdown returns promptly instead of after a full interval.
        while not self._reaper_stop.wait(interval):
            try:
                self.reap_dead_terminals()
            except Exception as exc:  # never let the daemon thread die
                print(f"Reaper error: {exc}", file=sys.stderr, flush=True)

    def start_reaper(self, interval=30):
        """Start the background reaper thread (idempotent)."""
        if self._reaper_thread and self._reaper_thread.is_alive():
            return
        self._reaper_stop.clear()
        self._reaper_thread = threading.Thread(
            target=self._reaper_loop, args=(interval,), daemon=True, name="ttyd-reaper"
        )
        self._reaper_thread.start()

    def stop_reaper(self):
        """Signal the reaper thread to stop and join it briefly."""
        self._reaper_stop.set()
        thread = self._reaper_thread
        if thread and thread.is_alive():
            thread.join(timeout=5)

    def create_terminal(self, wait=False):
        """Spawn a new ttyd process. Returns terminal info dict, 'limit', or None."""
        with self.lock:
            if len(self.terminals) >= self.max_terminals:
                return "limit"
            terminal_id = self.next_id
            port = self._allocate_port()
            if port is None:
                return "limit"
            # Consume the ID before starting the process: a failed start must
            # not let the next terminal reuse the same ID.
            self.next_id += 1
            try:
                process = self._start_ttyd_process(terminal_id, port)
            except OSError as exc:
                print(f"Failed to start TTYD on port {port}: {exc}", file=sys.stderr, flush=True)
                return None

            info = {"id": terminal_id, "port": port, "pid": process.pid, "process": process}
            self.terminals[terminal_id] = info

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

    @contextmanager
    def lease_terminal(self, terminal_id):
        """Hold a terminal's port against reuse for an in-flight proxy request."""
        dead_info = None
        port = None
        terminal = None
        with self.lock:
            info = self.terminals.get(terminal_id)
            if info:
                process = info.get("process")
                if process and process.poll() is not None:
                    dead_info = self.terminals.pop(terminal_id)
                else:
                    port = info["port"]
                    self._port_leases[port] = self._port_leases.get(port, 0) + 1
                    terminal = {"id": info["id"], "port": port}

        if dead_info:
            self._cleanup_terminal(
                terminal_id,
                dead_info,
                f"Terminal ttyd{terminal_id} died, cleaned up",
            )

        try:
            yield terminal
        finally:
            if port is not None:
                with self.lock:
                    remaining = self._port_leases[port] - 1
                    if remaining:
                        self._port_leases[port] = remaining
                    else:
                        del self._port_leases[port]

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
