"""Graceful shutdown: SIGTERM must terminate the proxy, not deadlock.

The old handler called httpd.shutdown() from the signal handler, which runs
in the same main thread as serve_forever() — shutdown() then waits forever
for serve_forever() to exit, leaving a zombie process that no longer serves
requests.
"""
import os
import signal
import socket
import subprocess
import sys
import time
import unittest


APP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "app",
)


class GracefulShutdownTest(unittest.TestCase):
    def test_sigterm_exits_promptly(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        env = dict(os.environ, PORT=str(port))
        # Skip real ttyd spawning: on hosts with runuser but no ttyd binary,
        # create_terminal(wait=True) burns 15s in _wait_for_ready before the
        # HTTP server binds, overrunning this test's listen deadline.
        child_code = (
            "from ttydproxy import app\n"
            "app.ttyd_manager.create_terminal = lambda wait=False: None\n"
            "app.main()\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", child_code],
            cwd=APP_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                if proc.poll() is not None:
                    self.fail(
                        f"server died on startup: {proc.stdout.read()[:500]!r}"
                    )
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                self.fail("server never started listening")

            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.fail(
                    "proxy did not exit within 5s after SIGTERM "
                    "(shutdown deadlock)"
                )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
