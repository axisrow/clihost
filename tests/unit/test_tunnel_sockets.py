"""Tests for bidirectional socket tunneling in the ttyd proxy."""
import socket
import threading
import time
import unittest

from ttydproxy import proxy


class FakeHandler:
    def __init__(self, conn):
        self.connection = conn


def _recv_exactly(sock, expected_length, chunk_size=4096, delay=0):
    """Read until EOF or expected_length bytes, optionally pacing reads."""
    received = bytearray()
    while len(received) < expected_length:
        chunk = sock.recv(chunk_size)
        if not chunk:
            break
        received.extend(chunk)
        if delay:
            time.sleep(delay)
    return bytes(received)


class TunnelSocketsTest(unittest.TestCase):
    def setUp(self):
        self.client_inner, self.client_outer = socket.socketpair()
        self.upstream_inner, self.upstream_outer = socket.socketpair()
        self.client_outer.settimeout(10)
        self.upstream_outer.settimeout(10)
        self.thread = None

    def tearDown(self):
        for sock in (
            self.client_inner,
            self.client_outer,
            self.upstream_inner,
            self.upstream_outer,
        ):
            try:
                sock.close()
            except OSError:
                pass

    def start_tunnel(self):
        def run():
            proxy.tunnel_sockets(FakeHandler(self.client_inner), self.upstream_inner)
            # Close inner ends so the outer ends observe EOF after the
            # tunnel returns, mirroring proxy_ttyd_websocket cleanup.
            for sock in (self.client_inner, self.upstream_inner):
                try:
                    sock.close()
                except OSError:
                    pass

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def join_tunnel(self):
        self.thread.join(timeout=10)
        self.assertFalse(self.thread.is_alive(), "tunnel thread did not finish")

    def test_bidirectional_small_payloads(self):
        self.start_tunnel()
        self.client_outer.sendall(b"input from browser")
        self.upstream_outer.sendall(b"output from ttyd")

        self.assertEqual(
            _recv_exactly(self.upstream_outer, len(b"input from browser")),
            b"input from browser",
        )
        self.assertEqual(
            _recv_exactly(self.client_outer, len(b"output from ttyd")),
            b"output from ttyd",
        )

        self.client_outer.close()
        self.join_tunnel()

    def test_large_burst_to_slow_reader_no_data_loss(self):
        # Regression test: with non-blocking sendall() the tunnel dropped
        # bytes and disconnected once the kernel send buffer filled up.
        self.client_inner.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.client_outer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.start_tunnel()

        payload = bytes(range(256)) * 2048  # 512 KiB of patterned data

        def write_payload():
            self.upstream_outer.sendall(payload)
            self.upstream_outer.shutdown(socket.SHUT_WR)

        writer = threading.Thread(target=write_payload, daemon=True)
        writer.start()

        received = _recv_exactly(
            self.client_outer, len(payload), chunk_size=2048, delay=0.0005
        )
        writer.join(timeout=10)
        self.assertFalse(writer.is_alive(), "writer thread did not finish")
        self.assertEqual(len(received), len(payload))
        self.assertEqual(received, payload)

    def test_eof_drains_pending_buffer(self):
        self.client_inner.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.client_outer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.start_tunnel()

        payload = b"x" * 65536
        self.upstream_outer.sendall(payload)
        self.upstream_outer.shutdown(socket.SHUT_WR)

        # Read past the payload: the next recv must return EOF only after
        # every buffered byte has been delivered.
        received = _recv_exactly(
            self.client_outer, len(payload) + 1, chunk_size=2048, delay=0.0005
        )
        self.assertEqual(received, payload)
        self.join_tunnel()

    def test_returns_when_client_closes(self):
        self.start_tunnel()
        self.client_outer.close()
        self.join_tunnel()

    def test_client_half_close_still_drains_pending_data(self):
        # Regression test: an early-exit on client EOF used to discard
        # ttyd output still buffered for the (half-closed) client.
        self.client_inner.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.client_outer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.start_tunnel()

        payload = b"z" * 65536
        self.upstream_outer.sendall(payload)
        # Let the tunnel ingest the burst into its pending buffer before
        # the client half-closes its write side.
        time.sleep(0.3)
        self.client_outer.shutdown(socket.SHUT_WR)

        received = _recv_exactly(
            self.client_outer, len(payload) + 1, chunk_size=2048, delay=0.0005
        )
        self.assertEqual(received, payload)
        self.join_tunnel()

    def test_backpressure_caps_buffering(self):
        original_cap = proxy.TUNNEL_MAX_PENDING
        proxy.TUNNEL_MAX_PENDING = 16384
        self.addCleanup(setattr, proxy, "TUNNEL_MAX_PENDING", original_cap)

        self.client_inner.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.client_outer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.upstream_outer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.start_tunnel()

        # Client never reads: the tunnel must stop accepting upstream data
        # once its pending buffer hits the cap, instead of buffering forever.
        self.upstream_outer.setblocking(False)
        chunk = b"y" * 4096
        accepted = 0
        stalled_since = None
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                accepted += self.upstream_outer.send(chunk)
                stalled_since = None
            except (BlockingIOError, InterruptedError):
                if stalled_since is None:
                    stalled_since = time.time()
                elif time.time() - stalled_since > 0.5:
                    break
                time.sleep(0.01)
        else:
            self.fail("upstream writes never stalled — no backpressure")

        # Cap + recv overshoot + kernel socket buffers, with generous slack.
        self.assertLess(accepted, 524288)
        self.assertTrue(self.thread.is_alive(), "tunnel died under backpressure")

        # Drain everything: no byte may be lost.
        self.upstream_outer.setblocking(True)
        self.upstream_outer.settimeout(10)
        self.upstream_outer.shutdown(socket.SHUT_WR)
        received = _recv_exactly(self.client_outer, accepted, chunk_size=4096)
        self.assertEqual(len(received), accepted)
        self.assertEqual(received, b"y" * accepted)
        self.join_tunnel()


if __name__ == "__main__":
    unittest.main()
