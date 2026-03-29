"""Test that the HTTP server handles concurrent requests (ThreadingHTTPServer)."""
import time
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


SLOW_DELAY = 0.3  # seconds each slow request takes


class SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(SLOW_DELAY)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass


class TestConcurrentRequests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=3)

    def test_concurrent_requests_complete_in_parallel(self):
        """3 concurrent slow requests should finish in ~SLOW_DELAY, not 3×SLOW_DELAY."""
        n = 3
        results = []

        def fetch():
            url = f"http://127.0.0.1:{self.port}/"
            with urllib.request.urlopen(url, timeout=5) as r:
                results.append(r.read())

        threads = [threading.Thread(target=fetch) for _ in range(n)]
        start = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        elapsed = time.monotonic() - start

        self.assertEqual(len(results), n, "All requests must complete")
        self.assertLess(elapsed, SLOW_DELAY * n * 0.8,
                        f"Expected parallel execution (~{SLOW_DELAY}s), got {elapsed:.2f}s")

    def test_single_request_still_works(self):
        url = f"http://127.0.0.1:{self.port}/"
        with urllib.request.urlopen(url, timeout=5) as r:
            self.assertEqual(r.read(), b"ok")


if __name__ == "__main__":
    unittest.main()
