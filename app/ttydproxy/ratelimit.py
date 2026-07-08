"""Simple in-memory rate limiting helpers."""
import threading
import time
from collections import defaultdict


class RateLimiter:
    """Simple rate limiter for request attempts."""

    def __init__(self, max_attempts=5, window_seconds=60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(list)
        self.lock = threading.Lock()
        self._call_count = 0
        self._cleanup_interval = 100

    def is_allowed(self, key):
        """Check if the request is allowed for the given key."""
        with self.lock:
            # Monotonic clock, not wall-clock: a backward jump (NTP correction,
            # host suspend/resume, VM migration — realistic on a PaaS container)
            # would make current_time - attempt_time negative, so neither the
            # per-key prune nor the periodic sweep would evict old entries and
            # is_allowed() would stay False far past the window, locking out
            # legitimate users. monotonic() never goes backward (#101/#4).
            current_time = time.monotonic()
            self._call_count += 1
            if self._call_count >= self._cleanup_interval:
                self._call_count = 0
                stale_keys = [
                    attempt_key
                    for attempt_key, timestamps in self.attempts.items()
                    if all(current_time - timestamp >= self.window_seconds for timestamp in timestamps)
                ]
                for attempt_key in stale_keys:
                    del self.attempts[attempt_key]

            self.attempts[key] = [
                attempt_time
                for attempt_time in self.attempts[key]
                if current_time - attempt_time < self.window_seconds
            ]

            if len(self.attempts[key]) >= self.max_attempts:
                return False

            self.attempts[key].append(current_time)
            return True

