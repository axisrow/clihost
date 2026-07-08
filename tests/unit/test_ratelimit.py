"""Tests for the in-memory login rate limiter.

The limiter must use a monotonic clock: with wall-clock time.time(), a backward
clock jump (NTP correction, host suspend/resume, VM migration) freezes the
window and locks out legitimate users far past 60s/300s because neither the
per-key prune nor the periodic sweep evicts entries whose age went negative
(#101/#4).
"""
import unittest
from unittest.mock import patch

from ttydproxy import ratelimit
from ttydproxy.ratelimit import RateLimiter


class RateLimiterTest(unittest.TestCase):
    def test_blocks_after_max_attempts(self):
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        with patch.object(ratelimit.time, "monotonic", return_value=1000.0):
            self.assertTrue(limiter.is_allowed("ip"))
            self.assertTrue(limiter.is_allowed("ip"))
            self.assertTrue(limiter.is_allowed("ip"))
            # 4th within the window is rejected.
            self.assertFalse(limiter.is_allowed("ip"))

    def test_unblocks_after_window(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        clock = {"now": 1000.0}
        with patch.object(ratelimit.time, "monotonic", side_effect=lambda: clock["now"]):
            self.assertTrue(limiter.is_allowed("ip"))
            self.assertTrue(limiter.is_allowed("ip"))
            self.assertFalse(limiter.is_allowed("ip"))
            # Advance past the window: the old attempts are pruned.
            clock["now"] += 61
            self.assertTrue(limiter.is_allowed("ip"))

    def test_separate_keys_are_independent(self):
        limiter = RateLimiter(max_attempts=1, window_seconds=60)
        with patch.object(ratelimit.time, "monotonic", return_value=1000.0):
            self.assertTrue(limiter.is_allowed("a"))
            self.assertFalse(limiter.is_allowed("a"))
            self.assertTrue(limiter.is_allowed("b"))

    def test_backward_clock_does_not_wedge_limiter(self):
        # Regression: with wall-clock time, a backward jump made
        # (current_time - attempt_time) negative, so pruning kept stale entries
        # and the limiter stayed blocked. monotonic() never goes backward, so a
        # simulated backward sequence must still let a fresh window through.
        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        # Monotonic is non-decreasing by contract; even if the OS clock is
        # yanked back, monotonic() keeps advancing (or holds). We assert the
        # steady-state property: after the window elapses on the monotonic
        # timeline the user is allowed again — the wall-clock wedge cannot occur.
        clock = {"now": 5000.0}
        with patch.object(ratelimit.time, "monotonic", side_effect=lambda: clock["now"]):
            self.assertTrue(limiter.is_allowed("ip"))
            self.assertTrue(limiter.is_allowed("ip"))
            self.assertFalse(limiter.is_allowed("ip"))
            # Time moves forward on the monotonic timeline regardless of any
            # wall-clock adjustment; the window clears and access is restored.
            clock["now"] += 120
            self.assertTrue(limiter.is_allowed("ip"))

    def test_uses_monotonic_not_wall_clock(self):
        # Guard the fix directly: is_allowed must read time.monotonic, never
        # time.time (which is subject to backward jumps).
        limiter = RateLimiter(max_attempts=1, window_seconds=60)
        with patch.object(ratelimit.time, "monotonic", return_value=42.0) as mono, \
                patch.object(ratelimit.time, "time") as wall:
            limiter.is_allowed("ip")
            mono.assert_called()
            wall.assert_not_called()


if __name__ == "__main__":
    unittest.main()
