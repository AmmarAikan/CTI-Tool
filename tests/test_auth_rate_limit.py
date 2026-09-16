from __future__ import annotations

import unittest

from starlette.requests import Request

from backend.app.core.rate_limit import SlidingWindowRateLimiter, rate_limit_key, request_identity


class SlidingWindowRateLimiterTests(unittest.TestCase):
    def test_enforces_window_and_recovers_deterministically(self) -> None:
        now = [100.0]
        limiter = SlidingWindowRateLimiter(clock=lambda: now[0], max_buckets=4)
        key = rate_limit_key("register", "client-a")

        self.assertIsNone(limiter.consume(key, limit=2, window_seconds=10))
        self.assertIsNone(limiter.consume(key, limit=2, window_seconds=10))
        self.assertEqual(limiter.consume(key, limit=2, window_seconds=10), 10)

        now[0] = 111.0
        self.assertIsNone(limiter.consume(key, limit=2, window_seconds=10))

    def test_clear_removes_only_selected_bucket(self) -> None:
        limiter = SlidingWindowRateLimiter(max_buckets=4)
        first = rate_limit_key("login", "client-a", "analyst")
        second = rate_limit_key("login", "client-b", "analyst")
        limiter.consume(first, limit=1, window_seconds=60)
        limiter.consume(second, limit=1, window_seconds=60)

        limiter.clear(first)

        self.assertIsNone(limiter.consume(first, limit=1, window_seconds=60))
        self.assertIsNotNone(limiter.consume(second, limit=1, window_seconds=60))

    def test_proxy_resolved_clients_get_distinct_keys(self) -> None:
        def identity(peer: str, forwarded: str) -> str:
            scope = {
                "type": "http",
                "client": (peer, 12345),
                "headers": [(b"x-forwarded-for", forwarded.encode("ascii"))],
            }
            return request_identity(Request(scope))

        self.assertNotEqual(identity("172.25.0.5", "100.91.28.22"), identity("172.25.0.5", "100.91.28.23"))
        self.assertEqual(identity("198.51.100.4", "203.0.113.9"), identity("198.51.100.4", "198.51.100.4"))
        self.assertEqual(identity("192.168.0.4", "203.0.113.9"), identity("192.168.0.4", "192.168.0.4"))
        self.assertEqual(identity("172.25.0.5", "not-an-ip"), identity("172.25.0.5", "172.25.0.5"))


if __name__ == "__main__":
    unittest.main()
