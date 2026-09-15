from __future__ import annotations

import hashlib
import ipaddress
import math
import threading
import time
from collections import deque
from collections.abc import Callable

from fastapi import Request


class SlidingWindowRateLimiter:
    """Small bounded limiter for a single ACTIT backend process."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_buckets: int = 4096,
    ) -> None:
        self._clock = clock
        self._max_buckets = max_buckets
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def consume(self, key: str, *, limit: int, window_seconds: int) -> int | None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate limit and window must be positive")
        now = self._clock()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                self._make_room()
                bucket = deque()
                self._buckets[key] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return max(1, math.ceil(window_seconds - (now - bucket[0])))
            bucket.append(now)
            return None

    def clear(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._buckets.pop(key, None)

    def _make_room(self) -> None:
        if len(self._buckets) < self._max_buckets:
            return
        empty = next((key for key, bucket in self._buckets.items() if not bucket), None)
        self._buckets.pop(empty or next(iter(self._buckets)), None)


def request_identity(request: Request) -> str:
    """Return a non-reversible client key, trusting XFF only from an internal peer."""

    peer = request.client.host if request.client else "unknown"
    candidate = peer
    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        peer_address = None

    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    if forwarded and peer_address is not None and (
        peer_address.is_private or peer_address.is_loopback
    ):
        try:
            candidate = str(ipaddress.ip_address(forwarded))
        except ValueError:
            candidate = peer

    return hashlib.sha256(candidate.encode("utf-8", errors="replace")).hexdigest()


def rate_limit_key(action: str, identity: str, subject: str = "") -> str:
    normalized_subject = subject.strip().casefold()
    material = f"{action}\\0{identity}\\0{normalized_subject}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()
