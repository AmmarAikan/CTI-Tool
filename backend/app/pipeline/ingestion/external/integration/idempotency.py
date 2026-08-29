from __future__ import annotations

import threading
from copy import deepcopy
from typing import Any, Protocol


class IdempotencyStore(Protocol):
    def get(self, scope: str, key: str) -> dict[str, Any] | None: ...
    def put(self, scope: str, key: str, value: dict[str, Any]) -> None: ...


class InMemoryIdempotencyStore:
    """Development-only idempotency store; production requires durable shared storage."""

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get(self, scope: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            value = self._values.get((scope, key))
            return deepcopy(value) if value is not None else None

    def put(self, scope: str, key: str, value: dict[str, Any]) -> None:
        with self._lock: self._values[(scope, key)] = deepcopy(value)
