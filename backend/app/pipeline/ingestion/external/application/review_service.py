from __future__ import annotations

from typing import Any, Protocol


class ReviewService(Protocol):
    """Read-only boundary for safely projected External review records."""

    def latest(self) -> dict[str, Any] | None: ...
