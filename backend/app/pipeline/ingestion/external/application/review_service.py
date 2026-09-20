from __future__ import annotations

from typing import Any, Protocol


class ReviewService(Protocol):
    """Boundary for validated External review records and atomic decisions."""

    def latest(self) -> dict[str, Any] | None: ...
    def decide(self, record_id: str, expected_content_sha256: str, decision: str, reason: str | None,
               *, requested_by: str) -> dict[str, Any]: ...
