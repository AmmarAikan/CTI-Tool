from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class JobView:
    job_id: str
    state: str
    created_at: str
    updated_at: str
    progress: dict[str, int] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class JobService(ABC):
    @abstractmethod
    def get_job_status(self, job_id: str) -> JobView | None:
        """Return transport-independent job state."""

    @abstractmethod
    def cancel_job(self, job_id: str, *, requested_by: str) -> JobView:
        """Request cooperative cancellation without killing unrelated processes."""

    @abstractmethod
    def get_latest_export(self) -> dict[str, Any] | None:
        """Return safe metadata for the latest validated export."""
