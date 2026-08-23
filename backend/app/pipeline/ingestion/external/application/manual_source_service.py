from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ManualSourceResult:
    status: str
    message: str
    records_created: int = 0
    records_updated: int = 0
    canonical_url: str | None = None
    job_id: str | None = None


class ManualSourceService(ABC):
    @abstractmethod
    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        """Validate and submit a public URL through policy-aware routing."""

    @abstractmethod
    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        """Request an incremental recheck without bypassing policy."""
