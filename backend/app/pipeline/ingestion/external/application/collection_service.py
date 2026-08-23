from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class CollectionRequest:
    source_ids: tuple[str, ...] = ()
    force: bool = False
    requested_by: str = "authorized_maintenance"
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class JobAccepted:
    job_id: str
    state: str = "queued"


class CollectionService(ABC):
    """Application boundary used by authorized adapters, never collectors directly."""

    @abstractmethod
    def start_collection(self, request: CollectionRequest) -> JobAccepted:
        """Validate a collection request and enqueue a job."""

    @abstractmethod
    def collect_source(self, source_id: str, *, requested_by: str) -> JobAccepted:
        """Validate and enqueue collection for one approved source."""
