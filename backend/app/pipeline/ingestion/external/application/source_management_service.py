from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SourceView:
    source_id: str
    name: str
    source_type: str
    status: str
    metadata: dict[str, Any]


class SourceManagementService(ABC):
    @abstractmethod
    def list_sources(self) -> list[SourceView]:
        """Return safe source summaries without credentials or sensitive URLs."""

    @abstractmethod
    def get_source_status(self, source_id: str) -> SourceView | None:
        """Return a safe source summary when it exists."""

    @abstractmethod
    def request_source_enable(self, source_id: str, *, requested_by: str) -> SourceView:
        """Request review; ordinary sources are not automatically activated."""

    @abstractmethod
    def disable_source(self, source_id: str, *, requested_by: str) -> SourceView:
        """Disable an External source through the application policy boundary."""
