from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from backend.app.pipeline.common.cti_schema import RawRecord


class ExternalConnector(ABC):
    """Base contract for external-source connectors."""

    source_name: str

    @abstractmethod
    def collect(self) -> Iterable[RawRecord]:
        """Yield normalized raw records from one external source."""
