from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from backend.app.pipeline.common.cti_schema import RawRecord


class InternalConnector(ABC):
    """Base contract for structured internal telemetry connectors."""

    source_name: str

    @abstractmethod
    def collect(self) -> Iterable[RawRecord]:
        """Yield raw internal records such as Wazuh, Zeek, firewall, or honeypot logs."""
