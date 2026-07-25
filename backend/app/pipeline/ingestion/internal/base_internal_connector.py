from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any


class InternalConnector(ABC):
    """Base contract for future structured internal telemetry connectors."""

    source_name: str

    @abstractmethod
    def collect(self) -> Iterable[dict[str, Any]]:
        """Yield raw internal records such as Wazuh, Zeek, firewall, or honeypot logs."""
