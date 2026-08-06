"""
Base collector abstraction.

All collector implementations (RSS, CERT advisories, vulnerability feeds,
social media, and future source types like deep/dark web or honeypots)
should inherit from `BaseCollector` and implement `collect()`. This keeps
`main.py` and any future orchestration logic decoupled from the specifics
of any single source type.
"""

from abc import ABC, abstractmethod
from typing import List

from src.utils.schema import CTIItem


class BaseCollector(ABC):
    """Abstract base class every source collector must implement."""

    #: Human-readable name of the collector, used in logs and metadata.
    name: str = "base_collector"

    @abstractmethod
    def collect(self) -> List[CTIItem]:
        """
        Collect items from the source and return them as a list of
        `CTIItem` instances conforming to the unified schema.

        Implementations must not raise on a single-source failure; they
        should log the error and return whatever was successfully
        collected (possibly an empty list).
        """
        raise NotImplementedError
