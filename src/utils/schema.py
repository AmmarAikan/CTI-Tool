"""
Unified data schema for all collected CTI items.

Every collector (RSS, CERT, vulnerability DB, social media, ...) must
eventually produce items conforming to this structure so downstream
modules (classification, NER, IOC extraction, database, dashboard) can
consume a single consistent format regardless of source type.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class CTIItem:
    """Represents a single normalized piece of collected CTI data."""

    title: str
    link: str
    source: str
    category: str = "uncategorized"
    content: str = ""
    summary: str = ""
    published: Optional[str] = None
    author: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    collected_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the item to a plain dictionary (e.g. for JSON output)."""
        return asdict(self)
