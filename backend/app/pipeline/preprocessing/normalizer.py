from __future__ import annotations

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.preprocessing.cleaner import TextCleaner


class RecordNormalizer:
    """Normalize raw external records while preserving original raw data."""

    def __init__(self, cleaner: TextCleaner | None = None) -> None:
        self.cleaner = cleaner or TextCleaner()

    def normalize_text(self, record: RawRecord) -> str:
        title = self.cleaner.clean(record.title)
        content = self.cleaner.clean(record.content)
        if title and title not in content:
            return f"{title}. {content}".strip()
        return content
