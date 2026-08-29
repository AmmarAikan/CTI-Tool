from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import PreprocessingResult, TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter, PrivacyResult


@dataclass(frozen=True, slots=True)
class ContentProcessingResult:
    cleaned_content: str
    export_content: str
    review_required: bool
    preprocessing: PreprocessingResult
    privacy: PrivacyResult
    metadata: dict[str, Any]


class ExternalContentProcessor:
    """Enforce cleaning before privacy review while retaining only stage hashes in audit metadata."""

    def __init__(self, preprocessor: TextPreprocessor, privacy_filter: PrivacyFilter) -> None:
        self.preprocessor = preprocessor
        self.privacy_filter = privacy_filter

    def process(self, source_text: str | None) -> ContentProcessingResult:
        preprocessing = self.preprocessor.process(source_text)
        privacy = self.privacy_filter.apply(preprocessing.text)
        metadata = {
            **privacy.metadata,
            "processing": {
                "clean_input_hash": preprocessing.input_hash,
                "clean_output_hash": preprocessing.output_hash,
                "clean_stage_hash": preprocessing.stage_hash,
                "privacy_input_hash": privacy.input_hash,
                "privacy_output_hash": privacy.output_hash,
                "privacy_stage_hash": privacy.stage_hash,
            },
        }
        return ContentProcessingResult(
            cleaned_content=preprocessing.text,
            export_content=privacy.content,
            review_required=privacy.status == "review_required",
            preprocessing=preprocessing,
            privacy=privacy,
            metadata=metadata,
        )
