from __future__ import annotations

from dataclasses import dataclass, replace

from backend.app.pipeline.ingestion.external.classification.classifier import (
    ClassificationResult,
    CTIRelevanceClassifier,
    MODEL_SHA256,
)
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification


TRUSTED_SOURCE_TYPES = frozenset(
    {"rss", "cert", "nvd", "cve", "mitre", "github_advisories", "cisa_kev", "vulnerability"}
)


@dataclass(frozen=True, slots=True)
class ClassifiedItemResult:
    item: ExternalCTIItem
    disposition: str
    result: ClassificationResult | None
    review_reason: str | None = None


class ClassificationService:
    """Apply model policy to general sources and preserve trusted bypasses."""

    def __init__(self, classifier: CTIRelevanceClassifier | None = None) -> None:
        self.classifier = classifier or CTIRelevanceClassifier()

    def classify_item(self, item: ExternalCTIItem) -> ClassifiedItemResult:
        if item.source_type.lower() in TRUSTED_SOURCE_TYPES or item.classification.status == "not_required":
            bypassed = replace(item, classification=ExternalClassification(status="not_required"))
            return ClassifiedItemResult(bypassed, "accepted", None)

        result = self.classifier.classify(item.content)
        classification = ExternalClassification(
            status=result.status,
            label=result.label,
            score=result.score,
            model_version=result.model_version,
        )
        metadata = {
            **item.metadata,
            "classification_stage": {
                "input_hash": item.content_hash,
                "output_hash": sha256_json(
                    {"status": result.status, "label": result.label, "score": result.score, "model_version": result.model_version}
                ),
                "model_sha256": MODEL_SHA256,
                "error_category": result.error_category,
            },
        }
        classified = replace(item, classification=classification, metadata=metadata)
        if result.status == "accepted":
            return ClassifiedItemResult(classified, "accepted", result)
        if result.status == "rejected":
            return ClassifiedItemResult(classified, "rejected", result)
        return ClassifiedItemResult(classified, "review", result, result.error_category)
