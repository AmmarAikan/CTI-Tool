"""Canonical External Sources relevance-classification integration."""

from .classifier import ClassificationResult, CTIRelevanceClassifier, preprocess_for_model
from .classification_service import ClassificationService, ClassifiedItemResult

__all__ = [
    "ClassificationResult",
    "CTIRelevanceClassifier",
    "ClassificationService",
    "ClassifiedItemResult",
    "preprocess_for_model",
]
