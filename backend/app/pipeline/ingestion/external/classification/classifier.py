from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


MODEL_PATH = Path(__file__).resolve().parent / "model" / "cti_svm_model.pkl"
MODEL_SHA256 = "0e929dfebd36c46498047a6f93d3b5d08ba9aad81d48f8f3f68070c6e21d7d8c"
MODEL_VERSION = f"cti-svm-sha256:{MODEL_SHA256}"
MIN_CLASSIFIABLE_CHARACTERS = 80

# Copied exactly from the approved prototype's documented training-time path.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

ClassificationStatus = Literal["accepted", "rejected", "not_run", "error"]


def preprocess_for_model(text: str) -> str:
    """Apply the preprocessing performed outside the serialized pipeline."""
    value = _CVE_PATTERN.sub("specifiedcve", text)
    value = _IPV4_PATTERN.sub("specifiedip", value)
    return value.lower()


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    status: ClassificationStatus
    label: str | None
    score: float | None
    model_version: str
    model_sha256: str
    error_category: str | None = None


class CTIRelevanceClassifier:
    """Lazy, process-reused adapter for the approved immutable model artifact."""

    _models: dict[Path, Any] = {}
    _load_errors: dict[Path, str] = {}
    _lock = threading.Lock()

    def __init__(self, model_path: str | Path = MODEL_PATH, *, minimum_characters: int = MIN_CLASSIFIABLE_CHARACTERS) -> None:
        self.model_path = Path(model_path).resolve()
        self.minimum_characters = minimum_characters

    def classify(self, text: str | None) -> ClassificationResult:
        value = text or ""
        if not value.strip():
            return self._result("not_run", None, error_category="empty_input")
        if len(value.strip()) < self.minimum_characters:
            return self._result("not_run", None, error_category="short_input")
        model = self._load_model()
        if model is None:
            return self._result("error", None, error_category=self._load_errors.get(self.model_path, "model_load_failed"))
        try:
            prediction = model.predict([preprocess_for_model(value)])[0]
            numeric = int(prediction)
            if numeric == 1:
                return self._result("accepted", "cti_related")
            if numeric == 0:
                return self._result("rejected", "not_cti_related")
            return self._result("error", None, error_category="unknown_model_label")
        except Exception:
            return self._result("error", None, error_category="prediction_failed")

    def _load_model(self) -> Any | None:
        with self._lock:
            if self.model_path in self._models:
                return self._models[self.model_path]
            if self.model_path in self._load_errors:
                return None
            if not self.model_path.is_file():
                self._load_errors[self.model_path] = "model_missing"
                return None
            try:
                digest = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
                if self.model_path == MODEL_PATH.resolve() and digest != MODEL_SHA256:
                    self._load_errors[self.model_path] = "model_hash_mismatch"
                    return None
                import joblib

                model = joblib.load(self.model_path)
                if not hasattr(model, "predict"):
                    raise TypeError("model has no predict method")
                self._models[self.model_path] = model
                return model
            except Exception:
                self._load_errors[self.model_path] = "model_load_failed"
                return None

    @staticmethod
    def _result(status: ClassificationStatus, label: str | None, *, error_category: str | None = None) -> ClassificationResult:
        # LinearSVC exposes a margin, not a calibrated probability; do not
        # misrepresent that value as the contract's 0..1 score.
        return ClassificationResult(status, label, None, MODEL_VERSION, MODEL_SHA256, error_category)

    @classmethod
    def clear_cache_for_tests(cls) -> None:
        with cls._lock:
            cls._models.clear()
            cls._load_errors.clear()
