from __future__ import annotations

from typing import Any

from backend.app.pipeline.classification.model_loader import ClassificationModelLoader
from backend.app.pipeline.common.cti_schema import ClassificationResult, RawRecord


CTI_KEYWORDS = {
    "apt",
    "attack campaign",
    "botnet",
    "command and control",
    "cve-",
    "exploit",
    "exploited",
    "indicator of compromise",
    "ioc",
    "kev",
    "malware",
    "phishing",
    "ransomware",
    "threat actor",
    "trojan",
    "zero-day",
}

CYBERSECURITY_KEYWORDS = {
    "authentication",
    "cybersecurity",
    "encryption",
    "firewall",
    "patch",
    "privacy",
    "security advisory",
    "security flaw",
    "vulnerability",
}


class RelevanceClassifier:
    """Document-level relevance classifier with explicit fallback metadata."""

    def __init__(self, model: Any | None = None, model_version: str = "rule_keywords_2026_07_24") -> None:
        self.model = model if model is not None else ClassificationModelLoader().load()
        self.model_version = model_version

    def classify(self, record: RawRecord, normalized_text: str) -> ClassificationResult:
        if record.trusted_cybersecurity_source:
            return ClassificationResult(
                label="cti_related",
                confidence=1.0,
                backend="trusted_source_bypass",
                model_version="source_contract_v1",
                reason="trusted structured cybersecurity source",
            )

        if self.model is not None:
            result = self._classify_with_model(normalized_text)
            if result is not None:
                return result

        return self._classify_with_rules(normalized_text)

    def _classify_with_model(self, text: str) -> ClassificationResult | None:
        try:
            prediction = self.model.predict([text])[0]
            confidence = 0.75
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba([text])[0]
                confidence = float(max(probabilities))
            return ClassificationResult(
                label=self._normalize_label(str(prediction)),
                confidence=round(confidence, 4),
                backend="sklearn",
                model_version=self.model_version,
            )
        except Exception:
            return None

    def _classify_with_rules(self, text: str) -> ClassificationResult:
        lowered = text.lower()
        cti_hits = sum(1 for keyword in CTI_KEYWORDS if keyword in lowered)
        cyber_hits = sum(1 for keyword in CYBERSECURITY_KEYWORDS if keyword in lowered)

        if cti_hits:
            confidence = min(0.95, 0.65 + (cti_hits * 0.07) + (cyber_hits * 0.03))
            return ClassificationResult(
                label="cti_related",
                confidence=round(confidence, 4),
                backend="rule_based",
                model_version=self.model_version,
                reason=f"matched {cti_hits} CTI keyword(s)",
            )
        if cyber_hits:
            confidence = min(0.85, 0.55 + (cyber_hits * 0.08))
            return ClassificationResult(
                label="cybersecurity_related",
                confidence=round(confidence, 4),
                backend="rule_based",
                model_version=self.model_version,
                reason=f"matched {cyber_hits} cybersecurity keyword(s)",
            )
        return ClassificationResult(
            label="not_cybersecurity",
            confidence=0.8,
            backend="rule_based",
            model_version=self.model_version,
            reason="no cybersecurity or CTI indicators matched",
        )

    def _normalize_label(self, label: str):
        normalized = label.strip().lower().replace(" ", "_").replace("-", "_")
        if normalized in {"cti", "cti_related", "threat_intelligence"}:
            return "cti_related"
        if normalized in {"cybersecurity", "cybersecurity_related", "security_related"}:
            return "cybersecurity_related"
        return "not_cybersecurity"
