from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar


@dataclass(slots=True)
class RiskResult:
    score: float
    severity: str
    factors: dict[str, float]


class RiskScorer:
    """Explainable 0-100 score; this is a project rule, not a trained model."""

    SEVERITY_BASE: ClassVar[dict[str, float]] = {
        "critical": 35.0,
        "high": 28.0,
        "medium": 18.0,
        "low": 8.0,
    }

    def score(
        self,
        cti_object: Any,
        enrichments: list[dict[str, Any]] | None = None,
        source_count: int = 1,
        correlation_count: int = 0,
    ) -> RiskResult:
        enrichments = enrichments or []
        cvss_scores = [
            float(item["cvss_score"])
            for item in enrichments
            if item.get("cvss_score") is not None
        ]
        raw_reference = getattr(cti_object, "raw_reference", {}) or {}
        source_severity = raw_reference.get("source_severity") or cti_object.severity
        severity_base = self.SEVERITY_BASE.get(str(source_severity or "").lower(), 5.0)
        cvss_factor = max(cvss_scores, default=0.0) * 4.0
        indicator_factor = min(20.0, len(cti_object.indicators) * 3.0)
        confidence_factor = min(10.0, max(0.0, cti_object.confidence) * 10.0)
        source_factor = min(9.0, max(0, source_count - 1) * 3.0)
        correlation_factor = min(10.0, correlation_count * 2.0)
        outlier_factor = 12.0 if "outlier" in cti_object.tags else 0.0
        base_factor = cvss_factor if cvss_scores else severity_base
        factors = {
            "base_severity_or_cvss": round(base_factor, 2),
            "indicators": indicator_factor,
            "confidence": round(confidence_factor, 2),
            "source_diversity": source_factor,
            "correlations": correlation_factor,
            "internal_outlier": outlier_factor,
        }
        score = round(min(100.0, sum(factors.values())), 2)
        return RiskResult(score=score, severity=self.severity_for(score), factors=factors)

    @staticmethod
    def severity_for(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"
