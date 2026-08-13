from __future__ import annotations

import hashlib
from dataclasses import dataclass

from backend.app.pipeline.common.cti_schema import CTIObject, Entity, Relationship
from backend.app.pipeline.extraction.ioc_extractor import IoCExtractor
from backend.app.pipeline.outlier.detector import (
    InternalOutlierDetector,
    OutlierDetection,
)
from backend.app.pipeline.outlier.feature_extractor import SessionFeatureExtractor
from backend.app.pipeline.outlier.sessionizer import (
    InternalSession,
    InternalSessionizer,
)

SENSITIVE_RAW_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "password",
    "secret",
    "token",
}


def _redact_for_cti(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_RAW_KEYS else _redact_for_cti(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_for_cti(item) for item in value]
    return value


@dataclass(slots=True)
class InternalPipelineResult:
    detections: list[OutlierDetection]
    cti_objects: list[CTIObject]


class InternalCTIPipeline:
    """Structured internal flow: sessionize, extract features, detect anomalies, and build CTI."""

    def __init__(
        self,
        sessionizer: InternalSessionizer | None = None,
        feature_extractor: SessionFeatureExtractor | None = None,
        detector: InternalOutlierDetector | None = None,
        ioc_extractor: IoCExtractor | None = None,
    ) -> None:
        self.sessionizer = sessionizer or InternalSessionizer()
        self.feature_extractor = feature_extractor or SessionFeatureExtractor()
        self.detector = detector or InternalOutlierDetector()
        self.ioc_extractor = ioc_extractor or IoCExtractor()

    def process(self, records) -> InternalPipelineResult:
        records = list(records)
        sessions = self.sessionizer.build_sessions(records)
        features = [self.feature_extractor.extract(session) for session in sessions]
        detections = self.detector.detect(sessions, features)
        objects = [self._to_cti_object(item) for item in detections if item.is_outlier]
        return InternalPipelineResult(detections=detections, cti_objects=objects)

    def _to_cti_object(self, detection: OutlierDetection) -> CTIObject:
        session = detection.session
        text = "\n".join(f"{record.title}: {record.content}" for record in session.records)
        indicators = self.ioc_extractor.extract(text)
        severity = self._severity(detection.features)
        relationship = Relationship(
            subject=session.source_ip,
            relation="observed-in",
            object=session.session_id,
            confidence=0.95,
            extraction_method="structured_sessionization",
            source_record_id=session.session_id,
        )
        confidence = min(1.0, 0.65 + max(0.0, detection.anomaly_score))
        source_label = "Wazuh" if session.source_type == "wazuh" else session.source_name
        parser_name = f"structured_{session.source_type}_parser"
        tags = ["internal", session.source_type, "outlier", severity]
        if session.source_type == "dionaea":
            tags.insert(2, "honeypot")
        return CTIObject(
            object_id=self._object_id(session),
            source_id=session.session_id,
            source_type=f"{session.source_type}_session",
            source_pipeline="internal",
            title=f"Outlier {source_label} session from {session.source_ip}",
            original_text=text,
            normalized_text=text.strip(),
            classification_label="cti_related",
            classification_confidence=round(confidence, 4),
            classification_backend=detection.backend,
            indicators=indicators,
            entities=[Entity(session.source_ip, "source_ip", 1.0, parser_name)],
            relationships=[relationship],
            first_seen=session.started_at.isoformat(),
            last_seen=session.ended_at.isoformat(),
            confidence=round(confidence, 4),
            severity=severity,
            tags=tags,
            raw_reference={
                "session_id": session.session_id,
                "source_type": session.source_type,
                "source_name": session.source_name,
                "source_ip": session.source_ip,
                "features": detection.features,
                "anomaly_score": detection.anomaly_score,
                "detector_backend": detection.backend,
                "alerts": _redact_for_cti(session.raw_alerts),
            },
            processing_status="transformed",
        )

    def _object_id(self, session: InternalSession) -> str:
        digest = hashlib.sha256(f"internal:{session.session_id}".encode()).hexdigest()
        return f"cti-{digest[:24]}"

    def _severity(self, features: dict[str, float]) -> str:
        level = features.get("max_rule_level", 0.0)
        credentials = features.get("credential_attempts", 0.0)
        alerts = features.get("alerts_count", 0.0)
        if level >= 12 or credentials >= 10 or alerts >= 20:
            return "critical"
        if level >= 10 or credentials >= 5 or alerts >= 10:
            return "high"
        if level >= 7 or credentials >= 1 or alerts >= 5:
            return "medium"
        return "low"
