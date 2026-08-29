from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from backend.app.pipeline.ingestion.external.common.config_loader import load_config
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.privacy.pii_detector import PrivacyFinding, SensitiveDataDetector


IMPLEMENTATION_VERSION = "external_privacy_filter_v3"


@dataclass(frozen=True, slots=True)
class PrivacyResult:
    content: str
    status: str
    input_hash: str
    output_hash: str
    rules_hash: str
    rules_version: str
    metadata: dict[str, Any]
    findings: tuple[PrivacyFinding, ...]
    implementation_version: str = IMPLEMENTATION_VERSION

    @property
    def stage_hash(self) -> str:
        return sha256_json(
            {
                "input_hash": self.input_hash,
                "implementation_version": self.implementation_version,
                "rules_hash": self.rules_hash,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "status": self.status,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "rules_hash": self.rules_hash,
            "rules_version": self.rules_version,
            "metadata": self.metadata,
            "findings": [asdict(finding) for finding in self.findings],
            "implementation_version": self.implementation_version,
            "stage_hash": self.stage_hash,
        }


class PrivacyFilter:
    """Apply configured deterministic redaction after normal text cleaning."""

    def __init__(self, rules_path: str | Path, detector: SensitiveDataDetector | None = None) -> None:
        self.rules = load_config(rules_path)
        self.rules_version = str(self.rules.get("rules_version") or "")
        if not self.rules_version:
            raise ValueError("privacy rules_version is required")
        policy = self.rules.get("policy")
        placeholders = self.rules.get("redaction_placeholders")
        if not isinstance(policy, dict) or not isinstance(placeholders, dict):
            raise ValueError("privacy rules require policy and redaction_placeholders objects")
        self.policy = policy
        self.placeholders = {str(key): str(value) for key, value in placeholders.items()}
        self.rules_hash = sha256_json(self.rules)
        self.detector = detector or SensitiveDataDetector()

    def apply(self, cleaned_text: str) -> PrivacyResult:
        findings = self.detector.detect(cleaned_text)
        redactable = [finding for finding in findings if self._should_redact(finding)]
        output = cleaned_text
        for finding in sorted(redactable, key=lambda item: item.start, reverse=True):
            placeholder = self.placeholders.get(finding.value_type, f"[REDACTED:{finding.value_type}]")
            output = output[:finding.start] + placeholder + output[finding.end:]

        review_required = any(finding.action == "review" for finding in findings)
        status = "review_required" if review_required else "reviewed"
        redaction_types = sorted({finding.value_type for finding in redactable})
        preserved_types = sorted({finding.value_type for finding in findings if finding.category == "possible_cti_indicator"})
        categories = {category: sum(1 for finding in findings if finding.category == category) for category in sorted({item.category for item in findings})}
        metadata = {
            "privacy": {
                "status": status,
                "pii_detected": any(finding.category == "possible_personal_data" for finding in findings),
                "redactions_count": len(redactable),
                "redaction_types": redaction_types,
                "cti_value_types_preserved": preserved_types,
                "finding_categories": categories,
            }
        }
        return PrivacyResult(
            content=output,
            status=status,
            input_hash=sha256_text(cleaned_text),
            output_hash=sha256_text(output),
            rules_hash=self.rules_hash,
            rules_version=self.rules_version,
            metadata=metadata,
            findings=findings,
        )

    def _should_redact(self, finding: PrivacyFinding) -> bool:
        if finding.action != "redact":
            return False
        if finding.category == "possible_secret":
            return bool(self.policy.get("redact_high_confidence_secrets", True))
        if finding.category == "possible_personal_data":
            return bool(self.policy.get("redact_high_confidence_personal_data", True))
        return False
