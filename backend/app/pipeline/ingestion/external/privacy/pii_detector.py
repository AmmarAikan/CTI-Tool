from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


FindingCategory = Literal[
    "possible_cti_indicator",
    "public_attribution",
    "possible_personal_data",
    "possible_secret",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class PrivacyFinding:
    category: FindingCategory
    value_type: str
    start: int
    end: int
    confidence: float
    action: str


SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 1.0),
    ("possible_api_token", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.99),
    ("possible_api_token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.98),
    ("possible_api_token", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_./+\-=]{12,})['\"]?"), 0.96),
)
PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d ().-]{5,}\d(?!\w)")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://[^\s<>'\"]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)
HANDLE_RE = re.compile(r"(?<!\w)@[A-Za-z0-9_]{2,32}\b")


class SensitiveDataDetector:
    """Detect sensitive spans without retaining their values in findings."""

    def detect(self, text: str) -> tuple[PrivacyFinding, ...]:
        findings: list[PrivacyFinding] = []
        occupied: list[tuple[int, int]] = []

        for value_type, pattern, confidence in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                self._append(findings, occupied, PrivacyFinding("possible_secret", value_type, match.start(), match.end(), confidence, "redact"))

        for pattern, value_type in ((URL_RE, "url"), (CVE_RE, "cve"), (HASH_RE, "hash"), (IP_RE, "ipv4")):
            for match in pattern.finditer(text):
                self._append(findings, occupied, PrivacyFinding("possible_cti_indicator", value_type, match.start(), match.end(), 0.9, "preserve"))

        for match in EMAIL_RE.finditer(text):
            context = text[max(0, match.start() - 60): min(len(text), match.end() + 60)].lower()
            if any(word in context for word in ("author", "researcher", "reported by", "contact", "security team")):
                finding = PrivacyFinding("public_attribution", "email", match.start(), match.end(), 0.8, "preserve")
            elif any(word in context for word in ("indicator", "ioc", "phishing", "sender", "malicious", "observed")):
                finding = PrivacyFinding("possible_cti_indicator", "email", match.start(), match.end(), 0.75, "preserve")
            else:
                finding = PrivacyFinding("unknown", "email", match.start(), match.end(), 0.5, "review")
            self._append(findings, occupied, finding)

        for match in PHONE_RE.finditer(text):
            digits = sum(character.isdigit() for character in match.group(0))
            if 7 <= digits <= 15:
                self._append(findings, occupied, PrivacyFinding("possible_personal_data", "phone_number", match.start(), match.end(), 0.95, "redact"))

        for match in HANDLE_RE.finditer(text):
            self._append(findings, occupied, PrivacyFinding("unknown", "username", match.start(), match.end(), 0.5, "review"))

        return tuple(sorted(findings, key=lambda item: (item.start, item.end, item.value_type)))

    @staticmethod
    def _append(findings: list[PrivacyFinding], occupied: list[tuple[int, int]], finding: PrivacyFinding) -> None:
        if any(finding.start < end and finding.end > start for start, end in occupied):
            return
        findings.append(finding)
        occupied.append((finding.start, finding.end))
