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
CTI_EMAIL_CONTEXT = (
    "attacker", "threat actor", "attacker-controlled account", "malicious sender",
    "phishing sender", "register attacker infrastructure", "registered attacker infrastructure",
    "indicator", "ioc", "indicator table",
)
MONTH_NAME = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
CALENDAR_PATTERNS = (
    ("calendar_date", re.compile(rf"(?i)\b{MONTH_NAME}\s+\d{{1,2}}(?:\s*[-–—]\s*\d{{1,2}})?(?:,?\s+\d{{4}})?\b")),
    ("calendar_date", re.compile(r"\b(?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}\b")),
    ("year_range", re.compile(r"\b(?:19|20)\d{2}\s*[-–—]\s*(?:19|20)\d{2}\b")),
)
TECHNICAL_PATTERNS = (
    ("cpu_frequency", re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:Hz|kHz|MHz|GHz|THz)\b")),
    ("hexadecimal_identifier", re.compile(r"(?i)\b0x[0-9a-f]+\b")),
    ("processor_hardware_id", re.compile(r"(?im)^\s*(?:processor|processor id|cpu family|model|stepping|apicid|physical id|core id)\s*:\s*[0-9a-f-]+\s*$")),
    ("cvss_value", re.compile(r"(?i)\bCVSS(?::\d\.\d)?(?:/[A-Z]{1,4}:[A-Z0-9.]+)+\b|\bCVSS\s*v?\d(?:\.\d)?\s*(?:score)?\s*[:=]?\s*\d(?:\.\d)?\b")),
    ("network_port", re.compile(r"(?i)\b(?:port|tcp|udp)\s*[:=]?\s*\d{1,5}\b")),
    ("diagnostic_output", re.compile(r"(?im)^\s*(?:cpu MHz|cache size|bogomips|flags|microcode|address sizes|clflush size|cache_alignment)\s*:\s*[^\r\n]+$")),
)


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

        # Technical values must occupy their spans before the deliberately
        # conservative phone detector runs. This prevents diagnostic output
        # and CTI identifiers from being treated as personal data.
        for value_type, pattern in TECHNICAL_PATTERNS:
            for match in pattern.finditer(text):
                self._append(findings, occupied, PrivacyFinding("possible_cti_indicator", value_type, match.start(), match.end(), 0.95, "preserve"))

        # Calendar and disclosure-timeline values are non-personal numeric
        # spans. Reserve them before phone matching so dates and ranges remain
        # intact even when they contain seven or more digits.
        for value_type, pattern in CALENDAR_PATTERNS:
            for match in pattern.finditer(text):
                self._append(findings, occupied, PrivacyFinding("possible_cti_indicator", value_type, match.start(), match.end(), 0.99, "preserve"))

        for match in EMAIL_RE.finditer(text):
            context = text[max(0, match.start() - 120): min(len(text), match.end() + 120)].lower()
            if any(word in context for word in ("author", "researcher", "reported by", "contact", "security team")):
                finding = PrivacyFinding("public_attribution", "email", match.start(), match.end(), 0.8, "preserve")
            elif any(word in context for word in CTI_EMAIL_CONTEXT):
                finding = PrivacyFinding("possible_cti_indicator", "email", match.start(), match.end(), 0.75, "preserve")
            else:
                finding = PrivacyFinding("unknown", "email", match.start(), match.end(), 0.5, "review")
            self._append(findings, occupied, finding)

        for match in PHONE_RE.finditer(text):
            digits = sum(character.isdigit() for character in match.group(0))
            context = text[max(0, match.start() - 32):match.start()].lower()
            has_phone_context = any(label in context for label in ("phone", "telephone", "tel:", "mobile", "call", "contact number"))
            international = match.group(0).lstrip().startswith("+")
            grouped = bool(re.search(r"\d{2,4}[- ()]\d{2,4}[- ]\d{2,4}", match.group(0)))
            if 7 <= digits <= 15 and (has_phone_context or international or grouped):
                self._append(findings, occupied, PrivacyFinding("possible_personal_data", "phone_number", match.start(), match.end(), 0.95, "redact"))

        for match in HANDLE_RE.finditer(text):
            if self._is_programming_decorator(text, match.start(), match.end()):
                self._append(findings, occupied, PrivacyFinding(
                    "possible_cti_indicator", "programming_decorator", match.start(), match.end(), 0.98, "preserve"
                ))
                continue
            self._append(findings, occupied, PrivacyFinding("unknown", "username", match.start(), match.end(), 0.5, "review"))

        return tuple(sorted(findings, key=lambda item: (item.start, item.end, item.value_type)))

    @staticmethod
    def _is_programming_decorator(text: str, start: int, end: int) -> bool:
        line_start, line_end = text.rfind("\n", 0, start) + 1, text.find("\n", end)
        if line_end < 0: line_end = len(text)
        line = text[line_start:line_end].strip()
        suffix = text[end:line_end]
        dotted = suffix.startswith(".") and bool(re.match(r"\.[A-Za-z_]\w*", suffix))
        decorator_line = line.startswith("@") and bool(re.match(r"@[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+(?:\([^\n]*\))?$", line))
        nearby = text[max(0, line_start - 160):min(len(text), line_end + 160)]
        code_context = bool(re.search(r"(?m)^\s*(?:from\s+\S+\s+import|import\s+\S+|async\s+def\s+|def\s+|class\s+)", nearby))
        return dotted and (decorator_line or code_context)

    @staticmethod
    def _append(findings: list[PrivacyFinding], occupied: list[tuple[int, int]], finding: PrivacyFinding) -> None:
        if any(finding.start < end and finding.end > start for start, end in occupied):
            return
        findings.append(finding)
        occupied.append((finding.start, finding.end))
