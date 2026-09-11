from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    confidence: float
    mapping_source: str
    evidence: str
    url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackMappingService:
    """Conservative ATT&CK candidate mapping with evidence on every result."""

    CATALOG_VERSION = "ATT&CK v19.1"
    CATALOG: dict[str, tuple[str, str]] = {
        "T1003": ("OS Credential Dumping", "credential-access"),
        "T1053": ("Scheduled Task/Job", "persistence"),
        "T1059.001": ("PowerShell", "execution"),
        "T1071.001": ("Web Protocols", "command-and-control"),
        "T1110": ("Brute Force", "credential-access"),
        "T1190": ("Exploit Public-Facing Application", "initial-access"),
        "T1486": ("Data Encrypted for Impact", "impact"),
        "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
        "T1566": ("Phishing", "initial-access"),
        "T1566.001": ("Spearphishing Attachment", "initial-access"),
        "T1566.002": ("Spearphishing Link", "initial-access"),
    }
    RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
        ("T1059.001", re.compile(r"\b(?:powershell|pwsh)\b", re.I), "PowerShell mention"),
        ("T1003", re.compile(r"\b(?:credential dumping|mimikatz)\b", re.I), "credential dumping behavior"),
        ("T1566.001", re.compile(r"\b(?:spearphishing attachment|malicious attachment)\b", re.I), "phishing attachment behavior"),
        ("T1566.002", re.compile(r"\b(?:spearphishing link|phishing link)\b", re.I), "phishing link behavior"),
        ("T1566", re.compile(r"\b(?:phishing|spearphishing)\b", re.I), "phishing behavior"),
        ("T1110", re.compile(r"\b(?:brute force|password spray(?:ing)?|credential stuffing)\b", re.I), "credential guessing behavior"),
        ("T1190", re.compile(r"\b(?:exploit(?:ed|ing)? (?:a )?public-facing application|web application exploit)\b", re.I), "public-facing application exploitation"),
        ("T1071.001", re.compile(r"\b(?:command and control|c2)\b.{0,80}\b(?:https?|web)\b|\b(?:https?|web)\b.{0,80}\b(?:command and control|c2)\b", re.I), "web-based command and control"),
        ("T1053", re.compile(r"\b(?:scheduled task|cron job)\b", re.I), "scheduled execution behavior"),
        ("T1547.001", re.compile(r"\b(?:registry run keys?|startup folder)\b", re.I), "registry or startup persistence"),
        ("T1486", re.compile(r"\b(?:encrypt(?:ed|ing) files|data encrypted for impact)\b", re.I), "file encryption impact"),
    )
    EXPLICIT_RE = re.compile(r"(?<![A-Z0-9])T\d{4}(?:\.\d{3})?(?![A-Z0-9])", re.I)

    def map_event(self, event: Any) -> list[dict[str, Any]]:
        text = "\n".join(
            str(part or "")
            for part in (getattr(event, "title", ""), getattr(event, "summary", ""), getattr(event, "normalized_text", ""))
        )
        results: dict[str, AttackTechnique] = {}
        for match in self.EXPLICIT_RE.finditer(text):
            technique_id = match.group(0).upper()
            name, tactic = self.CATALOG.get(technique_id, ("ATT&CK technique", "unknown"))
            results[technique_id] = self._item(technique_id, name, tactic, 0.98, "explicit_id", text, match.start())
        for technique_id, pattern, reason in self.RULES:
            if technique_id in results:
                continue
            match = pattern.search(text)
            if not match:
                continue
            name, tactic = self.CATALOG[technique_id]
            item = self._item(technique_id, name, tactic, 0.65, "rule_based_candidate", text, match.start())
            results[technique_id] = AttackTechnique(**{**asdict(item), "evidence": f"{reason}: {item.evidence}"})
        return [results[key].to_dict() for key in sorted(results)]

    @staticmethod
    def _item(
        technique_id: str, name: str, tactic: str, confidence: float, source: str, text: str, position: int
    ) -> AttackTechnique:
        start = max(0, position - 70)
        end = min(len(text), position + 170)
        evidence = " ".join(text[start:end].split())[:240]
        return AttackTechnique(
            technique_id=technique_id,
            name=name,
            tactic=tactic,
            confidence=confidence,
            mapping_source=source,
            evidence=evidence,
            url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        )
