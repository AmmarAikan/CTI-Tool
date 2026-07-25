from __future__ import annotations

import ipaddress
import re

from backend.app.pipeline.common.cti_schema import Indicator


URL_RE = re.compile(r"\bhttps?://[^\s<>'\")]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
COMMON_TLDS = {
    "ai",
    "at",
    "au",
    "biz",
    "br",
    "ca",
    "ch",
    "cn",
    "co",
    "com",
    "de",
    "edu",
    "es",
    "eu",
    "fi",
    "fr",
    "gov",
    "in",
    "info",
    "io",
    "ir",
    "it",
    "jp",
    "me",
    "mil",
    "net",
    "nl",
    "no",
    "org",
    "pl",
    "ru",
    "se",
    "tr",
    "tv",
    "ua",
    "uk",
    "us",
    "xyz",
}


class IoCExtractor:
    """Regex-based observed indicator extractor."""

    def extract(self, text: str) -> list[Indicator]:
        indicators: list[Indicator] = []
        indicators.extend(self._matches(URL_RE, text, "url"))
        indicators.extend(self._matches(EMAIL_RE, text, "email"))
        indicators.extend(self._matches(CVE_RE, text, "cve"))
        indicators.extend(self._hashes(text))
        indicators.extend(self._ips(text))
        indicators.extend(self._domains(text))
        return self._deduplicate(indicators)

    def _matches(self, regex: re.Pattern[str], text: str, indicator_type: str) -> list[Indicator]:
        return [
            Indicator(
                value=match.group(0).rstrip(".,;:"),
                type=indicator_type,
                confidence=1.0,
                extractor="regex",
            )
            for match in regex.finditer(text)
        ]

    def _hashes(self, text: str) -> list[Indicator]:
        indicators = []
        for match in HASH_RE.finditer(text):
            value = match.group(0)
            hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
            indicators.append(Indicator(value=value, type=hash_type, confidence=1.0, extractor="regex"))
        return indicators

    def _ips(self, text: str) -> list[Indicator]:
        indicators = []
        for match in IPV4_RE.finditer(text):
            value = match.group(0)
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            indicators.append(Indicator(value=value, type="ipv4", confidence=1.0, extractor="regex"))
        return indicators

    def _domains(self, text: str) -> list[Indicator]:
        url_domains = {self._domain_from_url(indicator.value) for indicator in self._matches(URL_RE, text, "url")}
        values = []
        for match in DOMAIN_RE.finditer(text):
            value = match.group(0).lower().rstrip(".,;:")
            if value.rsplit(".", 1)[-1] not in COMMON_TLDS:
                continue
            if value in url_domains:
                continue
            values.append(Indicator(value=value, type="domain", confidence=1.0, extractor="regex"))
        return values

    def _domain_from_url(self, value: str) -> str:
        without_scheme = value.split("://", 1)[-1]
        return without_scheme.split("/", 1)[0].split(":", 1)[0].lower()

    def _deduplicate(self, indicators: list[Indicator]) -> list[Indicator]:
        seen = set()
        unique = []
        for indicator in indicators:
            key = (indicator.type, indicator.value.lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append(indicator)
        return unique
