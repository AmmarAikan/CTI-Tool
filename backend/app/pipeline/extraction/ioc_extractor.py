from __future__ import annotations

import ipaddress
import re

from backend.app.pipeline.common.cti_schema import Indicator


URL_RE = re.compile(r"\bhttps?://[^\s<>'\")]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
ASN_RE = re.compile(r"\bAS([1-9]\d{0,9})\b", re.IGNORECASE)
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
DEFANGED_SCHEME_RE = re.compile(r"\bhxxps?(?=://)", re.IGNORECASE)
DEFANGED_DOT_RE = re.compile(
    r"\s*(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\))\s*",
    re.IGNORECASE,
)
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
    """Extract syntactically validated technical observables from CTI text.

    The legacy pipeline schema calls these values ``Indicator`` for backwards
    compatibility. A match proves only that an observable was present in the
    source text; it does not establish maliciousness.
    """

    def extract(self, text: str) -> list[Indicator]:
        prepared_text = self._refang(text)
        indicators: list[Indicator] = []
        indicators.extend(self._matches(URL_RE, prepared_text, "url"))
        indicators.extend(self._matches(EMAIL_RE, prepared_text, "email"))
        indicators.extend(self._matches(CVE_RE, prepared_text, "cve"))
        indicators.extend(self._hashes(prepared_text))
        indicators.extend(self._ipv4s(prepared_text))
        indicators.extend(self._ipv6s(prepared_text))
        indicators.extend(self._asns(prepared_text))
        indicators.extend(self._macs(prepared_text))
        indicators.extend(self._domains(prepared_text))
        return self._deduplicate(indicators)

    @staticmethod
    def _refang(text: str) -> str:
        """Canonicalize common defensive notation in an extraction-only copy."""
        prepared = DEFANGED_SCHEME_RE.sub(
            lambda match: "https" if match.group(0).lower() == "hxxps" else "http",
            text,
        )
        return DEFANGED_DOT_RE.sub(".", prepared)

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

    def _ipv4s(self, text: str) -> list[Indicator]:
        indicators = []
        for match in IPV4_RE.finditer(text):
            value = match.group(0)
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                continue
            if parsed.version != 4:
                continue
            indicators.append(
                Indicator(value=str(parsed), type="ipv4", confidence=1.0, extractor="validated_regex")
            )
        return indicators

    def _ipv6s(self, text: str) -> list[Indicator]:
        indicators = []
        for match in IPV6_CANDIDATE_RE.finditer(text):
            value = match.group(0)
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                continue
            if parsed.version != 6:
                continue
            indicators.append(
                Indicator(value=parsed.compressed, type="ipv6", confidence=1.0, extractor="validated_regex")
            )
        return indicators

    def _asns(self, text: str) -> list[Indicator]:
        indicators = []
        for match in ASN_RE.finditer(text):
            number = int(match.group(1))
            if number > 4_294_967_295:
                continue
            indicators.append(
                Indicator(value=f"AS{number}", type="asn", confidence=1.0, extractor="validated_regex")
            )
        return indicators

    def _macs(self, text: str) -> list[Indicator]:
        return [
            Indicator(
                value=match.group(0).replace("-", ":").lower(),
                type="mac",
                confidence=1.0,
                extractor="validated_regex",
            )
            for match in MAC_RE.finditer(text)
        ]

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
