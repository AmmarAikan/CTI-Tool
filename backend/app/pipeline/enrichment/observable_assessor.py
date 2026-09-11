from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,63})$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)
_ASN_RE = re.compile(r"^AS([1-9]\d{0,9})$", re.IGNORECASE)
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)

_REFERENCE_HOST_SUFFIXES = (
    "attack.mitre.org",
    "cve.org",
    "github.com",
    "gitlab.com",
    "git.kernel.org",
    "help.splunk.com",
    "nvd.nist.gov",
    "osv.dev",
    "plugins.trac.wordpress.org",
    "support.hpe.com",
    "thehackernews.com",
    "vuldb.com",
    "vulncheck.com",
    "wordfence.com",
    "wpscan.com",
    "bugzilla.redhat.com",
    "cna.erlef.org",
    "cvefeed.io",
    "drupal.org",
    "ibm.com",
    "mozilla.org",
)
_RESERVED_DOMAINS = (".example", ".invalid", ".localhost", ".test")
_RESERVED_DOMAIN_NAMES = {"example.com", "example.net", "example.org", "localhost"}


@dataclass(frozen=True)
class ObservableAssessment:
    semantic_role: str
    validation_status: str
    assessment: str
    assessment_confidence: float
    actionable: bool
    evidence_count: int
    evidence_providers: tuple[str, ...]
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence_providers"] = list(self.evidence_providers)
        return value


class ObservableAssessor:
    """Separate syntax extraction from contextual threat assessment.

    A regex match is never promoted to a malicious indicator by itself. Only an
    explicit enrichment verdict can produce ``suspicious`` or ``malicious``.
    """

    HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}

    def assess(self, item: Any, event: Any | None = None) -> ObservableAssessment:
        value_type = str(getattr(item, "indicator_type", getattr(item, "type", ""))).lower()
        value = str(getattr(item, "value", "")).strip()
        enrichments = tuple(getattr(item, "enrichments", ()) or ())
        providers = tuple(sorted({str(getattr(row, "provider", "unknown")) for row in enrichments}))
        verdict = self._explicit_verdict(enrichments)
        if verdict:
            return self._result(
                "indicator", "valid", verdict, 0.9, True, providers, "enrichment_verdict"
            )

        validation = self._validate(value_type, value)
        if validation != "valid":
            return self._result(
                "observable", "invalid", "non_actionable", 1.0, False, providers, validation
            )

        if value_type == "cve":
            return self._result(
                "vulnerability", "valid", "reference", 1.0, False, providers, "vulnerability_id"
            )

        if self._inside_event_url(value_type, value, event):
            return self._result(
                "external_reference", "valid", "reference", 1.0, False, providers, "embedded_in_url"
            )

        if value_type == "url":
            host_kind = self._url_host_kind(value)
            if host_kind == "reference":
                return self._result(
                    "external_reference", "valid", "reference", 0.95, False, providers, "reference_host"
                )
            if host_kind == "non_global":
                return self._result(
                    "observable", "valid", "non_actionable", 1.0, False, providers, "non_global_url_host"
                )

        if value_type == "domain" and self._is_reference_domain(value):
            return self._result(
                "external_reference", "valid", "reference", 0.95, False, providers, "reference_host"
            )

        if value_type in {"ipv4", "ipv6"}:
            parsed = ipaddress.ip_address(value)
            if not parsed.is_global:
                return self._result(
                    "observable", "valid", "non_actionable", 1.0, False, providers, "non_global_ip"
                )

        if value_type == "domain" and (
            value.lower().rstrip(".") in _RESERVED_DOMAIN_NAMES
            or value.lower().endswith(_RESERVED_DOMAINS)
        ):
            return self._result(
                "observable", "valid", "non_actionable", 1.0, False, providers, "reserved_domain"
            )

        if value_type == "mac":
            first_octet = int(value.split(":", 1)[0], 16)
            if first_octet & 2:
                return self._result(
                    "observable", "valid", "non_actionable", 0.95, False, providers, "locally_administered_mac"
                )

        return self._result(
            "observable", "valid", "unknown", 0.0, False, providers, "needs_enrichment"
        )

    def _validate(self, value_type: str, value: str) -> str:
        if not value:
            return "empty_value"
        if value_type == "url":
            try:
                parsed = urlsplit(value)
                return "valid" if parsed.scheme in {"http", "https"} and bool(parsed.hostname) else "invalid_url"
            except ValueError:
                return "invalid_url"
        if value_type == "domain":
            return "valid" if _DOMAIN_RE.fullmatch(value.rstrip(".")) else "invalid_domain"
        if value_type == "email":
            return "valid" if _EMAIL_RE.fullmatch(value) else "invalid_email"
        if value_type == "cve":
            return "valid" if _CVE_RE.fullmatch(value) else "invalid_cve"
        if value_type in self.HASH_LENGTHS:
            expected = self.HASH_LENGTHS[value_type]
            return "valid" if len(value) == expected and _HEX_RE.fullmatch(value) else "invalid_hash"
        if value_type in {"ipv4", "ipv6"}:
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                return "invalid_ip"
            return "valid" if parsed.version == (4 if value_type == "ipv4" else 6) else "invalid_ip_version"
        if value_type == "asn":
            match = _ASN_RE.fullmatch(value)
            return "valid" if match and int(match.group(1)) <= 4_294_967_295 else "invalid_asn"
        if value_type == "mac":
            return "valid" if _MAC_RE.fullmatch(value.replace("-", ":")) else "invalid_mac"
        return "unsupported_type"

    @staticmethod
    def _explicit_verdict(enrichments: Iterable[Any]) -> str | None:
        for row in enrichments:
            if str(getattr(row, "status", "")).lower() not in {"success", "completed"}:
                continue
            data = getattr(row, "data", {}) or {}
            if not isinstance(data, dict):
                continue
            verdict = str(data.get("verdict") or "").lower()
            if verdict in {"malicious", "suspicious"}:
                return verdict
            if data.get("malicious") is True:
                return "malicious"
        return None

    @staticmethod
    def _inside_event_url(value_type: str, value: str, event: Any | None) -> bool:
        if value_type not in {"md5", "sha1", "sha256", "ipv4", "ipv6", "email", "domain"} or event is None:
            return False
        needle = value.casefold()
        for other in getattr(event, "indicators", ()) or ():
            if str(getattr(other, "indicator_type", "")).lower() != "url":
                continue
            if needle in str(getattr(other, "value", "")).casefold():
                return True
        return False

    @staticmethod
    def _is_reference_url(value: str) -> bool:
        try:
            host = (urlsplit(value).hostname or "").lower()
        except ValueError:
            return False
        return ObservableAssessor._is_reference_domain(host)

    @staticmethod
    def _url_host_kind(value: str) -> str:
        try:
            host = (urlsplit(value).hostname or "").lower()
        except ValueError:
            return "unknown"
        if ObservableAssessor._is_reference_domain(host):
            return "reference"
        if host in _RESERVED_DOMAIN_NAMES or host.endswith(_RESERVED_DOMAINS):
            return "non_global"
        try:
            return "unknown" if ipaddress.ip_address(host).is_global else "non_global"
        except ValueError:
            return "unknown"

    @staticmethod
    def _is_reference_domain(value: str) -> bool:
        host = value.lower().rstrip(".")
        return any(host == suffix or host.endswith(f".{suffix}") for suffix in _REFERENCE_HOST_SUFFIXES)

    @staticmethod
    def _result(
        role: str,
        validation: str,
        assessment: str,
        confidence: float,
        actionable: bool,
        providers: tuple[str, ...],
        reason: str,
    ) -> ObservableAssessment:
        return ObservableAssessment(
            semantic_role=role,
            validation_status=validation,
            assessment=assessment,
            assessment_confidence=confidence,
            actionable=actionable,
            evidence_count=len(providers),
            evidence_providers=providers,
            reason_code=reason,
        )
