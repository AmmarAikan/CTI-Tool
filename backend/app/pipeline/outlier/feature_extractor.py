from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from backend.app.pipeline.extraction.ioc_extractor import IoCExtractor
from backend.app.pipeline.ingestion.internal.wazuh_connector import nested_value
from backend.app.pipeline.outlier.sessionizer import InternalSession

NUMERIC_FEATURES = (
    "alerts_count",
    "duration_minutes",
    "max_rule_level",
    "avg_rule_level",
    "distinct_rules",
    "unique_destinations",
    "unique_urls",
    "unique_ports",
    "cve_count",
    "ip_count",
    "domain_count",
    "failed_actions",
    "credential_attempts",
    "http_get_count",
    "http_post_count",
)


class SessionFeatureExtractor:
    def __init__(self, ioc_extractor: IoCExtractor | None = None) -> None:
        self.ioc_extractor = ioc_extractor or IoCExtractor()

    def extract(self, session: InternalSession) -> dict[str, float]:
        levels: list[float] = []
        rules: set[str] = set()
        destinations: set[str] = set()
        urls: set[str] = set()
        ports: set[str] = set()
        text_parts: list[str] = []
        http_get = 0
        http_post = 0
        failed_actions = 0
        credential_attempts = 0

        for record in session.records:
            raw = record.raw_data
            level = nested_value(raw, "rule.level", "level")
            try:
                levels.append(float(level or 0))
            except (TypeError, ValueError):
                levels.append(0.0)
            rule_id = nested_value(raw, "rule.id", "rule.groups", "decoder.name", "connection.protocol")
            if rule_id:
                rules.add(str(rule_id))
            destination = nested_value(raw, "data.dstip", "data.dst_ip", "destination.ip", "dstip", "dst_ip")
            if destination:
                destinations.add(str(destination))
            port = nested_value(raw, "data.dstport", "data.dst_port", "destination.port", "dstport", "dst_port")
            if port:
                ports.add(str(port))
            url = nested_value(raw, "data.url", "data.http.url", "url.original")
            if url:
                urls.add(str(url))
            content = f"{record.title} {record.content}"
            text_parts.append(content)
            http_get += len(re.findall(r"\bGET\b", content, flags=re.IGNORECASE))
            http_post += len(re.findall(r"\bPOST\b", content, flags=re.IGNORECASE))
            failed_actions += len(re.findall(r"\b(?:fail(?:ed|ure)?|denied|invalid)\b", content, flags=re.IGNORECASE))
            credentials = nested_value(raw, "credentials")
            if isinstance(credentials, list):
                credential_count = len(credentials)
            elif isinstance(credentials, dict):
                list_lengths = [len(item) for item in credentials.values() if isinstance(item, list)]
                credential_count = max(list_lengths, default=1 if credentials else 0)
            else:
                credential_count = 0
            credential_attempts += credential_count
            failed_actions += credential_count

        indicators = self.ioc_extractor.extract("\n".join(text_parts))
        values = {kind: set() for kind in ("cve", "ipv4", "domain")}
        for indicator in indicators:
            if indicator.type in values:
                values[indicator.type].add(indicator.value.lower())
            elif indicator.type == "url":
                hostname = urlparse(indicator.value).hostname
                if hostname:
                    values["domain"].add(hostname.lower())
        duration = max(0.0, (session.ended_at - session.started_at).total_seconds() / 60.0)
        return {
            "alerts_count": float(len(session.records)),
            "duration_minutes": round(duration, 4),
            "max_rule_level": max(levels, default=0.0),
            "avg_rule_level": round(sum(levels) / len(levels), 4) if levels else 0.0,
            "distinct_rules": float(len(rules)),
            "unique_destinations": float(len(destinations)),
            "unique_urls": float(len(urls)),
            "unique_ports": float(len(ports)),
            "cve_count": float(len(values["cve"])),
            "ip_count": float(len(values["ipv4"])),
            "domain_count": float(len(values["domain"])),
            "failed_actions": float(failed_actions),
            "credential_attempts": float(credential_attempts),
            "http_get_count": float(http_get),
            "http_post_count": float(http_post),
        }

    @staticmethod
    def vector(features: dict[str, Any]) -> list[float]:
        return [float(features.get(name, 0.0)) for name in NUMERIC_FEATURES]
