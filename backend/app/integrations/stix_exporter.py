from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import ClassVar


def stix_id(object_type: str, _value: str = "") -> str:
    # STIX Domain Objects use UUIDv4 identifiers. The source event ID is kept in
    # the report content; it must not be converted into a non-conformant UUIDv5.
    return f"{object_type}--{uuid.uuid4()}"


def stix_timestamp(value=None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class STIXExporter:
    PATTERN_TYPES: ClassVar[dict[str, str]] = {
        "ipv4": "ipv4-addr:value",
        "ipv6": "ipv6-addr:value",
        "domain": "domain-name:value",
        "url": "url:value",
        "email": "email-addr:value",
        "md5": "file:hashes.'MD5'",
        "sha1": "file:hashes.'SHA-1'",
        "sha256": "file:hashes.'SHA-256'",
    }

    def export_event(self, event) -> dict:
        now = stix_timestamp()
        identity_id = stix_id("identity", "AI-Based CTI Platform")
        objects = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": "AI-Based CTI Platform",
                "identity_class": "system",
            }
        ]
        refs = []
        for indicator in event.indicators:
            if indicator.indicator_type == "cve":
                object_id = stix_id("vulnerability", indicator.value.upper())
                objects.append(
                    {
                        "type": "vulnerability",
                        "spec_version": "2.1",
                        "id": object_id,
                        "created": now,
                        "modified": now,
                        "name": indicator.value.upper(),
                        "created_by_ref": identity_id,
                    }
                )
                refs.append(object_id)
                continue
            pattern_path = self.PATTERN_TYPES.get(indicator.indicator_type)
            if not pattern_path:
                continue
            escaped = indicator.value.replace("\\", "\\\\").replace("'", "\\'")
            object_id = stix_id("indicator", f"{indicator.indicator_type}:{indicator.value}")
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": object_id,
                    "created": now,
                    "modified": now,
                    "created_by_ref": identity_id,
                    "name": f"{indicator.indicator_type}: {indicator.value}",
                    "pattern": f"[{pattern_path} = '{escaped}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                    "valid_from": stix_timestamp(event.first_seen),
                    "confidence": round(indicator.confidence * 100),
                }
            )
            refs.append(object_id)
        report_id = stix_id("report", event.id)
        objects.append(
            {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": event.title,
                "description": event.description[:5000],
                "published": stix_timestamp(event.first_seen or event.created_at),
                "report_types": ["threat-report"],
                "labels": event.tags,
                "confidence": round(event.confidence * 100),
                "object_refs": refs or [identity_id],
            }
        )
        return {
            "type": "bundle",
            "id": stix_id("bundle", event.id),
            "objects": objects,
        }
