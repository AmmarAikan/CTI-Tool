from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import ClassVar


def stix_id(object_type: str, _value: str = "") -> str:
    # STIX Domain Objects use UUIDv4 identifiers. The source event ID is kept in
    # the report content; it must not be converted into a non-conformant UUIDv5.
    return f"{object_type}--{uuid.uuid4()}"


STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def stix_sco_id(object_type: str, contributing_properties: dict) -> str:
    """Create the deterministic UUIDv5 identifier recommended for STIX SCOs."""
    canonical = json.dumps(
        contributing_properties,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"{object_type}--{uuid.uuid5(STIX_SCO_NAMESPACE, canonical)}"


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
    SIMPLE_OBSERVABLE_TYPES: ClassVar[dict[str, str]] = {
        "ipv4": "ipv4-addr",
        "ipv6": "ipv6-addr",
        "domain": "domain-name",
        "url": "url",
        "email": "email-addr",
        "mac": "mac-addr",
    }
    HASH_NAMES: ClassVar[dict[str, str]] = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
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
            observable = self._observable(indicator)
            if observable is None:
                continue
            objects.append(observable)
            object_id = observable["id"]
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

    def _observable(self, indicator) -> dict | None:
        """Map an extracted value to a STIX SCO without asserting maliciousness."""
        observable_type = self.SIMPLE_OBSERVABLE_TYPES.get(indicator.indicator_type)
        if observable_type:
            contributing_properties = {"value": indicator.value}
            return {
                "type": observable_type,
                "spec_version": "2.1",
                "id": stix_sco_id(observable_type, contributing_properties),
                "value": indicator.value,
            }
        hash_name = self.HASH_NAMES.get(indicator.indicator_type)
        if hash_name:
            contributing_properties = {"hashes": {hash_name: indicator.value}}
            return {
                "type": "file",
                "spec_version": "2.1",
                "id": stix_sco_id("file", contributing_properties),
                **contributing_properties,
            }
        if indicator.indicator_type == "asn":
            try:
                number = int(str(indicator.value).upper().removeprefix("AS"))
            except ValueError:
                return None
            contributing_properties = {"number": number}
            return {
                "type": "autonomous-system",
                "spec_version": "2.1",
                "id": stix_sco_id("autonomous-system", contributing_properties),
                **contributing_properties,
            }
        return None
