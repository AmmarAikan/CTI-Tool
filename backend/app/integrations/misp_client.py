from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, ClassVar

import requests

from backend.app.core.config import get_settings


class MISPClient:
    NAMESPACE: ClassVar[uuid.UUID] = uuid.UUID("ef1932f8-50d6-4d34-b4d7-d4e2965706ac")
    ATTRIBUTE_TYPES: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "ipv4": ("ip-src", "Network activity", True),
        "ipv6": ("ip-src", "Network activity", True),
        "domain": ("domain", "Network activity", True),
        "url": ("url", "Network activity", True),
        "email": ("email-src", "Network activity", True),
        "md5": ("md5", "Payload delivery", True),
        "sha1": ("sha1", "Payload delivery", True),
        "sha256": ("sha256", "Payload delivery", True),
        "cve": ("vulnerability", "External analysis", False),
    }

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        verify_tls: bool | None = None,
        timeout: int | None = None,
        session: requests.Session | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.misp_url or "").rstrip("/")
        self.api_key = api_key or settings.misp_api_key
        self.verify_tls = settings.misp_verify_tls if verify_tls is None else verify_tls
        self.timeout = timeout or settings.misp_timeout_seconds
        self.session = session or requests.Session()

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def event_payload(self, event) -> dict[str, Any]:
        attributes = []
        for indicator in event.indicators:
            mapping = self.ATTRIBUTE_TYPES.get(indicator.indicator_type)
            if not mapping:
                continue
            misp_type, category, to_ids = mapping
            attribute = {
                "uuid": str(
                    uuid.uuid5(
                        self.NAMESPACE,
                        f"attribute:{event.id}:{indicator.indicator_type}:{indicator.value.lower()}",
                    )
                ),
                "type": misp_type,
                "category": category,
                "value": indicator.value,
                "to_ids": to_ids,
                "comment": f"Extracted by {indicator.extractor}; confidence={indicator.confidence:.2f}",
            }
            first_seen = self._iso(getattr(indicator, "first_seen", None))
            last_seen = self._iso(getattr(indicator, "last_seen", None))
            if first_seen:
                attribute["first_seen"] = first_seen
            if last_seen:
                attribute["last_seen"] = last_seen
            attributes.append(attribute)
        event_uuid = str(uuid.uuid5(self.NAMESPACE, f"event:{event.id}"))
        first_seen = getattr(event, "first_seen", None)
        misp_event = {
            "uuid": event_uuid,
            "info": event.title[:255],
            "distribution": 0,
            "threat_level_id": self._threat_level(event.severity),
            "analysis": 1,
            "published": False,
            "Attribute": attributes,
            "Tag": [{"name": name} for name in self._event_tags(event)],
        }
        if isinstance(first_seen, datetime):
            misp_event["date"] = first_seen.date().isoformat()
        return {"Event": misp_event}

    def send_event(self, event, dry_run: bool = True) -> dict[str, Any]:
        payload = self.event_payload(event)
        if dry_run:
            return {"dry_run": True, "configured": self.configured, "payload": payload}
        if not self.configured:
            raise RuntimeError("MISP_URL and MISP_API_KEY must be configured before sending events")
        response = self.session.post(
            f"{self.base_url}/events/add",
            json=payload,
            headers=self._headers(),
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def healthcheck(self) -> dict[str, Any]:
        if not self.configured:
            return {"configured": False, "reachable": False}
        try:
            response = self.session.get(
                f"{self.base_url}/servers/getVersion",
                headers=self._headers(),
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return {"configured": True, "reachable": True, "version": response.json()}
        except (requests.RequestException, ValueError, TypeError) as exc:
            return {
                "configured": True,
                "reachable": False,
                "error_type": type(exc).__name__,
            }

    def _headers(self) -> dict[str, str]:
        return {"Authorization": str(self.api_key), "Accept": "application/json", "Content-Type": "application/json"}

    def _threat_level(self, severity: str | None) -> int:
        return {"critical": 1, "high": 1, "medium": 2, "low": 3}.get(
            (severity or "").lower(),
            4,
        )

    @staticmethod
    def _iso(value: object) -> str | None:
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value) if value else None

    @staticmethod
    def _event_tags(event) -> list[str]:
        tags = [f"cti-platform:{tag}" for tag in event.tags[:20]]
        tags.extend(
            [
                f"cti-platform:source-pipeline={event.source_pipeline}",
                f"cti-platform:severity={event.severity or 'unknown'}",
            ]
        )
        return sorted(set(tags))
