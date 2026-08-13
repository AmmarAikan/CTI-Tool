from __future__ import annotations

from typing import Any, ClassVar

import requests

from backend.app.core.config import get_settings


class MISPClient:
    ATTRIBUTE_TYPES: ClassVar[dict[str, str]] = {
        "ipv4": "ip-src",
        "ipv6": "ip-src",
        "domain": "domain",
        "url": "url",
        "email": "email-src",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "cve": "vulnerability",
    }

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        verify_tls: bool | None = None,
        timeout: int | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.misp_url or "").rstrip("/")
        self.api_key = api_key or settings.misp_api_key
        self.verify_tls = settings.misp_verify_tls if verify_tls is None else verify_tls
        self.timeout = timeout or settings.misp_timeout_seconds

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def event_payload(self, event) -> dict[str, Any]:
        attributes = []
        for indicator in event.indicators:
            misp_type = self.ATTRIBUTE_TYPES.get(indicator.indicator_type)
            if not misp_type:
                continue
            attributes.append(
                {
                    "type": misp_type,
                    "category": "External analysis" if misp_type == "vulnerability" else "Network activity",
                    "value": indicator.value,
                    "to_ids": misp_type != "vulnerability",
                    "comment": f"Extracted by {indicator.extractor}; confidence={indicator.confidence:.2f}",
                }
            )
        return {
            "Event": {
                "info": event.title[:255],
                "distribution": "0",
                "threat_level_id": self._threat_level(event.severity),
                "analysis": "1",
                "published": False,
                "Attribute": attributes,
                "Tag": [{"name": f"cti-platform:{tag}"} for tag in event.tags[:20]],
            }
        }

    def send_event(self, event, dry_run: bool = True) -> dict[str, Any]:
        payload = self.event_payload(event)
        if dry_run:
            return {"dry_run": True, "configured": self.configured, "payload": payload}
        if not self.configured:
            raise RuntimeError("MISP_URL and MISP_API_KEY must be configured before sending events")
        response = requests.post(
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
            response = requests.get(
                f"{self.base_url}/servers/getVersion",
                headers=self._headers(),
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return {"configured": True, "reachable": True, "version": response.json()}
        except requests.RequestException as exc:
            return {"configured": True, "reachable": False, "error": str(exc)}

    def _headers(self) -> dict[str, str]:
        return {"Authorization": str(self.api_key), "Accept": "application/json", "Content-Type": "application/json"}

    def _threat_level(self, severity: str | None) -> str:
        return {"critical": "1", "high": "1", "medium": "2", "low": "3"}.get((severity or "").lower(), "4")
