from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import urlparse

import requests

from backend.app.core.config import get_settings


class MISPClient:
    INTERNAL_HTTP_HOSTS: ClassVar[frozenset[str]] = frozenset(
        {"cti-misp", "localhost", "127.0.0.1", "::1"}
    )
    NAMESPACE: ClassVar[uuid.UUID] = uuid.UUID("ef1932f8-50d6-4d34-b4d7-d4e2965706ac")
    ATTRIBUTE_TYPES: ClassVar[dict[str, tuple[str, str, bool]]] = {
        # Extraction proves observation, not maliciousness. Analysts or an
        # enrichment rule must opt in to IDS use after contextual validation.
        "ipv4": ("ip-src", "Network activity", False),
        "ipv6": ("ip-src", "Network activity", False),
        "domain": ("domain", "Network activity", False),
        "url": ("url", "Network activity", False),
        "email": ("email-src", "Network activity", False),
        "md5": ("md5", "Payload delivery", False),
        "sha1": ("sha1", "Payload delivery", False),
        "sha256": ("sha256", "Payload delivery", False),
        "asn": ("AS", "Network activity", False),
        "mac": ("mac-address", "Network activity", False),
        "cve": ("vulnerability", "External analysis", False),
    }

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        verify_tls: bool | None = None,
        allow_http: bool | None = None,
        timeout: int | None = None,
        session: requests.Session | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.misp_url or "").rstrip("/")
        self.api_key = api_key or settings.misp_api_key
        self.verify_tls = settings.misp_verify_tls if verify_tls is None else verify_tls
        self.allow_http = settings.misp_allow_http if allow_http is None else allow_http
        self.timeout = timeout or settings.misp_timeout_seconds
        self.session = session or requests.Session()
        self._validate_url()

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
                "comment": (
                    f"Observed by {indicator.extractor}; "
                    f"extraction-confidence={indicator.confidence:.2f}; "
                    "maliciousness-not-asserted"
                ),
            }
            first_seen, last_seen = self._time_bounds(
                getattr(indicator, "first_seen", None),
                getattr(indicator, "last_seen", None),
            )
            if first_seen:
                attribute["first_seen"] = first_seen
            if last_seen:
                attribute["last_seen"] = last_seen
            attributes.append(attribute)
        event_uuid = str(uuid.uuid5(self.NAMESPACE, f"event:{event.id}"))
        first_seen, _ = self._time_bounds(
            getattr(event, "first_seen", None),
            getattr(event, "last_seen", None),
        )
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
        if first_seen:
            try:
                misp_event["date"] = datetime.fromisoformat(first_seen.replace("Z", "+00:00")).date().isoformat()
            except ValueError:
                pass
        return {"Event": misp_event}

    def send_event(self, event, dry_run: bool = True) -> dict[str, Any]:
        payload = self.event_payload(event)
        if dry_run:
            return {"dry_run": True, "configured": self.configured, "payload": payload}
        if not self.configured:
            raise RuntimeError("MISP_URL and MISP_API_KEY must be configured before sending events")

        expected_attributes = list(payload["Event"].get("Attribute", []))
        event_uuid = str(payload["Event"]["uuid"])
        misp_event = self._find_event(event_uuid)
        created = misp_event is None
        if misp_event is None:
            event_only = dict(payload["Event"])
            event_only.pop("Attribute", None)
            response = self.session.post(
                f"{self.base_url}/events/add",
                json={"Event": event_only},
                headers=self._headers(),
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            response.raise_for_status()
            misp_event = self._extract_event(response.json())

        event_id = str(misp_event.get("id") or "")
        if not event_id:
            raise RuntimeError("MISP accepted the request but returned no event id")

        existing_keys = {
            self._attribute_key(attribute)
            for attribute in misp_event.get("Attribute", [])
            if self._attribute_key(attribute) is not None
        }
        pending = [
            attribute
            for attribute in expected_attributes
            if self._attribute_key(attribute) not in existing_keys
        ]
        for attribute in pending:
            response = self.session.post(
                f"{self.base_url}/attributes/add/{event_id}",
                json={"Attribute": attribute},
                headers=self._headers(),
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            response.raise_for_status()

        response = self.session.get(
            f"{self.base_url}/events/view/{event_id}",
            headers=self._headers(),
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        response.raise_for_status()
        stored_event = self._extract_event(response.json())
        stored_keys = {
            self._attribute_key(attribute)
            for attribute in stored_event.get("Attribute", [])
            if self._attribute_key(attribute) is not None
        }
        expected_keys = {
            self._attribute_key(attribute)
            for attribute in expected_attributes
            if self._attribute_key(attribute) is not None
        }
        missing = sorted(expected_keys - stored_keys)
        if missing:
            raise RuntimeError(
                "MISP event was created but indicator verification failed "
                f"({len(missing)} missing of {len(expected_keys)})"
            )

        return {
            "Event": stored_event,
            "cti_delivery": {
                "created": created,
                "event_id": event_id,
                "event_uuid": event_uuid,
                "attributes_requested": len(expected_attributes),
                "attributes_added": len(pending),
                "attributes_verified": len(expected_keys),
                "published": bool(stored_event.get("published", False)),
            },
        }

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

    def _validate_url(self) -> None:
        if not self.base_url:
            return
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MISP_URL must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("MISP_URL must not contain credentials, a query, or a fragment")
        if parsed.scheme == "http":
            if not self.allow_http:
                raise ValueError("MISP_URL must use HTTPS unless MISP_ALLOW_HTTP=true")
            if parsed.hostname.lower() not in self.INTERNAL_HTTP_HOSTS:
                raise ValueError("MISP HTTP is limited to the isolated cti-misp or loopback endpoint")

    def _find_event(self, event_uuid: str) -> dict[str, Any] | None:
        response = self.session.post(
            f"{self.base_url}/events/restSearch",
            json={"returnFormat": "json", "uuid": event_uuid},
            headers=self._headers(),
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        response.raise_for_status()
        body = response.json()
        candidates = body.get("response", []) if isinstance(body, dict) else []
        for candidate in candidates:
            misp_event = candidate.get("Event", candidate) if isinstance(candidate, dict) else None
            if isinstance(misp_event, dict) and str(misp_event.get("uuid")) == event_uuid:
                return misp_event
        return None

    @staticmethod
    def _attribute_key(attribute: dict[str, Any]) -> tuple[str, str] | None:
        attribute_type = str(attribute.get("type") or "").strip().lower()
        value = str(attribute.get("value") or attribute.get("value1") or "").strip().lower()
        if not attribute_type or not value:
            return None
        return attribute_type, value

    @staticmethod
    def _extract_event(body: object) -> dict[str, Any]:
        if isinstance(body, dict) and isinstance(body.get("Event"), dict):
            return body["Event"]
        if isinstance(body, dict) and isinstance(body.get("response"), list):
            for candidate in body["response"]:
                if isinstance(candidate, dict) and isinstance(candidate.get("Event"), dict):
                    return candidate["Event"]
        raise RuntimeError("MISP returned an unexpected event response")

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

    @classmethod
    def _time_bounds(cls, first_seen: object, last_seen: object) -> tuple[str | None, str | None]:
        first = cls._iso(first_seen)
        last = cls._iso(last_seen)
        if not first or not last:
            return first, last
        try:
            parsed_first = datetime.fromisoformat(first.replace("Z", "+00:00"))
            parsed_last = datetime.fromisoformat(last.replace("Z", "+00:00"))
        except ValueError:
            return first, last
        if parsed_first > parsed_last:
            return last, first
        return first, last

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
