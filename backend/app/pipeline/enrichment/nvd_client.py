from __future__ import annotations

from typing import Any

import requests

from backend.app.core.config import get_settings


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None, timeout: int = 20) -> None:
        self.api_key = api_key if api_key is not None else get_settings().nvd_api_key
        self.timeout = timeout

    def fetch_cve(self, cve_id: str) -> dict[str, Any]:
        normalized = cve_id.strip().upper()
        headers = {"User-Agent": "graduation-cti-platform/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        response = requests.get(
            self.BASE_URL,
            params={"cveId": normalized},
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"cve_id": normalized, "found": False, "provider": "NVD"}
        cve = vulnerabilities[0].get("cve", {})
        return self._normalize(cve)

    def _normalize(self, cve: dict[str, Any]) -> dict[str, Any]:
        metrics = cve.get("metrics", {})
        cvss_data: dict[str, Any] = {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                break
        descriptions = cve.get("descriptions", [])
        description = next(
            (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            weaknesses.extend(
                item.get("value") for item in weakness.get("description", []) if item.get("value")
            )
        references = [item.get("url") for item in cve.get("references", []) if item.get("url")]
        return {
            "provider": "NVD",
            "found": True,
            "cve_id": cve.get("id"),
            "description": description,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": cve.get("vulnStatus"),
            "cvss_version": cvss_data.get("version"),
            "cvss_score": cvss_data.get("baseScore"),
            "severity": str(cvss_data.get("baseSeverity") or "").lower() or None,
            "vector": cvss_data.get("vectorString"),
            "cwes": sorted(set(weaknesses)),
            "references": references[:25],
        }
