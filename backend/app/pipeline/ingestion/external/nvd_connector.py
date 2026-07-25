from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from backend.app.pipeline.common.cti_schema import RawRecord, utc_now_iso
from backend.app.pipeline.ingestion.base_connector import ExternalConnector


class NVDRecordConnector(ExternalConnector):
    """Normalize already-fetched NVD API records without reclassifying the trusted source."""

    source_name = "NVD"

    def __init__(self, vulnerabilities: Sequence[dict[str, Any]]) -> None:
        self.vulnerabilities = vulnerabilities

    def collect(self) -> Iterable[RawRecord]:
        for item in self.vulnerabilities:
            cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
            cve_id = str(cve.get("id") or cve.get("cve_id") or item.get("id") or "unknown-cve")
            descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
            description = self._english_description(descriptions) or str(cve.get("description") or cve_id)
            published = str(cve.get("published") or cve.get("published_at") or "") or None
            yield RawRecord(
                external_id=cve_id,
                source_name=self.source_name,
                source_type="nvd",
                title=cve_id,
                content=description,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != "unknown-cve" else None,
                published_at=published,
                collected_at=utc_now_iso(),
                raw_data=item,
                trusted_cybersecurity_source=True,
            )

    def _english_description(self, descriptions: list[dict[str, Any]]) -> str | None:
        for description in descriptions:
            if str(description.get("lang", "")).lower() == "en" and description.get("value"):
                return str(description["value"])
        return None
