from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urljoin

from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.manual_source.json_ingestion import JSONIngestionError, decode_json
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor


@dataclass(frozen=True, slots=True)
class CSAFSource:
    source_id: str
    name: str
    catalog_url: str
    document_base_url: str
    catalog_path_prefix: str = "csaf_files/"
    max_advisories: int = 50


@dataclass(frozen=True, slots=True)
class CSAFError:
    source_id: str
    category: str
    retryable: bool = False


@dataclass(slots=True)
class CSAFResult:
    source_id: str
    status: str = "completed"
    accepted_items: list[ExternalCTIItem] = field(default_factory=list)
    review_items: list[ExternalCTIItem] = field(default_factory=list)
    errors: list[CSAFError] = field(default_factory=list)
    skipped_items: int = 0


class CSAFConnector:
    """Bounded adapter for an operator-approved CISA CSAF catalog and documents."""

    def __init__(self, source: CSAFSource, *, catalog_client: Any, document_client: Any,
                 content_processor: ExternalContentProcessor, state: dict[str, Any] | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        if not 1 <= source.max_advisories <= 100:
            raise ValueError("invalid CSAF advisory bound")
        self.source, self.catalog_client, self.document_client = source, catalog_client, document_client
        self.content_processor = content_processor
        self.state = state if state is not None else {}
        self.state.setdefault("sources", {}); self.state.setdefault("items", {})
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def collect_result(self) -> CSAFResult:
        result = CSAFResult(self.source.source_id)
        try:
            response = self.catalog_client.get(self.source.catalog_url, headers={"Accept": "application/json"})
            catalog = decode_json(response.body, response.headers, max_bytes=self.catalog_client.settings.max_response_bytes)
            paths = self._catalog_paths(catalog)[:self.source.max_advisories]
            if not paths:
                raise ValueError("empty CSAF catalog")
        except Exception:
            return CSAFResult(self.source.source_id, "failed", errors=[CSAFError(self.source.source_id, "csaf_catalog_failed", True)])
        for path in paths:
            stage = "retrieval"
            try:
                response = self.document_client.get(urljoin(self.source.document_base_url, path), headers={"Accept": "application/json"})
                stage = "decoding"
                value = self._decode_document(response.body, response.headers)
                stage = "mapping"
                item = self._item(value)
                stage = "hashing"
                stable = item.to_dict(); stable.pop("collected_at", None)
                record_hash = sha256_json(stable)
                item_state = self.state["items"].setdefault(item.record_id, {})
                if item_state.get("record_hash") == record_hash:
                    result.skipped_items += 1; continue
                item_state.update({"record_hash": record_hash, "last_checked": item.collected_at})
                if item.metadata.get("privacy", {}).get("status") == "review_required": result.review_items.append(item)
                else: result.accepted_items.append(item)
            except JSONIngestionError as exc:
                category = "csaf_document_media_type" if exc.category == "unsupported_content_type" else "csaf_document_invalid"
                result.errors.append(CSAFError(self.source.source_id, category))
            except Exception:
                category = {"retrieval": "csaf_document_request_failed", "mapping": "csaf_mapping_invalid",
                            "hashing": "csaf_record_invalid"}.get(stage, "csaf_advisory_invalid")
                result.errors.append(CSAFError(self.source.source_id, category, stage == "retrieval"))
        if result.errors: result.status = "partial" if result.accepted_items or result.review_items else "failed"
        self.state["sources"].setdefault(self.source.source_id, {})["collection_method"] = "official_csaf"
        return result

    def _decode_document(self, body: bytes, headers: dict[str, str]) -> Any:
        """Decode approved raw-host `.json` files without relaxing generic JSON ingestion."""
        content_type = headers.get("Content-Type") or headers.get("content-type") or ""
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type == "text/plain":
            headers = {**headers, "Content-Type": "application/json"}
        return decode_json(body, headers, max_bytes=self.document_client.settings.max_response_bytes)

    def _catalog_paths(self, value: Any) -> list[str]:
        if isinstance(value, dict) and value.get("truncated") is True:
            raise ValueError("truncated CSAF catalog")
        entries = value.get("tree") if isinstance(value, dict) else value
        if not isinstance(entries, list) or len(entries) > 20_000:
            raise ValueError("invalid CSAF catalog")
        paths = []
        for entry in entries:
            path = entry.get("path") if isinstance(entry, dict) else entry
            if (isinstance(path, str) and path.startswith(self.source.catalog_path_prefix)
                    and path.endswith(".json") and ".." not in path and len(path) <= 300):
                paths.append(path)
        return sorted(set(paths), reverse=True)

    def _item(self, value: Any) -> ExternalCTIItem:
        if not isinstance(value, dict) or not isinstance(value.get("document"), dict):
            raise ValueError("invalid CSAF document")
        document = value["document"]
        if document.get("csaf_version") != "2.0" or document.get("category") != "csaf_security_advisory":
            raise ValueError("invalid CSAF identity")
        tracking = document.get("tracking")
        if not isinstance(tracking, dict): raise ValueError("invalid CSAF tracking")
        advisory_id = str(tracking.get("id") or "").strip()
        title = str(document.get("title") or "").strip()
        if not advisory_id or not title: raise ValueError("missing CSAF identity")
        notes = document.get("notes") if isinstance(document.get("notes"), list) else []
        summary_parts = [str(note.get("text") or "").strip() for note in notes
                         if isinstance(note, dict) and note.get("category") == "summary"]
        content_parts = [str(note.get("text") or "").strip() for note in notes
                         if isinstance(note, dict) and note.get("category") in {"summary", "details", "general"}]
        processing = self.content_processor.process("\n\n".join(part for part in content_parts if part))
        vulnerabilities = value.get("vulnerabilities") if isinstance(value.get("vulnerabilities"), list) else []
        cves = sorted({str(entry.get("cve")) for entry in vulnerabilities if isinstance(entry, dict) and entry.get("cve")})[:100]
        remediations = sum((entry.get("remediations", []) for entry in vulnerabilities if isinstance(entry, dict)), [])[:100]
        references = document.get("references") if isinstance(document.get("references"), list) else []
        public_link = next((str(entry.get("url")) for entry in references
                            if isinstance(entry, dict) and entry.get("category") == "self"
                            and isinstance(entry.get("url"), str) and entry["url"].startswith("https://")), None)
        products = self._product_names(value.get("product_tree"))[:100]
        severity = document.get("aggregate_severity") if isinstance(document.get("aggregate_severity"), dict) else {}
        metadata = {**processing.metadata, "delivery_method": "official_csaf", "cves": cves,
                    "severity": str(severity.get("text") or "")[:40] or None,
                    "references": [str(entry.get("url"))[:500] for entry in references[:50]
                                   if isinstance(entry, dict) and isinstance(entry.get("url"), str)],
                    "products": products,
                    "remediations": [str(entry.get("details") or "")[:1000] for entry in remediations
                                     if isinstance(entry, dict) and entry.get("details")]}
        collected = self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return ExternalCTIItem(
            record_id=f"csaf-{sha256_text(advisory_id).split(':', 1)[1][:32]}", source_item_id=advisory_id,
            source=self.source.name, source_type="cert", category="advisory", title=title, link=public_link,
            content=processing.export_content, summary=" ".join(summary_parts)[:2000],
            published=str(tracking.get("initial_release_date") or "") or None,
            updated_at=str(tracking.get("current_release_date") or "") or None,
            collected_at=collected, content_hash=sha256_text(processing.export_content), tags=tuple(cves),
            classification=ExternalClassification(status="not_required"), metadata=metadata,
        )

    def _product_names(self, value: Any) -> list[str]:
        names: list[str] = []
        pending = [value]
        while pending and len(names) < 100:
            current = pending.pop()
            if isinstance(current, dict):
                full = current.get("full_product_name")
                if isinstance(full, dict) and isinstance(full.get("name"), str): names.append(full["name"][:300])
                pending.extend(item for item in current.values() if isinstance(item, (dict, list)))
            elif isinstance(current, list): pending.extend(current[:1000])
        return names
