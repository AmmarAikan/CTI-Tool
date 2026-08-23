from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import canonical_json, sha256_bytes, sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.json_storage import atomic_replace
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem
from backend.app.pipeline.ingestion.external.common.run_manifest import RunManifest
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager


PROJECT_ROOT = Path(__file__).resolve().parents[6]
OFFICIAL_TYPES = frozenset({"rss", "cert", "nvd", "cve", "mitre", "github_advisories", "cisa_kev", "vulnerability", "reddit", "hackernews", "telegram"})


@dataclass(frozen=True, slots=True)
class RunSourceOutput:
    run_id: str
    source_id: str
    status: str
    accepted: tuple[ExternalCTIItem | dict[str, Any], ...] = ()
    review: tuple[ExternalCTIItem | dict[str, Any], ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExportResult:
    dataset_path: Path
    manifest_path: Path
    review_path: Path
    manifest: dict[str, Any]


class ExternalDatasetExporter:
    """Build one run-isolated, validated, deterministic External handoff."""

    def __init__(self, *, exports_dir: str | Path, review_dir: str | Path, state_manager: JsonStateManager,
                 item_schema: str | Path = PROJECT_ROOT / "contracts" / "external_cti_item.schema.json",
                 manifest_schema: str | Path = PROJECT_ROOT / "contracts" / "external_export_manifest.schema.json",
                 clock: Callable[[], datetime] | None = None) -> None:
        self.exports_dir, self.review_dir, self.state_manager = Path(exports_dir), Path(review_dir), state_manager
        self.item_validator = Draft202012Validator(self._load_schema(item_schema))
        self.manifest_validator = Draft202012Validator(self._load_schema(manifest_schema))
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def export(self, manifest: RunManifest, outputs: Iterable[RunSourceOutput], *, classifier_model_sha256: str | None = None) -> ExportResult:
        batches = tuple(outputs)
        if manifest.status != "running": raise ValueError("export requires a running manifest")
        if any(batch.run_id != manifest.run_id for batch in batches): raise ValueError("source output belongs to another run")
        accepted_candidates, review_entries, invalid_count = [], [], 0
        source_counts: dict[str, Any] = {}
        for batch in sorted(batches, key=lambda value: value.source_id):
            source_counts[batch.source_id] = {"status": batch.status, "total": len(batch.accepted) + len(batch.review), "accepted": 0, "review": len(batch.review), "invalid": 0}
            if batch.status == "failed" and not batch.errors: manifest.record_failure(batch.source_id, "source_failed")
            for value in batch.review:
                review_entries.append(self._review(self._mapping(value, manifest.run_id), batch.source_id, "collector_review"))
            for reason in batch.errors:
                manifest.record_failure(batch.source_id, self._safe_reason(reason))
            for value in batch.accepted:
                record = self._mapping(value, manifest.run_id)
                reasons = self._exclusion_reasons(record)
                schema_errors = sorted(error.validator for error in self.item_validator.iter_errors(record))
                if schema_errors:
                    reasons.append("item_contract_invalid"); invalid_count += 1; source_counts[batch.source_id]["invalid"] += 1
                if reasons:
                    review_entries.append(self._review(record, batch.source_id, *reasons)); source_counts[batch.source_id]["review"] += 1
                else:
                    accepted_candidates.append((batch.source_id, record))

        merged, duplicates = self._deduplicate(accepted_candidates)
        accepted_by_source = {source_id: 0 for source_id in source_counts}
        for record in merged:
            for source_id in record.get("metadata", {}).get("observed_in", []):
                if source_id in accepted_by_source: accepted_by_source[source_id] += 1
        for source_id, count in accepted_by_source.items(): source_counts[source_id]["accepted"] = count

        dataset = sorted(merged, key=lambda value: (value["record_id"], canonical_json(value)))
        review_entries.sort(key=canonical_json)
        dataset_bytes = self._json_bytes(dataset)
        review_bytes = self._json_bytes(review_entries)
        dataset_name = f"final_dataset_{manifest.run_id}.json"
        review_name = f"external_review_{manifest.run_id}.json"
        manifest.total_records = sum(value["total"] for value in source_counts.values())
        manifest.accepted_records, manifest.review_records = len(dataset), len(review_entries)
        manifest.invalid_records, manifest.duplicates_removed = invalid_count, duplicates
        manifest.sources, manifest.dataset_file = source_counts, dataset_name
        manifest.dataset_sha256 = sha256_bytes(dataset_bytes)
        manifest.classifier_model_sha256 = classifier_model_sha256
        if classifier_model_sha256 and not manifest.classifier_model_version:
            manifest.classifier_model_version = self._model_version(dataset)
        terminal = "failed" if not dataset and batches and all(batch.status == "failed" for batch in batches) else ("partial" if manifest.failed_sources else "completed")
        manifest.status, manifest.completed_at = terminal, self._now()
        manifest_value = manifest.to_dict()
        self.manifest_validator.validate(manifest_value)
        manifest_bytes = self._json_bytes(manifest_value)

        dataset_path, review_path = self.exports_dir / dataset_name, self.review_dir / review_name
        manifest_path = self.exports_dir / f"external_export_manifest_{manifest.run_id}.json"
        atomic_replace(dataset_path, dataset_bytes); atomic_replace(review_path, review_bytes); atomic_replace(manifest_path, manifest_bytes)
        state = self.state_manager.load(); state.setdefault("runs", {})[manifest.run_id] = {
            "status": terminal, "dataset_file": dataset_name, "dataset_sha256": manifest.dataset_sha256,
            "manifest_file": manifest_path.name, "review_file": review_name, "completed_at": manifest.completed_at,
        }
        self.state_manager.save(state)
        return ExportResult(dataset_path, manifest_path, review_path, manifest_value)

    def _deduplicate(self, candidates: list[tuple[str, dict[str, Any]]]) -> tuple[list[dict[str, Any]], int]:
        groups: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for source_id, record in candidates: groups.setdefault(self._identity(record), []).append((source_id, record))
        result = []
        for identity, observations in sorted(groups.items()):
            ordered = sorted(observations, key=lambda value: canonical_json(value[1]))
            primary = deepcopy(ordered[0][1])
            metadata = primary.setdefault("metadata", {})
            observed = set(metadata.get("observed_in", [])); identifiers, provenance, references = set(), [], set()
            for source_id, record in ordered:
                observed.add(source_id)
                if record.get("source_item_id"): identifiers.add(str(record["source_item_id"]))
                current = record.get("metadata", {})
                observed.update(str(value) for value in current.get("observed_in", []))
                references.update(str(value) for value in current.get("references", []))
                for value in current.get("provenance", []):
                    if value not in provenance: provenance.append(value)
            metadata["observed_in"], metadata["source_identifiers"] = sorted(observed), sorted(identifiers)
            if references: metadata["references"] = sorted(references)
            if provenance: metadata["provenance"] = sorted(provenance, key=canonical_json)
            primary["record_id"] = f"ext-{sha256_text(identity).split(':', 1)[1][:32]}"
            result.append(primary)
        return result, len(candidates) - len(result)

    def _identity(self, record: dict[str, Any]) -> str:
        metadata, source_type = record.get("metadata", {}), str(record.get("source_type", "")).lower()
        official = metadata.get("cve_id") or metadata.get("ghsa_id") or (record.get("source_item_id") if source_type in OFFICIAL_TYPES else None)
        if official: return f"official:{str(official).upper()}"
        if record.get("link"):
            try: return f"url:{canonicalize_url(str(record['link']))}"
            except ValueError: pass
        normalized = " ".join(str(record.get("content") or "").split()).casefold()
        if normalized: return f"content:{sha256_text(normalized)}"
        return f"fallback:{sha256_json({'source': record.get('source'), 'title': record.get('title'), 'published': record.get('published')})}"

    @staticmethod
    def _exclusion_reasons(record: dict[str, Any]) -> list[str]:
        reasons = []
        if not str(record.get("content") or "").strip(): reasons.append("empty_content")
        status = str(record.get("classification", {}).get("status") or "")
        if status in {"error", "not_run"}: reasons.append("classification_incomplete")
        elif status == "rejected": reasons.append("classification_rejected")
        privacy = record.get("metadata", {}).get("privacy", {})
        if privacy.get("status") == "review_required" or privacy.get("high_confidence_unresolved") is True: reasons.append("privacy_unresolved")
        return reasons

    @staticmethod
    def _mapping(value: ExternalCTIItem | dict[str, Any], run_id: str) -> dict[str, Any]:
        result = deepcopy(value.to_dict() if isinstance(value, ExternalCTIItem) else value)
        result.setdefault("metadata", {})["run_id"] = run_id
        return result

    def _review(self, value: ExternalCTIItem | dict[str, Any], source_id: str, *reasons: str) -> dict[str, Any]:
        record = deepcopy(value.to_dict() if isinstance(value, ExternalCTIItem) else value)
        link = str(record.get("link") or "")
        if ".onion" in link.lower(): record["link"] = "onion://[redacted]"
        return {"source_id": source_id, "reason_codes": sorted(set(reasons)), "record": record}

    @staticmethod
    def _safe_reason(value: str) -> str:
        allowed = "".join(character for character in str(value).lower() if character.isalnum() or character == "_")
        return allowed[:64] or "source_failed"
    @staticmethod
    def _model_version(dataset: list[dict[str, Any]]) -> str | None:
        values = sorted({str(record["classification"]["model_version"]) for record in dataset if record.get("classification", {}).get("model_version")})
        return ",".join(values) or None
    @staticmethod
    def _json_bytes(value: Any) -> bytes:
        return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    @staticmethod
    def _load_schema(path: str | Path) -> dict[str, Any]:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    def _now(self) -> str:
        return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
