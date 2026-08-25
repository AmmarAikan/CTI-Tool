from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.common.run_manifest import RunManifest
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.export.final_dataset import ExternalDatasetExporter, RunSourceOutput


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
MODEL_HASH = "sha256:" + "a" * 64


def item(identity: str, *, source="Source A", source_type="rss", link=None, content="Substantial sanitized cybersecurity advisory content.",
         status="not_required", metadata=None):
    return ExternalCTIItem(record_id="input-" + sha256_text(identity).split(":", 1)[1][:32], source_item_id=identity,
        source=source, source_type=source_type, category="cti", title="Sanitized advisory", link=link,
        content=content, summary=content[:30], collected_at="2026-08-23T12:00:00Z", content_hash=sha256_text(content),
        classification=ExternalClassification(status=status, model_version="test-model" if status != "not_required" else None),
        metadata=metadata or {"observed_in": [source.lower().replace(" ", "-")]})


class ExternalDatasetExporterTests(unittest.TestCase):
    def make(self, folder):
        root = Path(folder)
        return ExternalDatasetExporter(exports_dir=root / "exports", review_dir=root / "review",
            state_manager=JsonStateManager(root / "state.json"), clock=lambda: NOW)

    def manifest(self, run_id="ext-20260823T120000Z-test00000001"):
        return RunManifest(run_id=run_id, started_at="2026-08-23T11:59:00Z", classifier_model_version="test-model")

    def test_schema_sha_counts_partial_status_and_atomic_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            exporter, manifest = self.make(folder), self.manifest()
            outputs = [RunSourceOutput(manifest.run_id, "rss-a", "completed", (item("guid-1"),)),
                       RunSourceOutput(manifest.run_id, "failed-b", "failed", errors=("timeout",))]
            result = exporter.export(manifest, outputs, classifier_model_sha256=MODEL_HASH)
            dataset = json.loads(result.dataset_path.read_text(encoding="utf-8"))
            manifest_value = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            item_schema = json.loads((Path(__file__).resolve().parents[3] / "contracts/external_cti_item.schema.json").read_text(encoding="utf-8"))
            manifest_schema = json.loads((Path(__file__).resolve().parents[3] / "contracts/external_export_manifest.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator(item_schema).validate(dataset[0]); Draft202012Validator(manifest_schema).validate(manifest_value)
            self.assertEqual(manifest_value["dataset_sha256"], sha256_bytes(result.dataset_path.read_bytes()))
            self.assertEqual((manifest_value["accepted_records"], manifest_value["status"]), (1, "partial"))
            self.assertEqual(manifest_value["classifier_model_sha256"], MODEL_HASH)
            self.assertFalse(list(Path(folder).rglob("*.tmp")))

    def test_run_isolation_rejects_mixed_checkpoint_set(self):
        with tempfile.TemporaryDirectory() as folder:
            exporter, manifest = self.make(folder), self.manifest()
            with self.assertRaises(ValueError): exporter.export(manifest, [RunSourceOutput("different-run", "rss-a", "completed")])
            self.assertFalse((Path(folder) / "exports").exists())

    def test_stable_ids_and_deterministic_ordering(self):
        outputs_order = [item("guid-z"), item("guid-a")]
        datasets = []
        with tempfile.TemporaryDirectory() as folder:
            for suffix, values in (("01", outputs_order), ("02", list(reversed(outputs_order)))):
                run_id = "ext-20260823T120000Z-test000000" + suffix
                result = self.make(Path(folder) / suffix).export(self.manifest(run_id), [RunSourceOutput(run_id, "rss-a", "completed", tuple(values))])
                dataset = json.loads(result.dataset_path.read_text(encoding="utf-8"))
                for record in dataset: record["metadata"].pop("run_id", None)
                datasets.append(dataset)
        self.assertEqual(datasets[0], datasets[1])
        self.assertTrue(all(record["record_id"].startswith("ext-") and len(record["record_id"]) == 36 for record in datasets[0]))

    def test_dedup_preserves_provenance_identifiers_references(self):
        first = item("CVE-2026-1234", source="NVD", source_type="vulnerability",
                     metadata={"cve_id": "CVE-2026-1234", "observed_in": ["nvd"], "references": ["https://a.example/"]})
        second = item("CVE-2026-1234", source="CVE", source_type="cve",
                      metadata={"cve_id": "CVE-2026-1234", "observed_in": ["cve"], "references": ["https://b.example/"], "provenance": [{"source_id": "cve"}]})
        with tempfile.TemporaryDirectory() as folder:
            manifest = self.manifest(); result = self.make(folder).export(manifest, [RunSourceOutput(manifest.run_id, "nvd", "completed", (first,)), RunSourceOutput(manifest.run_id, "cve", "completed", (second,))])
            record = json.loads(result.dataset_path.read_text(encoding="utf-8"))[0]
        self.assertEqual(manifest.duplicates_removed, 1)
        self.assertEqual(record["metadata"]["observed_in"], ["cve", "nvd"])
        self.assertEqual(record["metadata"]["references"], ["https://a.example/", "https://b.example/"])
        self.assertEqual(record["metadata"]["source_identifiers"], ["CVE-2026-1234"])

    def test_manual_and_registered_url_dedup_preserves_manual_stable_id(self):
        link = "https://example.test/shared-advisory"
        registered = item("feed-guid", source="RSS Source", source_type="rss", link=link,
                          metadata={"observed_in": ["rss-source"]})
        manual = item(link, source="Manual URL", source_type="manual_url", link=link, status="accepted",
                      metadata={"observed_in": ["manual_url"]}).to_dict()
        manual["record_id"] = "manual-" + sha256_text(link).split(":", 1)[1][:32]
        with tempfile.TemporaryDirectory() as folder:
            manifest = self.manifest(); result = self.make(folder).export(manifest, [
                RunSourceOutput(manifest.run_id, "rss-source", "completed", (registered,)),
                RunSourceOutput(manifest.run_id, "manual_url", "completed", (manual,)),
            ])
            records = json.loads(result.dataset_path.read_text(encoding="utf-8"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["record_id"], manual["record_id"])
        self.assertEqual(records[0]["metadata"]["observed_in"], ["manual_url", "rss-source"])

    def test_carried_checkpoint_preserves_original_run_provenance(self):
        carried = item("manual-carried", source="Manual URL", source_type="manual_url", status="accepted",
                       metadata={"run_id": "ext-original-run", "observed_in": ["manual_url"]}).to_dict()
        carried["record_id"] = "manual-" + "a" * 32
        with tempfile.TemporaryDirectory() as folder:
            manifest = self.manifest(); result = self.make(folder).export(
                manifest, [RunSourceOutput(manifest.run_id, "manual_url", "completed", (carried,))])
            record = json.loads(result.dataset_path.read_text(encoding="utf-8"))[0]
        self.assertEqual(record["metadata"]["run_id"], "ext-original-run")

    def test_exclusions_are_preserved_with_safe_review_reasons(self):
        empty = item("empty", content="")
        classify = item("classification", source_type="manual_url", status="error")
        private = item("privacy", metadata={"privacy": {"status": "review_required"}})
        invalid = deepcopy(item("invalid").to_dict()); invalid.pop("title")
        with tempfile.TemporaryDirectory() as folder:
            manifest = self.manifest(); result = self.make(folder).export(manifest, [RunSourceOutput(manifest.run_id, "manual", "completed", (empty, classify, private, invalid))])
            dataset = json.loads(result.dataset_path.read_text(encoding="utf-8")); review = json.loads(result.review_path.read_text(encoding="utf-8"))
        self.assertEqual(dataset, []); self.assertEqual(len(review), 4); self.assertEqual(manifest.invalid_records, 1)
        reasons = {reason for entry in review for reason in entry["reason_codes"]}
        self.assertTrue({"empty_content", "classification_incomplete", "privacy_unresolved", "item_contract_invalid"}.issubset(reasons))

    def test_state_and_filenames_are_scoped_to_run(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = self.manifest(); exporter = self.make(folder)
            result = exporter.export(manifest, [RunSourceOutput(manifest.run_id, "rss-a", "completed", (item("guid-1"),))])
            state = exporter.state_manager.load()
        self.assertEqual(result.dataset_path.name, f"final_dataset_{manifest.run_id}.json")
        self.assertEqual(result.manifest_path.name, f"external_export_manifest_{manifest.run_id}.json")
        self.assertEqual(state["runs"][manifest.run_id]["dataset_sha256"], manifest.dataset_sha256)


if __name__ == "__main__": unittest.main()
