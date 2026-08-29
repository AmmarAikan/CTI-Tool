from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.config_loader import (
    ConfigurationError,
    load_config,
    validate_collection_settings,
)
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.json_storage import latest_file, load_json, save_json, timestamped_filename
from backend.app.pipeline.ingestion.external.common.logging import redact_mapping
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.common.run_manifest import RunManifest, generate_run_id
from backend.app.pipeline.ingestion.external.common.state_manager import EMPTY_STATE, JsonStateManager, StateCorruptionError


ROOT = Path(__file__).resolve().parents[3]


class ContractTests(unittest.TestCase):
    def test_all_contract_schemas_are_valid_draft_2020_12(self) -> None:
        for path in sorted((ROOT / "contracts").glob("*.schema.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)

    def test_external_fixture_validates(self) -> None:
        schema = json.loads((ROOT / "contracts" / "external_cti_item.schema.json").read_text(encoding="utf-8"))
        fixture = json.loads((ROOT / "tests" / "external_sources" / "fixtures" / "external_item.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(fixture)


class HashAndUrlTests(unittest.TestCase):
    def test_hashing_is_stable_for_equivalent_mapping_order(self) -> None:
        self.assertEqual(sha256_json({"b": 2, "a": 1}), sha256_json({"a": 1, "b": 2}))
        self.assertRegex(sha256_text("content"), r"^sha256:[a-f0-9]{64}$")

    def test_canonical_url_removes_tracking_and_preserves_meaningful_query(self) -> None:
        first = canonicalize_url("HTTPS://Example.COM:443/report?id=7&utm_source=test#part")
        second = canonicalize_url("https://example.com/report?id=7")
        self.assertEqual(first, second)
        self.assertEqual(first, "https://example.com/report?id=7")

    def test_canonical_url_rejects_credentials_and_non_http(self) -> None:
        with self.assertRaises(ValueError):
            canonicalize_url("https://user:secret@example.test/")
        with self.assertRaises(ValueError):
            canonicalize_url("file:///tmp/input")


class ModelTests(unittest.TestCase):
    def test_external_item_maps_to_shared_raw_record(self) -> None:
        content = "Sanitized advisory content."
        item = ExternalCTIItem(
            record_id="external-record-000001",
            source_item_id="ADV-1",
            source="Example CERT",
            source_type="cert",
            category="advisory",
            title="Advisory",
            link="https://example.test/advisory/1",
            content=content,
            summary="Summary",
            collected_at="2026-08-20T10:00:00Z",
            content_hash=sha256_text(content),
            classification=ExternalClassification(status="not_required"),
        )
        record = item.to_raw_record()
        self.assertEqual(record.external_id, "ADV-1")
        self.assertEqual(record.source_pipeline, "external")
        self.assertTrue(record.trusted_cybersecurity_source)

    def test_item_rejects_mismatched_content_hash(self) -> None:
        with self.assertRaises(ValueError):
            ExternalCTIItem(
                record_id="external-record-000001",
                source="Example",
                source_type="rss",
                category="news",
                title="Title",
                link=None,
                content="content",
                summary="",
                collected_at="2026-08-20T10:00:00Z",
                content_hash=sha256_text("different"),
            )


class StorageAndStateTests(unittest.TestCase):
    def test_json_write_read_latest_and_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = save_json({"value": 1}, root / "result_1.json")
            second = save_json({"value": 2}, root / "result_2.json")
            self.assertEqual(load_json(first), {"value": 1})
            self.assertEqual(latest_file(root, "result"), second)
        stamp = timestamped_filename("run", now=datetime(2026, 8, 20, tzinfo=timezone.utc))
        self.assertEqual(stamp, "run_20260820T000000Z.json")

    def test_state_corruption_is_quarantined_and_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("{broken", encoding="utf-8")
            manager = JsonStateManager(path)
            self.assertEqual(manager.load(), EMPTY_STATE)
            self.assertFalse(path.exists())
            self.assertEqual(len(list(path.parent.glob("state.json.corrupt-*"))), 1)

    def test_state_corruption_can_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(StateCorruptionError):
                JsonStateManager(path).load(recover_corrupt=False)


class ConfigurationAndManifestTests(unittest.TestCase):
    def test_repository_collection_settings_validate(self) -> None:
        value = load_config(ROOT / "config" / "collection_settings.json")
        self.assertIs(validate_collection_settings(value), value)

    def test_bad_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"schema_version":"2.0"}', encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                load_config(path)

    def test_manifest_has_safe_failure_and_terminal_state(self) -> None:
        run_id = generate_run_id(datetime(2026, 8, 20, tzinfo=timezone.utc))
        self.assertRegex(run_id, r"^ext-20260820T000000Z-[a-f0-9]{12}$")
        manifest = RunManifest(run_id=run_id)
        manifest.record_failure("source-1", "timeout", retryable=True)
        manifest.finish("partial")
        value = manifest.to_dict()
        self.assertEqual(value["status"], "partial")
        self.assertTrue(value["completed_at"].endswith("Z"))
        self.assertNotIn("message", value["failed_sources"][0])

    def test_sensitive_mapping_values_are_redacted(self) -> None:
        value = redact_mapping({"api_key": "secret", "nested": {"token": "secret", "count": 2}})
        self.assertEqual(value["api_key"], "[REDACTED]")
        self.assertEqual(value["nested"]["token"], "[REDACTED]")
        self.assertEqual(value["nested"]["count"], 2)


if __name__ == "__main__":
    unittest.main()
