from __future__ import annotations

import importlib
import logging
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.pipeline.ingestion.external.dark_web_connector import (
    DarkWebConfigurationError, DarkWebSource, TorResponse, load_dark_web_config,
)
from backend.app.pipeline.ingestion.external.integration.api import API_PREFIX
from backend.app.pipeline.ingestion.external.common.json_storage import save_json


FAKE_ONION = "http://" + "a" * 56 + ".onion/advisories/"


class AvailableTorClient:
    def tor_available(self): return True
    def get(self, source, url, **_kwargs):
        assert source.allows(url)
        html = ("<html><main><article><h1>Sanitized threat advisory</h1><p>" +
                "A trusted security report describes malware behavior, affected systems, indicators, " * 8 +
                "mitigation and remediation guidance.</p></article></main></html>").encode()
        return TorResponse(200, html, "text/html")


class UnavailableTorClient:
    def tor_available(self): return False


class CompletedRSSConnector:
    def collect_result(self):
        return SimpleNamespace(status="completed", accepted_items=[], review_items=[], rejected_items=[],
                               skipped_items=0, errors=[])


class LocalDarkWebRegistryTests(unittest.TestCase):
    @staticmethod
    def _config(path: Path, *, duplicate=False):
        sources = [{"id": "darkweb-source-test", "name": "Approved test source", "url": FAKE_ONION,
                    "enabled": True, "category": "dark_web_cti", "allowed_paths": ["/advisories/"],
                    "max_items": 3, "rate_limit_seconds": 0, "trusted_curated": True},
                   {"id": "darkweb-disabled-test", "name": "Disabled test source",
                    "url": "http://" + "b" * 56 + ".onion/reports/", "enabled": False,
                    "category": "dark_web_cti", "allowed_paths": ["/reports/"], "max_items": 2,
                    "rate_limit_seconds": 0, "trusted_curated": True}]
        if duplicate: sources.append(dict(sources[0]))
        save_json({"schema_version": "1.0", "proxy": {"host": "127.0.0.1", "port": 19050},
                   "sources": sources}, path)

    def _build(self, root: Path, client, *, connector_factory=None):
        config = root / "dark_web_sources.local.json"; self._config(config)
        environment = {"EXTERNAL_API_TOKEN": "dark-registry-token", "EXTERNAL_API_ROLES": "operator",
                       "EXTERNAL_API_DEV_WORKERS": "1", "EXTERNAL_DARK_WEB_CONFIG_PATH": str(config)}
        with patch.dict(os.environ, environment):
            local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
            return local.build_local_app(dark_web_config_path=config, dark_web_client=client,
                connector_factory=connector_factory, state_directory=root / "state",
                processed_directory=root / "processed", review_directory=root / "review",
                exports_directory=root / "exports", export_state_path=root / "state" / "exports.json",
                manual_checkpoint_path=root / "state" / "manual_checkpoints.json",
                manual_state_path=root / "state" / "manual.json", log_path=root / "logs" / "cti_tool.log")

    @staticmethod
    def _wait(client, job_id, headers):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = client.get(f"{API_PREFIX}/jobs/{job_id}", headers=headers).json()
            if value["state"] in {"completed", "partial", "failed", "cancelled"}: return value
            time.sleep(.01)
        raise AssertionError("dark-web job did not terminate")

    def test_sources_are_unified_redacted_and_execute_only_requested_definition(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, AvailableTorClient()); client = TestClient(app)
            headers = {"Authorization": "Bearer dark-registry-token"}
            response = client.get(f"{API_PREFIX}/sources", headers=headers)
            dark = {value["source_id"]: value for value in response.json() if value["source_type"] == "dark_web"}
            self.assertEqual(dark["darkweb-source-test"], {"source_id": "darkweb-source-test",
                "name": "Approved test source", "source_type": "dark_web", "status": "enabled", "metadata": {}})
            self.assertEqual(dark["darkweb-disabled-test"]["status"], "disabled")
            serialized = response.text.lower()
            self.assertNotIn(".onion", serialized); self.assertNotIn("allowed_paths", serialized)
            self.assertNotIn("19050", serialized); self.assertNotIn("tor_proxy", serialized)
            queued = client.post(f"{API_PREFIX}/sources/darkweb-source-test/jobs", headers=headers)
            terminal = self._wait(client, queued.json()["job_id"], headers)
            self.assertEqual((queued.status_code, terminal["state"], terminal["result"]["source_id"]),
                             (202, "completed", "darkweb-source-test"))
            latest = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            self.assertTrue(latest["dataset"])
            self.assertTrue(all(record["classification"]["status"] == "not_required" for record in latest["dataset"]))
            self.assertNotIn(".onion", str(terminal).lower())
            disabled = client.post(f"{API_PREFIX}/sources/darkweb-disabled-test/jobs", headers=headers)
            self.assertEqual((disabled.status_code, disabled.json()["code"]), (409, "source_disabled"))
            self._close(app, root)

    def test_tor_failure_is_isolated_from_registered_public_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, UnavailableTorClient(),
                connector_factory=lambda _source, _state: CompletedRSSConnector()); client = TestClient(app)
            headers = {"Authorization": "Bearer dark-registry-token"}
            queued = client.post(f"{API_PREFIX}/jobs", json={
                "source_ids": ["darkweb-source-test", "the-hacker-news"]}, headers=headers).json()
            terminal = self._wait(client, queued["job_id"], headers)
            self.assertEqual((terminal["state"], terminal["result"]["status"]), ("partial", "partial"))
            self.assertEqual(terminal["result"]["sources"]["darkweb-source-test"]["status"], "failed")
            self.assertEqual(terminal["result"]["sources"]["the-hacker-news"]["status"], "completed")
            self._close(app, root)

    def test_single_source_force_reprocesses_unchanged_record_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, AvailableTorClient()); client = TestClient(app)
            headers = {"Authorization": "Bearer dark-registry-token"}
            first_job = client.post(f"{API_PREFIX}/sources/darkweb-source-test/jobs", json={"force": False}, headers=headers).json()
            first = self._wait(client, first_job["job_id"], headers)
            first_dataset = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()["dataset"]
            skipped_job = client.post(f"{API_PREFIX}/sources/darkweb-source-test/jobs", json={"force": False}, headers=headers).json()
            skipped = self._wait(client, skipped_job["job_id"], headers)
            forced_job = client.post(f"{API_PREFIX}/sources/darkweb-source-test/jobs", json={"force": True}, headers=headers).json()
            forced = self._wait(client, forced_job["job_id"], headers)
            forced_dataset = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()["dataset"]
            self.assertEqual((first["result"]["accepted_records"], skipped["result"]["skipped_records"],
                              forced["result"]["accepted_records"], forced["result"]["force"]), (1, 1, 1, True))
            self.assertEqual(len(forced_dataset), 1)
            self.assertEqual((forced_dataset[0]["record_id"], forced_dataset[0]["collected_at"]),
                             (first_dataset[0]["record_id"], first_dataset[0]["collected_at"]))
            self._close(app, root)

    def test_multi_source_force_reprocesses_dark_web_record(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, AvailableTorClient(),
                connector_factory=lambda _source, _state: CompletedRSSConnector()); client = TestClient(app)
            headers = {"Authorization": "Bearer dark-registry-token"}
            initial_job = client.post(f"{API_PREFIX}/sources/darkweb-source-test/jobs", headers=headers).json()
            self._wait(client, initial_job["job_id"], headers)
            queued = client.post(f"{API_PREFIX}/jobs", json={
                "source_ids": ["darkweb-source-test", "the-hacker-news"], "force": True}, headers=headers).json()
            terminal = self._wait(client, queued["job_id"], headers)
            self.assertEqual((terminal["state"], terminal["result"]["force"], terminal["result"]["accepted_records"],
                              terminal["result"]["skipped_records"]), ("completed", True, 1, 0))
            self._close(app, root)

    def test_duplicate_ids_and_registry_collisions_fail_deterministically(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); config = root / "dark.json"; self._config(config, duplicate=True)
            with self.assertRaisesRegex(DarkWebConfigurationError, "source_id=darkweb-source-test reason=duplicate_source_id"):
                load_dark_web_config(config)
            sources_path = root / "sources.json"
            save_json({"rss_sources": [{"source_id": "collision", "name": "Public", "url": "https://example.test/feed", "enabled": True}]}, sources_path)
            with patch.dict(os.environ, {"EXTERNAL_API_TOKEN": "duplicate-test-token",
                                         "EXTERNAL_DARK_WEB_CONFIG_PATH": str(root / "missing.json")}):
                local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
            source = DarkWebSource("collision", "Private", FAKE_ONION, ("/advisories/",), True)
            with self.assertRaisesRegex(DarkWebConfigurationError, "duplicate external source id: collision"):
                local.load_collection_registry(sources_path, dark_web_sources=(source,))

    def test_enabled_invalid_source_fails_local_startup_without_address_disclosure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); config = root / "invalid-local.json"
            save_json({"schema_version": "1.0", "proxy": {"host": "127.0.0.1", "port": 19050}, "sources": [{
                "id": "startup-invalid-test", "name": "Invalid", "url": "http://" + "d" * 55 + ".onion/reports/",
                "enabled": True, "allowed_paths": ["/reports/"],
            }]}, config)
            with patch.dict(os.environ, {"EXTERNAL_API_TOKEN": "startup-test-token",
                                         "EXTERNAL_DARK_WEB_CONFIG_PATH": str(root / "missing.json")}):
                local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
                with self.assertRaises(DarkWebConfigurationError) as raised:
                    local.build_local_app(dark_web_config_path=config, log_path=root / "logs" / "cti_tool.log")
            message = str(raised.exception)
            self.assertIn("source_id=startup-invalid-test", message)
            self.assertIn("reason=invalid_v3_onion_length", message)
            self.assertNotIn(".onion", message); self.assertNotIn("d" * 20, message)
            self.assertFalse((root / "logs" / "cti_tool.log").exists())

    @staticmethod
    def _close(app, root):
        app.state.services.job_runner.shutdown()
        target = (root / "logs" / "cti_tool.log").resolve()
        logger = logging.getLogger()
        for handler in tuple(logger.handlers):
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename).resolve() == target:
                logger.removeHandler(handler); handler.close()


if __name__ == "__main__": unittest.main()
