from __future__ import annotations

import importlib
import logging
import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.pipeline.ingestion.external.classification.classification_service import ClassifiedItemResult
from backend.app.pipeline.ingestion.external.application.manual_source_service import AdapterResult
from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.common.json_storage import load_json, save_json
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.common.run_manifest import RunManifest
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult
from backend.app.pipeline.ingestion.external.export.final_dataset import ExternalDatasetExporter, RunSourceOutput
from backend.app.pipeline.ingestion.external.integration.api import API_PREFIX
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy


PUBLIC = lambda _host, port: [(2, 1, 6, "", ("93.184.216.34", port))]
URL = "https://example.test/security-report"
GHSA_URL = "https://github.com/advisories/GHSA-2345-6789-CFGH"
LISTING_URL = "https://example.test/research/"
CONTACT_URL = "https://example.test/contact/"
ACTIVE_ARTICLE_URL = "https://example.test/research/active-threat-report"


def successful_crawl(text: str) -> CrawlResult:
    return CrawlResult(
        URL, URL, "success", "Sanitized security report", text, "article", 0.95, (), {},
        {"etag": f'"{sha256_text(text)[7:15]}"', "last_modified": "Mon, 25 Aug 2026 00:00:00 GMT"},
        sha256_text("raw:" + text), sha256_text(text),
    )


CONTENT_ONE = (
    "A detailed cybersecurity report describes malware execution, persistence, credential theft, "
    "affected systems, detection guidance, and defensive remediation for security teams."
)
CONTENT_TWO = CONTENT_ONE + " The revised report adds containment and recovery guidance."


class SequenceCrawler:
    def __init__(self, values):
        self.values = list(values)

    def crawl(self, _url, **_kwargs):
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class AcceptClassification:
    classifier = type("Classifier", (), {"model_version": "test-model"})()

    def classify_item(self, item):
        classified = replace(item, classification=ExternalClassification(status="accepted", label="cti_related", model_version="test-model"))
        return ClassifiedItemResult(classified, "accepted", None)


class RejectClassification:
    classifier = type("Classifier", (), {"model_version": "test-model"})()

    def classify_item(self, item):
        classified = replace(item, classification=ExternalClassification(status="rejected", label="not_cti_related", model_version="test-model"))
        return ClassifiedItemResult(classified, "rejected", None)


class AcceptedStructuredAdapter:
    def collect_url(self, canonical_url, *, identifier, source_id, state):
        del state
        content = "A structured GitHub security advisory with affected packages and remediation guidance."
        value = ExternalCTIItem(record_id="vuln-" + sha256_text(identifier).split(":", 1)[1][:32], source_item_id=identifier,
            source="GitHub Advisories", source_type="vulnerability", category="vulnerability", title=identifier,
            link=canonical_url, content=content, summary=content, collected_at="2026-08-25T12:00:00Z",
            content_hash=sha256_text(content), classification=ExternalClassification(status="not_required"),
            metadata={"observed_in": [source_id]})
        return AdapterResult("stored", (value,), "structured advisory processed")


class LocalManualSourceJobTests(unittest.TestCase):
    @staticmethod
    def _wait(client: TestClient, job_id: str, headers: dict[str, str]) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = client.get(f"{API_PREFIX}/jobs/{job_id}", headers=headers).json()
            if value["state"] in {"completed", "failed", "cancelled"}:
                return value
            time.sleep(0.01)
        raise AssertionError("manual job did not reach a terminal state")

    def _build(self, root: Path, crawler, classification, *, adapters=None):
        environment = {"EXTERNAL_API_TOKEN": "manual-test-token", "EXTERNAL_API_ROLES": "operator", "EXTERNAL_API_DEV_WORKERS": "1"}
        with patch.dict(os.environ, environment):
            local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
            app = local.build_local_app(
                dark_web_config_path=root / "missing-dark-web.json",
                manual_policy=ManualURLPolicy(resolver=PUBLIC), manual_crawler=crawler,
                manual_classification_service=classification, manual_state_path=root / "state" / "manual_sources.json",
                processed_directory=root / "processed", review_directory=root / "review", log_path=root / "logs" / "cti_tool.log",
                exports_directory=root / "exports", export_state_path=root / "state" / "exports.json",
                manual_checkpoint_path=root / "state" / "manual_checkpoints.json",
                manual_adapters=adapters,
            )
        return app

    def _submit(self, client: TestClient, *, recheck: bool = False) -> dict:
        endpoint = f"{API_PREFIX}/manual-sources/recheck" if recheck else f"{API_PREFIX}/manual-sources"
        headers = {"Authorization": "Bearer manual-test-token"}
        accepted = client.post(endpoint, json={"url": URL}, headers=headers)
        self.assertEqual((accepted.status_code, accepted.json()["state"]), (202, "queued"))
        return self._wait(client, accepted.json()["job_id"], headers)

    def test_new_manual_url_is_stored_by_canonical_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, SequenceCrawler([successful_crawl(CONTENT_ONE)]), AcceptClassification()); client = TestClient(app)
            terminal = self._submit(client)
            self.assertEqual((terminal["state"], terminal["result"]["status"], terminal["result"]["records_created"]), ("completed", "stored", 1))
            self.assertTrue((root / "state" / "manual_sources.json").is_file())
            self.assertEqual(len(list((root / "processed").glob("manual_*.json"))), 1)
            latest = client.get(f"{API_PREFIX}/exports/latest", headers={"Authorization": "Bearer manual-test-token"})
            self.assertEqual(latest.status_code, 200)
            self.assertEqual((latest.json()["accepted_records"], latest.json()["manifest"]["accepted_records"]), (1, 1))
            record = latest.json()["dataset"][0]
            self.assertEqual((record["record_id"], record["link"], record["source_item_id"]),
                             ("manual-" + sha256_text(URL).split(":", 1)[1][:32], URL, URL))
            self.assertEqual(record["content_hash"], sha256_text(record["content"]))
            self.assertEqual(record["classification"]["status"], "accepted")
            self._close(app, root)

    def test_preview_is_non_persistent_until_frozen_approval_exports_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, SequenceCrawler([successful_crawl(CONTENT_ONE)]), AcceptClassification())
            client = TestClient(app); headers = {"Authorization": "Bearer manual-test-token"}
            preview = client.post(f"{API_PREFIX}/manual-sources/previews", json={"url": URL}, headers=headers)
            self.assertEqual((preview.status_code, preview.json()["state"]), (201, "pending"))
            self.assertFalse((root / "state" / "manual_sources.json").exists())
            self.assertFalse(list((root / "exports").glob("final_dataset_*.json")))
            approved = client.post(
                f"{API_PREFIX}/manual-sources/previews/{preview.json()['preview_id']}/approve",
                json={"expected_content_sha256": preview.json()["content_sha256"]},
                headers={**headers, "Idempotency-Key": "approve-preview-once"},
            )
            terminal = self._wait(client, approved.json()["job_id"], headers)
            self.assertEqual((approved.status_code, terminal["state"]), (202, "completed"))
            self.assertEqual(terminal["result"]["accepted_records"], 1)
            self.assertEqual(client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()["accepted_records"], 1)
            self._close(app, root)

    def test_unchanged_manual_url_completes_as_unchanged(self):
        values = [successful_crawl(CONTENT_ONE), CrawlResult(URL, URL, "unchanged")]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, SequenceCrawler(values), AcceptClassification()); client = TestClient(app)
            self.assertEqual(self._submit(client)["result"]["status"], "stored")
            headers = {"Authorization": "Bearer manual-test-token"}
            before = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            export_count = len(list((root / "exports").glob("final_dataset_*.json")))
            second = self._submit(client)
            self.assertEqual((second["state"], second["result"]["status"]), ("completed", "unchanged"))
            after = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            self.assertEqual((before["run_id"], after["run_id"]), (before["run_id"], before["run_id"]))
            self.assertEqual(len(after["dataset"]), 1)
            self.assertEqual(len(list((root / "exports").glob("final_dataset_*.json"))), export_count)
            self._close(app, root)

    def test_changed_manual_url_reports_updated_record(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, SequenceCrawler([successful_crawl(CONTENT_ONE), successful_crawl(CONTENT_TWO)]), AcceptClassification()); client = TestClient(app)
            self._submit(client)
            changed = self._submit(client, recheck=True)
            self.assertEqual((changed["state"], changed["result"]["status"], changed["result"]["records_updated"]), ("completed", "stored", 1))
            self._close(app, root)

    def test_rejected_manual_url_is_not_reported_as_stored(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, SequenceCrawler([successful_crawl(CONTENT_ONE)]), RejectClassification())
            client = TestClient(app); terminal = self._submit(client)
            self.assertEqual((terminal["state"], terminal["result"]["status"]), ("completed", "ignored"))
            self.assertEqual(len(list((root / "review").glob("manual_*.json"))), 1)
            latest = client.get(f"{API_PREFIX}/exports/latest", headers={"Authorization": "Bearer manual-test-token"}).json()
            self.assertEqual((latest["accepted_records"], latest["review_records"], latest["dataset"]), (0, 1, []))
            self._close(app, root)

    def test_business_error_result_maps_to_failed_job_contract(self):
        failed_crawl = CrawlResult(URL, URL, "error", errors=())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, SequenceCrawler([failed_crawl]), AcceptClassification())
            terminal = self._submit(TestClient(app))
            self.assertEqual((terminal["state"], terminal["error"]["code"]), ("failed", "job_failed"))
            self.assertIsNone(terminal["result"])
            self._close(app, root)

    def test_internal_failure_maps_to_safe_failed_job(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, SequenceCrawler([RuntimeError("token=do-not-return content=do-not-return")]), AcceptClassification())
            terminal = self._submit(TestClient(app))
            self.assertEqual((terminal["state"], terminal["error"]["code"]), ("failed", "job_failed"))
            self.assertNotIn("do-not-return", str(terminal))
            self._close(app, root)

    def test_structured_url_uses_adapter_never_crawler_and_enters_export(self):
        crawler = SequenceCrawler([])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, crawler, AcceptClassification(),
                adapters={"github_advisory": AcceptedStructuredAdapter()}); client = TestClient(app)
            headers = {"Authorization": "Bearer manual-test-token"}
            queued = client.post(f"{API_PREFIX}/manual-sources", json={"url": GHSA_URL}, headers=headers).json()
            terminal = self._wait(client, queued["job_id"], headers)
            self.assertEqual((terminal["state"], terminal["result"]["status"]), ("completed", "stored"))
            latest = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            self.assertEqual(len(latest["dataset"]), 1)
            self.assertEqual(latest["dataset"][0]["source_item_id"], "GHSA-2345-6789-CFGH")
            self.assertEqual(crawler.values, [])
            self._close(app, root)

    def test_removed_listing_child_is_retired_and_never_carried_into_new_export(self):
        old_content = "Legacy contact page content that was incorrectly accepted by an earlier classifier execution."
        old_record = ExternalCTIItem(record_id="manual-" + sha256_text(CONTACT_URL).split(":", 1)[1][:32],
            source_item_id=CONTACT_URL, source="Manual URL", source_type="manual_url", category="manual", title="Contact",
            link=CONTACT_URL, content=old_content, summary=old_content, collected_at="2026-08-24T00:00:00Z",
            content_hash=sha256_text(old_content), classification=ExternalClassification(status="accepted", label="cti_related"),
            metadata={"parent_listing": LISTING_URL, "run_id": "ext-original-run"})
        active_content = CONTENT_ONE + " This article contains additional threat intelligence evidence and response details."
        first_listing = CrawlResult(LISTING_URL, LISTING_URL, "success", "Research", "Research listing", "listing", .9,
                                    (ACTIVE_ARTICLE_URL,), {}, {}, sha256_text("listing-v2"), sha256_text("Research listing"))
        active_page = CrawlResult(ACTIVE_ARTICLE_URL, ACTIVE_ARTICLE_URL, "success", "Active threat report", active_content,
                                  "article", .9, (), {}, {}, sha256_text("active-raw"), sha256_text(active_content))
        second_listing = CrawlResult(LISTING_URL, LISTING_URL, "success", "Research", "Research listing", "listing", .9,
                                     (ACTIVE_ARTICLE_URL,), {}, {}, sha256_text("listing-v2"), sha256_text("Research listing"))
        unchanged = CrawlResult(ACTIVE_ARTICLE_URL, ACTIVE_ARTICLE_URL, "unchanged")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            save_json({"schema_version": "1.0", "accepted": {old_record.record_id: old_record.to_dict()}},
                      root / "state" / "manual_checkpoints.json")
            save_json({"schema_version": "1.0", "sources": {},
                       "urls": {LISTING_URL: {"known_sub_links": [CONTACT_URL, ACTIVE_ARTICLE_URL]}},
                       "items": {old_record.record_id: {"record_hash": "sha256:legacy", "active": True}}},
                      root / "state" / "manual_sources.json")
            save_json(old_record.to_dict(), root / "processed" / f"manual_{old_record.record_id}.json")
            app = self._build(root, SequenceCrawler([first_listing, active_page, second_listing, unchanged]), AcceptClassification()); client = TestClient(app)
            headers = {"Authorization": "Bearer manual-test-token"}
            def recheck():
                queued = client.post(f"{API_PREFIX}/manual-sources/recheck", json={"url": LISTING_URL}, headers=headers).json()
                return self._wait(client, queued["job_id"], headers)
            first = recheck(); self.assertEqual(first["state"], "completed")
            latest = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            self.assertEqual([record["link"] for record in latest["dataset"]], [ACTIVE_ARTICLE_URL])
            self.assertNotIn(CONTACT_URL, str(latest["dataset"]))
            checkpoint = load_json(root / "state" / "manual_checkpoints.json")
            self.assertNotIn(old_record.record_id, checkpoint["accepted"])
            self.assertIn(old_record.record_id, checkpoint.get("retired", {}), checkpoint)
            retired = checkpoint["retired"][old_record.record_id]
            self.assertEqual(retired["reason"], "no_longer_discovered")
            self.assertEqual(retired["record"]["metadata"]["run_id"], "ext-original-run")
            self.assertEqual(retired["record"]["collected_at"], "2026-08-24T00:00:00Z")
            self.assertTrue((root / "processed" / f"manual_{old_record.record_id}.json").exists())
            run_id = latest["run_id"]
            second = recheck(); self.assertEqual(second["state"], "completed")
            unchanged_latest = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            self.assertEqual((unchanged_latest["run_id"], len(unchanged_latest["dataset"])), (run_id, 1))
            state = load_json(root / "state" / "manual_sources.json")
            self.assertEqual(state["urls"][CONTACT_URL]["retired_reason"], "no_longer_discovered")
            self._close(app, root)

    def test_step4_legacy_snapshot_is_reconciled_from_accepted_checkpoints(self):
        contact_content = "Get support for an existing account by phone, email, chat, billing, or setup assistance."
        article_content = CONTENT_ONE + " It includes verified indicators, mitigations, and incident response context."
        def legacy_item(url, title, content):
            return ExternalCTIItem(record_id="manual-" + sha256_text(url).split(":", 1)[1][:32],
                source_item_id=url, source="Manual URL", source_type="manual_url", category="manual", title=title,
                link=url, content=content, summary=content, collected_at="2026-08-25T10:23:18Z",
                content_hash=sha256_text(content), classification=ExternalClassification(status="accepted", label="cti_related"),
                metadata={"parent_listing": LISTING_URL})
        contact = legacy_item(CONTACT_URL, "Contact", contact_content)
        article = legacy_item(ACTIVE_ARTICLE_URL, "Active threat report", article_content)
        standalone_url = "https://example.test/standalone-threat-report"
        standalone_content = CONTENT_TWO + " Independent analysis covers a separate campaign and defensive recommendations."
        standalone = replace(legacy_item(standalone_url, "Standalone threat report", standalone_content), metadata={})
        listing = CrawlResult(LISTING_URL, LISTING_URL, "success", "Research", "Research listing", "listing", .9,
                              (ACTIVE_ARTICLE_URL,), {}, {}, sha256_text("listing-current"), sha256_text("Research listing"))
        unchanged = CrawlResult(ACTIVE_ARTICLE_URL, ACTIVE_ARTICLE_URL, "unchanged")
        earliest_run = "ext-20260825T102507Z-15d0f1c7aec6"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            exporter = ExternalDatasetExporter(exports_dir=root / "exports", review_dir=root / "review",
                state_manager=JsonStateManager(root / "state" / "exports.json"))
            exporter.export(RunManifest(run_id=earliest_run, started_at="2026-08-25T10:25:07Z"),
                            (RunSourceOutput(earliest_run, "manual_url", "completed", (contact, article, standalone)),))
            save_json({"schema_version": "1.0", "accepted": {
                contact.record_id: contact.to_dict(), article.record_id: article.to_dict(), standalone.record_id: standalone.to_dict(),
            }}, root / "state" / "manual_checkpoints.json")
            save_json({"schema_version": "1.0", "sources": {}, "urls": {
                LISTING_URL: {"known_sub_links": [ACTIVE_ARTICLE_URL]},
                CONTACT_URL: {"missing_from_source": "2026-08-25T13:41:24Z"},
                ACTIVE_ARTICLE_URL: {},
            }, "items": {
                contact.record_id: {"record_hash": "sha256:legacy-contact"},
                article.record_id: {"record_hash": "sha256:legacy-article"},
            }}, root / "state" / "manual_sources.json")
            save_json(contact.to_dict(), root / "processed" / f"manual_{contact.record_id}.json")
            save_json(article.to_dict(), root / "processed" / f"manual_{article.record_id}.json")
            save_json(standalone.to_dict(), root / "processed" / f"manual_{standalone.record_id}.json")
            crawler = SequenceCrawler([listing, unchanged, listing, unchanged])
            app = self._build(root, crawler, AcceptClassification()); client = TestClient(app)
            headers = {"Authorization": "Bearer manual-test-token"}
            def recheck():
                queued = client.post(f"{API_PREFIX}/manual-sources/recheck", json={"url": LISTING_URL}, headers=headers).json()
                return self._wait(client, queued["job_id"], headers)
            first = recheck(); self.assertEqual(first["state"], "completed")
            latest = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            links = [record["link"] for record in latest["dataset"]]
            self.assertEqual(set(links), {ACTIVE_ARTICLE_URL, standalone_url})
            self.assertEqual((links.count(ACTIVE_ARTICLE_URL), links.count(standalone_url)), (1, 1))
            checkpoint = load_json(root / "state" / "manual_checkpoints.json")
            self.assertNotIn(contact.record_id, checkpoint["accepted"])
            self.assertIn(article.record_id, checkpoint["accepted"])
            self.assertIn(standalone.record_id, checkpoint["accepted"])
            retired = checkpoint["retired"][contact.record_id]
            self.assertEqual(retired["reason"], "no_longer_discovered")
            self.assertEqual(retired["record"]["metadata"]["run_id"], earliest_run)
            self.assertEqual(retired["record"]["metadata"]["lifecycle"]["active"], False)
            self.assertEqual(retired["record"]["metadata"]["lifecycle"]["retired_reason"], "no_longer_discovered")
            self.assertEqual(checkpoint["accepted"][article.record_id]["metadata"]["run_id"], earliest_run)
            marker = checkpoint["migrations"]["manual_listing_reconciliation"]
            self.assertEqual(marker["version"], "1.0")
            self.assertTrue((root / "processed" / f"manual_{contact.record_id}.json").exists())
            generated_run = latest["run_id"]
            retired_at = retired["retired_at"]
            second = recheck(); self.assertEqual(second["state"], "completed")
            latest_again = client.get(f"{API_PREFIX}/exports/latest", headers=headers).json()
            self.assertEqual((latest_again["run_id"], len(latest_again["dataset"])), (generated_run, 2))
            checkpoint_again = load_json(root / "state" / "manual_checkpoints.json")
            self.assertEqual(checkpoint_again["retired"][contact.record_id]["retired_at"], retired_at)
            self.assertEqual(len(checkpoint_again["accepted"]), 2)
            self._close(app, root)

    @staticmethod
    def _close(app, root: Path) -> None:
        app.state.services.job_runner.shutdown()
        target = (root / "logs" / "cti_tool.log").resolve()
        logger = logging.getLogger()
        for handler in tuple(logger.handlers):
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename).resolve() == target:
                logger.removeHandler(handler); handler.close()


if __name__ == "__main__":
    unittest.main()
