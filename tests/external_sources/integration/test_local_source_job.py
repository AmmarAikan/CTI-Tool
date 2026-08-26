from __future__ import annotations

import importlib
import logging
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse
from backend.app.pipeline.ingestion.external.common.logging import configure_file_logging
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult
from backend.app.pipeline.ingestion.external.integration.api import API_PREFIX
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner
from backend.app.pipeline.ingestion.external.rss_connector import RSSConnector


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class FakeFeedClient:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def get(self, url: str, **_kwargs) -> HttpResponse:
        return HttpResponse(url, 200, {"Content-Type": "application/rss+xml"}, self.body)


class FakeArticleCrawler:
    def crawl(self, url: str, **_kwargs) -> CrawlResult:
        text = (
            "A detailed sanitized security advisory describes a remotely exploitable vulnerability, "
            "affected systems, technical impact, detection guidance, and remediation steps for defenders."
        )
        return CrawlResult(url, url, "success", title="Sanitized advisory", extracted_text=text, page_type="article")


class LocalSourceJobTests(unittest.TestCase):
    @staticmethod
    def _wait(client: TestClient, job_id: str, headers: dict[str, str]) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = client.get(f"{API_PREFIX}/jobs/{job_id}", headers=headers).json()
            if value["state"] in {"completed", "partial", "failed", "cancelled"}:
                return value
            time.sleep(0.01)
        raise AssertionError("local job did not reach a terminal state")

    def test_real_canonical_rss_source_job_completes_through_local_adapter(self) -> None:
        feed = (FIXTURES / "rss_feed.xml").read_bytes()

        def connector_factory(source, state):
            return RSSConnector.from_source(source, state=state, http_client=FakeFeedClient(feed), crawler=FakeArticleCrawler())

        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "EXTERNAL_API_TOKEN": "local-regression-token",
            "EXTERNAL_API_ROLES": "operator",
            "EXTERNAL_API_DEV_WORKERS": "1",
        }):
            local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
            root = Path(folder)
            app = local.build_local_app(connector_factory=connector_factory, state_directory=root / "state",
                                        dark_web_config_path=root / "missing-dark-web.json",
                                        processed_directory=root / "processed", review_directory=root / "review",
                                        exports_directory=root / "exports", export_state_path=root / "state" / "exports.json",
                                        manual_checkpoint_path=root / "state" / "manual_checkpoints.json",
                                        log_path=root / "logs" / "cti_tool.log")
            client = TestClient(app)
            headers = {"Authorization": "Bearer local-regression-token"}
            accepted = client.post(f"{API_PREFIX}/sources/the-hacker-news/jobs", headers=headers)
            self.assertEqual((accepted.status_code, accepted.json()["state"]), (202, "queued"))
            terminal = self._wait(client, accepted.json()["job_id"], headers)
            self.assertEqual(terminal["state"], "completed")
            self.assertEqual(terminal["command_id"], accepted.json()["command_id"])
            self.assertEqual(terminal["result"]["source_id"], "the-hacker-news")
            self.assertGreaterEqual(terminal["result"]["accepted_records"], 1)
            self.assertTrue((root / "state" / "rss_the-hacker-news.json").is_file())
            self.assertTrue(any((root / "processed").glob("rss_the-hacker-news_*.json")))
            app.state.services.job_runner.shutdown()
            self._close_file_handler(root / "logs" / "cti_tool.log")

    def test_local_docs_environment_flag_is_default_off_and_explicitly_enabled(self) -> None:
        base_environment = {
            "EXTERNAL_API_TOKEN": "local-docs-token",
            "EXTERNAL_API_ROLES": "operator",
            "EXTERNAL_API_DEV_WORKERS": "1",
        }
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, base_environment, clear=True):
            local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
            root = Path(folder)
            disabled = local.build_local_app(log_path=root / "disabled.log",
                                             dark_web_config_path=root / "missing-dark-web.json")
            self.assertEqual(TestClient(disabled).get("/docs").status_code, 404)
            disabled.state.services.job_runner.shutdown()
            self._close_file_handler(root / "disabled.log")

            with patch.dict(os.environ, {**base_environment, "EXTERNAL_API_DOCS_ENABLED": "true"}, clear=True):
                enabled = local.build_local_app(log_path=root / "enabled.log",
                                                dark_web_config_path=root / "missing-dark-web.json")
                client = TestClient(enabled)
                self.assertEqual(client.get("/docs").status_code, 200)
                self.assertEqual(client.get("/openapi.json").status_code, 200)
                enabled.state.services.job_runner.shutdown()
                self._close_file_handler(root / "enabled.log")

    def test_runner_logs_safe_internal_failure_context(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "logs" / "cti_tool.log"
            configure_file_logging(log_path)
            runner = InProcessJobRunner(max_workers=1)

            def fail():
                raise RuntimeError("token=must-not-appear article content must-not-appear")

            job = runner.submit("cmd-safe-123", fail, safe_context={"source_id": "the-hacker-news"})
            deadline = time.monotonic() + 5
            while runner.get(job.job_id).state not in {"failed", "completed"} and time.monotonic() < deadline:
                time.sleep(0.01)
            runner.shutdown()
            self._close_file_handler(log_path)
            logged = log_path.read_text(encoding="utf-8")
            self.assertIn(job.job_id, logged)
            self.assertIn("command_id=cmd-safe-123", logged)
            self.assertIn("source_id=the-hacker-news", logged)
            self.assertIn("exception_type=RuntimeError", logged)
            self.assertNotIn("must-not-appear", logged)
            self.assertEqual(runner.get(job.job_id).error["code"], "job_failed")

    @staticmethod
    def _close_file_handler(path: Path) -> None:
        target = path.resolve()
        root = logging.getLogger()
        for handler in tuple(root.handlers):
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename).resolve() == target:
                root.removeHandler(handler)
                handler.close()


if __name__ == "__main__":
    unittest.main()
