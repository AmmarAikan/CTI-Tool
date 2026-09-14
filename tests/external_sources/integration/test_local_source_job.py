from __future__ import annotations

import importlib
import json
import logging
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse
from backend.app.pipeline.ingestion.external.common.logging import (
    configure_file_logging,
)
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult
from backend.app.pipeline.ingestion.external.integration.api import API_PREFIX
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner
from backend.app.pipeline.ingestion.external.rss_connector import RSSConnector

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FIXED_NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


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
    def test_real_canonical_rss_source_job_completes_through_local_adapter(self) -> None:
        feed = (FIXTURES / "rss_feed.xml").read_bytes()

        def connector_factory(source, state):
            return RSSConnector.from_source(
                source,
                state=state,
                http_client=FakeFeedClient(feed),
                crawler=FakeArticleCrawler(),
                clock=lambda: FIXED_NOW,
            )

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
            try:
                accepted = app.state.services.collection_service.collect_source(
                    "the-hacker-news", requested_by="local-regression")
                deadline = time.monotonic() + 5
                terminal = app.state.services.job_runner.get(accepted.job_id)
                while terminal.state not in {"completed", "partial", "failed", "cancelled"} and time.monotonic() < deadline:
                    time.sleep(0.01)
                    terminal = app.state.services.job_runner.get(accepted.job_id)
                self.assertEqual(terminal.state, "completed")
                self.assertEqual(terminal.command_id, accepted.command_id)
                self.assertEqual(terminal.result["source_id"], "the-hacker-news")
                self.assertGreaterEqual(terminal.result["accepted_records"], 1)
                self.assertTrue((root / "state" / "rss_the-hacker-news.json").is_file())
                self.assertTrue(any((root / "processed").glob("rss_the-hacker-news_*.json")))
            finally:
                app.state.services.job_runner.shutdown()
                self._close_file_handler(root / "logs" / "cti_tool.log")

    def test_reddit_registry_requires_all_documented_oauth_settings(self) -> None:
        names = ("REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET", "REDDIT_USER_AGENT")
        base = {"EXTERNAL_API_TOKEN": "registry-test-token", "EXTERNAL_API_ROLES": "operator"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sources.json"
            path.write_text(json.dumps({"social_media_sources":[{"source_id":"reddit-oauth-test","name":"OAuth test","source_type":"reddit","transport":"reddit_oauth","enabled":True,"subreddit":"netsec","max_items":10,"request_timeout_seconds":20,"rate_limit_delay_seconds":1,"fetch_linked_articles":False,"max_response_bytes":100000,"max_redirects":2}]}),encoding="utf-8")
            with patch.dict(os.environ, {**base, **{name: "" for name in names}}, clear=False):
                local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
                public = local.load_collection_registry()["reddit-netsec"]
                self.assertTrue(public.enabled)
                self.assertNotIn("requires_configuration", public.configuration)
                source = local.load_collection_registry(path)["reddit-oauth-test"]
                self.assertFalse(source.enabled)
                self.assertTrue(source.configuration["requires_configuration"])
            with patch.dict(os.environ, {**base, **{name: "configured-for-test" for name in names}}, clear=False):
                source = local.load_collection_registry(path)["reddit-oauth-test"]
                self.assertTrue(source.enabled)
                self.assertNotIn("requires_configuration", source.configuration)

    def test_health_and_exact_job_get_remain_responsive_during_slow_collection(self) -> None:
        started, release = threading.Event(), threading.Event()

        class SlowExecutor:
            def execute(self, source, *, force, command_id):
                del force, command_id
                started.set()
                release.wait(3)
                from backend.app.pipeline.ingestion.external.application.collection_service import SourceExecutionResult
                return SourceExecutionResult(source.source_id, "completed")

        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "EXTERNAL_API_TOKEN": "concurrency-token", "EXTERNAL_API_ROLES": "operator",
            "EXTERNAL_API_DEV_WORKERS": "1",
        }):
            local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
            root = Path(folder)
            app = local.build_local_app(collection_executor=SlowExecutor(), state_directory=root / "state",
                dark_web_config_path=root / "missing.json", processed_directory=root / "processed",
                review_directory=root / "review", exports_directory=root / "exports",
                export_state_path=root / "state" / "exports.json", manual_checkpoint_path=root / "state" / "manual.json",
                log_path=root / "external.log")
            try:
                accepted = app.state.services.collection_service.collect_source(
                    "the-hacker-news", requested_by="concurrency-test")
                self.assertTrue(started.wait(1))
                routes = {route.path: route.endpoint for route in app.routes if hasattr(route, "path")}
                before = time.monotonic()
                health = routes[f"{API_PREFIX}/health"]()
                exact = routes[f"{API_PREFIX}/jobs/{{job_id}}"](accepted.job_id, None)
                self.assertLess(time.monotonic() - before, 0.1)
                self.assertEqual(health.status, "ok")
                self.assertEqual(exact.job_id, accepted.job_id)
            finally:
                release.set()
                app.state.services.job_runner.shutdown()
                self._close_file_handler(root / "external.log")

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
            self.assertNotIn("/docs", {route.path for route in disabled.routes})
            disabled.state.services.job_runner.shutdown()
            self._close_file_handler(root / "disabled.log")

            with patch.dict(os.environ, {**base_environment, "EXTERNAL_API_DOCS_ENABLED": "true"}, clear=True):
                enabled = local.build_local_app(log_path=root / "enabled.log",
                                                dark_web_config_path=root / "missing-dark-web.json")
                paths = {route.path for route in enabled.routes}
                self.assertIn("/docs", paths)
                self.assertIn("/openapi.json", paths)
                self.assertEqual(enabled.openapi()["info"]["version"], "1.0.0")
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

    def test_runner_preserves_only_allowlisted_terminal_failure_classification(self) -> None:
        runner = InProcessJobRunner(max_workers=1)
        try:
            job = runner.submit("cmd-safe-category", lambda: {
                "status": "failed", "error_count": 1,
                "_failure_category": "rate_limited", "_failure_retryable": True,
            })
            deadline = time.monotonic() + 2
            while runner.get(job.job_id).state != "failed" and time.monotonic() < deadline:
                time.sleep(0.01)
            stored = runner.get(job.job_id)
            self.assertEqual((stored.error["code"], stored.error["retryable"]), ("rate_limited", True))
            self.assertNotIn("_failure_category", stored.result)
            unsafe = runner.submit("cmd-unsafe-category", lambda: {
                "status": "failed", "_failure_category": "https://private.invalid/token", "_failure_retryable": True,
            })
            deadline = time.monotonic() + 2
            while runner.get(unsafe.job_id).state != "failed" and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(runner.get(unsafe.job_id).error["code"], "internal_failure")
            self.assertFalse(runner.get(unsafe.job_id).error["retryable"])
        finally:
            runner.shutdown()

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
