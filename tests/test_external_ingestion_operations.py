from __future__ import annotations

import threading
import tempfile
import unittest
import re
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from fastapi import HTTPException
from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base
from backend.app.db.models import ExternalIngestionOperation, PipelineRun
from backend.app.db.migrations import apply_additive_migrations
from backend.app.pipeline.ingestion.external.http_connector import ExternalFeedResult
from backend.app.services.external_ingestion_service import (FAIRNESS_INTERACTIVE_LIMIT,
    ExternalIngestionService, _claim_next, _ensure_gateway_operation, _retry_state)


IDENTITY = ("job-operation-123456", "ext-operation-123456", "a" * 64)
SQL_MIGRATION = (Path(__file__).resolve().parents[1]
                 / "backend/migrations/20260927_add_external_ingestion_operations.sql")


def execute_postgres_migration_on_sqlite(connection: sqlite3.Connection) -> None:
    """Execute the checked-in SQL, adapting only SQLite's missing IF NOT EXISTS syntax."""
    sql = re.sub(r"(?m)^\s*--.*$", "", SQL_MIGRATION.read_text(encoding="utf-8"))
    for raw_statement in sql.split(";"):
        statement = raw_statement.strip()
        if not statement:
            continue
        match = re.fullmatch(
            r"ALTER TABLE\s+(\w+)\s+ADD COLUMN IF NOT EXISTS\s+(\w+)\s+(.+)",
            statement, flags=re.IGNORECASE | re.DOTALL)
        if match:
            table, column, declaration = match.groups()
            existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
            continue
        connection.execute(statement)
    connection.commit()


def engine():
    value = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(value)
    return value


class Client:
    def get_job(self, job_id):
        return {"state": "completed", "result": {"accepted_records": 0, "export": {
            "status": "completed", "run_id": IDENTITY[1], "dataset_sha256": IDENTITY[2],
            "accepted_records": 15}}}


class ExternalIngestionOperationTests(unittest.TestCase):
    def test_legacy_manual_writers_are_gone(self):
        from backend.app.api.v1.router import pull_external_feed, sync_external_accepted
        with Session(engine()) as session:
            for endpoint in (pull_external_feed, sync_external_accepted):
                with self.assertRaises(HTTPException) as caught:
                    endpoint(session, SimpleNamespace())
                self.assertEqual(caught.exception.status_code, 410)
                self.assertEqual(caught.exception.detail["code"], "legacy_writer_disabled")

    def test_additive_migration_handles_fresh_existing_and_repeated_schema(self):
        fresh = create_engine("sqlite://", poolclass=StaticPool)
        apply_additive_migrations(fresh)
        self.assertIn("external_ingestion_operations", inspect(fresh).get_table_names())
        apply_additive_migrations(fresh)
        existing = create_engine("sqlite://", poolclass=StaticPool)
        Base.metadata.create_all(existing, tables=[table for table in Base.metadata.sorted_tables
                                                  if table.name != "external_ingestion_operations"])
        self.assertNotIn("external_ingestion_operations", inspect(existing).get_table_names())
        with Session(existing) as session:
            session.add(PipelineRun(id="preserved-run", pipeline="external", status="completed")); session.commit()
        apply_additive_migrations(existing)
        apply_additive_migrations(existing)
        with Session(existing) as session:
            self.assertIsNotNone(session.get(PipelineRun, "preserved-run"))

    def test_actual_sql_migration_evolves_existing_table_idempotently(self):
        sql = SQL_MIGRATION.read_text(encoding="utf-8")
        priority_column = sql.index("ADD COLUMN IF NOT EXISTS priority")
        priority_index = sql.index("CREATE INDEX IF NOT EXISTS ix_external_ingestion_operations_priority")
        self.assertLess(priority_column, priority_index)

        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript("""
            CREATE TABLE pipeline_runs (id VARCHAR(36) PRIMARY KEY);
            CREATE TABLE external_ingestion_operations (
                id VARCHAR(36) PRIMARY KEY,
                operation_type VARCHAR(40) NOT NULL DEFAULT 'external_ingestion',
                state VARCHAR(30) NOT NULL DEFAULT 'queued',
                stage VARCHAR(40) NOT NULL DEFAULT 'export_ready',
                retryable BOOLEAN NOT NULL DEFAULT TRUE,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                external_job_id VARCHAR(200) NOT NULL,
                export_run_id VARCHAR(200) NOT NULL,
                dataset_sha256 VARCHAR(64) NOT NULL,
                gateway_checkpoint VARCHAR(200),
                pipeline_run_id VARCHAR(36),
                collected_count INTEGER NOT NULL DEFAULT 0,
                exported_count INTEGER NOT NULL DEFAULT 0,
                imported_count INTEGER NOT NULL DEFAULT 0,
                created_count INTEGER NOT NULL DEFAULT 0,
                updated_count INTEGER NOT NULL DEFAULT 0,
                unchanged_count INTEGER NOT NULL DEFAULT 0,
                failed_count INTEGER NOT NULL DEFAULT 0,
                acknowledged_count INTEGER NOT NULL DEFAULT 0,
                error_code VARCHAR(100), error_category VARCHAR(100), claim_token VARCHAR(36),
                lease_expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMPTZ,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMPTZ,
                CONSTRAINT uq_external_ingestion_identity UNIQUE
                    (external_job_id, export_run_id, dataset_sha256)
            );
            CREATE INDEX ix_legacy_external_state ON external_ingestion_operations(state);
            INSERT INTO external_ingestion_operations
                (id, external_job_id, export_run_id, dataset_sha256, imported_count)
            VALUES ('legacy-operation', 'legacy-job', 'legacy-run',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 37);
        """)
        execute_postgres_migration_on_sqlite(connection)
        execute_postgres_migration_on_sqlite(connection)

        columns = {row[1]: row for row in connection.execute(
            "PRAGMA table_info(external_ingestion_operations)")}
        for name, expected_default in {
            "priority": "100", "processed_offset": "0", "fairness_skips": "0",
        }.items():
            self.assertIn(name, columns)
            self.assertEqual(columns[name][3], 1)
            self.assertEqual(columns[name][4], expected_default)
        row = connection.execute("""
            SELECT id, external_job_id, export_run_id, dataset_sha256, imported_count,
                   priority, processed_offset, fairness_skips
            FROM external_ingestion_operations WHERE id='legacy-operation'
        """).fetchone()
        self.assertEqual(row, (
            "legacy-operation", "legacy-job", "legacy-run", "a" * 64, 37, 100, 0, 0))
        indexes = {row[1] for row in connection.execute(
            "PRAGMA index_list(external_ingestion_operations)")}
        self.assertIn("ix_legacy_external_state", indexes)
        self.assertIn("ix_external_ingestion_operations_priority", indexes)

    def test_actual_sql_migration_installs_empty_schema_idempotently(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE pipeline_runs (id VARCHAR(36) PRIMARY KEY)")
        execute_postgres_migration_on_sqlite(connection)
        execute_postgres_migration_on_sqlite(connection)
        columns = {row[1] for row in connection.execute(
            "PRAGMA table_info(external_ingestion_operations)")}
        self.assertTrue({"priority", "processed_offset", "fairness_skips"}.issubset(columns))
        indexes = {row[1] for row in connection.execute(
            "PRAGMA index_list(external_ingestion_operations)")}
        self.assertIn("ix_external_ingestion_operations_priority", indexes)

    def test_repeated_and_concurrent_commands_converge_on_one_operation(self):
        db = engine()
        with Session(db) as session:
            first = ExternalIngestionService(session, Client()).create_or_resume(IDENTITY[0]).id
            second = ExternalIngestionService(session, Client()).create_or_resume(IDENTITY[0]).id
            self.assertEqual(first, second)
            self.assertEqual(session.scalar(select(func.count()).select_from(ExternalIngestionOperation)), 1)

        with tempfile.TemporaryDirectory() as folder:
            concurrent_db = create_engine(f"sqlite:///{folder}/operations.sqlite3")
            Base.metadata.create_all(concurrent_db)
            ids = []
            barrier = threading.Barrier(2)
            def create():
                with Session(concurrent_db) as session:
                    barrier.wait()
                    ids.append(ExternalIngestionService(session, Client()).create_or_resume(IDENTITY[0]).id)
            threads = [threading.Thread(target=create) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(len(set(ids)), 1)
            with Session(concurrent_db) as session:
                self.assertEqual(session.scalar(select(func.count()).select_from(ExternalIngestionOperation)), 1)

    def test_zero_new_collection_preserves_completed_export_count(self):
        with Session(engine()) as session:
            operation = ExternalIngestionService(session, Client()).create_or_resume(IDENTITY[0])
            self.assertEqual(operation.collected_count, 0)
            self.assertEqual(operation.exported_count, 15)

    def test_database_claim_is_atomic_and_stale_lease_is_recoverable(self):
        db = engine()
        with Session(db) as session:
            operation = ExternalIngestionService(session, Client()).create_or_resume(IDENTITY[0])
            first = _claim_next(session)
            self.assertEqual(first.id, operation.id)
            operation_id, first_token = operation.id, first.claim_token
        with Session(db) as second:
            self.assertIsNone(_claim_next(second))
            claimed = second.get(ExternalIngestionOperation, operation_id)
            claimed.lease_expires_at = claimed.created_at
            second.commit()
            recovered = _claim_next(second)
            self.assertEqual(recovered.id, operation_id)
            self.assertNotEqual(recovered.claim_token, first_token)

    def test_interactive_fifo_and_durable_backlog_fairness(self):
        db = engine()
        with Session(db) as session:
            backlog = ExternalIngestionOperation(
                external_job_id="gateway-legacy-backlog", export_run_id="gateway-backlog-run",
                dataset_sha256="b" * 64, priority=0, state="published", stage="published")
            session.add(backlog)
            interactive = []
            for index in range(FAIRNESS_INTERACTIVE_LIMIT + 1):
                value = ExternalIngestionOperation(
                    external_job_id=f"job-interactive-{index:04d}",
                    export_run_id=f"run-interactive-{index:04d}", dataset_sha256=f"{index:064x}",
                    priority=100, state="published", stage="published")
                session.add(value); interactive.append(value)
            session.commit()
            for expected in interactive[:FAIRNESS_INTERACTIVE_LIMIT]:
                claimed = _claim_next(session)
                self.assertEqual(claimed.id, expected.id)
                claimed.state, claimed.claim_token, claimed.lease_expires_at = "completed", None, None
                session.commit()
            session.refresh(backlog)
            self.assertEqual(backlog.fairness_skips, FAIRNESS_INTERACTIVE_LIMIT)
            claimed = _claim_next(session)
            self.assertEqual(claimed.id, backlog.id)
            self.assertEqual(claimed.fairness_skips, 0)
            claimed.state, claimed.claim_token, claimed.lease_expires_at = "completed", None, None
            session.commit()
            self.assertEqual(_claim_next(session).id, interactive[-1].id)

    def test_concurrent_claimers_never_receive_same_operation(self):
        with tempfile.TemporaryDirectory() as folder:
            db = create_engine(f"sqlite:///{folder}/claims.sqlite3")
            Base.metadata.create_all(db)
            with Session(db) as session:
                session.add_all([ExternalIngestionOperation(
                    external_job_id=f"job-claim-{index:04d}", export_run_id=f"run-claim-{index:04d}",
                    dataset_sha256=f"{index:064x}") for index in range(2)])
                session.commit()
            claimed_ids: list[str] = []
            barrier = threading.Barrier(2)
            def claim() -> None:
                with Session(db) as session:
                    barrier.wait()
                    value = _claim_next(session)
                    if value is not None:
                        claimed_ids.append(value.id)
            threads = [threading.Thread(target=claim) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(len(claimed_ids), len(set(claimed_ids)))

    def test_3059_backlog_yields_to_15_record_job_then_resumes_checkpoint(self):
        with Session(engine()) as session:
            backlog = ExternalIngestionOperation(
                external_job_id="gateway-legacy-3059", export_run_id="gateway-backlog-3059",
                dataset_sha256="3" * 64, priority=0, state="published", stage="published",
                exported_count=3059)
            interactive = ExternalIngestionOperation(
                external_job_id="job-ui-15-records", export_run_id="run-ui-15-records",
                dataset_sha256="f" * 64, priority=100, state="published", stage="published",
                exported_count=15)
            session.add_all([backlog, interactive]); session.commit()
            first = _claim_next(session)
            self.assertEqual(first.id, interactive.id)
            first.state, first.stage = "completed", "completed"
            first.processed_offset = first.acknowledged_count = 15
            first.claim_token = first.lease_expires_at = None
            session.commit()
            second = _claim_next(session)
            self.assertEqual(second.id, backlog.id)
            second.state, second.stage, second.processed_offset = "central_importing", "persisting", 250
            second.claim_token = second.lease_expires_at = None
            session.commit()
            resumed = _claim_next(session)
            self.assertEqual(resumed.id, backlog.id)
            self.assertEqual(resumed.processed_offset, 250)
            self.assertEqual(interactive.acknowledged_count, 15)
            self.assertEqual(backlog.acknowledged_count, 0)

    def test_worker_adopts_modern_and_legacy_gateway_checkpoints(self):
        db = engine()
        modern = ExternalFeedResult(checkpoint="b" * 64, external_job_id=IDENTITY[0],
            export_run_id=IDENTITY[1], dataset_sha256=IDENTITY[2])
        with Session(db) as session, patch(
            "backend.app.services.external_ingestion_service.PipelineService.external_feed_connector",
            return_value=SimpleNamespace(fetch=Mock(return_value=modern))):
            _ensure_gateway_operation(session)
            operation = session.scalar(select(ExternalIngestionOperation))
            self.assertEqual((operation.external_job_id, operation.export_run_id,
                              operation.dataset_sha256, operation.state), (*IDENTITY, "published"))
            _ensure_gateway_operation(session)
            self.assertEqual(session.scalar(select(func.count()).select_from(ExternalIngestionOperation)), 1)

        legacy_db = engine()
        legacy = ExternalFeedResult(checkpoint="c" * 64)
        with Session(legacy_db) as session, patch(
            "backend.app.services.external_ingestion_service.PipelineService.external_feed_connector",
            return_value=SimpleNamespace(fetch=Mock(return_value=legacy))):
            _ensure_gateway_operation(session)
            operation = session.scalar(select(ExternalIngestionOperation))
            self.assertTrue(operation.external_job_id.startswith("gateway-legacy-"))
            self.assertEqual(operation.gateway_checkpoint, "c" * 64)

    def test_digest_conflict_fails_closed(self):
        client = Client()
        client.get_job = Mock(return_value={"state": "completed", "result": {"export": {
            "run_id": IDENTITY[1], "dataset_sha256": "not-a-digest"}}})
        with Session(engine()) as session:
            with self.assertRaisesRegex(ValueError, "external_job_export_invalid"):
                ExternalIngestionService(session, client).create_or_resume(IDENTITY[0])

    def test_ack_failure_after_commit_retries_ack_without_pipeline_run(self):
        with Session(engine()) as session:
            run = PipelineRun(pipeline="external", status="completed")
            session.add(run); session.flush()
            operation = ExternalIngestionOperation(external_job_id=IDENTITY[0], export_run_id=IDENTITY[1],
                dataset_sha256=IDENTITY[2], state="committed", stage="committed",
                gateway_checkpoint="b" * 64, pipeline_run_id=run.id, exported_count=15,
                imported_count=15)
            session.add(operation); session.commit()
            with patch("backend.app.services.external_ingestion_service.PipelineService.external_feed_connector",
                       return_value=SimpleNamespace()), patch(
                "backend.app.services.external_ingestion_service.PipelineService.acknowledge_external_feed",
                side_effect=requests.ConnectionError("private")):
                ExternalIngestionService(session, None).process(operation)
            session.refresh(operation)
            self.assertEqual(operation.state, "failed_retryable")
            self.assertEqual(operation.stage, "acknowledging")
            self.assertEqual(_retry_state(operation.stage), "acknowledging")
            self.assertEqual(session.scalar(select(func.count()).select_from(PipelineRun)), 1)

            operation.state = _retry_state(operation.stage); session.commit()
            with patch("backend.app.services.external_ingestion_service.PipelineService.external_feed_connector",
                       return_value=SimpleNamespace()), patch(
                "backend.app.services.external_ingestion_service.PipelineService.acknowledge_external_feed",
                return_value={"status": "acknowledged", "checkpoint": "b" * 64}):
                ExternalIngestionService(session, None).process(operation)
            session.refresh(operation)
            self.assertEqual(operation.state, "completed")
            self.assertEqual(operation.acknowledged_count, 15)
            self.assertEqual(session.scalar(select(func.count()).select_from(PipelineRun)), 1)


if __name__ == "__main__":
    unittest.main()
