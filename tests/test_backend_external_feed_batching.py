from __future__ import annotations

import hashlib
import tracemalloc
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base
from backend.app.db.models import ExternalIngestionOperation, PipelineRun, RawItem, Source, ThreatEvent
from backend.app.pipeline.common.cti_schema import CTIObject, RawRecord
from backend.app.services.pipeline_service import PipelineService


def database_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def record(index: int) -> RawRecord:
    return RawRecord(
        external_id=f"feed-item-{index:05d}",
        source_name="Synthetic External Feed",
        source_type="rss",
        title=f"Threat report {index}",
        content=f"Threat report {index} discusses CVE-2026-{index % 10000:04d}.",
        published_at="2026-09-25T00:00:00Z",
        collected_at="2026-09-25T00:00:00Z",
        raw_data={
            "source_type": "rss",
            "published_at": "2026-09-25T00:00:00Z",
            "category": "advisory",
        },
    )


def cti_object(value: RawRecord) -> CTIObject:
    identity = hashlib.sha256(
        f"{value.source_name}:{value.external_id}".encode("utf-8")
    ).hexdigest()
    return CTIObject(
        object_id=identity,
        source_id=value.external_id,
        source_type=value.source_type,
        source_pipeline="external",
        title=value.title,
        original_text=value.content,
        normalized_text=value.content.lower(),
        classification_label="cti_related",
        classification_confidence=0.99,
        classification_backend="test",
        processing_status="stored",
    )


class FeedResult:
    def __init__(self, values: list[RawRecord], checkpoint: str) -> None:
        self.records = values
        self.checkpoint = checkpoint
        self.etag = f'"{checkpoint}"'
        self.generated_at = "2026-09-25T00:00:00Z"

    def details(self) -> dict[str, object]:
        return {
            "transport": "synthetic_test",
            "pages": 80,
            "response_bytes": 100_000_000,
            "duplicate_items": 0,
        }


class ControlledConnector:
    def __init__(self, values: list[RawRecord], checkpoint: str = "a" * 64) -> None:
        self.last_result = FeedResult(values, checkpoint)
        self.acknowledgements: list[str] = []

    def collect(self):
        yield from self.last_result.records

    def acknowledge(self, checkpoint: str) -> dict[str, object]:
        self.acknowledgements.append(checkpoint)
        return {"status": "acknowledged", "checkpoint": checkpoint}


class NotModifiedConnector:
    def __init__(self, checkpoint: str) -> None:
        self.last_result = SimpleNamespace(
            checkpoint=None,
            etag=f'"{checkpoint}"',
            generated_at=None,
            not_modified=True,
            details=lambda: {
                "transport": "synthetic_test",
                "not_modified": True,
                "duplicate_items": 0,
            },
        )
        self.acknowledgements: list[str] = []

    def collect(self):
        return iter(())

    def acknowledge(self, checkpoint: str):
        self.acknowledgements.append(checkpoint)
        raise AssertionError("a 304 replay must not issue a second acknowledgement")


class ExternalFeedBatchingTests(unittest.TestCase):
    def test_processed_offset_commits_with_batch_and_restart_resumes_next_record(self) -> None:
        engine = database_engine()
        values = [record(index) for index in range(3)]
        settings = SimpleNamespace(external_feed_processing_batch_size=2)
        first_batch = True
        with Session(engine, expire_on_commit=False) as session:
            operation = ExternalIngestionOperation(
                external_job_id="job-offset-123456", export_run_id="run-offset-123456",
                dataset_sha256="d" * 64, state="central_importing", stage="persisting")
            session.add(operation); session.commit()

            def progress(offset, counts):
                current = session.get(ExternalIngestionOperation, operation.id)
                current.processed_offset = offset
                current.imported_count = counts["stored"]

            def fail_second(batch):
                nonlocal first_batch
                if first_batch:
                    first_batch = False
                    return [cti_object(value) for value in batch]
                raise RuntimeError("restart boundary")

            service = PipelineService(session)
            with patch("backend.app.services.pipeline_service.get_settings", return_value=settings), patch(
                "backend.app.services.pipeline_service.ExternalCTIPipeline",
                return_value=SimpleNamespace(process_batch=fail_second)):
                with self.assertRaisesRegex(RuntimeError, "External pipeline failed"):
                    service._run_external_records(values, details={"transport": "restart"},
                                                  progress_callback=progress)
            session.refresh(operation)
            self.assertEqual(operation.processed_offset, 2)
            run = session.scalar(select(PipelineRun))
            self.assertEqual(session.scalar(select(func.count()).select_from(RawItem)), 2)

            with patch("backend.app.services.pipeline_service.get_settings", return_value=settings), patch(
                "backend.app.services.pipeline_service.ExternalCTIPipeline",
                return_value=SimpleNamespace(process_batch=lambda batch: [cti_object(value) for value in batch])):
                service._run_external_records(values, details={"transport": "restart"},
                                              existing_run_id=run.id,
                                              start_offset=operation.processed_offset,
                                              progress_callback=progress)
            session.refresh(operation)
            self.assertEqual(operation.processed_offset, 3)
            self.assertEqual(session.scalar(select(func.count()).select_from(RawItem)), 3)
            self.assertEqual(session.scalar(select(func.count()).select_from(ThreatEvent)), 3)

    def test_not_modified_replay_preserves_checkpoint_without_second_ack(self) -> None:
        engine = database_engine()
        checkpoint = "f" * 64
        settings = SimpleNamespace(external_feed_processing_batch_size=100)
        connector = NotModifiedConnector(checkpoint)
        with Session(engine, expire_on_commit=False) as session:
            session.add(
                Source(
                    name="Remote External Feed API",
                    source_type="api",
                    source_pipeline="external",
                    config={
                        "etag": f'"{checkpoint}"',
                        "checkpoint": checkpoint,
                        "gateway_ack_status": "acknowledged",
                        "gateway_ack_checkpoint": checkpoint,
                    },
                )
            )
            session.commit()
            with patch(
                "backend.app.services.pipeline_service.get_settings",
                return_value=settings,
            ):
                result = PipelineService(session).run_external_feed(connector)
            state = session.scalar(
                select(Source).where(Source.name == "Remote External Feed API")
            )

        self.assertEqual(connector.acknowledgements, [])
        self.assertEqual(state.config["checkpoint"], checkpoint)
        self.assertEqual(state.config["gateway_ack_checkpoint"], checkpoint)
        self.assertTrue(result["details"]["gateway_ack_replayed"])

    def test_cpu_processing_runs_without_transaction_and_commits_bounded_batches(self) -> None:
        engine = database_engine()
        values = [record(index) for index in range(5)]
        observed_transaction_states: list[bool] = []

        with Session(engine, expire_on_commit=False) as session:
            def process(batch):
                observed_transaction_states.append(session.in_transaction())
                return [cti_object(value) for value in batch]

            processor = SimpleNamespace(process_batch=Mock(side_effect=process))
            settings = SimpleNamespace(external_feed_processing_batch_size=2)
            connector = ControlledConnector(values)
            with patch(
                "backend.app.services.pipeline_service.get_settings",
                return_value=settings,
            ), patch(
                "backend.app.services.pipeline_service.ExternalCTIPipeline",
                return_value=processor,
            ), patch.object(
                PipelineService,
                "run_correlations",
                side_effect=AssertionError("global correlation must not run during ingestion"),
            ):
                result = PipelineService(session).run_external_feed(connector)

            run = session.get(PipelineRun, result["run_id"])
            raw_count = session.scalar(select(func.count()).select_from(RawItem))
            event_count = session.scalar(select(func.count()).select_from(ThreatEvent))

        self.assertEqual(observed_transaction_states, [False, False, False])
        self.assertEqual(processor.process_batch.call_count, 3)
        self.assertEqual(run.details["committed_batches"], 3)
        self.assertEqual(run.details["processing_batch_size"], 2)
        self.assertEqual(run.details["correlation_status"], "deferred_bounded_ingestion")
        self.assertEqual((raw_count, event_count), (5, 5))
        self.assertEqual(connector.acknowledgements, ["a" * 64])

    def test_partial_durable_progress_replays_idempotently_and_acks_once(self) -> None:
        engine = database_engine()
        values = [record(index) for index in range(3)]
        settings = SimpleNamespace(external_feed_processing_batch_size=2)
        failed_connector = ControlledConnector(values, "b" * 64)
        first_batch = True

        with Session(engine, expire_on_commit=False) as session:
            def fail_second_batch(batch):
                nonlocal first_batch
                if first_batch:
                    first_batch = False
                    return [cti_object(value) for value in batch]
                raise RuntimeError("synthetic second batch failure")

            with patch(
                "backend.app.services.pipeline_service.get_settings",
                return_value=settings,
            ), patch(
                "backend.app.services.pipeline_service.ExternalCTIPipeline",
                return_value=SimpleNamespace(process_batch=fail_second_batch),
            ):
                with self.assertRaisesRegex(RuntimeError, "External pipeline failed"):
                    PipelineService(session).run_external_feed(failed_connector)

            self.assertEqual(
                session.scalar(select(func.count()).select_from(RawItem)), 2
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(ThreatEvent)), 2
            )
            self.assertEqual(failed_connector.acknowledgements, [])
            state = session.scalar(
                select(Source).where(Source.name == "Remote External Feed API")
            )
            self.assertIsNone((state.config or {}).get("checkpoint"))
            failed_run = session.scalar(
                select(PipelineRun)
                .where(PipelineRun.status == "failed")
                .order_by(PipelineRun.started_at.desc())
            )
            self.assertEqual(failed_run.details["committed_batches"], 1)

            replay_processor = Mock(
                side_effect=lambda batch: [cti_object(value) for value in batch]
            )
            successful_connector = ControlledConnector(values, "b" * 64)
            with patch(
                "backend.app.services.pipeline_service.get_settings",
                return_value=settings,
            ), patch(
                "backend.app.services.pipeline_service.ExternalCTIPipeline",
                return_value=SimpleNamespace(process_batch=replay_processor),
            ):
                successful = PipelineService(session).run_external_feed(
                    successful_connector
                )

            self.assertEqual(replay_processor.call_count, 1)
            self.assertEqual(len(replay_processor.call_args.args[0]), 1)
            self.assertEqual(
                session.scalar(select(func.count()).select_from(RawItem)), 3
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(ThreatEvent)), 3
            )
            self.assertEqual(successful_connector.acknowledgements, ["b" * 64])
            state = session.scalar(
                select(Source).where(Source.name == "Remote External Feed API")
            )
            self.assertEqual(state.config["checkpoint"], "b" * 64)
            self.assertEqual(state.config["gateway_ack_status"], "acknowledged")
            self.assertEqual(successful["details"]["gateway_ack_status"], "acknowledged")

            idempotent_connector = ControlledConnector(values, "b" * 64)
            with patch(
                "backend.app.services.pipeline_service.get_settings",
                return_value=settings,
            ), patch(
                "backend.app.services.pipeline_service.ExternalCTIPipeline"
            ) as pipeline_factory:
                replayed = PipelineService(session).run_external_feed(
                    idempotent_connector
                )

            pipeline_factory.assert_not_called()
            self.assertEqual(idempotent_connector.acknowledgements, [])
            self.assertTrue(replayed["details"]["gateway_ack_replayed"])
            self.assertEqual(
                session.scalar(select(func.count()).select_from(RawItem)), 3
            )

    def test_twenty_thousand_record_orchestration_is_bounded(self) -> None:
        engine = database_engine()
        settings = SimpleNamespace(external_feed_processing_batch_size=128)
        values = [record(index) for index in range(20_000)]
        processor = SimpleNamespace(
            process_batch=Mock(side_effect=lambda batch: [object() for _ in batch])
        )

        with Session(engine, expire_on_commit=False) as session:
            service = PipelineService(session)

            def compare(batch):
                session.commit()
                return list(batch), 0

            def persist(batch, _objects):
                session.commit()
                return {
                    "unchanged": 0,
                    "created": len(batch),
                    "updated": 0,
                    "stored": len(batch),
                    "failed": 0,
                    "event_ids": [],
                }

            tracemalloc.start()
            with patch(
                "backend.app.services.pipeline_service.get_settings",
                return_value=settings,
            ), patch(
                "backend.app.services.pipeline_service.ExternalCTIPipeline",
                return_value=processor,
            ), patch.object(service, "_external_batch_changes", side_effect=compare), patch.object(
                service, "_persist_external_batch", side_effect=persist
            ):
                result = service._run_external_records(
                    values, details={"transport": "20k_synthetic"}
                )
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        self.assertEqual(result["collected_count"], 20_000)
        self.assertEqual(result["stored_count"], 20_000)
        self.assertEqual(result["details"]["committed_batches"], 157)
        self.assertEqual(processor.process_batch.call_count, 157)
        self.assertLessEqual(
            max(len(call.args[0]) for call in processor.process_batch.call_args_list),
            128,
        )
        self.assertLess(peak, 64 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
