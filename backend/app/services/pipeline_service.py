from __future__ import annotations

from pathlib import Path
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.db.models import ThreatEvent
from backend.app.pipeline.correlation.correlator import (
    SimilarityCorrelator,
    SimpleCorrelator,
)
from backend.app.pipeline.enrichment.nvd_client import NVDClient
from backend.app.pipeline.ingestion.external.file_connector import (
    ExternalJsonFileConnector,
)
from backend.app.pipeline.ingestion.internal.base_internal_connector import (
    InternalConnector,
)
from backend.app.pipeline.ingestion.internal.dionaea_connector import (
    DionaeaFileConnector,
)
from backend.app.pipeline.ingestion.internal.wazuh_connector import WazuhFileConnector
from backend.app.pipeline.internal_orchestrator import InternalCTIPipeline
from backend.app.pipeline.orchestrator import ExternalCTIPipeline
from backend.app.pipeline.scoring.risk_scorer import RiskScorer
from backend.app.repositories.cti_repository import CTIRepository


class PipelineService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repository = CTIRepository(session)
        self.risk_scorer = RiskScorer()

    def run_external_files(self, paths: list[str | Path]) -> dict[str, Any]:
        connector = ExternalJsonFileConnector(paths)
        records = list(connector.collect())
        run = self.repository.create_run("external", details={"paths": [str(path) for path in paths]})
        stored = failed = 0
        try:
            raw_context = []
            for record in records:
                source = self.repository.get_or_create_source(
                    record.source_name,
                    record.source_type,
                    "external",
                )
                raw_item = self.repository.upsert_raw_record(source, record)
                raw_context.append((source, raw_item))
            objects = ExternalCTIPipeline().process_batch(records)
            for (source, raw_item), cti_object in zip(raw_context, objects):
                risk = self.risk_scorer.score(cti_object)
                cti_object.severity = risk.severity
                cti_object.raw_reference["risk_factors"] = risk.factors
                self.repository.upsert_cti_object(source, cti_object, raw_item, risk.score)
                if cti_object.processing_status == "failed":
                    failed += 1
                else:
                    stored += 1
            status = "completed_with_errors" if failed else "completed"
            self.repository.finish_run(
                run,
                status=status,
                collected=len(records),
                processed=len(objects),
                stored=stored,
                failed=failed,
            )
            self.session.commit()
            return self._run_summary(run)
        except Exception as exc:
            self.session.rollback()
            raise RuntimeError(f"External pipeline failed: {exc}") from exc

    def run_wazuh_files(self, paths: list[str | Path]) -> dict[str, Any]:
        return self._run_internal_files(
            WazuhFileConnector(paths),
            source_name="Wazuh",
            source_type="wazuh",
            paths=paths,
        )

    def run_dionaea_files(self, paths: list[str | Path]) -> dict[str, Any]:
        return self._run_internal_files(
            DionaeaFileConnector(paths),
            source_name="Dionaea Honeypot",
            source_type="dionaea",
            paths=paths,
        )

    def _run_internal_files(
        self,
        connector: InternalConnector,
        *,
        source_name: str,
        source_type: str,
        paths: list[str | Path],
    ) -> dict[str, Any]:
        records = list(connector.collect())
        source = self.repository.get_or_create_source(source_name, source_type, "internal")
        run = self.repository.create_run(
            "internal",
            source,
            {"paths": [str(path) for path in paths], "source_type": source_type},
        )
        try:
            raw_items = [self.repository.upsert_raw_record(source, record) for record in records]
            result = InternalCTIPipeline().process(records)
            event_ids: dict[str, str] = {}
            for cti_object in result.cti_objects:
                risk = self.risk_scorer.score(cti_object)
                cti_object.severity = risk.severity
                cti_object.raw_reference["risk_factors"] = risk.factors
                event = self.repository.upsert_cti_object(source, cti_object, risk_score=risk.score)
                event_ids[cti_object.source_id] = event.id
            for detection in result.detections:
                session = detection.session
                self.repository.store_outlier_session(
                    session_id=session.session_id,
                    source=source,
                    source_ip=session.source_ip,
                    started_at=session.started_at,
                    ended_at=session.ended_at,
                    features=detection.features,
                    is_outlier=detection.is_outlier,
                    anomaly_score=detection.anomaly_score,
                    detector_backend=detection.backend,
                    alerts=session.raw_alerts,
                    event_id=event_ids.get(session.session_id),
                )
            self.repository.finish_run(
                run,
                status="completed",
                collected=len(records),
                processed=len(result.detections),
                stored=len(raw_items) + len(result.detections) + len(result.cti_objects),
                failed=0,
                details={
                    "session_count": len(result.detections),
                    "outlier_count": sum(item.is_outlier for item in result.detections),
                    "event_count": len(result.cti_objects),
                },
            )
            self.session.commit()
            return self._run_summary(run)
        except Exception as exc:
            self.session.rollback()
            raise RuntimeError(f"Internal {source_name} pipeline failed: {exc}") from exc

    def run_correlations(self, similarity_threshold: float = 0.35) -> dict[str, int]:
        events = list(
            self.session.scalars(
                select(ThreatEvent).options(selectinload(ThreatEvent.indicators))
            ).unique()
        )
        simple = SimpleCorrelator().correlate(events)
        similarity = SimilarityCorrelator(similarity_threshold).correlate(events)
        for candidate in [*simple, *similarity]:
            self.repository.upsert_correlation(
                candidate.event_a_id,
                candidate.event_b_id,
                candidate.correlation_type,
                candidate.score,
                candidate.reason,
                candidate.evidence,
            )
        self.session.commit()
        return {"simple": len(simple), "similarity": len(similarity), "total": len(simple) + len(similarity)}

    def enrich_event_cves(self, event_id: str, client: NVDClient | None = None) -> list[dict[str, Any]]:
        event = self.repository.get_event(event_id)
        if event is None:
            raise LookupError(event_id)
        client = client or NVDClient()
        results = []
        for indicator in event.indicators:
            if indicator.indicator_type != "cve":
                continue
            try:
                data = client.fetch_cve(indicator.value)
                status = "completed" if data.get("found") else "not_found"
            except (requests.RequestException, ValueError, TypeError, KeyError) as exc:
                data = {"cve_id": indicator.value, "error": str(exc)}
                status = "failed"
            self.repository.upsert_enrichment(indicator, "NVD", data, status)
            results.append(data)
        successful = [item for item in results if item.get("found")]
        if successful:
            cvss = max((float(item.get("cvss_score") or 0) for item in successful), default=0.0)
            score = min(100.0, cvss * 4.0 + len(event.indicators) * 3.0 + event.confidence * 10.0)
            event.risk_score = round(score, 2)
            event.severity = RiskScorer.severity_for(score)
            event.raw_reference = {
                **event.raw_reference,
                "nvd_enrichment_count": len(successful),
                "nvd_cvss_score": cvss,
            }
        self.session.commit()
        return results

    def _run_summary(self, run) -> dict[str, Any]:
        return {
            "run_id": run.id,
            "pipeline": run.pipeline,
            "status": run.status,
            "collected_count": run.collected_count,
            "processed_count": run.processed_count,
            "stored_count": run.stored_count,
            "failed_count": run.failed_count,
            "details": run.details,
        }
