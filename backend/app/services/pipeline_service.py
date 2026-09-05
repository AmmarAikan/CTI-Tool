from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.core.config import get_settings
from backend.app.db.models import CorrelationRecord, IndicatorRecord, ThreatEvent
from backend.app.pipeline.correlation.correlator import (
    SimilarityCorrelator,
    SimpleCorrelator,
)
from backend.app.pipeline.enrichment.nvd_client import NVDClient
from backend.app.pipeline.ingestion.external.file_connector import (
    ExternalJsonFileConnector,
)
from backend.app.pipeline.ingestion.external.http_connector import (
    ExternalFeedAPIConnector,
)
from backend.app.pipeline.ingestion.internal.dionaea_connector import (
    DionaeaFileConnector,
)
from backend.app.pipeline.ingestion.internal.dionaea_http_connector import (
    DionaeaAPIConnector,
)
from backend.app.pipeline.ingestion.internal.security_sensor_http_connector import (
    SecuritySensorAPIConnector,
)
from backend.app.pipeline.ingestion.internal.wazuh_connector import WazuhFileConnector
from backend.app.pipeline.ingestion.internal.wazuh_indexer_connector import (
    WazuhIndexerConnector,
)
from backend.app.pipeline.internal_orchestrator import InternalCTIPipeline
from backend.app.pipeline.orchestrator import ExternalCTIPipeline
from backend.app.pipeline.scoring.risk_scorer import RiskScorer
from backend.app.repositories.cti_repository import CTIRepository


class PipelineService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repository = CTIRepository(session)
        self.risk_scorer = RiskScorer()

    @staticmethod
    def integration_status() -> dict[str, Any]:
        settings = get_settings()
        external_control_host = urlparse(
            str(settings.external_control_api_url or "")
        ).hostname
        if external_control_host == "cti-external-control":
            external_control_deployment = "vps_internal"
            external_control_transport = "docker_internal_http"
        elif external_control_host in {"localhost", "127.0.0.1", "::1"}:
            external_control_deployment = "vps_loopback"
            external_control_transport = (
                "ssh_tunnel" if settings.external_control_allow_http else "https"
            )
        else:
            external_control_deployment = "remote_private"
            external_control_transport = (
                "http" if settings.external_control_allow_http else "https"
            )
        return {
            "external_feed": {
                "configured": settings.external_feed_configured,
                "tls_verification": settings.external_feed_verify_tls,
                "hmac_verification": bool(settings.external_feed_hmac_secret),
            },
            "external_control_api": {
                "configured": settings.external_control_configured,
                "deployment_status": external_control_deployment,
                "tls_verification": settings.external_control_verify_tls,
                "transport": external_control_transport,
            },
            "wazuh_indexer": {
                "configured": settings.wazuh_indexer_configured,
                "deployment_status": "deferred_not_deployed",
                "tls_verification": settings.wazuh_indexer_verify_tls,
                "authentication": "bearer" if settings.wazuh_indexer_token else "basic",
            },
            "dionaea_sensor_api": {
                "configured": settings.dionaea_api_configured,
                "tls_verification": settings.dionaea_api_verify_tls,
                "hmac_verification": bool(settings.dionaea_api_hmac_secret),
            },
            "host_auth_sensor_api": {
                "configured": settings.host_auth_api_configured,
                "tls_verification": settings.internal_sensor_verify_tls,
                "hmac_verification": bool(settings.internal_sensor_api_hmac_secret),
            },
            "web_access_sensor_api": {
                "configured": settings.web_access_api_configured,
                "tls_verification": settings.internal_sensor_verify_tls,
                "hmac_verification": bool(settings.internal_sensor_api_hmac_secret),
            },
            "misp": {
                "configured": settings.misp_configured,
                "tls_verification": settings.misp_verify_tls,
            },
        }

    @staticmethod
    def external_feed_health() -> dict[str, Any]:
        settings = get_settings()
        if not settings.external_feed_configured:
            return {"configured": False, "reachable": False}
        return ExternalFeedAPIConnector(
            str(settings.external_feed_url),
            str(settings.external_feed_token),
            hmac_secret=settings.external_feed_hmac_secret,
            verify_tls=settings.external_feed_verify_tls,
            allow_http=settings.external_feed_allow_http,
            require_contract=settings.external_feed_require_contract,
            connect_timeout=settings.external_feed_connect_timeout_seconds,
            read_timeout=settings.external_feed_read_timeout_seconds,
            max_bytes=settings.external_feed_max_bytes,
            max_pages=settings.external_feed_max_pages,
            page_size=settings.external_feed_page_size,
        ).healthcheck()

    @staticmethod
    def wazuh_indexer_health() -> dict[str, Any]:
        settings = get_settings()
        if not settings.wazuh_indexer_configured:
            return {"configured": False, "reachable": False}
        return WazuhIndexerConnector(
            str(settings.wazuh_indexer_url),
            username=settings.wazuh_indexer_username,
            password=settings.wazuh_indexer_password,
            token=settings.wazuh_indexer_token,
            verify_tls=settings.wazuh_indexer_verify_tls,
            allow_http=settings.wazuh_indexer_allow_http,
            timeout=settings.wazuh_indexer_timeout_seconds,
            batch_size=settings.wazuh_indexer_batch_size,
            source_name=settings.wazuh_indexer_name,
            index_pattern=settings.wazuh_index_pattern,
            timestamp_field=settings.wazuh_timestamp_field,
            tiebreaker_field=settings.wazuh_tiebreaker_field,
        ).healthcheck()

    @staticmethod
    def dionaea_api_health() -> dict[str, Any]:
        settings = get_settings()
        if not settings.dionaea_api_configured:
            return {"configured": False, "reachable": False}
        return DionaeaAPIConnector(
            str(settings.dionaea_api_url),
            str(settings.dionaea_api_token),
            source_name=settings.dionaea_sensor_name,
            hmac_secret=settings.dionaea_api_hmac_secret,
            verify_tls=settings.dionaea_api_verify_tls,
            allow_http=settings.dionaea_api_allow_http,
            timeout=settings.dionaea_api_timeout_seconds,
            max_bytes=settings.dionaea_api_max_bytes,
            max_pages=settings.dionaea_api_max_pages,
            page_size=settings.dionaea_api_page_size,
        ).healthcheck()

    @staticmethod
    def security_sensor_health(source_type: str) -> dict[str, Any]:
        settings = get_settings()
        url, source_name, configured = PipelineService._security_sensor_profile(settings, source_type)
        if not configured:
            return {"configured": False, "reachable": False}
        return SecuritySensorAPIConnector(
            str(url),
            str(settings.internal_sensor_api_token),
            source_name=source_name,
            source_type=source_type,
            hmac_secret=settings.internal_sensor_api_hmac_secret,
            verify_tls=settings.internal_sensor_verify_tls,
            allow_http=settings.internal_sensor_allow_http,
            timeout=settings.internal_sensor_timeout_seconds,
            max_bytes=settings.internal_sensor_max_bytes,
            max_pages=settings.internal_sensor_max_pages,
            page_size=settings.internal_sensor_page_size,
        ).healthcheck()

    def run_external_files(self, paths: list[str | Path]) -> dict[str, Any]:
        connector = ExternalJsonFileConnector(paths)
        records = list(connector.collect())
        return self._run_external_records(
            records,
            details={"transport": "file_upload", "paths": [str(path) for path in paths]},
        )

    def run_external_feed(self, connector: ExternalFeedAPIConnector | None = None) -> dict[str, Any]:
        settings = get_settings()
        state_source = self.repository.get_or_create_source(
            "Remote External Feed API",
            "api",
            "external",
        )
        state = dict(state_source.config or {})
        if connector is None:
            if not settings.external_feed_configured:
                raise RuntimeError("EXTERNAL_FEED_URL and EXTERNAL_FEED_TOKEN must be configured")
            connector = ExternalFeedAPIConnector(
                str(settings.external_feed_url),
                str(settings.external_feed_token),
                hmac_secret=settings.external_feed_hmac_secret,
                verify_tls=settings.external_feed_verify_tls,
                allow_http=settings.external_feed_allow_http,
                require_contract=settings.external_feed_require_contract,
                connect_timeout=settings.external_feed_connect_timeout_seconds,
                read_timeout=settings.external_feed_read_timeout_seconds,
                max_bytes=settings.external_feed_max_bytes,
                max_pages=settings.external_feed_max_pages,
                page_size=settings.external_feed_page_size,
                if_none_match=state.get("etag"),
                checkpoint=state.get("checkpoint"),
            )
        records = list(connector.collect())
        result = connector.last_result
        if result is None:
            raise RuntimeError("External feed connector returned no collection result")
        summary = self._run_external_records(records, details=result.details(), run_source=state_source)
        state_source.config = {
            **state,
            "etag": result.etag,
            "checkpoint": result.checkpoint,
            "last_generated_at": result.generated_at,
            "last_run_id": summary["run_id"],
        }
        self.session.commit()
        return summary

    def _run_external_records(
        self,
        records,
        *,
        details: dict[str, Any],
        run_source=None,
    ) -> dict[str, Any]:
        records = list(records)
        run = self.repository.create_run("external", run_source, details=details)
        stored = failed = unchanged = 0
        try:
            raw_context = []
            processable_records = []
            source_cache = {}
            record_sources = []
            external_ids_by_source = {}
            for record in records:
                source = source_cache.get(record.source_name)
                if source is None:
                    source = self.repository.get_or_create_source(
                        record.source_name,
                        record.source_type,
                        "external",
                    )
                    source_cache[record.source_name] = source
                record_sources.append((record, source))
                external_ids_by_source.setdefault(source.id, []).append(record.external_id)

            existing_by_source = {
                source.id: self.repository.get_raw_records(
                    source, external_ids_by_source.get(source.id, [])
                )
                for source in source_cache.values()
            }
            for record, source in record_sources:
                raw_item = existing_by_source.get(source.id, {}).get(record.external_id)
                if raw_item is not None and self.repository.raw_record_is_unchanged(
                    raw_item, source, record
                ):
                    unchanged += 1
                    continue
                raw_item = self.repository.upsert_raw_record(
                    source, record, raw_item, flush=False
                )
                raw_context.append((source, raw_item))
                processable_records.append(record)
            self.session.flush()
            objects = (
                ExternalCTIPipeline().process_batch(processable_records)
                if processable_records
                else []
            )
            for (source, raw_item), cti_object in zip(raw_context, objects):
                cti_object.raw_reference["source_severity"] = cti_object.severity or "unknown"
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
                details={
                    "connector_duplicate_items": int(details.get("duplicate_items", 0)),
                    "database_unchanged_items": unchanged,
                    "changed_or_new_items": len(processable_records),
                    "duplicate_items": int(details.get("duplicate_items", 0)) + unchanged,
                },
            )
            self.session.commit()
            return self._run_summary(run)
        except Exception as exc:
            self.session.rollback()
            raise RuntimeError(f"External pipeline failed: {exc}") from exc

    def run_wazuh_files(self, paths: list[str | Path]) -> dict[str, Any]:
        connector = WazuhFileConnector(paths)
        return self._run_internal_records(
            list(connector.collect()),
            source_name="Wazuh",
            source_type="wazuh",
            details={"transport": "file_upload", "paths": [str(path) for path in paths]},
        )

    def run_dionaea_files(self, paths: list[str | Path]) -> dict[str, Any]:
        connector = DionaeaFileConnector(paths)
        return self._run_internal_records(
            list(connector.collect()),
            source_name="Dionaea Honeypot",
            source_type="dionaea",
            details={"transport": "file_upload", "paths": [str(path) for path in paths]},
        )

    def run_dionaea_api(self, connector: DionaeaAPIConnector | None = None) -> dict[str, Any]:
        settings = get_settings()
        state_source = self.repository.get_or_create_source(
            settings.dionaea_sensor_name,
            "dionaea",
            "internal",
        )
        state = dict(state_source.config or {})
        if connector is None:
            if not settings.dionaea_api_configured:
                raise RuntimeError("DIONAEA_API_URL and DIONAEA_API_TOKEN must be configured")
            connector = DionaeaAPIConnector(
                str(settings.dionaea_api_url),
                str(settings.dionaea_api_token),
                source_name=settings.dionaea_sensor_name,
                hmac_secret=settings.dionaea_api_hmac_secret,
                verify_tls=settings.dionaea_api_verify_tls,
                allow_http=settings.dionaea_api_allow_http,
                timeout=settings.dionaea_api_timeout_seconds,
                max_bytes=settings.dionaea_api_max_bytes,
                max_pages=settings.dionaea_api_max_pages,
                page_size=settings.dionaea_api_page_size,
                checkpoint=state.get("checkpoint"),
            )
        records = list(connector.collect())
        result = connector.last_result
        if result is None:
            raise RuntimeError("Dionaea API connector returned no collection result")
        summary = self._run_internal_records(
            records,
            source_name=settings.dionaea_sensor_name,
            source_type="dionaea",
            details=result.details(),
            source=state_source,
        )
        state_source.config = {
            **state,
            "checkpoint": result.checkpoint,
            "last_generated_at": result.generated_at,
            "last_run_id": summary["run_id"],
        }
        self.session.commit()
        return summary

    def run_security_sensor_api(
        self,
        source_type: str,
        connector: SecuritySensorAPIConnector | None = None,
    ) -> dict[str, Any]:
        settings = get_settings()
        url, source_name, configured = self._security_sensor_profile(settings, source_type)
        state_source = self.repository.get_or_create_source(source_name, source_type, "internal")
        state = dict(state_source.config or {})
        if connector is None:
            if not configured:
                raise RuntimeError(f"{source_type} sensor URL and INTERNAL_SENSOR_API_TOKEN must be configured")
            connector = SecuritySensorAPIConnector(
                str(url),
                str(settings.internal_sensor_api_token),
                source_name=source_name,
                source_type=source_type,
                hmac_secret=settings.internal_sensor_api_hmac_secret,
                verify_tls=settings.internal_sensor_verify_tls,
                allow_http=settings.internal_sensor_allow_http,
                timeout=settings.internal_sensor_timeout_seconds,
                max_bytes=settings.internal_sensor_max_bytes,
                max_pages=settings.internal_sensor_max_pages,
                page_size=settings.internal_sensor_page_size,
                checkpoint=state.get("checkpoint"),
            )
        records = list(connector.collect())
        result = connector.last_result
        if result is None:
            raise RuntimeError(f"{source_type} sensor connector returned no collection result")
        summary = self._run_internal_records(
            records,
            source_name=source_name,
            source_type=source_type,
            details=result.details(),
            source=state_source,
        )
        state_source.config = {
            **state,
            "checkpoint": result.checkpoint,
            "last_generated_at": result.generated_at,
            "last_run_id": summary["run_id"],
        }
        self.session.commit()
        return summary

    @staticmethod
    def _security_sensor_profile(settings, source_type: str):
        if source_type == "linux_auth":
            return (
                settings.host_auth_api_url,
                settings.host_auth_sensor_name,
                settings.host_auth_api_configured,
            )
        if source_type == "web_access":
            return (
                settings.web_access_api_url,
                settings.web_access_sensor_name,
                settings.web_access_api_configured,
            )
        raise ValueError("source_type must be linux_auth or web_access")

    def run_wazuh_indexer(self, connector: WazuhIndexerConnector | None = None) -> dict[str, Any]:
        settings = get_settings()
        state_source = self.repository.get_or_create_source(
            settings.wazuh_indexer_name,
            "wazuh",
            "internal",
        )
        state = dict(state_source.config or {})
        if connector is None:
            if not settings.wazuh_indexer_configured:
                raise RuntimeError("WAZUH_INDEXER_URL and credentials must be configured")
            connector = WazuhIndexerConnector(
                str(settings.wazuh_indexer_url),
                username=settings.wazuh_indexer_username,
                password=settings.wazuh_indexer_password,
                token=settings.wazuh_indexer_token,
                verify_tls=settings.wazuh_indexer_verify_tls,
                allow_http=settings.wazuh_indexer_allow_http,
                timeout=settings.wazuh_indexer_timeout_seconds,
                batch_size=settings.wazuh_indexer_batch_size,
                source_name=settings.wazuh_indexer_name,
                index_pattern=settings.wazuh_index_pattern,
                timestamp_field=settings.wazuh_timestamp_field,
                tiebreaker_field=settings.wazuh_tiebreaker_field,
                since=state.get("last_timestamp") or settings.wazuh_initial_since,
                search_after=state.get("last_sort"),
            )
        records = list(connector.collect())
        result = connector.last_result
        if result is None:
            raise RuntimeError("Wazuh indexer connector returned no collection result")
        summary = self._run_internal_records(
            records,
            source_name=settings.wazuh_indexer_name,
            source_type="wazuh",
            details=result.details(),
            source=state_source,
        )
        state_source.config = {
            **state,
            "last_timestamp": result.last_timestamp,
            "last_sort": result.last_sort,
            "last_run_id": summary["run_id"],
        }
        self.session.commit()
        return summary

    def _run_internal_records(
        self,
        records,
        *,
        source_name: str,
        source_type: str,
        details: dict[str, Any],
        source=None,
    ) -> dict[str, Any]:
        records = list(records)
        source = source or self.repository.get_or_create_source(source_name, source_type, "internal")
        run = self.repository.create_run(
            "internal",
            source,
            {**details, "source_type": source_type},
        )
        try:
            raw_items = [self.repository.upsert_raw_record(source, record) for record in records]
            result = InternalCTIPipeline().process(records)
            event_ids: dict[str, str] = {}
            for cti_object in result.cti_objects:
                cti_object.raw_reference["source_severity"] = cti_object.severity or "unknown"
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
        self.session.flush()
        recalculated = self._recalculate_risk_scores()
        self.session.commit()
        return {
            "simple": len(simple),
            "similarity": len(similarity),
            "total": len(simple) + len(similarity),
            "risk_recalculated": recalculated,
        }

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
        self.session.flush()
        successful = [item for item in results if item.get("found")]
        if successful:
            cvss = max(
                (float(item.get("cvss_score") or 0) for item in successful),
                default=0.0,
            )
            event.raw_reference = {
                **event.raw_reference,
                "nvd_enrichment_count": len(successful),
                "nvd_cvss_score": cvss,
            }
        self._recalculate_risk_scores({event.id})
        self.session.commit()
        return results

    def _recalculate_risk_scores(self, event_ids: set[str] | None = None) -> int:
        """Apply the same explainable formula after enrichment/correlation changes."""
        events = list(
            self.session.scalars(
                select(ThreatEvent).options(
                    selectinload(ThreatEvent.indicators).selectinload(
                        IndicatorRecord.enrichments
                    )
                )
            ).unique()
        )
        indicator_sources: dict[tuple[str, str], set[str]] = {}
        event_indicator_keys: dict[str, set[tuple[str, str]]] = {}
        for current in events:
            keys: set[tuple[str, str]] = set()
            for indicator in current.indicators:
                key = (indicator.indicator_type, indicator.value.lower())
                keys.add(key)
                if current.source_id:
                    indicator_sources.setdefault(key, set()).add(current.source_id)
            event_indicator_keys[current.id] = keys

        correlation_counts = {current.id: 0 for current in events}
        for correlation in self.session.scalars(select(CorrelationRecord)):
            correlation_counts[correlation.event_a_id] = (
                correlation_counts.get(correlation.event_a_id, 0) + 1
            )
            correlation_counts[correlation.event_b_id] = (
                correlation_counts.get(correlation.event_b_id, 0) + 1
            )

        recalculated = 0
        for current in events:
            if event_ids is not None and current.id not in event_ids:
                continue
            source_ids = {
                source_id
                for key in event_indicator_keys[current.id]
                for source_id in indicator_sources.get(key, set())
            }
            if current.source_id:
                source_ids.add(current.source_id)
            enrichments = [
                enrichment.data
                for indicator in current.indicators
                for enrichment in indicator.enrichments
                if enrichment.status == "completed" and isinstance(enrichment.data, dict)
            ]
            risk = self.risk_scorer.score(
                current,
                enrichments=enrichments,
                source_count=max(1, len(source_ids)),
                correlation_count=correlation_counts.get(current.id, 0),
            )
            current.risk_score = risk.score
            current.severity = risk.severity
            current.raw_reference = {
                **(current.raw_reference or {}),
                "risk_factors": risk.factors,
                "risk_context": {
                    "source_count": max(1, len(source_ids)),
                    "correlation_count": correlation_counts.get(current.id, 0),
                },
            }
            recalculated += 1
        self.session.flush()
        return recalculated

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
