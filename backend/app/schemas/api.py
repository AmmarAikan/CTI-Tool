from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class BootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=10, max_length=200)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    password: str = Field(min_length=12, max_length=200)


class RegisteredUserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    username: str = Field(max_length=100)
    role: Literal["viewer"]
    is_active: bool


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=10, max_length=200)
    role: Literal["admin", "analyst", "viewer"] = "analyst"


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    source_type: str = Field(min_length=2, max_length=50)
    source_pipeline: Literal["external", "internal"]
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class CorrelationRequest(BaseModel):
    similarity_threshold: float = Field(default=0.35, ge=0.0, le=1.0)


class MISPSendRequest(BaseModel):
    dry_run: bool = True


class ExternalCollectionStartRequest(BaseModel):
    source_ids: list[str] = Field(default_factory=list, max_length=100)
    scope: Literal["all_enabled"] | None = None
    force: bool = False


class ExternalSourceRunRequest(BaseModel):
    force: bool = False


class ExternalManualSourceRequest(BaseModel):
    url: HttpUrl
    force: bool = False


class ExternalManualRecheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root_id: str = Field(min_length=16, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    force: bool = False


class ExternalManualPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: HttpUrl


class ExternalManualPreviewApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ExternalManualPreviewRejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Literal["not_relevant", "duplicate", "user_cancelled"]


class ExternalReviewDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decision: Literal["approved", "rejected"]
    reason: Literal["not_relevant", "duplicate", "privacy_risk", "low_quality"] | None = None


class ExternalReviewLifecycleItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str = Field(min_length=16, max_length=100)
    review_id: str = Field(min_length=16, max_length=100)
    content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    external_job_id: str | None = Field(default=None, max_length=100)
    export_run_id: str | None = Field(default=None, max_length=200)
    dataset_sha256: str | None = Field(default=None, pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    central_run_id: str | None = Field(default=None, max_length=64)
    state: Literal["pending_review", "approved_processing", "processed", "rejected", "processing_failed"]
    stage: Literal["review", "export", "central_import", "processed"]
    retryable: bool
    updated_at: str = Field(max_length=40)


class ExternalReviewLifecycleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    items: list[ExternalReviewLifecycleItemResponse] = Field(max_length=1000)


class ExternalManualPreviewItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    item_index: int = Field(ge=1)
    title: str = Field(max_length=200)
    excerpt: str = Field(max_length=300)
    page_type: Literal["article"]
    disposition: Literal["accepted", "review", "rejected"]
    classification_label: str | None = Field(default=None, max_length=80)
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    privacy_status: Literal["reviewed", "review_required"]
    review_reasons: list[Literal["privacy_review", "classification_review", "relevance_rejected"]] = Field(max_length=3)
    content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    published: str | None = Field(default=None, max_length=40)


class ExternalManualPreviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    preview_id: str = Field(min_length=20)
    state: Literal["pending"]
    created_at: str
    expires_at: str
    display_url: str = Field(max_length=400)
    page_type: str = Field(max_length=80)
    title: str = Field(max_length=300)
    excerpt: str = Field(max_length=500)
    disposition: Literal["accepted", "review", "rejected"]
    classification_label: str | None = Field(default=None, max_length=80)
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    privacy_status: Literal["reviewed", "review_required"]
    review_reasons: list[Literal["privacy_review", "classification_review", "relevance_rejected"]]
    content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    items_preview: list[ExternalManualPreviewItemResponse] = Field(max_length=20)
    items_preview_total: int = Field(ge=0)
    items_preview_truncated: bool
    counts: dict[str, int]
    detected_type: Literal["json_collection"] | None = None
    collection_path: list[str] | None = Field(default=None, max_length=4)
    proposed_mapping: dict[str, str] | None = Field(default=None, max_length=9)
    validation_warnings: list[Literal["explicit_approval_required", "empty_collection"]] | None = Field(default=None, max_length=4)
    approval_required: bool | None = None


class ExternalManualPreviewRejectedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    preview_id: str
    state: Literal["rejected"]
    decided_at: str

class DarkWebWatchCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    keyword: str = Field(min_length=2,max_length=100)
class DarkWebWatchPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool

class DarkWebSchedulePatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    interval_seconds: Literal[3600,21600,43200,86400]
class DarkWebDiscoveryWatchCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    keywords: list[str] = Field(min_length=1,max_length=10)
    match_mode: Literal["any","all"] = "any"
    provider_id: str = Field(min_length=1,max_length=64,pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    scan_interval_seconds: int = Field(default=3600,ge=300,le=604800)
class DarkWebDiscoveredSourcePatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool

class DarkWebPromotionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class InternalEventResponse(BaseModel):
    """Deliberately narrow projection: never expose raw sensor-derived text."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=64)
    integration: Literal["dionaea", "host-auth", "web-access"]
    source: Literal["Dionaea", "Host Auth", "Web Access"]
    event_type: Literal["dionaea_session", "linux_auth_session", "web_access_session"]
    category: str | None = Field(default=None, max_length=50)
    severity: str | None = Field(default=None, max_length=30)
    summary: str = Field(max_length=160)
    first_seen: str | None = Field(default=None, max_length=40)
    last_seen: str | None = Field(default=None, max_length=40)
    created_at: str = Field(max_length=40)


class InternalEventPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[InternalEventResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class InternalPullResponse(BaseModel):
    """Safe synchronous-pull result; connector details remain server-side."""

    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(max_length=36)
    pipeline: Literal["internal"]
    status: str = Field(max_length=30)
    collected_count: int = Field(ge=0)
    processed_count: int = Field(ge=0)
    stored_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)


class ExternalPullResponse(InternalPullResponse):
    pipeline: Literal["external"] = "external"


class ExternalAcceptedSyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(max_length=36)
    status: str = Field(max_length=30)
    imported: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    updated: int = Field(ge=0)
    failed: int = Field(ge=0)
    total: int = Field(ge=0, le=10_000)

class ExternalJobImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(min_length=8, max_length=100)


class IntelligenceIndicatorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    event_id: str = Field(max_length=64)
    type: str = Field(max_length=50)
    value: str = Field(max_length=2048)
    confidence: float = Field(ge=0, le=1)
    source_pipeline: Literal["external", "internal"]
    severity: str | None = Field(default=None, max_length=30)
    first_seen: str | None = Field(default=None, max_length=40)
    last_seen: str | None = Field(default=None, max_length=40)
    semantic_role: Literal["external_reference", "vulnerability", "observable", "indicator"]
    validation_status: Literal["valid", "invalid"]
    assessment: Literal["reference", "non_actionable", "unknown", "suspicious", "malicious"]
    assessment_confidence: float = Field(ge=0, le=1)
    actionable: bool
    evidence_count: int = Field(ge=0)
    evidence_providers: list[str]
    reason_code: str = Field(max_length=80)


class IntelligenceEventSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=64)
    title: str = Field(max_length=500)
    summary: str = Field(max_length=500)
    source_type: str = Field(max_length=50)
    source_pipeline: Literal["external", "internal"]
    category: str | None = Field(default=None, max_length=50)
    severity: str | None = Field(default=None, max_length=30)
    risk_score: float = Field(ge=0)
    confidence: float = Field(ge=0, le=1)
    processing_status: str = Field(max_length=30)
    first_seen: str | None = Field(default=None, max_length=40)
    last_seen: str | None = Field(default=None, max_length=40)
    created_at: str = Field(max_length=40)
    indicator_count: int = Field(ge=0)
    entity_count: int = Field(ge=0)


class IntelligenceEntityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(max_length=100)
    value: str = Field(max_length=1000)
    confidence: float = Field(ge=0, le=1)


class IntelligenceRelationshipResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(max_length=1000)
    relation: str = Field(max_length=100)
    object: str = Field(max_length=1000)
    confidence: float = Field(ge=0, le=1)


class IntelligenceEventDetailResponse(IntelligenceEventSummaryResponse):
    indicators: list[IntelligenceIndicatorResponse]
    entities: list[IntelligenceEntityResponse]
    relationships: list[IntelligenceRelationshipResponse]


class IntelligenceEventPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[IntelligenceEventSummaryResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class IntelligenceIndicatorPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[IntelligenceIndicatorResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class IntelligenceIndicatorSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total: int = Field(ge=0)
    by_role: dict[str, int]
    by_assessment: dict[str, int]
    by_validation: dict[str, int]
    by_type: dict[str, int]


class IntelligenceSearchResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["event", "indicator", "entity", "source", "correlation"]
    id: str = Field(max_length=64)
    label: str = Field(min_length=1, max_length=2048)
    context: str = Field(min_length=1, max_length=500)
    match_field: Literal["id", "title", "value", "type", "name", "reason", "event_id"]
    match_quality: Literal["exact", "prefix", "contains"]
    source_pipeline: Literal["external", "internal"] | None = None
    source_type: str | None = Field(default=None, max_length=50)
    source_id: str | None = Field(default=None, max_length=64)
    source_name: str | None = Field(default=None, max_length=200)
    event_id: str | None = Field(default=None, max_length=64)
    related_event_id: str | None = Field(default=None, max_length=64)
    severity: str | None = Field(default=None, max_length=30)
    confidence: float | None = Field(default=None, ge=0, le=1)
    created_at: str | None = Field(default=None, max_length=40)


class IntelligenceSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=2, max_length=100)
    items: list[IntelligenceSearchResultResponse] = Field(max_length=50)
    returned: int = Field(ge=0, le=50)
    limit_per_type: int = Field(ge=1, le=10)
    truncated: bool


class IntelligenceCorrelationEndpointResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    title: str = Field(min_length=1, max_length=500)
    source_pipeline: Literal["external", "internal"]
    source_type: str = Field(max_length=50)
    source_id: str | None = Field(default=None, max_length=64)
    source_name: str | None = Field(default=None, max_length=200)
    severity: str | None = Field(default=None, max_length=30)
    risk_score: float = Field(ge=0, le=100)
    created_at: str = Field(max_length=40)


class IntelligenceCorrelationFactorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["shared_observable", "algorithm", "threshold", "method"]
    label: str = Field(min_length=1, max_length=100)
    value: str = Field(min_length=1, max_length=2048)


class IntelligenceCorrelationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    source_event_id: str = Field(max_length=64)
    target_event_id: str = Field(max_length=64)
    type: str = Field(max_length=50)
    score: float = Field(ge=0, le=1)
    reason: str = Field(max_length=500)
    source_event: IntelligenceCorrelationEndpointResponse
    target_event: IntelligenceCorrelationEndpointResponse
    cross_source: bool
    score_basis: Literal["exact_observable_match", "normalized_text_similarity", "recorded_correlation"]
    evidence_status: Literal["available", "partial", "unavailable"]
    factors: list[IntelligenceCorrelationFactorResponse] = Field(max_length=22)
    created_at: str = Field(max_length=40)


class IntelligenceOutlierResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=64)
    event_id: str | None = Field(default=None, max_length=64)
    started_at: str = Field(max_length=40)
    ended_at: str = Field(max_length=40)
    alert_count: int = Field(ge=0)
    is_outlier: bool
    anomaly_score: float
    detector: str = Field(max_length=100)


class IntelligenceRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    pipeline: str = Field(max_length=20)
    status: str = Field(max_length=30)
    collected: int = Field(ge=0)
    processed: int = Field(ge=0)
    stored: int = Field(ge=0)
    failed: int = Field(ge=0)
    error_category: str | None = Field(default=None, max_length=80)
    started_at: str = Field(max_length=40)
    completed_at: str | None = Field(default=None, max_length=40)
    duration_seconds: float | None = Field(default=None, ge=0)


class PipelineRunEntityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(max_length=100)
    value: str = Field(max_length=1000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    event_id: str = Field(max_length=64)
    record_title: str = Field(max_length=500)


class PipelineRunIndicatorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(max_length=50)
    value: str = Field(max_length=2048)
    confidence: float | None = Field(default=None, ge=0, le=1)
    event_id: str = Field(max_length=64)
    record_title: str = Field(max_length=500)


class PipelineRunCorrelationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_event_id: str = Field(max_length=64)
    target_event_id: str = Field(max_length=64)
    type: str = Field(max_length=50)
    score: float = Field(ge=0, le=1)
    explanation: str = Field(max_length=500)


class PipelineRunResultsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(max_length=36)
    status: str = Field(max_length=30)
    imported_documents: int = Field(ge=0)
    processed_documents: int = Field(ge=0)
    entity_count: int = Field(ge=0)
    indicator_count: int = Field(ge=0)
    correlation_count: int = Field(ge=0)
    review_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    error_count: int = Field(ge=0)
    entities: list[PipelineRunEntityResponse] = Field(max_length=200)
    indicators: list[PipelineRunIndicatorResponse] = Field(max_length=200)
    correlations: list[PipelineRunCorrelationResponse] = Field(max_length=200)


class AcceptedRecordSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=64)
    title: str = Field(max_length=500)
    source: str = Field(max_length=200)
    source_type: str = Field(max_length=50)
    category: str | None = Field(default=None, max_length=80)
    summary: str = Field(max_length=1000)
    published: str | None = Field(default=None, max_length=40)
    collected_at: str | None = Field(default=None, max_length=40)
    accepted_at: str = Field(max_length=40)
    processing_state: str = Field(max_length=30)
    classification: str | None = Field(default=None, max_length=50)
    privacy_status: str | None = Field(default=None, max_length=40)
    entity_count: int = Field(ge=0)
    indicator_count: int = Field(ge=0)
    correlation_count: int = Field(ge=0)


class AcceptedRecordDetailResponse(AcceptedRecordSummaryResponse):
    content: str = Field(max_length=20000)
    entities: list[PipelineRunEntityResponse] = Field(max_length=200)
    indicators: list[PipelineRunIndicatorResponse] = Field(max_length=200)
    correlations: list[PipelineRunCorrelationResponse] = Field(max_length=200)


class IntelligencePageMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class AcceptedRecordPageResponse(IntelligencePageMeta):
    items: list[AcceptedRecordSummaryResponse]


class IntelligenceCorrelationPageResponse(IntelligencePageMeta):
    items: list[IntelligenceCorrelationResponse]


class IntelligenceOutlierPageResponse(IntelligencePageMeta):
    items: list[IntelligenceOutlierResponse]


class IntelligenceRunPageResponse(IntelligencePageMeta):
    items: list[IntelligenceRunResponse]


class IntelligenceMLQualityGateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_]+$")
    category: Literal["artifact", "performance", "dataset_integrity"]
    passed: bool


class IntelligenceMLInferenceEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observed: bool
    input_count: int = Field(ge=0)
    chunk_count: int = Field(ge=0)


class IntelligenceMLStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_model: Literal["central_backend"]
    backend: str = Field(max_length=50)
    primary_model: str = Field(max_length=80)
    secondary_model: str = Field(max_length=80)
    primary_loaded: bool
    secondary_loaded: bool
    inference_evidence: IntelligenceMLInferenceEvidenceResponse
    quality_gates_passed: bool
    held_out_f1: float | None = None
    unique_unseen_f1: float | None = None
    runtime_state: Literal["primary_active", "secondary_fallback_active", "unavailable"]
    readiness: Literal["ready", "degraded", "unavailable"]
    inference_scope: Literal["named_entity_recognition"]
    metric_scope: Literal["saved_offline_evaluation"]
    quality_gates: list[IntelligenceMLQualityGateResponse] = Field(max_length=9)
    limitations: list[
        Literal[
            "saved_metrics_not_live_accuracy",
            "quality_gates_incomplete",
            "primary_unavailable",
            "fallback_unavailable",
        ]
    ] = Field(max_length=4)


class IntelligenceMISPHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    configured: bool
    reachable: bool
    failure_category: str | None = Field(default=None, max_length=80)


class IntelligenceMISPAttributeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(max_length=40)
    category: str = Field(max_length=80)
    value: str = Field(max_length=2048)
    to_ids: bool


class IntelligenceMISPPreviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    title: str = Field(max_length=255)
    configured: bool
    published: Literal[False]
    distribution: Literal[0]
    attributes: list[IntelligenceMISPAttributeResponse]
    tags: list[str] = Field(max_length=100)
    included: int = Field(ge=0)
    omitted: int = Field(ge=0)
    omitted_by_reason: dict[str, int]


class IntelligenceMISPCandidateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    title: str = Field(max_length=500)
    source_pipeline: Literal["external", "internal"]
    severity: str | None = Field(default=None, max_length=30)
    risk_score: float = Field(ge=0, le=100)
    included: int = Field(ge=0)
    omitted: int = Field(ge=0)
    omitted_by_reason: dict[str, int]
    ready: bool
    readiness_reason: Literal["ready", "misp_unconfigured", "no_transferable_attributes"]
    delivery_count: int = Field(ge=0)
    last_delivered_at: str | None = Field(default=None, max_length=40)
    last_misp_event_id: str | None = Field(default=None, max_length=64)


class IntelligenceMISPCandidatePageResponse(IntelligencePageMeta):
    configured: bool
    items: list[IntelligenceMISPCandidateResponse]


class IntelligenceMISPBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_ids: list[str] = Field(min_length=1, max_length=20)
    confirm_unpublished: Literal[True]


class IntelligenceMISPDeliveryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    created: bool
    attributes_requested: int = Field(ge=0)
    attributes_added: int = Field(ge=0)
    attributes_verified: int = Field(ge=0)
    published: bool
    misp_event_id: str | None = Field(default=None, max_length=64)
    misp_event_uuid: str | None = Field(default=None, max_length=36)


class IntelligenceMISPBatchItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    status: Literal["delivered", "skipped", "failed"]
    reason: str | None = Field(default=None, max_length=80)
    created: bool | None = None
    attributes_requested: int | None = Field(default=None, ge=0)
    attributes_added: int | None = Field(default=None, ge=0)
    attributes_verified: int | None = Field(default=None, ge=0)
    published: bool | None = None
    misp_event_id: str | None = Field(default=None, max_length=64)
    misp_event_uuid: str | None = Field(default=None, max_length=36)


class IntelligenceMISPBatchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str = Field(max_length=36)
    requested: int = Field(ge=1, le=20)
    delivered: int = Field(ge=0)
    skipped: int = Field(ge=0)
    failed: int = Field(ge=0)
    published: int = Field(ge=0)
    items: list[IntelligenceMISPBatchItemResponse] = Field(max_length=20)


class IntelligenceMISPDeliveryHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    event_id: str | None = Field(default=None, max_length=64)
    username: str | None = Field(default=None, max_length=100)
    created_at: str = Field(max_length=40)
    status: Literal["delivered", "skipped", "failed"]
    reason: str | None = Field(default=None, max_length=80)
    batch_id: str | None = Field(default=None, max_length=36)
    misp_event_id: str | None = Field(default=None, max_length=64)
    misp_event_uuid: str | None = Field(default=None, max_length=36)
    created: bool | None = None
    attributes_requested: int | None = Field(default=None, ge=0)
    attributes_added: int | None = Field(default=None, ge=0)
    attributes_verified: int | None = Field(default=None, ge=0)
    published: bool | None = None


class IntelligenceMISPDeliveryHistoryResponse(IntelligencePageMeta):
    items: list[IntelligenceMISPDeliveryHistoryItem]


class IntelligenceAttackTechniqueResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str = Field(max_length=20)
    name: str = Field(max_length=150)
    tactic: str = Field(max_length=80)
    confidence: float = Field(ge=0, le=1)
    mapping_source: Literal["explicit_id", "rule_based_candidate"]
    evidence: str = Field(max_length=240)
    url: str = Field(max_length=300)


class IntelligenceAttackMappingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    catalog_version: str = Field(max_length=50)
    source: Literal["built_in_subset"]
    official_dataset_url: str = Field(max_length=300)
    techniques: list[IntelligenceAttackTechniqueResponse]


class IntelligenceStorylineRiskFactorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: Literal[
        "base_severity_or_cvss",
        "indicators",
        "confidence",
        "source_diversity",
        "correlations",
        "internal_outlier",
    ]
    value: float = Field(ge=0, le=100)


class IntelligenceStorylineRiskContextResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_count: int | None = Field(default=None, ge=0)
    correlation_count: int | None = Field(default=None, ge=0)


class IntelligenceEnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_external_lookup: Literal[True]
    refresh: bool = False


class IntelligenceEnrichmentItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator_id: str = Field(max_length=36)
    cve_id: str = Field(max_length=20)
    provider: Literal["NVD"]
    status: Literal["not_run", "completed", "not_found", "failed"]
    enriched_at: str | None = Field(default=None, max_length=40)
    found: bool
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_version: str | None = Field(default=None, max_length=20)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    description: str | None = Field(default=None, max_length=1000)
    cwes: list[str] = Field(max_length=20)
    nvd_url: str = Field(max_length=200)


class IntelligenceEnrichmentRiskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["deterministic_rule_score"]
    score: float = Field(ge=0, le=100)
    severity: str | None = Field(default=None, max_length=30)
    factors: list[IntelligenceStorylineRiskFactorResponse] = Field(max_length=6)


class IntelligenceEnrichmentStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    provider: Literal["NVD"]
    eligible_count: int = Field(ge=0)
    completed_count: int = Field(ge=0)
    not_found_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    pending_count: int = Field(ge=0)
    last_enriched_at: str | None = Field(default=None, max_length=40)
    items_truncated: bool
    items: list[IntelligenceEnrichmentItemResponse] = Field(max_length=100)
    risk: IntelligenceEnrichmentRiskResponse


class IntelligenceEnrichmentRunResponse(IntelligenceEnrichmentStatusResponse):
    previous_risk_score: float = Field(ge=0, le=100)
    risk_changed: bool
    attempted_count: int = Field(ge=0, le=5)


class IntelligenceStorylineEvidenceCountsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observables: int = Field(ge=0)
    entities: int = Field(ge=0)
    relationships: int = Field(ge=0)
    correlations: int = Field(ge=0)
    attack_mappings: int = Field(ge=0)


class IntelligenceStorylineMilestoneResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=100)
    kind: Literal["observed", "last_observed", "processed", "correlated", "attack_mapping"]
    occurred_at: str | None = Field(default=None, max_length=40)
    event_id: str = Field(max_length=64)
    related_event_id: str | None = Field(default=None, max_length=64)
    title: str = Field(min_length=1, max_length=500)
    detail: str = Field(min_length=1, max_length=500)
    source_pipeline: Literal["external", "internal"]
    evidence_status: Literal["recorded", "derived", "candidate"]
    confidence: float | None = Field(default=None, ge=0, le=1)
    score: float | None = Field(default=None, ge=0, le=1)


class IntelligenceStorylineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event: IntelligenceEventSummaryResponse
    source_name: str | None = Field(default=None, max_length=200)
    risk_method: Literal["deterministic_rule_score"]
    risk_factors: list[IntelligenceStorylineRiskFactorResponse] = Field(max_length=6)
    risk_context: IntelligenceStorylineRiskContextResponse
    evidence_counts: IntelligenceStorylineEvidenceCountsResponse
    observables: list[IntelligenceIndicatorResponse] = Field(max_length=20)
    entities: list[IntelligenceEntityResponse] = Field(max_length=20)
    relationships: list[IntelligenceRelationshipResponse] = Field(max_length=20)
    correlations: list[IntelligenceCorrelationResponse] = Field(max_length=20)
    attack: IntelligenceAttackMappingResponse
    milestones: list[IntelligenceStorylineMilestoneResponse] = Field(max_length=40)
    evidence_truncated: bool
    limitations: list[Literal[
        "chronology_not_causality",
        "attack_candidates_require_review",
        "internal_raw_telemetry_hidden",
        "bounded_evidence",
    ]] = Field(max_length=4)


class AdminUserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=200)
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class AdminUserRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["admin", "analyst", "viewer"]


class AdminUserActiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_active: bool


class AdminPasswordResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=10, max_length=200)


class AdminUserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    username: str = Field(max_length=100)
    role: Literal["admin", "analyst", "viewer"]
    is_active: bool
    created_at: str = Field(max_length=40)


class AdminUserPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[AdminUserResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class AdminAuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    actor: str | None = Field(default=None, max_length=100)
    action: str = Field(max_length=100)
    target_type: str = Field(max_length=100)
    target_id: str | None = Field(default=None, max_length=100)
    outcome: Literal["success"]
    created_at: str = Field(max_length=40)


class AdminAuditPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[AdminAuditResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
