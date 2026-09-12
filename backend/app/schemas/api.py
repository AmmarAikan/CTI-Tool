from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class BootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=10, max_length=200)


class LoginRequest(BaseModel):
    username: str
    password: str


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


class ExternalManualPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: HttpUrl


class ExternalManualPreviewApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ExternalManualPreviewRejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Literal["not_relevant", "duplicate", "user_cancelled"]


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


class IntelligenceCorrelationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    source_event_id: str = Field(max_length=64)
    target_event_id: str = Field(max_length=64)
    type: str = Field(max_length=50)
    score: float = Field(ge=0, le=1)
    reason: str = Field(max_length=100)


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


class IntelligencePageMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class IntelligenceCorrelationPageResponse(IntelligencePageMeta):
    items: list[IntelligenceCorrelationResponse]


class IntelligenceOutlierPageResponse(IntelligencePageMeta):
    items: list[IntelligenceOutlierResponse]


class IntelligenceRunPageResponse(IntelligencePageMeta):
    items: list[IntelligenceRunResponse]


class IntelligenceMLStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_model: Literal["central_backend"]
    backend: str = Field(max_length=50)
    primary_model: str = Field(max_length=80)
    secondary_model: str = Field(max_length=80)
    primary_loaded: bool
    secondary_loaded: bool
    quality_gates_passed: bool
    held_out_f1: float | None = None


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


class IntelligenceMISPDeliveryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    created: bool
    attributes_requested: int = Field(ge=0)
    attributes_added: int = Field(ge=0)
    attributes_verified: int = Field(ge=0)
    published: bool


class IntelligenceMISPDeliveryHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=36)
    event_id: str | None = Field(default=None, max_length=64)
    username: str | None = Field(default=None, max_length=100)
    created_at: str = Field(max_length=40)
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
