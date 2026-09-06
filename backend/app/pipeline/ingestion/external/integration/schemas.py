from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    service: Literal["external-sources"] = "external-sources"
    api_version: Literal["v1"] = "v1"


class CollectionRequestBody(StrictModel):
    source_ids: list[str] = Field(default_factory=list, max_length=100)
    scope: Literal["all_enabled"] | None = Field(
        default=None,
        description="Run all enabled registered sources and active tracked Manual roots in one job and validated export.",
    )
    force: bool = False
    options: dict[str, Any] = Field(default_factory=dict)


class SourceCollectionRequestBody(StrictModel):
    force: bool = False


class ManualURLRequestBody(StrictModel):
    url: HttpUrl
    force: bool = False


class ManualPreviewRequestBody(StrictModel):
    url: HttpUrl


class ManualPreviewApproveBody(StrictModel):
    expected_content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ManualPreviewRejectBody(StrictModel):
    reason: Literal["not_relevant", "duplicate", "user_cancelled"]


class ManualPreviewResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
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
    counts: dict[Literal["items", "accepted", "review", "rejected", "skipped", "errors"], int]


class ManualPreviewRejectedResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    preview_id: str
    state: Literal["rejected"]
    decided_at: str


class JobStatusResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    job_id: str = Field(min_length=10)
    command_id: str = Field(min_length=10)
    state: Literal["queued", "running", "completed", "partial", "failed", "cancellation_requested", "cancelled"]
    created_at: str
    updated_at: str
    progress: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class SourceResponse(StrictModel):
    source_id: str
    name: str
    source_type: str
    status: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationErrorResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class LatestExportResponse(StrictModel):
    run_id: str
    status: str
    dataset_sha256: str | None = None
    accepted_records: int = 0
    review_records: int = 0
    completed_at: str | None = None
    dataset: list[dict[str, Any]] = Field(default_factory=list)
    manifest: dict[str, Any] = Field(default_factory=dict)


class LatestExportSummaryResponse(StrictModel):
    run_id: str
    status: str
    dataset_sha256: str | None = None
    accepted_records: int = 0
    review_records: int = 0
    completed_at: str | None = None


class ReviewRecordResponse(StrictModel):
    record_id: str
    canonical_url: str | None = None
    title: str | None = None
    source_type: str | None = None
    review_reason: str
    review_reasons: list[str] = Field(default_factory=list)
    stage_status: dict[str, str] = Field(default_factory=dict)
    classification_label: str | None = None
    privacy_status: str | None = None
    collected_at: str | None = None
    published: str | None = None


class LatestReviewResponse(StrictModel):
    run_id: str
    records: list[ReviewRecordResponse] = Field(default_factory=list)
