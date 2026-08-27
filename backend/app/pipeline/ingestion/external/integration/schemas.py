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
