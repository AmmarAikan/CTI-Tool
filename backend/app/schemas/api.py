from __future__ import annotations

from typing import Any, Literal

from pydantic import ConfigDict

from pydantic import BaseModel, Field, HttpUrl


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


class ExternalJobResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    job_id: str = Field(min_length=10)
    command_id: str = Field(min_length=10)
    state: Literal["queued", "running", "completed", "partial", "failed", "cancellation_requested", "cancelled"]
    created_at: str
    updated_at: str
    progress: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class ExternalReviewRecordResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class ExternalLatestReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    records: list[ExternalReviewRecordResponse] = Field(default_factory=list)


class ExternalLatestExportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    status: str
    dataset_sha256: str | None = None
    accepted_records: int = 0
    review_records: int = 0
    completed_at: str | None = None
    dataset: list[dict[str, Any]] = Field(default_factory=list)
    manifest: dict[str, Any] = Field(default_factory=dict)
