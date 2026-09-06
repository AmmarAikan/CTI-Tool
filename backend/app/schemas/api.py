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
    counts: dict[str, int]


class ExternalManualPreviewRejectedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    preview_id: str
    state: Literal["rejected"]
    decided_at: str
