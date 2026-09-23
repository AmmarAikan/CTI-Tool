"""Offline-only provider contracts for the isolated ACTIT defense demo.

The service has no production credentials and is reachable only on the demo's
internal Docker network. It implements read-only Review and MISP health
contracts; all MISP delivery methods fail closed.
"""
from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Response, status

app = FastAPI(title="ACTIT isolated demo provider", docs_url=None, redoc_url=None)
REVIEW_MODE: Literal["available", "empty"] = "available"
CONTROL_TOKEN = "defense-demo-control"
EXTERNAL_TOKEN = os.getenv("EXTERNAL_API_TOKEN", "")
CONTENT_SHA256 = "sha256:" + "6b" * 32
UPDATED_AT = "2026-01-15T12:00:00Z"
RECORD_ID = "demo-review-record-0001"


def _external_auth(authorization: str | None) -> None:
    if authorization != f"Bearer {EXTERNAL_TOKEN}" or len(EXTERNAL_TOKEN) < 24:
        raise HTTPException(status_code=401, detail="authentication failed")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "actit-defense-demo-offline-provider", "api_version": "1.0"}


@app.get("/reviews/latest")
def latest_reviews(authorization: str | None = Header(default=None)) -> dict[str, object]:
    _external_auth(authorization)
    records = []
    if REVIEW_MODE == "available":
        records.append({
            "record_id": RECORD_ID,
            "canonical_url": "https://example.invalid/advisories/demo-0001",
            "title": "[DEMO] Analyst review candidate",
            "source_type": "rss",
            "review_reason": "classification_review",
            "review_reasons": ["classification_review"],
            "stage_status": "review",
            "classification_label": "uncertain",
            "privacy_status": "reviewed",
            "collected_at": UPDATED_AT,
            "published": UPDATED_AT,
            "content_sha256": CONTENT_SHA256,
            "review_version": "1.0",
            "summary": "Synthetic offline review artifact for the defense walkthrough.",
            "excerpt": "A bounded synthetic record requiring an analyst decision.",
            "source": "[DEMO] Offline advisory provider",
            "category": "advisory",
            "status": "pending",
        })
    return {"run_id": "demo-review-run-0001", "records": records}


@app.get("/reviews/lifecycle")
def review_lifecycle(authorization: str | None = Header(default=None)) -> dict[str, object]:
    _external_auth(authorization)
    items = []
    if REVIEW_MODE == "available":
        items.append({
            "record_id": RECORD_ID,
            "review_id": RECORD_ID,
            "content_sha256": CONTENT_SHA256,
            "external_job_id": "demo-external-job-0001",
            "export_run_id": None,
            "dataset_sha256": None,
            "state": "pending_review",
            "stage": "review",
            "retryable": False,
            "updated_at": UPDATED_AT,
        })
    return {"schema_version": "1.0", "items": items}


@app.post("/demo/reviews/mode/{mode}")
def set_review_mode(mode: Literal["available", "empty"], x_demo_control: str | None = Header(default=None)) -> dict[str, str]:
    if x_demo_control != CONTROL_TOKEN:
        raise HTTPException(status_code=403, detail="demo control denied")
    global REVIEW_MODE
    REVIEW_MODE = mode
    return {"mode": REVIEW_MODE}


@app.get("/servers/getVersion")
def misp_version() -> dict[str, object]:
    return {"version": "offline-demo", "mocked": True, "live_delivery": False}


@app.api_route(
    "/{path:path}",
    methods=["POST", "PUT", "PATCH", "DELETE"],
    include_in_schema=False,
)
def reject_mutation(path: str) -> Response:
    if path.startswith(("events/", "attributes/")):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="live MISP delivery is disabled in the isolated defense demo",
        )
    raise HTTPException(status_code=405, detail="mutation disabled in the isolated defense demo")
