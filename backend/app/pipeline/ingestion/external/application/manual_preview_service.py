from __future__ import annotations

import json
import ipaddress
import os
import re
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit, urlunsplit

from backend.app.pipeline.ingestion.external.application.manual_source_service import (
    CanonicalManualSourceService, ManualPreviewBundle, ManualSourceResult,
)
from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification

MAX_PREVIEW_BYTES = 1024 * 1024
MAX_CLEANUP_ROWS = 50
SAFE_REASONS = frozenset({"not_relevant", "duplicate", "user_cancelled"})


class PreviewError(RuntimeError):
    code = "preview_error"
class PreviewNotFound(PreviewError): code = "preview_not_found"
class PreviewExpired(PreviewError): code = "preview_expired"
class PreviewConsumed(PreviewError): code = "preview_consumed"
class PreviewHashMismatch(PreviewError): code = "preview_content_mismatch"


@dataclass(frozen=True, slots=True)
class PreviewRecord:
    preview_id: str
    state: str
    created_at: str
    expires_at: str
    content_sha256: str
    payload: dict[str, Any] | None


class SQLiteManualPreviewStore:
    def __init__(self, path: Path, *, ttl_seconds: int = 900, clock: Callable[[], datetime] | None = None) -> None:
        self.path = path
        self.ttl_seconds = min(3600, max(60, ttl_seconds))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise RuntimeError("manual preview database path is unsafe")
        if not path.exists():
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        self._initialize()
        try: os.chmod(path, 0o600)
        except OSError: pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if version > 1: raise RuntimeError("manual preview database schema is newer than this service")
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS manual_url_previews (
                preview_id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('pending','approving','approved','rejected','expired')),
                created_at TEXT NOT NULL, expires_at TEXT NOT NULL, content_sha256 TEXT NOT NULL,
                payload_json TEXT, reject_reason TEXT, decided_at TEXT
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS ix_manual_url_previews_expiry ON manual_url_previews(state, expires_at)")
            db.execute("PRAGMA user_version=1")
            db.commit()

    def create(self, payload: dict[str, Any], content_sha256: str) -> PreviewRecord:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_PREVIEW_BYTES: raise PreviewError("preview payload exceeds safe limit")
        now = self.clock(); created = _time(now); expires = _time(now + timedelta(seconds=self.ttl_seconds))
        preview_id = f"prv-{secrets.token_hex(16)}"
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE"); self._cleanup(db, created)
            db.execute("INSERT INTO manual_url_previews VALUES (?, 'pending', ?, ?, ?, ?, NULL, NULL)",
                       (preview_id, created, expires, content_sha256, encoded))
            db.commit()
        return PreviewRecord(preview_id, "pending", created, expires, content_sha256, payload)

    def claim_approval(self, preview_id: str, expected_hash: str) -> PreviewRecord:
        return self._decide(preview_id, "approving", expected_hash=expected_hash)

    def reject(self, preview_id: str, reason: str) -> PreviewRecord:
        if reason not in SAFE_REASONS: raise ValueError("invalid rejection reason")
        return self._decide(preview_id, "rejected", reason=reason)

    def mark_approved(self, preview_id: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE manual_url_previews SET state='approved', payload_json=NULL, decided_at=? WHERE preview_id=? AND state='approving'",
                       (_time(self.clock()), preview_id))

    def release_approval(self, preview_id: str) -> None:
        now = _time(self.clock())
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT expires_at FROM manual_url_previews WHERE preview_id=? AND state='approving'", (preview_id,)).fetchone()
            if row is not None:
                if row["expires_at"] <= now:
                    db.execute("UPDATE manual_url_previews SET state='expired', payload_json=NULL WHERE preview_id=? AND state='approving'", (preview_id,))
                else:
                    db.execute("UPDATE manual_url_previews SET state='pending' WHERE preview_id=? AND state='approving'", (preview_id,))
            db.commit()

    def _decide(self, preview_id: str, state: str, *, expected_hash: str | None = None, reason: str | None = None) -> PreviewRecord:
        now = _time(self.clock())
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE"); self._cleanup(db, now)
            row = db.execute("SELECT * FROM manual_url_previews WHERE preview_id=?", (preview_id,)).fetchone()
            if row is None: db.commit(); raise PreviewNotFound()
            if row["state"] == "expired" or row["expires_at"] <= now:
                db.execute("UPDATE manual_url_previews SET state='expired', payload_json=NULL WHERE preview_id=?", (preview_id,))
                db.commit(); raise PreviewExpired()
            if row["state"] != "pending": db.commit(); raise PreviewConsumed()
            if expected_hash is not None and row["content_sha256"] != expected_hash: db.commit(); raise PreviewHashMismatch()
            decided = now if state == "rejected" else None
            payload_json = None if state == "rejected" else row["payload_json"]
            db.execute("UPDATE manual_url_previews SET state=?, payload_json=?, reject_reason=?, decided_at=? WHERE preview_id=? AND state='pending'",
                       (state, payload_json, reason, decided, preview_id))
            db.commit()
            payload = json.loads(row["payload_json"]) if row["payload_json"] else None
            return PreviewRecord(row["preview_id"], state, row["created_at"], row["expires_at"], row["content_sha256"], payload)

    @staticmethod
    def _cleanup(db: sqlite3.Connection, now: str) -> None:
        ids = [row[0] for row in db.execute(
            "SELECT preview_id FROM manual_url_previews WHERE state IN ('pending','approving') AND expires_at<=? LIMIT ?", (now, MAX_CLEANUP_ROWS)
        )]
        if ids:
            db.executemany("UPDATE manual_url_previews SET state='expired', payload_json=NULL WHERE preview_id=?", ((value,) for value in ids))


class ManualPreviewService:
    def __init__(self, manual: CanonicalManualSourceService, store: SQLiteManualPreviewStore,
                 commit: Callable[[ManualPreviewBundle, str], ManualSourceResult]) -> None:
        self.manual, self.store, self.commit = manual, store, commit

    def create(self, url: str, *, requested_by: str) -> dict[str, Any]:
        bundle = self.manual.preview_url(url, requested_by=requested_by)
        payload = _bundle_dict(bundle)
        digest = sha256_text("\n".join(item.content for item, _ in bundle.items))
        record = self.store.create(payload, digest)
        return _safe_preview(record, bundle)

    def claim_approval(self, preview_id: str, expected_hash: str) -> PreviewRecord:
        return self.store.claim_approval(preview_id, expected_hash)

    def approve_claimed(self, record: PreviewRecord, *, requested_by: str) -> ManualSourceResult:
        if record.payload is None: raise PreviewConsumed()
        bundle = _bundle_from_dict(record.payload)
        result = self.commit(bundle, requested_by)
        self.store.mark_approved(record.preview_id)
        return result

    def release_approval(self, preview_id: str) -> None:
        self.store.release_approval(preview_id)

    def reject(self, preview_id: str, reason: str, *, requested_by: str) -> dict[str, str]:
        del requested_by
        record = self.store.reject(preview_id, reason)
        return {"schema_version": "1.0", "preview_id": record.preview_id, "state": "rejected", "decided_at": _time(self.store.clock())}


def _bundle_dict(bundle: ManualPreviewBundle) -> dict[str, Any]:
    return {"canonical_url": bundle.canonical_url, "page_type": bundle.page_type, "state": bundle.state,
            "result": asdict(bundle.result), "items": [{"item": item.to_dict(), "disposition": disposition} for item, disposition in bundle.items]}


def _bundle_from_dict(value: dict[str, Any]) -> ManualPreviewBundle:
    items = []
    for entry in value["items"]:
        raw = dict(entry["item"]); raw["tags"] = tuple(raw.get("tags", ()))
        raw["classification"] = ExternalClassification(**raw.get("classification", {}))
        items.append((ExternalCTIItem(**raw), str(entry["disposition"])))
    return ManualPreviewBundle(str(value["canonical_url"]), str(value["page_type"]), tuple(items),
                               dict(value["state"]), ManualSourceResult(**value["result"]))


def _safe_preview(record: PreviewRecord, bundle: ManualPreviewBundle) -> dict[str, Any]:
    first = bundle.items[0] if bundle.items else None
    item, disposition = first if first else (None, "rejected")
    parts = urlsplit(bundle.canonical_url)
    display = _display_url(parts)
    privacy = item.metadata.get("privacy", {}) if item else {}
    reasons = []
    if privacy.get("status") == "review_required": reasons.append("privacy_review")
    if disposition == "review": reasons.append("classification_review")
    if disposition == "rejected": reasons.append("relevance_rejected")
    classification = item.classification if item else ExternalClassification()
    title = _clean(item.title if item else "")
    excerpt = _clean(item.summary if item and privacy.get("status") != "review_required" else "")
    result = bundle.result
    return {"schema_version": "1.0", "preview_id": record.preview_id, "state": record.state,
            "created_at": record.created_at, "expires_at": record.expires_at, "display_url": display,
            "page_type": bundle.page_type, "title": title[:300], "excerpt": excerpt[:500],
            "disposition": disposition, "classification_label": _clean(classification.label or "")[:80] or None,
            "classification_confidence": round(classification.score, 4) if classification.score is not None else None,
            "privacy_status": str(privacy.get("status") or "reviewed"), "review_reasons": sorted(set(reasons)),
            "content_sha256": record.content_sha256,
            "counts": {"items": len(bundle.items), "accepted": result.accepted_records, "review": result.review_records,
                       "rejected": result.rejected_records, "skipped": result.skipped_records, "errors": result.error_count}}


def _clean(value: str) -> str:
    value = re.sub(r"https?://\S+|\b[a-z2-7]{16,56}\.onion\b|(?:token|password|secret|authorization)\s*[=:]\s*\S+", "[redacted]", value, flags=re.I)
    return " ".join("[redacted]" if _is_ip(token.strip("[](),.;")) else token for token in value.split())
def _display_url(parts) -> str:
    if parts.hostname and parts.hostname.endswith(".onion"): return "[restricted-source]"
    segments = []
    for segment in parts.path.split("/"):
        decoded = unquote(segment)
        unsafe = len(decoded) > 80 or re.search(r"(token|secret|password|authorization|api[_-]?key)", decoded, re.I)
        segments.append("[redacted]" if unsafe else segment)
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments)[:300], "", ""))
def _is_ip(value: str) -> bool:
    try: ipaddress.ip_address(value); return True
    except ValueError: return False
def _time(value: datetime) -> str: return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
