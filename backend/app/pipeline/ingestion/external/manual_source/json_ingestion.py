from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json


JSON_MEDIA_TYPES = frozenset({"application/json"})
COLLECTION_NAMES = ("posts", "items", "results", "entries", "data")
FIELD_NAMES = frozenset({
    "posts", "items", "results", "entries", "data",
    "id", "identifier", "guid", "uuid", "slug", "name", "title", "headline",
    "message", "content", "body", "text", "description", "summary", "excerpt",
    "published", "published_at", "date", "created", "created_at", "updated", "updated_at",
    "url", "link", "canonical_url", "category", "source", "tags",
})
MAX_JSON_DEPTH = 20
MAX_JSON_RECORDS = 100
MAX_PATH_PARTS = 4
MAX_FIELD_LENGTH = 80


class JSONIngestionError(ValueError):
    def __init__(self, category: str, *, retryable: bool = False) -> None:
        super().__init__(category)
        self.category, self.retryable = category, retryable


@dataclass(frozen=True, slots=True)
class JSONFieldMapping:
    collection_path: tuple[str, ...] = ()
    id_field: str | None = None
    title_field: str | None = None
    content_field: str | None = None
    summary_field: str | None = None
    published_field: str | None = None
    updated_field: str | None = None
    link_field: str | None = None
    fixed_source: str | None = None
    fixed_category: str | None = None
    max_records: int = 50
    max_pages: int = 1

    def __post_init__(self) -> None:
        if (not isinstance(self.collection_path, tuple) or len(self.collection_path) > MAX_PATH_PARTS
                or any(not _valid_name(value) for value in self.collection_path)):
            raise JSONIngestionError("invalid_mapping")
        for value in (self.id_field, self.title_field, self.content_field, self.summary_field,
                      self.published_field, self.updated_field, self.link_field):
            if value is not None and not _valid_name(value):
                raise JSONIngestionError("invalid_mapping")
        if (type(self.max_records) is not int or type(self.max_pages) is not int
                or not self.title_field or not self.content_field
                or not 1 <= self.max_records <= MAX_JSON_RECORDS or self.max_pages != 1):
            raise JSONIngestionError("invalid_mapping")
        if self.fixed_source is not None and (not isinstance(self.fixed_source, str) or not 1 <= len(self.fixed_source) <= 100):
            raise JSONIngestionError("invalid_mapping")
        if self.fixed_category is not None and (not isinstance(self.fixed_category, str) or not 1 <= len(self.fixed_category) <= 80):
            raise JSONIngestionError("invalid_mapping")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["collection_path"] = list(self.collection_path)
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "JSONFieldMapping":
        allowed = {field.name for field in __import__("dataclasses").fields(cls)}
        if type(value) is not dict or set(value) - allowed:
            raise JSONIngestionError("invalid_mapping")
        raw = dict(value)
        path = raw.get("collection_path", ())
        if type(path) not in {list, tuple} or any(type(part) is not str for part in path):
            raise JSONIngestionError("invalid_mapping")
        raw["collection_path"] = tuple(path)
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class JSONRecord:
    identity: str
    title: str
    content: str
    summary: str
    published: str | None
    updated: str | None
    link: str | None
    tags: tuple[str, ...]
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class JSONDocument:
    value: Any
    content_hash: str
    mapping: JSONFieldMapping
    approximate_count: int
    warnings: tuple[str, ...] = ()


def approved_json_media_type(headers: dict[str, str]) -> bool:
    raw = headers.get("Content-Type") or headers.get("content-type") or ""
    media = raw.split(";", 1)[0].strip().lower()
    return media in JSON_MEDIA_TYPES or (media.startswith("application/") and media.endswith("+json"))


def decode_json(body: bytes, headers: dict[str, str], *, max_bytes: int) -> Any:
    if not approved_json_media_type(headers):
        raise JSONIngestionError("unsupported_content_type")
    if not body:
        raise JSONIngestionError("malformed_json")
    if len(body) > max_bytes:
        raise JSONIngestionError("response_too_large")
    try:
        text = body.decode("utf-8", errors="strict")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise JSONIngestionError("malformed_json") from None
    if _depth(value) > MAX_JSON_DEPTH:
        raise JSONIngestionError("json_too_deep")
    if not isinstance(value, (dict, list)):
        raise JSONIngestionError("unsupported_json_schema")
    return value


def detect_mapping(value: Any) -> JSONFieldMapping:
    path: tuple[str, ...]
    records: list[Any]
    if isinstance(value, list):
        path, records = (), value
    elif isinstance(value, dict):
        candidates = [(name, value.get(name)) for name in COLLECTION_NAMES if isinstance(value.get(name), list)]
        if len(candidates) != 1:
            raise JSONIngestionError("unsupported_json_schema")
        name, records = candidates[0]
        path = (name,)
    else:
        raise JSONIngestionError("unsupported_json_schema")
    samples = [entry for entry in records[:20] if isinstance(entry, dict)]
    if records and not samples:
        raise JSONIngestionError("unsupported_json_schema")
    keys = set.intersection(*(set(sample) for sample in samples)) if samples else set()
    return JSONFieldMapping(
        collection_path=path,
        id_field=_first(keys, ("id", "identifier", "guid", "uuid", "slug")),
        title_field=_first(keys, ("title", "name", "headline")) or "title",
        content_field=_first(keys, ("content", "body", "message", "text", "description")) or "content",
        summary_field=_first(keys, ("summary", "excerpt", "description")),
        published_field=_first(keys, ("published", "published_at", "date", "created_at", "created")),
        updated_field=_first(keys, ("updated", "updated_at")),
        link_field=_first(keys, ("url", "link", "canonical_url")),
    )


def parse_document(body: bytes, headers: dict[str, str], *, max_bytes: int,
                   mapping: JSONFieldMapping | None = None) -> JSONDocument:
    value = decode_json(body, headers, max_bytes=max_bytes)
    selected = mapping or detect_mapping(value)
    records = locate_records(value, selected)
    return JSONDocument(value, sha256_bytes(body), selected, min(len(records), selected.max_records),
                        ("empty_collection",) if not records else ())


def locate_records(value: Any, mapping: JSONFieldMapping) -> list[Any]:
    current = value
    for part in mapping.collection_path:
        if not isinstance(current, dict) or part not in current:
            raise JSONIngestionError("schema_changed")
        current = current[part]
    if not mapping.collection_path and isinstance(current, dict):
        return [current]
    if not isinstance(current, list):
        raise JSONIngestionError("schema_changed")
    return current[:mapping.max_records]


def adapt_records(document: JSONDocument, *, document_url: str) -> Iterable[tuple[JSONRecord | None, str | None]]:
    records = locate_records(document.value, document.mapping)
    for index, value in enumerate(records):
        try:
            yield _adapt(value, document.mapping, document_url, index), None
        except JSONIngestionError as exc:
            yield None, exc.category


def _adapt(value: Any, mapping: JSONFieldMapping, document_url: str, index: int) -> JSONRecord:
    if not isinstance(value, dict):
        raise JSONIngestionError("missing_required_record_fields")
    title = _text(value.get(mapping.title_field), 300)
    content = _text(value.get(mapping.content_field), 200_000)
    if not title or not content:
        raise JSONIngestionError("missing_required_record_fields")
    raw_identity = _text(value.get(mapping.id_field), 500) if mapping.id_field else ""
    identity = raw_identity or sha256_json({"title": title, "content": content})
    summary = _text(value.get(mapping.summary_field), 2_000) if mapping.summary_field else ""
    published = _text(value.get(mapping.published_field), 80) if mapping.published_field else ""
    updated = _text(value.get(mapping.updated_field), 80) if mapping.updated_field else ""
    raw_link = _text(value.get(mapping.link_field), 2_000) if mapping.link_field else ""
    link = None
    if raw_link:
        try: link = canonicalize_url(raw_link)
        except ValueError: raise JSONIngestionError("invalid_record_link") from None
        if urlsplit(link).scheme not in {"http", "https"}: raise JSONIngestionError("invalid_record_link")
    raw_tags = value.get("tags", ())
    tags = tuple(_text(tag, 80) for tag in raw_tags[:20] if _text(tag, 80)) if isinstance(raw_tags, list) else ()
    return JSONRecord(identity, title, content, summary, published or None, updated or None, link,
                      tags, {"json_item_index": index + 1, "json_mapping_hash": sha256_json(mapping.to_dict())})


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_JSON_DEPTH: return level
    if isinstance(value, dict): return max((_depth(item, level + 1) for item in value.values()), default=level + 1)
    if isinstance(value, list): return max((_depth(item, level + 1) for item in value), default=level + 1)
    return level


def _valid_name(value: str) -> bool:
    return bool(isinstance(value, str) and value and len(value) <= MAX_FIELD_LENGTH
                and value in FIELD_NAMES and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", value))


def _first(keys: set[str], choices: tuple[str, ...]) -> str | None:
    return next((value for value in choices if value in keys), None)


def _text(value: Any, limit: int) -> str:
    if value is None: return ""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)): return ""
    text = str(value).strip()
    return text[:limit]
