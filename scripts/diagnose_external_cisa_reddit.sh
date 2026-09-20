#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cisa_source_id="${1:-cisa-advisories}"
reddit_source_id="${2:-reddit-netsec}"

case "${cisa_source_id}" in
  cisa-advisories|cert-eu-advisories|cert-at-warnings) ;;
  *) printf 'error=unsupported_cisa_source_id\n' >&2; exit 2 ;;
esac
case "${reddit_source_id}" in
  reddit-netsec|reddit-cybersecurity|reddit-blueteamsec|reddit-asknetsec) ;;
  *) printf 'error=unsupported_reddit_source_id\n' >&2; exit 2 ;;
esac

cd -- "${repository_root}"
docker compose \
  --project-name cti-ext-readiness \
  --env-file .env.external-test \
  -f compose.external-test.yml \
  exec -T external-sources python - "${cisa_source_id}" "${reddit_source_id}" <<'PY'
from __future__ import annotations

import hashlib
import json
import socket
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import feedparser
import requests

from backend.app.pipeline.ingestion.external.cert_connector import CERTSource
from backend.app.pipeline.ingestion.external.reddit_connector import RedditConnector, RedditSource
from backend.app.pipeline.ingestion.external.reddit_playwright import RedditPlaywrightCollector


CONFIG_PATH = Path("/app/config/sources.json")
DATA_PATH = Path("/app/data/external")
READ_CHUNK = 64 * 1024


def data_fingerprint() -> str:
    digest = hashlib.sha256()
    if not DATA_PATH.exists():
        digest.update(b"missing")
        return digest.hexdigest()
    for path in sorted(DATA_PATH.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            digest.update(b"symlink")
            digest.update(path.relative_to(DATA_PATH).as_posix().encode("utf-8"))
            continue
        if not path.is_file():
            continue
        digest.update(path.relative_to(DATA_PATH).as_posix().encode("utf-8"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(READ_CHUNK), b""):
                digest.update(chunk)
    return digest.hexdigest()


def status_class(status: int | None) -> str:
    return f"{status // 100}xx" if isinstance(status, int) and 100 <= status <= 599 else "unavailable"


def size_class(size: int | None, limit: int) -> str:
    if size is None:
        return "unavailable"
    if size > limit:
        return "over_limit"
    if size == 0:
        return "empty"
    if size <= 64 * 1024:
        return "small"
    if size <= 1024 * 1024:
        return "medium"
    return "large_within_limit"


def redirect_class(request_url: str, status: int, location: str | None) -> str:
    if status not in {301, 302, 303, 307, 308}:
        return "none"
    if not location:
        return "missing_location"
    try:
        origin = urlsplit(request_url)
        target = urlsplit(urljoin(request_url, location))
        if target.scheme != "https" or not target.hostname:
            return "non_https_or_invalid"
        return "same_host" if target.hostname == origin.hostname else "cross_host"
    except ValueError:
        return "invalid"


def bounded_get(url: str, *, connect: float, read: float, maximum: int, accept: str) -> tuple[dict[str, object], bytes]:
    result: dict[str, object] = {
        "dns": "not_attempted", "connect": "not_attempted", "http_class": "unavailable",
        "content_type": "unavailable", "redirect": "unavailable", "response_size": "unavailable",
        "exception_class": None,
    }
    hostname = urlsplit(url).hostname
    try:
        socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        result["dns"] = "resolved"
    except Exception as exc:
        result["dns"] = "failed"
        result["exception_class"] = type(exc).__name__
        return result, b""
    session = requests.Session()
    session.trust_env = False
    try:
        with session.get(
            url, headers={"Accept": accept, "User-Agent": "CTI-Tool-External-Diagnostic/1.0"},
            timeout=(connect, read), allow_redirects=False, stream=True,
        ) as response:
            result["connect"] = "connected"
            result["http_class"] = status_class(response.status_code)
            result["content_type"] = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() or "missing"
            result["redirect"] = redirect_class(url, response.status_code, response.headers.get("Location"))
            body = bytearray()
            for chunk in response.iter_content(chunk_size=READ_CHUNK):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) > maximum:
                    break
            result["response_size"] = size_class(len(body), maximum)
            return result, bytes(body[: maximum + 1])
    except Exception as exc:
        result["connect"] = "failed"
        result["exception_class"] = type(exc).__name__
        return result, b""
    finally:
        session.close()


def diagnose_cisa(mapping: dict[str, object]) -> dict[str, object]:
    source = CERTSource.from_mapping(mapping)
    report, body = bounded_get(
        source.url, connect=5, read=20, maximum=2 * 1024 * 1024,
        accept="application/atom+xml,application/rss+xml,application/xml,text/xml",
    )
    report.update({"source_id": source.source_id, "parser_result_count": 0})
    if report["http_class"] == "2xx" and report["response_size"] != "over_limit":
        try:
            parsed = feedparser.parse(body)
            report["parser_result_count"] = len(list(parsed.entries)[: source.max_items])
            if getattr(parsed, "bozo", False) and not parsed.entries:
                report["exception_class"] = type(getattr(parsed, "bozo_exception", ValueError())).__name__
        except Exception as exc:
            report["exception_class"] = type(exc).__name__
    return report


def fallback_stage(category: str | None) -> str:
    return {
        "playwright_unavailable": "browser_launch", "browser_launch_failure": "browser_launch",
        "browser_redirect_rejected": "navigation", "navigation_timeout": "navigation",
        "blocked_challenge_page": "selector", "dom_contract_change": "selector",
        "browser_insufficient_results": "scroll",
    }.get(category or "", "completed" if category is None else "unknown")


def diagnose_reddit(mapping: dict[str, object]) -> dict[str, object]:
    source = RedditSource.from_mapping(mapping)
    connector = RedditConnector(source)
    rss_url = f"https://www.reddit.com/r/{source.subreddit}/.rss"
    report, body = bounded_get(
        rss_url, connect=min(5, source.request_timeout_seconds), read=source.request_timeout_seconds,
        maximum=source.max_response_bytes,
        accept="application/atom+xml,application/rss+xml,application/xml,text/xml",
    )
    parsed_entries = 0
    usable_entries = 0
    insufficiency = None
    if report["http_class"] == "2xx" and report["response_size"] != "over_limit":
        try:
            parsed = feedparser.parse(body)
            entries = list(parsed.entries)[: source.limit]
            parsed_entries = len(entries)
            usable_entries = sum(connector._rss_post(entry) is not None for entry in entries)
            if getattr(parsed, "bozo", False) and not entries:
                insufficiency = "rss_parsing_failure"
                report["exception_class"] = type(getattr(parsed, "bozo_exception", ValueError())).__name__
            elif usable_entries < source.minimum_usable_posts:
                insufficiency = "below_minimum_usable_posts"
        except Exception as exc:
            insufficiency = "rss_parsing_failure"
            report["exception_class"] = type(exc).__name__
    else:
        insufficiency = "rss_request_unsuccessful"
    rss_report = {
        "http_class": report["http_class"], "content_type": report["content_type"],
        "response_size": report["response_size"], "exception_class": report["exception_class"],
        "source_id": source.source_id, "parsed_entries": parsed_entries,
        "usable_entries": usable_entries, "insufficiency_reason": insufficiency,
    }
    fallback: dict[str, object] = {"required": bool(insufficiency), "attempted": False}
    if insufficiency and source.fallback_enabled and source.transport == "rss_with_browser_fallback":
        fallback["attempted"] = True
        category = None
        try:
            posts = RedditPlaywrightCollector(source).collect()
            extracted = sum(connector._validated_post(post) is not None for post in posts)
        except Exception as exc:
            extracted = 0
            category = getattr(exc, "category", type(exc).__name__)
            fallback["exception_class"] = type(exc).__name__
        fallback.update({
            "stage": fallback_stage(category), "extracted_count": extracted,
            "challenge_detected": category == "blocked_challenge_page",
        })
    rss_report["fallback"] = fallback
    return rss_report


def safe_diagnostic(callback, source_id: str) -> dict[str, object]:
    try:
        return callback()
    except Exception as exc:
        return {"source_id": source_id, "diagnostic": "failed", "exception_class": type(exc).__name__}


def main() -> int:
    cisa_id, reddit_id = sys.argv[1:3]
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cisa_mapping = next((item for item in config.get("cert_sources", []) if item.get("source_id") == cisa_id), None)
    reddit_mapping = next((item for item in config.get("social_media_sources", []) if item.get("source_id") == reddit_id), None)
    if not isinstance(cisa_mapping, dict) or not isinstance(reddit_mapping, dict):
        print(json.dumps({"error": "configured_source_not_found"}, sort_keys=True))
        return 2
    before = data_fingerprint()
    reports: dict[str, object] = {"data_fingerprint_before": before}
    try:
        reports["cisa"] = safe_diagnostic(lambda: diagnose_cisa(cisa_mapping), cisa_id)
        reports["reddit"] = safe_diagnostic(lambda: diagnose_reddit(reddit_mapping), reddit_id)
    finally:
        after = data_fingerprint()
        reports["data_fingerprint_after"] = after
        reports["data_files_unchanged"] = before == after
        print(json.dumps(reports, sort_keys=True, separators=(",", ":")))
    return 0 if before == after else 3


raise SystemExit(main())
PY
