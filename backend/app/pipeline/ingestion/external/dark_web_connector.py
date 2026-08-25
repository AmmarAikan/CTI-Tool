from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Literal
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.ingestion.base_connector import ExternalConnector
from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.json_storage import load_json
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.crawler.page_type_detector import PageTypeDetector
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


PROJECT_ROOT = Path(__file__).resolve().parents[5]
LOCAL_CONFIG = PROJECT_ROOT / "config" / "dark_web_sources.local.json"
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml")
NOISE_TAGS = ("script", "style", "noscript", "template", "nav", "header", "footer", "aside", "form")


class DarkWebConfigurationError(ValueError):
    pass


class TorUnavailableError(ConnectionError):
    pass


class DarkWebRequestError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TorProxy:
    host: str
    port: int

    @property
    def url(self) -> str:
        return f"socks5h://{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class DarkWebSource:
    source_id: str
    name: str
    url: str
    allowed_paths: tuple[str, ...]
    enabled: bool = False
    category: str = "dark_web_cti"
    max_items: int = 20
    rate_limit_seconds: float = 2.0
    trusted_curated: bool = False

    def allows(self, url: str) -> bool:
        candidate, configured = urlsplit(url), urlsplit(self.url)
        if candidate.scheme not in {"http", "https"} or candidate.username or candidate.password:
            return False
        if (candidate.hostname or "").lower() != (configured.hostname or "").lower():
            return False
        if not (candidate.hostname or "").lower().endswith(".onion"):
            return False
        path = candidate.path or "/"
        return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in self.allowed_paths)


@dataclass(frozen=True, slots=True)
class TorResponse:
    status_code: int
    content: bytes
    content_type: str
    etag: str | None = None
    last_modified: str | None = None


class TorHttpClient:
    """GET-only onion client whose DNS resolution stays inside Tor."""

    def __init__(self, proxy: TorProxy, *, session: requests.Session | None = None,
                 connect_timeout: float = 15, read_timeout: float = 45,
                 max_response_bytes: int = 2_000_000, retries: int = 1,
                 backoff_seconds: float = 1, max_redirects: int = 3,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        if not proxy.host.strip() or not 1 <= proxy.port <= 65535:
            raise DarkWebConfigurationError("an explicit valid Tor proxy host and port are required")
        self.proxy, self.session, self.connect_timeout, self.read_timeout = proxy, session or requests.Session(), connect_timeout, read_timeout
        self.max_response_bytes, self.retries, self.backoff_seconds, self.max_redirects, self.sleeper = max_response_bytes, retries, backoff_seconds, max_redirects, sleeper

    def tor_available(self) -> bool:
        try:
            with socket.create_connection((self.proxy.host, self.proxy.port), timeout=min(self.connect_timeout, 3)):
                return True
        except OSError:
            return False

    def get(self, source: DarkWebSource, url: str, *, etag: str | None = None, last_modified: str | None = None) -> TorResponse:
        if not source.allows(url):
            raise DarkWebRequestError("request blocked by configured dark-web source policy")
        headers = {"Accept": "text/html,application/xhtml+xml"}
        if etag: headers["If-None-Match"] = etag
        if last_modified: headers["If-Modified-Since"] = last_modified
        current = url
        for attempt in range(self.retries + 1):
            try:
                return self._get_following_allowed_redirects(source, current, headers)
            except (requests.ConnectionError, requests.Timeout) as exc:
                if attempt >= self.retries:
                    raise TorUnavailableError("Tor request unavailable") from exc
                self.sleeper(self.backoff_seconds * (2 ** attempt))
        raise TorUnavailableError("Tor request unavailable")

    def _get_following_allowed_redirects(self, source: DarkWebSource, url: str, headers: dict[str, str]) -> TorResponse:
        current = url
        for _ in range(self.max_redirects + 1):
            response = self.session.get(current, headers=headers, proxies={"http": self.proxy.url, "https": self.proxy.url},
                                        timeout=(self.connect_timeout, self.read_timeout), stream=True, allow_redirects=False)
            if response.status_code in {301, 302, 303, 307, 308}:
                destination = urljoin(current, response.headers.get("Location", ""))
                response.close()
                if not source.allows(destination):
                    raise DarkWebRequestError("redirect blocked by configured dark-web source policy")
                current = destination
                continue
            if response.status_code == 304:
                response.close()
                return TorResponse(304, b"", "")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in ALLOWED_CONTENT_TYPES:
                response.close()
                raise DarkWebRequestError("response content type is not permitted")
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > self.max_response_bytes:
                    response.close()
                    raise DarkWebRequestError("response exceeded configured size limit")
                chunks.append(chunk)
            result = TorResponse(response.status_code, b"".join(chunks), content_type, response.headers.get("ETag"), response.headers.get("Last-Modified"))
            response.close()
            return result
        raise DarkWebRequestError("too many redirects")


def load_dark_web_config(path: str | Path = LOCAL_CONFIG, *, environ: dict[str, str] | None = None) -> tuple[TorProxy, tuple[DarkWebSource, ...]]:
    values = load_json(path, default=None)
    if not isinstance(values, dict) or values.get("schema_version") != "1.0":
        raise DarkWebConfigurationError("valid local dark-web configuration is required")
    env = os.environ if environ is None else environ
    proxy_config = values.get("proxy") if isinstance(values.get("proxy"), dict) else {}
    host = env.get("TOR_PROXY_HOST") or proxy_config.get("host")
    raw_port = env.get("TOR_PROXY_PORT") or proxy_config.get("port")
    if not host or raw_port in {None, ""}:
        raise DarkWebConfigurationError("Tor proxy host and port must be explicitly configured")
    try: proxy = TorProxy(str(host), int(raw_port))
    except (TypeError, ValueError) as exc: raise DarkWebConfigurationError("Tor proxy port must be an integer") from exc
    sources = []
    for raw in values.get("sources", []):
        if not isinstance(raw, dict): continue
        allowed_paths = tuple(str(value) for value in raw.get("allowed_paths", []))
        source = DarkWebSource(str(raw.get("id") or ""), str(raw.get("name") or ""), str(raw.get("url") or ""), allowed_paths,
                               bool(raw.get("enabled", False)), str(raw.get("category") or "dark_web_cti"),
                               max(1, min(int(raw.get("max_items", 20)), 100)), max(0, float(raw.get("rate_limit_seconds", 2))), bool(raw.get("trusted_curated", False)))
        if not source.source_id or not source.name or not allowed_paths or not source.allows(source.url):
            raise DarkWebConfigurationError("dark-web source is incomplete or outside its own policy")
        sources.append(source)
    return proxy, tuple(sources)


@dataclass(slots=True)
class DarkWebCollectionResult:
    status: Literal["completed", "unavailable", "failed"] = "completed"
    accepted_items: list[ExternalCTIItem] = field(default_factory=list)
    review_items: list[ExternalCTIItem] = field(default_factory=list)
    rejected_items: list[ExternalCTIItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_items: int = 0


class DarkWebConnector(ExternalConnector):
    source_name = "dark_web"

    def __init__(self, sources: Iterable[DarkWebSource], client: TorHttpClient, *, state: dict[str, Any] | None = None,
                 content_processor: ExternalContentProcessor | None = None, classification_service: ClassificationService | None = None,
                 detector: PageTypeDetector | None = None, clock=None, sleeper: Callable[[float], None] = time.sleep) -> None:
        self.sources, self.client = tuple(sources), client
        self.state = state if state is not None else {"schema_version": "1.0", "sources": {}, "urls": {}, "items": {}, "runs": {}}
        self.state.setdefault("sources", {}); self.state.setdefault("urls", {}); self.state.setdefault("items", {})
        self.content_processor = content_processor or ExternalContentProcessor(TextPreprocessor(PROJECT_ROOT / "config" / "preprocessing_rules.json"), PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json"))
        self.classification_service, self.detector = classification_service or ClassificationService(), detector or PageTypeDetector()
        self.clock, self.sleeper = clock or (lambda: datetime.now(timezone.utc)), sleeper

    def collect(self) -> Iterable[RawRecord]:
        return (item.to_raw_record() for item in self.collect_result().accepted_items)

    def collect_result(self, *, check_proxy: bool = True) -> DarkWebCollectionResult:
        result = DarkWebCollectionResult()
        if check_proxy and not self.client.tor_available():
            result.status, result.errors = "unavailable", ["tor_proxy_unavailable"]
            return result
        for source in self.sources:
            if not source.enabled: continue
            try: self._collect_source(source, result)
            except TorUnavailableError: result.errors.append(f"{source.source_id}:tor_unavailable")
            except Exception: result.errors.append(f"{source.source_id}:source_failed")
        if result.errors and not (result.accepted_items or result.review_items or result.rejected_items): result.status = "failed"
        return result

    def collect_url(self, source: DarkWebSource, url: str, *, check_proxy: bool = True) -> DarkWebCollectionResult:
        """Collect exactly one configured and allowed onion URL without listing expansion."""
        result = DarkWebCollectionResult()
        if not source.enabled or not source.allows(url):
            result.status, result.errors = "failed", ["source_policy_rejected"]
            return result
        if check_proxy and not self.client.tor_available():
            result.status, result.errors = "unavailable", ["tor_proxy_unavailable"]
            return result
        try:
            response = self._fetch(source, url)
            if response is None: result.skipped_items += 1
            else: self._process_page(source, url, response, result)
        except TorUnavailableError: result.status, result.errors = "unavailable", ["tor_unavailable"]
        except Exception: result.status, result.errors = "failed", ["source_failed"]
        return result

    def _collect_source(self, source: DarkWebSource, result: DarkWebCollectionResult) -> None:
        source_state = self.state["sources"].setdefault(source.source_id, {})
        source_state["source_config_hash"] = sha256_json({"id": source.source_id, "url": source.url, "allowed_paths": source.allowed_paths})
        response = self._fetch(source, source.url)
        if response is None: result.skipped_items += 1; return
        html = response.content.decode("utf-8", errors="replace")
        text = self._extract_text(html)
        detected = self.detector.detect(html, source.url, text)
        if detected.page_type == "listing":
            children = [url for url in detected.candidate_links if source.allows(url)][:source.max_items]
            for index, child in enumerate(children):
                self.sleeper(source.rate_limit_seconds)
                try:
                    child_response = self._fetch(source, child)
                    if child_response is None: result.skipped_items += 1; continue
                    self._process_page(source, child, child_response, result, parent_url=source.url)
                except Exception: result.errors.append(f"{source.source_id}:item_failed")
        else:
            self._process_page(source, source.url, response, result)
        source_state.update({"last_checked": self._now(), "last_successful_run": self._now()})

    def _fetch(self, source: DarkWebSource, url: str) -> TorResponse | None:
        key = sha256_text(url)
        url_state = self.state["urls"].setdefault(key, {})
        response = self.client.get(source, url, etag=url_state.get("etag"), last_modified=url_state.get("last_modified"))
        url_state["last_checked"] = self._now()
        if response.status_code == 304: return None
        if response.status_code != 200: raise DarkWebRequestError("source returned unsuccessful status")
        raw_hash, previous = sha256_text(response.content.decode("utf-8", errors="replace")), url_state.get("raw_content_hash")
        url_state.update({"etag": response.etag, "last_modified": response.last_modified, "raw_content_hash": raw_hash})
        if previous == raw_hash: return None
        url_state["last_changed"] = self._now()
        return response

    def _process_page(self, source: DarkWebSource, url: str, response: TorResponse, result: DarkWebCollectionResult, *, parent_url: str | None = None) -> None:
        html = response.content.decode("utf-8", errors="replace")
        soup, extracted = BeautifulSoup(html, "lxml"), self._extract_text(html)
        processed = self.content_processor.process(extracted)
        title = (soup.title.get_text(" ", strip=True) if soup.title else source.name) or source.name
        record_id = f"dark-{sha256_text(url).split(':', 1)[1][:32]}"
        item = ExternalCTIItem(record_id=record_id, source_item_id=sha256_text(url), source=source.name, source_type="dark_web",
                               category=source.category, title=title, link=url, content=processed.export_content,
                               summary=processed.export_content[:300], collected_at=self._now(), content_hash=sha256_text(processed.export_content),
                               classification=ExternalClassification(status="not_required") if source.trusted_curated else ExternalClassification(),
                               metadata={"network": "tor", "collection_method": "configured_onion_get", "source_id": source.source_id,
                                         "parent_listing": parent_url, **processed.metadata})
        classified_result = self.classification_service.classify_item(item)
        classified = classified_result.item
        item_state = self.state["items"].setdefault(record_id, {})
        stable = classified.to_dict(); stable.pop("collected_at", None)
        record_hash = sha256_json(stable)
        checked_at = self._now()
        stages = {
            "extraction": {"input_hash": sha256_text(html), "output_hash": sha256_text(extracted), "status": "completed", "timestamp": checked_at, "version": "dark_web_html_extraction_v1"},
            "cleaning": {"input_hash": processed.preprocessing.input_hash, "output_hash": processed.preprocessing.output_hash, "status": "completed", "timestamp": checked_at, "version": processed.preprocessing.implementation_version},
            "privacy": {"input_hash": processed.privacy.input_hash, "output_hash": processed.privacy.output_hash, "status": processed.privacy.status, "timestamp": checked_at, "version": processed.privacy.implementation_version},
            "classification": {"input_hash": classified.content_hash, "output_hash": classified.metadata.get("classification_stage", {}).get("output_hash"), "status": classified.classification.status, "timestamp": checked_at, "version": classified.classification.model_version},
        }
        item_state.update({"raw_content_hash": sha256_text(html), "extracted_content_hash": sha256_text(extracted),
                           "clean_content_hash": processed.preprocessing.output_hash, "privacy_output_hash": processed.privacy.output_hash,
                           "classification_output_hash": classified.metadata.get("classification_stage", {}).get("output_hash"),
                           "record_hash": record_hash, "last_checked": checked_at, "stages": stages})
        if processed.review_required or not processed.export_content or classified_result.disposition == "review": result.review_items.append(classified)
        elif classified_result.disposition == "rejected": result.rejected_items.append(classified)
        else: result.accepted_items.append(classified)

    @staticmethod
    def _extract_text(html: str) -> str:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup.find_all(NOISE_TAGS): tag.decompose()
        return soup.get_text("\n", strip=True)

    def _now(self) -> str:
        return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
