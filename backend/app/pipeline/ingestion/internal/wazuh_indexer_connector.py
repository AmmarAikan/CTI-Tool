from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.ingestion.internal.base_internal_connector import (
    InternalConnector,
)
from backend.app.pipeline.ingestion.internal.wazuh_connector import (
    WazuhFileConnector,
    nested_value,
)


@dataclass(slots=True)
class WazuhIndexerResult:
    records: list[RawRecord] = field(default_factory=list)
    total_hits: int = 0
    last_timestamp: str | None = None
    last_sort: list[Any] | None = None
    index_pattern: str = "wazuh-alerts*"

    def details(self) -> dict[str, Any]:
        return {
            "transport": "wazuh_indexer_api",
            "index_pattern": self.index_pattern,
            "returned_hits": len(self.records),
            "total_hits": self.total_hits,
            "last_timestamp": self.last_timestamp,
            "checkpoint_advanced": self.last_sort is not None,
        }


class WazuhIndexerConnector(InternalConnector):
    """Pull bounded alert batches from the authenticated Wazuh indexer REST API."""

    def __init__(
        self,
        base_url: str,
        *,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        verify_tls: bool = True,
        allow_http: bool = False,
        timeout: int = 30,
        batch_size: int = 500,
        source_name: str = "Wazuh VPS",
        index_pattern: str = "wazuh-alerts*",
        timestamp_field: str = "timestamp",
        tiebreaker_field: str = "id",
        since: str | None = None,
        search_after: list[Any] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = max(1, timeout)
        self.batch_size = max(1, min(batch_size, 1000))
        self.source_name = source_name
        self.index_pattern = index_pattern
        self.timestamp_field = timestamp_field
        self.tiebreaker_field = tiebreaker_field
        self.since = since
        self.search_after = search_after
        self.session = session or self._session()
        self.last_result: WazuhIndexerResult | None = None
        self._validate(allow_http)

    def collect(self):
        self.last_result = self.fetch()
        yield from self.last_result.records

    def fetch(self) -> WazuhIndexerResult:
        query: dict[str, Any] = {"match_all": {}}
        if self.since:
            query = {"range": {self.timestamp_field: {"gte": self.since}}}
        payload = {
            "size": self.batch_size,
            "track_total_hits": True,
            "sort": [
                {self.timestamp_field: {"order": "asc", "unmapped_type": "date"}},
                {
                    self.tiebreaker_field: {
                        "order": "asc",
                        "unmapped_type": "keyword",
                    }
                },
            ],
            "query": query,
        }
        if self.search_after:
            payload["search_after"] = self.search_after
        response = self.session.post(
            f"{self.base_url}/{self.index_pattern}/_search",
            json=payload,
            headers=self._headers(),
            auth=self._basic_auth(),
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        body = response.json()
        hits_container = body.get("hits", {}) if isinstance(body, dict) else {}
        raw_hits = hits_container.get("hits", []) if isinstance(hits_container, dict) else []
        if not isinstance(raw_hits, list):
            raise TypeError("Wazuh indexer response hits.hits must be a list")

        normalizer = WazuhFileConnector([], source_name=self.source_name)
        records: list[RawRecord] = []
        for hit in raw_hits:
            if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                continue
            item = dict(hit["_source"])
            item.setdefault("id", hit.get("_id"))
            item.setdefault("_wazuh_index", hit.get("_index"))
            records.append(normalizer.normalize_item(item, Path("wazuh-indexer.json")))

        total_value = hits_container.get("total", 0) if isinstance(hits_container, dict) else 0
        if isinstance(total_value, dict):
            total_value = total_value.get("value", 0)
        timestamps = [
            str(nested_value(record.raw_data, "timestamp", "@timestamp"))
            for record in records
            if nested_value(record.raw_data, "timestamp", "@timestamp")
        ]
        last_sort = None
        if raw_hits and isinstance(raw_hits[-1], dict):
            candidate = raw_hits[-1].get("sort")
            if isinstance(candidate, list) and candidate:
                last_sort = candidate
        return WazuhIndexerResult(
            records=records,
            total_hits=int(total_value or 0),
            last_timestamp=max(timestamps) if timestamps else self.since,
            last_sort=last_sort or self.search_after,
            index_pattern=self.index_pattern,
        )

    def healthcheck(self) -> dict[str, Any]:
        try:
            response = self.session.get(
                f"{self.base_url}/_cluster/health",
                headers=self._headers(),
                auth=self._basic_auth(),
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
            return {
                "configured": True,
                "reachable": True,
                "cluster_name": payload.get("cluster_name"),
                "cluster_status": payload.get("status"),
                "number_of_nodes": payload.get("number_of_nodes"),
            }
        except (requests.RequestException, ValueError, TypeError) as exc:
            return {
                "configured": True,
                "reachable": False,
                "error_type": type(exc).__name__,
            }

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _basic_auth(self) -> tuple[str, str] | None:
        if self.token:
            return None
        if self.username and self.password:
            return self.username, self.password
        return None

    def _validate(self, allow_http: bool) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("WAZUH_INDEXER_URL must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not allow_http:
            raise ValueError("WAZUH_INDEXER_URL must use HTTPS unless WAZUH_INDEXER_ALLOW_HTTP=true")
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in WAZUH_INDEXER_URL")
        if not self.token and not (self.username and self.password):
            raise ValueError("Configure WAZUH_INDEXER_TOKEN or username/password")
        if not re.fullmatch(r"[A-Za-z0-9_.*-]+", self.index_pattern):
            raise ValueError("WAZUH_INDEX_PATTERN contains unsupported characters")
        if not re.fullmatch(r"[A-Za-z0-9_@.-]+", self.timestamp_field):
            raise ValueError("WAZUH_TIMESTAMP_FIELD contains unsupported characters")
        if not re.fullmatch(r"[A-Za-z0-9_@.-]+", self.tiebreaker_field):
            raise ValueError("WAZUH_TIEBREAKER_FIELD contains unsupported characters")

    @staticmethod
    def _session() -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=2,
            status=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            respect_retry_after_header=True,
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        return session
