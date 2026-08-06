"""
Phase 6 (continued) — GitHub Sources.

Collects entries from GitHub's global Security Advisories database via
its public REST API (`GET https://api.github.com/advisories`) —
requests only, no Playwright, no scraping. This endpoint works
unauthenticated for public resources (GitHub's own documentation
confirms this); an optional `GITHUB_TOKEN` environment variable raises
the rate limit from 60/hour to 5000/hour if set, but nothing here
requires one.

Most likely real-world cause of "no output": GitHub's unauthenticated
rate limit (60 requests/hour) is shared across the *entire* IP address
making the request — on a shared machine/CI runner/sandbox, that quota
can already be exhausted by unrelated traffic before this collector
ever runs. This is a genuine external constraint, not a bug, but it
produces a silent-looking "0 items" if you're not watching the logs
closely — this module now surfaces GitHub's own rate-limit response
headers explicitly (`X-RateLimit-Remaining`, `X-RateLimit-Reset`)
whenever they're present, on both success and failure, so that's
visible immediately rather than requiring a manual `curl` to diagnose.

This sits alongside Mastodon as what replaced X/Twitter in this
project: like Mastodon, it's a real, stable, public REST API rather
than something requiring browser automation or login.

Note on categorization: GitHub Security Advisories are closer in spirit
to Phase 5's vulnerability databases (structured, per-package CVE-like
records) than to "social media" in the traditional sense. It lives
under `src/social_media/` because that's where this task's scope placed
it, but the data itself is much more structured (it always has a real
CVE/GHSA-style record shape) than a Reddit post or Mastodon toot.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from src.classification.classifier import filter_cti_relevant
from src.collectors.base_collector import BaseCollector
from src.utils.config_loader import get_github_sources
from src.utils.logger import get_logger
from src.utils.schema import CTIItem
from src.utils.storage import save_json, timestamped_filename

logger = get_logger(__name__)

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"

DEFAULT_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "CTI-Tool-GitHubCollector/1.0",
}

GITHUB_TOKEN_ENV_VAR = "GITHUB_TOKEN"


class GitHubCollector(BaseCollector):
    """Collects entries from GitHub's global Security Advisories database via its REST API."""

    name = "github_collector"

    def __init__(
        self,
        sources: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 15,
        max_retries: int = 2,
        retry_delay: float = 3.0,
    ):
        """
        Args:
            sources: Optional explicit list of source dicts
                (`{"name", "category", "per_page", "severity", "ecosystem"}`).
                If not provided, sources are loaded from
                `config/sources.json`.
            timeout: Per-request timeout in seconds.
            max_retries: Retry attempts for a transient failure
                (timeout, connection error, or a 5xx from GitHub's own
                servers — a real, observed occurrence) before giving up.
                Never retries a 4xx (403/422/429/etc.) — those already
                have specific handling and retrying an identical request
                won't produce a different result.
            retry_delay: Seconds to wait between retry attempts.
        """
        self.sources = sources if sources is not None else get_github_sources()
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session = requests.Session()
        headers = dict(DEFAULT_HEADERS)

        token = self._get_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
            logger.info("Using GITHUB_TOKEN for authenticated requests (5000/hour limit).")
        else:
            logger.info(
                "No GITHUB_TOKEN set — using unauthenticated requests (60/hour limit, "
                "shared across this machine's IP address)."
            )
        self.session.headers.update(headers)

    @staticmethod
    def _get_token() -> Optional[str]:
        """
        Read an optional GitHub token from the environment — never from
        config, and never required. Only raises the rate limit; no
        additional access is granted for this public, read-only endpoint.
        """
        import os

        return os.environ.get(GITHUB_TOKEN_ENV_VAR)

    @staticmethod
    def _log_rate_limit(response: requests.Response, source_name: str) -> None:
        """
        Surface GitHub's own rate-limit headers explicitly. This is the
        single most useful diagnostic for "why did this return nothing" —
        rather than making someone go run `curl` by hand to find out the
        quota is exhausted, log it every time it's present.
        """
        remaining = response.headers.get("X-RateLimit-Remaining")
        limit = response.headers.get("X-RateLimit-Limit")
        reset = response.headers.get("X-RateLimit-Reset")

        if remaining is None:
            return

        if remaining == "0" and reset:
            import datetime as dt

            reset_time = dt.datetime.fromtimestamp(int(reset), tz=dt.timezone.utc)
            logger.warning(
                "%s: GitHub rate limit exhausted (0/%s remaining). Resets at %s UTC. "
                "Set a GITHUB_TOKEN environment variable to raise the limit to 5000/hour.",
                source_name, limit, reset_time.isoformat(),
            )
        else:
            logger.info("%s: GitHub rate limit — %s/%s requests remaining.", source_name, remaining, limit)

    def collect(self) -> List[CTIItem]:
        """
        Collect entries from every configured GitHub source.

        A single source failing (rate limited, network error) is logged
        and skipped, never interrupting collection from the remaining
        sources.

        Returns:
            A list of `CTIItem` objects collected across all sources.
        """
        all_items: List[CTIItem] = []

        if not self.sources:
            logger.warning("No GitHub sources configured; nothing to collect.")
            return all_items

        for source in self.sources:
            source_name = source.get("name", "GitHub Security Advisories")

            try:
                items = self._collect_advisories(source)
                logger.info("Collected %d advisories from %s", len(items), source_name)
                all_items.extend(items)
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else "?"
                if status in (403, 429):
                    logger.warning(
                        "Source '%s' returned HTTP %s — likely rate limited. Set a "
                        "GITHUB_TOKEN environment variable to raise the limit from "
                        "60/hour to 5000/hour.", source_name, status,
                    )
                elif status == 422:
                    body_preview = e.response.text[:300] if e.response is not None else ""
                    logger.error(
                        "Source '%s' returned HTTP 422 (validation failed) — check the "
                        "configured 'severity'/'ecosystem' filter values. Response: %s",
                        source_name, body_preview,
                    )
                else:
                    logger.error("Source '%s' returned HTTP %s.", source_name, status)
            except requests.exceptions.RequestException as e:
                logger.error("Failed to collect GitHub source '%s': %s", source_name, e)
            except Exception as e:  # noqa: BLE001 - one source must never abort the run
                logger.error("Failed to collect GitHub source '%s': %s", source_name, e)

        return all_items

    def _get_with_retry(self, url: str, params: Dict[str, Any], source_name: str) -> requests.Response:
        """
        GET with retry-on-transient-failure: connection errors, timeouts,
        and 5xx responses from GitHub's own servers are retried (a real,
        observed occurrence — GitHub's API does occasionally return 503).
        A 4xx is never retried here — those already have specific
        handling in `collect()` (403/422/429/etc.) and retrying an
        identical request won't produce a different result. Raises the
        last exception if every attempt fails.
        """
        last_exception: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 2):  # +1 initial + retries
            try:
                response = self.session.get(url, params=params, timeout=self.timeout)
                self._log_rate_limit(response, source_name)
                if response.status_code >= 500:
                    raise requests.exceptions.HTTPError(
                        f"{response.status_code} Server Error", response=response
                    )
                response.raise_for_status()
                return response
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                last_exception = e
                logger.warning(
                    "Attempt %d/%d failed for '%s' (%s); %s",
                    attempt, self.max_retries + 1, source_name, e,
                    "retrying..." if attempt <= self.max_retries else "giving up.",
                )
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else None
                if status is not None and status >= 500:
                    last_exception = e
                    logger.warning(
                        "Attempt %d/%d failed for '%s' (HTTP %s from GitHub's servers, "
                        "not a request problem); %s",
                        attempt, self.max_retries + 1, source_name, status,
                        "retrying..." if attempt <= self.max_retries else "giving up.",
                    )
                else:
                    raise  # 4xx — handled specifically by the caller

            if attempt <= self.max_retries:
                time.sleep(self.retry_delay)

        raise last_exception

    def _collect_advisories(self, source: Dict[str, Any]) -> List[CTIItem]:
        """Fetch a page of global security advisories via the GitHub REST API."""
        source_name = source.get("name", "GitHub Security Advisories")
        category = source.get("category", "vulnerability")
        per_page = min(source.get("per_page", 20), 100)  # GitHub's own documented max

        params: Dict[str, Any] = {"per_page": per_page, "sort": "published", "direction": "desc"}
        if source.get("severity"):
            params["severity"] = source["severity"]
        if source.get("ecosystem"):
            params["ecosystem"] = source["ecosystem"]

        response = self._get_with_retry(GITHUB_ADVISORIES_URL, params, source_name)

        advisories = response.json()
        if not isinstance(advisories, list):
            logger.warning("Unexpected response shape from %s; skipping.", source_name)
            return []

        logger.info("%s: received %d raw advisories from the API.", source_name, len(advisories))

        items = []
        for advisory in advisories:
            item = self._parse_advisory(advisory, source_name, category)
            if item is not None:
                items.append(item)

        return items

    @staticmethod
    def _parse_advisory(advisory: Dict[str, Any], source_name: str, category: str) -> Optional[CTIItem]:
        """Convert a single GitHub advisory record into a unified CTIItem."""
        ghsa_id = advisory.get("ghsa_id")
        if not ghsa_id:
            return None

        summary = advisory.get("summary", "")
        description = advisory.get("description", "")
        content = description or summary

        # GitHub's real API returns `references` as a list of plain URL
        # strings (confirmed against GitHub's own docs) — NOT a list of
        # {"url": ...} objects. Handle both defensively in case this
        # ever changes again, rather than assuming one shape.
        raw_references = advisory.get("references", [])
        references = []
        for ref in raw_references:
            if isinstance(ref, str):
                references.append(ref)
            elif isinstance(ref, dict) and ref.get("url"):
                references.append(ref["url"])

        severity = advisory.get("severity")
        cvss = advisory.get("cvss") or {}

        return CTIItem(
            title=summary or ghsa_id,
            link=advisory.get("html_url", f"https://github.com/advisories/{ghsa_id}"),
            source=source_name,
            category=category,
            content=content,
            summary=summary[:300].strip() if summary else content[:300].strip(),
            published=advisory.get("published_at"),
            collected_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "collection_method": "api",
                "ghsa_id": ghsa_id,
                "cve_id": advisory.get("cve_id"),
                "severity": severity,
                "cvss": {
                    "score": cvss.get("score"),
                    "vector_string": cvss.get("vector_string"),
                },
                "references": references,
            },
        )


def run() -> str:
    """
    Convenience entry point: collect all configured GitHub sources,
    filter to CTI-relevant entries, and persist the results to a
    timestamped JSON file.

    Note on this specific choice: the current GitHub source here is
    Security Advisories — structured, curated security data, arguably
    closer to Phase 5's NVD/MITRE (bypassed for classification) than to
    a general-purpose source. It's classified here for consistency with
    an explicit "GitHub" entry in the general-sources list this was
    integrated against; since real advisory content is already almost
    always genuinely CTI-relevant, this filter should rarely discard
    anything in practice. If a future GitHub source becomes a general
    keyword-search over arbitrary repositories, this same call already
    covers it — no further change needed.

    Returns:
        Path to the written JSON file, or an empty string if nothing
        was collected, nothing passed classification, or saving failed.
    """
    collector = GitHubCollector()
    items = collector.collect()

    if not items:
        logger.warning("GitHub collection produced no items.")
        return ""

    item_dicts = [item.to_dict() for item in items]
    item_dicts = filter_cti_relevant(item_dicts)

    if not item_dicts:
        logger.warning("GitHub collection produced no CTI-relevant items after classification.")
        return ""

    filename = timestamped_filename("github_advisories")
    return save_json(item_dicts, filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"GitHub collection complete. Output saved to: {output_path}")
    else:
        print("GitHub collection finished with no output.")