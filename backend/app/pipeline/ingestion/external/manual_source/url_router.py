from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit


RouteKind = Literal["github_advisory", "github_public", "vulnerability", "rss", "dark_web", "generic_web"]
CVE_RE = re.compile(r"(?:^|/)(CVE-\d{4}-\d{4,19})(?:$|[/?#])", re.I)
GHSA_RE = re.compile(r"(?:^|/)(GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})(?:$|[/?#])", re.I)


@dataclass(frozen=True, slots=True)
class URLRoute:
    kind: RouteKind
    identifier: str | None = None


class ManualURLRouter:
    def route(self, canonical_url: str, *, detected_feed: bool = False) -> URLRoute:
        parts, path = urlsplit(canonical_url), urlsplit(canonical_url).path.lower()
        host = (parts.hostname or "").lower()
        if host.endswith(".onion"): return URLRoute("dark_web")
        ghsa = GHSA_RE.search(parts.path)
        if host in {"github.com", "api.github.com"} and ghsa: return URLRoute("github_advisory", ghsa.group(1).upper())
        if host in {"github.com", "api.github.com", "raw.githubusercontent.com"}: return URLRoute("github_public")
        cve = CVE_RE.search(parts.path)
        if cve and host in {"nvd.nist.gov", "www.cve.org", "cve.org", "cve.mitre.org"}: return URLRoute("vulnerability", cve.group(1).upper())
        if detected_feed or path.endswith((".rss", ".atom", ".xml")) or any(token in path for token in ("/feed", "/rss", "/atom")):
            return URLRoute("rss")
        return URLRoute("generic_web")
