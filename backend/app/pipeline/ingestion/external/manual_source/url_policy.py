from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url


class URLPolicyError(ValueError):
    pass


Resolver = Callable[[str, int], list[tuple]]


@dataclass(frozen=True, slots=True)
class ValidatedURL:
    canonical_url: str
    hostname: str
    is_onion: bool


class ManualURLPolicy:
    """Fail closed for credentials, non-public DNS results, and unapproved onions."""

    def __init__(self, *, resolver: Resolver | None = None, approved_onion: Callable[[str], bool] | None = None) -> None:
        self.resolver = resolver or socket.getaddrinfo
        self.approved_onion = approved_onion or (lambda _url: False)

    def validate(self, url: str, *, allow_onion: bool = True) -> ValidatedURL:
        try:
            canonical = canonicalize_url(url)
            parts = urlsplit(canonical)
        except ValueError as exc:
            raise URLPolicyError("URL must be credential-free HTTP or HTTPS") from exc
        host = (parts.hostname or "").lower()
        if host.endswith(".onion"):
            if not allow_onion or not self.approved_onion(canonical):
                raise URLPolicyError("onion URL is not an approved configured source")
            return ValidatedURL(canonical, host, True)
        if host == "localhost" or host.endswith(".localhost"):
            raise URLPolicyError("destination is not public")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            answers = self.resolver(host, port)
        except OSError as exc:
            raise URLPolicyError("destination DNS resolution failed") from exc
        addresses = {str(answer[4][0]).split("%", 1)[0] for answer in answers if len(answer) > 4 and answer[4]}
        if not addresses:
            raise URLPolicyError("destination DNS resolution returned no addresses")
        try:
            parsed = [ipaddress.ip_address(address) for address in addresses]
        except ValueError as exc:
            raise URLPolicyError("destination DNS response was invalid") from exc
        if any(
            not address.is_global or address.is_loopback or address.is_private or address.is_link_local
            or address.is_multicast or address.is_unspecified or address.is_reserved
            for address in parsed
        ):
            raise URLPolicyError("destination resolves to a non-public address")
        return ValidatedURL(canonical, host, False)
