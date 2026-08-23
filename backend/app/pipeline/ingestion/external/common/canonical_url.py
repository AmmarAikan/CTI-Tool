from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


DEFAULT_TRACKING_PARAMETERS = frozenset(
    {"fbclid", "gclid", "mc_cid", "mc_eid", "utm_campaign", "utm_content", "utm_medium", "utm_source", "utm_term"}
)


def canonicalize_url(url: str, tracking_parameters: frozenset[str] = DEFAULT_TRACKING_PARAMETERS) -> str:
    """Return a stable HTTP(S) URL while preserving meaningful query parameters."""
    value = url.strip()
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("only http and https URLs can be canonicalized")
    if not parts.hostname or parts.username is not None or parts.password is not None:
        raise ValueError("URL must contain a host and no embedded credentials")

    host = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if port is None or default_port else f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]" if port is None or default_port else f"[{host}]:{port}"

    path = parts.path or "/"
    query_items = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in tracking_parameters and not key.lower().startswith("utm_")
    ]
    query = urlencode(sorted(query_items))
    return urlunsplit((scheme, netloc, path, query, ""))
