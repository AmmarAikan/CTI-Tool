# External Sources Phase 8 — curated dark-web delivery

The sole canonical implementation is `backend/app/pipeline/ingestion/external/dark_web_connector.py`. The preserved `src/dark_web/` collector and `tests/test_dark_web_collector.py` are prototype-only; the test imports `src.dark_web` and is not evidence for the canonical runtime.

## Policy boundary

- Sources must be explicitly configured, operator-verified, enabled, and restricted to one onion host plus bounded path prefixes.
- Requests are read-only GETs through a hostname-aware `socks5h` proxy. Proxy host and port must come from the ignored local configuration or `TOR_PROXY_HOST` and `TOR_PROXY_PORT`; there is no default port.
- Redirects are handled manually and rejected unless the destination remains inside the configured host/path policy.
- Responses are limited by timeout, byte size, HTML content type, conservative retries, redirect count, item count, and per-source delay.
- Listing traversal is one level only. There is no discovery, search, recursive crawling, login, form submission, messaging, upload, purchase, or file download.
- The implementation supports an already-running proxy only. It does not auto-start Tor and cannot terminate Tor Browser or another Tor process.
- Ordinary errors contain source IDs and safe categories, never onion URLs. The canonical collector has no direct-web fallback.

## Local configuration and processing

Only `config/dark_web_sources.example.json` is committed, with an intentionally invalid fake onion name and `enabled: false`. Real addresses belong in Git-ignored `config/dark_web_sources.local.json` and must not be printed or logged.

Fetched HTML remains inside the Tor client boundary. The connector then reuses the canonical `PageTypeDetector`, text preprocessing, privacy filter, classification service, SHA-256 helpers, `ExternalCTIItem`, and `RawRecord` mapping. State is independent per configured source, listing URL, child URL, item, and processing stage. A source marked `trusted_curated` explicitly bypasses relevance classification; other dark-web content is classified, and inference failures go to review.

Phase 8 verification uses deterministic fake-host fixtures and mocked Tor responses. No live Tor proxy or onion service was contacted.
