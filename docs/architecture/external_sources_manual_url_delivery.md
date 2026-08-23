# External Sources Phase 9 — manual URL routing

`CanonicalManualSourceService` in `backend/app/pipeline/ingestion/external/application/manual_source_service.py` is the framework-independent operation boundary that a future Phase 11 authenticated transport adapter may call. Dashboard code must not invoke collectors directly.

The service uses `ManualURLPolicy`, `ManualURLRouter`, and `SSRFProtectedHttpClient` under the canonical `manual_source/` package. It rejects credentials and non-HTTP(S) schemes, resolves public hosts before every connection and redirect, rejects every non-public address class, strips cookies and authorization headers, performs GET-only bounded streaming, and never permits onion URLs through the public client. Approved onion URLs require both the local Phase 8 policy callback and the configured `dark_web` adapter.

Routing prefers configured structured adapters for GitHub Security Advisories, supported public GitHub resources, CVE/NVD records, RSS/Atom feeds, and approved onion sources. The adapter map is dependency-injected so canonical Phase 3, Phase 5, and Phase 8 adapters remain the single implementations. Missing optional adapters fail closed as `ignored`; they never fall back to scraping.

Generic articles reuse `WebCrawler`, preprocessing, privacy, classification, `ExternalCTIItem`, and atomic `JsonStateManager` storage. Listings are restricted to the same host (a conservative subset of the same registrable-domain policy), canonicalized, deduplicated, bounded to at most 20 links, and followed once. State retains the listing hash, sorted-link-set hash, known children, disappeared-child timestamps, independent child state, conditional headers, and per-stage hashes/status/version/timestamps. A preprocessing, privacy, or model fingerprint change suppresses conditional short-circuiting and reruns downstream processing.

Phase 9 tests use sanitized fixtures and mocks only. They perform no public network, live API, Tor, or onion request.
