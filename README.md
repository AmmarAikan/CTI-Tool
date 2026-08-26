# CTI Tool — External Sources

This shared-repository component collects and prepares external Cyber Threat Intelligence. Its sole canonical implementation is:

```text
backend/app/pipeline/ingestion/external/
```

The former top-level prototype has been retired. Do not create a parallel implementation. External Sources does not own Internal Sources, NER/IoC extraction, central persistence, or the dashboard.

## Capabilities

The canonical package provides bounded connectors for RSS, CERT advisories, vulnerability databases, Reddit, Hacker News, Telegram public previews, and operator-approved onion sources. It also provides generic crawling, manual URL routing, cleaning, privacy review, relevance classification, incremental SHA-256 state, run-scoped export, and an internal FastAPI integration adapter.

Accepted handoff artifacts are validated against the schemas in `contracts/`. Runtime state and outputs belong under `data/external/`; they are local operational files, not central storage.

## Setup

Python 3.11 or newer is required.

```powershell
python -m pip install -r requirements.txt
```

Optional credentials and local adapter settings are documented in `.env.example`. Never commit `.env`, tokens, or local onion-source configuration.

## Configuration

Committed, non-secret External Sources configuration:

- `config/sources.json`
- `config/collection_settings.json`
- `config/preprocessing_rules.json`
- `config/privacy_rules.json`
- `config/dark_web_sources.example.json`

For dark-web collection, copy the disabled example locally:

```powershell
Copy-Item config/dark_web_sources.example.json config/dark_web_sources.local.json
```

Edit only the Git-ignored `config/dark_web_sources.local.json`. Configure an explicit Tor SOCKS proxy host and port and only operator-verified v3 onion sources. Every enabled source must have an exact 56-character v3 onion label and its configured URL path must fall within `allowed_paths`; invalid enabled entries stop API startup with a source-ID-only error. Never place real onion addresses in committed configuration. Onion traffic is GET-only, bounded to configured hosts and paths, and has no direct-web fallback.

Optional environment variables include `NVD_API_KEY`, `GITHUB_TOKEN`, Reddit API credentials, and explicit `TOR_PROXY_HOST`/`TOR_PROXY_PORT` overrides. See `.env.example` and the architecture documents for the applicable policies.

## Internal REST adapter

The dashboard is the sole production end-user interface. The API is an internal integration adapter and routes call framework-independent application services rather than collectors directly.

For local adapter testing, set a strong temporary token and start on loopback:

```powershell
$env:EXTERNAL_API_TOKEN = "replace-with-a-strong-random-local-token"
$env:EXTERNAL_API_ROLES = "operator"
$env:EXTERNAL_API_DEV_WORKERS = "2"
python -m uvicorn backend.app.pipeline.ingestion.external.integration.local:app --host 127.0.0.1 --port 8000
```

Health endpoint:

```text
GET http://127.0.0.1:8000/api/v1/external-sources/health
```

Swagger and OpenAPI are disabled by default. For local development only, enable them before starting the adapter:

```powershell
$env:EXTERNAL_API_DOCS_ENABLED = "true"
```

Swagger is then available at `http://127.0.0.1:8000/docs` and the schema at `http://127.0.0.1:8000/openapi.json`. Use Swagger's **Authorize** button with the same bearer token configured in `EXTERNAL_API_TOKEN`. Documentation mode does not bypass authentication on protected API operations and must not be enabled on a publicly reachable adapter.

The bundled static-token authentication, in-memory idempotency store, and thread runner are development adapters only. The local composition can execute enabled canonical RSS source jobs and the canonical Manual Source workflow for authorized testing and maintenance. Manual public URLs retain DNS/redirect SSRF validation and pass through crawling, preprocessing, privacy, classification, incremental state, and atomic accepted/review output. A returned business error becomes a failed job rather than a successful completion. The adapter still does not provide durable production orchestration or a cloud-ready queue. Internal job failures are recorded safely in `logs/cti_tool.log`; public responses never include exception details. Do not expose it publicly.

`POST /api/v1/external-sources/jobs` accepts enabled registered source IDs from `config/sources.json` and valid operator-approved IDs loaded at startup from the ignored `config/dark_web_sources.local.json`. It supports multi-source and force requests and reports isolated source failures as a partial job. Source APIs never expose onion URLs, allowed paths, rate limits, or Tor settings. Unknown IDs return `404 source_not_found`; disabled sources and Manual Source identifiers return `409`. Manual URLs must be submitted only through `POST /api/v1/external-sources/manual-sources` or its recheck operation. Failures to accept an otherwise valid command return the safely redacted `503 collection_unavailable` response.

Every completed local collection run invokes the canonical Phase 10 exporter with only that run's in-memory source results. The terminal job result includes `run_id` and export status. Collection remains completed if exporting fails, while `result.export.error` reports the safe `export_failed` contract. `GET /api/v1/external-sources/exports/latest` returns the latest dataset and validated manifest, or the documented `404 export_not_found` response when none is valid.

Accepted Manual Source records are atomically persisted in the processed area and in an explicit manual checkpoint index. A material manual operation regenerates the canonical export from the previous validated checkpoint plus the current accepted manual checkpoint set; unchanged rechecks do not create an export. Review/rejected manual records remain outside the accepted dataset. Registered collection exports also include the explicit eligible manual checkpoint set, allowing the Phase 10 canonical URL/content identities to deduplicate manual and registered observations without scanning unrelated runtime files.

Manual URL detection uses the canonical source registry from `config/sources.json` and returns an explicit structured route with a matched source ID where available. Exact canonical host/path rules cover vulnerability, GitHub, RSS/CERT, Telegram, Reddit, onion, and other registered URLs. Thin dependency-injected adapters reuse the existing canonical connectors and run only the matched configured source or bounded identifier. Unsupported public GitHub/CERT item routes, missing credentials, unavailable Tor, disabled sources, and unconfigured structured routes fail closed and are never silently sent through the generic crawler.

## Authorized maintenance and testing

Direct Python/module access is limited to development, automated testing, diagnostics, emergency recovery, and authorized maintenance. It is not an end-user interface.

```powershell
python -m pytest -v tests/external_sources
python -m pytest -v tests/test_external_pipeline.py
python -m pytest -v
python -m unittest discover -v
python -m compileall backend/app/pipeline/ingestion/external
```

Canonical deterministic tests use sanitized fixtures and mocks; ordinary test runs do not require live NVD, GitHub, Reddit, Telegram, RSS, CERT, Tor, or onion access.

## Export handoff

The Phase 10 exporter writes run-scoped artifacts atomically under:

```text
data/external/exports/final_dataset_<run_id>.json
data/external/exports/external_export_manifest_<run_id>.json
data/external/review/external_review_<run_id>.json
```

Only records from the intended run/checkpoint set are merged. Invalid, privacy-ambiguous, or required-classification-error records go to review rather than being silently discarded. External-only deduplication preserves provenance; cross-team deduplication and central persistence remain downstream responsibilities.

## Architecture and contracts

- `AGENTS.md` — ownership, boundaries, and engineering rules
- `docs/external_sources_master_prompt.md` — approved phased requirements
- `docs/architecture/` — delivery and integration decisions
- `contracts/` — item, manifest, command, job, event, and error schemas
- `tests/external_sources/` — canonical External Sources tests

Any required shared-contract change must be reported and approved before modifying shared or other-team modules.
