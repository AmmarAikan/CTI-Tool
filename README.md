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

Edit only the Git-ignored `config/dark_web_sources.local.json`. Configure an explicit Tor SOCKS proxy host and port and only operator-verified onion sources. Never place real onion addresses in committed configuration. Onion traffic is GET-only, bounded to configured hosts and paths, and has no direct-web fallback.

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

The bundled static-token authentication, in-memory idempotency store, and thread runner are development adapters only. The local composition can execute enabled canonical RSS source jobs for authorized testing and maintenance, but it does not provide durable production orchestration or a cloud-ready queue. Internal job failures are recorded safely in `logs/cti_tool.log`; public responses never include exception details. Do not expose it publicly.

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
