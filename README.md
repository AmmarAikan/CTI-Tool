# AI-Based Cyber Threat Intelligence Platform

This repository now contains the backend foundation of the graduation-project CTI platform as well as the external-source collectors. The backend joins external CTI with internal Wazuh and Dionaea telemetry in one source-independent schema, persists the results, exposes an analyst API, correlates events, detects outlier sessions, and supports STIX export and optional MISP sharing.

## Backend status

- [x] FastAPI application and OpenAPI documentation
- [x] PostgreSQL persistence with SQLite support for local tests
- [x] Sources, raw items, threat events, indicators, entities, enrichments, correlations, outlier sessions, pipeline runs, users, and audit logs
- [x] Wazuh `alerts.json` ingestion in JSON, JSONL, and NDJSON forms
- [x] Authenticated Wazuh Indexer pull with bounded checkpointed pagination
- [x] Dionaea `log_json` ingestion plus a live isolated VPS sensor and authenticated/HMAC API
- [x] Lightweight VPS SSH-auth and gateway web-access JSON sensor ingestion
- [x] VPS-hosted External Sources with private job control, scheduled JSON publish, and authenticated/HMAC pull
- [x] 30-minute source-IP sessionization and session feature extraction
- [x] Isolation Forest outlier detection with a clearly labeled small-sample fallback
- [x] DNRTI BERT as the primary runtime NER model; DNRTI sklearn as the secondary fallback
- [x] Explainable risk scoring, exact-indicator correlation, and TF-IDF similarity correlation
- [x] NVD CVE enrichment, observable-first STIX 2.1 export, and live unpublished/verified MISP submission
- [x] Cached/chunked BERT runtime and `/ml/status` held-out quality evidence
- [x] Refanged IPv4/domain/URL extraction plus validated IPv6, ASN, and MAC observables
- [x] Sentence-aware, type-bounded relationship extraction and repeatable PostgreSQL quality backfill
- [x] Bearer authentication, admin/analyst/viewer roles, and audit logging

The backend is intentionally a graduation-project prototype. PostgreSQL is the central application database. External Sources, MISP 2.5.44, the CTI Gateway, Dionaea, and lightweight SSH/web sensors run on the VPS; FastAPI, PostgreSQL, DNRTI BERT, and the sklearn fallback remain on Ammar's computer. No collaborator computer is required at runtime. Wazuh Manager/Indexer/Dashboard are not deployed on the current 12 GB server; the tested Wazuh connector remains available for a future larger or separate host. The current deployment and sanitized acceptance evidence are documented in `Parts Report/Hybrid_VPS_Backend_Deployment_Report.md`; the live database result-quality audit and OpenCTI-inspired corrections are in `Parts Report/CTI_Result_Quality_Audit.md`.

## Quick start — backend

Docker Desktop must be running for this path:

```powershell
Copy-Item .env.example .env
# Edit .env and replace every CHANGE_ME value.
docker compose up --build
```

Compose mounts the local `ml/models/dnrti_bert_ner` directory read-only as the primary model. If it is unavailable, the container safely falls back to the sklearn model included in the image.

Then open `http://localhost:8000/docs`. The first administrator is created from the `BOOTSTRAP_ADMIN_*` values in `.env`.

Local development without PostgreSQL uses SQLite automatically:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
```

Use `data/internal_samples/wazuh_alerts_sample.json` and `data/internal_samples/dionaea_events_sample.jsonl` to demonstrate internal ingestion. Full operational instructions are in `docs/operations/backend_setup.md`, and the implemented architecture is documented under `docs/architecture/`. Heavy optional infrastructure is explicitly bounded in `docs/architecture/future_bound_work.md`.

## External Sources Module

This shared-repository component collects and prepares external Cyber Threat Intelligence. Its sole canonical implementation is:

```text
backend/app/pipeline/ingestion/external/
```

The former top-level prototype has been retired. Do not create a parallel implementation. External Sources does not own Internal Sources, NER/IoC extraction, central persistence, or the dashboard.

## Capabilities

The canonical package provides bounded connectors for RSS, CERT advisories, vulnerability databases, Reddit, Hacker News, Telegram public previews, and operator-approved onion sources. It also provides generic crawling, manual URL routing, cleaning, privacy review, relevance classification, incremental SHA-256 state, run-scoped export, and an internal FastAPI integration adapter.

In the implemented two-node deployment, this same canonical package runs as a hardened VPS loopback service on `127.0.0.1:8090`. A systemd timer collects enabled sources and publishes the validated JSON to the loopback CTI Gateway every two hours. Ammar's central backend reaches the Gateway, job-control service, and MISP through tailnet-only Tailscale Serve HTTPS; SSH local forwarding remains an emergency fallback. The backend exposes only authenticated central API routes to the future frontend. See `docs/operations/vps_external_sources.md`.

Accepted handoff artifacts are validated against the schemas in `contracts/`. Runtime state and outputs belong under `data/external/`; they are local operational files, not central storage.

## Setup

Python 3.11 or newer is required; Python 3.12 is the project baseline.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
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

## Local Docker Desktop

The External Sources-only container uses Python 3.12, runs the canonical FastAPI adapter as non-root UID/GID `10001`, and publishes the API only on host loopback. Docker Desktop must be using Linux containers. This setup does not include Tor, a dashboard, a production queue, or cloud deployment.

Create the ignored runtime environment file and the ignored local dark-web configuration before validating Compose:

```powershell
if (!(Test-Path .env.external.local)) { Copy-Item .env.external.example .env.external.local }
if (!(Test-Path config/dark_web_sources.local.json)) { Copy-Item config/dark_web_sources.example.json config/dark_web_sources.local.json }
```

Set a strong `EXTERNAL_API_TOKEN` in `.env.external.local`. Configure only approved sources in `config/dark_web_sources.local.json`; Compose mounts that file read-only as `/run/secrets/dark_web_sources`, so it is never copied into the image. The container reaches the existing Windows Tor SOCKS service through `host.docker.internal:9050`. Tor must be configured to accept that Docker Desktop connection. Onion requests retain the canonical `socks5h` isolation and never fall back to direct web access.

Validate, build, and start only the External Sources service:

```powershell
docker compose -f compose.external.yml config
docker compose -f compose.external.yml build
docker compose -f compose.external.yml up -d
docker compose -f compose.external.yml ps
```

Health is available without authentication:

```powershell
curl.exe http://127.0.0.1:8000/api/v1/external-sources/health
```

Stop the service without deleting its named volumes:

```powershell
docker compose -f compose.external.yml down
```

Runtime state, exports, and logs persist in the `external-data` and `external-logs` named volumes. The root filesystem remains read-only, all Linux capabilities are dropped, and `no-new-privileges` is enabled. The local thread runner and job status are still in-process development adapters: a container restart preserves files but does not resume an active job. Do not add multiple Uvicorn workers.

The bundled static-token authentication, in-memory idempotency store, and thread runner are development adapters only. The local composition can execute enabled canonical RSS source jobs and the canonical Manual Source workflow for authorized testing and maintenance. Manual public URLs retain DNS/redirect SSRF validation and pass through crawling, preprocessing, privacy, classification, incremental state, and atomic accepted/review output. A returned business error becomes a failed job rather than a successful completion. The adapter still does not provide durable production orchestration or a cloud-ready queue. Internal job failures are recorded safely in `logs/cti_tool.log`; public responses never include exception details. Do not expose it publicly.

`POST /api/v1/external-sources/jobs` accepts enabled registered source IDs from `config/sources.json` and valid operator-approved IDs loaded at startup from the ignored `config/dark_web_sources.local.json`. It supports multi-source and force requests. `"scope": "all_enabled"` runs every enabled registered source and then every active tracked Manual root sequentially in one job; it must not be combined with non-empty `source_ids`. Failures are isolated, Manual outcomes expose only stable root hashes, cancellation is checked between operations, and a local lock prevents overlapping all-enabled jobs. After collection, the canonical Phase 10 exporter is invoked exactly once with the same run ID; Latest Export changes only after validated dataset, review, and manifest artifacts are atomically published. Cancellation creates no export, while export failure preserves the previous Latest Export and remains visible in the unified result. Source APIs never expose onion URLs, allowed paths, rate limits, Tor settings, or local artifact paths. Unknown IDs return `404 source_not_found`; disabled sources and Manual Source identifiers return `409`; conflicting scope/source selections return `422 invalid_collection_request`. Manual URLs must be submitted only through `POST /api/v1/external-sources/manual-sources` or its recheck operation. Failures to accept an otherwise valid command return the safely redacted `503 collection_unavailable` response.

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
