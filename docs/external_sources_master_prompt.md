# CTI-Tool — External Sources Collection Pipeline

## Master Build Prompt for Codex

## 1. Project Context and Team Boundary

Build a modular Python backend named **CTI-Tool — External Sources Collection Pipeline**. It is one component of a larger university Cyber Threat Intelligence (CTI) platform developed by multiple teams.

The overall platform contains separate teams responsible for:

- Collecting internal sources.
- Collecting external sources — **this repository's responsibility**.
- Analysis, NER, IOC extraction, and correlation.
- Central database and long-term persistence.
- Dashboard, APIs, and user interface.

This repository is responsible only for:

1. Collecting cybersecurity data from external sources.
2. Extracting substantial text and structured source metadata.
3. Cleaning and normalizing collected text.
4. Detecting and carefully handling personal or sensitive data without destroying valid CTI indicators.
5. Applying an already-trained relevance classifier only where required.
6. Tracking changes incrementally for every source, URL, item, and processing stage.
7. Deduplicating records within external-source outputs while preserving provenance.
8. Producing a validated, versioned JSON handoff for the downstream teams.
9. Exposing framework-independent application services and versioned command/job contracts so the dashboard team can later request scans, submit URLs, manage approved sources, and inspect job status without calling collectors directly.

The repository must **not** implement:

- PostgreSQL, SQLAlchemy, Alembic, or a central database.
- Central persistence or dashboard-facing queries.
- Cross-team deduplication between internal and external sources.
- NER, IOC extraction, threat correlation, or enrichment performed by downstream teams.
- A dashboard or frontend.
- A public API during the core collector phases. The repository must still provide transport-independent application services from the beginning, and may add an approved internal integration adapter in the final integration phase after the teams agree on the protocol.
- Training, retraining, or replacing the classification model.

Local JSON files are allowed and required for operational state, checkpoints, testing, incremental collection, external-source deduplication, and handoff. They are not the platform's central persistence layer.

### Sole End-User Interface

In the completed CTI platform, the **dashboard is the only user-facing interface** for external-source operations.

End users must not interact directly with:

- Collectors or their Python modules.
- `main.py` or CLI commands.
- Configuration or local state files.
- Local JSON export directories.
- Tor proxy/process configuration.
- Model files, credentials, or environment variables.

All end-user operations must pass through the approved dashboard and its authenticated internal integration adapter. The dashboard itself is built by another team and remains outside this repository.

The CLI and `main.py` remain available only for development, automated testing, authorized maintenance, diagnostics, and emergency administrative recovery. They are not an alternative end-user interface and must enforce the same validation, authorization assumptions, source policies, collection bounds, hashing, privacy, classification, logging, and auditing rules as dashboard-originated commands.

---

## 2. Execution Rules for Codex

Build incrementally, one phase at a time. Complete and test the current phase, report the result, and wait for explicit user confirmation before proceeding.

Follow these rules throughout the build:

1. Inspect the existing repository before editing it. Preserve correct completed work and user changes.
2. Start with Phase 0 and do not implement later phases early.
3. Never redesign a completed module unless fixing a demonstrated bug or implementing an explicitly approved contract change.
4. One module has one clear responsibility.
5. Reuse shared capabilities through composition or shared utilities; do not copy and paste fetching, extraction, hashing, storage, or retry logic.
6. A single source or item failure must never crash the entire run. Log it, record it in the run manifest, and continue safely.
7. Use type hints, docstrings where they add value, deterministic functions, and unit-testable boundaries.
8. Use UTC ISO-8601 timestamps ending in `Z`.
9. Never fabricate credentials, tokens, model files, API responses, source availability, or onion addresses.
10. Use environment variables for credentials and secrets. Provide `.env.example`, never commit `.env`.
11. Verify current official API documentation before implementing an external API. Do not rely on remembered endpoints, rate limits, or response fields.
12. Prefer an official API or feed over HTML scraping when it provides the required data.
13. Respect bounded collection, rate limits, timeouts, response-size limits, and configured delays.
14. Update `requirements.txt`, tests, `README.md`, and `AGENTS.md` incrementally.
15. Do not claim live integration works if only mock tests were possible. State exactly what was tested.
16. Do not continue past a phase that requires a missing user-supplied artifact, such as the trained classification model.

Create a concise repository-level `AGENTS.md` in Phase 0 containing:

- Repository purpose and team boundary.
- Important directories.
- Supported Python version.
- Setup, test, lint, and run commands.
- Engineering conventions.
- Data-contract rules.
- The rule that the dashboard is the sole end-user interface and CLI access is restricted to development/testing/authorized maintenance.
- Prohibited features.
- The definition of done for a phase.

Keep detailed architecture in project documentation rather than making `AGENTS.md` unnecessarily large.

---

## 3. Repository Integration and Canonical Path Mapping

This is a shared multi-team repository. Its existing architecture takes priority over the standalone example tree from which this prompt was adapted.

The sole canonical implementation root for External Sources is:

```text
backend/app/pipeline/ingestion/external/
```

Do not create a parallel final implementation under `src/`. The existing `src/` tree is a migration source only: preserve it until each useful module has been ported, integrated, and covered by equivalent tests, then remove obsolete prototype modules only in an explicitly approved cleanup phase. Final backend modules must not depend permanently on `src.*` compatibility imports.

Use the repository's existing stage-oriented architecture and approved shared modules:

```text
backend/app/pipeline/
├── common/                         # shared cross-team contracts
│   └── cti_schema.py
├── preprocessing/                  # approved shared cleaning/normalization
│   ├── cleaner.py
│   ├── normalizer.py
│   └── deduplicator.py
├── ingestion/
│   ├── base_connector.py           # shared ExternalConnector contract
│   ├── internal/                    # Internal Sources team; do not modify
│   └── external/                    # sole External Sources implementation root
│       ├── application/
│       │   ├── collection_service.py
│       │   ├── manual_source_service.py
│       │   ├── source_management_service.py
│       │   └── job_service.py
│       ├── common/                  # External-only foundations
│       │   ├── models.py
│       │   ├── config_loader.py
│       │   ├── http_client.py
│       │   ├── canonical_url.py
│       │   ├── hashing.py
│       │   ├── json_storage.py
│       │   ├── state_manager.py
│       │   ├── run_manifest.py
│       │   └── logging.py
│       ├── crawler/
│       │   ├── web_crawler.py
│       │   └── page_type_detector.py
│       ├── privacy/
│       │   ├── pii_detector.py
│       │   └── privacy_filter.py
│       ├── collectors/
│       │   ├── rss_connector.py
│       │   ├── cert_connector.py
│       │   ├── vulnerability_connector.py
│       │   ├── github_advisory_connector.py
│       │   ├── hackernews_connector.py
│       │   ├── telegram_connector.py
│       │   └── dark_web_connector.py
│       ├── manual_source/
│       │   ├── manual_url.py
│       │   └── url_router.py
│       ├── classification/            # thin adapter to approved shared model contract
│       │   └── classifier_adapter.py
│       ├── export/
│       │   └── final_dataset.py
│       └── integration/               # transport adapters; Phase 11 only
├── classification/                 # shared/other-team runtime; do not duplicate
├── extraction/                     # NER/IoC/relation teams; do not modify
└── orchestrator.py                 # shared integration point
```

Repository-level supporting paths remain:

```text
CTI-Tool/
├── AGENTS.md
├── README.md
├── requirements.txt
├── .env.example
├── config/
│   ├── sources.json
│   ├── collection_settings.json
│   ├── preprocessing_rules.json
│   ├── privacy_rules.json
│   ├── dark_web_sources.example.json
│   └── dark_web_sources.local.json       # ignored by Git
├── contracts/
│   ├── external_cti_item.schema.json
│   ├── external_export_manifest.schema.json
│   ├── command.schema.json
│   ├── job_status.schema.json
│   ├── integration_error.schema.json
│   ├── event.schema.json
│   └── README.md
├── data/
│   └── external/
│       ├── raw/
│       ├── processed/
│       ├── review/
│       ├── state/
│       └── exports/
└── tests/
    └── external_sources/
        ├── fixtures/
        ├── unit/
        └── integration/
```

### Shared-module and team-boundary rules

1. Reuse `backend/app/pipeline/ingestion/base_connector.py` and emit the shared `RawRecord` contract from `backend/app/pipeline/common/cti_schema.py`.
2. Reuse approved capabilities from `backend/app/pipeline/preprocessing/`; do not copy them into the External Sources package. External-only preprocessing behavior may be added only as composition around the shared stages.
3. Treat `backend/app/pipeline/common/`, `backend/app/pipeline/preprocessing/`, `backend/app/pipeline/classification/`, and `backend/app/pipeline/orchestrator.py` as shared integration surfaces, not External Sources-owned modules.
4. Do not modify `backend/app/pipeline/ingestion/internal/`, `backend/app/pipeline/extraction/`, `ml/`, storage-team code, dashboard/API code, or frontend code.
5. If a shared contract or shared module cannot support a required External Sources behavior, stop before editing it and report the exact proposed change, affected consumers, compatibility impact, and tests required. Implement the shared change only after explicit approval.
6. Keep External collection state, privacy handling, export contracts, application services, and source-specific connector logic inside the canonical External Sources package or the repository-level External-owned `config/`, `contracts/`, `data/external/`, and `tests/external_sources/` paths shown above.
7. The versioned External export schema is a handoff contract; it must map explicitly to the existing shared `RawRecord`/`CTIObject` flow rather than silently redefining either shared type.
8. Existing prototype modules under `src/` may be read and selectively migrated, but do not extend them as the final implementation and do not leave duplicate active collectors, schemas, storage helpers, classifiers, exporters, or orchestration paths.

Empty runtime directories may be retained with `.gitkeep`, but generated datasets, local dark-web source files, logs, secrets, model artifacts that cannot be redistributed, browser profiles, and temporary files must be ignored appropriately.

---

## 4. Cross-Team Data Contract

The external JSON export is a versioned contract between this team and downstream analysis/storage teams.

Every exported item must validate against `contracts/external_cti_item.schema.json` and have this logical structure:

```json
{
  "schema_version": "1.0",
  "record_id": "...",
  "source_item_id": null,
  "source": "...",
  "source_type": "rss",
  "category": "...",
  "title": "...",
  "link": "...",
  "content": "...",
  "summary": "...",
  "published": null,
  "updated_at": null,
  "author": null,
  "tags": [],
  "language": "en",
  "collected_at": "...",
  "content_hash": "sha256:...",
  "classification": {
    "status": "not_required",
    "label": null,
    "score": null,
    "model_version": null
  },
  "metadata": {}
}
```

Contract rules:

1. Required keys must remain present even when nullable.
2. `content` must be plain, substantial text whenever extraction is possible, never raw HTML.
3. Source-specific structured information belongs in `metadata` without changing the common top-level contract.
4. Do not remove or change the meaning/type of an existing field without incrementing `schema_version` and documenting the migration.
5. Preserve provenance when duplicates are merged using fields such as `metadata.observed_in` and source-specific identifiers.
6. Generate stable identity in this order when available:
   - Official source identifier such as CVE, GHSA, Reddit post ID, feed GUID, or Telegram message ID.
   - Canonical URL.
   - Hash of stable fields such as source, title, and published time.
7. Use SHA-256. `record_id` may be a stable, sufficiently long encoded prefix, but never rely on a very short collision-prone hash.
8. Deduplicate only within external-source outputs. Cross-team deduplication belongs to the central integration/storage team.

---

## 5. Incremental Collection and Per-Stage Hashing

Incremental change detection applies to **every collector, source, canonical URL, item, and processing stage**, not only manually submitted URLs.

Maintain JSON-backed state containing, where applicable:

- `source_config_hash`
- `etag`
- `last_modified`
- `raw_content_hash`
- `extracted_content_hash`
- `clean_content_hash`
- `privacy_output_hash`
- `record_hash`
- `last_checked`
- `last_changed`
- `last_successful_run`
- `known_sub_links`
- Per-stage `input_hash`, `output_hash`, status, timestamp, and implementation/rules/model version.

Hashing rules:

1. Use canonical deterministic serialization before hashing structured data.
2. Use SHA-256 consistently.
3. Canonicalize URLs before using them as state keys: lowercase scheme/host, remove fragments and configured tracking parameters, normalize default ports, and preserve meaningful query parameters.
4. Before downloading full content, use HTTP conditional requests with `If-None-Match` and `If-Modified-Since` when supported.
5. A `304 Not Modified` response updates `last_checked` and skips downstream processing.
6. When the raw response changes, calculate the extracted-text hash. If extracted content is unchanged, do not repeat cleaning, privacy handling, classification, or export.
7. A stage may be skipped only if its input hash, its configuration/rules/model hash, and its implementation version are unchanged and the prior stage execution completed successfully.
8. If preprocessing rules, privacy rules, classifier model, or stage implementation changes, rerun that stage and all dependent downstream stages even when source content is unchanged.
9. Never use Python's process-randomized built-in `hash()` for persistent identity.
10. Do not store credentials, tokens, or unredacted detected secrets in state files or logs.

For listing pages, store:

- Listing page raw/extracted/clean hashes.
- A stable hash of the sorted current canonical link set.
- `known_sub_links`.
- Independent state for every sub-link.

On a later run:

- New sub-link: fetch and process it.
- Known unchanged sub-link: skip it.
- Known changed sub-link: process the changed stages.
- Missing sub-link: mark `missing_from_source` with an observation timestamp; never delete its prior record automatically.

The system must still contact a source to determine whether it changed unless a source-specific mechanism provides a trustworthy change signal. Hashing does not eliminate the initial check request.

---

## 6. Build Phases

### Phase 0 — Foundation, State, and Contracts

Create the project structure and implement the shared foundations before any collector:

- `AGENTS.md`.
- Unified schema/dataclass or equivalent typed model.
- JSON Schema contracts for items and export manifests.
- Versioned, transport-independent schemas for commands, job status, integration errors, and events.
- Central logger.
- Config loader and validation.
- Shared HTTP client with retries, exponential backoff, timeouts, response-size limits, user agent, and conditional-request support.
- Canonical URL utility.
- SHA-256 hashing utility.
- JSON storage helpers: `save_json`, `load_json`, atomic replace, `latest_file`, and timestamped filenames.
- JSON-backed state manager with safe atomic writes and corruption recovery behavior.
- Run ID generation and run-manifest skeleton.
- Framework-independent application-service interfaces for collection, manual URLs, source management, and jobs. These interfaces must be callable from tests and CLI code without HTTP, FastAPI, Flask, a message queue, or the central database.
- Test structure and realistic fixtures.

Use atomic writes for state and exported JSON so interruption cannot leave half-written files. Do not implement a collector in this phase.

### Phase 1 — General Web Crawler and Page-Type Detection

Implement a reusable `WebCrawler` that accepts a public HTTP/HTTPS URL and:

- Fetches through the shared HTTP client.
- Follows only a configured limited number of redirects.
- Accepts HTML-compatible content types only.
- Extracts clean main content with `readability-lxml` and `BeautifulSoup`.
- Removes scripts, styles, navigation, advertisements, forms, and comments from extracted HTML.
- Returns raw response metadata, extracted text, canonical URL, candidate links, hashes, and errors in a structured result.

Implement page-type detection for:

- `article`
- `listing`
- `unknown`

Use multiple explainable signals: extraction yield, repeated `<article>` or card structures, headline-like same-domain links, text density, headings, metadata, and clustering. Return:

```json
{
  "page_type": "article",
  "confidence": 0.82,
  "candidate_links": [],
  "signals": {}
}
```

Do not force a high-confidence decision when evidence is weak. Keep the class importable and independent because RSS, CERT, social, dark-web where applicable, and manual URL handling reuse it.

### Phase 2 — Text Preprocessing and Sensitive-Data Handling

Implement `TextPreprocessor` to:

- Strip HTML remnants and decode entities.
- Normalize line endings and Unicode safely.
- Remove invisible/control characters while preserving useful text.
- Remove configurable boilerplate lines such as cookie notices, share bars, newsletter prompts, navigation fragments, and repeated legal/footer text.
- Collapse excessive whitespace while preserving paragraphs and headings.
- Avoid destructive transformations that alter IOCs, code snippets, hashes, CVE identifiers, URLs, domains, IP addresses, or command lines.

Boilerplate rules must live in `config/preprocessing_rules.json`, have a rules version, and be included in stage hashing.

Also implement a separate privacy step after normal text cleaning. Detect and classify potentially sensitive values into:

- `possible_cti_indicator`
- `public_attribution`
- `possible_personal_data`
- `possible_secret`
- `unknown`

Privacy rules:

1. Do not blindly delete emails, IP addresses, domains, URLs, usernames, filenames, or hashes because they may be valid CTI evidence or future IOCs.
2. Redact only high-confidence non-CTI personal data and exposed secrets according to configurable policy.
3. Make redaction deterministic and auditable.
4. Store only redaction categories and counts in metadata; never copy a detected secret into logs or audit metadata.
5. Preserve the distinction between cleaned pre-privacy content and approved export content through hashes and stage state. Avoid retaining unredacted personal data longer than operationally required.
6. If context is ambiguous, flag the item for review rather than destructively removing a possible CTI indicator.

Example metadata:

```json
{
  "privacy": {
    "status": "reviewed",
    "pii_detected": true,
    "redactions_count": 2,
    "redaction_types": ["phone_number", "possible_api_token"],
    "cti_value_types_preserved": ["ipv4", "domain"]
  }
}
```

### Phase 3 — RSS Feeds

Collect from trusted curated feeds such as The Hacker News, BleepingComputer, Krebs on Security, Cisco Talos, and SANS ISC using `feedparser`.

RSS remains a dedicated collector because feeds provide structured metadata for many items efficiently. Source definitions, enable flags, categories, limits, and lookback windows belong in config.

For each feed item:

- Capture GUID/source item ID, title, canonical link, summary, author, tags, and timestamps.
- Use conditional feed requests and per-feed state when supported.
- Use the shared WebCrawler to enrich the linked article with full text.
- Clean and privacy-check the extracted text.
- If full extraction fails, do not falsely label the summary as full content. Set `metadata.content_status = "summary_only"` and send it to review output unless the downstream contract explicitly allows summary-only records.
- Trusted curated security RSS bypasses relevance classification.

Do not replace feed parsing with generic listing-page crawling.

### Phase 4 — CERT Security Advisories

Implement a dedicated collector for configured sources including CISA, CERT-EU, and CERT-AT.

At implementation time, verify the current official delivery mechanism for each exact content category: RSS/Atom, JSON/API, downloadable catalog, or bounded HTML listing. Do not assume that one statement about an organization applies to every feed/category.

Use official structured sources when available and the shared WebCrawler for full advisory text when necessary. Code may reuse shared feed/HTTP parsing utilities, but CERT orchestration and mapping remain a dedicated collector.

Add CISA Known Exploited Vulnerabilities as a configurable structured source if it remains officially available and fits the agreed source configuration.

Trusted CERT content bypasses relevance classification.

### Phase 5 — Vulnerability and Advisory Databases

Use official structured interfaces only; never scrape vulnerability databases when their required data is available officially.

Implement configured collection from:

- NVD CVE API.
- Official CVE/MITRE records for CVE IDs discovered from the incremental collection window.
- GitHub Global Security Advisories API.
- CISA KEV when enabled and not already handled by the CERT design.

Collect and map, as available:

- CVE ID and GHSA ID.
- Descriptions.
- Published and modified timestamps.
- CVSS version, score, vector, and severity.
- CWE values.
- Affected ecosystems/packages/version ranges.
- References.
- KEV status and relevant official dates.

Requirements:

- Use incremental published/modified windows and pagination.
- Persist sync checkpoints only after successful processing of the relevant page/window.
- Deduplicate CVE/GHSA observations while preserving `metadata.observed_in` and source-specific data.
- Use optional environment variables such as `NVD_API_KEY` and `GITHUB_TOKEN` only where officially supported.
- Handle multiple CVSS versions without assuming one fixed response path.
- Trusted official vulnerability/advisory sources bypass relevance classification.

### Phase 6 — Existing Classification Model Integration

A trained classification model already exists and will be uploaded by the user when this phase is reached. Do not train, retrain, substitute, or generate a placeholder model.

If the artifact has not been provided, stop and request:

- The trained model artifact.
- Its serialization/framework and dependency versions.
- Label mapping and acceptance rule.
- The training script or exact inference preprocessing specification.
- Representative validation examples if available.

Implement a thin wrapper that:

- Loads the model lazily once and reuses it.
- Exposes a typed classification result rather than only a Boolean when the model supports score/label.
- Replicates exactly any preprocessing performed outside the serialized model pipeline during training.
- Records model version/hash in per-stage state and exported classification metadata.
- Handles empty/short input explicitly.
- Tests preprocessing parity and varied realistic content. Do not require predictions with and without preprocessing to differ; verify parity with the training path instead.

Classification applies to:

- Reddit.
- Hacker News.
- Telegram.
- Dark-web content unless its configured source is explicitly approved as curated and guaranteed relevant.
- Manual URLs and generic web content.

Classification does not apply to trusted RSS, CERT, NVD/CVE, GitHub Global Security Advisories, or CISA KEV.

On a missing model or prediction error:

- Do not silently discard the collected item.
- Do not silently mark it accepted.
- Set classification status to `error` or `not_run`.
- Write it to the review output with the error category.
- Exclude it from the accepted classified final dataset unless an explicit approved policy says otherwise.

### Phase 7 — Social and Community Sources

Build each source as an independent collector using the shared infrastructure.

#### Reddit

Prefer a currently permitted official/public structured interface if available for the required public data. If the agreed implementation uses Playwright, keep it optional, bounded, configurable, and isolated so failure or missing browser dependencies do not affect other collectors. Extract public configured subreddit posts only. For link posts, fetch the linked article through WebCrawler subject to URL-safety rules.

#### Hacker News

Use the current documented Algolia public Search API when verified. Use plain HTTP requests, incremental windows, source IDs, pagination, and linked-article extraction where appropriate.

#### Telegram

Collect only from operator-configured, verified, legitimate public channels. Use public `t.me/s/{channel}` previews with requests and BeautifulSoup when accessible. Do not log in, message users, join private channels, bypass access controls, or make Telegram availability a dependency for the rest of the run. Track Telegram message IDs and linked content independently.

All social/community items pass through cleaning, privacy handling, and classification before acceptance.

GitHub Global Security Advisories are not a social-media source; keep their implementation in Phase 5.

### Phase 8 — Curated Dark-Web Sources

Dark-web collection is an intentional part of this external-source team's scope.

Implement strictly read-only, GET-only, curated-source-only collection through a configured Tor SOCKS5 proxy.

Requirements:

1. Never hardcode or fabricate onion addresses.
2. Commit only `dark_web_sources.example.json` with clearly fake placeholders and `enabled: false`.
3. Load real verified sources from `dark_web_sources.local.json` or an approved secret/config mechanism; ignore the local file in Git.
4. Never log full sensitive onion URLs if the configured logging policy requires redaction.
5. Do not implement arbitrary onion discovery, search-engine crawling, recursive crawling, authentication, forms, purchases, uploads, messaging, or file downloads.
6. Restrict collection to configured hosts and bounded configured paths/pages.
7. Apply timeouts, response-size limits, content-type checks, retries with conservative backoff, and per-source rate limits.
8. Fail gracefully and produce a clear phase result when Tor is unavailable. No other phase depends on Tor.
9. Support an already-running Tor proxy. Optionally support start/stop of a configured local Tor executable through an environment variable, but start only the exact configured binary and stop only the process created by this run.
10. Never terminate Tor Browser or unrelated Tor processes.
11. Apply extraction, cleaning, privacy handling, hashing, and classification policy independently to every onion URL/item.

### Phase 9 — Manual URL Submission and URL Routing

Implement a backend function such as:

```python
add_manual_source(url: str) -> dict
```

It is the future dashboard's general entry point for a user-submitted public URL. It must first route known structured URLs to the best available adapter:

- GitHub advisory URL -> GitHub Advisory adapter/API.
- GitHub release/repository/file URL -> appropriate public GitHub API adapter where available.
- CVE/NVD URL -> vulnerability adapter.
- RSS/Atom URL -> RSS adapter.
- Configured onion URL -> dark-web adapter and Tor policy.
- Other HTTP/HTTPS URL -> generic WebCrawler.

Prefer an official structured API over HTML scraping. Public GitHub pages containing news, releases, advisories, README text, or public files can be collected when supported. Private/authenticated GitHub resources are outside scope unless a later approved requirement adds official authentication.

#### Manual URL security

- Allow only HTTP and HTTPS, plus `.onion` only through the explicit dark-web route.
- Reject embedded credentials.
- Reject localhost, loopback, private, link-local, multicast, unspecified, and reserved IP ranges.
- Resolve and validate DNS before connection and revalidate every redirect destination to reduce SSRF and DNS-rebinding risk.
- Limit redirects, response size, content type, and timeouts.
- Never forward user credentials, cookies, or authorization headers to submitted destinations.
- Never download files or execute page content.
- Canonicalize the URL before state lookup.

#### Article flow

1. Validate and route the URL.
2. Load its state and perform a conditional request where possible.
3. If unchanged, return `status: "unchanged"`.
4. Extract, clean, privacy-check, classify when required, and store if accepted.
5. Update hashes and stage state atomically.

#### Listing flow

For a listing/index page:

- Extract candidate headline/article links.
- Restrict normal web candidates to the same registrable domain and approved schemes.
- Cap candidates using configurable limits, for example 15–20.
- Follow only one level deep; never recurse from child pages.
- Canonicalize and compare the sorted link set with `known_sub_links`.
- Fetch new links and changed known links only.
- Maintain separate hashes/stage state for the listing and every child URL.
- Store genuine listing introduction text only if substantial and accepted.

Always return a structured result and do not raise for normal collection failures:

```json
{
  "status": "stored | ignored | unchanged | listing_processed | review_required | error",
  "message": "...",
  "records_created": 0,
  "records_updated": 0,
  "canonical_url": "..."
}
```

This phase contains backend logic only, not UI work.

### Phase 10 — External Dataset Export and Handoff Manifest

Create one `run_id` at orchestration start and propagate it to all phase outputs. Merge only outputs belonging to the intended run/checkpoint set; do not blindly combine unrelated "latest" files from different runs.

Export:

```text
data/exports/final_dataset_<run_id>.json
data/exports/external_export_manifest_<run_id>.json
```

The exporter must:

- Load successful outputs for the current run.
- Validate every accepted record against the versioned JSON Schema.
- Exclude empty-content and classification-error records from the accepted dataset, while preserving them in review/error outputs.
- Perform external-source deduplication using official IDs, canonical URLs, and normalized content hashes.
- Preserve all provenance when merging observations.
- Assign stable `record_id` values.
- Sort deterministically so repeated exports are reproducible.
- Write files atomically.
- Calculate and record the final dataset SHA-256.

The manifest must validate against its contract and include at least:

```json
{
  "schema_version": "1.0",
  "producer": "external-sources-team",
  "run_id": "...",
  "started_at": "...",
  "completed_at": "...",
  "status": "completed | partial | failed",
  "dataset_file": "...",
  "dataset_sha256": "sha256:...",
  "total_records": 0,
  "accepted_records": 0,
  "review_records": 0,
  "duplicates_removed": 0,
  "sources": {},
  "failed_sources": [],
  "classifier_model_version": null
}
```

The final JSON and manifest are the handoff artifacts for downstream analysis and storage teams.

### Phase 11 — Dashboard/Platform Integration Adapter

This phase connects the completed external-source service to the wider CTI platform. Do not start it until Phases 0–10 are complete and the external-sources, dashboard, analysis, and storage teams have agreed on:

- Transport: internal REST API, message queue, event bus, or another approved mechanism.
- Authentication and authorization ownership.
- Deployment/network topology.
- Synchronous versus asynchronous operations.
- Result delivery to the central storage team.
- Command, job-status, cancellation, error, and event contract versions.

The dashboard itself remains outside this repository and is the sole end-user interface in production. Collectors must never be imported or called directly by dashboard code. The integration adapter must call the framework-independent application services created earlier.

The application-service boundary must support these logical operations, subject to authorization and policy:

```python
start_collection(...)
collect_source(source_id, ...)
add_manual_source(url, ...)
recheck_url(url, force=False, ...)
list_sources(...)
get_source_status(source_id, ...)
request_source_enable(source_id, ...)
disable_source(source_id, ...)
get_job_status(job_id, ...)
cancel_job(job_id, ...)
get_latest_export(...)
```

Long-running operations must use an asynchronous job-oriented contract. An accepted command returns a stable `job_id`; it does not hold a dashboard request open while collection completes. Supported job states must include:

- `queued`
- `running`
- `completed`
- `partial`
- `failed`
- `cancellation_requested`
- `cancelled`

Cancellation is cooperative: do not kill unrelated processes or leave state/output half-written. A job must expose progress by safe aggregate counts and phase/source status without returning credentials, secrets, full sensitive onion URLs, or unredacted source content in error messages.

The adapter must not bypass:

- URL and SSRF validation.
- Source allowlists and configured collection bounds.
- Role/approval policy.
- Per-source enable/disable state.
- Hash/state tracking.
- Privacy handling.
- Classification policy.
- Rate limits and resource limits.
- Central logging and job auditing.

Adding an ordinary source through the dashboard must create it as `pending_review` or `disabled` unless an approved policy explicitly permits automatic activation. Adding or changing a dark-web source requires an explicitly authorized operator workflow and must never be automatically activated by an untrusted dashboard request.

If the teams choose REST, use an internal versioned path such as `/api/v1/` and return structured request-validation errors. If they choose a queue/event system, preserve the same semantic command and job contracts. Transport-specific schemas must map to the Phase 0 contracts rather than redefining business behavior.

Test the adapter with authentication/authorization boundaries, duplicate command submission, idempotency keys where applicable, retries, cancellation, partial failure, invalid URLs, unauthorized source changes, and safe error serialization.

---

## 7. Main Orchestration

`main.py` must:

1. Generate a run ID and initialize the manifest.
2. Load and validate configuration.
3. Run enabled collectors in a deterministic sequence.
4. Isolate every phase and source failure.
5. Reuse the state manager and per-stage hashes to skip unchanged work.
6. Send classification errors and privacy ambiguities to review output.
7. Export the accepted external dataset and manifest.
8. Log a concise final summary without exposing secrets or sensitive source details.
9. Return a nonzero process exit code only according to a documented policy, distinguishing total failure from an allowed partial run.

`main.py` is an internal development, testing, and authorized-maintenance orchestration adapter, not an end-user interface and not the owner of business logic. It must call the same application services that the production Dashboard/Platform Integration Adapter calls. Do not create two separate business-logic paths for CLI and dashboard requests, and do not let internal CLI use bypass production validation or policy.

All collectors must be independently enableable/disableable in configuration. Disabling one collector must not require code changes.

---

## 8. Testing Requirements

For every phase:

- Add unit tests for deterministic logic.
- Add realistic sanitized fixtures for external HTML/API/feed responses.
- Mock unavailable services honestly.
- Test malformed data, timeouts, rate limiting, partial responses, encoding issues, and missing fields.
- Test state migration/corruption behavior and atomic writes.
- Test hash stability and invalidation when content, rules, config, implementation version, or model changes.
- Test that cosmetic raw HTML changes do not force unnecessary downstream work when extracted content is identical.
- Test canonical URL equivalence and meaningful query-parameter preservation.
- Test deduplication without losing provenance.
- Test SSRF rejection, redirect validation, size limits, and non-HTML rejection for manual URLs.
- Test application-service commands without starting an HTTP server.
- Test command validation, job-state transitions, idempotent duplicate requests where applicable, and safe error responses.
- Test that dashboard and authorized internal adapters enforce the same application-level validation and policy, and that no collector is directly exposed as an end-user command.
- Validate produced examples against every applicable contract JSON Schema.

Live network tests must be marked and separable from the default deterministic test suite. Never make ordinary unit tests depend on Tor, GitHub, NVD, CISA, Reddit, Telegram, or another live service.

---

## 9. Deliverable Report for Every Phase

After completing a phase, stop and report:

1. Files created.
2. Files modified.
3. Design decisions and any justified deviations.
4. Tests executed and their exact result.
5. Whether testing was live, mocked, or both.
6. Known limitations or blocked integrations.
7. Any contract/config/dependency changes.
8. The exact next phase, without starting it.

Do not proceed until the user explicitly confirms.

---

## 10. Start Instruction

Start with **Phase 0 — Foundation, State, and Contracts** only.

First inspect the repository, summarize any existing relevant files, and then implement Phase 0 without deleting or rewriting correct user work. Run its tests, provide the required phase report, and wait for confirmation before Phase 1.
