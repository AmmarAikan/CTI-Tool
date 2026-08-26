# External Sources Phase 11 — internal REST integration

The canonical adapter is `backend/app/pipeline/ingestion/external/integration/`. FastAPI is used because the repository had no existing API framework. It is an internal dashboard/backend adapter, not a public collector API, and all routes are versioned under `/api/v1/external-sources`.

## Boundaries

Routes depend on `CollectionService`, `ManualSourceService`, `SourceManagementService`, `JobService`, `JobRunner`, `Authenticator`, `Authorizer`, and `IdempotencyStore`. They do not import or invoke RSS, CERT, vulnerability, social, dark-web, crawler, classifier, privacy, exporter, or storage implementations directly. Deployment composition supplies those application services.

The adapter returns command/job/error shapes compatible with the Phase 0 contracts. Long operations return HTTP 202 with `job_id` and `queued` immediately. Mutating collection and manual-source commands support `Idempotency-Key`, scoped by authenticated subject and operation.

The canonical collection application service validates every requested ID against the configured registry before queueing. Unknown IDs return 404, disabled or Manual Source IDs return 409, invalid collection requests return 422, and unexpected command-acceptance failures return a redacted 503. OpenAPI documents these responses. Multi-source execution is deterministic, force mode is propagated to every selected source, connector-reported failures produce a partial aggregate when another source succeeds, and Manual URLs remain exclusive to the Manual Source operations.

Role policy distinguishes viewer, operator, source approver, dark-web approver, and administrator permissions. Ordinary enablement requests must remain `pending_review` or `disabled`. Dark-web enablement additionally requires `dark_web:approve`.

Responses remove URL/path/credential-like source metadata. Latest-export responses contain the contract-validated accepted dataset and its validated manifest, never filesystem paths. Exceptions become stable safe error categories without traces or internal exception text.

## Local development adapter

`integration/local.py` provides a static bearer-token authenticator, in-memory idempotency, a thread-based job runner, read-only source summaries, and application-service composition for enabled canonical collectors and Manual Source. At startup it loads public definitions from `config/sources.json` and operator-approved definitions once from the ignored `config/dark_web_sources.local.json`, rejects duplicate IDs, and builds collection, source-management, and Manual routing from that unified registry. Every enabled dark-web definition must use a credential-free HTTP(S) URL with an exact 56-character v3 onion label and a configured path inside `allowed_paths`; an invalid enabled definition aborts startup with only its safe source ID and reason category. Disabled invalid placeholders are ignored. No validation error or log contains an onion address. Source APIs expose only ID, display name, type, and status; onion URLs, allowed paths, rate limits, and Tor configuration remain confined to the canonical connector composition. A registered dark-web job executes only its requested parsed definition through `DarkWebConnector`; Tor failure is isolated to that source and there is no direct-web fallback. Collection jobs reuse canonical connectors, save per-source state under `data/external/state/`, and write accepted/review operational output under the corresponding `data/external/` directories. Each completed or partial run passes only its in-memory result batches to the sole canonical Phase 10 exporter; it never merges unrelated latest files. The exporter atomically writes the run-scoped dataset, manifest, and review artifact. Export failure remains visible as a safe `result.export.error` while collection stays completed. The latest-export operation revalidates the manifest, every dataset item, and the dataset SHA-256; absence of a valid export returns the documented 404 response. Manual Source composes the canonical URL policy, SSRF-protected HTTP client, crawler, preprocessing, privacy, classification, state manager, and atomic local record sink. Application results with `status=error` map to a failed job contract. These components are intended only for authorized local testing and maintenance; they are not durable, distributed, multi-process safe, or cloud-ready.

The local Manual Source sink maintains an atomic explicit checkpoint index for accepted manual records alongside the processed artifact. Material manual operations regenerate the canonical export using the prior validated accepted checkpoint and the current manual checkpoint set; ignored, rejected, privacy-review, and classification-error items are routed to the run review artifact. An unchanged recheck performs no export. Subsequent registered collection exports include the same explicit eligible manual checkpoints, so the canonical Phase 10 deduplicator can merge overlapping manual and registered observations by URL or content while preserving manual stable IDs and provenance. No directory-wide processed-file discovery is used.

The canonical logger writes internal job failures to `logs/cti_tool.log`. Entries include only `job_id`, `command_id`, safe `source_id`, and exception type. API job errors remain category-only and never expose exception text, credentials, content, source URLs, or filesystem paths.

Required local environment:

```text
EXTERNAL_API_TOKEN=<strong random local token>
EXTERNAL_API_ROLES=operator
EXTERNAL_API_DEV_WORKERS=2
```

Start on loopback only:

```powershell
python -m uvicorn backend.app.pipeline.ingestion.external.integration.local:app --host 127.0.0.1 --port 8000
```

Production must replace the local authenticator with the agreed identity provider, use a durable idempotency and job backend, compose the real application services, restrict network access, and add deployment monitoring. Docker and cloud deployment are outside Phase 11.
