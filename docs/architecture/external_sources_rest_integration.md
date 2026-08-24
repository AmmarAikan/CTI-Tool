# External Sources Phase 11 — internal REST integration

The canonical adapter is `backend/app/pipeline/ingestion/external/integration/`. FastAPI is used because the repository had no existing API framework. It is an internal dashboard/backend adapter, not a public collector API, and all routes are versioned under `/api/v1/external-sources`.

## Boundaries

Routes depend on `CollectionService`, `ManualSourceService`, `SourceManagementService`, `JobService`, `JobRunner`, `Authenticator`, `Authorizer`, and `IdempotencyStore`. They do not import or invoke RSS, CERT, vulnerability, social, dark-web, crawler, classifier, privacy, exporter, or storage implementations directly. Deployment composition supplies those application services.

The adapter returns command/job/error shapes compatible with the Phase 0 contracts. Long operations return HTTP 202 with `job_id` and `queued` immediately. Mutating collection and manual-source commands support `Idempotency-Key`, scoped by authenticated subject and operation.

Role policy distinguishes viewer, operator, source approver, dark-web approver, and administrator permissions. Ordinary enablement requests must remain `pending_review` or `disabled`. Dark-web enablement additionally requires `dark_web:approve`.

Responses remove URL/path/credential-like source metadata. Latest-export responses contain aggregate metadata and hashes only, never filesystem paths. Exceptions become stable safe error categories without traces or internal exception text.

## Local development adapter

`integration/local.py` provides a static bearer-token authenticator, in-memory idempotency, a thread-based job runner, read-only source summaries, and an application-service composition for enabled canonical RSS source jobs. RSS jobs resolve sources from `config/sources.json`, reuse the canonical connector, save per-source state under `data/external/state/`, and write accepted/review output under the corresponding `data/external/` directories. These components are intended only for authorized local testing and maintenance; they are not durable, distributed, multi-process safe, or cloud-ready.

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
