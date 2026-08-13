# Dionaea and Backend Completion Report

## Decision

The graduation-project backend remains a focused local prototype. PostgreSQL is the central application database, MISP remains an optional API integration target, and heavy multi-service infrastructure is documented as future bound work. Dionaea is included now because it is lightweight and provides an important real internal telemetry source.

## Dionaea integration

The project uses the official `dinotools/dionaea:0.11.0` image pinned to the verified digest in `infra/dionaea/Dockerfile`. The official `log_json` incident handler is enabled through a small derived image and writes newline-delimited JSON to a persistent Docker volume.

The Compose service is opt-in through the `honeypot` profile. It is attached to an internal Docker network and publishes no host ports. The backend joins the same isolated network only to generate a controlled test interaction while receiving the log through a read-only shared volume. This preserves a useful local lab without exposing intentionally vulnerable services to Windows, the LAN, or the internet.

The backend can ingest Dionaea data in two ways:

1. Upload JSON, JSONL, or NDJSON to `POST /api/v1/uploads/dionaea`.
2. Collect the shared container log through `POST /api/v1/internal/dionaea/collect`.

The connector follows the official JSON structure: connection protocol, transport and type; source/destination addresses and ports; timestamp; credential attempts; and captured commands. A content summary is produced without copying attempted passwords into analyst-facing text.

## Internal processing

Dionaea and Wazuh records use the same source-independent internal pipeline. Sessions are separated by source type and source IP, with a 30-minute idle boundary. Features include record count, duration, severity/rule information where present, destinations, ports, protocols/rules, IoCs, failed actions, credential attempts, and HTTP methods.

Four or more sessions use deterministic Isolation Forest. Smaller batches use the explicitly named non-ML heuristic. Every raw record and every session is stored; only outlier sessions become CTI events.

The raw repository retains the original honeypot JSON for investigation. CTI event copies recursively redact fields named password, token, secret, API key, or authorization so normal event APIs do not duplicate sensitive values.

## One Python environment

Two environments existed because Part 0 BERT work first required a clean Python 3.12 environment (`.venv_bert312`), while later backend work created another Python 3.12 environment (`.venv_backend`). Both now use the same interpreter version, and the BERT model was verified successfully from the backend environment. Keeping both therefore adds disk usage and dependency drift without adding isolation value.

The project now uses one root environment named `.venv`. The root `requirements.txt` includes backend, model/training, and external-collector dependencies. Current operational documentation uses only `.venv`; the old names remain only in historical Part 0 reports where they describe what happened during the original training run.

## Scope boundary

`docs/architecture/future_bound_work.md` records MongoDB, a hosted MISP stack, live Wazuh Manager/Indexer/Dashboard, background workers, TAXII, and additional SIEM connectors as future extensions. It explains the resource and maintenance cost, the intended future role, and the evidence required before any such integration can be called complete.

## Validation record

Validation completed on 2026-08-12 from the `ammar-internal-db` working tree:

- The single `.venv` loaded the primary DNRTI BERT model and returned three entities whose source was `dnrti_bert_ner`.
- 21 `unittest` backend, external-pipeline, API, Wazuh, and Dionaea tests passed.
- 29 legacy dark-web/external-collector checks passed.
- Ruff passed for every new or changed Dionaea/internal/API service file, `pip check` reported no broken requirements, Python compilation passed, and `git diff --check` found no whitespace errors.
- A clean Compose stack built and started PostgreSQL, FastAPI, and the pinned Dionaea image. PostgreSQL became healthy.
- A request sent from the backend inside `honeypot_lab` received HTTP 200 from Dionaea. Dionaea wrote one official JSONL record, the backend saw the same file through its read-only volume, and `POST /internal/dionaea/collect` persisted one raw record and one normal session with zero failures.
- Uploading `dionaea_events_sample.jsonl` collected five records, created five sessions, identified one Isolation Forest outlier, and created one CTI event.
- Uploading `wazuh_alerts_sample.json` collected eight records, created four sessions, identified one outlier, and created one CTI event.
- The combined dashboard contained two CTI events, six indicators, ten sessions, and two outliers. The Dionaea event exported as a valid STIX bundle with four objects, and MISP dry-run mapping succeeded while correctly reporting that no real instance was configured.
- Database checks confirmed that the original fake credential was retained in raw storage, was absent from the event copy, and `[REDACTED]` was present in its place.
- Recollecting the unchanged append-only Dionaea log left the database at ten sessions and two events, confirming stable session upserts rather than duplication.
- Dionaea and PostgreSQL published no host ports. FastAPI alone was bound to `127.0.0.1:8000`.

The disposable validation containers, volumes, database, logs, and credentials were removed after the test. The ready local images `cti-dionaea:0.11.0` and `graduationproject-backend:latest` remain available for the user's own `.env` configuration.
