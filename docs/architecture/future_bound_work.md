# Future Bound Work

## Purpose

This file defines the boundary between the completed graduation-project backend and heavier infrastructure that is intentionally postponed. The current system is a focused CTI prototype, not an enterprise SOC deployment. A postponed component is not required for the present ingestion, analysis, persistence, correlation, API, or STIX demonstration to work.

## Current backend boundary

The implemented backend includes external file and authenticated API ingestion, Wazuh file and authenticated Indexer ingestion, direct local and remote Dionaea JSON ingestion, raw-data retention, normalization, 30-minute internal sessionization, Isolation Forest outlier detection, CTI event creation, PostgreSQL/SQLite persistence, NVD enrichment, correlation, unified explainable risk scoring, authentication, audit logging, STIX export, and a safe MISP client/dry-run/send path.

The local Dionaea source is deliberately lightweight. It runs only when the `honeypot` Compose profile is selected, writes the official `log_json` JSONL format to a persistent volume, and publishes no host ports. It is part of the implemented backend, not future work.

## Deferred infrastructure

### MongoDB

MongoDB is not required by the current prototype because PostgreSQL JSON columns already retain semi-structured raw records alongside the relational CTI model. Adding MongoDB now would duplicate storage, credentials, backup procedures, and consistency handling without improving the graduation demonstration.

A future high-volume deployment may use MongoDB for immutable raw telemetry and long-lived baseline sessions while retaining PostgreSQL for sources, users, events, indicators, correlations, and audit records. That change would require a retention policy, authenticated connections, encryption, backup/restore tests, and a clear source of truth.

### MISP cloud deployment and synchronization

The backend maps events to stable MISP event/attribute UUIDs, provides a dry run, checks connectivity, and can send an unpublished event when `MISP_URL` and `MISP_API_KEY` are configured. Deploying the real MISP server is now part of the planned VPS phase, but remains uncompleted until SSH deployment and live acceptance evidence exist. It adds MariaDB, Redis, MISP modules, TLS certificates, administrator lifecycle, upgrades, backups, and its own security boundary.

After the server is accepted, later extensions may add bidirectional synchronization, richer taxonomy/galaxy mapping, publishing workflows, retry queues, verified repeat-send/upsert behavior, and scheduled pulls. MISP remains a sharing copy; PostgreSQL remains the central application database.

### Wazuh cloud platform

The Wazuh connectors accept actual `alerts.json`, JSONL, and NDJSON exports and can pull bounded, checkpointed pages from an authenticated Wazuh Indexer. Deploying Manager, Indexer, Dashboard, certificates, agents, least-privilege reader, and retention policy is part of the planned VPS phase, but is not complete before live health and end-to-end tests.

The VPS phase will place a Wazuh agent beside Dionaea and may add custom decoders/rules. The separate authenticated Dionaea sensor API remains useful because it preserves the original honeypot record before SIEM transformation.

### Public Dionaea deployment

The local isolated Dionaea profile remains implemented and safe for deterministic demonstration. A public Dionaea sensor is planned but not deployed. It should use a separate disposable VPS/VM; placing it beside Wazuh/MISP on one kernel is a documented residual risk, not the recommended architecture. Completion requires segmentation, controlled egress, log rotation, Wazuh monitoring, raw sensor API health, and verified absence of sensitive routes/secrets.

### Background workers and streaming

The prototype processes a bounded upload or configured API pull synchronously. Redis/Celery, Kafka, dead-letter queues, continuous scheduling, and automatic model retraining are deferred until ingestion volume requires them. A future worker design must include idempotency, bounded retries, backpressure, observability, and safe recovery after partial failure.

### Other future integrations

TAXII server/client synchronization, live Suricata, Zeek, Sysmon and firewall connectors, production secrets management, Alembic migration operations, multi-node deployment, and a full analyst frontend are future extensions. The API already supplies the data needed by a later dashboard.

## Resource and safety reason

The development computer retains PostgreSQL, the backend, and the BERT runtime. Wazuh and MISP are multi-service platforms and will move to adequately sized cloud infrastructure instead of competing with the model and development tools locally. The linked 8 GB VPS tier is also insufficient for all cloud components; capacity and separation requirements are recorded in `docs/operations/vps_deployment_plan.md`.

No local honeypot port in this repository is bound to the host, LAN, or a public interface. The planned internet-facing sensor must run on a separate disposable VM/host where possible, with network segmentation, no personal credentials, no development-LAN access, controlled egress, monitoring, retention, and documented legal/ethical scope.

## Future completion criteria

A deferred component should be called implemented only after its real service is deployed, secrets are protected, health checks pass, failure and retry behavior is tested, data is visible at the destination, an end-to-end test is recorded, and operating/backup instructions are documented. Configuration placeholders alone do not count as completed integration.
