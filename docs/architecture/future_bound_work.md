# Future Bound Work

## Purpose

This file defines the boundary between the completed graduation-project backend and heavier infrastructure that is intentionally postponed. The current system is a focused CTI prototype, not an enterprise SOC deployment. A postponed component is not required for the present ingestion, analysis, persistence, correlation, API, or STIX demonstration to work.

## Current backend boundary

The implemented backend includes external-source ingestion, Wazuh file ingestion, direct Dionaea JSON-log ingestion, raw-data retention, normalization, 30-minute internal sessionization, Isolation Forest outlier detection, CTI event creation, PostgreSQL/SQLite persistence, NVD enrichment, correlation, risk scoring, authentication, audit logging, STIX export, and a safe MISP client/dry-run path.

The local Dionaea source is deliberately lightweight. It runs only when the `honeypot` Compose profile is selected, writes the official `log_json` JSONL format to a persistent volume, and publishes no host ports. It is part of the implemented backend, not future work.

## Deferred infrastructure

### MongoDB

MongoDB is not required by the current prototype because PostgreSQL JSON columns already retain semi-structured raw records alongside the relational CTI model. Adding MongoDB now would duplicate storage, credentials, backup procedures, and consistency handling without improving the graduation demonstration.

A future high-volume deployment may use MongoDB for immutable raw telemetry and long-lived baseline sessions while retaining PostgreSQL for sources, users, events, indicators, correlations, and audit records. That change would require a retention policy, authenticated connections, encryption, backup/restore tests, and a clear source of truth.

### Full MISP deployment and synchronization

The backend already maps events to MISP, provides a dry run, checks connectivity, and can send an unpublished event when `MISP_URL` and `MISP_API_KEY` are configured. Hosting a complete MISP instance is deferred because it adds MariaDB, Redis, MISP modules, TLS certificates, administrator lifecycle, upgrades, backups, and its own security boundary.

Future work may add bidirectional synchronization, taxonomy and galaxy mapping, publishing approval, retry queues, duplicate-event handling, and scheduled pulls. The current backend remains complete without a continuously running MISP server.

### Live Wazuh platform

The current Wazuh connector accepts actual `alerts.json`, JSONL, and NDJSON exports. Running Wazuh Manager, Indexer, and Dashboard continuously is deferred because the single-node platform is materially heavier than the application backend.

Future work may place a Wazuh agent beside Dionaea, add custom decoders and rules, and stream or tail the resulting `alerts.json`. The direct Dionaea connector remains useful even after that addition because it preserves the original honeypot record before SIEM transformation.

### Background workers and streaming

The prototype processes a bounded upload or configured Dionaea log synchronously. Redis/Celery, Kafka, dead-letter queues, continuous file watching, distributed scheduling, and automatic model retraining are deferred until ingestion volume requires them. A future worker design must include idempotency, bounded retries, backpressure, observability, and safe recovery after partial failure.

### Other future integrations

TAXII server/client synchronization, live Suricata, Zeek, Sysmon and firewall connectors, production secrets management, Alembic migration operations, multi-node deployment, and a full analyst frontend are future extensions. The API already supplies the data needed by a later dashboard.

## Resource and safety reason

The development computer has approximately 16 GB RAM and limited free disk space. Wazuh and MISP are multi-service platforms and should not be kept running together with PostgreSQL, the BERT runtime, and development tools on this machine. Dionaea is retained because its official image is small and it can be safely demonstrated inside a local-only isolated network.

No honeypot port in this repository is bound to the host, LAN, or a public interface. Any future internet-facing honeypot must run on a separate, disposable VM or host with network segmentation, no personal credentials, no access to the development LAN, controlled egress, monitoring, and a documented legal/ethical scope.

## Future completion criteria

A deferred component should be called implemented only after its real service is deployed, secrets are protected, health checks pass, failure and retry behavior is tested, data is visible at the destination, an end-to-end test is recorded, and operating/backup instructions are documented. Configuration placeholders alone do not count as completed integration.
