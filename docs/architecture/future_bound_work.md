# Future Bound Work

## Purpose

This file separates the completed graduation-project backend from heavier enterprise work. A deferred item is not required for the present ingestion, ML extraction, persistence, correlation, API, STIX, or MISP demonstration.

## Implemented boundary

The current system includes:

- External JSON file and authenticated/HMAC API ingestion with schema, bounds, ETag, pagination, stable identity, privacy filtering, a cumulative VPS snapshot that survives missed collection windows, and idempotent central storage.
- Live Dionaea JSON, lightweight SSH-auth JSON, and gateway web-access JSON from the VPS.
- Raw-record retention separate from unified processed CTI.
- Thirty-minute internal sessionization, Isolation Forest, retained normal sessions, and outlier-only CTI promotion.
- PostgreSQL central persistence, API authentication/roles/audit, NVD client, correlation, explainable risk, and STIX export.
- DNRTI BERT NER as primary and DNRTI sklearn NER as secondary fallback, with saved held-out evidence and runtime quality gates.
- Live MISP 2.5.44 on the VPS with unpublished, verified, idempotent event/attribute delivery.
- VPS-hosted External Sources with private job control, scheduled validated export, and no collaborator-computer availability dependency.
- Hardened VPS, loopback-only Gateway/MISP administration, SSH tunnels, scoped secrets, Dionaea egress controls, systemd collection, and log rotation.
- Incremental PostgreSQL comparison that skips semantically unchanged External records before BERT and bulk-prefetches existing identities.

## Deferred infrastructure

### Wazuh Manager/Indexer/Dashboard

Wazuh is intentionally not deployed on the current 12 GB VPS. Its file and authenticated Indexer connectors remain implemented and tested so a future larger or separate server can be integrated without redesigning the CTI schema.

Future value would include endpoint agents, rules/decoders, a SIEM dashboard, centralized host telemetry, and a read-only `wazuh-alerts*` stream. Completion would require a separate capacity decision, certificates, agent enrollment, retention, a least-privilege reader, live alert evidence, and backup/restore testing. Historical Wazuh sample data in PostgreSQL is not evidence of a live Wazuh server.

### MongoDB

MongoDB is not used. PostgreSQL relational tables plus JSON columns already preserve semi-structured raw records and give one transactional source of truth. Adding MongoDB now would duplicate credentials, consistency logic, and backup work without improving the graduation demonstration.

A future high-volume design may place immutable telemetry or long-lived baselines in object storage/MongoDB while keeping PostgreSQL authoritative for users, sources, events, indicators, correlations, runs, and audit records.

### Celery/Redis/Kafka workers

Current ingestion is bounded and synchronous. This keeps execution traceable and simple for the graduation scope. Large first-time snapshots can therefore occupy the request until BERT completes, although repeated snapshots use ETag and changed snapshots skip unchanged database records before the model. Celery/Redis or Kafka would add background scheduling, retries, backpressure, dead-letter handling, progress reporting, and horizontal workers when feeds grow. It would also require idempotent task keys, retry budgets, monitoring, recovery tests, and operational ownership.

MISP's internal Redis/Valkey is owned only by MISP and is not the backend task queue.

### Risk model

Risk is an explainable rule-based score using severity/CVSS, confidence, source diversity, correlations, and internal-outlier evidence. This supports transparent demonstrations and analyst review. It is not presented as a trained AI risk model.

A future learned scorer requires labelled outcomes, leakage-safe splits, calibration, class-imbalance handling, threshold policy, drift monitoring, explanations, and comparison against the current rules baseline.

### Relationship extraction

Relationship extraction remains a rule-based prototype. It produces auditable relationships from supported patterns but is not a general semantic relation model.

Future work may add a trained relation classifier, ontology constraints, negative examples, confidence calibration, and held-out evaluation before replacing the prototype.

### Stronger honeypot isolation

Dionaea currently runs in a constrained Docker network on the same physical VPS as loopback-only MISP. It has no MISP/backend secrets or shared data volumes and new outbound traffic is blocked, but all containers share one kernel.

The preferred future architecture moves Dionaea to a separate disposable VPS/VM, connects only its signed evidence path, adds independent snapshots/retention, and treats compromise of that host as expected. WireGuard or mTLS and a second provider/account boundary may be added.

### Production TLS, secrets, and availability

Current private services use SSH forwarding and lab self-signed MISP TLS. Future production work includes DNS, public-key infrastructure, mTLS or WireGuard, a secrets manager, key rotation automation, rate limiting at a reverse proxy, high availability, alerting, and tested disaster recovery.

### MISP extensions

MISP is live, but automatic publishing is deliberately disabled. Future work includes team browser access through a controlled network, richer taxonomies/galaxies, analyst approval workflows, bidirectional synchronization, scheduled export, and a dedicated least-privilege automation user instead of the bootstrap automation key.

### Other sources and frontend

Live Suricata, Zeek, Sysmon, firewall, TAXII, and Onion sources; Alembic operational migrations; model retraining automation; and the analyst frontend remain future work. Because the current VPS has no Tor proxy or approved live Onion source list, its External container does not mount the disabled example as though it were operational. Registered External additions still require reviewed configuration, while operator-supplied public URLs use the implemented Manual Source API. The existing FastAPI endpoints are the contract for the frontend phase.

## Not claimed

The project does not claim enterprise SOC scale, high availability, real-time streaming, a trained AI risk model, a trained relationship model, live Wazuh, live Onion coverage, a physically separate honeypot kernel, or completed off-host restore evidence.

## Completion rule

A future component becomes “implemented” only when the real service is deployed, secrets and network boundaries are protected, positive and negative tests pass, destination data is verified, repeat/retry behavior is measured, backup restoration succeeds, and the result is documented with sanitized evidence. Configuration placeholders alone do not count.
