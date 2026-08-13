# Backend, Internal Sources, Database, and Sharing Report

## Scope

This implementation completes the backend foundation required to continue the graduation-project CTI lifecycle. It follows the practical architecture in `Explain Project.docx` and adapts the cited ThreatWise AI paper to a maintainable student prototype rather than reproducing every research component.

## Implemented work

### Central backend and database

A FastAPI application and source-independent SQLAlchemy repository were added. PostgreSQL is the main database, while SQLite supports fast local tests. The schema stores sources, original raw items, threat events, indicators, entities, enrichments, correlations, Wazuh sessions, pipeline runs, users, and audit entries.

Raw data is retained before analysis. This allows parsing or extraction errors to be investigated without losing the source alert or document.

Event persistence is idempotent for repeated source ingestion. Existing indicators, entities, and relationships are synchronized by their stable semantic keys rather than deleted and recreated, so duplicate uploads do not violate database constraints and previously stored indicator enrichment records remain attached.

An optional Adminer 5.4.1 service was added for local visual inspection of PostgreSQL. It is isolated behind the explicit `database-ui` Compose profile, binds only to `127.0.0.1:8080`, and reaches PostgreSQL through the internal Compose hostname `db`. PostgreSQL itself remains unpublished. The service is intended for inspecting tables, relationships, and demonstration records; it is not part of the deployed application or a replacement for the API.

### Internal Wazuh and Dionaea sources

The Wazuh connector reads JSON arrays, wrapped JSON lists, JSONL, and NDJSON. It preserves every alert and normalizes the fields needed by the pipeline. Alerts are grouped by source IP. More than 30 minutes of inactivity closes a session.

The session feature vector contains alert volume, duration, Wazuh rule levels, distinct rules, destinations, URLs, ports, IoC counts, failed actions, and HTTP method counts. Isolation Forest analyzes batches of four or more sessions. A clearly identified deterministic fallback is used for smaller demonstration files so the project does not misrepresent a model trained on insufficient data.

All sessions are stored. Outlier sessions additionally become internal CTI events and enter the same schema used by external intelligence.

The direct Dionaea connector reads the official `log_json` JSONL structure, retains the original record, normalizes connection and protocol fields, counts captured credential attempts and commands, and sends its sessions through the same outlier pipeline. A pinned, lightweight Dionaea image is available through an explicitly selected local-only Compose profile. It publishes no host ports, and its Docker network blocks external routing.

Sensitive password/token fields are redacted from CTI event copies. Original honeypot records remain in protected raw storage for investigation.

### AI and model use

The fine-tuned DNRTI BERT model in `ml/models/dnrti_bert_ner` is the primary NER runtime. `ml/models/dnrti_sklearn_ner` is the secondary fallback only. Isolation Forest is used for internal anomaly detection, and TF-IDF/cosine similarity is used for prototype advanced textual correlation. Rule-based fallbacks remain explicitly labeled and are not described as trained ML.

### Enrichment, scoring, and correlation

CVEs can be enriched from the official NVD API. Risk scoring produces a transparent 0-100 value using CVSS/severity, indicators, confidence, source diversity, correlations, and the internal-outlier signal. Exact shared indicators provide simple correlation. TF-IDF similarity provides advanced document correlation. Correlation records include the method, score, reason, and evidence.

### API, security, and audit

The API provides authentication, users, sources, Wazuh/external upload, events, indicators, NVD enrichment, correlations, outliers, runs, dashboard summaries, STIX export, MISP sharing, and audit routes. Passwords use scrypt. Tokens are signed and expire. Roles are admin, analyst, and viewer. Material analyst/admin actions are audited.

### Sharing

Threat events can be exported as STIX 2.1 bundles without any external service. MISP integration maps CTI indicators to MISP attributes, creates events as unpublished, supports a safe dry-run, and fails clearly when no MISP instance is configured.

MISP is not installed inside the application stack because the official platform has its own database, Redis, modules, TLS, and maintenance requirements. It remains an optional external instance connected through the MISP API.

## Deliberate project simplifications

- PostgreSQL replaces the paper's extra MongoDB store to avoid maintaining two application databases.
- File-based Wazuh ingestion and direct Dionaea JSON-log ingestion are implemented before live Wazuh streaming.
- No automatic daily model retraining is performed.
- MISP is optional rather than required for the CTI backend to function.
- Redis/Celery, TAXII, live Suricata/Zeek/Sysmon connectors, and the frontend remain later work.

## Reproducible environment

`compose.yaml` starts PostgreSQL and the FastAPI backend after Docker Desktop is running. The optional `honeypot` profile also starts Dionaea, while the optional `database-ui` profile starts the local Adminer database browser. `.env.example` documents required secrets. One project-wide Python 3.12 environment named `.venv` runs the backend, collectors, and model utilities locally. The internal demonstration datasets are `data/internal_samples/wazuh_alerts_sample.json` and `data/internal_samples/dionaea_events_sample.jsonl`.

The reason and acceptance criteria for MongoDB, hosted MISP, live Wazuh, Redis/Celery, TAXII, and other heavier extensions are documented in `docs/architecture/future_bound_work.md`.

## Validation result

Validation covers legacy external-pipeline behavior, BERT-first model priority, Wazuh and Dionaea formats, 30-minute session splitting, append-safe session identifiers, feature extraction, Isolation Forest/fallback labeling, API authentication, PostgreSQL persistence, sensitive-value redaction, dashboard counts, STIX export, MISP dry-run mapping, compilation, Docker Compose configuration, and Git whitespace/status checks. The exact 2026-08-12 execution results are recorded in `Parts Report/Dionaea_Backend_Completion_Report.md`.
