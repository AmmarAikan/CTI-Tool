# Backend Data Model

PostgreSQL is the central repository for both pipelines. SQLite uses the same ORM schema for local testing.

```text
Source
├── RawItem
│   └── ThreatEvent
└── PipelineRun

ThreatEvent
├── Indicator
│   └── Enrichment
├── Entity
└── ExtractedRelationship

ThreatEvent ── Correlation ── ThreatEvent
ThreatEvent ── optional link ── OutlierSession
User ── AuditLog
```

## Tables

- `sources`: connector identity, type, pipeline, enablement, and non-secret configuration.
- `raw_items`: immutable-source reference, original content, complete source JSON, and observation time. `(source_id, external_id)` is unique.
- `threat_events`: normalized CTI, classification, severity, explainable risk score, confidence, lifecycle timestamps, tags, and processing status.
- `indicators`: extracted IoCs keyed per event/type/value.
- `entities`: BERT/sklearn/structured entities keyed per event/type/value.
- `extracted_relationships`: within-event relationships produced by extraction.
- `enrichments`: provider result per indicator, initially NVD for CVEs.
- `correlations`: between-event exact matches and text similarity with score and evidence.
- `outlier_sessions`: every internal session, its feature vector, detector backend, anomaly result, and original alerts.
- `pipeline_runs`: processing counts, status, timestamps, paths, and failure information.
- `users`: hashed credentials and role.
- `audit_logs`: actor, action, resource, details, and time.

Secrets never belong in `sources.config`; they are environment variables.
