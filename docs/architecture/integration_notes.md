# Integration Notes

## What Was Integrated

The prepared external JSON files under `data/external_samples/` are treated as external source inputs. They are not copied over the backend and they do not create a duplicate application.

New backend runtime modules add:

```text
common CTI schema
external connector contract
prepared JSON file connector
RSS connector scaffold
NVD structured-record connector
internal connector contract
text cleaning and normalization
deduplication
document relevance classification
regex IoC extraction
rule-based relation extraction
external pipeline orchestrator
Wazuh JSON/JSONL connector
Dionaea log_json JSONL connector and isolated local-lab service
source-IP sessionization
session feature extraction and outlier detection
PostgreSQL/SQLite persistence
NVD enrichment and explainable risk scoring
simple and text-similarity correlation
FastAPI, authentication, roles, audit logging, and uploads
STIX 2.1 export and optional MISP sharing
```

## Current Limitations

The document classifier currently uses a rule-based fallback unless a sklearn classifier path is provided through `CTI_CLASSIFIER_MODEL_PATH`.

Relation extraction is rule-based and intentionally conservative. It should not be described as ML-based.

The trained document classifier remains optional. The DNRTI BERT NER model is primary, and the DNRTI sklearn model is secondary.

Wazuh file processing and direct Dionaea JSON-log processing are implemented. Live Wazuh streaming, Suricata, Zeek, and Sysmon remain future extensions.

MISP submission is disabled unless `MISP_URL` and `MISP_API_KEY` are configured. Dry-run mapping and STIX export work without MISP. TAXII remains future work.

Schema creation currently uses SQLAlchemy metadata for the prototype. Versioned Alembic migrations should be introduced before a production deployment with existing data.

The authoritative list and rationale for deferred heavy infrastructure is `docs/architecture/future_bound_work.md`.

## Error Handling

Batch processing catches per-record failures and emits a failed CTI object with:

```text
processing_status=failed
processing_errors[].stage
processing_errors[].message
processing_errors[].connector_name
processing_errors[].source_record_id
```

## Secrets

API keys, tokens, credentials, local virtual environments, large model checkpoints, and archives must not be committed. Existing `.gitignore` already excludes the local BERT model directory, virtual environments, and archives.
