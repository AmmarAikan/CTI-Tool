# System Architecture

This project is an AI-based Cyber Threat Intelligence platform. The repository now separates three pipelines instead of treating every source as the same problem.

## Pipeline A: Offline NLP/ML Training

Part 0 is the offline model training pipeline. It uses the DNRTI BIO dataset to train and evaluate cyber NER models before runtime.

Flow:

```text
DNRTI Dataset
-> Dataset Validation
-> BIO/IOB Preprocessing
-> Train / Validation / Test Splits
-> NER Model Training
-> Model Evaluation
-> Saved Model and Label Map
-> Runtime NERExtractor
```

Implemented files:

```text
ml/common/
ml/preprocessing/
ml/training/
ml/evaluation/
ml/models/dnrti_sklearn_ner/
ml/reports/
backend/app/pipeline/extraction/ner_extractor.py
```

The runtime extractor uses `ml/models/dnrti_bert_ner` as the primary NER model and falls back to `ml/models/dnrti_sklearn_ner` only when BERT cannot load. The large model is cached once per backend process, long reports are processed as overlapping chunks, and low-confidence entities are filtered by configuration. If neither model is available, it returns an empty entity list instead of crashing. `/api/v1/ml/status` exposes runtime selection and saved held-out evaluation evidence.

## Pipeline B: External Runtime

External records are normalized into one raw record contract, then processed as documents or trusted structured records.

Flow:

```text
External Connector
-> Raw Record
-> Text Cleaning and Normalization
-> Deduplication
-> Cybersecurity/CTI Classification
-> NER and IoC Extraction
-> Relation Extraction
-> CTI Object Builder
-> External CTI Objects
```

For unstructured external text, classification happens before NER. Trusted structured sources such as NVD can bypass the document classifier with explicit metadata.

External input may arrive by file or from the VPS-hosted External Sources service. Its scheduled publisher writes the validated JSON to the loopback Gateway; the backend then pulls it through an SSH tunnel using a scoped bearer token, HMAC, ETag, pagination, stable IDs, and strict size/page/schema checks before persistence. The private control path can list sources, start bounded jobs, add approved manual URLs, and read job/export summaries without exposing collector credentials or artifacts publicly.

## Pipeline C: Internal Runtime

Internal sources are implemented for Wazuh `alerts.json`, authenticated Wazuh Indexer pulls, direct Dionaea `log_json` JSONL, and a checkpointed Dionaea sensor API. Structured security telemetry is not forced through ordinary document classification.

Expected flow:

```text
Internal Connector
-> Raw Log Storage
-> Log Parsing
-> Normalization
-> Structured Field Extraction
-> IoC and IoA Extraction
-> Session Building
-> Outlier / Anomaly Detection
-> Internal CTI Objects
```

The current implementation stores all raw Wazuh and Dionaea records, groups them into 30-minute source/type sessions, extracts measurable features, uses Isolation Forest for suitable batches, stores every session, and promotes outlier sessions to internal CTI objects. Credential values remain in protected raw storage when retention is needed, but sensitive values are redacted from CTI event copies.

## Merge Layer

Both runtime pipelines should produce the same source-independent CTI object shape:

```text
External CTI Objects + Internal CTI Objects
-> Unified CTI Schema
-> Correlation Engine
-> Enrichment
-> Central CTI Repository
-> MISP / STIX / TAXII / Dashboard
```

The current schema is defined in:

```text
backend/app/pipeline/common/cti_schema.py
```

The central repository is implemented with SQLAlchemy and PostgreSQL. SQLite is supported for lightweight local tests. Exact indicator matching provides simple correlation, TF-IDF/cosine similarity provides prototype advanced textual correlation, NVD provides CVE enrichment, STIX 2.1 provides portable export, and MISP is an optional external sharing target. NVD and correlation changes re-run the same explainable risk formula with source-diversity and correlation evidence; repeated recalculation does not compound already-derived severity. TAXII and the frontend dashboard remain future work; dashboard data is already available through the API.

The implemented VPS-only layout and its trust boundaries are defined in `cloud_distributed_architecture.md`. MongoDB, background workers, TAXII, and other nonessential heavy extensions remain in `future_bound_work.md`.

## Backend API and security

FastAPI exposes versioned routes under `/api/v1`. Authentication uses short-lived signed bearer tokens, scrypt password hashing, and admin/analyst/viewer roles. Material operations such as uploads, correlation runs, enrichment, MISP submission, source creation, and user creation are written to `audit_logs`.

## Isolated graduation-defense overlay

`compose.demo.yml` is a development-only overlay, not a production topology or replacement architecture. It builds the current ACTIT Frontend, Backend, and Gateway and connects them to a disposable PostgreSQL database plus a contract-compatible offline provider.

```text
Browser on 127.0.0.1:19090
  -> Demo Frontend (only published service)
     -> Current Central Backend
        -> Disposable PostgreSQL on tmpfs
        -> Current Gateway with synthetic sensor fixtures
        -> Offline Reviews and MISP-health provider
```

The service network is Docker-internal. Backend, PostgreSQL, Gateway, and provider ports are not published. The optional Playwright smoke runner joins only that internal network. Stored NVD-like evidence is synthetic; the MISP provider rejects delivery; Frontend removes live MISP controls; no External collection service or scheduler is present. Project-scoped cleanup removes only the `actit-defense-demo` containers, networks, and disposable Gateway volume.

This overlay demonstrates existing ACTIT contracts and analyst workflows without asserting production readiness. Development-verified ML transparency, CVE enrichment, Reviews, and Web Access behavior remain distinct from the existing deployed release. The production External collection failure and historical Gateway OOM remain unresolved and are not exercised by the overlay. See `docs/graduation-demo.md` for the exact trust boundaries and walkthrough.
