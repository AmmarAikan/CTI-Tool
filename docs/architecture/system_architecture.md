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

The runtime extractor uses `ml/models/dnrti_bert_ner` as the primary NER model and falls back to `ml/models/dnrti_sklearn_ner` only when BERT cannot load. If neither model is available, it returns an empty entity list instead of crashing.

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

## Pipeline C: Internal Runtime

Internal sources are implemented for Wazuh `alerts.json` and direct Dionaea `log_json` JSONL. Structured security telemetry is not forced through ordinary document classification.

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

The central repository is implemented with SQLAlchemy and PostgreSQL. SQLite is supported for lightweight local tests. Exact indicator matching provides simple correlation, TF-IDF/cosine similarity provides prototype advanced textual correlation, NVD provides CVE enrichment, STIX 2.1 provides portable export, and MISP is an optional external sharing target. TAXII and the frontend dashboard remain future work; dashboard data is already available through the API.

Heavy infrastructure boundaries, including MongoDB, a hosted MISP platform, and live Wazuh services, are defined in `future_bound_work.md`. They are deliberate extensions rather than missing runtime dependencies.

## Backend API and security

FastAPI exposes versioned routes under `/api/v1`. Authentication uses short-lived signed bearer tokens, scrypt password hashing, and admin/analyst/viewer roles. Material operations such as uploads, correlation runs, enrichment, MISP submission, source creation, and user creation are written to `audit_logs`.
