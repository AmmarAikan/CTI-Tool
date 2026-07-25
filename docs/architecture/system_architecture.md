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

The runtime extractor prefers the local transformer model when present and falls back to the sklearn model. If neither model is available, it returns an empty entity list instead of crashing.

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

Internal sources are future work. They should not be forced through ordinary document classification when records are structured security telemetry.

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

The current repository includes the internal connector interface only.

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
