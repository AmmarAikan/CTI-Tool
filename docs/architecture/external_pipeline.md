# External Runtime Pipeline

The external runtime pipeline integrates the prepared source data under `data/external_samples/` without copying it blindly into the backend.

## Inputs

The current prepared external files are:

```text
data/external_samples/cert_advisories_20260722_184300.json
data/external_samples/clean_articles_20260722_184214.json
data/external_samples/crawled_articles_20260722_184214.json
data/external_samples/social_media_posts_20260722_184742.json
data/external_samples/telegram_posts_20260722_184813.json
data/external_samples/vulnerabilities_20260722_184347.json
```

Each file is read by `ExternalJsonFileConnector` and converted into a `RawRecord` with:

```text
external_id
source_name
source_type
title
content
url
published_at
collected_at
raw_data
trusted_cybersecurity_source
```

## Processing Order

Unstructured records follow:

```text
Cleaning and Normalization
-> Deduplication
-> Classification
-> NER / IoC Extraction
-> Relation Extraction
-> CTI Object Creation
```

`Not Cybersecurity` records are retained as ignored records and do not run NER. `Cybersecurity Related` records are retained. `CTI Related` records run NER, IoC extraction, and relation extraction.

## Classification Metadata

Classification result shape:

```json
{
  "label": "cti_related",
  "confidence": 0.91,
  "backend": "sklearn|transformer|rule_based|trusted_source_bypass",
  "model_version": "..."
}
```

The current implementation includes a rule-based fallback and optional sklearn model loader. It does not claim keyword matching is an ML classifier.

## Trusted Source Bypass

NVD, MITRE CVE, CISA, CERT-EU, and CERT-AT records marked as vulnerability or advisory records may bypass the general document classifier. The classification metadata records:

```text
backend=trusted_source_bypass
reason=trusted structured cybersecurity source
```

## Run Command

Process a small sample:

```bash
python -m backend.app.pipeline.orchestrator data/external_samples/vulnerabilities_20260722_184347.json --limit 2
```
