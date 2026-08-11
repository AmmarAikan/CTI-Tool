# CTI-Tool

AI-based Cyber Threat Intelligence platform for a graduation project. The project keeps the offline DNRTI model-training work separate from runtime CTI data processing.

The complete source repository is private for team collaboration. Public architecture, methodology, sanitized demonstrations, and evaluation evidence are available in [CTI-Tool-Showcase](https://github.com/AmmarAikan/CTI-Tool-Showcase).

## Architecture Summary

The platform is organized as three connected pipelines:

```text
Offline NLP/ML Training Pipeline
External Data Runtime Pipeline
Internal Data Runtime Pipeline
```

Part 0 is the offline DNRTI NER pipeline. It trains and evaluates NER models, saves model artifacts, and exposes the runtime `NERExtractor`.

External runtime processing now supports prepared JSON inputs such as `data/external_samples/` advisories, NVD/CVE records, security articles, Reddit-style posts, and Telegram feed records.

Internal runtime processing is prepared through an interface only. Structured security logs such as Wazuh, Zeek, Suricata, firewall, and honeypot records should later follow parsing and structured extraction, not ordinary document classification.

## Current Implementation Status

Implemented:

```text
ml/ DNRTI preprocessing, training, evaluation, reports, label maps
backend/app/pipeline/extraction/ner_extractor.py
backend/app/pipeline/ingestion/ external connector contracts
backend/app/pipeline/preprocessing/ cleaning, normalization, deduplication
backend/app/pipeline/classification/ relevance classifier with explicit fallback metadata
backend/app/pipeline/extraction/ioc_extractor.py
backend/app/pipeline/extraction/relation_extractor.py
backend/app/pipeline/orchestrator.py
tests/test_external_pipeline.py
docs/architecture/
```

Future work:

```text
database repositories
API routes
dashboard
correlation engine
enrichment services
MISP/STIX/TAXII export
internal Wazuh and log pipelines
trained document classifier
```

## Setup

Create and activate a Python environment, then install Part 0 dependencies when model training or transformer runtime is needed:

```bash
pip install -r ml/requirements-part0.txt
```

The sklearn fallback model is tracked under:

```text
ml/models/dnrti_sklearn_ner/
```

Large local transformer checkpoints are intentionally ignored:

```text
ml/models/dnrti_bert_ner/
```

## Safe Run Commands

Run the external pipeline on a small prepared sample:

```bash
python -m backend.app.pipeline.orchestrator data/external_samples/vulnerabilities_20260722_184347.json --limit 2
```

Run focused tests:

```bash
python -m unittest discover -s tests
```

Check available NER evaluation reports:

```bash
python ml/evaluation/evaluate_ner.py
```

Smoke-test the runtime NER extractor:

```bash
python -c "from backend.app.pipeline.extraction.ner_extractor import NERExtractor; e=NERExtractor(); print(e.backend); print(e.extract_entities('APT28 used X-Agent malware to target government organizations in Ukraine through spear phishing attack.'))"
```

## Branch Workflow

Do not work directly on `main`. Start a new branch from the current remote `main`:

```bash
git switch main
git pull --ff-only origin main
git switch -c your-feature-branch
```

Review changes before committing:

```bash
git status --short
git diff
```

Open a pull request from the contributor branch into `main`. Do not add commits to another contributor's branch unless the team explicitly coordinates that work.

## Team and rights

CTI-Tool is a collaborative graduation project maintained by its project contributors.

© 2026 CTI-Tool Project Contributors. All Rights Reserved. Copyright in each contribution remains with its respective contributor. See [COPYRIGHT.md](COPYRIGHT.md).
