# Model Training Pipeline

Part 0 is the offline NLP/ML training pipeline. DNRTI is a training dataset, not a live data source like RSS, NVD, or Wazuh.

## Existing Flow

```text
ml/datasets/dnrti/
-> ml/preprocessing/prepare_dnrti.py
-> ml/training/train_ner_bert.py or ml/training/train_ner_sklearn.py
-> ml/evaluation/evaluate_ner.py
-> ml/models/
-> backend/app/pipeline/extraction/ner_extractor.py
```

## Existing Artifacts

```text
ml/reports/dataset_summary.json
ml/reports/label_distribution.tsv
ml/reports/label_map.json
ml/reports/ner_test_metrics.json
ml/reports/sklearn_ner_metrics.json
ml/models/dnrti_sklearn_ner/model.joblib
ml/models/dnrti_sklearn_ner/metadata.json
```

The local transformer directory `ml/models/dnrti_bert_ner/` may exist for runtime use, but it is intentionally ignored by Git because it contains large model files.

## Commands

Prepare DNRTI data:

```bash
python ml/preprocessing/prepare_dnrti.py
```

Train sklearn fallback:

```bash
python ml/training/train_ner_sklearn.py
```

Train BERT only when explicitly approved:

```bash
python ml/training/train_ner_bert.py
```

Evaluate available reports:

```bash
python ml/evaluation/evaluate_ner.py
```

Runtime smoke test:

```bash
python -c "from backend.app.pipeline.extraction.ner_extractor import NERExtractor; e=NERExtractor(); print(e.backend); print(e.extract_entities('APT28 used X-Agent malware to target government organizations in Ukraine through spear phishing attack.'))"
```
