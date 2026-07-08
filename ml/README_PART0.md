# Part 0: DNRTI NER Pipeline

This folder implements the offline NER training stage described in `Explain Part 0 Project.docx`.

## Dataset

The DNRTI BIO files are stored in:

```text
ml/datasets/dnrti/train.txt
ml/datasets/dnrti/valid.txt
ml/datasets/dnrti/test.txt
```

Each non-empty line is expected to contain a token and its BIO label. Empty lines separate sentences.

## Prepare Data

```bash
python ml/preprocessing/prepare_dnrti.py
```

Outputs:

```text
ml/reports/label_map.json
ml/reports/dataset_summary.json
ml/reports/label_distribution.tsv
```

## Train Transformer Model

Install the training dependencies first:

```bash
pip install -r ml/requirements-part0.txt
```

Then fine-tune BERT:

```bash
python ml/training/train_ner_bert.py
```

Outputs:

```text
ml/models/dnrti_bert_ner/
ml/reports/ner_test_metrics.json
```

## Train Local Baseline

If the transformer dependencies or pretrained model download are not available, train the local scikit-learn baseline:

```bash
python ml/training/train_ner_sklearn.py
```

Outputs:

```text
ml/models/dnrti_sklearn_ner/model.joblib
ml/models/dnrti_sklearn_ner/metadata.json
ml/reports/sklearn_ner_metrics.json
ml/reports/sklearn_ner_classification_report.txt
```

## Evaluate

```bash
python ml/evaluation/evaluate_ner.py
```

The backend runtime extractor is available at:

```text
backend/app/pipeline/extraction/ner_extractor.py
```

It prefers the saved BERT model and falls back to the scikit-learn baseline when BERT is not available.
