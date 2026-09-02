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
ml/reports/dnrti_integrity_report.json
```

The integrity report is a required quality gate. It counts exact sentence
duplicates within and across splits, conflicting BIO sequences, malformed
rows, and the number of unique test sentences absent from train. Run it
directly (and fail CI when the source data has not yet been repaired) with:

```bash
python ml/evaluation/audit_dnrti_integrity.py --fail-on-integrity-errors
```

Build the reproducible clean derivative without editing the original dataset:

```powershell
.\.venv\Scripts\python.exe ml\preprocessing\clean_dnrti.py
```

This rejects complete sentences containing malformed rows, excludes every text
with conflicting label sequences, collapses duplicates, and assigns consistent
cross-split duplicates to `train`, then `valid`, then `test`. The derived files
under `ml/datasets/dnrti_clean_v1/` are local generated data and are ignored by
Git. The policy, hashes, counts, and conflict fingerprints are recorded in
`ml/reports/dnrti_clean_v1_report.json`.

## Train Transformer Model

Use the repository's single Python 3.12 environment and install the complete project requirements:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Then fine-tune BERT:

```bash
python ml/training/train_ner_bert.py
```

For the clean-v1 experiment, keep the current production model and report
untouched by using separate destinations:

```powershell
.\.venv\Scripts\python.exe ml\training\train_ner_bert.py --data-dir ml\datasets\dnrti_clean_v1 --model-dir ml\models\dnrti_bert_ner_clean_v1 --report-name ner_clean_v1_test_metrics.json --require-clean-data --epochs 2 --learning-rate 3e-5
```

If the first clean run is still improving but does not pass the current-model
baseline, one bounded continuation run can be kept separate as follows:

```powershell
.\.venv\Scripts\python.exe ml\training\train_ner_bert.py --data-dir ml\datasets\dnrti_clean_v1 --base-model ml\models\dnrti_bert_ner_clean_v1 --model-dir ml\models\dnrti_bert_ner_clean_v1_stage2 --report-name ner_clean_v1_stage2_test_metrics.json --require-clean-data --epochs 1 --learning-rate 1e-5
```

Compare both candidates against the unchanged current model before activation:

```powershell
.\.venv\Scripts\python.exe ml\evaluation\compare_clean_ner_models.py
```

A candidate is not eligible for activation unless it meets or exceeds both the
current micro-F1 and macro-F1 on the same clean-v1 test set. Training refuses
to replace an existing model or report unless `--overwrite-output` is supplied
explicitly, preventing an accidental repeat of a long run.

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

The original DNRTI split contains duplicate sentences. Generate the additional
leakage-aware exact-span micro, macro, and per-entity report with:

```bash
python ml/evaluation/evaluate_ner_unseen.py --batch-size 16
```

This writes `ml/reports/ner_unseen_test_metrics.json`. It keeps only the first
unique test sentence whose normalized text does not occur in train. It does not
replace a future manually labelled live-CTI evaluation set.

The backend runtime extractor is available at:

```text
backend/app/pipeline/extraction/ner_extractor.py
```

It prefers the saved BERT model and falls back to the scikit-learn baseline when BERT is not available.

Runtime BERT inference accepts bounded batches and maintains a process-local
LRU cache. Configure them with `NER_INFERENCE_BATCH_SIZE` and `NER_CACHE_SIZE`.
The cache is keyed only by a SHA-256 text fingerprint, is cleared on restart,
and does not change PostgreSQL identities or External Sources deduplication.

## Optional ONNX CPU experiment

Install the separate optimization dependencies, export FP32 ONNX, and build a
dynamic INT8 candidate with:

```powershell
.\.venv\Scripts\python.exe -m pip install -r ml\requirements-optimization.txt
.\.venv\Scripts\python.exe ml\optimization\optimize_ner_onnx.py
```

Evaluate every runtime on the same unique test sentences and record the final
activation decision:

```powershell
.\.venv\Scripts\python.exe ml\evaluation\evaluate_ner_unseen.py --runtime pytorch --model-dir ml\models\dnrti_bert_ner --output-name ner_unseen_pytorch_metrics.json
.\.venv\Scripts\python.exe ml\evaluation\evaluate_ner_unseen.py --runtime onnx --model-dir ml\models\dnrti_bert_ner_onnx_fp32 --output-name ner_unseen_onnx_fp32_metrics.json
.\.venv\Scripts\python.exe ml\evaluation\evaluate_ner_unseen.py --runtime onnx --model-dir ml\models\dnrti_bert_ner_onnx_int8 --output-name ner_unseen_onnx_int8_metrics.json
.\.venv\Scripts\python.exe ml\evaluation\compare_ner_runtimes.py
```

ONNX is experimental and is not loaded by the backend. Activation requires an
absolute unseen-set F1 drop no greater than `0.01` and at least `1.5x` measured
speedup over the already-batched PyTorch path. Generated model directories are
local artifacts and are excluded from Git.
