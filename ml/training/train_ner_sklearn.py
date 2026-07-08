from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from joblib import dump  # noqa: E402
from sklearn.feature_extraction import DictVectorizer  # noqa: E402
from sklearn.linear_model import SGDClassifier  # noqa: E402
from sklearn.metrics import classification_report  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402

from ml.common.dnrti import DEFAULT_DATA_DIR, DEFAULT_REPORTS_DIR, read_dnrti_splits, write_json  # noqa: E402
from ml.common.metrics import entity_micro_metrics, label_counter, token_accuracy  # noqa: E402
from ml.common.token_features import sentence_to_feature_dicts  # noqa: E402


DEFAULT_MODEL_DIR = Path("ml/models/dnrti_sklearn_ner")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a lightweight local DNRTI NER baseline with scikit-learn."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--max-iter", type=int, default=25)
    return parser.parse_args()


def flatten_features(tokens: list[list[str]], labels: list[list[str]]) -> tuple[list[dict[str, object]], list[str]]:
    features: list[dict[str, object]] = []
    flat_labels: list[str] = []
    for sentence_tokens, sentence_labels in zip(tokens, labels):
        features.extend(sentence_to_feature_dicts(sentence_tokens))
        flat_labels.extend(sentence_labels)
    return features, flat_labels


def unflatten(flat_labels: list[str], sentence_tokens: list[list[str]]) -> list[list[str]]:
    sequences: list[list[str]] = []
    cursor = 0
    for tokens in sentence_tokens:
        length = len(tokens)
        sequences.append(flat_labels[cursor : cursor + length])
        cursor += length
    return sequences


def evaluate_split(
    model: Pipeline,
    split_name: str,
    tokens: list[list[str]],
    labels: list[list[str]],
) -> tuple[dict[str, object], str]:
    features, true_flat = flatten_features(tokens, labels)
    pred_flat = list(model.predict(features))
    predictions = unflatten(pred_flat, tokens)

    metrics: dict[str, object] = {
        "split": split_name,
        "token_accuracy": token_accuracy(labels, predictions),
        "labels": label_counter(labels),
    }
    metrics.update(entity_micro_metrics(labels, predictions))

    report_text = classification_report(true_flat, pred_flat, digits=4, zero_division=0)
    return metrics, report_text


def main() -> None:
    args = parse_args()
    splits = read_dnrti_splits(args.data_dir)

    train_features, train_labels = flatten_features(splits["train"].tokens, splits["train"].labels)

    model = Pipeline(
        [
            ("vectorizer", DictVectorizer(sparse=True)),
            (
                "classifier",
                SGDClassifier(
                    loss="log_loss",
                    penalty="l2",
                    alpha=1e-5,
                    max_iter=args.max_iter,
                    tol=1e-3,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    model.fit(train_features, train_labels)

    valid_metrics, valid_report = evaluate_split(
        model, "valid", splits["valid"].tokens, splits["valid"].labels
    )
    test_metrics, test_report = evaluate_split(
        model, "test", splits["test"].tokens, splits["test"].labels
    )

    args.model_dir.mkdir(parents=True, exist_ok=True)
    args.reports_dir.mkdir(parents=True, exist_ok=True)

    dump(model, args.model_dir / "model.joblib")
    write_json(
        args.model_dir / "metadata.json",
        {
            "model_type": "sklearn_token_classifier",
            "feature_extractor": "ml.common.token_features.sentence_to_feature_dicts",
            "labels": sorted(set(train_labels)),
            "data_dir": str(args.data_dir),
        },
    )
    write_json(
        args.reports_dir / "sklearn_ner_metrics.json",
        {"validation": valid_metrics, "test": test_metrics},
    )

    with (args.reports_dir / "sklearn_ner_classification_report.txt").open(
        "w", encoding="utf-8"
    ) as file:
        file.write("Validation report\n")
        file.write("=================\n")
        file.write(valid_report)
        file.write("\n\nTest report\n")
        file.write("===========\n")
        file.write(test_report)

    print("DNRTI sklearn baseline training completed.")
    print(f"Model written to: {args.model_dir}")
    print(
        "Test metrics: "
        f"token_accuracy={test_metrics['token_accuracy']:.4f}, "
        f"entity_f1={test_metrics['entity_f1']:.4f}"
    )


if __name__ == "__main__":
    main()

