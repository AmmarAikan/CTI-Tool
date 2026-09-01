from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.common.dnrti import (  # noqa: E402
    DEFAULT_DATA_DIR,
    DEFAULT_REPORTS_DIR,
    read_dnrti_splits,
    unique_unseen_split,
    write_json,
)
from ml.common.metrics import detailed_entity_metrics  # noqa: E402


DEFAULT_MODEL_DIR = Path("ml/models/dnrti_bert_ner")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate BERT on unique test sentences that do not occur in train."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=120)
    parser.add_argument(
        "--runtime",
        choices=("pytorch", "onnx"),
        default="pytorch",
        help="Inference engine used for the saved model directory.",
    )
    parser.add_argument(
        "--output-name",
        default="ner_unseen_test_metrics.json",
        help="JSON report filename written below --reports-dir.",
    )
    return parser.parse_args()


def evaluate(args: argparse.Namespace) -> dict[str, object]:
    from transformers import AutoTokenizer

    splits = read_dnrti_splits(args.data_dir)
    unseen = unique_unseen_split(splits)
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    if args.runtime == "onnx":
        from optimum.onnxruntime import ORTModelForTokenClassification

        model = ORTModelForTokenClassification.from_pretrained(args.model_dir)
        tensor_format = "np"
    else:
        from transformers import AutoModelForTokenClassification

        model = AutoModelForTokenClassification.from_pretrained(args.model_dir)
        model.eval()
        tensor_format = "pt"
    id2label = {int(key): value for key, value in model.config.id2label.items()}
    true_sequences: list[list[str]] = []
    pred_sequences: list[list[str]] = []
    batch_size = max(1, min(int(args.batch_size), 128))
    started = time.perf_counter()

    def run_model(encoded: object) -> object:
        if args.runtime == "onnx":
            return model(**encoded).logits.argmax(-1)
        import torch

        with torch.inference_mode():
            return model(**encoded).logits.argmax(-1).cpu().numpy()

    for start in range(0, unseen.sentence_count, batch_size):
        batch_tokens = unseen.tokens[start : start + batch_size]
        batch_labels = unseen.labels[start : start + batch_size]
        encoded = tokenizer(
            batch_tokens,
            is_split_into_words=True,
            truncation=True,
            max_length=max(8, int(args.max_length)),
            padding=True,
            return_tensors=tensor_format,
        )
        predictions = run_model(encoded)
        for batch_index, labels in enumerate(batch_labels):
            word_ids = encoded.word_ids(batch_index=batch_index)
            previous_word_id = None
            true_labels: list[str] = []
            pred_labels: list[str] = []
            for token_index, word_id in enumerate(word_ids):
                if word_id is None or word_id == previous_word_id:
                    previous_word_id = word_id
                    continue
                true_labels.append(labels[word_id])
                pred_labels.append(id2label[int(predictions[batch_index, token_index])])
                previous_word_id = word_id
            true_sequences.append(true_labels)
            pred_sequences.append(pred_labels)

    runtime = time.perf_counter() - started
    metrics = detailed_entity_metrics(true_sequences, pred_sequences)
    return {
        "scope": "unique test sentences absent from train; first duplicate retained",
        "model_type": str(model.config.model_type),
        "model_name": args.model_dir.name,
        "runtime": args.runtime,
        "original_test_sentences": splits["test"].sentence_count,
        "evaluated_sentences": unseen.sentence_count,
        "runtime_seconds": runtime,
        "samples_per_second": unseen.sentence_count / runtime if runtime else 0.0,
        "batch_size": batch_size,
        "max_length": int(args.max_length),
        "metrics": metrics,
    }


def main() -> None:
    args = parse_args()
    report = evaluate(args)
    output = args.reports_dir / args.output_name
    write_json(output, report)
    micro = report["metrics"]["micro"]
    print(f"Unseen NER report: {output}")
    print(f"Sentences: {report['evaluated_sentences']}")
    print(f"Entity F1: {micro['entity_f1']:.4f}")


if __name__ == "__main__":
    main()
