from __future__ import annotations

import argparse
import inspect
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np  # noqa: E402
import torch  # noqa: E402

from ml.common.dnrti import DEFAULT_DATA_DIR, DEFAULT_REPORTS_DIR, build_label_map, read_dnrti_splits, write_json  # noqa: E402
from ml.common.metrics import entity_micro_metrics, token_accuracy  # noqa: E402


DEFAULT_MODEL_DIR = Path("ml/models/dnrti_bert_ner")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune BERT for DNRTI NER.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--base-model", default="bert-base-cased")
    parser.add_argument("--epochs", type=float, default=4.0)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=1e-4)
    parser.add_argument("--max-length", type=int, default=120)
    return parser.parse_args()


def import_training_dependencies():
    try:
        from transformers import (
            AutoModelForTokenClassification,
            AutoTokenizer,
            DataCollatorForTokenClassification,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise SystemExit(
            "Missing training dependency. Install Part 0 requirements first:\n"
            "  pip install -r ml/requirements-part0.txt\n"
            f"Original error: {exc}"
        ) from exc

    return {
        "AutoTokenizer": AutoTokenizer,
        "AutoModelForTokenClassification": AutoModelForTokenClassification,
        "DataCollatorForTokenClassification": DataCollatorForTokenClassification,
        "Trainer": Trainer,
        "TrainingArguments": TrainingArguments,
    }


class TokenClassificationDataset(torch.utils.data.Dataset):
    def __init__(self, encodings):
        self.encodings = encodings

    def __getitem__(self, index: int):
        return {
            key: torch.tensor(value[index])
            for key, value in self.encodings.items()
        }

    def __len__(self) -> int:
        return len(self.encodings["input_ids"])


def tokenize_and_align_labels(
    token_sequences: list[list[str]],
    label_sequences: list[list[str]],
    tokenizer,
    label2id: dict[str, int],
    max_length: int,
):
    tokenized_inputs = tokenizer(
        token_sequences,
        truncation=True,
        is_split_into_words=True,
        max_length=max_length,
    )

    labels = []
    for index, label_sequence in enumerate(label_sequences):
        word_ids = tokenized_inputs.word_ids(batch_index=index)
        previous_word_id = None
        label_ids = []
        for word_id in word_ids:
            if word_id is None:
                label_ids.append(-100)
            elif word_id != previous_word_id:
                label_ids.append(label2id[label_sequence[word_id]])
            else:
                label_ids.append(-100)
            previous_word_id = word_id
        labels.append(label_ids)

    tokenized_inputs["labels"] = labels
    return tokenized_inputs


def compute_metrics_builder(id2label):
    def compute_metrics(eval_predictions):
        logits, labels = eval_predictions
        predictions = np.argmax(logits, axis=-1)

        true_labels = []
        true_predictions = []
        for prediction, label in zip(predictions, labels):
            sentence_labels = []
            sentence_predictions = []
            for predicted_id, label_id in zip(prediction, label):
                if label_id == -100:
                    continue
                sentence_labels.append(id2label[int(label_id)])
                sentence_predictions.append(id2label[int(predicted_id)])
            true_labels.append(sentence_labels)
            true_predictions.append(sentence_predictions)

        entity_metrics = entity_micro_metrics(true_labels, true_predictions)
        return {
            "precision": entity_metrics["entity_precision"],
            "recall": entity_metrics["entity_recall"],
            "f1": entity_metrics["entity_f1"],
            "accuracy": token_accuracy(true_labels, true_predictions),
        }

    return compute_metrics


def training_arguments(TrainingArguments, args: argparse.Namespace):
    kwargs = {
        "output_dir": str(args.model_dir),
        "save_strategy": "epoch",
        "learning_rate": args.learning_rate,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": args.batch_size,
        "num_train_epochs": args.epochs,
        "weight_decay": 0.01,
        "logging_dir": str(args.reports_dir / "logs"),
        "logging_steps": 50,
        "load_best_model_at_end": True,
        "metric_for_best_model": "f1",
        "greater_is_better": True,
        "save_total_limit": 2,
        "report_to": [],
    }
    signature = inspect.signature(TrainingArguments.__init__)
    if "eval_strategy" in signature.parameters:
        kwargs["eval_strategy"] = "epoch"
    else:
        kwargs["evaluation_strategy"] = "epoch"
    return TrainingArguments(**kwargs)


def main() -> None:
    args = parse_args()
    deps = import_training_dependencies()

    splits = read_dnrti_splits(args.data_dir)
    all_label_sequences = [labels for split in splits.values() for labels in split.labels]
    label2id, id2label = build_label_map(all_label_sequences)

    tokenizer = deps["AutoTokenizer"].from_pretrained(args.base_model)
    train_dataset = TokenClassificationDataset(
        tokenize_and_align_labels(
            splits["train"].tokens, splits["train"].labels, tokenizer, label2id, args.max_length
        )
    )
    valid_dataset = TokenClassificationDataset(
        tokenize_and_align_labels(
            splits["valid"].tokens, splits["valid"].labels, tokenizer, label2id, args.max_length
        )
    )
    test_dataset = TokenClassificationDataset(
        tokenize_and_align_labels(
            splits["test"].tokens, splits["test"].labels, tokenizer, label2id, args.max_length
        )
    )

    model = deps["AutoModelForTokenClassification"].from_pretrained(
        args.base_model,
        num_labels=len(label2id),
        id2label=id2label,
        label2id=label2id,
    )

    trainer = deps["Trainer"](
        model=model,
        args=training_arguments(deps["TrainingArguments"], args),
        train_dataset=train_dataset,
        eval_dataset=valid_dataset,
        tokenizer=tokenizer,
        data_collator=deps["DataCollatorForTokenClassification"](tokenizer=tokenizer),
        compute_metrics=compute_metrics_builder(id2label),
    )

    trainer.train()
    eval_result = trainer.evaluate(test_dataset)

    args.model_dir.mkdir(parents=True, exist_ok=True)
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(args.model_dir))
    tokenizer.save_pretrained(str(args.model_dir))

    with (args.reports_dir / "ner_test_metrics.json").open("w", encoding="utf-8") as file:
        json.dump(eval_result, file, indent=2)

    write_json(
        args.reports_dir / "label_map.json",
        {
            "label2id": label2id,
            "id2label": {str(index): label for index, label in id2label.items()},
            "num_labels": len(label2id),
        },
    )

    print("BERT NER training completed.")
    print(eval_result)


if __name__ == "__main__":
    main()
