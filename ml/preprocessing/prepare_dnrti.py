from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.common.dnrti import (  # noqa: E402
    DEFAULT_DATA_DIR,
    DEFAULT_REPORTS_DIR,
    build_label_map,
    flatten,
    read_dnrti_splits,
    summarize_split,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare the DNRTI BIO dataset.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    splits = read_dnrti_splits(args.data_dir)

    all_label_sequences = [labels for split in splits.values() for labels in split.labels]
    label2id, id2label = build_label_map(all_label_sequences)

    summary = {
        "data_dir": str(args.data_dir),
        "splits": {name: summarize_split(split) for name, split in splits.items()},
        "total_sentences": sum(split.sentence_count for split in splits.values()),
        "total_tokens": sum(split.token_count for split in splits.values()),
        "num_labels": len(label2id),
        "labels": list(label2id.keys()),
    }

    label_map = {
        "label2id": label2id,
        "id2label": {str(index): label for index, label in id2label.items()},
        "num_labels": len(label2id),
        "train_sentences": splits["train"].sentence_count,
        "valid_sentences": splits["valid"].sentence_count,
        "test_sentences": splits["test"].sentence_count,
    }

    args.reports_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.reports_dir / "label_map.json", label_map)
    write_json(args.reports_dir / "dataset_summary.json", summary)

    label_counts = {}
    for split_name, split in splits.items():
        for label in flatten(split.labels):
            label_counts.setdefault(label, {"train": 0, "valid": 0, "test": 0, "total": 0})
            label_counts[label][split_name] += 1
            label_counts[label]["total"] += 1

    distribution_path = args.reports_dir / "label_distribution.tsv"
    with distribution_path.open("w", encoding="utf-8") as file:
        file.write("label\ttrain\tvalid\ttest\ttotal\n")
        for label in sorted(label_counts):
            counts = label_counts[label]
            file.write(
                f"{label}\t{counts['train']}\t{counts['valid']}\t"
                f"{counts['test']}\t{counts['total']}\n"
            )

    print("DNRTI preparation completed.")
    print(f"Data directory: {args.data_dir}")
    print(f"Labels: {len(label2id)}")
    print(
        "Sentences: "
        f"train={splits['train'].sentence_count}, "
        f"valid={splits['valid'].sentence_count}, "
        f"test={splits['test'].sentence_count}"
    )
    print(f"Reports written to: {args.reports_dir}")


if __name__ == "__main__":
    main()

