from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_REPORTS_DIR = Path("ml/reports")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Print available DNRTI NER evaluation metrics.")
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument("--metrics-file", type=Path)
    return parser.parse_args()


def find_metrics_file(reports_dir: Path, explicit: Path | None) -> Path | None:
    if explicit:
        return explicit

    candidates = [
        reports_dir / "ner_test_metrics.json",
        reports_dir / "sklearn_ner_metrics.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def print_metric_tree(payload: object, prefix: str = "") -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            next_prefix = f"{prefix}.{key}" if prefix else key
            print_metric_tree(value, next_prefix)
    elif isinstance(payload, float):
        print(f"{prefix}: {payload:.4f}")
    else:
        print(f"{prefix}: {payload}")


def main() -> None:
    args = parse_args()
    metrics_file = find_metrics_file(args.reports_dir, args.metrics_file)
    if metrics_file is None or not metrics_file.exists():
        print("No evaluation report found. Run training first.")
        return

    with metrics_file.open("r", encoding="utf-8") as file:
        metrics = json.load(file)

    print("NER Evaluation Metrics")
    print("----------------------")
    print(f"Source: {metrics_file}")
    print_metric_tree(metrics)


if __name__ == "__main__":
    main()

