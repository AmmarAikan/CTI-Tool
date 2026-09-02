from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.common.dnrti import DEFAULT_REPORTS_DIR, write_json  # noqa: E402


REPORT_NAMES = {
    "current": "ner_clean_v1_baseline_metrics.json",
    "clean_v1_stage1": "ner_clean_v1_test_metrics.json",
    "clean_v1_stage2": "ner_clean_v1_stage2_test_metrics.json",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare the current NER model with clean-v1 training candidates."
    )
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    return parser.parse_args()


def _read(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _metrics(name: str, report: dict[str, object]) -> dict[str, float]:
    if name == "current":
        metrics = report["metrics"]
        micro = metrics["micro"]
        macro = metrics["macro"]
        return {
            "precision": float(micro["entity_precision"]),
            "recall": float(micro["entity_recall"]),
            "micro_f1": float(micro["entity_f1"]),
            "macro_f1": float(macro["entity_macro_f1"]),
            "token_accuracy": float(metrics["token_accuracy"]),
        }
    return {
        "precision": float(report["eval_precision"]),
        "recall": float(report["eval_recall"]),
        "micro_f1": float(report["eval_f1"]),
        "macro_f1": float(report["eval_macro_f1"]),
        "token_accuracy": float(report["eval_accuracy"]),
    }


def compare(reports: dict[str, dict[str, object]]) -> dict[str, object]:
    variants = {name: _metrics(name, report) for name, report in reports.items()}
    baseline = variants["current"]
    for name, values in variants.items():
        values["micro_f1_delta_from_current"] = values["micro_f1"] - baseline["micro_f1"]
        values["macro_f1_delta_from_current"] = values["macro_f1"] - baseline["macro_f1"]
        values["passes_current_micro_f1"] = values["micro_f1"] >= baseline["micro_f1"]
        values["passes_current_macro_f1"] = values["macro_f1"] >= baseline["macro_f1"]
        values["activation_gate_passed"] = (
            values["passes_current_micro_f1"] and values["passes_current_macro_f1"]
        )

    eligible = [
        name
        for name in ("clean_v1_stage1", "clean_v1_stage2")
        if variants[name]["activation_gate_passed"]
    ]
    selected = max(
        eligible,
        key=lambda name: (variants[name]["micro_f1"], variants[name]["macro_f1"]),
        default="current",
    )
    return {
        "evaluation_scope": "272 clean-v1 test sentences with zero train overlap",
        "activation_policy": (
            "a candidate must meet or exceed both current micro-F1 and macro-F1"
        ),
        "variants": variants,
        "selected_model": selected,
        "production_change_recommended": selected != "current",
        "decision": (
            f"activate {selected}"
            if selected != "current"
            else "keep current production model; both clean-v1 candidates failed activation gates"
        ),
    }


def main() -> None:
    args = parse_args()
    reports = {
        name: _read(args.reports_dir / filename)
        for name, filename in REPORT_NAMES.items()
    }
    result = compare(reports)
    output = args.reports_dir / "ner_clean_v1_model_comparison.json"
    write_json(output, result)
    print(f"Clean model comparison: {output}")
    print(f"Decision: {result['decision']}")


if __name__ == "__main__":
    main()
