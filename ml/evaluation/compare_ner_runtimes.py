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
    "pytorch": "ner_unseen_pytorch_metrics.json",
    "onnx_fp32": "ner_unseen_onnx_fp32_metrics.json",
    "onnx_int8": "ner_unseen_onnx_int8_metrics.json",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare saved DNRTI NER quality and CPU throughput reports."
    )
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument("--maximum-f1-drop", type=float, default=0.01)
    parser.add_argument("--minimum-speedup", type=float, default=1.5)
    return parser.parse_args()


def _read_report(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def compare(
    reports: dict[str, dict[str, object]],
    maximum_f1_drop: float,
    minimum_speedup: float,
) -> dict[str, object]:
    baseline = reports["pytorch"]
    baseline_micro = baseline["metrics"]["micro"]
    baseline_f1 = float(baseline_micro["entity_f1"])
    baseline_throughput = float(baseline["samples_per_second"])
    variants: dict[str, dict[str, object]] = {}

    for name, report in reports.items():
        micro = report["metrics"]["micro"]
        f1 = float(micro["entity_f1"])
        throughput = float(report["samples_per_second"])
        f1_drop = baseline_f1 - f1
        speedup = throughput / baseline_throughput if baseline_throughput else 0.0
        quality_passed = f1_drop <= maximum_f1_drop
        speed_passed = speedup >= minimum_speedup
        variants[name] = {
            "runtime": report.get("runtime", name),
            "model_name": report.get("model_name"),
            "entity_f1": f1,
            "entity_precision": float(micro["entity_precision"]),
            "entity_recall": float(micro["entity_recall"]),
            "runtime_seconds": float(report["runtime_seconds"]),
            "samples_per_second": throughput,
            "f1_drop_from_pytorch": f1_drop,
            "speedup_over_pytorch": speedup,
            "quality_gate_passed": quality_passed,
            "speed_gate_passed": speed_passed,
            "activation_gate_passed": quality_passed and speed_passed,
        }

    accepted = [
        name
        for name, result in variants.items()
        if name != "pytorch" and result["activation_gate_passed"]
    ]
    selected = max(
        accepted,
        key=lambda name: float(variants[name]["speedup_over_pytorch"]),
        default="pytorch",
    )
    return {
        "evaluation_scope": baseline.get("scope"),
        "evaluated_sentences": baseline.get("evaluated_sentences"),
        "quality_gate": {"maximum_f1_drop": maximum_f1_drop},
        "speed_gate": {"minimum_speedup": minimum_speedup},
        "variants": variants,
        "selected_runtime": selected,
        "production_change_recommended": selected != "pytorch",
        "decision": (
            f"activate {selected}"
            if selected != "pytorch"
            else "keep PyTorch; ONNX candidates did not pass both activation gates"
        ),
    }


def main() -> None:
    args = parse_args()
    reports = {
        name: _read_report(args.reports_dir / filename)
        for name, filename in REPORT_NAMES.items()
    }
    comparison = compare(reports, args.maximum_f1_drop, args.minimum_speedup)
    output = args.reports_dir / "ner_runtime_comparison.json"
    write_json(output, comparison)
    print(f"Runtime comparison: {output}")
    print(f"Decision: {comparison['decision']}")


if __name__ == "__main__":
    main()
