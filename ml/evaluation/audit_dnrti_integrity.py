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
    audit_split_integrity,
    read_dnrti_splits,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit DNRTI split leakage, duplicates, malformed rows, and label conflicts."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument("--fail-on-integrity-errors", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = audit_split_integrity(read_dnrti_splits(args.data_dir))
    output = args.reports_dir / "dnrti_integrity_report.json"
    write_json(output, report)
    print(f"DNRTI integrity report: {output}")
    print(f"Quality gates passed: {report['all_quality_gates_passed']}")
    print(f"Unique unseen test sentences: {report['unique_unseen_test_sentences']}")
    if args.fail_on_integrity_errors and not report["all_quality_gates_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
