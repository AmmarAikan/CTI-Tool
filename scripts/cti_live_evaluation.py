"""Authorized evaluation maintenance; not a second production user interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from ml.evaluation.cti_annotations import (
    agreement_report,
    evaluate_annotations,
    validate_annotations,
)
from ml.evaluation.cti_sampling import (
    canonical_json,
    load_package,
    read_jsonl,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    export = modes.add_parser(
        "export", help="Read-only PostgreSQL snapshot and blind sample"
    )
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--size", type=int, default=400)
    export.add_argument("--seed", default="cti-live-v1")
    for name in ["status", "agreement", "evaluate"]:
        subparser = modes.add_parser(name)
        subparser.add_argument("--bundle", type=Path, required=True)
        subparser.add_argument("--annotator-a", type=Path)
        subparser.add_argument("--annotator-b", type=Path)
        subparser.add_argument("--gold", type=Path)
        if name != "status":
            subparser.add_argument("--report", type=Path)
        if name == "agreement":
            subparser.add_argument(
                "--allow-partial",
                action="store_true",
                help="Pilot agreement only, never final accuracy",
            )
    args = parser.parse_args()
    if args.mode == "export":
        destination = args.output.resolve()
        private_root = (PROJECT_ROOT / "data" / "evaluation").resolve()
        if destination == private_root or not destination.is_relative_to(private_root):
            raise ValueError(
                "Live text output must be a versioned child of ignored data/evaluation"
            )
        from backend.app.db.database import SessionLocal, engine
        from backend.app.services.cti_evaluation_service import CTIEvaluationService

        if engine.dialect.name != "postgresql":
            raise ValueError(
                "Live export requires explicit PostgreSQL configuration; no SQLite fallback"
            )
        with SessionLocal() as session:
            manifest = CTIEvaluationService(session).export(
                destination, size=args.size, seed=args.seed
            )
        result = {
            key: manifest[key]
            for key in [
                "schema_version",
                "selected_documents",
                "scanned_external_events",
                "unique_documents",
                "duplicate_events_excluded",
                "exclusions",
                "sample_source_type_counts",
                "status",
                "metrics",
            ]
        }
    else:
        manifest, documents, references = load_package(args.bundle)
        a = read_jsonl(args.annotator_a or args.bundle / "blind/annotator_a.jsonl")
        b = read_jsonl(args.annotator_b or args.bundle / "blind/annotator_b.jsonl")
        gold = read_jsonl(args.gold or args.bundle / "private/adjudicated.jsonl")
        if args.mode == "status":
            result = {
                "selected_documents": len(documents),
                "metrics": None,
                "note": "Status never calculates accuracy from pending labels or model predictions",
            }
            for name, rows, is_gold in [
                ("annotator_a", a, False),
                ("annotator_b", b, False),
                ("adjudicated", gold, True),
            ]:
                validated = validate_annotations(documents, rows, adjudicated=is_gold)
                result[name] = dict(
                    Counter(row["status"] for row in validated.values())
                )
        elif args.mode == "agreement":
            result = agreement_report(documents, a, b, allow_partial=args.allow_partial)
        else:
            result = evaluate_annotations(manifest, documents, references, a, b, gold)
        if getattr(args, "report", None):
            if args.report.exists():
                raise FileExistsError(
                    "Report already exists; choose a new report filename"
                )
            args.report.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.report.with_suffix(args.report.suffix + ".tmp")
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(canonical_json(result) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, args.report)
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    from sqlalchemy.exc import SQLAlchemyError

    try:
        main()
    except SQLAlchemyError:
        # Connection exceptions can contain credentials/addresses; do not echo them.
        raise SystemExit(
            "PostgreSQL evaluation failed; no results were committed. Check local DB configuration."
        ) from None
    except (ValueError, FileExistsError, FileNotFoundError) as error:
        raise SystemExit(str(error)) from None
