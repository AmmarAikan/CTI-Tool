from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.db.database import SessionLocal  # noqa: E402
from backend.app.repositories.cti_repository import CTIRepository  # noqa: E402
from backend.app.services.cti_quality_service import CTIQualityService  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Preview or apply deterministic CTI result quality policies."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit the changes. Without this flag the database is rolled back.",
    )
    parser.add_argument(
        "--remove-rejected-entities",
        action="store_true",
        help="Delete flagged legacy DNRTI entities; requires --apply and is off by default.",
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(payload, file, indent=2, sort_keys=True)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


def main() -> None:
    args = parse_args()
    if args.remove_rejected_entities and not args.apply:
        raise SystemExit("--remove-rejected-entities requires --apply")
    with SessionLocal() as session:
        summary = CTIQualityService(session).run(
            apply=args.apply,
            remove_rejected_entities=args.remove_rejected_entities,
        )
        if args.apply:
            CTIRepository(session).audit(
                "apply_cti_quality_backfill",
                "threat_event_collection",
                username="system-maintenance",
                details=summary,
            )
            session.commit()
        else:
            session.rollback()

    if args.output:
        write_json_atomic(args.output, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
