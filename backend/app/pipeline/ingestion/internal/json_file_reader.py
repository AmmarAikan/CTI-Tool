from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any


def read_json_records(
    path: Path,
    *,
    wrapper_keys: Sequence[str],
    format_name: str,
) -> Iterable[dict[str, Any]]:
    """Read a JSON array, wrapper object, single object, JSONL, or NDJSON file."""

    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return

    if text[0] in "[{":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            if isinstance(payload, list):
                yield from (item for item in payload if isinstance(item, dict))
                return
            if isinstance(payload, dict):
                records = next(
                    (
                        payload[key]
                        for key in wrapper_keys
                        if isinstance(payload.get(key), list)
                    ),
                    [payload],
                )
                yield from (item for item in records if isinstance(item, dict))
                return

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid {format_name} JSONL at {path}:{line_number}: {exc.msg}"
            ) from exc
        if isinstance(item, dict):
            yield item
