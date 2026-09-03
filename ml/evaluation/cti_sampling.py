"""Reproducible, blinded evaluation packages. No inference or database writes."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "cti-live-evaluation-v1"
MAX_PACKAGE_BYTES = 100 * 1024 * 1024


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Candidate:
    event_id: str
    source_key: str
    source_type: str
    classification: str
    text_sha256: str
    dedup_sha256: str
    characters: int

    @property
    def stratum(self) -> str:
        return canonical_json([self.source_key, self.source_type, self.classification])

    @property
    def sample_id(self) -> str:
        return "doc-" + self.text_sha256


def select_sample(
    candidates: list[Candidate], *, size: int = 400, seed: str = "cti-live-v1"
) -> tuple[list[Candidate], dict[str, Any]]:
    """Balance source/label strata; hash-ranking is independent of model success.

    Duplicated whitespace/case-normalized texts have one deterministic event
    representative. Weights refer to this unique-document population, NOT raw
    ingestion records or all repeated events.
    """
    if not 1 <= size <= 500 or not seed:
        raise ValueError("Sample size must be 1..500 and seed must be nonempty")
    representatives: dict[str, Candidate] = {}
    for candidate in sorted(candidates, key=lambda item: item.event_id):
        representatives.setdefault(candidate.dedup_sha256, candidate)
    strata: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in representatives.values():
        strata[candidate.stratum].append(candidate)
    if not strata:
        raise ValueError("No eligible documents")
    if size < len(strata):
        raise ValueError("Sample size must cover every nonempty stratum")
    for group in strata.values():
        group.sort(
            key=lambda item: (digest(seed + ":" + item.sample_id), item.event_id)
        )
    allocated: Counter[str] = Counter()
    selected = []
    ordered_strata = sorted(strata, key=lambda key: (digest(seed + key), key))
    while len(selected) < min(size, len(representatives)):
        for key in ordered_strata:
            if len(selected) >= size:
                break
            if allocated[key] < len(strata[key]):
                selected.append(strata[key][allocated[key]])
                allocated[key] += 1
    return selected, {
        "eligible_events": len(candidates),
        "unique_documents": len(representatives),
        "duplicate_events_excluded": len(candidates) - len(representatives),
        "requested_sample_size": size,
        "selected_documents": len(selected),
        "seed": seed,
        "population_sha256": digest(
            canonical_json(
                [
                    asdict(item)
                    for item in sorted(
                        representatives.values(), key=lambda item: item.event_id
                    )
                ]
            )
        ),
        "strata": {
            key: {
                "population": len(strata[key]),
                "selected": allocated[key],
                "inclusion_probability": allocated[key] / len(strata[key]),
                "weight": len(strata[key]) / allocated[key],
            }
            for key in sorted(strata)
        },
        "scope": "Unique eligible stored External threat-event texts; not ingestion recall",
        "selection": "Balanced strata (source key, source type, predicted relevance); seeded SHA-256 ranking",
    }


def annotation_template(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": VERSION,
        "sample_id": document["sample_id"],
        "text_sha256": document["text_sha256"],
        "reviewer_id": "",
        "annotation_source": "human",
        "reviewed_at": None,
        "status": "pending",
        "reviewed": dict.fromkeys(
            ["relevance", "entities", "observables", "relationships"], False
        ),
        "relevance": None,
        "entities": [],
        "observables": [],
        "relationships": [],
        "exclusion_reason": "",
        "adjudication_note": "",
    }


def write_package(
    destination: Path,
    documents: list[dict[str, Any]],
    references: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Write private artifacts atomically, manifest last; NEVER overwrite a run."""
    if destination.exists():
        raise FileExistsError(
            "Evaluation output already exists; use a new versioned directory"
        )
    templates = [annotation_template(document) for document in documents]
    gold = [{**row, "annotation_source": "human_adjudication"} for row in templates]
    contents = {
        "blind/documents.jsonl": documents,
        "blind/annotator_a.jsonl": templates,
        "blind/annotator_b.jsonl": templates,
        "private/reference.jsonl": references,
        "private/adjudicated.jsonl": gold,
    }
    serialized = {
        name: "".join(canonical_json(row) + "\n" for row in rows)
        for name, rows in contents.items()
    }
    if (
        sum(len(value.encode("utf-8")) for value in serialized.values())
        > MAX_PACKAGE_BYTES
    ):
        raise ValueError("Evaluation package exceeds 100 MiB limit")
    final_manifest = {
        **manifest,
        "schema_version": VERSION,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sealed_files": {
            name: digest(serialized[name])
            for name in ["blind/documents.jsonl", "private/reference.jsonl"]
        },
        "pilot_sample_ids": [document["sample_id"] for document in documents[:10]],
        "status": "awaiting_independent_human_annotations",
        "metrics": None,
        "prediction_scope": "Frozen DB outputs plus deterministic NER-policy filter, not fresh model inference",
        "offset_convention": "Unicode code points, zero-based, end-exclusive; original text unchanged",
        "private_data_warning": "Local sensitive text; do not commit, upload, or distribute private/reference.jsonl to annotators",
    }
    serialized["manifest.json"] = canonical_json(final_manifest) + "\n"
    destination.mkdir(parents=True, exist_ok=False)
    for name, value in serialized.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    return final_manifest


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.stat().st_size > MAX_PACKAGE_BYTES:
        raise ValueError("Input file exceeds size limit")
    with path.open(encoding="utf-8-sig") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("JSONL rows must be objects")
    return rows


def load_package(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != VERSION:
        raise ValueError("Unsupported evaluation schema")
    # Fixed paths, never paths supplied by a mutable manifest.
    for name in ["blind/documents.jsonl", "private/reference.jsonl"]:
        candidate = path / name
        if candidate.stat().st_size > MAX_PACKAGE_BYTES:
            raise ValueError("Package file exceeds size limit")
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != manifest[
            "sealed_files"
        ].get(name):
            raise ValueError("Sealed evaluation input changed")
    documents = read_jsonl(path / "blind/documents.jsonl")
    references = read_jsonl(path / "private/reference.jsonl")
    ids = [row["sample_id"] for row in documents]
    if len(ids) != len(set(ids)) or set(ids) != {
        row["sample_id"] for row in references
    }:
        raise ValueError("Document/reference membership mismatch")
    if (
        len(references) != len(documents)
        or len(documents) != manifest["selected_documents"]
    ):
        raise ValueError("Document/reference count mismatch")
    if any(digest(row["text"]) != row["text_sha256"] for row in documents):
        raise ValueError("Document text digest mismatch")
    return manifest, documents, references
