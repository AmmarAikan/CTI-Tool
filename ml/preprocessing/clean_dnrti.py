from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.common.dnrti import (  # noqa: E402
    DEFAULT_DATA_DIR,
    DEFAULT_REPORTS_DIR,
    SPLIT_FILES,
    BioSplit,
    audit_split_integrity,
    read_bio_file_strict,
    sentence_key,
    summarize_split,
    write_json,
)


DEFAULT_OUTPUT_DIR = Path("ml/datasets/dnrti_clean_v1")
SPLIT_PRIORITY = {"train": 0, "valid": 1, "test": 2}


@dataclass(frozen=True, slots=True)
class SentenceOccurrence:
    split: str
    index: int
    tokens: list[str]
    labels: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic, leakage-free DNRTI derivative dataset."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    return parser.parse_args()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_bio_atomic(path: Path, split: BioSplit) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as file:
        for tokens, labels in zip(split.tokens, split.labels):
            for token, label in zip(tokens, labels):
                file.write(f"{token} {label}\n")
            file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


def build_clean_splits(
    source_splits: dict[str, BioSplit],
) -> tuple[dict[str, BioSplit], dict[str, object]]:
    groups: OrderedDict[str, list[SentenceOccurrence]] = OrderedDict()
    for split_name in ("train", "valid", "test"):
        split = source_splits[split_name]
        for index, (tokens, labels) in enumerate(zip(split.tokens, split.labels)):
            groups.setdefault(sentence_key(tokens), []).append(
                SentenceOccurrence(split_name, index, tokens, labels)
            )

    clean_tokens = {name: [] for name in SPLIT_PRIORITY}
    clean_labels = {name: [] for name in SPLIT_PRIORITY}
    conflict_groups: list[dict[str, object]] = []
    conflicting_occurrences = 0
    duplicate_occurrences = 0
    cross_split_groups = 0

    for key, occurrences in groups.items():
        label_sequences = {tuple(item.labels) for item in occurrences}
        source_names = sorted({item.split for item in occurrences}, key=SPLIT_PRIORITY.get)
        if len(label_sequences) > 1:
            conflicting_occurrences += len(occurrences)
            conflict_groups.append(
                {
                    "text_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(),
                    "occurrences": len(occurrences),
                    "source_splits": source_names,
                    "distinct_label_sequences": len(label_sequences),
                }
            )
            continue

        if len(source_names) > 1:
            cross_split_groups += 1
        target = min(source_names, key=SPLIT_PRIORITY.get)
        selected = next(item for item in occurrences if item.split == target)
        clean_tokens[target].append(list(selected.tokens))
        clean_labels[target].append(list(selected.labels))
        duplicate_occurrences += len(occurrences) - 1

    clean_splits = {
        name: BioSplit(name, clean_tokens[name], clean_labels[name], 0, [])
        for name in ("train", "valid", "test")
    }
    integrity = audit_split_integrity(clean_splits)
    report = {
        "policy_version": "dnrti-clean-v1",
        "policy": {
            "malformed_sentence": "exclude the complete sentence; never infer a missing token",
            "conflicting_labels": "exclude the normalized text from every split",
            "duplicate_text": "retain one occurrence",
            "cross_split_priority": ["train", "valid", "test"],
            "source_files_modified": False,
        },
        "source": {
            name: {
                "accepted_sentences_after_strict_parse": split.sentence_count,
                "malformed_lines": split.malformed_count,
                "rejected_malformed_sentences": split.rejected_sentence_count,
            }
            for name, split in source_splits.items()
        },
        "grouping": {
            "unique_normalized_text_groups": len(groups),
            "cross_split_groups_collapsed": cross_split_groups,
            "duplicate_occurrences_removed": duplicate_occurrences,
            "conflicting_text_groups_excluded": len(conflict_groups),
            "conflicting_occurrences_excluded": conflicting_occurrences,
            "conflict_groups": conflict_groups,
        },
        "output": {
            name: summarize_split(split) for name, split in clean_splits.items()
        },
        "integrity": integrity,
    }
    if not integrity["all_quality_gates_passed"]:
        raise RuntimeError("Clean DNRTI derivative failed its integrity gates")
    return clean_splits, report


def main() -> None:
    args = parse_args()
    source_splits = {
        name: read_bio_file_strict(args.data_dir / filename, name)
        for name, filename in SPLIT_FILES.items()
    }
    clean_splits, report = build_clean_splits(source_splits)

    for name, filename in SPLIT_FILES.items():
        _write_bio_atomic(args.output_dir / filename, clean_splits[name])

    report["source_files"] = {
        filename: _sha256_file(args.data_dir / filename)
        for filename in SPLIT_FILES.values()
    }
    report["output_files"] = {
        filename: _sha256_file(args.output_dir / filename)
        for filename in SPLIT_FILES.values()
    }
    output_report = args.reports_dir / "dnrti_clean_v1_report.json"
    write_json(output_report, report)
    print(f"Clean DNRTI directory: {args.output_dir}")
    print(f"Cleaning report: {output_report}")
    for name, split in clean_splits.items():
        print(f"{name}: {split.sentence_count} sentences, {split.token_count} tokens")


if __name__ == "__main__":
    main()
