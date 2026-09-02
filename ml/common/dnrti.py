from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Iterable


DEFAULT_DATA_DIR = Path("ml/datasets/dnrti")
DEFAULT_REPORTS_DIR = Path("ml/reports")
SPLIT_FILES = {
    "train": "train.txt",
    "valid": "valid.txt",
    "test": "test.txt",
}


@dataclass
class BioSplit:
    name: str
    tokens: list[list[str]]
    labels: list[list[str]]
    malformed_count: int
    malformed_examples: list[dict[str, object]]
    rejected_sentence_count: int = 0

    @property
    def sentence_count(self) -> int:
        return len(self.tokens)

    @property
    def token_count(self) -> int:
        return sum(len(sentence) for sentence in self.tokens)


def read_bio_file(file_path: Path, split_name: str | None = None) -> BioSplit:
    """Read a CoNLL/BIO file where each non-empty line ends with a BIO label."""
    sentences: list[list[str]] = []
    labels: list[list[str]] = []
    current_tokens: list[str] = []
    current_labels: list[str] = []
    malformed_count = 0
    malformed_examples: list[dict[str, object]] = []

    with file_path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                if current_tokens:
                    sentences.append(current_tokens)
                    labels.append(current_labels)
                    current_tokens = []
                    current_labels = []
                continue

            parts = line.split()
            if len(parts) < 2:
                malformed_count += 1
                if len(malformed_examples) < 25:
                    malformed_examples.append(
                        {"line_number": line_number, "line": raw_line.rstrip("\n")}
                    )
                continue

            token = " ".join(parts[:-1])
            label = parts[-1]
            current_tokens.append(token)
            current_labels.append(label)

    if current_tokens:
        sentences.append(current_tokens)
        labels.append(current_labels)

    return BioSplit(
        name=split_name or file_path.stem,
        tokens=sentences,
        labels=labels,
        malformed_count=malformed_count,
        malformed_examples=malformed_examples,
    )


def read_bio_file_strict(file_path: Path, split_name: str | None = None) -> BioSplit:
    """Read BIO data while rejecting every sentence containing a malformed row."""
    sentences: list[list[str]] = []
    labels: list[list[str]] = []
    current_tokens: list[str] = []
    current_labels: list[str] = []
    current_is_malformed = False
    malformed_count = 0
    rejected_sentence_count = 0
    malformed_examples: list[dict[str, object]] = []

    def flush_sentence() -> None:
        nonlocal current_tokens, current_labels, current_is_malformed
        nonlocal rejected_sentence_count
        if current_is_malformed:
            rejected_sentence_count += 1
        elif current_tokens:
            sentences.append(current_tokens)
            labels.append(current_labels)
        current_tokens = []
        current_labels = []
        current_is_malformed = False

    with file_path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                if current_tokens or current_is_malformed:
                    flush_sentence()
                continue

            parts = line.split()
            if len(parts) < 2:
                malformed_count += 1
                current_is_malformed = True
                if len(malformed_examples) < 25:
                    malformed_examples.append(
                        {"line_number": line_number, "line": raw_line.rstrip("\n")}
                    )
                continue

            current_tokens.append(" ".join(parts[:-1]))
            current_labels.append(parts[-1])

    if current_tokens or current_is_malformed:
        flush_sentence()

    return BioSplit(
        name=split_name or file_path.stem,
        tokens=sentences,
        labels=labels,
        malformed_count=malformed_count,
        malformed_examples=malformed_examples,
        rejected_sentence_count=rejected_sentence_count,
    )


def read_dnrti_splits(data_dir: Path = DEFAULT_DATA_DIR) -> dict[str, BioSplit]:
    missing = [name for name in SPLIT_FILES.values() if not (data_dir / name).exists()]
    if missing:
        joined = ", ".join(missing)
        raise FileNotFoundError(f"Missing DNRTI split file(s) in {data_dir}: {joined}")

    return {
        split_name: read_bio_file(data_dir / file_name, split_name)
        for split_name, file_name in SPLIT_FILES.items()
    }


def flatten(nested: Iterable[Iterable[str]]) -> list[str]:
    return [item for sequence in nested for item in sequence]


def build_label_map(label_sequences: Iterable[Iterable[str]]) -> tuple[dict[str, int], dict[int, str]]:
    labels = sorted(set(flatten(label_sequences)))
    if "O" in labels:
        labels.remove("O")
        labels.insert(0, "O")
    label2id = {label: index for index, label in enumerate(labels)}
    id2label = {index: label for label, index in label2id.items()}
    return label2id, id2label


def entity_type(label: str) -> str | None:
    if label == "O":
        return None
    if "-" not in label:
        return label
    return label.split("-", 1)[1]


def summarize_split(split: BioSplit) -> dict[str, object]:
    lengths = [len(sentence) for sentence in split.tokens]
    label_distribution = Counter(flatten(split.labels))
    entity_distribution = Counter(
        entity
        for label in flatten(split.labels)
        for entity in [entity_type(label)]
        if entity
    )

    return {
        "sentences": split.sentence_count,
        "tokens": split.token_count,
        "min_sentence_length": min(lengths) if lengths else 0,
        "max_sentence_length": max(lengths) if lengths else 0,
        "avg_sentence_length": round(mean(lengths), 2) if lengths else 0,
        "malformed_lines": split.malformed_count,
        "rejected_malformed_sentences": split.rejected_sentence_count,
        "malformed_examples": split.malformed_examples,
        "label_distribution": dict(sorted(label_distribution.items())),
        "entity_type_distribution": dict(sorted(entity_distribution.items())),
    }


def sentence_key(tokens: Iterable[str]) -> str:
    """Stable comparison key used only for leakage and duplicate audits."""
    return " ".join(" ".join(tokens).split()).casefold()


def _sentence_label_map(split: BioSplit) -> dict[str, set[tuple[str, ...]]]:
    mapping: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    for tokens, labels in zip(split.tokens, split.labels):
        mapping[sentence_key(tokens)].add(tuple(labels))
    return dict(mapping)


def unique_unseen_split(
    splits: dict[str, BioSplit],
    *,
    target: str = "test",
    reference: str = "train",
) -> BioSplit:
    """Keep the first target sentence not present in the reference split."""
    target_split = splits[target]
    reference_keys = {sentence_key(tokens) for tokens in splits[reference].tokens}
    seen: set[str] = set()
    tokens: list[list[str]] = []
    labels: list[list[str]] = []
    for sentence_tokens, sentence_labels in zip(target_split.tokens, target_split.labels):
        key = sentence_key(sentence_tokens)
        if key in reference_keys or key in seen:
            continue
        seen.add(key)
        tokens.append(sentence_tokens)
        labels.append(sentence_labels)
    return BioSplit(
        name=f"{target}_unique_unseen_{reference}",
        tokens=tokens,
        labels=labels,
        malformed_count=target_split.malformed_count,
        malformed_examples=target_split.malformed_examples,
    )


def audit_split_integrity(splits: dict[str, BioSplit]) -> dict[str, object]:
    """Report exact sentence leakage, duplicates, and BIO-label conflicts."""
    mappings = {name: _sentence_label_map(split) for name, split in splits.items()}
    split_reports: dict[str, dict[str, int]] = {}
    for name, split in splits.items():
        mapping = mappings[name]
        split_reports[name] = {
            "sentences": split.sentence_count,
            "unique_sentences": len(mapping),
            "duplicate_rows": split.sentence_count - len(mapping),
            "texts_with_conflicting_label_sequences": sum(
                1 for label_sets in mapping.values() if len(label_sets) > 1
            ),
            "malformed_lines": split.malformed_count,
        }

    overlaps: dict[str, dict[str, float | int]] = {}
    names = [name for name in ("train", "valid", "test") if name in splits]
    for left_index, left in enumerate(names):
        for right in names[left_index + 1 :]:
            shared = set(mappings[left]) & set(mappings[right])
            smaller = min(len(mappings[left]), len(mappings[right]))
            same_labels = sum(
                1 for key in shared if mappings[left][key] & mappings[right][key]
            )
            only_conflicting = sum(
                1 for key in shared if not (mappings[left][key] & mappings[right][key])
            )
            mixed = sum(
                1
                for key in shared
                if mappings[left][key] & mappings[right][key]
                and mappings[left][key] != mappings[right][key]
            )
            overlaps[f"{left}_{right}"] = {
                "shared_unique_sentences": len(shared),
                "percent_of_smaller_unique_split": round(
                    100 * len(shared) / smaller, 2
                )
                if smaller
                else 0.0,
                "has_same_label_sequence": same_labels,
                "only_conflicting_label_sequences": only_conflicting,
                "mixed_label_sets": mixed,
            }

    unseen = unique_unseen_split(splits) if {"train", "test"} <= set(splits) else None
    malformed_total = sum(split.malformed_count for split in splits.values())
    conflicting_total = sum(
        values["texts_with_conflicting_label_sequences"] for values in split_reports.values()
    )
    shared_total = sum(int(values["shared_unique_sentences"]) for values in overlaps.values())
    quality_gates = {
        "cross_split_overlap_zero": shared_total == 0,
        "within_split_label_conflicts_zero": conflicting_total == 0,
        "malformed_lines_zero": malformed_total == 0,
    }
    return {
        "splits": split_reports,
        "cross_split_overlaps": overlaps,
        "unique_unseen_test_sentences": unseen.sentence_count if unseen else None,
        "quality_gates": quality_gates,
        "all_quality_gates_passed": all(quality_gates.values()),
    }


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)
