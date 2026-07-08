from __future__ import annotations

import json
from collections import Counter
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
        "malformed_examples": split.malformed_examples,
        "label_distribution": dict(sorted(label_distribution.items())),
        "entity_type_distribution": dict(sorted(entity_distribution.items())),
    }


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)
