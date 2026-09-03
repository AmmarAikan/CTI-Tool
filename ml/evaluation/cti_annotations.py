"""Strict human-annotation validation and auditable CTI set metrics.

Database entities have no offsets: model scores are document/type/value scores,
not exact-span NER scores. Exact spans are used ONLY for human-human agreement.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from backend.app.pipeline.extraction.ioc_extractor import IoCExtractor
from ml.evaluation.cti_sampling import VERSION, canonical_json, digest

ENTITY_TYPES = frozenset(
    {
        "threat_actor",
        "tool_or_malware",
        "organization",
        "location",
        "security_team",
        "industry_sector",
        "attack_method",
        "sample_file",
        "exploit",
        "technical_feature",
        "time",
        "objective",
    }
)
OBSERVABLE_TYPES = frozenset(
    {
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "email",
        "md5",
        "sha1",
        "sha256",
        "cve",
        "asn",
        "mac",
    }
)
RELATIONS = frozenset({"USES", "TARGETS", "EXPLOITS"})
RELEVANCE = frozenset(
    {"cti_related", "cybersecurity_related", "not_cybersecurity", "uncertain"}
)
REVIEW_FIELDS = frozenset({"relevance", "entities", "observables", "relationships"})
Key = tuple[Any, ...]


def normalized_entity(value: str) -> str:
    return " ".join(value.split()).casefold()


def normalized_observable(kind: str, value: str) -> str:
    """Normalize notation, NOT maliciousness. URL paths remain case sensitive."""
    value = IoCExtractor._refang(value.strip())
    if kind in {"ipv4", "ipv6"}:
        address = ipaddress.ip_address(value)
        if address.version != int(kind[-1]):
            raise ValueError("IP version mismatch")
        return address.compressed
    if kind in {"md5", "sha1", "sha256"}:
        length = {"md5": 32, "sha1": 40, "sha256": 64}[kind]
        if not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value):
            raise ValueError("Invalid hash")
        return value.lower()
    if kind == "cve":
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", value, flags=re.IGNORECASE):
            raise ValueError("Invalid CVE")
        return value.upper()
    if kind == "asn":
        if not re.fullmatch(r"AS[1-9]\d{0,9}", value, flags=re.IGNORECASE):
            raise ValueError("Invalid ASN")
        number = int(value[2:])
        if number > 4_294_967_295:
            raise ValueError("Invalid ASN range")
        return f"AS{number}"
    if kind == "mac":
        if not re.fullmatch(
            r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}",
            value,
        ):
            raise ValueError("Invalid MAC")
        return value.replace("-", ":").lower()
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("Invalid HTTP URL")
        # Preserve userinfo/path/query/fragment case; only host and scheme fold.
        prefix, separator, _ = parts.netloc.rpartition("@")
        host = parts.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        port = f":{parts.port}" if parts.port is not None else ""
        netloc = (prefix + separator if separator else "") + host + port
        return urlunsplit(
            (parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)
        )
    if kind == "email":
        local, separator, host = value.rpartition("@")
        if (
            not separator
            or not local
            or any(character.isspace() for character in local)
        ):
            raise ValueError("Invalid email")
        return local + "@" + normalized_observable("domain", host)
    if kind == "domain":
        value = value.rstrip(".").lower()
        if len(value) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*", value
        ):
            raise ValueError("Invalid domain")
        return value
    raise ValueError("Unsupported observable type")


def _span(item: dict[str, Any], text: str, value_field: str) -> tuple[int, int]:
    start, end = item.get("start"), item.get("end")
    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start < end <= len(text)
    ):
        raise ValueError("Invalid Unicode code-point span")
    if item.get(value_field) != text[start:end]:
        raise ValueError("Span does not match immutable source text")
    if not text[start:end].strip():
        raise ValueError("Whitespace-only spans are not annotations")
    return start, end


def validate_annotations(
    documents: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    *,
    adjudicated: bool = False,
) -> dict[str, dict[str, Any]]:
    by_document = {row["sample_id"]: row for row in documents}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        sample_id = row.get("sample_id")
        if sample_id not in by_document or sample_id in result:
            raise ValueError("Duplicate or unknown annotation document")
        document = by_document[sample_id]
        if (
            row.get("schema_version") != VERSION
            or row.get("text_sha256") != document["text_sha256"]
        ):
            raise ValueError("Annotation schema/text checksum mismatch")
        status = row.get("status")
        if status not in {"pending", "complete", "excluded"}:
            raise ValueError("Invalid annotation status")
        if row.get("annotation_source") != (
            "human_adjudication" if adjudicated else "human"
        ):
            raise ValueError("Human provenance declaration required")
        if any(
            not isinstance(row.get(field), list)
            for field in ["entities", "observables", "relationships"]
        ):
            raise ValueError("Annotation collections must be lists")
        result[sample_id] = row
        if status == "pending":
            continue
        if (
            not isinstance(row.get("reviewer_id"), str)
            or not row["reviewer_id"].strip()
        ):
            raise ValueError(
                "Completed/excluded records need an actual reviewer pseudonym"
            )
        stamp = row.get("reviewed_at")
        if not isinstance(stamp, str) or not stamp.endswith("Z"):
            raise ValueError("Human review requires a UTC timestamp ending in Z")
        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if status == "excluded":
            if (
                not isinstance(row.get("exclusion_reason"), str)
                or not row["exclusion_reason"].strip()
            ):
                raise ValueError(
                    "Excluded documents need a reason; never silently drop negatives"
                )
            continue
        reviewed = row.get("reviewed")
        if (
            not isinstance(reviewed, dict)
            or set(reviewed) != REVIEW_FIELDS
            or any(value is not True for value in reviewed.values())
        ):
            raise ValueError(
                "All four tasks must be exhaustively reviewed before completion"
            )
        if row.get("relevance") not in RELEVANCE:
            raise ValueError("Missing/invalid human relevance label")
        nodes: dict[str, dict[str, Any]] = {}
        text = document["text"]
        for field, allowed in [
            ("entities", ENTITY_TYPES),
            ("observables", OBSERVABLE_TYPES),
        ]:
            seen = set()
            for item in row[field]:
                if not isinstance(item, dict) or item.get("type") not in allowed:
                    raise ValueError("Invalid annotation entity/observable type")
                item_id = item.get("id")
                if (
                    not isinstance(item_id, str)
                    or not re.fullmatch(r"[eo][1-9]\d*", item_id)
                    or item_id in nodes
                ):
                    raise ValueError(
                        "Entity/observable IDs must be unique e1/o1 style identifiers"
                    )
                start, end = _span(
                    item, text, "value" if field == "entities" else "surface"
                )
                key = (item["type"], start, end)
                if key in seen:
                    raise ValueError("Duplicate annotation span/type")
                seen.add(key)
                if field == "observables":
                    if (
                        not isinstance(item.get("value"), str)
                        or not 0 < len(item["value"]) <= 2048
                    ):
                        raise ValueError("Invalid observable value")
                    if normalized_observable(
                        item["type"], item["value"]
                    ) != normalized_observable(item["type"], item["surface"]):
                        raise ValueError(
                            "Canonical observable differs from annotated source span"
                        )
                    if item.get("assessment") not in {"unknown", "benign", "malicious"}:
                        raise ValueError("Observable assessment required")
                    if item["assessment"] != "unknown":
                        evidence = item.get("assessment_evidence")
                        if (
                            not isinstance(evidence, str)
                            or not evidence.strip()
                            or evidence not in text
                        ):
                            raise ValueError(
                                "Benign/malicious judgment needs a verbatim contextual evidence quote"
                            )
                nodes[item_id] = item
        relation_keys = set()
        for relation in row["relationships"]:
            if (
                not isinstance(relation, dict)
                or relation.get("relation") not in RELATIONS
            ):
                raise ValueError("Unsupported semantic relation")
            if (
                relation.get("subject_id") not in nodes
                or relation.get("object_id") not in nodes
            ):
                raise ValueError("Relationship references an unknown annotation node")
            _span(relation, text, "evidence")
            key = (relation["subject_id"], relation["relation"], relation["object_id"])
            if key in relation_keys:
                raise ValueError("Duplicate relationship annotation")
            relation_keys.add(key)
    if set(result) != set(by_document):
        raise ValueError(
            "Annotation file must retain every sampled document, including pending/excluded rows"
        )
    return result


def value_keys(row: dict[str, Any], field: str) -> set[Key]:
    keys = set()
    for item in row[field]:
        if field == "observables":
            try:
                value = normalized_observable(item["type"], item["value"])
            except ValueError:
                # Invalid stored predictions remain false positives, not silently discarded.
                value = "invalid-observable:" + item["value"]
        else:
            value = normalized_entity(item["value"])
        keys.add((item["type"], value))
    return keys


def relation_keys(row: dict[str, Any], *, predicted: bool = False) -> set[Key]:
    nodes = (
        {
            item["id"]: item
            for field in ["entities", "observables"]
            for item in row[field]
        }
        if not predicted
        else {}
    )
    return {
        (
            item["relation"],
            normalized_entity(
                item["subject"] if predicted else nodes[item["subject_id"]]["value"]
            ),
            normalized_entity(
                item["object"] if predicted else nodes[item["object_id"]]["value"]
            ),
        )
        for item in row["relationships"]
    }


def _scores(counts: Counter[str]) -> dict[str, Any]:
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "support": tp + fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
    }


def set_metrics(pairs: list[tuple[set[Key], set[Key], float, str]]) -> dict[str, Any]:
    total: Counter[str] = Counter()
    weighted: Counter[str] = Counter()
    types: dict[str, Counter[str]] = defaultdict(Counter)
    sources: dict[str, Counter[str]] = defaultdict(Counter)
    for truth, predicted, weight, source in pairs:
        for name, values in [
            ("tp", truth & predicted),
            ("fp", predicted - truth),
            ("fn", truth - predicted),
        ]:
            total[name] += len(values)
            weighted[name] += len(values) * weight
            sources[source][name] += len(values)
            for key in values:
                types[str(key[0])][name] += 1
    per_type = {key: _scores(value) for key, value in sorted(types.items())}
    supported = [value for value in per_type.values() if value["support"] > 0]
    return {
        "micro": _scores(total),
        "weighted_micro": _scores(weighted),
        "macro_f1_supported_types": sum(value["f1"] for value in supported)
        / len(supported)
        if supported
        else None,
        "per_type": per_type,
        "per_source_type": {
            key: _scores(value) for key, value in sorted(sources.items())
        },
    }


def categorical_agreement(left: list[str], right: list[str]) -> dict[str, Any]:
    if len(left) != len(right) or not left:
        raise ValueError("Categorical agreement requires nonempty paired observations")
    count = len(left)
    observed = sum(a == b for a, b in zip(left, right)) / count
    a_counts, b_counts = Counter(left), Counter(right)
    expected = (
        sum(
            a_counts[label] * b_counts[label]
            for label in a_counts.keys() | b_counts.keys()
        )
        / count**2
    )
    return {
        "documents": count,
        "raw_agreement": observed,
        "cohen_kappa": (observed - expected) / (1 - expected) if expected < 1 else None,
    }


def _same_judgments(a: dict[str, Any], b: dict[str, Any]) -> bool:
    def semantic(row: dict[str, Any]) -> tuple[Any, ...]:
        spans = [
            frozenset(
                (item["type"], item["start"], item["end"], item.get("assessment"))
                for item in row[field]
            )
            for field in ["entities", "observables"]
        ]
        return row["relevance"], *spans, frozenset(relation_keys(row))

    return semantic(a) == semantic(b)


def agreement_report(
    documents: list[dict[str, Any]],
    a_rows: list[dict[str, Any]],
    b_rows: list[dict[str, Any]],
    *,
    allow_partial: bool = False,
) -> dict[str, Any]:
    a = validate_annotations(documents, a_rows)
    b = validate_annotations(documents, b_rows)
    if not allow_partial and any(
        row["status"] == "pending" for row in [*a.values(), *b.values()]
    ):
        raise ValueError(
            "Annotations incomplete; partial agreement requires explicit pilot mode"
        )
    ids = sorted(key for key in a if a[key]["status"] == b[key]["status"] == "complete")
    if not ids:
        raise ValueError("No independently completed pairs; metrics are unavailable")
    left_reviewers = {a[key]["reviewer_id"].strip().casefold() for key in ids}
    right_reviewers = {b[key]["reviewer_id"].strip().casefold() for key in ids}
    if left_reviewers & right_reviewers:
        raise ValueError(
            "Independent annotation sets must have disjoint reviewer identities"
        )
    result: dict[str, Any] = {
        "paired_complete_documents": len(ids),
        "not_paired_documents": len(a) - len(ids),
        "relevance": categorical_agreement(
            [a[key]["relevance"] for key in ids], [b[key]["relevance"] for key in ids]
        ),
        "disagreement_sample_ids": [
            key for key in ids if not _same_judgments(a[key], b[key])
        ],
        "note": "Pairwise extraction F1 is agreement, NOT model accuracy; kappa is only for categorical relevance",
    }
    for field in ["entities", "observables"]:
        pairs = []
        for key in ids:
            span_sets = [
                {(item["type"], item["start"], item["end"]) for item in row[field]}
                for row in [a[key], b[key]]
            ]
            pairs.append((span_sets[0], span_sets[1], 1.0, "all"))
        result[field + "_exact_span_agreement"] = set_metrics(pairs)
    result["relationship_agreement"] = set_metrics(
        [(relation_keys(a[key]), relation_keys(b[key]), 1.0, "all") for key in ids]
    )
    assessment_pairs = []
    for key in ids:
        # Occurrence spans prevent silently merging contradictory judgments.
        assessments = [
            {
                (item["type"], item["start"], item["end"]): item["assessment"]
                for item in row["observables"]
            }
            for row in [a[key], b[key]]
        ]
        assessment_pairs.extend(
            (assessments[0][span], assessments[1][span])
            for span in assessments[0].keys() & assessments[1].keys()
        )
    result["observable_assessment_agreement"] = {
        "matched_spans": len(assessment_pairs),
        "raw_agreement": sum(left == right for left, right in assessment_pairs)
        / len(assessment_pairs)
        if assessment_pairs
        else None,
    }
    return result


def evaluate_annotations(
    manifest: dict[str, Any],
    documents: list[dict[str, Any]],
    references: list[dict[str, Any]],
    a_rows: list[dict[str, Any]],
    b_rows: list[dict[str, Any]],
    gold_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    agreement = agreement_report(documents, a_rows, b_rows)
    a = validate_annotations(documents, a_rows)
    b = validate_annotations(documents, b_rows)
    gold = validate_annotations(documents, gold_rows, adjudicated=True)
    if any(row["status"] == "pending" for row in gold.values()):
        raise ValueError(
            "Gold annotations have not been fully adjudicated; model metrics withheld"
        )
    selected = [key for key, row in gold.items() if row["status"] == "complete"]
    if not selected:
        raise ValueError("No adjudicated documents to evaluate")
    for key in selected:
        if a[key]["status"] != "complete" or b[key]["status"] != "complete":
            raise ValueError(
                "Gold inclusion requires two completed independent reviews"
            )
        if (
            not _same_judgments(a[key], b[key])
            and not str(gold[key].get("adjudication_note", "")).strip()
        ):
            raise ValueError("Every disagreement needs a human adjudication note")
    predictions = {row["sample_id"]: row for row in references}
    metrics: dict[str, Any] = {}
    tasks: list[tuple[str, Callable[[dict], set[Key]], Callable[[dict], set[Key]]]] = [
        (
            "stored_entities_document_values",
            lambda row: value_keys(row, "entities"),
            lambda row: value_keys(row, "entities"),
        ),
        (
            "policy_filtered_entities_document_values",
            lambda row: value_keys(row, "entities"),
            lambda row: value_keys(row, "policy_entities"),
        ),
        (
            "observables_document_values",
            lambda row: value_keys(row, "observables"),
            lambda row: value_keys(row, "observables"),
        ),
        (
            "semantic_relationship_document_tuples",
            relation_keys,
            lambda row: relation_keys(row, predicted=True),
        ),
    ]
    for name, truth_keys, predicted_keys in tasks:
        pairs = [
            (
                truth_keys(gold[key]),
                predicted_keys(predictions[key]),
                predictions[key]["weight"],
                predictions[key]["source_type"],
            )
            for key in selected
        ]
        metrics[name] = set_metrics(pairs)
        metrics[name]["per_source_key"] = {
            source: set_metrics(
                [
                    pairs[index]
                    for index, key in enumerate(selected)
                    if predictions[key]["source_key"] == source
                ]
            )["micro"]
            for source in sorted({predictions[key]["source_key"] for key in selected})
        }
    classified = [key for key in selected if gold[key]["relevance"] != "uncertain"]
    if classified:
        metrics["relevance"] = set_metrics(
            [
                (
                    {(gold[key]["relevance"],)},
                    {(predictions[key]["classification"] or "unclassified",)},
                    predictions[key]["weight"],
                    predictions[key]["source_type"],
                )
                for key in classified
            ]
        )
    else:
        metrics["relevance"] = None
    return {
        "schema_version": VERSION,
        "status": "human_adjudicated_sample_evaluated",
        "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "annotation_sha256": {
            name: digest(canonical_json(sorted(rows, key=lambda row: row["sample_id"])))
            for name, rows in [
                ("annotator_a", a_rows),
                ("annotator_b", b_rows),
                ("adjudicated", gold_rows),
            ]
        },
        "population_sha256": manifest["population_sha256"],
        "sealed_files": manifest["sealed_files"],
        "evaluated_documents": len(selected),
        "excluded_documents": len(gold) - len(selected),
        "uncertain_relevance_documents": len(selected) - len(classified),
        "agreement": agreement,
        "metrics": metrics,
        "weight_caveat": "Weights target eligible unique stored documents, not all ingestion; exclusions may bias estimates",
        "limitations": [
            "No DB span accuracy: offsets were never persisted",
            "No ingestion recall or verified global maliciousness",
            "No confidence intervals in v1; rare-type estimates need adequate gold support",
            "Policy-filter comparison uses frozen historical outputs, not a retrained model",
        ],
        "model_promotion": "not_performed",
    }
