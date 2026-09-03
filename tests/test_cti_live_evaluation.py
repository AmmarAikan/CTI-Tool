from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from backend.app.db.database import Base
from backend.app.db.models import EntityRecord, ThreatEvent
from backend.app.services.cti_evaluation_service import CTIEvaluationService
from ml.evaluation.cti_annotations import (
    agreement_report,
    categorical_agreement,
    evaluate_annotations,
    normalized_observable,
    set_metrics,
    validate_annotations,
)
from ml.evaluation.cti_sampling import (
    Candidate,
    annotation_template,
    digest,
    load_package,
    read_jsonl,
    select_sample,
    write_package,
)


def document(value: str = "APT29 used Cobalt Strike.") -> dict:
    checksum = digest(value)
    return {"sample_id": "doc-" + checksum, "text": value, "text_sha256": checksum}


def annotated(doc: dict, reviewer: str, *, gold: bool = False) -> dict:
    result = annotation_template(doc)
    result.update(
        {
            "status": "complete",
            "reviewer_id": reviewer,
            "reviewed_at": "2026-09-03T10:00:00Z",
            "relevance": "cti_related",
            "reviewed": dict.fromkeys(result["reviewed"], True),
            "annotation_source": "human_adjudication" if gold else "human",
        }
    )
    for item_id, label, value in [
        ("e1", "threat_actor", "APT29"),
        ("e2", "tool_or_malware", "Cobalt Strike"),
    ]:
        if value in doc["text"]:
            start = doc["text"].index(value)
            result["entities"].append(
                {
                    "id": item_id,
                    "type": label,
                    "value": value,
                    "start": start,
                    "end": start + len(value),
                }
            )
    if len(result["entities"]) == 2:
        result["relationships"].append(
            {
                "subject_id": "e1",
                "relation": "USES",
                "object_id": "e2",
                "start": 0,
                "end": len(doc["text"]),
                "evidence": doc["text"],
            }
        )
    return result


def reference(doc: dict) -> dict:
    nodes = [
        {"type": "threat_actor", "value": "APT29"},
        {"type": "tool_or_malware", "value": "Cobalt Strike"},
    ]
    return {
        "sample_id": doc["sample_id"],
        "source_type": "rss",
        "source_key": "source-1",
        "weight": 2.0,
        "classification": "cti_related",
        "entities": nodes,
        "policy_entities": nodes,
        "observables": [],
        "relationships": [
            {"subject": "APT29", "relation": "USES", "object": "Cobalt Strike"}
        ],
    }


class CTISamplingTests(unittest.TestCase):
    def test_sampling_is_seeded_balanced_unique_and_keeps_negative_documents(
        self,
    ) -> None:
        candidates = []
        for group, size in [("rss", 20), ("cert", 3)]:
            for index in range(size):
                value = f"{group} {index}"
                candidates.append(
                    Candidate(
                        value,
                        group,
                        group,
                        "not_cybersecurity",
                        digest(value),
                        digest(value),
                        len(value),
                    )
                )
        candidates.append(
            Candidate(
                "z-duplicate",
                "rss",
                "rss",
                "cti_related",
                digest("rss 0"),
                digest("rss 0"),
                5,
            )
        )
        selected, manifest = select_sample(candidates, size=8, seed="fixed")
        reversed_selected, reversed_manifest = select_sample(
            list(reversed(candidates)), size=8, seed="fixed"
        )
        self.assertEqual(selected, reversed_selected)
        self.assertEqual(manifest, reversed_manifest)
        self.assertEqual(manifest["unique_documents"], 23)
        self.assertEqual(manifest["duplicate_events_excluded"], 1)
        self.assertEqual(sum(item.source_type == "cert" for item in selected), 3)
        self.assertEqual(len({item.dedup_sha256 for item in selected}), 8)
        self.assertTrue(
            all(item.classification == "not_cybersecurity" for item in selected)
        )
        self.assertAlmostEqual(
            sum(manifest["strata"][item.stratum]["weight"] for item in selected), 23
        )
        with self.assertRaises(ValueError):
            select_sample(candidates, size=1)

    def test_export_is_blind_sealed_and_refuses_overwrite(self) -> None:
        doc = document()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "package"
            write_package(root, [doc], [reference(doc)], {"selected_documents": 1})
            manifest, docs, refs = load_package(root)
            self.assertIsNone(manifest["metrics"])
            self.assertEqual(docs, [doc])
            self.assertEqual(refs, [reference(doc)])
            template = read_jsonl(root / "blind/annotator_a.jsonl")[0]
            self.assertEqual(template["entities"], [])
            self.assertEqual(template["status"], "pending")
            self.assertNotIn("classification", docs[0])
            self.assertNotIn("source_type", docs[0])
            with self.assertRaises(FileExistsError):
                write_package(root, [doc], [], {})
            with (root / "blind/documents.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(" ")
            with self.assertRaisesRegex(ValueError, "Sealed"):
                load_package(root)

    def test_service_is_external_only_read_only_and_never_loads_bert(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        try:
            with Session(engine) as session, tempfile.TemporaryDirectory() as directory:
                for number, pipeline, content in [
                    (1, "external", "attacker noted APT29."),
                    (2, "external", ""),
                    (3, "internal", "Internal event."),
                    (4, "external", "attacker noted APT29."),
                ]:
                    event = ThreatEvent(
                        id=str(number),
                        source_record_id=str(number),
                        source_pipeline=pipeline,
                        source_type="rss",
                        title="private-title",
                        normalized_text=content,
                        classification_label="cti_related",
                        processing_status="transformed",
                        raw_reference={},
                    )
                    if number == 1:
                        event.entities.append(
                            EntityRecord(
                                entity_type="threat_actor",
                                value="attacker",
                                confidence=0.99,
                                extractor="dnrti_bert_ner",
                            )
                        )
                    session.add(event)
                session.commit()
                with patch(
                    "backend.app.pipeline.extraction.ner_extractor.NERExtractor.__init__",
                    side_effect=AssertionError("inference forbidden"),
                ):
                    manifest = CTIEvaluationService(session).export(
                        Path(directory) / "package", size=4
                    )
                self.assertEqual(manifest["scanned_external_events"], 3)
                self.assertEqual(manifest["exclusions"]["empty_text"], 1)
                self.assertEqual(manifest["duplicate_events_excluded"], 1)
                self.assertEqual(manifest["selected_documents"], 1)
                self.assertEqual(
                    session.scalar(select(func.count()).select_from(EntityRecord)), 1
                )
                self.assertEqual(
                    session.scalar(select(func.count()).select_from(ThreatEvent)), 4
                )
                _, _, refs = load_package(Path(directory) / "package")
                self.assertEqual(len(refs[0]["entities"]), 1)
                self.assertEqual(refs[0]["policy_entities"], [])
        finally:
            engine.dispose()


class CTIAnnotationTests(unittest.TestCase):
    def test_pending_labels_never_produce_accuracy(self) -> None:
        doc = document()
        pending = annotation_template(doc)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            evaluate_annotations({}, [doc], [reference(doc)], [pending], [pending], [])
        with self.assertRaisesRegex(ValueError, "No independently"):
            agreement_report([doc], [pending], [pending], allow_partial=True)

    def test_complete_rows_require_independence_checksums_coverage_and_human_provenance(
        self,
    ) -> None:
        doc = document()
        a = annotated(doc, "reviewer-a")
        validate_annotations([doc], [a])
        with self.assertRaisesRegex(ValueError, "disjoint"):
            agreement_report([doc], [a], [copy.deepcopy(a)])
        for field, bad in [
            ("text_sha256", "changed"),
            ("annotation_source", "bert"),
            ("reviewed", {}),
            ("reviewed_at", None),
            ("reviewer_id", ""),
        ]:
            changed = copy.deepcopy(a)
            changed[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_annotations([doc], [changed])
        with self.assertRaises(ValueError):
            validate_annotations([doc], [a, a])
        with self.assertRaises(ValueError):
            validate_annotations([doc], [])

    def test_offsets_are_unicode_code_points_not_bytes(self) -> None:
        doc = document("أمر APT29")
        a = annotated(doc, "a")
        validate_annotations([doc], [a])
        a["entities"][0]["start"] += 1
        with self.assertRaisesRegex(ValueError, "Span"):
            validate_annotations([doc], [a])

    def test_observable_assessments_need_context_and_refang_preserves_url_case(
        self,
    ) -> None:
        value = "hxxps://EVIL[.]example/Path"
        doc = document(value + " is an example.")
        row = annotated(doc, "a")
        row["observables"] = [
            {
                "id": "o1",
                "type": "url",
                "value": "https://evil.example/Path",
                "surface": value,
                "start": 0,
                "end": len(value),
                "assessment": "unknown",
                "assessment_evidence": "",
            }
        ]
        validate_annotations([doc], [row])
        self.assertNotEqual(
            normalized_observable("url", "https://evil.example/Path"),
            normalized_observable("url", "https://evil.example/path"),
        )
        row["observables"][0]["assessment"] = "malicious"
        with self.assertRaisesRegex(ValueError, "evidence"):
            validate_annotations([doc], [row])
        row["observables"][0]["assessment_evidence"] = doc["text"]
        validate_annotations([doc], [row])
        row["observables"][0]["value"] = "https://other.example/Path"
        with self.assertRaisesRegex(ValueError, "differs"):
            validate_annotations([doc], [row])

    def test_relation_references_and_evidence_are_validated(self) -> None:
        doc = document()
        row = annotated(doc, "a")
        row["relationships"][0]["subject_id"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown annotation"):
            validate_annotations([doc], [row])
        row = annotated(doc, "a")
        row["relationships"][0]["evidence"] = "invented"
        with self.assertRaisesRegex(ValueError, "Span"):
            validate_annotations([doc], [row])

    def test_real_disagreements_require_adjudication_and_model_scores_are_value_based(
        self,
    ) -> None:
        doc = document()
        a, b, gold = (
            annotated(doc, "a"),
            annotated(doc, "b"),
            annotated(doc, "consensus", gold=True),
        )
        b["entities"] = b["entities"][:1]
        b["relationships"] = []
        meta = {"population_sha256": "population", "sealed_files": {}}
        with self.assertRaisesRegex(ValueError, "adjudication note"):
            evaluate_annotations(meta, [doc], [reference(doc)], [a], [b], [gold])
        gold["adjudication_note"] = (
            "Both reviewers resolved the omitted tool and its explicit USES relation."
        )
        predictions = reference(doc)
        predictions["entities"] = [
            *predictions["entities"],
            {"type": "threat_actor", "value": "attacker"},
        ]
        result = evaluate_annotations(meta, [doc], [predictions], [a], [b], [gold])
        stored = result["metrics"]["stored_entities_document_values"]
        filtered = result["metrics"]["policy_filtered_entities_document_values"]
        self.assertEqual(stored["micro"]["tp"], 2)
        self.assertEqual(stored["micro"]["fp"], 1)
        self.assertEqual(filtered["micro"]["f1"], 1.0)
        self.assertEqual(stored["weighted_micro"]["tp"], 4)
        self.assertEqual(result["model_promotion"], "not_performed")
        self.assertIn(doc["sample_id"], result["agreement"]["disagreement_sample_ids"])
        json.dumps(result, allow_nan=False)

    def test_empty_negatives_and_zero_support_do_not_inflate_f1(self) -> None:
        result = set_metrics([(set(), {("threat_actor", "attacker")}, 3.0, "rss")])
        self.assertEqual(result["micro"]["fp"], 1)
        self.assertEqual(result["micro"]["f1"], 0)
        self.assertIsNone(result["micro"]["recall"])
        self.assertIsNone(result["macro_f1_supported_types"])
        self.assertIsNone(set_metrics([(set(), set(), 1.0, "rss")])["micro"]["f1"])
        self.assertIsNone(categorical_agreement(["same"], ["same"])["cohen_kappa"])
        self.assertEqual(
            categorical_agreement(["A", "B"], ["A", "B"])["cohen_kappa"], 1.0
        )

    def test_partial_pilot_agreement_is_not_final_model_accuracy(self) -> None:
        doc, later = document(), document("A different text.")
        a, b = annotated(doc, "a"), annotated(doc, "b")
        pending = annotation_template(later)
        result = agreement_report(
            [doc, later], [a, pending], [b, pending], allow_partial=True
        )
        self.assertEqual(result["paired_complete_documents"], 1)
        self.assertEqual(result["not_paired_documents"], 1)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            agreement_report([doc, later], [a, pending], [b, pending])


if __name__ == "__main__":
    unittest.main()
