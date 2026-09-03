from __future__ import annotations

import re

from backend.app.pipeline.common.cti_schema import Entity, Indicator, Relationship


SEGMENT_RE = re.compile(r"(?<=[.!?])\s+|[\r\n;]+")
LONG_SEGMENT_RE = re.compile(r",\s+|\s+[-\u2013\u2014]\s+")
USES_RE = re.compile(r"\b(?:use|used|uses|using|deploy|deployed|deploys|deploying)\b", re.IGNORECASE)
TARGETS_RE = re.compile(r"\b(?:target|targeted|targets|targeting|against)\b", re.IGNORECASE)
EXPLOITS_RE = re.compile(
    r"\b(?:exploit|exploited|exploits|exploiting|vulnerability|vulnerabilities|cve-\d{4}-\d+)\b",
    re.IGNORECASE,
)


class RelationExtractor:
    """Sentence-aware, schema-bounded CTI relationship extractor."""

    MAX_SEGMENT_CHARS = 1_000
    MAX_PAIRS_PER_SEGMENT = 25

    def extract(
        self,
        text: str,
        entities: list[Entity],
        indicators: list[Indicator],
        source_record_id: str,
    ) -> list[Relationship]:
        relationships: list[Relationship] = []
        for segment in self._segments(text):
            mentioned_entities = [
                entity for entity in entities if self._is_mentioned(entity.text, segment)
            ]
            mentioned_indicators = [
                indicator for indicator in indicators if self._is_mentioned(indicator.value, segment)
            ]
            actors = [
                entity
                for entity in mentioned_entities
                if entity.type in {"threat_actor", "hackorg"}
            ]
            tools = [
                entity
                for entity in mentioned_entities
                if entity.type in {"tool", "malware", "tool_or_malware", "sample_file"}
            ]
            targets = [
                entity
                for entity in mentioned_entities
                if entity.type in {"organization", "industry_sector", "location", "security_team"}
            ]
            vulnerabilities = [
                indicator for indicator in mentioned_indicators if indicator.type == "cve"
            ]

            if USES_RE.search(segment):
                relationships.extend(
                    self._bounded_pairs(
                        actors,
                        tools,
                        "USES",
                        0.70,
                        source_record_id,
                    )
                )
            if TARGETS_RE.search(segment):
                relationships.extend(
                    self._bounded_pairs(
                        actors,
                        targets,
                        "TARGETS",
                        0.70,
                        source_record_id,
                    )
                )
            if EXPLOITS_RE.search(segment):
                relationships.extend(
                    self._bounded_pairs(
                        tools,
                        vulnerabilities,
                        "EXPLOITS",
                        0.70,
                        source_record_id,
                    )
                )

        for entity in entities:
            relationships.append(
                self._relationship("report", "MENTIONS", entity.text, 0.5, source_record_id)
            )

        return self._deduplicate(relationships)

    def _segments(self, text: str) -> list[str]:
        segments = [part.strip() for part in SEGMENT_RE.split(text) if part.strip()]
        bounded: list[str] = []
        for segment in segments:
            if len(segment) <= self.MAX_SEGMENT_CHARS:
                bounded.append(segment)
                continue
            for part in LONG_SEGMENT_RE.split(segment):
                bounded.extend(self._bounded_chunks(part.strip()))
        return bounded

    def _bounded_chunks(self, text: str) -> list[str]:
        chunks = []
        start = 0
        while start < len(text):
            end = min(len(text), start + self.MAX_SEGMENT_CHARS)
            if end < len(text):
                whitespace = text.rfind(" ", start, end)
                if whitespace > start:
                    end = whitespace
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            start = max(end, start + 1)
            while start < len(text) and text[start].isspace():
                start += 1
        return chunks

    @staticmethod
    def _is_mentioned(value: str, segment: str) -> bool:
        value = value.strip()
        if not value:
            return False
        return re.search(
            rf"(?<!\w){re.escape(value)}(?!\w)",
            segment,
            flags=re.IGNORECASE,
        ) is not None

    def _bounded_pairs(
        self,
        subjects: list[Entity],
        objects: list[Entity] | list[Indicator],
        relation: str,
        confidence: float,
        source_record_id: str,
    ) -> list[Relationship]:
        relationships = []
        for subject in subjects:
            for object_item in objects:
                if len(relationships) >= self.MAX_PAIRS_PER_SEGMENT:
                    return relationships
                object_value = (
                    object_item.text if isinstance(object_item, Entity) else object_item.value
                )
                relationships.append(
                    self._relationship(
                        subject.text,
                        relation,
                        object_value,
                        confidence,
                        source_record_id,
                    )
                )
        return relationships

    def _relationship(
        self,
        subject: str,
        relation: str,
        object_value: str,
        confidence: float,
        source_record_id: str,
    ) -> Relationship:
        return Relationship(
            subject=subject,
            relation=relation,
            object=object_value,
            confidence=confidence,
            extraction_method="rule_based",
            source_record_id=source_record_id,
        )

    def _deduplicate(self, relationships: list[Relationship]) -> list[Relationship]:
        seen = set()
        unique = []
        for relationship in relationships:
            key = (
                relationship.subject.lower(),
                relationship.relation,
                relationship.object.lower(),
                relationship.source_record_id,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(relationship)
        return unique
