from __future__ import annotations

from backend.app.pipeline.common.cti_schema import Entity, Indicator, Relationship


class RelationExtractor:
    """Initial rule-based CTI relationship extractor."""

    def extract(
        self,
        text: str,
        entities: list[Entity],
        indicators: list[Indicator],
        source_record_id: str,
    ) -> list[Relationship]:
        lowered = text.lower()
        relationships: list[Relationship] = []
        actors = [entity for entity in entities if entity.type in {"threat_actor", "hackorg"}]
        tools = [
            entity
            for entity in entities
            if entity.type in {"tool", "malware", "tool_or_malware", "sample_file"}
        ]
        targets = [
            entity
            for entity in entities
            if entity.type in {"organization", "industry_sector", "location", "security_team"}
        ]
        vulnerabilities = [indicator for indicator in indicators if indicator.type == "cve"]

        for actor in actors:
            for tool in tools:
                if any(keyword in lowered for keyword in (" use ", " used ", " uses ", " deploy ", " deployed ")):
                    relationships.append(
                        self._relationship(actor.text, "USES", tool.text, 0.65, source_record_id)
                    )
            for target in targets:
                if any(keyword in lowered for keyword in (" target ", " targeted ", " targets ", " against ")):
                    relationships.append(
                        self._relationship(actor.text, "TARGETS", target.text, 0.6, source_record_id)
                    )

        for tool in tools:
            for vulnerability in vulnerabilities:
                if any(keyword in lowered for keyword in (" exploit", " vulnerability", " cve-")):
                    relationships.append(
                        self._relationship(tool.text, "EXPLOITS", vulnerability.value, 0.55, source_record_id)
                    )

        for entity in entities:
            relationships.append(
                self._relationship("report", "MENTIONS", entity.text, 0.5, source_record_id)
            )

        return self._deduplicate(relationships)

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
