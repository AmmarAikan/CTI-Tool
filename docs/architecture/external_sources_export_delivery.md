# External Sources Phase 10 — dataset export and handoff

The sole canonical exporter is `backend/app/pipeline/ingestion/external/export/final_dataset.py`. The obsolete prototype exporter was retired after canonical run isolation, contract validation, and deterministic export coverage were established.

Orchestration creates one `RunManifest` (and therefore one `run_id`) before collection. Every collector result is wrapped in `RunSourceOutput` carrying that same ID. The exporter rejects any mixed run/checkpoint set and adds the run ID to exported record metadata.

Accepted candidates are validated against `external_cti_item.schema.json`. Empty content, incomplete/rejected classification, unresolved privacy review, and invalid contracts are excluded from the accepted dataset and preserved in the run-scoped review file with safe reason codes. Source failures use category-only manifest entries.

External-only deduplication uses official identifiers, then canonical URLs, normalized content hashes, and finally stable source/title/published identity. Merged observations preserve `observed_in`, source identifiers, references, and provenance. Final IDs use SHA-256 and records are deterministically sorted.

Outputs are `final_dataset_<run_id>.json`, `external_export_manifest_<run_id>.json`, and `external_review_<run_id>.json`. Each artifact and the JSON run-state update uses the repository atomic replacement utility. The manifest SHA-256 is calculated from the exact completed dataset bytes. Phase 10 does not perform cross-team deduplication or start the Phase 11 transport adapter.
