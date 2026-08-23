# External Sources contracts

These JSON Schemas define the versioned handoff and transport-independent application contracts owned by External Sources. They do not replace the shared runtime types in `backend/app/pipeline/common/cti_schema.py`; application code maps validated External items to the shared `RawRecord` contract.

Schema version `1.0` is additive-only. Removing fields or changing their meaning or type requires a documented version migration and downstream coordination.

Phase 10 adds optional manifest properties `invalid_records` and `classifier_model_sha256`. Canonical Phase 10 exports always emit both properties; keeping them optional in schema version 1.0 preserves validation compatibility for previously produced manifests.
