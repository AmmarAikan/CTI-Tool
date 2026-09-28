-- Additive durable External ingestion operation state. Safe for an existing database.
CREATE TABLE IF NOT EXISTS external_ingestion_operations (
    id VARCHAR(36) PRIMARY KEY,
    operation_type VARCHAR(40) NOT NULL DEFAULT 'external_ingestion',
    state VARCHAR(30) NOT NULL DEFAULT 'queued',
    stage VARCHAR(40) NOT NULL DEFAULT 'export_ready',
    retryable BOOLEAN NOT NULL DEFAULT TRUE,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 100,
    external_job_id VARCHAR(200) NOT NULL,
    export_run_id VARCHAR(200) NOT NULL,
    dataset_sha256 VARCHAR(64) NOT NULL,
    gateway_checkpoint VARCHAR(200),
    pipeline_run_id VARCHAR(36) REFERENCES pipeline_runs(id) ON DELETE SET NULL,
    collected_count INTEGER NOT NULL DEFAULT 0,
    exported_count INTEGER NOT NULL DEFAULT 0,
    imported_count INTEGER NOT NULL DEFAULT 0,
    created_count INTEGER NOT NULL DEFAULT 0,
    updated_count INTEGER NOT NULL DEFAULT 0,
    unchanged_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    acknowledged_count INTEGER NOT NULL DEFAULT 0,
    processed_offset INTEGER NOT NULL DEFAULT 0,
    fairness_skips INTEGER NOT NULL DEFAULT 0,
    error_code VARCHAR(100),
    error_category VARCHAR(100),
    claim_token VARCHAR(36),
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_external_ingestion_identity UNIQUE
        (external_job_id, export_run_id, dataset_sha256)
);
CREATE INDEX IF NOT EXISTS ix_external_ingestion_operations_state
    ON external_ingestion_operations (state);
CREATE INDEX IF NOT EXISTS ix_external_ingestion_operations_stage
    ON external_ingestion_operations (stage);
CREATE INDEX IF NOT EXISTS ix_external_ingestion_operations_lease
    ON external_ingestion_operations (lease_expires_at);
CREATE INDEX IF NOT EXISTS ix_external_ingestion_operations_updated
    ON external_ingestion_operations (updated_at);
CREATE INDEX IF NOT EXISTS ix_external_ingestion_operations_priority
    ON external_ingestion_operations (priority, created_at);
