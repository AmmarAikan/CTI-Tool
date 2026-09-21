# Data Model: Gateway OOM Recovery Evidence

## Purpose

This feature adds no production database schema and no new authoritative datastore. This model defines the evidence records needed to diagnose, validate, approve, and decide readiness safely. Small sanitized summaries may be stored in the feature evidence directory; raw logs, production payloads, secrets, and large fixtures remain uncommitted.

## Entity: IncidentEvidenceTimeline

Represents one observed scheduled-service invocation.

| Field | Type | Rules |
|---|---|---|
| `incident_key` | string | Sanitized local key; not a container ID or secret |
| `started_at` / `ended_at` | UTC timestamp or null | ISO-8601 ending in `Z` |
| `service_result` | enum | `success`, `exit-code`, `timeout`, `oom`, `unknown` |
| `exec_main_code` / `exec_main_status` | string/int or null | Read-only systemd evidence |
| `observed_stage` | enum | Lifecycle checkpoint where evidence stops/fails |
| `gateway_oom_evidence` | enum | `verified`, `not-observed`, `unavailable` |
| `gateway_restart_delta` | integer or null | Non-negative; bounded observation window |
| `documentation_discrepancy` | string or null | Sanitized statement, never silently resolved |
| `sources` | list | Journal/metadata categories and time windows, not secret content |

**Validation**: A failed unit may have an unknown failure stage. OOM is `verified` only with corroborating kernel/cgroup/container evidence.

## Entity: LifecycleCheckpoint

Represents one boundary in one workflow.

| Field | Type | Rules |
|---|---|---|
| `workflow_key` | string | Correlates sanitized records |
| `stage` | enum | `scheduled`, `collection`, `export`, `selection`, `gateway_receive`, `gateway_merge`, `gateway_persist`, `gateway_ack`, `downstream_pull`, `downstream_process`, `downstream_checkpoint` |
| `status` | enum | `verified-success`, `verified-failure`, `unverified`, `not-applicable` |
| `observed_at` | UTC timestamp or null | ISO-8601 `Z` |
| `safe_identity` | string or null | Hash/run correlation that contains no record data |
| `evidence_summary` | string | Concise and sanitized |
| `source_reference` | string | Evidence file/command category, not credentials |
| `failure_class` | enum or null | Collection, export, stale selection, transport, merge, lost ACK, resource, downstream, other |

**Transition rule**: A later verified success does not retroactively prove an earlier unobserved checkpoint. Readiness requires every required stage to be verified.

## Entity: ValidatedExportIdentity

Describes an External handoff without embedding its records.

| Field | Type | Rules |
|---|---|---|
| `workflow_key` | string | Links to lifecycle |
| `collection_run_key` | string or null | Sanitized run correlation |
| `export_status` | enum | `succeeded`, `failed`, `unverified` |
| `schema_version` | string or null | Existing contract version |
| `dataset_sha256` | SHA-256 or null | Canonical export digest |
| `manifest_sha256` | SHA-256 or null | If exposed by existing metadata |
| `byte_count` | integer or null | Non-negative |
| `item_count` | integer or null | Non-negative |
| `is_selected_latest` | boolean or null | Read-only selection observation |
| `correlation_status` | enum | `current-run`, `prior-run`, `ambiguous`, `unverified` |

**Invariant**: A `partial` collection is not sufficient evidence of current export success. A selected latest export must correlate to the current run before publish readiness is inferred.

## Entity: GatewaySnapshotIdentity

Describes Gateway persistent state before or after a publish.

| Field | Type | Rules |
|---|---|---|
| `observation` | enum | `before`, `after`, `retry-after` |
| `snapshot_sha256` | SHA-256 or null | Hash of canonical stored artifact |
| `etag` | string or null | Existing API ETag |
| `byte_count` | integer or null | Non-negative |
| `item_count` | integer or null | Non-negative |
| `inserted` / `updated` / `unchanged` | integer or null | From successful ACK only |
| `persistence_state` | enum | `old-preserved`, `new-persisted`, `ambiguous`, `unverified` |
| `ack_state` | enum | `accepted`, `lost-or-empty`, `rejected`, `unverified` |

**Invariants**:

- A failed request must not leave a truncated/intermediate snapshot.
- A lost ACK may coexist with `new-persisted`; identity inspection precedes retry.
- An identical successful retry must not duplicate items and should produce unchanged/idempotent results.

## Entity: FixtureProfile

Defines a deterministic non-sensitive isolated workload.

| Field | Type | Rules |
|---|---|---|
| `profile_version` | string | Versioned test profile |
| `seed` | string/int | Fixed and non-secret |
| `initial_snapshot_bytes/items` | integer | Within existing Gateway bounds |
| `incoming_bytes/items` | integer | Request stays within existing bound |
| `expected_merged_bytes/items` | integer | Cumulative result stays within bounds |
| `overlap_count` | integer | Exercises updates/unchanged paths |
| `fixture_sha256` | SHA-256 | Reproducibility |
| `contains_production_data` | boolean | Must be false |
| `external_egress_required` | boolean | Must be false |

**Invariant**: The profile is representative of the merge shape, not a copy of live records.

## Entity: ResourceMeasurementSet

Captures one bounded baseline or candidate window.

| Field | Type | Rules |
|---|---|---|
| `measurement_key` | string | Unique sanitized key |
| `variant` | enum | `baseline`, `candidate` |
| `fixture_profile_version` | string | Must match for comparisons |
| `gateway_limit_bytes` | integer | Effective cgroup limit |
| `gateway_idle_bytes` / `peak_bytes` | integer or null | Measured, not inferred |
| `oom_event_delta` | integer | Must be zero for success |
| `restart_delta` | integer | Must be zero for success |
| `duration_ms` | integer or null | Non-negative |
| `host_total_bytes` / `host_available_min_bytes` | integer or null | Same bounded window |
| `swap_activity` | summary | Sanitized measured delta |
| `memory_pressure` | summary | PSI or platform-equivalent |
| `co_resident_observations` | list | Health/resource signals, no payloads |
| `safety_policy_reference` | string or null | Existing ACTIT policy if used |
| `derived_margin_rationale` | string | Evidence-based; no invented fixed percentage |
| `outcome` | enum | `pass`, `fail`, `stopped`, `unverified` |

**Success rule**: Candidate outcome is `pass` only if the representative workload completes with zero OOM events/restarts, no unsafe host pressure, and no starvation/degradation of co-resident services.

## Entity: CandidateDecision

| Field | Type | Rules |
|---|---|---|
| `root_cause` | string | Verified evidence reference |
| `candidate_kind` | enum | `no-change`, `gateway-code`, `gateway-resource`, `scheduler-guard`, `combined-approved` |
| `affected_components` | list | Existing components only |
| `data_boundaries` | list | Must preserve protected state |
| `contract_impact` | string | Expected `none`; otherwise blocks |
| `dependency_impact` | string | Expected `none` |
| `rejected_alternatives` | list | Reasoned from evidence |
| `validation_evidence` | list | Tests and measurements |
| `production_impact` | string | Exact targeted impact |
| `rollback_constraints` | list | State compatibility and approval |

## Entity: ApprovalGate

| Field | Type | Rules |
|---|---|---|
| `candidate_digest` | SHA-256 | Identifies exact candidate/config |
| `approval_status` | enum | `not-requested`, `pending`, `approved`, `rejected`, `expired` |
| `approved_scope` | list | Exact service/files/actions |
| `approved_at` | UTC timestamp or null | Required for approved |
| `workflow_allowance` | integer | Must equal 1 |
| `monitoring_window` | string | Bounded |
| `stop_conditions` | list | Required |
| `rollback_approved` | boolean | False unless separately explicit |

**Invariant**: Candidate digest or scope change invalidates approval.

## Entity: MonitoredWorkflow

| Field | Type | Rules |
|---|---|---|
| `workflow_key` | string | One approved production lifecycle |
| `trigger_kind` | enum | `scheduled-timer` or `explicitly-approved-manual` |
| `collection_invocation_count` | integer | Must equal 1 |
| `downstream_process_count` | integer | Must equal 1 for readiness |
| `checkpoints` | references | LifecycleCheckpoint records |
| `resource_observation` | reference | Production bounded metrics |
| `rerun_performed` | boolean | Must be false |
| `automatic_rollback_performed` | boolean | Must be false |
| `outcome` | enum | `complete`, `failed`, `stopped`, `unverified` |

## Entity: ReadinessDecision

| Field | Type | Rules |
|---|---|---|
| `decision` | enum | `GO`, `NO-GO`, `PARTIALLY-VERIFIED` |
| `workflow_key` | string | Approved monitored workflow |
| `verified_criteria` | list | Spec success criteria with evidence |
| `failed_criteria` | list | Exact boundary |
| `unverified_criteria` | list | Never inferred |
| `status_update_required` | boolean | True after meaningful checkpoint |
| `next_safe_action` | string | Must respect approval/data boundaries |

**GO invariant**: Collection, durable export/state, Gateway publish/persist/ACK, downstream completion, resource safety, co-resident safety, and preserved security/data controls are all verified.

## Relationships

```text
IncidentEvidenceTimeline
  └── LifecycleCheckpoint[*]
        ├── ValidatedExportIdentity
        └── GatewaySnapshotIdentity[*]

FixtureProfile
  └── ResourceMeasurementSet (baseline)
  └── ResourceMeasurementSet (candidate)
        └── CandidateDecision
              └── ApprovalGate
                    └── MonitoredWorkflow
                          └── LifecycleCheckpoint[*]
                          └── ReadinessDecision
```

## State transitions

```text
UNVERIFIED
  → INCIDENT_VERIFIED
  → FAILURE_BOUNDARY_CLASSIFIED
  → BASELINE_MEASURED
  → CANDIDATE_SELECTED
  → CANDIDATE_VALIDATED
  → APPROVAL_PENDING
  → APPROVED
  → ONE_WORKFLOW_MONITORED
  → GO | NO-GO | PARTIALLY_VERIFIED
```

Any missing evidence stops forward transition. Failure during the approved workflow transitions to `NO-GO` or `PARTIALLY_VERIFIED`; it never loops automatically to another workflow.

