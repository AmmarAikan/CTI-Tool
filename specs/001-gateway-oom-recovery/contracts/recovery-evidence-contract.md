# Contract: Recovery Evidence and Approval Record

## Purpose

This contract defines the minimum sanitized evidence needed to advance through diagnosis, isolated validation, approval, one monitored production workflow, and readiness. It is a documentation/evidence contract, not a new production API or datastore.

## General rules

Every assertion MUST be one of:

- `verified-success`;
- `verified-failure`;
- `unverified`;
- `not-applicable`.

Evidence MUST distinguish observation from inference. Missing evidence is `unverified`, never successful.

All timestamps use UTC ISO-8601 ending in `Z`. Persistent identities use SHA-256 over canonical content where the existing system supports it.

Evidence MUST NOT contain:

- credentials, passwords, tokens, API keys, environment secrets, HMAC material;
- production feed records, sensitive source text/metadata, private onion lists, or browser state;
- raw environment dumps;
- live database rows;
- large generated datasets;
- container IDs or other transient identifiers not needed for a durable conclusion.

## Incident record

Minimum fields:

```yaml
incident:
  observed_window_utc: "<bounded window>"
  service_result: "<systemd result>"
  exec_main_code: "<value or unverified>"
  exec_main_status: "<value or unverified>"
  last_verified_stage: "<lifecycle stage>"
  gateway_oom: "<verified | not-observed | unavailable>"
  gateway_restart_delta: "<integer or unavailable>"
  documentation_discrepancy: "<sanitized text or none>"
  evidence_sources:
    - "<journal/metadata category and window>"
```

A documentation discrepancy MUST be recorded when live evidence differs from `IMPLEMENTATION_STATUS.md`.

## Lifecycle matrix

The record MUST include each stage:

```yaml
lifecycle:
  scheduled_start: "<status>"
  collection_terminal_state: "<status>"
  current_export_durable: "<status>"
  selected_export_matches_run: "<status>"
  gateway_received_and_validated: "<status>"
  gateway_merge_completed: "<status>"
  gateway_snapshot_persisted: "<status>"
  gateway_ack_received: "<status>"
  downstream_pull_completed: "<status>"
  downstream_processing_completed: "<status>"
  downstream_checkpoint_persisted: "<status>"
```

Each stage includes a safe evidence reference and optional failure class. The boundary decision MUST explicitly consider collection, export, stale-latest selection, transport, merge, lost ACK, resource exhaustion, and downstream failure.

## Fixture record

```yaml
fixture:
  profile_version: "<version>"
  deterministic_seed: "<non-secret>"
  initial_snapshot_bytes: 0
  initial_snapshot_items: 0
  incoming_bytes: 0
  incoming_items: 0
  expected_merged_bytes: 0
  expected_merged_items: 0
  overlap_items: 0
  fixture_sha256: "<sha256>"
  contains_production_data: false
  uses_production_network_or_volume: false
  external_egress: false
```

The fixture MUST remain inside existing Gateway request/cumulative/item bounds and MUST be disposed rather than committed if large.

## Resource measurement record

Baseline and candidate records use the same fixture profile:

```yaml
measurement:
  variant: "<baseline | candidate>"
  gateway_effective_limit_bytes: 0
  gateway_idle_bytes: "<value or unavailable>"
  gateway_peak_bytes: "<value or unavailable>"
  gateway_oom_event_delta: 0
  gateway_restart_delta: 0
  publish_duration_ms: "<value or unavailable>"
  response_status: "<value or unavailable>"
  snapshot_integrity: "<old-preserved | new-valid | ambiguous | failed>"
  host_total_bytes: "<value>"
  host_available_min_bytes: "<value or unavailable>"
  swap_activity: "<sanitized summary>"
  memory_pressure: "<sanitized summary>"
  co_resident_services: "<safe | degraded | unverified>"
  safety_policy_reference: "<existing policy or none>"
  derived_margin_rationale: "<measured evidence>"
  outcome: "<pass | fail | stopped | unverified>"
```

No fixed headroom percentage may be inserted. A candidate passes only when the representative workload completes without OOM, unexpected restart, unsafe host pressure, or resource starvation of co-resident services.

## Candidate decision record

```yaml
candidate:
  verified_root_cause: "<evidence reference>"
  kind: "<no-change | gateway-code | gateway-resource | scheduler-guard | combined-approved>"
  affected_components:
    - "<existing component>"
  data_preservation_boundaries:
    - "<protected state>"
  public_contract_change: false
  new_runtime_dependency: false
  expected_production_impact: "<exact scope>"
  rollback_constraints:
    - "<compatibility/approval constraint>"
  rejected_alternatives:
    - option: "<alternative>"
      reason: "<evidence-backed reason>"
```

A combined candidate requires independent evidence for every included change and explicit approval of the expanded scope.

## Approval gate record

```yaml
approval:
  candidate_digest: "<sha256>"
  status: "<pending | approved | rejected | expired>"
  exact_scope:
    - "<file/image/config/service/action>"
  workflow_allowance: 1
  monitoring_window: "<bounded window>"
  stop_conditions:
    - "<condition>"
  data_preservation_confirmed: true
  rollback_separately_approved: false
```

Approval is invalid if the candidate digest or exact scope changes. Approval to activate the candidate is not approval to roll back.

## Monitored workflow record

```yaml
production_workflow:
  approval_reference: "<approval record>"
  trigger: "<scheduled-timer | explicitly-approved-manual>"
  collection_invocation_count: 1
  current_export_matches_run: "<status>"
  gateway_publish_and_ack: "<status>"
  downstream_process_count: 1
  complete_lifecycle: "<status>"
  oom_event_delta: 0
  gateway_restart_delta: 0
  host_pressure: "<safe | unsafe | unverified>"
  co_resident_services: "<safe | degraded | unverified>"
  misp_automatic_share_count: 0
  rerun_performed: false
  automatic_rollback_performed: false
  outcome: "<complete | failed | stopped | unverified>"
```

A manual workflow MUST NOT be added if a timer occurrence is already the selected approved workflow. Downstream completion may use one associated existing automation run or one separately approved existing authenticated pull, never a second collection.

## Readiness record

```yaml
readiness:
  decision: "<GO | NO-GO | PARTIALLY-VERIFIED>"
  complete_lifecycle_verified: false
  resource_safety_verified: false
  co_resident_safety_verified: false
  data_and_contract_preservation_verified: false
  failed_or_unverified_boundaries:
    - "<boundary>"
  implementation_status_updated: false
  next_safe_action: "<action requiring no inferred success>"
```

`GO` is valid only when all four verification booleans are true and the approved production workflow outcome is `complete`. A healthy endpoint, isolated candidate success, publish without downstream completion, or missing resource evidence cannot yield `GO`.

