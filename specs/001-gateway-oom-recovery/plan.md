# Implementation Plan: Scheduled External Collection and Gateway OOM Recovery

**Branch**: `codex/actit-final-production` | **Date**: 2026-09-21 | **Specification**: [spec.md](./spec.md)  
**Input**: Existing ACTIT brownfield production system and `specs/001-gateway-oom-recovery/spec.md`

## Summary

Diagnose the failed scheduled External collection/publish lifecycle, identify the verified failure boundary, and apply the smallest data-preserving correction. The work begins with read-only incident verification, uses one bounded representative workload in an isolated Compose project, and measures Gateway merge memory and host coexistence before selecting either a minimal correction or an evidence-justified resource adjustment. No production-affecting action occurs before an explicit approval gate. After approval, exactly one real workflow is monitored through collection, durable export/state, Gateway publish/processing, and successful downstream completion before readiness is decided and `IMPLEMENTATION_STATUS.md` is updated.

The current architecture remains unchanged: the existing External Sources pipeline produces versioned JSON handoffs; the existing Gateway validates and atomically merges the feed into its persistent volume; the existing authenticated downstream pull/process path writes to authoritative PostgreSQL. MISP remains a selective analyst-controlled destination and is outside this recovery flow.

## Technical Context

**Language/Version**: Python 3.11+ repository baseline; current Gateway image uses Python 3.12; Bash and YAML for VPS operations  
**Primary Dependencies**: Existing FastAPI/Starlette/Uvicorn Gateway stack, External Sources services, Docker Engine/Compose, systemd, curl, standard-library `unittest`; no new framework or runtime dependency planned  
**Storage**: PostgreSQL remains authoritative; Gateway snapshot in the existing `gateway_data` volume; External state/exports in existing External volumes; no schema migration  
**Testing**: Existing `unittest` suites, FastAPI/TestClient Gateway tests, Compose topology/rendering tests, and a new disposable Gateway-only Compose validation harness using bounded generated fixtures  
**Target Platform**: Existing Ubuntu VPS with Docker/Compose and systemd; isolated validation runs on the VPS without attaching to production networks, volumes, secrets, or paths  
**Project Type**: Existing multi-service web platform  
**Performance Goals**: The representative candidate publish and merge, plus its identical repeat, complete within existing client/server timeouts and preserve contract semantics; no OOM kill, unexpected restart, unsafe host pressure, or resource starvation of co-resident ACTIT services  
**Constraints**: VPS-only production; Docker/Compose runtime; diagnose before modifying; one bounded isolated baseline and candidate sequence; no heavy repeated reproduction; no destructive state actions; no production changes without approval; no invented fixed safety percentage  
**Scale/Scope**: Existing Gateway contract bounds of 20 MiB per request, 100 MiB cumulative stored feed, and 20,000 items; the bounded fixture will reproduce the relevant merge shape without production records or sensitive data

## Constitution Check

### Pre-design gate

| Principle | Plan compliance |
|---|---|
| Preserve architecture and ownership | Reuses External Sources, Gateway, systemd publisher, downstream pull, PostgreSQL, and current contracts. No replacement service, queue, datastore, or framework. |
| VPS-only Compose production | Production remains VPS Docker/Compose; isolated validation uses a separately named Compose project only. |
| Preserve data and automation | PostgreSQL, MISP, Docker volumes, Gateway/External state, Tailscale, and systemd are never deleted, reset, recreated, restored, or overwritten. |
| Diagnose first | Candidate selection follows verified lifecycle boundary and measured memory/host evidence. |
| Complete lifecycle readiness | Health checks are supporting evidence only; readiness requires the approved real lifecycle through downstream completion. |
| Bound risky execution | Existing evidence is reused; one bounded isolated baseline/candidate sequence is preferred; production receives exactly one monitored workflow after approval. |
| Production approval boundary | `/opt/cti-platform` and live services remain read-only until explicit approval identifies the exact action and candidate. |
| Security and secrets | Existing authentication, HMAC, loopback/Tailscale, rate limits, validation, logging, and secret isolation are preserved; evidence is sanitized. |
| Evidence-based completion | Each phase has required artifacts and stop conditions; unverified outcomes remain explicitly unverified. |
| Durable operational record | `IMPLEMENTATION_STATUS.md` is updated only after a meaningful verified checkpoint. |

**Gate result**: PASS. No constitution violation or complexity exception is required.

### Post-design gate

The research, data model, compatibility contract, evidence contract, and validation guide preserve the same service boundaries and introduce no new production component. Planned test-only files are disposable, isolated, and do not contain production data or secrets. Candidate production edits remain conditional on evidence and approval. **Gate result: PASS.**

## Existing Components and Planned File Scope

### Existing implementation to inspect and reuse

```text
backend/app/pipeline/ingestion/external/application/
├── collection_service.py                       # unified collection/export lifecycle
└── job_service.py                              # in-memory job execution/state
backend/app/pipeline/ingestion/external/export/final_dataset.py
backend/app/pipeline/ingestion/external/integration/api.py
backend/app/api/v1/router.py                     # authenticated downstream pull
backend/app/services/pipeline_service.py         # ETag/checkpoint processing
infra/vps/compose.yaml                           # current service/resource topology
infra/vps/gateway/app.py                         # current publish/read/merge implementation
infra/vps/scripts/run_external_collection.sh     # scheduled lifecycle orchestration
infra/vps/systemd/cti-external-collection.service
infra/vps/systemd/cti-external-collection.timer
tests/                                           # Gateway, External, topology, deployment tests
docs/api/external_feed_contract.md
docs/operations/                                 # VPS and External operations
```

### Planned implementation/validation files

```text
compose.gateway-recovery-test.yml                # disposable Gateway-only isolation harness
scripts/generate_gateway_recovery_fixture.py     # deterministic bounded synthetic export
scripts/run_gateway_recovery_validation.sh       # bounded baseline/candidate evidence capture
tests/test_gateway_recovery_compose.py            # isolation and safety assertions

specs/001-gateway-oom-recovery/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── gateway-publish-compatibility.md
│   └── recovery-evidence-contract.md
└── evidence/                                     # sanitized small summaries only
```

Conditional implementation edits are limited to the already-owned path proven responsible: `infra/vps/gateway/app.py` for a minimal merge-memory correction, `infra/vps/compose.yaml` for an evidence-justified Gateway resource adjustment, or `infra/vps/scripts/run_external_collection.sh` for a proven export/run-correlation defect. Associated existing tests and operations documentation may be updated. The plan does not authorize all three changes, shared-module changes, schedule changes, or production edits.

## Implementation Strategy

### Candidate decision ladder

1. Classify the last failed run, including whether `ExecMainStatus=1` is the current event while the continuation record describes an earlier exit 52/OOM event.
2. Correlate job run ID, export manifest/dataset identity, Gateway pre/post snapshot identity, publisher response or lost ACK, container OOM/restart evidence, and downstream result.
3. Measure the current Gateway with a bounded synthetic fixture in isolation. Do not use production data or rerun the live collector.
4. If measurement verifies avoidable simultaneous full-payload representations in the existing merge path, prefer the smallest compatible code correction and regression coverage.
5. If residual peak is legitimate, consider a resource adjustment only from measured baseline/candidate peaks, host pressure, total VPS capacity, and safe coexistence. Derive the safety margin from evidence or an existing policy; do not invent a percentage.
6. If evidence proves a partial job with failed export can publish a stale prior “latest” artifact, add only the smallest run/export-correlation guard in the existing publisher path. Do not alter timer cadence or duplicate orchestration.
7. Preserve publish/read APIs, atomic snapshot semantics, ETag/idempotency, authenticated paths, and the existing volume. Add no streaming service, queue, replacement Gateway, or alternate datastore.

## Phased Plan

### Phase 1 — Read-only incident verification

**Existing files/components involved**: `IMPLEMENTATION_STATUS.md`; live collection service/timer metadata; root-only service journal; kernel journal; current External/Gateway container metadata; `run_external_collection.sh`; live Compose metadata.

**Read-only versus writable**: Repository and `/opt/cti-platform` are read-only. Live systemd, Docker, kernel, Gateway, External state, and exports are inspected only. A sanitized evidence summary may be written under the feature directory; raw journals and secrets are not committed.

**Data-preservation boundaries**: No start/restart, timer trigger, HTTP mutation, state-writing exec, Compose action, volume mount, state-file touch, or mutating database query. Do not print environments, credentials, tokens, request bodies, records, or sensitive paths.

**Validation evidence**:

- Service `Result`, `ExecMainCode`, `ExecMainStatus`, timestamps, timer metadata, and safely observable failing stage.
- Sanitized journal sequence for health, collection, export retrieval, Gateway publish, and ACK parsing.
- Kernel/cgroup OOM evidence, Gateway OOM/restart metadata, effective memory limit, and host pressure near the event.
- Identities/counts/hashes sufficient to correlate job export and Gateway snapshot without copying records.
- An explicit discrepancy note if live evidence differs from `IMPLEMENTATION_STATUS.md`, especially status 1 versus the documented historical curl status 52.

**Failure/stop conditions**: Stop if inspection would expose secrets, require a write, lacks authorization, or cannot correlate timestamps safely. Mark unavailable evidence unavailable; do not infer success or trigger another run.

**Production impact**: None beyond bounded read-only metadata/journal access.

**Rollback considerations**: None; no production mutation occurs.

### Phase 2 — Evidence-backed failure-boundary/root-cause analysis

**Existing files/components involved**: External collection service, exporter/latest reader, manifest/schema, publisher script, Gateway publish/merge/atomic write, downstream pull/checkpoint service, API contract, and Phase 1 evidence.

**Read-only versus writable**: Existing code/state stay read-only. Write only a sanitized lifecycle matrix and root-cause decision record.

**Data-preservation boundaries**: Do not replay requests or alter state. Treat the last durable export and Gateway snapshot as protected evidence. PostgreSQL and MISP receive no speculative mutation.

**Validation evidence**: Classify every checkpoint as verified success, verified failure, or unverified:

`scheduled start → collection state → export status/identity → latest selection → Gateway receive/validate → merge → atomic replace → ACK → downstream pull/process/checkpoint`.

Distinguish collection-state failure, export failure, stale-latest selection, transport failure, merge failure, lost ACK after persistence, cgroup exhaustion, and downstream failure. Root cause requires corroborating evidence; timing alone is insufficient.

**Failure/stop conditions**: Stop candidate selection if export-to-run correlation or pre/post Gateway identity is ambiguous. Do not retry until lost-ACK versus pre-write failure is resolved enough to preserve idempotency.

**Production impact**: None.

**Rollback considerations**: None.

### Phase 3 — Isolated bounded large-export reproduction

**Existing files/components involved**: Gateway image/app, existing Compose test conventions, publish contract/tests, and External schema fixtures.

**Read-only versus writable**: Production remains read-only. Writable scope is the test-only Compose file, deterministic fixture generator, validation runner, test code, and a disposable project-scoped volume/network.

**Data-preservation boundaries**: Use a unique project name, synthetic credentials/items, loopback-only exposure, no production networks/volumes, no `/opt/cti-platform` bind, and no provider egress. Large fixtures and runtime volumes are disposable and uncommitted.

**Validation evidence**: Rendered topology; fixture seed/profile, byte size, item count, and hash; initial snapshot profile; one bounded publish result; response outcome; snapshot hash/count/ETag; container state, restart count, and cgroup events.

**Failure/stop conditions**: Abort if any production path/network/volume/secret is referenced. Stop after the first representative attempt if it reproduces OOM or unsafe pressure; do not loop or increase load. If unsafe to represent, record the limitation and use existing evidence plus lower-bound profiling.

**Production impact**: None. Isolated host resource use is time-bounded and monitored.

**Rollback considerations**: Stop the uniquely named test project and remove only its verified disposable resources and fixtures. Never prune broadly.

### Phase 4 — Baseline memory/publish/merge measurements

**Existing files/components involved**: Isolated harness, unmodified Gateway, cgroup/host metrics, Gateway API and snapshot.

**Read-only versus writable**: Baseline code is read-only. The disposable test snapshot and sanitized measurement summary are writable.

**Data-preservation boundaries**: Only synthetic test state changes. Do not profile production or export production payloads.

**Validation evidence**:

- Idle/current and peak memory, cgroup limit/events, OOM/restart, request and snapshot sizes, item counts, duration, status/ACK, ETag, and pre/post hashes.
- Host total/available memory, swap activity, pressure indicators, and read-only health/resource observations for co-resident services.
- One identical repeat only if the first publish completed safely, to verify unchanged/idempotent behavior; never repeat a failure.

**Failure/stop conditions**: Stop on OOM, restart, sustained unsafe pressure, co-resident degradation, timeout, corrupt/truncated snapshot, or data loss. Do not rerun the failing baseline.

**Production impact**: No production writes; bounded contention is controlled by preflight capacity checks and evidence/policy-derived stop thresholds.

**Rollback considerations**: Dispose only the isolated project after evidence is summarized.

### Phase 5 — Minimal candidate correction or evidence-justified resource adjustment

**Existing files/components involved**: The single verified fault-owning component and its tests/configuration: likely Gateway merge, Gateway `mem_limit`, or scheduler export/run validation.

**Read-only versus writable**: Production remains read-only. Repository changes are limited to one justified candidate and tests/docs. Shared modules require separate reporting and approval.

**Data-preservation boundaries**: Preserve Gateway schema/volume, External state/exports, PostgreSQL, MISP, and API contracts. No destructive migration, alternate store, queue, duplicated service, or broad dependency.

**Validation evidence**: A decision record links candidate to verified cause and compares no-change/rejected alternatives. A resource adjustment records measured peaks, host pressure, total capacity, co-resident demand, and evidence/policy-derived safety margin.

**Failure/stop conditions**: Stop if cause is ambiguous, ownership approval is missing, persistence/API semantics change, destructive migration is needed, or coexistence is unsafe. Never raise a limit without capacity evidence.

**Production impact**: None during implementation. Exact expected service/config impact is documented for approval.

**Rollback considerations**: Define a targeted reversal preserving `gateway_data` and External state. Verify snapshot compatibility and the risk of reintroducing prior merge/compaction behavior before proposing an image rollback. Never auto-rollback.

### Phase 6 — Isolated candidate validation and regression testing

**Existing files/components involved**: Candidate, isolated harness, Gateway tests, External export/job tests, downstream idempotency tests, topology and deployment-safety tests.

**Read-only versus writable**: Production is read-only. Only repository test artifacts and disposable isolated state are writable.

**Data-preservation boundaries**: Synthetic data only. Cleanup targets the exact isolated project; no production secret, network, volume, state, dataset, or provider connection.

**Validation evidence**:

- Focused tests for the changed path and existing auth/HMAC, validation, bounds, cumulative merge, response, ETag, idempotency, and atomic preservation.
- Export/job correlation tests if that path changes; downstream unchanged/retry tests.
- Topology/deployment safety tests.
- One bounded candidate run using the baseline fixture, followed by one identical safe repeat for idempotency.
- Candidate peak, host pressure/capacity, co-resident observations, completion/ACK, counts/hashes/ETag, and OOM/restart events.

Success requires completion without OOM, unexpected restart, unsafe host pressure, or co-resident starvation. Safety margin comes from evidence or existing ACTIT policy.

**Failure/stop conditions**: Any regression, integrity mismatch, OOM/restart, unsafe pressure/starvation, security weakening, or missing evidence-based margin blocks production approval. Do not tune through repeated heavy runs.

**Production impact**: None.

**Rollback considerations**: Revert only the rejected repository candidate; retain sanitized evidence and do not touch live state.

### Phase 7 — Explicit user approval gate

**Existing files/components involved**: Root-cause record, candidate diff/config, isolated evidence, capacity analysis, production action outline, and rollback compatibility assessment.

**Read-only versus writable**: No production write is allowed. The approval package may be written to feature evidence.

**Data-preservation boundaries**: Approval names exact files/image/config/service and confirms preservation of volumes, state, PostgreSQL, MISP, Tailscale, and systemd schedule. Approval for one action does not authorize broader deployment or rollback.

**Validation evidence**: Present verified cause, candidate rationale, tests, measurements, coexistence, unresolved risks, expected impact, monitoring window, stop conditions, and rollback limitations.

**Failure/stop conditions**: Missing/ambiguous approval, stale evidence, changed candidate, or inadequate compatibility keeps NO-GO. Renew approval if scope changes.

**Production impact**: None until approval.

**Rollback considerations**: Include a separately controlled non-destructive rollback proposal; executing it also needs explicit approval.

### Phase 8 — Exactly one monitored real workflow after approval

**Existing files/components involved**: Approved targeted activation, current Compose service, unchanged systemd service/timer, External state/export, Gateway volume/API, verified existing downstream automation/path, PostgreSQL, journals and resource metrics.

**Read-only versus writable**: Only the approved targeted action and normal writes of exactly one lifecycle are writable. Everything else remains read-only. `/opt/cti-platform` changes stay within approved scope.

**Data-preservation boundaries**: No Compose down, volume recreation/removal, database restore/reset, state overwrite, broad deployment, timer redesign, Tailscale change, or MISP sharing. Do not manually start a duplicate if the chosen timer occurrence is the approved run.

**Validation evidence**:

- Unique service invocation/job/export identity proving only one collection/publish lifecycle.
- Collection, durable export/state, export-to-run correlation, Gateway receive/merge/atomic persistence/ACK, OOM/restart/cgroup/host pressure, and co-resident safety.
- Exactly one associated downstream pull/process/checkpoint when live automation is verified. If none exists, a separately approved single existing authenticated pull may complete the workflow without another collection.
- Safe PostgreSQL checkpoint/count verification; confirmation that MISP received no automatic sharing.

**Failure/stop conditions**: On failure, unsafe pressure, OOM/restart, ACK ambiguity, integrity concern, or co-resident degradation, stop and preserve evidence. Do not rerun, auto-rollback, or trigger a second collection.

**Production impact**: One approved targeted candidate activation may restart only the affected Gateway if required, followed by one normal workflow. Normal writes are External state/export, Gateway snapshot, and downstream PostgreSQL processing.

**Rollback considerations**: No automatic rollback. Inspect snapshot compatibility, preserve state/volumes, present exact rollback impact, and obtain explicit approval.

### Phase 9 — Readiness decision and `IMPLEMENTATION_STATUS.md` update

**Existing files/components involved**: Lifecycle evidence, readiness docs/criteria, specification success criteria, and `IMPLEMENTATION_STATUS.md`.

**Read-only versus writable**: Production returns to read-only verification. Repository writes are limited to sanitized evidence, relevant durable operations docs if behavior changed, and status update after a verified checkpoint.

**Data-preservation boundaries**: No further live run fills evidence gaps. Missing evidence is unverified. Never commit sensitive identifiers, credentials, row data, container IDs, or temporary facts.

**Validation evidence**: GO requires the single workflow to prove collection, durable export/state, Gateway publish/process/ACK, downstream completion, no OOM/restart/unsafe pressure/starvation, preserved security/contracts/data, and expected scheduling. Otherwise record NO-GO or partial verification with the exact boundary.

**Failure/stop conditions**: Health-only, isolated-only, publish-without-downstream, or inferred results cannot produce GO.

**Production impact**: None.

**Rollback considerations**: Record the approved candidate, compatibility constraints, evidence, and any separately approved rollback path; do not execute rollback.

## Validation Matrix

| Concern | Required evidence | Existing coverage | Planned addition |
|---|---|---|---|
| Export durability/identity | Schema, SHA-256, counts, manifest-last, run correlation | External dataset/job integration tests | Correlation regression only if deficient |
| Gateway contract | Auth/HMAC, validation, bounds, response, ETag | `tests/test_vps_gateway.py` | Candidate-specific regression |
| Merge persistence | Counts, hashes, atomic old-or-new state | Gateway cumulative/bound tests | Failure/lost-ACK cases where feasible |
| Memory safety | Current/peak, cgroup events, pressure, coexistence | Live incident evidence | Disposable bounded Compose harness |
| Downstream idempotency | Checkpoint/ETag, unchanged repeat | `tests/test_backend_enhancements.py` | Workflow evidence correlation |
| Data/deployment safety | No destructive action; automation preserved | VPS topology/deployment tests | Isolation guard assertions |
| End-to-end readiness | One correlated approved lifecycle | Operations readiness criteria | Sanitized monitored-workflow record |

## Complexity Tracking

No constitution exception is planned. A test-only Compose harness is necessary because unit tests cannot enforce cgroup limits or observe container OOM/restart behavior; it is not a production service and is isolated and disposable.

## Deliverables

- Sanitized incident timeline and lifecycle boundary decision.
- Deterministic bounded isolation harness and measurements.
- One minimal evidence-backed candidate, or a documented no-change/NO-GO decision.
- Explicit approval package before production impact.
- Evidence for exactly one approved real workflow.
- Evidence-based readiness decision and durable `IMPLEMENTATION_STATUS.md` update.

This plan itself performs none of the implementation, testing, deployment, restart, collection, rollback, or production actions described above.
