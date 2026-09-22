# Tasks: Scheduled External Collection and Gateway OOM Recovery

**Branch**: `codex/actit-final-production`  
**Feature directory**: `specs/001-gateway-oom-recovery`  
**Input**: [spec.md](./spec.md), [plan.md](./plan.md), [research.md](./research.md), [data-model.md](./data-model.md), [quickstart.md](./quickstart.md), [contracts/](./contracts/), `.specify/memory/constitution.md`, and `IMPLEMENTATION_STATUS.md`

**Safety rule**: This is an execution checklist, not authority for production change. Tasks marked **BLOCKED** require the explicit approval described in Phase 7. No task authorizes automatic production deployment, restart, rollback, collection trigger, publisher invocation, Docker/Compose production action, or write under `/opt/cti-platform`.

## Format: `[ID] [P?] [Story?] Description`

- `[P]` means different files/evidence sources can be handled in parallel after their prerequisite.
- `[US1]` through `[US4]` map to the approved specification’s user stories.
- Every production observation is sanitized: never record secrets, request bodies, source records, environment dumps, or transient identifiers unnecessarily.

## Phase 1 — Read-only incident verification (US1, P1)

**Goal**: Produce a time-bounded, sanitized account of the latest failed scheduled workflow without mutating production.

**Independent test**: The incident evidence identifies the last verified success, first verified failure, and each unverified boundary using only existing read-only evidence.

- [X] T001 [US1] Create `specs/001-gateway-oom-recovery/evidence/incident-timeline.md` from read-only `cti-external-collection.service` and timer metadata; record result, `ExecMainCode`, `ExecMainStatus`, UTC window, and safe failing-stage evidence; STOP if access would write production, expose secrets, or require triggering the unit.
- [X] T002 [US1] Append sanitized bounded service and kernel-journal observations to `specs/001-gateway-oom-recovery/evidence/incident-timeline.md`; correlate health, collection, export retrieval, Gateway publish/ACK, and OOM/cgroup timestamps; do not start/restart services, trigger timers, run collection/publisher scripts, or use Docker/Compose actions.
- [X] T003 [US1] Append safe read-only Gateway and External container metadata, effective Gateway memory limit, OOM/restart evidence, and bounded host-pressure observations to `specs/001-gateway-oom-recovery/evidence/incident-timeline.md`; do not inspect environment variables, attach volumes, execute state-writing commands, or copy production data.
- [X] T004 [US1] Append safe collection-job, export-manifest/latest-export, Gateway snapshot, and downstream checkpoint identities/counts to `specs/001-gateway-oom-recovery/evidence/incident-timeline.md`; preserve all production state and mark any unavailable correlation as `unverified`.
- [X] T005 [US1] Record any conflict between the live incident and `IMPLEMENTATION_STATUS.md` in `specs/001-gateway-oom-recovery/evidence/incident-timeline.md`, including the current reported `ExecMainStatus=1` versus historical curl 52/OOM evidence; STOP rather than silently reconciling contradictory facts.

**Phase 1 evidence/stop condition**: The record satisfies the `IncidentEvidenceTimeline` fields in `data-model.md`. If a required observation cannot be obtained read-only, document it as unavailable and do not trigger another live workflow.

---

## Phase 2 — Evidence-backed failure-boundary/root-cause analysis (US1, P1)

**Goal**: Classify the first failed lifecycle boundary before selecting a candidate.

**Independent test**: The lifecycle matrix names each required checkpoint as verified success, verified failure, unverified, or not applicable and does not infer root cause from health alone.

- [X] T006 [US1] Create `specs/001-gateway-oom-recovery/evidence/failure-boundary.md` with the `LifecycleCheckpoint` sequence from `data-model.md`: scheduled start → collection → export → selected latest artifact → Gateway receive/merge/persist/ACK → downstream pull/process/checkpoint; derive it only from Phase 1 read-only evidence.
- [X] T007 [US1] Compare the collection run, export status, manifest/dataset identity, and selected latest artifact in `specs/001-gateway-oom-recovery/evidence/failure-boundary.md`; explicitly test for the partial-job/failed-export/stale-latest edge case without replaying a request or touching External state.
- [X] T008 [US1] Compare Gateway pre/post snapshot identity, ACK/empty-reply evidence, OOM/restart evidence, and downstream checkpoint evidence in `specs/001-gateway-oom-recovery/evidence/failure-boundary.md`; explicitly distinguish pre-persist failure from lost ACK after durable persistence without retrying publish.
- [X] T009 [US1] Record the verified root-cause conclusion, alternative failure classes rejected, and every remaining uncertainty in `specs/001-gateway-oom-recovery/evidence/failure-boundary.md`; STOP candidate selection if export-to-run or snapshot/ACK correlation remains ambiguous.

**Phase 2 evidence/stop condition**: The result must address collection-state, export, stale selection, transport, validation/merge, lost ACK, resource exhaustion, and downstream failure. No code/configuration candidate is selected while the responsible boundary is unverified.

---

## Phase 3 — Isolated bounded large-export reproduction (US2, P1)

**Goal**: Build a disposable Gateway-only environment and deterministic synthetic fixture that cannot attach to production.

**Independent test**: Static isolation checks prove the rendered test topology has no production network, volume, path, secret, data, or provider egress before any test container starts.

- [ ] T010 [US2] Create `compose.gateway-recovery-test.yml` as a uniquely named, Gateway-only disposable Compose project with loopback-only exposure, synthetic credentials, explicit bounded memory limit, project-scoped network/volume, and no production service dependencies; fail closed on `/opt/cti-platform`, production volume/network, or production environment-file references.
- [ ] T011 [P] [US2] Create `scripts/generate_gateway_recovery_fixture.py` to generate a deterministic non-sensitive existing snapshot and incoming export under existing Gateway request, cumulative-snapshot, and item bounds; emit only seed/profile/count/size/SHA-256 metadata and never copy production records.
- [ ] T012 [P] [US2] Create `tests/test_gateway_recovery_compose.py` to assert `compose.gateway-recovery-test.yml` has no production bind mount, network, volume, secret source, provider egress, or ambiguous project/resource name; test the isolation guard before any runtime workload.
- [ ] T013 [US2] Create `scripts/run_gateway_recovery_validation.sh` to preflight the isolated project, record the fixture and cgroup/host metrics defined by `contracts/recovery-evidence-contract.md`, and stop after the first unsafe result; scope all temporary paths and cleanup targets to the exact test project.
- [ ] T014 [US2] Create `specs/001-gateway-oom-recovery/evidence/isolation-preflight.md` from the rendered isolated configuration and fixture metadata; STOP if isolation cannot be proved or host capacity/co-resident conditions make the workload unsafe.

**Phase 3 evidence/stop condition**: The fixture’s `contains_production_data`, `uses_production_network_or_volume`, and `external_egress` values are all false. Do not start the isolated workload if the topology check fails.

---

## Phase 4 — Baseline memory/publish/merge measurements (US2, P1)

**Goal**: Measure the unchanged Gateway once with the representative merge shape and establish state/ACK behavior.

**Independent test**: One bounded baseline publish yields a complete measurement or one bounded failure record; if successful, exactly one identical repeat proves idempotency without duplicate identities.

- [ ] T015 [US2] Extend `tests/test_vps_gateway.py` with candidate-independent coverage for a representative pre-existing snapshot plus incoming stable-identity merge, safe bound rejection, and previous-snapshot preservation; preserve the existing Gateway publish/read contract in `contracts/gateway-publish-compatibility.md`.
- [ ] T016 [US2] Extend `tests/test_vps_gateway.py` with deterministic pre-commit failure and lost-ACK/persistence identity cases where feasible; require the prior snapshot to remain byte-for-byte usable for rejected or pre-replacement failures and never claim an ambiguous ACK is a successful retry.
- [ ] T017 [US2] Run the isolated baseline exactly once through `scripts/run_gateway_recovery_validation.sh` using the T011 fixture and record request/snapshot bytes, item/merge counts, duration, response/ACK, hashes/ETag, cgroup current/peak/events, restart delta, host availability/swap/pressure, and co-resident observations in `specs/001-gateway-oom-recovery/evidence/baseline-measurement.md`; STOP immediately on OOM, unexpected restart, unsafe pressure, timeout, corruption, or co-resident degradation.
- [ ] T018 [US2] Submit exactly one identical isolated repeat only if T017 completed safely, and append unchanged/idempotency counts, snapshot identity, and resource observations to `specs/001-gateway-oom-recovery/evidence/baseline-measurement.md`; do not repeat a failing baseline or increase fixture load.
- [ ] T019 [US2] Record the measured operation responsible for peak resource use and its relationship, if any, to the observed empty reply/scheduler failure in `specs/001-gateway-oom-recovery/evidence/baseline-measurement.md`; mark causal linkage unverified unless corroborated by evidence.

**Phase 4 evidence/stop condition**: Evidence must meet FR-007 through FR-009 and SC-002/SC-003. Baseline failure is diagnostic evidence only; it never authorizes a production limit increase.

---

## Phase 5 — Minimal candidate correction or evidence-justified resource adjustment (US3, P1)

**Goal**: Choose one smallest, owned, data-preserving candidate from verified evidence.

**Independent test**: The decision record identifies a verified cause, one selected candidate or NO-GO, rejected alternatives, protected data boundaries, and an evidence-derived resource margin where relevant.

- [ ] T020 [US3] Create `specs/001-gateway-oom-recovery/evidence/candidate-decision.md` using the `CandidateDecision` fields in `data-model.md`; compare no-change, minimal Gateway behavior correction, Gateway resource adjustment, and scheduler export/run-correlation guard, and select exactly one candidate or record NO-GO. If NO-GO is selected, explicitly STOP: record the NO-GO decision and next safe action in `IMPLEMENTATION_STATUS.md`, mark T025–T036 as not applicable for that path in `specs/001-gateway-oom-recovery/evidence/candidate-decision.md`, do not enter Phases 6–8, and permit no production action.
- [ ] T021 [US3] If and only if T020 selects a Gateway merge candidate, modify `infra/vps/gateway/app.py` and the directly affected assertions in `tests/test_vps_gateway.py` to reduce the verified memory-amplifying operation while preserving feed identities, merge counts, bounds, auth/HMAC, atomic persistence, response fields, ETag, and consumer compatibility; STOP if the candidate changes the contract or requires a new service, queue, datastore, framework, or dependency.
- [ ] T022 [US3] If and only if T020 selects a resource candidate, modify only the Gateway resource setting in `infra/vps/compose.yaml` and its relevant assertions in `tests/test_vps_production_deployment.py` or `tests/test_vps_local_network_topology.py`; document in `specs/001-gateway-oom-recovery/evidence/candidate-decision.md` measured baseline/candidate peak memory, host pressure, total VPS capacity, co-resident demand, and a safety margin derived from evidence or existing policy—not a fixed percentage.
- [ ] T023 [US3] If and only if T020 selects an export/run-correlation candidate, modify `infra/vps/scripts/run_external_collection.sh` and add focused coverage in `tests/test_external_pipeline.py` or the appropriate existing External integration test; require successful current export identity before publish without changing timer cadence, systemd semantics, collector scope, or External persistence behavior.
- [ ] T024 [US3] Update only the candidate-relevant portions of `docs/api/external_feed_contract.md` and/or `docs/operations/vps_external_sources.md` after the selected repository change is verified; preserve security controls, ownership boundaries, Tailscale, systemd automation, PostgreSQL authority, and MISP’s selective analyst-controlled role.

**Phase 5 evidence/stop condition**: T021, T022, and T023 are mutually exclusive; execute only the path selected by T020. If T020 is NO-GO, T025–T036 are not applicable and work stops after the required `IMPLEMENTATION_STATUS.md` update; no candidate validation, production approval, or production action follows. If a combined candidate seems necessary, STOP and obtain a revised specification/approval rather than bundling changes.

---

## Phase 6 — Isolated candidate validation and regression testing (US3, P1)

**Goal**: Prove the selected candidate against the same bounded workload and established contracts before requesting production approval.

**Independent test**: The selected candidate completes the representative publish and one safe identical repeat without OOM/restart/unsafe pressure/starvation, preserves state and contracts, and passes proportionate regressions.

- [ ] T025 [US3] Select and run only the applicable candidate-relevant tests from the following existing suites: `tests/test_vps_gateway.py`, `tests/test_gateway_recovery_compose.py`, `tests/external_sources/integration/test_external_dataset_export.py`, `tests/external_sources/integration/test_local_collection_job.py`, `tests/test_backend_enhancements.py`, `tests/test_vps_local_network_topology.py`, and `tests/test_vps_production_deployment.py`; Gateway code candidates require Gateway contract plus isolation/topology/deployment-safety tests, Gateway resource candidates require isolation/topology/deployment-safety plus relevant Gateway contract tests, scheduler/export-correlation candidates require External export/job-correlation plus scheduler/deployment-safety tests, and downstream/idempotency tests run only when that boundary is affected; record selected tests and results in `specs/001-gateway-oom-recovery/evidence/candidate-validation.md` and STOP on any contract, security, topology, or data-preservation regression.
- [ ] T026 [US3] Run the isolated candidate once through `scripts/run_gateway_recovery_validation.sh` with the unchanged T011 fixture profile; record response/ACK, hashes/ETag, merge counts, peak/cgroup events, host pressure/capacity, co-resident observations, and persistence integrity in `specs/001-gateway-oom-recovery/evidence/candidate-validation.md`; STOP on OOM, restart, unsafe pressure, starvation, timeout, or integrity mismatch.
- [ ] T027 [US3] Submit one identical isolated candidate repeat only after T026 completes safely, append idempotency/unchanged evidence to `specs/001-gateway-oom-recovery/evidence/candidate-validation.md`, and do not tune or repeat a failing heavy workload.
- [ ] T028 [US3] Compare T017/T018 baseline evidence with T026/T027 candidate evidence in `specs/001-gateway-oom-recovery/evidence/candidate-validation.md`; derive the required safety margin from measurements or documented ACTIT policy and mark production eligibility as `pass`, `fail`, or `unverified` without using a fixed percentage.
- [ ] T029 [US3] Remove only the verified disposable project resources and temporary synthetic fixture paths through `scripts/run_gateway_recovery_validation.sh`, then record cleanup scope and retained sanitized evidence in `specs/001-gateway-oom-recovery/evidence/candidate-validation.md`; never run broad Docker pruning or touch production volumes/networks.

**Phase 6 evidence/stop condition**: Isolated acceptance requires complete representative workload, zero OOM/restart, safe host/co-resident behavior, valid atomic state, and preserved contract/idempotency. Failure blocks Phase 7 approval and leaves production unchanged.

---

## Phase 7 — STOP: explicit user approval gate

**Goal**: Present evidence and halt. This phase contains no production action.

- [ ] T030 Before creating `specs/001-gateway-oom-recovery/evidence/production-approval-request.md`, update `IMPLEMENTATION_STATUS.md` with the verified Phase 6 checkpoint: verified root cause, selected candidate, isolated validation result, sanitized evidence references, production impact, remaining uncertainty, readiness state, compatibility/rollback constraints, and next safe action; then create `specs/001-gateway-oom-recovery/evidence/production-approval-request.md` with exact candidate digest/scope, affected components, data-preservation boundaries, focused-test results, baseline/candidate metrics, host/co-resident analysis, evidence-derived margin, expected production impact, monitoring window, stop conditions, and targeted rollback compatibility/limitations.
- [ ] T031 **STOP — USER APPROVAL REQUIRED; END THIS IMPLEMENT RUN**: Record explicit user approval or rejection in `specs/001-gateway-oom-recovery/evidence/production-approval-request.md`; `$speckit-implement` MUST stop after producing T030 and reaching T031, and a checked or recorded T031 is not permission for the already-running agent to continue into Phase 8. Do not execute or schedule any production deployment, restart, configuration change, rollback, timer trigger, collection, publisher run, Docker/Compose action, `/opt/cti-platform` write, or downstream pull in this run.

**Gate**: Phase 8 has no automatic continuation from Phase 7. It requires a new, separate explicit user instruction after the user reviews `specs/001-gateway-oom-recovery/evidence/production-approval-request.md`. That later instruction may authorize only the exact unchanged candidate and scope. If the candidate digest, scope, evidence, or live state differs, STOP and request approval again; a changed candidate, stale evidence, ambiguous scope, or missing rollback compatibility returns the work to Phase 5/6 or NO-GO.

---

## Phase 8 — Exactly one monitored real workflow after approval (US4, P2) — BLOCKED: NEW USER-AUTHORIZED SESSION REQUIRED

**Goal**: After approval only, perform and observe one real scheduled lifecycle through downstream completion.

**Independent test**: One approved workflow completes collection → durable current export/state → Gateway merge/persist/ACK → downstream processing/checkpoint without OOM/restart/unsafe pressure/starvation; any failure stops without retry or rollback.

- [ ] T032 [US4] **BLOCKED pending a new, separate explicit user instruction after T031 review**: Reconfirm the approved candidate digest/scope, current state/volume compatibility, preservation of PostgreSQL/MISP/Gateway/External/Docker-volume/Tailscale/systemd boundaries, and the chosen single timer occurrence in `specs/001-gateway-oom-recovery/evidence/monitored-workflow.md`; STOP and request approval again if the candidate digest, scope, evidence, or live state differs.
- [ ] T033 [US4] **MANUAL, USER-AUTHORIZED ONLY IN THE NEW SEPARATE SESSION; BLOCKED pending T032**: Execute only the exact unchanged approved targeted activation described in `specs/001-gateway-oom-recovery/evidence/production-approval-request.md`, if activation is required; do not use broad deployment scripts, `compose down`, volume operations, timer changes, automatic rollback, or any action beyond the approved Gateway/component scope. This task MUST NOT execute automatically in the `$speckit-implement` run that reaches T031.
- [ ] T034 [US4] **MANUAL, USER-AUTHORIZED ONLY IN THE NEW SEPARATE SESSION; BLOCKED pending T032/T033 as applicable**: Observe exactly one selected `cti-external-collection.timer` workflow and append the unique invocation, collection terminal state, durable current export identity, selected-export correlation, Gateway receive/merge/atomic persistence/ACK, cgroup/restart/host pressure, and co-resident observations to `specs/001-gateway-oom-recovery/evidence/monitored-workflow.md`; do not trigger a second collection or retry on failure.
- [ ] T035 [US4] **MANUAL, USER-AUTHORIZED ONLY IN THE NEW SEPARATE SESSION; BLOCKED pending T032/T034**: Verify the existing downstream automation/path read-only and append its one associated pull/process/checkpoint result to `specs/001-gateway-oom-recovery/evidence/monitored-workflow.md`; if it is absent or fails, STOP and request separate explicit approval for one existing authenticated pull of the same published artifact—never another collection. This task MUST NOT execute automatically in the `$speckit-implement` run that reaches T031.
- [ ] T036 [US4] **MANUAL, USER-AUTHORIZED ONLY IN THE NEW SEPARATE SESSION; BLOCKED pending T032–T035 as applicable**: On any failed, ambiguous, OOM/restart, unsafe-pressure, starvation, state-integrity, or downstream checkpoint result, finalize the failure evidence in `specs/001-gateway-oom-recovery/evidence/monitored-workflow.md`, classify External readiness as NO-GO/unverified, and stop with no automatic retry, rollback, data restoration, or follow-on live workflow. This task MUST NOT execute automatically in the `$speckit-implement` run that reaches T031.

**Phase 8 evidence/stop condition**: Exactly one collection invocation is permitted. MISP automatic-share count remains zero. A successful Gateway health check or publish without downstream completion is insufficient.

---

## Phase 9 — Readiness decision and durable continuation update (US4, P2)

**Goal**: Make an evidence-based GO/NO-GO decision and preserve the verified checkpoint for continuation.

**Independent test**: The readiness record separates verified, failed, and unverified checkpoints and `IMPLEMENTATION_STATUS.md` records only durable, sanitized conclusions after a meaningful verified checkpoint.

- [ ] T037 [US4] Create `specs/001-gateway-oom-recovery/evidence/readiness-decision.md` using the `ReadinessDecision` fields in `data-model.md`; require verified collection, durable current export/state, Gateway merge/persist/ACK, downstream completion, resource/co-resident safety, contract/data/security preservation, and scheduling behavior for GO, otherwise record NO-GO or PARTIALLY-VERIFIED.
- [ ] T038 [US4] Update `IMPLEMENTATION_STATUS.md` only after the later verified Phase 8 real-workflow checkpoint; record the monitored-workflow result, sanitized evidence references, production impact, remaining uncertainty, readiness decision, compatibility/rollback constraints, and next authorized action without secrets, transient IDs, current row counts, or inferred success.
- [ ] T039 [US4] Reconcile `docs/operations/vps_external_sources.md` and `docs/operations/vps_production_runbook.md` with the verified candidate behavior and readiness outcome only if Phase 5/8 changed durable operational behavior; otherwise record that no documentation behavior change was needed in `specs/001-gateway-oom-recovery/evidence/readiness-decision.md`.
- [ ] T040 [US4] Review `specs/001-gateway-oom-recovery/evidence/` against `contracts/recovery-evidence-contract.md` and `contracts/gateway-publish-compatibility.md`; confirm all missing evidence remains `unverified`, no sensitive data was retained, and no completion claim exceeds the one approved workflow’s evidence.

**Phase 9 completion condition**: External Sources is production-ready only when the complete verified lifecycle succeeds. If any required checkpoint is missing or fails, retain NO-GO/PARTIALLY-VERIFIED and do not initiate another production action.

---

## Dependencies & Execution Order

```text
Phase 1 (T001–T005, read-only) → Phase 2 (T006–T009, read-only)
  → Phase 3 (T010–T014, isolated harness) → Phase 4 (T015–T019, baseline)
  → Phase 5 (T020–T024, exactly one selected candidate) → Phase 6 (T025–T029, isolated validation)
  → Phase 7 (T030–T031, STOP / explicit approval)
  → Phase 8 (T032–T036, BLOCKED; exactly one workflow) → Phase 9 (T037–T040, readiness)
```

### User Story Dependencies

- **US1 — Verified failure boundary**: T001–T009; blocks all candidate work.
- **US2 — Isolated validation**: T010–T019; depends on US1 and blocks candidate selection.
- **US3 — Smallest safe correction**: T020–T029; depends on US2 and blocks production approval.
- **US4 — One real lifecycle and readiness**: T032–T040; requires recorded T031 approval, termination of the current `$speckit-implement` run, and a new, separate explicit user-authorized session after review of `specs/001-gateway-oom-recovery/evidence/production-approval-request.md`. T032–T036 are blocked and never automatic.

### Parallel opportunities

- T011 and T012 can proceed in parallel after T010 establishes the isolated topology.
- Candidate branches T021–T023 are mutually exclusive, not parallel; only the branch selected by T020 may proceed.

## Implementation Strategy

### MVP

The first deliverable is US1: a sanitized, read-only verified failure boundary. It makes no production or repository implementation change outside evidence files and may result in NO-GO if root cause cannot be proven.

### Incremental delivery

1. Complete read-only diagnosis (Phases 1–2).
2. Create and validate isolated harness/baseline (Phases 3–4).
3. Select one minimal candidate and validate it in isolation (Phases 5–6).
4. Stop for explicit user approval (Phase 7).
5. Only after approval, conduct one monitored workflow and record readiness (Phases 8–9).

## Task Validation

- All 40 tasks use the required checkbox, sequential ID, optional parallel marker, applicable user-story label, and exact file path format.
- No Phase 1 or Phase 2 task mutates production, writes `/opt/cti-platform`, runs Docker/Compose, triggers collection/publisher work, deploys, restarts, or rolls back.
- No Phase 8 task is executable before the explicit Phase 7 approval record.
- The task list introduces no automatic retry, rollback, destructive persistent-state operation, or production redesign.
