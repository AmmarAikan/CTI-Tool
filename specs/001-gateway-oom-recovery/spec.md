# Feature Specification: Scheduled External Collection and Gateway OOM Recovery

**Feature Branch**: `codex/actit-final-production`

**Created**: 2026-09-21

**Status**: Draft

**Input**: User description: "Diagnose and safely resolve the failed scheduled External
Collection lifecycle and verified Gateway out-of-memory evidence with the smallest
data-preserving change."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Establish the Verified Failure Boundary (Priority: P1)

As the ACTIT production owner, I need a read-only, time-correlated account of the latest failed
scheduled workflow so that the failure is assigned to the correct lifecycle stage before any
change is proposed.

**Why this priority**: A healthy service endpoint can coexist with a failed collection lifecycle.
Acting before the failed stage and root cause are verified risks changing the wrong component or
damaging persistent state.

**Independent Test**: Review only existing service status, journals, kernel evidence, container
history, collection job status, export metadata, Gateway records, and downstream processing
records. The review passes when one evidence timeline identifies the last successful stage, the
first failed stage, and any remaining uncertainty without changing production.

**Acceptance Scenarios**:

1. **Given** the latest scheduled unit ended unsuccessfully, **When** an operator correlates its
   start and end times with collection, export, publish, Gateway, kernel, and downstream records,
   **Then** the incident is classified as one of collection-state failure, export failure, publish
   transport failure, Gateway merge/acceptance failure, downstream processing failure, or resource
   exhaustion, with cited evidence.
2. **Given** External Sources and Gateway health checks currently succeed, **When** readiness is
   assessed, **Then** those checks are recorded only as component-health evidence and do not
   satisfy end-to-end readiness.
3. **Given** evidence is incomplete or contradictory, **When** the investigation is documented,
   **Then** the unresolved point is marked unverified and no fix or readiness claim is inferred.

---

### User Story 2 - Validate the Failure Safely in Isolation (Priority: P1)

As the ACTIT production owner, I need an isolated, bounded reproduction of the large-export
publish and cumulative merge so that memory behavior, state safety, and acknowledgement semantics
can be measured without another live collection or contact with production state.

**Why this priority**: Existing kernel evidence already indicates resource exhaustion. A bounded
fixture can test that path without repeatedly running a heavy, externally connected collection.

**Independent Test**: Use an isolated VPS environment with non-production networks, temporary
persistent state, synthetic or sanitized data, and a representative bounded export. The test
passes when it distinguishes transport, validation, merge, atomic persistence, acknowledgement,
and resource behavior while proving production volumes and data were never attached.

**Acceptance Scenarios**:

1. **Given** a representative pre-existing cumulative snapshot and a bounded incoming export,
   **When** the isolated publish runs under measured resource limits, **Then** inserted, updated,
   unchanged, total-item, persistence, and acknowledgement outcomes are captured with peak memory
   and process-lifecycle evidence.
2. **Given** an injected failure before durable replacement, **When** the publish ends
   unsuccessfully, **Then** the previous valid snapshot remains byte-for-byte usable.
3. **Given** the same accepted export is submitted once more in isolation, **When** the merge
   completes, **Then** it creates no duplicate identities and returns a consistent acceptance
   result.
4. **Given** a fixture exceeds an existing payload, item, or snapshot bound, **When** it is
   submitted, **Then** it is rejected safely without changing the prior snapshot.

---

### User Story 3 - Select and Validate the Smallest Safe Correction (Priority: P1)

As the ACTIT production owner, I need a correction decision based on measured root-cause evidence
so that ACTIT regains reliable scheduled publishing without an architectural redesign or
unnecessary resource growth.

**Why this priority**: The correction must address the verified failure while preserving the
existing deployment, service boundaries, and persistent data.

**Independent Test**: Compare the verified failure mechanism against the candidate behavior in the
isolated environment. The story passes when the candidate removes that mechanism, retains all
existing data and contracts, meets the measured resource margin, and identifies a reversible
application/configuration rollback that never restores or replaces persistent data automatically.

**Acceptance Scenarios**:

1. **Given** evidence shows avoidable peak-memory amplification or unsafe merge behavior, **When**
   a correction is selected, **Then** it is limited to the affected publish/merge path and retains
   the existing external-feed contract and atomic state semantics.
2. **Given** evidence shows the current behavior is necessary and the resource ceiling alone is
   insufficient, **When** a resource adjustment is selected, **Then** it is justified by measured
   peak use, safety headroom, total VPS capacity, and coexistence with all existing services.
3. **Given** neither correction type passes isolated validation, **When** the decision is recorded,
   **Then** the feature remains blocked and no production change is authorized.

---

### User Story 4 - Prove One Real Lifecycle and Restore Readiness (Priority: P2)

As an ACTIT operator, I need exactly one approved and monitored real scheduled workflow after the
candidate is authorized so that readiness is based on the complete lifecycle rather than service
health alone.

**Why this priority**: Isolated evidence is necessary but cannot prove the real scheduler,
collection state, durable export, Gateway publishing, and downstream processing operate together.

**Independent Test**: After separate explicit approval for production-affecting work, observe one
real scheduled workflow from start through terminal processing. The story passes only if every
lifecycle checkpoint succeeds, no out-of-memory kill or unexpected restart occurs, and the durable
operational continuation record is updated with sanitized evidence.

**Acceptance Scenarios**:

1. **Given** the candidate passed isolated validation and explicit production approval was
   recorded, **When** one real workflow runs, **Then** collection reaches an allowed terminal
   state, its validated export is durable, Gateway publishing returns an acceptance result, the
   resulting snapshot is processable, downstream processing reaches successful completion, and
   no resource-exhaustion event occurs.
2. **Given** any lifecycle checkpoint fails during that one workflow, **When** the outcome is
   reviewed, **Then** External Sources remains not production-ready, evidence is preserved, and no
   automatic rerun, deployment, rollback, or data restoration occurs.
3. **Given** the full lifecycle succeeds, **When** readiness is re-evaluated, **Then** component
   health, scheduler outcome, durable state/export, publish/merge acceptance, downstream
   completion, resource stability, and data-preservation checks are all recorded before readiness
   is declared.

### Edge Cases

- The collection job fails before creating a new export while an older valid latest export remains.
- Collection finishes with isolated provider failures under the existing partial-success contract,
  but the scheduler or publish step still fails.
- Gateway durably replaces the snapshot but terminates before the publisher receives its
  acknowledgement, leaving an ambiguous retry outcome.
- Gateway restarts after an out-of-memory event and its health endpoint recovers while the publish
  was never acknowledged.
- The incoming export is small enough for its request bound, but combining it with the existing
  cumulative snapshot exceeds the snapshot item, byte, or memory budget.
- An incoming record updates an existing stable identity while other records are unchanged, making
  inserted-item count alone insufficient proof of a correct merge.
- The stored snapshot is invalid, truncated, or already above its configured bound.
- A proposed resource increase would leave insufficient capacity for the Backend, PostgreSQL,
  External Sources, MISP, Tor, Dionaea, or host operations.
- The isolated test passes with an empty snapshot but fails with a representative cumulative
  snapshot.
- The approved real workflow succeeds through Gateway acceptance but downstream processing does
  not reach a successful terminal state.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The investigation MUST begin with read-only inspection of the failed scheduled
  workflow and MUST NOT modify production state or files under `/opt/cti-platform`.
- **FR-002**: The investigation MUST preserve and correlate the scheduled-unit outcome, collection
  job state, run identity, export status, export integrity metadata, publisher outcome, Gateway
  process history, kernel resource evidence, persisted snapshot metadata, and downstream
  processing outcome in one sanitized timeline.
- **FR-003**: The investigation MUST distinguish collection-state failure, export failure, publish
  transport failure, Gateway validation or merge failure, lost acknowledgement after persistence,
  downstream processing failure, and resource exhaustion; unsupported conclusions MUST be marked
  unverified.
- **FR-004**: Existing logs and evidence MUST be used before any reproduction. Another live heavy
  collection MUST NOT be run solely to reproduce the known failure.
- **FR-005**: Evidence MUST exclude credentials, tokens, environment secrets, private source
  details, and sensitive production records while retaining timestamps, safe identifiers, counts,
  sizes, exit outcomes, and resource measurements needed for diagnosis.
- **FR-006**: Validation MUST include an isolated VPS-compatible environment with temporary
  non-production state, no production volumes or networks, no production secrets, no External
  provider calls, and a bounded synthetic or sanitized large-export fixture representative of the
  known failing size and cumulative merge shape.
- **FR-007**: Isolated validation MUST measure the publish lifecycle separately: request receipt,
  bounds enforcement, input validation, existing-snapshot read, stable-identity merge,
  serialization, durable atomic replacement, acceptance response, and repeat/idempotency outcome.
- **FR-008**: Isolated validation MUST prove the previous valid snapshot remains intact for rejected
  input, bound violations, malformed state, injected pre-commit failure, and process termination
  before durable replacement.
- **FR-009**: The root-cause conclusion MUST identify the operation responsible for the measured
  peak resource use and show whether the known out-of-memory event explains the publisher's empty
  reply and failed scheduler outcome.
- **FR-010**: Any proposed code correction MUST be limited to the verified failing path, preserve
  existing feed identities, merge counts, bounds, authentication, atomic persistence, and consumer
  compatibility, and introduce no replacement service, queue, datastore, or framework.
- **FR-011**: Any proposed resource adjustment MUST be justified by measured baseline and candidate
  peak memory, observed host pressure, total VPS capacity, and safe coexistence with all
  co-resident ACTIT services. The required safety margin MUST be derived from measured evidence or
  an existing documented ACTIT operational policy; no fixed percentage may be assumed.
- **FR-012**: If both a smaller behavioral correction and a resource adjustment are viable, the
  selected resolution MUST be the least invasive option that passes the same validation criteria;
  the rejected alternative and rationale MUST be recorded.
- **FR-013**: Production deployment, rollback, reconfiguration, and any write under
  `/opt/cti-platform` MUST remain separate approval-gated actions and MUST NOT occur as part of
  specification, diagnosis, or isolated validation.
- **FR-014**: PostgreSQL, MISP, Docker volumes, Gateway state, External collection state, and
  persistent datasets MUST NOT be deleted, recreated, reset, restored, or overwritten. Expected
  append/merge changes from the one approved workflow are the only permitted production data
  changes in this scope.
- **FR-015**: Tailscale routing, current systemd scheduling semantics, service ownership boundaries,
  authentication, and existing network isolation MUST remain unchanged unless a separately
  identified necessity is explicitly approved and justified.
- **FR-016**: After isolated acceptance and explicit approval, production validation MUST execute
  exactly one monitored real scheduled workflow. The validation MUST NOT automatically retry or
  start a second heavy collection if it fails.
- **FR-017**: The monitored workflow MUST record collection terminal state, durable export and
  integrity evidence, Gateway acceptance and merge counts, snapshot identity, Gateway memory and
  restart behavior, downstream process completion, duplicate behavior, and post-run component
  health.
- **FR-018**: External Sources MUST remain classified as not production-ready unless the complete
  collection → durable state/export → Gateway publish/merge acceptance → downstream processing →
  successful workflow completion lifecycle is evidenced.
- **FR-019**: A failed production validation MUST preserve all diagnostic evidence and persistent
  state, stop further live reproduction, report readiness as failed or unverified, and require a new
  explicit decision before any subsequent production action.
- **FR-020**: A successful verified checkpoint MUST update `IMPLEMENTATION_STATUS.md` with the root
  cause, approved correction, validation scope, sanitized evidence, production impact, remaining
  uncertainty, readiness decision, and next authorized action.

### Scope and Boundaries

**In scope**:

- Read-only diagnosis of the current scheduled External Collection failure.
- The existing External Sources export handoff, scheduled publisher, Gateway external-feed
  publish/merge/acceptance path, relevant resource configuration, downstream processing evidence,
  and existing operational documentation and tests.
- Isolated representative validation, decision between a minimal behavior correction and a
  justified resource adjustment, one separately approved production workflow, readiness
  re-validation, and the operational checkpoint update.

**Out of scope**:

- Redesigning ACTIT, replacing the Gateway, adding a queue or datastore, changing collector scope,
  changing PostgreSQL or MISP behavior, changing Tailscale exposure, changing schedule frequency,
  enabling new sources, or performing unrelated optimization.
- Automatic deployment, rollback, database restore, volume recreation, state cleanup, repeated
  production collection, or any production mutation during specification and diagnosis.

### Affected Components

- Scheduled External Collection unit and its existing collection-and-publish entry point.
- External Sources job state and validated export boundary.
- Gateway external-feed request bounds, cumulative stable-identity merge, atomic snapshot state,
  acceptance response, and resource ceiling.
- The existing downstream external-feed consumer only as needed to prove terminal processing.
- VPS Compose/resource configuration, isolated validation configuration, operations documentation,
  regression tests, and `IMPLEMENTATION_STATUS.md`.

### Data-Preservation Boundaries

- Production Gateway and External Sources volumes are evidence sources and MUST remain mounted only
  to their existing production services; isolated validation uses new temporary state.
- The prior valid Gateway snapshot MUST survive every failed or rejected publish.
- Existing External checkpoints, exports, review records, and Gateway stable identities MUST retain
  provenance and idempotency behavior.
- PostgreSQL and MISP are observation-only for this feature except for normal downstream effects of
  the one approved real workflow; neither may be restored, reset, mirrored, or rebuilt.

### Production Impact and Approval Gates

- Specification and diagnosis have no production-write impact.
- Isolated validation may create disposable non-production state only.
- Any candidate build, production configuration change, deployment, restart for reconciliation,
  rollback, or real workflow requires explicit user approval after the proposed target and impact
  are presented.
- The sole approved real workflow may collect external data and update the established External,
  Gateway, and downstream states through their normal contracts; no broader mutation is permitted.

### Validation Strategy

1. Establish the read-only incident timeline and failing lifecycle stage.
2. Build a bounded fixture matching the known request and cumulative snapshot shape without using
   live collection.
3. Measure baseline isolated behavior and verify failure-state preservation.
4. Validate the smallest candidate correction or resource adjustment against the same fixture,
   including one repeat publish for idempotency.
5. Run existing focused contract, Gateway, deployment, scheduler, and External export tests, then
   the proportionate regression set required by the affected surface.
6. After explicit approval only, observe exactly one real scheduled lifecycle and re-evaluate
   readiness from full-lifecycle evidence.

### Rollback Considerations

- A rollback plan, where applicable, MUST identify only the prior application image or resource
  configuration and the exact affected service.
- Rollback MUST preserve the current Gateway snapshot, External state/exports, Docker volumes,
  PostgreSQL, MISP, Tailscale, and systemd automation.
- Database or persistent-state restoration is not an application rollback and MUST never occur
  automatically.
- If rollback could reintroduce an incompatible state or known availability failure, that risk MUST
  be reported before approval rather than hidden by an automatic rollback.

### Required Completion Evidence

- A sanitized incident timeline with source references and an explicit root-cause statement.
- Baseline and candidate isolated measurements for input size, cumulative size, item counts, merge
  outcomes, peak memory, process exit/restart behavior, persistence integrity, and acknowledgement.
- Proof that isolated validation used no production volume, network, secret, or provider call.
- Focused and regression test results for every affected contract and operational boundary.
- The explicit production approval record and evidence from exactly one monitored workflow.
- A final readiness decision that distinguishes verified, failed, and unverified checkpoints.
- The corresponding durable update to `IMPLEMENTATION_STATUS.md` after a meaningful verified
  implementation or verification checkpoint.

### Key Entities *(include if feature involves data)*

- **Scheduled Workflow**: One timer-initiated collection-and-publish attempt, identified by its
  start/end time, unit result, collection job, and terminal outcome.
- **Collection Run**: The External Sources execution and its per-source statuses, accepted/review
  counts, state checkpoints, and export result.
- **Validated Export**: The durable run-scoped dataset and integrity metadata eligible for Gateway
  publication.
- **Gateway Snapshot**: The cumulative, bounded, stable-identity feed state that must be replaced
  atomically and preserved on failure.
- **Publish Attempt**: The transfer and Gateway processing of one validated export, including input
  size, merge counts, acceptance response, resource use, and persistence result.
- **Readiness Evidence Set**: The sanitized collection of health, lifecycle, integrity, resource,
  downstream completion, and data-preservation results used for the final decision.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The investigation produces one time-correlated evidence record that assigns the
  failure to a specific lifecycle stage and explains the relationship between the resource event,
  empty response, and scheduler failure, with zero production mutations during diagnosis.
- **SC-002**: One representative isolated publish and one identical repeat complete without an
  out-of-memory kill or unexpected process restart; the first reports correct merge totals and the
  repeat adds zero duplicate identities.
- **SC-003**: For 100 percent of tested rejection and injected pre-commit failure cases, the prior
  valid snapshot remains byte-for-byte intact and readable.
- **SC-004**: The selected candidate completes the representative large merge without an
  out-of-memory event, unexpected process restart, unsafe host pressure, or resource starvation of
  any co-resident ACTIT service, and the applied safety margin is supported by measured evidence or
  an existing documented ACTIT operational policy.
- **SC-005**: Exactly one approved real workflow reaches successful terminal completion across
  collection, durable export, Gateway acceptance, snapshot processing, and downstream processing,
  with zero resource-exhaustion events, zero unexpected Gateway restarts, and no duplicate or lost
  stable identities attributable to the recovery.
- **SC-006**: All required readiness checkpoints are evidenced; any missing checkpoint keeps the
  readiness decision explicitly failed or unverified rather than ready.
- **SC-007**: No PostgreSQL, MISP, Docker volume, Gateway state, External state, persistent dataset,
  Tailscale route, or systemd schedule is deleted, recreated, reset, restored, or unintentionally
  overwritten throughout the work.
- **SC-008**: The durable operational continuation record is updated at the verified checkpoint
  with 100 percent of the required root-cause, validation, production-impact, readiness, and
  remaining-risk fields.

## Assumptions

- Current observations—healthy core services, a failed scheduled unit, prior empty replies, a
  Gateway out-of-memory event during a large publish, and the current service resource limits—are
  investigation inputs rather than proof of the final root cause or a predetermined fix.
- The existing partial-success collection contract remains valid: isolated provider failures may
  be retained, but the overall scheduled publish workflow must still complete successfully.
- Existing production logs, journals, kernel records, container metadata, collection status, and
  export/Gateway state provide enough read-only evidence to establish an initial timeline.
- A synthetic or sanitized fixture can reproduce the relevant size and merge characteristics
  without copying sensitive production records or contacting external providers.
- Explicit approval and authorized VPS access will be available later if isolated validation
  supports a production candidate and one monitored real workflow.
- Existing component contracts, authentication, network boundaries, scheduling semantics, and
  persistent-state identities remain authoritative unless the verified root cause proves a narrow
  approved change is necessary.
