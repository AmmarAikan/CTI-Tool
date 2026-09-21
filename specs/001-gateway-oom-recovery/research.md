# Research: Scheduled External Collection and Gateway OOM Recovery

## Scope and method

This research is repository-based and read-only. It examines the current External Sources lifecycle, Gateway publish/merge implementation, VPS Compose topology, systemd automation, downstream processing, tests, and operations documentation. It does not verify current live production state; Phase 1 of implementation must do that read-only.

## Decision 1: Diagnose the complete lifecycle, not service health

**Decision**: Build a correlated checkpoint timeline from scheduled invocation through downstream completion. Mark every checkpoint verified success, verified failure, or unverified.

**Rationale**: The External health endpoint proves only process responsiveness. The scheduler can fail after health succeeds, collection can end partial, export can fail while an older valid export remains, Gateway can persist before a response is lost, and downstream processing can remain incomplete after publish.

**Required checkpoints**:

1. systemd timer/service invocation;
2. collection job ID and terminal state;
3. export status and manifest/dataset identity;
4. publisher-selected export identity;
5. Gateway request receipt and validation;
6. merge and atomic snapshot replacement;
7. successful publish ACK and returned counts/ETag;
8. downstream pull/process/checkpoint;
9. resource and co-resident service observations.

**Alternatives rejected**:

- Treating healthy containers/endpoints as readiness: incomplete.
- Treating the scheduler exit code alone as root cause: the code identifies process termination, not the failed lifecycle boundary.
- Running another production collection to obtain clearer logs: violates the bounded-execution and approval requirements.

## Decision 2: Reconcile current and historical incidents before attributing cause

**Decision**: Read-only live verification must distinguish the current reported `ExecMainStatus=1` event from the repository-documented historical curl exit 52 event and OOM evidence.

**Rationale**: `IMPLEMENTATION_STATUS.md` records an earlier empty reply/curl 52 plus kernel Gateway OOM evidence, while the current problem statement reports the latest unit ending with status 1. They may represent different attempts or boundaries. Documentation/live disagreement must be reported rather than silently normalized.

**Evidence needed**: unit timestamps/status, sanitized journal stages, kernel/cgroup timestamps, Gateway restart/OOM metadata, job/export identities, and snapshot identity.

**Alternative rejected**: Updating documentation to match the problem statement without inspecting live evidence.

## Decision 3: Treat Gateway memory amplification as a strong hypothesis to measure

**Decision**: Profile the existing Gateway merge path with a bounded synthetic existing snapshot plus incoming export before selecting a correction.

**Rationale**: The current publish path can hold multiple whole-feed representations at once:

- request bytes;
- decoded request text/object;
- normalized incoming graph;
- existing snapshot bytes/text/object;
- merged dictionary and sorted item list;
- serialized envelope used for size checking;
- serialized envelope used again for digest/write.

This makes a roughly 100 MiB stored feed plausibly exceed a 512 MiB cgroup limit. Kernel OOM evidence supports the hypothesis, but the exact peak and safe candidate must be measured.

**Alternative rejected**: Raising the memory limit immediately. A limit adjustment without peak, host capacity, pressure, and coexistence evidence may move the failure to the host or another ACTIT service.

## Decision 4: Preserve atomic and idempotent Gateway semantics

**Decision**: Any candidate must retain the current request/response contract, validation and bounds, cumulative merge semantics, ETag, atomic old-or-new snapshot behavior, and authenticated control path.

**Rationale**: Existing clients and downstream checkpoint logic rely on those semantics. The current atomic replace means an empty reply is ambiguous: an OOM before replacement should leave the old snapshot, while a connection loss after replacement but before ACK can leave the new snapshot. Blind retry is unsafe until snapshot identity is checked, even though an identical retry should ultimately be idempotent.

**Candidate direction if verified**: Reduce simultaneous full-size representations and duplicate serialization inside the existing process, without creating a queue, alternate persistence layer, replacement Gateway, or new framework.

**Alternatives rejected**:

- Replacement/streaming Gateway service: redesigns the architecture.
- Queue or broker: adds an unneeded production boundary.
- New datastore for feeds: conflicts with existing persistence and PostgreSQL authority.
- In-place non-atomic rewrite: weakens data preservation.

## Decision 5: Verify export-to-run correlation before assuming publish input is current

**Decision**: Correlate the terminal collection job with its export status and the artifact returned by the latest-export endpoint.

**Rationale**: The collection service can return `partial` when export fails, preserving the previous valid latest export. The current host script accepts both `completed` and `partial`, then fetches `exports/latest`; it does not visibly prove that the fetched export belongs to the just-finished job. A failed new export could therefore select an older artifact.

**Candidate direction if verified**: Add the smallest existing-path guard that requires a successful current export and correlates the selected artifact to the run. Preserve the timer, collection service, export format, and Gateway.

**Alternative rejected**: Reworking the collection scheduler or inventing another orchestration service.

## Decision 6: Use a dedicated disposable Gateway Compose harness

**Decision**: Add a Gateway-only test Compose file with a unique project name, synthetic secrets, generated non-sensitive fixtures, loopback-only access, and a project-scoped disposable volume/network.

**Rationale**: Existing unit tests cover behavior but cannot enforce cgroup memory limits or observe container OOM/restart. The existing External test Compose conventions provide an isolation pattern, but no current harness exercises a representative Gateway merge.

**Safety controls**:

- no production Compose project name;
- no production/external network;
- no production volume or bind mount;
- no `/opt/cti-platform` path;
- no production environment file or credentials;
- no external provider egress;
- deterministic fixture profile and hard size/item bounds;
- preflight host-capacity check;
- one baseline attempt and one candidate attempt, with no rerun after a failure;
- cleanup by exact verified project/resource names only.

**Alternative rejected**: Reproducing directly against production Gateway state.

## Decision 7: Base resource decisions on measured coexistence, not a fixed percentage

**Decision**: Capture baseline and candidate current/peak memory, cgroup events, host total/available memory, swap activity, pressure indicators, and co-resident ACTIT observations. Derive the safety margin from those measurements or an existing documented ACTIT policy.

**Rationale**: Compose memory caps are ceilings rather than reservations, and aggregate configured limits do not establish actual simultaneous demand. A universal percentage cannot prove safe coexistence on this VPS.

**Success condition**: The candidate completes the representative workload without OOM, unexpected restart, unsafe host pressure, or resource starvation of co-resident services.

**Alternative rejected**: Any fixed headroom or percent-of-limit rule not grounded in ACTIT evidence or policy.

## Decision 8: Select exactly one minimal candidate

**Decision**: Use this evidence hierarchy:

1. no code/config change if the current incident is not reproducible and no root cause is verified;
2. minimal Gateway merge-memory correction if avoidable amplification is verified;
3. evidence-justified Gateway resource adjustment if residual legitimate peak requires it and coexistence is safe;
4. minimal scheduler export/run-correlation guard if that failure boundary is verified;
5. combined changes only if independent evidence proves both are required and the expanded scope receives approval.

**Rationale**: This honors the smallest data-preserving fix rule and avoids speculative bundling.

**Alternative rejected**: Applying code optimization, limit increase, and scheduler changes together, which would obscure causality and increase rollback risk.

## Decision 9: Validate with existing tests plus bounded missing coverage

**Decision**: Reuse the following existing coverage:

- `tests/test_vps_gateway.py`: authentication/HMAC, pagination, ETag, cumulative merge, bounds, gzip;
- External export and local collection integration tests: schema, SHA, deterministic export, dedup/provenance, partial/failure behavior;
- `tests/test_backend_enhancements.py`: downstream ETag/idempotency;
- VPS topology and production deployment tests: network/volume/Tailscale/data-preservation boundaries.

Add only candidate-specific tests, isolation guard tests, and bounded resource validation.

**Known gaps to address where relevant**:

- representative large existing snapshot plus incoming merge under cgroup limit;
- snapshot preservation on induced candidate failure;
- lost-ACK-after-persist retry behavior;
- scheduler current-export correlation;
- malformed/truncated/over-limit stored snapshot handling if touched by the candidate.

**Alternative rejected**: A broad new test framework.

## Decision 10: Gate production and monitor exactly one workflow

**Decision**: After isolated success, present the exact candidate, evidence, expected impact, and targeted rollback limitations for explicit approval. After approval, use one chosen real workflow occurrence, not both a timer run and manual duplicate.

**Rationale**: The production workflow is data-producing and externally connected. One run is sufficient to prove the lifecycle and is the constitutionally required limit.

**Downstream handling**: First inspect whether the documented live mirror/pull automation actually exists. If it exists, observe one associated run. If it does not, separately approve one call through the existing authenticated downstream path; do not start another collection.

**Failure behavior**: Stop, preserve evidence, and report NO-GO. Do not rerun or auto-rollback.

## Decision 11: Rollback remains targeted, compatible, and separately approved

**Decision**: A rollback proposal must preserve `gateway_data`, External state, PostgreSQL, MISP, Tailscale, and systemd. Verify current snapshot compatibility before proposing an older image/config. Execution requires explicit approval.

**Rationale**: Repository operations guidance identifies a prior Gateway merge/compaction compatibility hazard. A generic downgrade may reintroduce the defect or mishandle the current cumulative snapshot.

**Alternative rejected**: Automatic image rollback, Compose down, volume recreation, or broad deployment-script rollback.

## Decision 12: Store only durable, sanitized evidence

**Decision**: Commit small evidence summaries and durable conclusions under the feature directory; keep large synthetic fixtures, raw production logs, transient IDs, current row counts, and secrets out of the repository.

**Rationale**: The constitution separates durable rules/continuation records from transient facts and forbids sensitive production data in reports and commits.

**Operational continuation**: After a meaningful verified checkpoint, update `IMPLEMENTATION_STATUS.md` with the verified boundary, candidate, validation status, readiness decision, and next safe action. Do not claim GO when downstream completion or resource safety remains unverified.

## Resolved unknowns

No planning-time clarification remains. Live status, exact root cause, measured peaks, host margin, and candidate choice are intentionally implementation evidence, not assumptions. Their absence now is represented by mandatory Phase 1–6 gates rather than an unresolved planning marker.

