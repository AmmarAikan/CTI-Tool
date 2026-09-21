# Quickstart: Safe Validation Guide

## Status

This guide is an implementation-time validation runbook for the approved feature plan. No command in this guide was executed while creating the plan. It does not authorize production modification, deployment, restart, collection, rollback, or testing.

Command classes:

- **RO-PROD**: read-only production inspection; stop if a command would expose secrets or mutate state.
- **ISO**: isolated, disposable validation only; must not reference production paths, networks, volumes, secrets, or data.
- **APPROVAL**: production-affecting; do not run until the user explicitly approves the exact candidate and action.

## Prerequisites

Before implementation validation:

1. Read the constitution, specification, plan, research, contracts, and current `IMPLEMENTATION_STATUS.md`.
2. Confirm the repository branch is `codex/actit-final-production`.
3. Confirm no unrelated working-tree change overlaps the candidate.
4. Confirm `/opt/cti-platform` is read-only unless and until an exact production action is approved.
5. Confirm no collection/publish service is currently running before any isolated host workload is considered.
6. Identify the host cgroup version and safe metric files read-only.
7. Establish evidence/policy-derived host stop conditions; do not invent a fixed headroom percentage.
8. Use UTC timestamps and redact all secret or record content from evidence.

## Scenario 1: Read-only incident verification

**Class**: RO-PROD  
**Goal**: Identify the current failed invocation and reconcile it with the historical exit 52/OOM record without triggering work.

Safe metadata examples:

```bash
sudo systemctl show cti-external-collection.service \
  --property=Result \
  --property=ExecMainCode \
  --property=ExecMainStatus \
  --property=ActiveEnterTimestamp \
  --property=InactiveEnterTimestamp

sudo systemctl show cti-external-collection.timer \
  --property=LastTriggerUSec \
  --property=NextElapseUSecRealtime \
  --property=Result
```

Read a bounded journal window selected from the unit timestamps:

```bash
sudo journalctl \
  --unit=cti-external-collection.service \
  --since='<UTC start>' \
  --until='<UTC end>' \
  --no-pager
```

Read a bounded kernel window for OOM/cgroup evidence:

```bash
sudo journalctl --dmesg \
  --since='<UTC start>' \
  --until='<UTC end>' \
  --no-pager
```

For Docker, use safe formatted fields only after resolving the exact existing Gateway container read-only. Do not inspect or print its environment:

```bash
docker inspect \
  --format '{{.Name}} oom={{.State.OOMKilled}} restart={{.RestartCount}} memory={{.HostConfig.Memory}}' \
  '<resolved-gateway-container>'
```

**Do not run**:

- `systemctl start`, `restart`, `reset-failed`, or timer triggers;
- mutating Gateway or External API calls;
- `docker compose up/down/restart`;
- commands that dump container environment or root-only secret files;
- collection or publisher scripts.

**Expected outcome**: A sanitized incident record with systemd status/timestamps, last verified lifecycle stage, OOM/restart evidence, and an explicit note about any difference between the live event and `IMPLEMENTATION_STATUS.md`.

**Stop conditions**: Missing authorization, secret exposure risk, a required write, or inability to bound the evidence window. Record unavailable evidence rather than rerunning production.

## Scenario 2: Correlate the failure boundary

**Class**: RO-PROD  
**Goal**: Complete the lifecycle matrix defined by [recovery-evidence-contract.md](./contracts/recovery-evidence-contract.md).

Correlate safe identifiers and summaries for:

1. collection job terminal state;
2. current run export success/failure;
3. export manifest/dataset hash and counts;
4. artifact returned as latest;
5. Gateway snapshot before/after identity;
6. publish ACK or empty/lost reply;
7. downstream checkpoint/result.

Use existing authenticated read-only application paths and root-only operational mechanisms. Keep tokens out of command arguments, shell history, evidence, and output. Do not print record bodies.

**Expected outcome**: One verified failure boundary, or a declared ambiguous/unverified boundary that blocks candidate selection.

**Stop conditions**: If a partial job cannot be correlated with the selected export, or persistence cannot be distinguished from lost ACK, stop. Do not publish or retry.

## Scenario 3: Static regression tests

**Class**: ISO/local repository  
**Goal**: Verify existing contracts before a resource workload.

After implementation, run focused suites appropriate to the candidate:

```bash
python -m unittest tests.test_vps_gateway -v
python -m unittest tests.external_sources.integration.test_external_dataset_export -v
python -m unittest tests.external_sources.integration.test_local_collection_job -v
python -m unittest tests.test_backend_enhancements -v
python -m unittest tests.test_vps_local_network_topology -v
python -m unittest tests.test_vps_production_deployment -v
python -m unittest tests.test_gateway_recovery_compose -v
```

A scheduler-only guard does not justify unrelated heavy suites; a Gateway candidate must run the existing Gateway contract tests. Run the full repository suite only if the changed scope or existing project policy requires it.

**Expected outcome**: Existing authentication, bounds, cumulative merge, atomic preservation, ETag/idempotency, export durability, downstream checkpoint, and topology/data-safety behavior remain green.

**Stop conditions**: Any contract, security, topology, or data-preservation regression blocks the resource workload and production approval.

## Scenario 4: Isolated topology preflight

**Class**: ISO  
**Goal**: Prove the planned harness is disconnected from production before starting it.

After `compose.gateway-recovery-test.yml` exists:

```bash
docker compose \
  --project-name cti-gateway-recovery-test \
  --file compose.gateway-recovery-test.yml \
  config
```

Review the rendered result without writing it to a committed file. It must show:

- only the intended Gateway test service and monitoring helper if justified;
- synthetic secret inputs;
- loopback-only exposure;
- a uniquely named project network and disposable volume;
- no production network, volume, container, environment file, or bind path;
- no `/opt/cti-platform`;
- no provider egress requirement;
- an explicit bounded memory limit and health check.

The isolation test must fail closed if any forbidden path/name/network/volume is detected.

**Expected outcome**: Preflight PASS before any container starts.

**Stop conditions**: Any production reference, ambiguous resource name, insufficient host capacity, an active production collection/publish window, or inability to monitor cgroup/host pressure.

## Scenario 5: Generate the bounded fixture

**Class**: ISO  
**Goal**: Generate a deterministic synthetic existing snapshot and incoming export matching the representative merge shape.

After the fixture generator exists:

```bash
python scripts/generate_gateway_recovery_fixture.py \
  --profile representative-large-merge-v1 \
  --output-dir '<temporary-directory>'
```

The generator must enforce the current request, cumulative snapshot, and item bounds before writing. Capture only profile version, seed, item counts, byte counts, overlap count, and SHA-256 in evidence. Never commit the large files.

**Expected outcome**: `contains_production_data=false`, `external_egress=false`, deterministic hashes, and sizes/counts within the compatibility contract.

**Stop conditions**: Fixture exceeds a bound, resembles/copied production data, needs external access, or lacks deterministic identity.

## Scenario 6: One bounded baseline

**Class**: ISO  
**Goal**: Measure the unmodified Gateway once under the representative workload.

After the validation runner exists:

```bash
bash scripts/run_gateway_recovery_validation.sh baseline \
  --project-name cti-gateway-recovery-test \
  --fixture-dir '<temporary-directory>' \
  --evidence-dir '<temporary-evidence-directory>'
```

Capture the fields in [recovery-evidence-contract.md](./contracts/recovery-evidence-contract.md): request/snapshot sizes, counts, duration, status/ACK, hashes/ETag, current/peak memory, cgroup events, restart count, host availability/swap/pressure, and co-resident observations.

If the first publish completes safely, one identical repeat may verify unchanged/idempotent behavior. If it OOMs, restarts, times out, corrupts state, or creates unsafe host pressure, do not repeat it.

**Expected outcome**: A baseline measurement or one bounded verified failure. Baseline failure is evidence, not permission to increase resource limits.

**Stop conditions**: OOM, restart, unsafe pressure, co-resident degradation, timeout, integrity mismatch, or a monitor/evidence failure.

## Scenario 7: Candidate validation

**Class**: ISO  
**Goal**: Validate exactly the candidate selected from verified evidence, using the same fixture profile.

```bash
bash scripts/run_gateway_recovery_validation.sh candidate \
  --project-name cti-gateway-recovery-test \
  --fixture-dir '<temporary-directory>' \
  --evidence-dir '<temporary-evidence-directory>'
```

Run candidate-specific unit/regression tests first. Then run one bounded candidate publish and, only after safe success, one identical repeat for idempotency.

Compare baseline/candidate evidence:

- contract response and counts;
- pre/post snapshot validity, hash, and ETag;
- duration;
- idle/current and peak memory;
- OOM/restart events;
- host total/available memory, swap, and pressure;
- co-resident service safety;
- safety-margin rationale from measurements or an existing documented policy.

**Expected outcome**: Representative workload completes without OOM, unexpected restart, unsafe host pressure, or co-resident starvation; all contract and persistence checks pass.

**Stop conditions**: Any regression or unsafe resource observation. Do not tune through repeated workloads.

## Scenario 8: Exact isolated cleanup

**Class**: ISO  
**Goal**: Remove only disposable test resources after evidence is summarized.

First list resources for the exact project and verify their labels/names. Then use only the harness-provided scoped cleanup command. It may be equivalent to:

```bash
docker compose \
  --project-name cti-gateway-recovery-test \
  --file compose.gateway-recovery-test.yml \
  down --volumes
```

This command is acceptable only for the verified isolated project and its disposable volume. Never substitute the production project, a broad wildcard, or prune commands.

Delete temporary large fixtures only after their exact temporary path is validated. Keep sanitized small summaries.

**Expected outcome**: No isolated containers/network/volume/large fixtures remain; no production resource changed.

## Scenario 9: Approval package

**Class**: RO-PROD / documentation  
**Goal**: Obtain explicit user approval before any production-affecting action.

Present:

- verified root cause and lifecycle boundary;
- exact candidate digest/diff/config;
- affected existing components;
- data-preservation boundaries;
- tests and baseline/candidate measurements;
- total capacity, host pressure, co-resident safety, and derived margin;
- expected production impact, including whether a targeted Gateway restart is required;
- one-workflow monitoring window and stop conditions;
- targeted rollback compatibility/limitations;
- unresolved risk or unverified evidence.

Approval must name the exact candidate and scope. A candidate/scope change invalidates it. Activation approval does not authorize rollback.

**Expected outcome**: Explicit approval or NO-GO. Without explicit approval, stop.

## Scenario 10: Exactly one monitored production workflow

**Class**: APPROVAL  
**Goal**: After approval only, activate the exact candidate and observe one complete real lifecycle.

Before action:

1. Reconfirm the candidate digest and approved scope.
2. Reconfirm no second/manual workflow will overlap the selected timer occurrence.
3. Reconfirm all protected volumes/state and current snapshot compatibility.
4. Reconfirm the downstream mirror/pull automation actually present in live state.
5. Establish bounded monitoring and stop conditions.

Do not place generic deployment, restart, collection, or rollback commands in this guide. The approval package must provide the exact targeted commands for the approved candidate only.

Monitor one correlated sequence:

```text
one collection invocation
→ durable current export/state
→ selected export matches that invocation
→ Gateway validates, merges, atomically persists, and ACKs
→ one downstream pull/process/checkpoint completes
```

If downstream automation is absent, stop and obtain separate approval for one call through the existing authenticated pull path. That call must reuse the same published artifact and must not start another collection.

**Expected outcome**: Every required checkpoint is verified; no OOM/restart/unsafe host pressure/starvation; MISP receives no automatic share.

**Stop conditions**: Any failure or ambiguity. Preserve evidence and stop. No rerun and no automatic rollback.

## Scenario 11: Readiness and continuation update

**Class**: documentation  
**Goal**: Make an evidence-based readiness decision and update the durable continuation record.

Use [data-model.md](./data-model.md) and the evidence contract.

- **GO**: all lifecycle, resource, coexistence, security, contract, and data-preservation criteria verified.
- **NO-GO**: a required checkpoint failed.
- **PARTIALLY-VERIFIED**: required evidence is unavailable or incomplete.

Update `IMPLEMENTATION_STATUS.md` only after a meaningful verified checkpoint. Record durable conclusions, current readiness, evidence references, compatibility/rollback constraints, and the next safe action. Keep transient container IDs, current row counts, raw incidents, and secrets out.

A healthy endpoint, isolated-only success, or successful publish without downstream completion is not readiness.

