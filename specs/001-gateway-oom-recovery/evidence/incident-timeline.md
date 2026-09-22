# Incident timeline: latest scheduled External collection failure

## Scope and handling

- **Incident key**: `scheduled-collection-2026-09-22T212804Z`
- **Observation window**: `2026-09-22T21:27:00Z` to `2026-09-22T21:39:00Z`
- **Collection method**: Read-only systemd metadata, a bounded filtered service journal, a bounded filtered kernel journal, formatted Docker metadata, and host memory/PSI files.
- **Safeguards observed**: No service, timer, container, or job was started, restarted, triggered, or otherwise changed. No Compose command, production-state read, environment inspection, export retrieval, Gateway request, or secret-bearing command was used.

## Sanitized incident record

```yaml
incident:
  observed_window_utc: "2026-09-22T21:27:00Z..2026-09-22T21:39:00Z"
  service_result: "exit-code"
  exec_main_code: 1
  exec_main_status: 1
  last_verified_stage: "collection_terminal_state"
  gateway_oom: "not-observed in the bounded current-run kernel window"
  gateway_restart_delta: "unavailable; no pre-run counter was captured"
  documentation_discrepancy: >-
    IMPLEMENTATION_STATUS.md records a historical 2026-09-18 curl exit 52 and
    Gateway OOM. The latest verified 2026-09-22 invocation instead exited 1
    after External collection reported state=failed. These are distinct events;
    the historical OOM is not treated as the cause of this invocation.
  evidence_sources:
    - "systemd service and timer metadata, read 2026-09-23"
    - "filtered service journal, 2026-09-22T21:27:00Z..2026-09-22T21:39:00Z"
    - "filtered kernel journal, same window"
    - "formatted Docker state and host memory/PSI observations, post-window"
```

## Observations

| Checkpoint | Result | Sanitized evidence | Interpretation limit |
|---|---|---|---|
| Timer invocation | verified-success | The timer's last trigger and the service start both correspond to `2026-09-22T21:28:04Z`. | Timer activation does not prove a complete workflow. |
| Scheduled service | verified-failure | systemd reported `Result=exit-code`, `ExecMainCode=1`, and `ExecMainStatus=1`; it exited at `2026-09-22T21:37:34Z`. | The status identifies termination, not an underlying collector cause. |
| Collection terminal state | verified-failure | The bounded service journal contains `external collection ended in state=failed` at `2026-09-22T21:37:34Z`. | No safe job identity, source-level error, or collector detail was present in the bounded output. |
| Export retrieval / latest selection | not-reached | The deployed publisher's existing control flow exits for any terminal state other than `completed` or `partial`, before its latest-export request. | No export manifest, dataset identity, or selected-latest correlation was obtained. |
| Gateway publish / ACK | not-reached | The same control flow performs the Gateway POST only after latest-export retrieval; no such journal line appeared. | This run provides no Gateway receive, merge, persistence, or ACK evidence. |
| Current-run OOM | not-observed | The bounded kernel journal contained no OOM, memory-cgroup, killed-process, or Gateway line. | Absence in this bounded evidence is not proof that Gateway is generally safe. |
| Gateway / External state | verified-success at inspection time | Formatted read-only container metadata showed both services running; Gateway's configured limit was 512 MiB and External Sources' was 2 GiB. | Current health/state does not prove the failed workflow completed. Cumulative Gateway restarts were non-zero, but no before/after counter established a delta for this run. |
| Host pressure | post-window observation only | At inspection, available host memory was present, swap was largely free, and instantaneous memory PSI averages were zero. | These values were not captured during the failed run and cannot establish resource safety or reject historical OOM evidence. |

## Unavailable correlation, deliberately not pursued

The bounded service journal held only lifecycle/terminal-state lines. Safe job status, current-export manifest/latest-export identity, Gateway snapshot identity, and downstream checkpoint identity/counts were therefore **unverified**. Obtaining them through the authenticated production application paths would require accessing control credentials or making additional production requests; that was outside this read-only, no-secret run. No attempt was made to read environment files, attach a volume, copy data, replay a publish, or trigger another collection.

## Data-preservation statement

PostgreSQL, MISP, Gateway state, External state, Docker volumes, Tailscale, systemd automation, and `/opt/cti-platform` remained unchanged. This document contains no payload, secret, raw journal, container identifier, record count, or transient process identifier.
