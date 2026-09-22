# Failure-boundary analysis: latest scheduled External collection failure

## Evidence basis

This analysis derives only from the sanitized Phase 1 record in [incident-timeline.md](./incident-timeline.md), the bounded production observations described there, and the existing publisher control flow in `infra/vps/scripts/run_external_collection.sh`. It does not infer success from container health or perform any retry, publish, state read, or production change.

## Lifecycle matrix

| Lifecycle checkpoint | Classification | Evidence and boundary decision |
|---|---|---|
| Scheduled start | verified-success | The timer triggered and systemd started the service at `2026-09-22T21:28:04Z`. |
| Collection terminal state | verified-failure | At `2026-09-22T21:37:34Z`, the publisher logged `state=failed` and systemd exited 1. This is the first verified failed boundary. |
| Durable current export | not-applicable | The existing publisher exits immediately for `failed`, before requesting an export. No export was created or inspected by this execution path. |
| Selected latest artifact matches run | not-applicable | Latest-export retrieval occurs only after a `completed` or `partial` collection state. |
| Gateway receive / validation | not-applicable | Gateway publish follows latest-export retrieval; neither was reached in the verified path. |
| Gateway merge | not-applicable | No Gateway request was issued by this failed invocation. |
| Gateway snapshot persistence | not-applicable | No Gateway request was issued by this failed invocation. Snapshot identity was not read. |
| Gateway ACK | not-applicable | No Gateway request was issued by this failed invocation. |
| Downstream pull | not-applicable | No Gateway publish occurred in this invocation. |
| Downstream processing | not-applicable | No Gateway publish occurred in this invocation. |
| Downstream checkpoint | not-applicable | No Gateway publish occurred in this invocation. |

## Root-cause conclusion

**Verified failure boundary:** External collection terminal state.

**Verified service-level cause:** the collection job returned the terminal state `failed`, and the existing publisher intentionally terminated with exit status 1 before export retrieval or Gateway publication.

**Underlying collector root cause:** **unverified.** The allowed bounded evidence does not identify a source-specific failure, job identifier, or collector error. It would be unsound to attribute that cause to Gateway memory, an export defect, or a scheduler defect.

## Alternative failure classes

| Failure class | Finding for this invocation | Reason |
|---|---|---|
| Collection state | verified-failure | Explicit terminal `failed` state in the bounded service journal. |
| Export | not-applicable | Publisher control flow stops before export retrieval. |
| Stale latest selection | not-applicable | No latest-export request was reached. |
| Transport / empty reply | not-applicable | No Gateway POST was reached. |
| Gateway validation / merge | not-applicable | No Gateway POST was reached. |
| Lost ACK after persistence | not-applicable | No Gateway POST or snapshot comparison occurred. |
| Resource exhaustion | unverified for this invocation | No bounded current-run OOM evidence. Historical curl 52/Gateway OOM evidence remains a separate documented incident. |
| Downstream failure | not-applicable | No Gateway publication occurred. |

## Stop condition and next safe action

No code, resource, or scheduler/export-correlation candidate is selected. The evidence does not reach the export-to-run or Gateway snapshot/ACK boundaries, and the collector's underlying cause is not identified. Stop after Phase 2 as authorized. Any follow-up must remain data-preserving, start with a new read-only investigation of the collector failure using a safely authorized non-secret evidence source, and must not replay this workflow merely to obtain more evidence.
