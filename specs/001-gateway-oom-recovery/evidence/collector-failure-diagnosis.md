# Collector failure diagnosis: 2026-09-22 scheduled workflow

## Scope and safety

This diagnosis used only repository code, non-secret operational documentation,
bounded systemd evidence, bounded External Sources stdout/stderr, and formatted
read-only Docker metadata. The incident window was
`2026-09-22T21:27:00Z..2026-09-22T21:39:00Z`.

No collection or publisher was run. No authenticated API call, environment or
secret inspection, container/service lifecycle action, Compose action, database
write, volume access, `/opt` write, payload read, or production mutation occurred.

## Verified production observations

| Observation | Classification | Sanitized evidence |
|---|---|---|
| External health before and during the job | verified-success | The bounded stdout window contained repeated successful health requests throughout the incident. Health does not prove job success. |
| Job acceptance | verified-success | One all-enabled job request was accepted at `2026-09-22T21:28:04Z`. |
| Job polling | verified-success | Status polling continued successfully until `2026-09-22T21:37:34Z`; the control path remained responsive. |
| Job terminal state | verified-failure | The scheduled publisher observed External collection `state=failed`; systemd exited with `Result=exit-code` and `ExecMainStatus=1`. |
| Publisher export retrieval | not-applicable | The publisher exits on `state=failed` before requesting the latest export. No export endpoint request occurred in the bounded stdout window. |
| Gateway publish, merge, persistence, and ACK | not-applicable | The publisher never reached its Gateway request. |
| External container process | verified-success during inspection | The existing container remained running and healthy, with no OOM-killed state and no restart since its pre-incident start. This rules out a container restart or container-level OOM as the observed terminal mechanism. |
| Collector/application failure details in stdout/stderr | unverified | The 138-line bounded window contained health/job-control access logs but zero application collector-failure, job-exception, or export-failure lines. |

## Repository-defined failure semantics

The existing all-enabled collection service isolates registered-source and Manual
root failures. Its normal aggregation returns:

- `failed` only when every attempted registered/manual operation has status
  `failed`;
- `partial` when at least one operation fails and at least one does not fail;
- `completed` when no operation fails.

An uncaught job-level exception can also set the in-process job to `failed`.
Examples of code boundaries that can propagate at job level include orchestration
around Manual capture; ordinary registered-source exceptions are converted to
isolated failed source results. Provider, network, Tor, parser, configuration,
and rate-limit errors can be represented as per-source safe failures.

An internal unified-export exception is caught and recorded as an export failure.
By itself it changes an otherwise completed aggregate to `partial`, not `failed`.
If all source operations were already failed, the aggregate remains `failed`.
Therefore export failure alone is not a sufficient explanation for this terminal
state.

The publisher's lack of export retrieval does **not** prove that the collection
service did not attempt or create its internal unified export. That internal
export outcome is unverified because no safe result body or application failure
log was available in the permitted evidence.

## Evidence limitation

Repository configuration routes internal job and source failure diagnostics to
`logs/cti_tool.log`; operations documentation states that this log persists in
the External logs volume. Under the later explicit root-level, read-only scope,
a bounded filtered read of the already-existing in-container log was performed.
The file was not copied, mounted, changed, or exposed verbatim.

The in-process job result could also distinguish all-source failure from an
uncaught job exception, but reading it requires the authenticated control path
or internal process state. Neither was authorized. The status response bodies
used by the scheduled script were held in its temporary runtime directory and
were removed by the existing cleanup behavior; they were not recovered or
recreated.


## Bounded internal application-log appendix

Only structured failure messages were read from `/app/logs/cti_tool.log`, after
converting local time to UTC and suppressing all sensitive identifiers, links,
and addresses. The source messages do not contain a `job_id` or `command_id`, so
they cannot be attributed conclusively to the scheduled job even though they
occurred inside its incident window.

| UTC time | Result | Inference boundary |
|---|---|---|
| 2026-09-22T21:32:20Z | A `cert`-class operation ended `partial` with `error_category=parsing_contract` and `retryable=False`. | A partial source/contract failure is verified, but correlation to the scheduled job is not. |
| 2026-09-22T21:33:53Z and 2026-09-22T21:34:15Z | Two `reddit`-class operations ended `failed` with `error_category=parsing_contract` and `retryable=False`. | Parser/contract failure is verified for those operations, but source and job identifiers were suppressed and correlation to the scheduled job is not established. |
| Bounded window through 2026-09-22T21:39:00Z | No `external job failed` message or export-failure message was clearly correlated to the job. | This does not prove that no exception occurred; the log does not provide a complete safe correlation between the job result and source messages. |

An `external job failed` message with `exception_type=TypeError` occurred after
the bounded incident window. It was therefore not used as evidence for this
incident's cause and MUST NOT be attributed to it.

If the partial `cert` message belonged to the scheduled job, normal aggregation
would have produced `partial`, not `failed`. This makes a fatal job-level
exception a viable possibility, but it is not verified because the permitted
messages lack `job_id`/`command_id` correlation. The evidence also cannot show
that all operations failed or that any one operation caused the exception.

## Updated conclusions

1. **Exact internal failing stage:** unverified. The only verified stage is that
   the `all_enabled` job ended `failed` before publisher export retrieval.
2. **Source/error class:** bounded evidence shows non-retryable
   `parsing_contract` errors for `cert` and `reddit` operations in the window;
   it does not establish that they caused the scheduled job failure.
3. **All operations versus fatal exception:** unverified. Normal all-operation
   failure aggregation and a fatal job-level exception remain possible; the
   uncorrelated partial operation prevents a conclusive distinction.
4. **Verified failure class:** job-state failure inside External Sources. This
   invocation did not reach Gateway, current-run OOM, or publisher export
   boundaries. A provider/network/Tor/parser/configuration/orchestration/export
   root cause remains unverified.
5. **Transient versus systemic:** the observed `parsing_contract` errors are
   non-retryable according to `retryable=False`, but the incident cannot be
   classified as external/transient or internal/systemic without job
   correlation.
6. **Candidate:** **NO-GO**. No specific code or configuration candidate can be
   selected.
7. **Remaining unverified points:** the safe job result correlated to this
   invocation, its operation identities, exception detail if present, and the
   internal export outcome.

## Diagnostic conclusions

1. **Collector/source or internal stage:** unverified. No specific registered
   collector, Manual root, or orchestration stage can be named from permitted
   evidence.
2. **Failure class:** unverified. Provider/network/Tor/parser/configuration
   failures across all operations and an uncaught job-orchestration exception
   remain viable. Export failure alone is not sufficient. Gateway failure and
   current-run container OOM are excluded from this invocation's observed path.
3. **Multiplicity:** unverified. Under normal aggregation, `failed` means every
   attempted operation failed; one isolated source failure with any other
   successful operation would have produced `partial`. The alternative is one
   fatal job-level exception. Available evidence cannot distinguish them.
4. **Exact verified boundary:** the failure occurred inside the accepted,
   responsive External Sources all-enabled in-process job, before the scheduled
   publisher's export-retrieval boundary. The narrower internal boundary is
   unverified.
5. **Candidate selection:** **NO-GO / unverified.** No code or configuration
   candidate can be selected without guessing between unrelated failure classes.

## Stop decision

Stop diagnosis here. Do not replay collection, run the publisher, enter Phase 3,
or select a Gateway, External, scheduler, resource, or configuration candidate.
Any further diagnosis requires separately authorized access to an existing safe
job-result or sanitized application-log source; it must not require production
mutation or expose records, source URLs, credentials, or secrets.
