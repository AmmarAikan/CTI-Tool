# MISP Population Runbook

This runbook governs a future, explicitly approved population of ACTIT's MISP
sharing destination. PostgreSQL remains authoritative. MISP is not a replica,
and this procedure does not authorize automatic mirroring or publication.

## Preconditions and approval gate

1. Deploy and validate the immutable release that contains the reviewed MISP
   candidate queue and batch workflow. Deployment requires its own explicit
   approval and is outside this runbook.
2. Obtain a new explicit approval for the exact population window. Record the
   approved release, operator, time window, candidate-snapshot digest, and
   maximum event count. Approval for deployment is not approval for delivery.
3. Confirm Central Backend and MISP health through their authenticated,
   read-only health paths. Confirm that MISP is configured and reachable.
4. Page through the Central candidate queue and build an ordered snapshot of
   events whose current reason is `ready`. Exclude events with a verified prior
   successful delivery unless the approval explicitly requests an idempotency
   re-verification. Hash the ordered event-ID list and record only the count and
   digest in the operational checkpoint.
5. Re-open the preview for each selected event. Stop if the event is no longer
   ready, the included-attribute count is zero, or the snapshot digest changes.

The number of batches is `ceil(approved_pending_event_count / 20)`. A batch may
contain at most 20 unique event IDs. Do not pad a final partial batch, combine
unreviewed events, or run concurrent batches.

## Monitored batch procedure

For each ordered batch:

1. An authenticated administrator selects at most 20 ready events in the ACTIT
   MISP candidate queue and reviews their filtered previews and omission reasons.
2. The administrator accepts the explicit unpublished-delivery confirmation.
   The request must carry `confirm_unpublished=true`; the API rejects any other
   value. Submit the batch exactly once.
3. Wait for the bounded response. Record its batch ID and aggregate counts, not
   event content or credentials. Every requested event must have one independent
   `delivered`, `skipped`, or `failed` outcome and a corresponding audit entry.
4. Verify that every delivered event reports `published=false`. For delivered
   events, verify the returned MISP identity and attribute verification counts.
   Deterministic event and attribute UUIDs make an explicitly approved repeat
   idempotent, but they do not authorize an automatic retry.
5. Continue only when all outcomes match the approved scope and MISP and Central
   remain healthy. Recompute remaining counts after each batch without changing
   PostgreSQL source data.

## Mandatory stop conditions

Stop the population window immediately on any failed or unexpected skipped
outcome, publication, identity mismatch, missing audit entry, attribute
verification mismatch, candidate/snapshot drift, authentication failure,
transport failure, unsafe host pressure, MISP health degradation, or operator
uncertainty. Do not retry or roll back automatically. Preserve all PostgreSQL,
MISP, Docker volume, and audit state, capture sanitized evidence, and request a
new approval for any changed scope or retry.

## Completion evidence

Completion requires all of the following:

- the approved pending count reaches zero;
- successful unique delivery identities equal the approved snapshot count;
- every batch contains at most 20 unique event IDs and has one batch audit plus
  per-event outcomes;
- every delivered MISP event remains unpublished;
- no event is counted complete solely because an HTTP request succeeded; and
- `IMPLEMENTATION_STATUS.md` records the sanitized counts, snapshot digest,
  batch outcome totals, residual limitations, and next safe action.
