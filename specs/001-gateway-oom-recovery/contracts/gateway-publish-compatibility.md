# Contract: Gateway Publish Compatibility

## Status

This is a compatibility contract for the recovery work. It does not define a new endpoint or authorize implementation. The existing API documentation and implementation remain authoritative where this document is silent.

## Existing boundary to preserve

- Publisher endpoint: `POST /api/v1/external-feed/publish`
- Producer: existing External Sources scheduled publisher
- Consumer: existing Gateway
- Persistent state: current Gateway snapshot in the existing `gateway_data` volume
- Downstream: existing authenticated Gateway read/pull path and PostgreSQL processing
- Transport/security: existing loopback/private-network exposure, authentication/HMAC controls, request bounds, validation, rate limiting, safe logging, and reverse-proxy trust

No replacement Gateway, queue, alternate datastore, public endpoint, or unauthenticated path may be introduced.

## Request compatibility

A candidate MUST continue to accept the existing validated External export envelope and content encodings already supported by the Gateway.

It MUST preserve:

- versioned contract validation;
- required nullable fields;
- source-specific metadata placement;
- existing request-size, cumulative-size, and item-count bounds;
- existing authentication and HMAC verification order/semantics;
- safe rejection of malformed, unauthorized, oversized, or unsupported input;
- no sensitive request payloads in logs.

A recovery candidate MUST NOT require a new publisher payload, schema version, authentication method, or client dependency unless separately specified and approved.

## Merge compatibility

For each accepted item identity, the candidate MUST preserve the current cumulative merge rules:

- new identities are inserted;
- existing identities with changed canonical content are updated;
- identical existing identities are unchanged;
- valid previously stored items absent from the incoming export remain retained;
- output ordering and canonical serialization remain deterministic;
- the stored artifact remains valid against the existing contract and bounds.

The candidate MUST NOT change External-only deduplication ownership or perform new cross-team deduplication.

## Persistence compatibility

A publish is state-safe only when the snapshot is observably old or new, never partial.

The candidate MUST:

- write through the existing Gateway persistence boundary;
- preserve atomic replacement semantics;
- keep the existing snapshot intact on validation, bounds, merge, or pre-replacement failure;
- avoid truncation/corruption on OOM or process termination as far as the operating system's atomic-replace guarantee permits;
- preserve existing volume contents across image/config activation and rollback consideration;
- make no PostgreSQL, MISP, External state, or schema migration.

If the connection ends before ACK, operators MUST compare safe snapshot identity/ETag/count evidence before deciding whether a retry is needed.

## Accepted response compatibility

A successful accepted publish continues to return the existing accepted status and fields:

```json
{
  "status": "accepted",
  "feed_id": "<existing feed identity>",
  "item_count": 0,
  "published_items": 0,
  "inserted": 0,
  "updated": 0,
  "unchanged": 0,
  "etag": "<existing ETag format>"
}
```

Field meanings, types, and status code remain compatible with the current Gateway implementation. No recovery-only response shape may replace them.

## Error compatibility

Existing safe error behavior remains:

- authentication failures do not reveal credential details;
- validation/bounds failures do not alter the stored snapshot;
- server/resource failures do not claim acceptance;
- logs omit secrets and sensitive feed content;
- an empty/lost reply is treated as ambiguous persistence until read-only identity evidence resolves it.

A candidate MUST NOT convert a failed or ambiguous request into a false successful ACK.

## Read and downstream compatibility

Existing Gateway read behavior, pagination, ETag/conditional behavior, and downstream checkpoint semantics remain unchanged. After a successful publish:

- downstream sees a valid cumulative snapshot;
- an identical repeat does not create duplicate processing;
- unchanged ETag/checkpoint behavior remains valid;
- PostgreSQL stays authoritative;
- MISP receives no automatic replica synchronization.

## Resource and timing compatibility

The representative publish and merge MUST complete within existing operational client/server timeouts. Resource success is not a fixed percentage; it requires measured evidence that the candidate completes without OOM, unexpected restart, unsafe host pressure, or starvation of co-resident ACTIT services.

## Contract verification

Reuse and extend existing coverage for:

- authenticated/HMAC publish;
- invalid/oversized request rejection;
- cumulative insert/update/retain/unchanged counts;
- deterministic ETag and pagination/read behavior;
- atomic preservation on failure;
- identical retry/idempotency;
- gzip behavior where currently supported;
- downstream unchanged/checkpoint behavior;
- representative bounded cgroup merge validation.

Any observable contract change requires a separate specification and approval; it is not part of this recovery.

