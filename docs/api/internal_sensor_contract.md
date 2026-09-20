# Internal Sensor Gateway Contract

## Purpose

The VPS Gateway exposes three read-only JSON sensor streams to the central backend:

- `GET /api/v1/sensors/dionaea`
- `GET /api/v1/sensors/host-auth`
- `GET /api/v1/sensors/web-access`

The Gateway is bound to VPS loopback and is reached primarily through tailnet-only Tailscale Serve HTTPS. SSH forwarding remains a recovery fallback. This contract does not make the sensor API public.

## Authentication and integrity

- Request header: `Authorization: Bearer <sensor-read-token>`.
- Response header: `X-CTI-Signature: sha256=<hex-hmac>`.
- HMAC-SHA256 covers the exact response bytes.
- The backend verifies the signature before parsing JSON.
- Read tokens, HMAC secrets, URLs, and SSH information never appear in API responses, logs, or Git.

## Pagination

Query parameters:

- `limit`: bounded server-side page size.
- `cursor`: opaque signed continuation token returned by the previous page.

Response envelope:

```json
{
  "schema_version": "1.0",
  "sensor_id": "cti-vps:dionaea",
  "source_type": "dionaea",
  "generated_at": "2026-08-29T00:00:00Z",
  "items": [],
  "has_more": false,
  "next_cursor": null,
  "checkpoint": "opaque-signed-value"
}
```

The central `sources.config` stores only non-secret checkpoints. Raw events use stable identities so a repeated page cannot duplicate `raw_items`.

## Dionaea items

Dionaea items originate from official `log_json` JSONL and may contain connection type, protocol, transport, source/destination addresses and ports, timestamps, and bounded interaction metadata. Attempted passwords, tokens, authorization headers, and secrets are not copied into promoted CTI descriptions.

## Host-auth items

The systemd collector reads `journalctl` JSON and maps supported SSH outcomes such as failed, accepted, and invalid-user attempts. It emits source address, timestamp, outcome, method/user metadata where safe, and a stable event ID. Password values and reusable credentials are never collected.

## Web-access items

Gateway middleware records method, path, status code, duration, and source address. It excludes authentication headers, cookies, request bodies, query secrets, health probes, and the web-access stream's own read endpoint to avoid recursive logging.

The web-access JSONL stays at `/data/web_access.jsonl`. Gateway streams pages without
loading or rejecting an entire legacy file above the generic 50 MiB sensor limit.
Each page is capped at 8 MiB of normalized events, and signed cursors retain
absolute event offsets across compaction. An individual event above that limit
or a malformed legacy line fails explicitly (413/422); neither is silently
discarded.

The backend may commit a bounded partial batch when its page or cumulative-byte
limit is reached, then resume from its PostgreSQL-persisted checkpoint on the
next pull. Only that subsequent first pull sends `X-CTI-Ack-Cursor` plus a
purpose-separated HMAC of `web-access-ack:<cursor>` keyed by the existing sensor
read token. The token therefore authorizes both reading and acknowledgement;
treat it as an ingestion credential. Gateway validates the bearer token and
signature before atomically compacting only events strictly before the committed
offset. Unacknowledged events and absolute offsets remain intact; stale or
beyond-end cursors return 409. A failed acknowledgement replays, not drops,
evidence.

`MAX_WEB_LOG_BYTES` (64 MiB by default) bounds new appends. When an
unacknowledged backlog reaches capacity, loggable requests receive 503 with
`Retry-After` until collection/acknowledgement frees space. Health, all three
sensor reads, and external-feed read/publish are operational control-plane
routes deliberately excluded from web-access logging and remain available to
drain the backlog. A legacy file already above the cap is still readable.
There is no age-only or blind oldest-first deletion.

## Backend processing

All three streams map to the shared `RawRecord` contract. The backend stores raw evidence, builds 30-minute sessions, computes numeric features, runs Isolation Forest, retains every session, and promotes outlier sessions only to CTI events.

## Rejection rules

The Gateway/backend reject:

- missing or incorrect bearer tokens;
- missing or incorrect HMAC signatures;
- invalid/foreign/tampered cursors;
- unsupported schema/source type;
- oversized stored objects, pages, or page counts;
- non-JSON/invalid UTF-8 responses;
- URLs containing embedded credentials or unapproved cleartext transport.

## Acceptance evidence

Live acceptance verified healthy signed pages for all three streams. A later evidence snapshot recorded 57 retained sessions, 7 outliers, and 50 non-threat sessions, demonstrating outlier-only promotion rather than treating every log as a threat.
