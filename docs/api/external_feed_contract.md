# External Feed API Contract

## Purpose

This contract is the hand-off boundary between the VPS-hosted External Sources service and the backend that performs BERT NER, IoC extraction, correlation, scoring, and persistence. The collector and Gateway run as separate private services so the backend still receives one predictable JSON schema.

Contract version: `1.0`.

## Endpoint

```http
GET /api/v1/external-feed?limit=250&cursor=<opaque-cursor>
Authorization: Bearer <feed-read-token>
Accept: application/json
```

Production rules:

- Use HTTPS with a valid certificate.
- Keep the bearer token and HMAC secret outside Git.
- Give this client read-only access.
- Treat `cursor` and `checkpoint` as opaque strings; clients must not parse them.
- Return at most the requested `limit`, with a server-side upper bound.
- Do not expose the External control API or Gateway publicly. Both remain on VPS loopback and the backend reaches them through tailnet-only Tailscale Serve HTTPS. SSH forwarding remains a recovery fallback.

The implemented graduation lab binds the Gateway to VPS loopback. The scheduled publisher stays on loopback, while remote reads use a valid Tailscale-issued HTTPS certificate over an encrypted WireGuard data plane. The only cleartext hop is the same-host loopback proxy from Tailscale Serve to the Gateway. No public endpoint is enabled.

## VPS publisher endpoint

The VPS systemd publisher sends the completed JSON artifact to the loopback Gateway with a publish-only credential:

```http
POST /api/v1/external-feed/publish
Authorization: Bearer <feed-publish-token>
Content-Type: application/json
```

Modern publishers provide `external_job_id`, `export_run_id`, and `dataset_sha256` together. The Gateway stores each identity as an immutable batch and never merges another export into it. Reads and ACKs repeat all three fields. Pagination cursors are HMAC-bound to that identity and the immutable batch checkpoint. Historical snapshots without a complete identity remain an isolated protected backlog and are never silently acknowledged, rewritten, or discarded during migration.

## Durable delivery acknowledgement

After all pages and raw records have been committed to PostgreSQL, Central Backend sends:

```http
POST /api/v1/external-feed/ack
Authorization: Bearer <feed-read-token>
Content-Type: application/json
X-CTI-Ack-Signature: sha256=<HMAC-SHA256 of the exact request body>

{"checkpoint":"<64-character snapshot SHA-256>"}
```

The acknowledgement is accepted only while the checkpoint still matches the current snapshot. A stale checkpoint receives `409` and leaves every unacknowledged record protected. The operation is idempotent. The Gateway response is signed with the normal `X-CTI-Signature` response HMAC. A restricted `external_ids` subset may be supplied only for a verified one-time migration of records already proven byte-for-byte durable in PostgreSQL; normal consumers always acknowledge the complete snapshot.

## Scheduling and restart guarantees

Frontend-created exports use priority `100` and are claimed FIFO by creation time.
An adopted legacy Gateway snapshot uses priority `0`. Backlog work commits at most
one configured processing batch per claim, persists `processed_offset` in the same
database transaction as that batch, releases its lease, and then becomes eligible
for another claim.

At every claim boundary, all ready interactive operations precede every backlog
operation, regardless of the legacy `fairness_skips` value. When no interactive
operation is ready, the oldest backlog operation receives one committed batch and
releases its lease. The worker then checks the complete queue again before another
backlog batch. Scheduling never yields inside an open database transaction and an
in-flight batch is never interrupted.

## Response envelope

```json
{
  "schema_version": "1.0",
  "feed_id": "external-team-feed",
  "generated_at": "2026-08-24T00:00:00Z",
  "items": [
    {
      "external_id": "nvd:CVE-2026-12345",
      "source": "NVD",
      "source_type": "nvd",
      "title": "CVE-2026-12345 vulnerability report",
      "content": "The vulnerability may allow remote code execution.",
      "summary": "Optional short summary",
      "url": "https://example.invalid/advisory/CVE-2026-12345",
      "published_at": "2026-08-23T18:30:00Z",
      "collected_at": "2026-08-24T00:00:00Z",
      "category": "vulnerability",
      "tags": ["cve", "remote-code-execution"],
      "metadata": {
        "cve_id": "CVE-2026-12345",
        "collector": "nvd_api"
      }
    }
  ],
  "has_more": false,
  "next_cursor": null,
  "checkpoint": "opaque-checkpoint-20260824-0000"
}
```

Required envelope fields:

- `schema_version`: currently a `1.x` value.
- `feed_id`: stable identifier, 1-200 characters, unchanged between pages.
- `generated_at`: valid ISO-8601 timestamp.
- `items`: JSON array.

Required item rules:

- Each item must have a stable `external_id` or `id`. The same source record must keep the same identifier on every run.
- Each item must contain at least one of `content`, `summary`, or `title`.
- `source_type` should be one of the collector's meaningful types, for example `rss`, `crawler`, `nvd`, `api`, or `dark_web`.
- Timestamps should be ISO-8601 UTC values.
- Never put API keys, cookies, authorization headers, passwords, or private analyst notes in `metadata`.

The complete example is stored in `data/external_samples/remote_feed_envelope_sample.json`.

## Integrity signature

When `EXTERNAL_FEED_HMAC_SECRET` is configured, the provider signs the exact response bytes:

```text
X-CTI-Signature: sha256=<lowercase hex HMAC-SHA256>
```

Provider-side Python example:

```python
body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
signature = hmac.new(shared_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
return Response(
    content=body,
    media_type="application/json",
    headers={"X-CTI-Signature": f"sha256={signature}"},
)
```

The signature must be calculated after final serialization. Re-serializing the body after signing invalidates the signature.

## Pagination and idempotency

If another page exists, return:

```json
{
  "has_more": true,
  "next_cursor": "opaque-next-page-token"
}
```

The final page returns `has_more=false`. Every page must retain the same `ETag`; the backend rejects the whole batch if it changes during pagination. The backend sends `If-None-Match` on the next first-page request. A `304 Not Modified` response creates a completed zero-item run. The backend also saves the final checkpoint and ignores duplicate `(source, external_id)` items inside a pulled batch. Before BERT, PostgreSQL compares the stored processing-relevant fields and skips unchanged records; new or changed content is processed and upserted. Only after the database transaction and checkpoint commit succeed does the backend send the Gateway acknowledgement. Repeated delivery and acknowledgement are therefore idempotent without paying the model cost again.

## Failure behavior

The backend rejects the whole remote batch before persistence when:

- authentication or TLS fails;
- the response exceeds configured byte/page limits;
- JSON, schema version, timestamp, stable identifier, pagination, or HMAC validation fails;
- `feed_id`, `schema_version`, or `ETag` changes between pages.

One malformed remote batch therefore cannot partially contaminate the CTI database.
Failure before persistence cannot advance the Gateway acknowledgement. If persistence succeeds but the acknowledgement request fails, the saved ETag/checkpoint makes the next pull a safe idempotent ACK retry.

## Backend configuration and calls

```text
EXTERNAL_FEED_URL=https://feed.example.org/api/v1/external-feed
EXTERNAL_FEED_TOKEN=<read-only-token>
EXTERNAL_FEED_HMAC_SECRET=<separate-shared-secret>
EXTERNAL_FEED_VERIFY_TLS=true
EXTERNAL_FEED_ALLOW_HTTP=false
EXTERNAL_FEED_REQUIRE_CONTRACT=true
EXTERNAL_FEED_MAX_BYTES=104857600
EXTERNAL_FEED_MAX_PAGES=100
EXTERNAL_FEED_PAGE_SIZE=250
```

After Swagger authorization:

1. `GET /api/v1/integrations/external-feed/health`
2. `POST /api/v1/integrations/external-feed/pull`
3. Inspect `GET /api/v1/runs`, `/events`, `/indicators`, and `/ml/status`.

The health check validates reachability, JSON contract, and HMAC when enabled. It does not return configured URLs, usernames, or secrets.
