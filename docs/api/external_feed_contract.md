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
- Do not expose the External control API or Gateway publicly. Both remain on VPS loopback and the backend reaches them through SSH forwarding.

The implemented graduation lab binds the Gateway to VPS loopback and carries both publish and read traffic through SSH forwarding. Cleartext HTTP is therefore confined inside the encrypted SSH tunnel; a future public endpoint must use valid HTTPS.

## Collaborator publish endpoint

The VPS systemd publisher sends the completed JSON artifact to the loopback Gateway with a publish-only credential:

```http
POST /api/v1/external-feed/publish
Authorization: Bearer <feed-publish-token>
Content-Type: application/json
```

The body may be the versioned envelope or the accepted dataset/list shape produced by External Sources. The Gateway applies byte/item bounds, stable identity/content checks, timestamp validation, metadata secret-key removal, and an atomic write. The publish token cannot read sensors or access MISP. The response contains only acceptance status, feed identity, item count, and ETag.

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

The final page returns `has_more=false`. The provider should return `ETag`; the backend sends `If-None-Match` on the next first-page request. A `304 Not Modified` response creates a completed zero-item run. The backend also saves the final checkpoint and ignores duplicate `(source, external_id)` items inside a pulled batch. Database upserts make repeated delivery idempotent.

## Failure behavior

The backend rejects the whole remote batch before persistence when:

- authentication or TLS fails;
- the response exceeds configured byte/page limits;
- JSON, schema version, timestamp, stable identifier, pagination, or HMAC validation fails;
- `feed_id` or `schema_version` changes between pages.

One malformed remote batch therefore cannot partially contaminate the CTI database.

## Backend configuration and calls

```text
EXTERNAL_FEED_URL=https://feed.example.org/api/v1/external-feed
EXTERNAL_FEED_TOKEN=<read-only-token>
EXTERNAL_FEED_HMAC_SECRET=<separate-shared-secret>
EXTERNAL_FEED_VERIFY_TLS=true
EXTERNAL_FEED_ALLOW_HTTP=false
EXTERNAL_FEED_REQUIRE_CONTRACT=true
```

After Swagger authorization:

1. `GET /api/v1/integrations/external-feed/health`
2. `POST /api/v1/integrations/external-feed/pull`
3. Inspect `GET /api/v1/runs`, `/events`, `/indicators`, and `/ml/status`.

The health check validates reachability, JSON contract, and HMAC when enabled. It does not return configured URLs, usernames, or secrets.
