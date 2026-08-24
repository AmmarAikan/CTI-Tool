# Dionaea Sensor API Contract

## Purpose

The cloud honeypot keeps Dionaea's official JSON incidents as raw evidence. Wazuh may also monitor and alert on the same sensor, but the raw Dionaea API is a separate input so SIEM transformation does not replace the original evidence.

```http
GET /api/v1/dionaea/events?limit=500&cursor=<opaque-cursor>
Authorization: Bearer <sensor-read-token>
Accept: application/json
```

Production requirements:

- Restrict the endpoint to the WireGuard network or a strict IP allow-list.
- Use HTTPS, a read-only bearer token, response byte/page limits, and HMAC-SHA256.
- Read from a rotated, append-only Dionaea JSON log. The API must never expose arbitrary filesystem paths.
- Never expose captured credentials through a public endpoint or browser UI.

Response contract:

```json
{
  "schema_version": "1.0",
  "sensor_id": "dionaea-vps-1",
  "generated_at": "2026-08-24T00:00:00Z",
  "events": [
    {
      "timestamp": "2026-08-24T00:00:00Z",
      "connection": {
        "protocol": "httpd",
        "transport": "tcp",
        "type": "accept"
      },
      "src_ip": "192.0.2.25",
      "src_port": 50000,
      "dst_ip": "172.30.0.2",
      "dst_port": 80
    }
  ],
  "has_more": false,
  "next_cursor": null,
  "checkpoint": "opaque-sensor-offset-101"
}
```

The `X-CTI-Signature` calculation is identical to the external feed contract: HMAC-SHA256 over the exact response bytes. Pagination requires a new opaque `next_cursor` while `has_more=true`. The backend saves the final checkpoint and deduplicates normalized event identifiers.

Backend calls after authorization:

1. `GET /api/v1/integrations/dionaea/health`
2. `POST /api/v1/integrations/dionaea/pull`
3. Inspect `/runs`, `/outliers`, `/events`, and `/dashboard/summary`.

The local Docker-only Dionaea profile and file upload remain available for an isolated demonstration even when the VPS sensor is offline.
