# VPS External Sources Operations

## Purpose

External Sources runs continuously on the VPS instead of depending on a collaborator computer. The canonical collectors, preprocessing, privacy checks, External-only deduplication, review records, and versioned export remain unchanged. The deployment changes only their runtime location and transport.

The VPS service is bound to `127.0.0.1:8090`. It is never a public collector API. Ammar's authenticated FastAPI backend reaches it through SSH forwarding on local port `18090`, and the frontend uses only the central FastAPI routes.

## Data flow

```text
VPS External Sources
-> validated run-scoped JSON export
-> scheduled host publisher
-> VPS Gateway cumulative, deduplicated snapshot
-> SSH tunnel + Bearer + HMAC
-> Ammar FastAPI
-> BERT / Regex / PostgreSQL / correlation / STIX / MISP
```

The systemd timer runs an `all_enabled` collection every two hours. It polls the bounded job API, downloads Latest Export only after a completed or partial terminal state, and publishes it to the Gateway with the existing scoped publish credential. The Gateway merges that incremental export into a bounded snapshot by stable external identity, so a backend that was offline does not miss an earlier run. An unchanged backend pull uses ETag/HTTP 304 and creates no duplicate CTI records. If the snapshot changes, PostgreSQL skips semantically unchanged records before BERT and processes only new or changed content.

Large feed pages are GZip-compressed by the Gateway while their HMAC continues to cover the canonical decompressed JSON body. The Windows SSH tunnel also enables transport compression. This matters because the first accepted live export contained thousands of records and an uncompressed tunnel was both slow and vulnerable to a transient network reset before the database transaction began.

## Live source behavior

The first VPS `all_enabled` acceptance run completed as `partial`, not failed: 14 of 17 enabled registered sources completed, 1,803 External-only deduplicated records were exported from 1,985 accepted source observations, 182 duplicates were removed, 68 records were routed to review, and the Gateway accepted the validated JSON. Per-source isolation kept the successful evidence when three providers failed.

Two provider failures were corrected and verified through the central authenticated API:

- GitHub Global Advisories rejected fractional-second `modified` filters with HTTP 422. The connector now sends whole-second ISO-8601 values; the live retry completed with 494 accepted, 6 review, and 0 errors.
- NVD returned more than 6 MB for a 2,000-record page, correctly exceeding the 5 MB client bound. Pages are now limited to 100 and continued by checkpointed pagination; the live retry completed with 498 accepted, 2 review, and 0 errors.

The CISA advisory HTML and RSS hosts return HTTP 403 from the current Contabo address, while the separate official CISA KEV JSON feed completes. The collector keeps this as an honest isolated provider failure; it does not bypass the provider WAF, impersonate a browser, or relay the request through an unapproved proxy.

Historical run artifacts remain in the External volume. During cumulative-feed migration, five validated exports containing 1,803, 445, 410, 874, and 880 run-scoped records were replayed oldest-to-newest. Stable-identity merging produced 4,184 unique snapshot records; replaying the final 880-record export inserted zero new records, updated 119, and left 761 unchanged. This is acceptance evidence for both retention and cross-run deduplication, not a claim that every provider completed: CISA advisories remained the isolated failed source.

## Private service addresses

| Service | VPS loopback | Ammar local tunnel |
|---|---|---|
| Gateway feed/sensors | `127.0.0.1:8088` | `127.0.0.1:18088` |
| External control API | `127.0.0.1:8090` | `127.0.0.1:18090` |
| MISP | `127.0.0.1:8443` | `127.0.0.1:18443` |

No PostgreSQL, Gateway, External control, MISP, Docker API, or collector documentation port is public.

## Scheduling and manual control

Scheduled collection:

```bash
systemctl status cti-external-collection.timer
journalctl -u cti-external-collection.service --since today
```

Authorized manual run on the VPS:

```bash
sudo systemctl start cti-external-collection.service
```

From the central authenticated FastAPI API, the frontend can:

```text
GET  /api/v1/integrations/external-control/health
GET  /api/v1/integrations/external-control/sources
POST /api/v1/integrations/external-control/jobs
POST /api/v1/integrations/external-control/sources/{source_id}/jobs
GET  /api/v1/integrations/external-control/jobs/{job_id}
POST /api/v1/integrations/external-control/manual-sources
POST /api/v1/integrations/external-control/manual-sources/recheck
GET  /api/v1/integrations/external-control/exports/latest
```

The central `exports/latest` operation uses the VPS summary route, not the full dataset response. The full validated dataset remains inside the VPS publish path, preventing a large JSON transfer merely to render frontend status.

Mutating operations require an `admin` or `analyst` JWT and are written to the central audit log. The VPS adapter still performs URL policy, SSRF, privacy, classification, source-state, and contract validation. The central API never returns the VPS control token or local artifact paths.

## Adding sources

For an operator-provided public URL, use the Manual Sources endpoint. It performs canonical routing and can reuse a registered connector when the URL matches one. Unknown or unsafe local/private URLs fail closed.

Registered scheduled sources remain committed in `config/sources.json` so changes are reviewed, tested, and reproducible. The current VPS has no Tor proxy or approved live Onion list, so the External container deliberately does not mount an Onion configuration. Enabling live Onion collection later requires an explicit Tor endpoint, a root-only source file, an intentional container mount, and separate live acceptance evidence; the committed example remains disabled and is not operational evidence.

## Secrets

`/etc/cti-platform/vps.env` contains the External control token and existing Gateway secrets with mode `0600`. Ammar receives a generated client fragment containing only the read/control values required by the local backend. The obsolete collaborator publisher fragment is removed.

Never commit `/etc/cti-platform/vps.env`, `.vps-client.env`, any future real Onion configuration, or provider credentials.

## Resource and retention policy

The External container has a 2 GB memory limit, 2 CPU limit, read-only root filesystem, no Linux capabilities, `no-new-privileges`, and an independently persisted data volume. A publish request is limited to 20 MB; the cumulative Gateway snapshot is limited to 100 MB and 20,000 items. The local reader uses matching bounded limits of 100 MB and 100 pages of at most 250 records.

Dionaea JSON incidents remain the authoritative sensor evidence. The verbose upstream `dionaea.log` is restricted to warning/error and rotated at 25 MB with four compressed rotations. Bistreams older than seven days and captured binaries older than thirty days are deleted by `cti-storage-maintenance.timer`. Captured payloads are never executed.

## Acceptance

A deployment is accepted only when the External container is healthy and loopback-only, source listing works through the central authenticated API, a bounded collection is published and pulled, an identical repeat creates no duplicates, unsafe tokens/URLs are rejected, and timer/storage evidence is recorded.
