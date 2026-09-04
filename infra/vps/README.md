# CTI Hybrid VPS Operations

This directory contains the project-owned deployment for the graduation lab. Large images and upstream MISP source are downloaded and built on the VPS; only these small configuration files and scripts are transferred from a developer computer.

## Deployed boundary

- VPS: Ubuntu 24.04, Docker Engine, Compose, 4 GB swap, UFW, fail2ban, unattended upgrades.
- Public sensor: Dionaea on selected honeypot ports.
- Private services: CTI Gateway on `127.0.0.1:8088`; External Sources control on `127.0.0.1:8090`; MISP HTTP/HTTPS on `127.0.0.1:8080/8443`.
- Lightweight internal telemetry: Dionaea JSON, SSH journal events, and gateway web-access JSON.
- Local Ammar PC: FastAPI, PostgreSQL, DNRTI BERT primary model, sklearn fallback, correlation, risk, and final CTI API.
- VPS External Sources: canonical collectors, privacy/classification, versioned export, and a scheduled loopback publisher.
- Wazuh is not deployed in the current 12 GB VPS design. Its connector remains optional code only.
- Live Onion collection is not enabled: the current VPS has no Tor proxy or approved operational Onion list, so no placeholder dark-web configuration is mounted.

MISP, Gateway, and External control are never exposed publicly or bound to a public interface. Tailscale Serve terminates tailnet-only HTTPS and proxies to their VPS loopback listeners. SSH local forwarding remains an emergency fallback.

## Repository layout

- `compose.yaml`: Gateway, VPS External Sources, and Dionaea.
- `gateway/`: authenticated feed/sensor API with HMAC, ETag, cursor, bounds, redaction, cumulative stable-identity feed merging, and structured web telemetry.
- `collectors/`: lightweight SSH journal collector.
- `misp/compose.override.yaml`: resource limits and loopback-only ports over the official MISP Compose project.
- `scripts/bootstrap_host.sh`: host hardening and Docker prerequisites.
- `scripts/deploy_stack.sh`: builds and starts Gateway/External Sources/Dionaea and installs their timers on the VPS.
- `scripts/deploy_misp.sh`: pins and starts MISP and creates a least-privilege backend client fragment.
- `scripts/start_local_tunnels.ps1`: starts the three Windows SSH forwards for emergency fallback.
- `systemd/`, `logrotate/`, `sysctl/`: timers, firewall persistence, log rotation, and the documented IPv4-only registry workaround.

## First deployment

Use a versioned release directory such as `/opt/cti-platform/releases/<release-id>` and point `/opt/cti-platform/current` to it. Run as root on the VPS:

```bash
/opt/cti-platform/current/infra/vps/scripts/bootstrap_host.sh
/opt/cti-platform/current/infra/vps/scripts/deploy_stack.sh /opt/cti-platform/current
/opt/cti-platform/current/infra/vps/scripts/deploy_misp.sh /opt/cti-platform/current
```

The scripts generate secrets under `/etc/cti-platform/` with root-only permissions. Never copy those files into Git. They create scoped client fragments under `/opt/cti-platform/clients/` for secure transfer to the intended machine.

MISP is cloned directly on the VPS at pinned commit `223b675c4480730832f928e113b6f2e5260b450d` and uses `misp-core:v2.5.44-slim` and `misp-modules:v3.0.9-slim`. The images are pulled on the VPS, not uploaded from a personal computer.

## VPS-local Central Backend networks

Gateway and External Sources use two independently provisioned internal bridge
networks when Central Backend runs on the same VPS:

- `cti-backend-gateway`: Central Backend (`cti-backend`) and Gateway
  (`cti-gateway`) only.
- `cti-backend-external`: Central Backend (`cti-backend`) and External Sources
  (`cti-external-control`) only.

Both Compose projects declare these networks as external. The dedicated
`scripts/provision_backend_networks.sh` entry point creates them idempotently,
rejects Docker inspection failures, refuses incompatible networks, and rejects
unauthorized or duplicate attached service roles. `bootstrap_host.sh` calls this
entry point for new hosts; existing hosts call it directly without rerunning host
hardening. Database, Redis, Tor, Dionaea, MISP, and MISP
Modules must never join either network.

The generated Backend client fragment uses the service aliases and container
ports directly. Feed, Dionaea, host-auth, and web-access remain mediated by
Gateway on port 8080; External control uses External Sources on port 8000.
Tokens, HMAC verification, request bounds, and timeouts are unchanged. Plain
HTTP is explicitly allowed only for `EXTERNAL_CONTROL_API_URL` at
`cti-external-control:8000` and for `EXTERNAL_FEED_URL` and `DIONAEA_API_URL` at
`cti-gateway:8080`, because both hops are confined to the two internal pairwise
Docker networks. The generated fragment sets exactly
`EXTERNAL_CONTROL_ALLOW_HTTP=true`, `EXTERNAL_FEED_ALLOW_HTTP=true`, and
`DIONAEA_API_ALLOW_HTTP=true` for those targets. Remote Tailscale clients retain
HTTPS verification and `*_ALLOW_HTTP=false` as documented below.

MISP is outside this migration. Its URL, certificate verification setting, and
networks remain unchanged; if its existing route is unavailable, health must
continue to report it as configured but disconnected. Wazuh remains
unconfigured.

The Tailscale and SSH sections below describe remote-client and recovery paths.
They do not replace the VPS-local Gateway and External Sources pairwise path.

### Existing-host narrow rollout

Do not rerun the full bootstrap or full-stack deployment merely to apply these
networks. From an immutable candidate release, provision and validate the two
networks, regenerate the client fragment atomically, then reconcile only Gateway
and External Sources:

```bash
sudo /opt/cti-platform/releases/<candidate>/infra/vps/scripts/provision_backend_networks.sh
sudo /opt/cti-platform/releases/<candidate>/infra/vps/scripts/generate_backend_client_fragment.sh /etc/cti-platform/vps.env
sudo docker compose --env-file /etc/cti-platform/vps.env \
  -f /opt/cti-platform/releases/<candidate>/infra/vps/compose.yaml \
  build gateway external-sources
sudo docker compose --env-file /etc/cti-platform/vps.env \
  -f /opt/cti-platform/releases/<candidate>/infra/vps/compose.yaml \
  up -d --no-deps gateway external-sources
```

These commands do not select Dionaea, Tor, MISP, databases, or other services.
The normal `deploy_stack.sh` remains the complete first-deployment/reconciliation
entry point and is intentionally broader than this existing-host operation.

### Restored transfer Backend experiment

The currently restored experimental Backend is controlled by
`/opt/cti-backend-transfers/20260903-v1/cti-backend-20260903-v1`, not by
`/opt/cti-platform/current/compose.yaml`. Preserve Compose project
`cti-backend-20260903-v1`, container service `backend`, its existing database
volume, and host binding `127.0.0.1:18000`. Do not edit the transfer base Compose
or private environment files. Add reviewed transfer-local Compose and environment
overrides, render the complete model, and reconcile only the existing `backend`
service with `-p cti-backend-20260903-v1 --no-deps`. Never start a second Backend
project or bind another service to the existing host port. Do not advance
`/opt/cti-platform/current` during the experiment. After creating reviewed
transfer-local `compose.vps-local.override.yaml` and `vps-local.env`, render and
reconcile the existing project with the original private env files discovered
from its Compose provenance:

```bash
transfer_root=/opt/cti-backend-transfers/20260903-v1/cti-backend-20260903-v1
sudo docker compose -p cti-backend-20260903-v1 \
  --env-file <exact-original-backend-env> \
  --env-file "${transfer_root}/vps-local.env" \
  -f "${transfer_root}/compose.yaml" \
  -f "${transfer_root}/compose.vps-local.override.yaml" config --quiet
sudo docker compose -p cti-backend-20260903-v1 \
  --env-file <exact-original-backend-env> \
  --env-file "${transfer_root}/vps-local.env" \
  -f "${transfer_root}/compose.yaml" \
  -f "${transfer_root}/compose.vps-local.override.yaml" \
  up -d --no-deps backend
```

The rendered model must retain `127.0.0.1:18000:8000` before the second command
is authorized.

## Primary Tailscale path and backend

Install Tailscale on the VPS and Ammar's Windows computer, join both to the same tailnet, and enable unattended mode on Windows. Keep Funnel disabled. On the VPS, expose only the existing loopback services to the tailnet:

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8088
tailscale serve --bg --https=8444 http://127.0.0.1:8090
tailscale serve --bg --https=8443 https+insecure://127.0.0.1:8443
tailscale serve status
```

The `https+insecure` target is limited to the VPS loopback hop to MISP's private certificate. Clients still validate the Tailscale-issued HTTPS certificate. Use the VPS MagicDNS name in ignored client fragments:

```text
EXTERNAL_FEED_URL=https://<VPS_TAILNET_DNS>/api/v1/external-feed
EXTERNAL_CONTROL_API_URL=https://<VPS_TAILNET_DNS>:8444/api/v1/external-sources
DIONAEA_API_URL=https://<VPS_TAILNET_DNS>/api/v1/sensors/dionaea
HOST_AUTH_API_URL=https://<VPS_TAILNET_DNS>/api/v1/sensors/host-auth
WEB_ACCESS_API_URL=https://<VPS_TAILNET_DNS>/api/v1/sensors/web-access
MISP_URL=https://<VPS_TAILNET_DNS>:8443
```

Keep every `*_VERIFY_TLS=true` and every `*_ALLOW_HTTP=false`. Then start the local backend:

```powershell
tailscale ping <VPS_TAILNET_DNS>
docker compose --env-file .env --env-file .vps-client.env --env-file .misp-client.env up -d --build db backend
```

## SSH recovery fallback

From PowerShell:

```powershell
.\infra\vps\scripts\start_local_tunnels.ps1 -ServerHost <VPS_IP> -KeyPath <SSH_KEY_PATH>
docker compose --env-file .env --env-file .vps-client.env --env-file .misp-client.env up -d --build db backend
```

Forwarding is:

- `127.0.0.1:18088` -> VPS `127.0.0.1:8088` for feed/sensors.
- `127.0.0.1:18090` -> VPS `127.0.0.1:8090` for External source control/jobs.
- `127.0.0.1:18443` -> VPS `127.0.0.1:8443` for MISP.

Use these forwards only if Tailscale is unavailable. After Windows sleep, network changes, or a server restart, rerun the tunnel script. It refuses to replace an occupied port, waits up to 90 seconds for a slow SSH handshake, and enables SSH compression. `-RemotePort` exists for authorized recovery listeners; normal operation remains `ammar` on port `22`.

## Public and private ports

Public ingress is limited to SSH plus the intended Dionaea services: TCP `21`, `445`, `1433`, `3306`, `5060`, `11211`, and UDP `5060`. Gateway, External control, MISP, MariaDB, Valkey/Redis, PostgreSQL, and Docker management sockets are not public.

The `DOCKER-USER` policy allows established replies and drops new outbound connections from the honeypot and gateway subnets. This is a cost-constrained single-VPS lab boundary, not kernel-level isolation between physical hosts.

## Health and acceptance

On the VPS:

```bash
curl --fail http://127.0.0.1:8088/health
curl --fail http://127.0.0.1:8090/api/v1/external-sources/health
curl --insecure --fail https://127.0.0.1:8443/users/heartbeat
docker ps
systemctl is-active cti-ssh-collector.timer cti-external-collection.timer cti-storage-maintenance.timer cti-docker-firewall.service
```

On Ammar's PC, use the authenticated FastAPI endpoints:

```text
/api/v1/integrations/status
/api/v1/integrations/external-feed/pull
/api/v1/integrations/external-control/health
/api/v1/integrations/external-control/sources
/api/v1/integrations/external-control/jobs
/api/v1/integrations/dionaea/pull
/api/v1/integrations/host-auth/pull
/api/v1/integrations/web-access/pull
/api/v1/ml/status
/api/v1/dashboard/summary
/api/v1/events/{event_id}/stix
/api/v1/events/{event_id}/misp
```

An identical External Feed returns HTTP 304 and creates a completed zero-record run. A changed snapshot skips unchanged PostgreSQL records before BERT and processes only new or changed content. MISP sends are unpublished-first and verify every requested indicator after insertion; a repeated send adds zero duplicate attributes.

The External timer runs every two hours. Manual source addition and per-source collection are issued through the central FastAPI API, not by publishing the VPS adapter or enabling its Swagger UI.

## Storage retention

The upstream Dionaea all-level text log is disabled in the derived image because it can grow by more than 100 GB per day on a public SMB sensor. JSON incidents remain enabled. Host logrotate bounds warning/error text logs, while the daily storage timer retains bistreams for seven days and captured binaries for thirty days.

## Backup and restore boundary

Back up at least:

- `/etc/cti-platform/` through an encrypted, access-controlled channel;
- MISP MariaDB data, MISP files/attachments, GPG data, and configuration;
- `/var/lib/cti-sensors/` if evidence retention requires it;
- local PostgreSQL with `pg_dump`;
- provider snapshot before upgrades, while keeping a separate off-host backup.

A backup is not accepted until it has been restored on a disposable test instance. Live restore testing and a second physical honeypot host remain future work.

## Safety

Do not execute captured payloads. Do not expose the Gateway or MISP loopback ports publicly. Do not publish synthetic acceptance events in MISP. Rotate client tokens if a local secret fragment is disclosed, and preserve only sanitized counts in public reports.
