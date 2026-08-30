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

MISP, Gateway, and External control are never exposed directly. The local backend reaches them through SSH local forwarding.

## Repository layout

- `compose.yaml`: Gateway, VPS External Sources, and Dionaea.
- `gateway/`: authenticated feed/sensor API with HMAC, ETag, cursor, bounds, redaction, cumulative stable-identity feed merging, and structured web telemetry.
- `collectors/`: lightweight SSH journal collector.
- `misp/compose.override.yaml`: resource limits and loopback-only ports over the official MISP Compose project.
- `scripts/bootstrap_host.sh`: host hardening and Docker prerequisites.
- `scripts/deploy_stack.sh`: builds and starts Gateway/External Sources/Dionaea and installs their timers on the VPS.
- `scripts/deploy_misp.sh`: pins and starts MISP and creates a least-privilege backend client fragment.
- `scripts/start_local_tunnels.ps1`: starts the three required Windows SSH forwards.
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

## Local tunnels and backend

From PowerShell:

```powershell
.\infra\vps\scripts\start_local_tunnels.ps1 -ServerHost <VPS_IP> -KeyPath <SSH_KEY_PATH>
docker compose --env-file .env --env-file .vps-client.env --env-file .misp-client.env up -d --build db backend
```

Forwarding is:

- `127.0.0.1:18088` -> VPS `127.0.0.1:8088` for feed/sensors.
- `127.0.0.1:18090` -> VPS `127.0.0.1:8090` for External source control/jobs.
- `127.0.0.1:18443` -> VPS `127.0.0.1:8443` for MISP.

After Windows sleep, network changes, or a server restart, rerun the tunnel script. It refuses to replace an occupied port, waits up to 90 seconds for a slow SSH handshake, and enables SSH compression. `-RemotePort` exists for authorized recovery listeners; normal operation remains `ammar` on port `22`.

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
