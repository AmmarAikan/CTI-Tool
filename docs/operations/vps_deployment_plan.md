# VPS Deployment Record and Runbook

## Recorded deployment

The VPS deployment was completed on 2026-08-29 for the hybrid graduation lab. The server has 6 vCPU, 12 GB RAM, 200 GB SSD, Ubuntu 24.04, and an added 4 GB swap file. Large Docker images and the official MISP repository were downloaded directly on the VPS because its network is faster than uploading images from a personal computer.

This document intentionally omits the public IP, credentials, tokens, hostile source addresses, and raw honeypot evidence.

## Implemented host baseline

- Named non-root administrator with key-only SSH and sudo.
- Effective OpenSSH policy verified with `sshd -T`: password and keyboard-interactive authentication disabled; public-key authentication enabled; root limited to key-based recovery; X11 disabled.
- A configuration-order defect was found: cloud-init's earlier `PasswordAuthentication yes` overrode a later file. The project now installs `00-cti-hardening.conf`, removes the ineffective later file, reloads SSH, and verifies a second connection.
- UFW defaults to deny inbound and allows SSH plus selected Dionaea ports only.
- fail2ban, unattended upgrades, time synchronization, and swap are active.
- Docker Engine 29 and Compose 5 are installed.
- IPv6 is disabled by the documented sysctl policy because large GHCR pulls repeatedly reset over the provider's IPv6 path while IPv4 was stable. All project access uses IPv4.

## Deployed services

| Service | Deployment | Exposure | Acceptance |
|---|---|---|---|
| CTI Gateway | Project container | `127.0.0.1:8088` | Healthy; all three sensor streams ready |
| External Sources | Canonical project container | `127.0.0.1:8090` | Private job control and scheduled validated JSON publish |
| Dionaea | Project-built image | Selected public honeypot ports | Running; JSON returned through signed sensor API |
| SSH collector | systemd timer | No network listener | Active; bounded JSONL with safe auth metadata |
| MISP Core | Official slim image `v2.5.44` | `127.0.0.1:8080/8443` | Healthy; API version 2.5.44 |
| MISP Modules | Official slim image `v3.0.9` | Internal Docker network | Healthy |
| MariaDB | Official container | Internal Docker network | Healthy |
| Valkey/Redis | Official container | Internal Docker network | Healthy |
| Wazuh | Not deployed | None | Intentionally deferred/cancelled for current server |

The official MISP Docker repository is pinned to commit `223b675c4480730832f928e113b6f2e5260b450d`. Resource limits cap MISP Core at 4 GB, MariaDB at 2 GB, Modules at 1.5 GB, and Redis at 512 MB. The server had about 185 GB free before MISP and no swap pressure during acceptance.

For VPS-local Central Backend deployment, the dedicated network-only provisioner
creates the stable internal bridge networks `cti-backend-gateway` and `cti-backend-external`.
Each network is external to Compose and contains exactly Central Backend plus
its intended peer. Gateway mediates feed and sensor reads on its container port
8080; External Sources serves control reads on container port 8000. No database,
Redis, Tor, Dionaea, MISP, MISP Modules, or broad-egress service is attached to
these pairwise networks. MISP is explicitly deferred from this topology change
and Wazuh remains unconfigured. Existing hosts call the provisioner directly and
use Compose `build gateway external-sources` followed by
`up -d --no-deps gateway external-sources`; the full bootstrap and full-stack
deployment are not used for this narrow change. The restored experimental Backend
remains owned by transfer path
`/opt/cti-backend-transfers/20260903-v1/cti-backend-20260903-v1`, project
`cti-backend-20260903-v1`, and host binding `127.0.0.1:18000`; transfer-local
overrides must preserve those values and `/opt/cti-platform/current` is not its
controller.

## Deployment procedure

1. Transfer a versioned Git archive of the tracked project files; build large images directly on the VPS.
2. Point `/opt/cti-platform/current` to the selected release.
3. Run `bootstrap_host.sh`.
4. Run `deploy_stack.sh` to build Gateway/Dionaea on the server and install systemd/firewall/logrotate policies.
5. Run `deploy_misp.sh` to clone the pinned upstream repository, generate server-only secrets, pull slim images, start services, and wait for MISP heartbeat.
6. Securely copy Ammar's least-privilege backend fragment; keep it ignored by Git.
7. Join the VPS and Ammar's Windows computer to one tailnet, enable tailnet-only Tailscale Serve HTTPS for the loopback services, update the ignored client fragments, and launch the local backend. Keep the three SSH tunnels as a recovery fallback.

Exact commands and layouts are in `infra/vps/README.md`.

## Network policy

| Port/service | Bind/exposure | Purpose |
|---|---|---|
| SSH 22/TCP | Public, key-only | Named administration and recovery forwarding |
| Dionaea 21, 445, 1433, 3306, 5060, 11211/TCP | Public | Selected honeypot emulations |
| Dionaea 5060/UDP | Public | SIP honeypot emulation |
| Gateway 8088 | VPS loopback | Feed and sensor API through tailnet-only HTTPS |
| External control 8090 | VPS loopback | Source/job control through tailnet-only HTTPS `8444` |
| MISP 8080/8443 | VPS loopback | Browser/backend access through tailnet-only HTTPS `8443` |
| MariaDB, Redis, PostgreSQL | Container/private only | Owning applications only |

Docker-published ports require a `DOCKER-USER` policy in addition to UFW. New outbound flows from the sensor and gateway Docker subnets are dropped; established replies remain allowed.

## Secret separation

- `/etc/cti-platform/vps.env`: Gateway/sensor server secrets, root-only.
- `/etc/cti-platform/misp.env`: MISP/MariaDB/Redis/application secrets, root-only.
- Ammar backend fragment: feed/sensor read keys plus External control token only.
- External publishing uses the server-only publish token locally on the VPS; no second computer receives it.
- MISP backend fragment: MISP URL/API key only.
- `.vps-client.env` and `.misp-client.env` are ignored by Git. The obsolete `.vps-publisher.env` pattern remains ignored defensively but is no longer used.

No client receives another role's token.

## Live acceptance evidence

- Gateway, Dionaea, MISP Core, MISP Modules, MariaDB, and Redis were healthy.
- External controlled JSON was accepted, sanitized, pulled, and stored once; an identical re-pull returned `not_modified=true` with zero collected/stored.
- Dionaea live pull collected 777 records in the later acceptance run, built 30 sessions, and promoted 3 outliers.
- SSH-auth pull collected 53 records, built 11 sessions, and promoted one outlier.
- Web-access pull collected 6 records, built 2 sessions, and promoted no outliers.
- PostgreSQL contained 9,832 raw rows and 4,216 CTI events at the final evidence snapshot; 169 sessions consisted of 19 outliers and 150 retained non-threat sessions.
- The controlled External row appeared once and contained zero `api_token` keys after Gateway sanitization.
- MISP event delivery requested, added, and re-read two indicators; `published=false`. A second send added zero attributes.
- A time-ordering defect discovered during MISP acceptance was fixed in central persistence and MISP mapping. Existing controlled data was normalized and the database then reported zero invalid event/indicator time bounds.

Counts are a dated evidence snapshot and will naturally grow while the public honeypot runs.

## Failure findings and fixes

| Finding | Cause | Fix and regression evidence |
|---|---|---|
| GHCR image pulls reset | Provider path selected unreliable IPv6 | Persisted IPv4-only sysctl; pull then completed directly on VPS |
| SSH password policy initially ineffective | OpenSSH first-value precedence with cloud-init file | Early `00-` hardening file and effective-config verification |
| Dionaea restart loop | Missing runtime capabilities/tmpfs/working directory and empty named volume | Minimal capabilities, writable config tmpfs, correct workdir, forced initial data |
| Gateway health error | Permission exception when probing sensor path | Safe file check and supplementary read group |
| MISP event created without indicators | Invalid `first_seen > last_seen` and unverified embedded attribute behavior | Normalize bounds, insert missing attributes individually, read back and compare |
| Repeated External pull returned 422 | Completed dataset checkpoint was incorrectly reused as page cursor | Use ETag for new-run revalidation; next cursor only within the current pagination run |

## Operations and rollback

- Verify `tailscale status`, `tailscale ping`, and `tailscale serve status` after Windows or VPS network changes. Use the SSH tunnel script only for recovery.
- Check containers, systemd timers, disk, memory, swap, and `/health` before pulling.
- Rotate sensor JSON with the installed logrotate policy.
- Pin versions; do not upgrade MISP or Docker blindly.
- Take a provider snapshot before upgrades and make an encrypted off-host service backup.
- To roll back code, repoint `/opt/cti-platform/current` to a previously tested release and rerun its deployment script. Do not delete volumes during code rollback.

## Remaining acceptance

Off-host backup restoration, a separate disposable honeypot VPS, sustained-load retention measurements, Tailscale key-expiry/service monitoring, and enterprise-grade high availability remain future work. They are not required to demonstrate the current backend but must be completed before calling this an enterprise deployment.
