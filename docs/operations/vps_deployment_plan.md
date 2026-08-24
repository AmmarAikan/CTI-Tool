# VPS Deployment and Acceptance Plan

## Current status

Prepared locally:

- authenticated external feed client and strict JSON contract;
- authenticated Wazuh Indexer client with bounded `search_after` pagination;
- authenticated Dionaea raw JSON sensor client;
- MISP health, dry-run, deterministic event/attribute mapping, and unpublished send path;
- integration health/pull APIs and safe configuration placeholders;
- automated tests that do not contact production services.

Not yet performed:

- VPS purchase and SSH access;
- DNS, WireGuard, TLS certificates, firewall, Wazuh, MISP, or public Dionaea deployment;
- real service credentials and end-to-end evidence.

No document should describe those remote items as completed before live verification.

## Capacity gate before purchase

Do not select the linked Cloud VPS 4 for all three platforms. Its current 4 vCores, 8 GB RAM, and 100 GB SSD are essentially Wazuh's own published single-node minimum. MISP adds MariaDB, Redis, modules, workers, and web services. The official MISP Docker project currently requires Docker Engine 25+ and Compose 2.17+ and recommends pinning the desired image build/tag for production.

Preferred layout:

1. Wazuh + MISP server: at least 8 vCores, 24 GB RAM, 300 GB SSD/NVMe.
2. Dionaea: separate small disposable VPS/VM with no sensitive services.

Cost-constrained layout:

1. Start Wazuh on Cloud VPS 4 and measure memory/disk.
2. Keep MISP off that host until resources are upgraded.
3. Keep the public honeypot separate.

Upstream references: [Wazuh Docker prerequisites](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html), [official MISP Docker repository](https://github.com/MISP/misp-docker), [Contabo portfolio](https://help.contabo.com/en/support/solutions/articles/103000408463-can-i-get-more-information-about-contabo-s-server-portfolio-).

## Information needed after subscription

Provide through a secure channel, not Git or chat screenshots containing secrets:

- VPS IPv4/IPv6 and Ubuntu version;
- SSH username and key-based access; do not send a reusable password if a key can be used;
- chosen domain/subdomains for feed, MISP, and Wazuh Dashboard;
- whether a second honeypot VPS is available;
- approved client public IPs or permission to deploy WireGuard;
- desired retention period and approximate disk budget;
- backup destination that is not the same VPS.

Credentials created during deployment will be stored in root-readable environment/secret files on the VPS and local `.env`, never committed.

## Deployment stages

### Stage 1: baseline and evidence

- Record OS/kernel, CPU, RAM, disk, DNS, and open ports.
- Apply updates and automatic security-update policy.
- Create named non-root administrators, SSH keys, and a recovery path before disabling password/root login.
- Configure time synchronization and a host firewall.
- Capture pre-deployment port and resource baselines.

### Stage 2: private administration network

- Install WireGuard.
- Give Ammar's PC and the collaborator's PC individual peer keys.
- Keep Wazuh Indexer `9200`, Wazuh API `55000`, Dionaea sensor API, databases, Redis, and container management ports private.
- Restrict SSH to WireGuard or known administrator addresses after connectivity is proven.

Wazuh documents agent communication on `1514/TCP`, enrollment on `1515/TCP`, and API-based enrollment on `55000/TCP`. Only the paths actually used will be allowed. Reference: [Wazuh agent enrollment requirements](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/requirements.html).

### Stage 3: Wazuh

- Use the official single-node Docker deployment with a pinned release.
- Generate certificates and replace every default password before exposure.
- Enroll Ammar's and the collaborator's agents individually.
- Create a least-privilege backend reader for `wazuh-alerts*`.
- Configure index retention and monitor disk watermarks.
- Keep Indexer `9200` private. The official API requires authentication and supports querying `wazuh-alerts*`; the backend uses that interface. Reference: [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html).

Acceptance evidence:

- green/yellow cluster health explained;
- both expected agents active;
- controlled test alert visible in Dashboard and Indexer;
- `/api/v1/integrations/wazuh/health` reachable;
- repeated backend pulls do not duplicate CTI rows.

### Stage 4: MISP

- Clone the official `MISP/misp-docker` repository and pin a known tag/build.
- Replace administrator, MariaDB, Redis, encryption, salt, UUID, and GPG defaults.
- Put MISP behind valid TLS; limit registration and automation-key permissions.
- Create a dedicated automation user for the backend.
- Configure organization, distribution defaults, taxonomies, and unpublished-first approval.
- Back up database, attachments, configs, GPG material, and required secrets off-host.

Acceptance evidence:

- `/api/v1/misp/health` returns the live version;
- dry-run mapping reviewed;
- one unpublished real event received with stable UUIDs and expected attributes/tags;
- repeat-send behavior is observed and documented before enabling automation;
- backup restoration is tested on a disposable copy.

### Stage 5: external feed service

- The collaborator syncs generated JSON outward to the VPS; the VPS does not mount or control the collaborator's machine.
- Deploy a small read-only API implementing `docs/api/external_feed_contract.md`.
- Add per-client bearer token, HMAC secret, request rate limit, maximum page size, cursor/checkpoint, ETag, audit logs, and TLS.
- Keep a bounded retention window and never store source credentials in returned metadata.

Acceptance evidence:

- valid health and pull;
- wrong token, wrong signature, wrong schema, oversize body, and repeated cursor are rejected;
- second identical pull creates no duplicate database rows;
- BERT primary backend is visible through `/api/v1/ml/status`.

### Stage 6: Dionaea

- Preferred: deploy on its own disposable VPS/VM.
- Publish only selected honeypot service ports; do not publish the sensor API publicly.
- Disable privileged containers, host PID/network, Docker socket, and sensitive mounts.
- Restrict outbound traffic to DNS/time, updates, Wazuh, and the evidence path as operationally required.
- Rotate official Dionaea JSON logs and expose only checkpointed JSON events through the private sensor contract.
- Install/enroll a Wazuh agent to monitor the host and selected Dionaea logs.

Acceptance evidence:

- external test interaction reaches only the intended honeypot service;
- JSON incident appears in the rotated sensor log;
- Wazuh alert/telemetry appears;
- raw event reaches the backend through `/integrations/dionaea/pull`;
- credentials are redacted from promoted CTI copies;
- no route or secret permits movement to MISP, Wazuh Indexer, PostgreSQL, or either personal LAN.

## Firewall intent

| Service | Exposure | Allowed clients |
|---|---|---|
| SSH | Private/restricted | Named administrators |
| HTTPS feed | Public TLS or VPN | Backend token/IP/rate limits |
| MISP HTTPS | Prefer VPN/restricted TLS | Team browsers and backend client |
| Wazuh Dashboard HTTPS | Prefer VPN/restricted TLS | Team browsers |
| Wazuh agent `1514/TCP` | Restricted | Enrolled agents |
| Wazuh enrollment `1515/TCP` | Temporary/restricted | Agent enrollment only |
| Wazuh API `55000/TCP` | VPN only | Authorized administration |
| Wazuh Indexer `9200/TCP` | VPN only | Backend read-only client |
| Dionaea service ports | Public on honeypot only | Untrusted internet |
| Dionaea sensor API | VPN only | Central backend |
| MariaDB/Redis/PostgreSQL | Container/private only | Their owning application |

The final firewall will use exact resolved interfaces and addresses after SSH access. No broad destructive or lockout-prone rule will be applied before a second access path is verified.

## Rollback and operations

- Pin versions and record checksums/config diffs.
- Take a provider snapshot before major upgrades, but do not treat a same-provider snapshot as the only backup.
- Test service-level restores.
- Define log/index retention before collecting public honeypot traffic.
- Monitor disk, memory, container health, TLS expiry, failed authentication, agent status, and backup age.
- Keep honeypot evidence within the project's approved legal/ethical scope and do not execute captured payloads on personal devices.
