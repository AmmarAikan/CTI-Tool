# ACTIT Final Production Implementation Status

Last updated: 2026-09-15 (UTC)

## Objective

Deliver the ACTIT graduation platform as a defensible VPS-only production system while preserving the existing PostgreSQL and MISP data, Docker volumes, integrations, Tailscale access, and valid repository work.

This document is the durable continuation checkpoint. The `Next Task` section is authoritative for the next implementation session.

## Current checkpoint

- Phase: P0 baseline and gap analysis complete; implementation has not started.
- Working branch: `codex/actit-final-production`.
- Branch base: `origin/codex/vps-production-integration` at `f9d0c311be6e6fa6a19429825da7dfc5bf7e0e8d`.
- Clean implementation worktree: `C:\My Projects\.codex-worktrees\actit-final-production`.
- Production source checkout: `/home/alaaldeen/cti-vps-production-integration`.
- Active immutable release: `/opt/cti-platform/releases/20260914T172623Z-f9d0c31` through `/opt/cti-platform/current`.
- Production state was inspected read-only. No container, network, firewall, volume, database, credential, or release mutation was made during the baseline.

## Verified production baseline

### Host and transport

- VPS: Contabo Ubuntu 24.04.4 LTS, kernel 6.8.0-136, x86_64/KVM, 6 vCPU, 11 GiB RAM.
- Storage at inspection: 193 GiB total, 59 GiB used, 135 GiB available.
- Public VPS address: `169.58.249.3`.
- Tailscale VPS address: `100.91.28.22`; the Windows peer was reachable at `100.77.72.109`.
- Tailscale Serve is the verified analyst transport:
  - `443` -> central frontend on `127.0.0.1:18080`.
  - `8443` -> MISP HTTPS on `127.0.0.1:8443`.
  - `8444` -> External Sources control on `127.0.0.1:8090`.
  - `8445` -> internal gateway on `127.0.0.1:8088`.
- UFW is active with default-deny inbound. SSH and intended honeypot ports are allowed; application ports remain loopback/tailnet-bound.
- The public-IP application target is not yet implemented: probes to public ports 80 and 443 did not expose ACTIT. Tailscale access remains healthy and must be preserved.

### Runtime services

| Service | Verified state | Boundary |
| --- | --- | --- |
| Central frontend | Healthy; HTTP 200 | Loopback `18080`, Tailscale Serve 443 |
| Central FastAPI backend | Healthy; `/api/v1/health` reports database available | Loopback `18000`, reached through frontend proxy |
| PostgreSQL 16.14 | Healthy; accepts connections | Internal Docker network only |
| External Sources | Healthy; `/api/v1/external-sources/health` reports `ok` | Loopback `8090`, Tailscale Serve 8444 |
| Internal gateway | Healthy; feed and Dionaea/host-auth/web-access streams ready | Loopback `8088`, Tailscale Serve 8445 |
| Dionaea | Running | Isolated honeypot networks plus intended sensor ports |
| Tor proxy | Healthy | Internal external-collection network only |
| MISP core 2.5.44 | Healthy and reachable | Loopback/Tailscale Serve 8443 |
| MISP modules 3.0.9 | Healthy | MISP internal network |
| MISP MariaDB/Valkey | Healthy | MISP internal network only |

Docker volumes for central PostgreSQL/uploads, gateway/external/Dionaea, and MISP database/cache/CA were inventoried and were not modified.

### Verified data state

PostgreSQL is the authoritative ACTIT datastore. Approximate live row counts at baseline:

| Dataset | Rows |
| --- | ---: |
| Raw items | 21,665 |
| Threat events | 13,994 |
| Indicators/observables | 20,390 |
| Entities | 54,950 |
| Extracted relationships | 36,112 |
| Correlations | 9 |
| Outlier sessions | 413 |
| Pipeline runs | 32 |
| Audit logs | 115 |
| Sources | 27 |
| Users | 5 |
| Enrichments | 0 |

MISP contains exactly one unpublished event, two attributes, and no objects. This is not caused by missing ACTIT events. The code has no automatic pipeline-to-MISP synchronization: MISP writes occur only through authenticated send endpoints. Event and attribute UUIDs are deterministic, so resending the same ACTIT event updates/reuses the existing MISP event instead of creating duplicates. Dry runs do not create MISP records.

### Verified ML and analytics state

- Runtime NER backend: `transformer`.
- Primary DNRTI BERT model loaded: yes.
- Secondary sklearn fallback loaded: no, because the primary model is active.
- Stored held-out BERT F1 exposed by the backend: `0.781165733250363`.
- Aggregate quality gate: currently false; the stored reports and individual failed gate(s) must be shown explicitly before claiming full model readiness.
- Rule-based IoC extraction, observable validation/assessment, relationship extraction, TF-IDF/cosine semantic correlation, exact-indicator correlation, risk scoring, Isolation Forest outlier detection, ATT&CK candidate mapping, STIX export, and selective MISP delivery exist in the backend.
- ATT&CK rule-based matches are correctly labeled as analyst-review candidates rather than confirmed techniques.

### Baseline verification results

| Check | Result |
| --- | --- |
| Frontend Vitest | 15 files, 106 tests passed; one non-failing React `act(...)` warning |
| Frontend production build | Passed; 95 modules built |
| External Sources compile check | Passed |
| Python unittest discovery | 344 tests executed; 1 failure and 3 errors |
| Python failure classification | Host test-environment dependency gaps: `joblib` and `stix2` unavailable; one model assertion consequently failed |
| Source Compose validation | Not completed because the ignored production `.env` is intentionally absent from the Git checkout; this is not a failure of the already-running immutable release |

The Python suite must be rerun in an isolated environment with the committed requirements before any remaining failures are classified as product defects.

## Verified end-to-end lifecycle

1. An authenticated user reaches the React dashboard through Tailscale Serve and same-origin HTTPS.
2. External collectors perform bounded collection, privacy and structural validation, relevance classification, preprocessing, versioned export, and authenticated gateway handoff.
3. Internal Dionaea, host-auth, and web-access telemetry is delivered through authenticated sensor/gateway paths.
4. The central FastAPI pipeline normalizes records, extracts IoCs/entities/relationships, runs DNRTI BERT NER with a safe fallback, scores risk, creates correlations, and detects internal outliers.
5. PostgreSQL stores the authoritative source, event, indicator, entity, relationship, correlation, outlier, run, user, and audit state.
6. The dashboard exposes operational and intelligence views. STIX is generated per event. MISP is a selective analyst-controlled review/sharing destination, not a database mirror.

## Gap Matrix

Legend: **Ready** = verified usable now; **Partial** = implemented but incomplete for P0; **Missing** = no production implementation; **Deferred** = intentionally P1 or later.

| Capability | State | Evidence | P0 gap / acceptance target |
| --- | --- | --- | --- |
| VPS-only immutable deployment | Ready | Active release `20260914T172623Z-f9d0c31`; clean source checkout | Preserve release/rollback model during deployment |
| Tailscale analyst access | Ready | Frontend and service routes verified | Preserve as private administrative/analyst transport |
| Public-IP ACTIT access | Missing | Public 80/443 probes did not expose the application | Add hardened reverse proxy on the existing VPS/public IP without exposing backend/databases |
| Login and session authentication | Partial | Scrypt password hashes, signed expiring tokens, active-user check | Add rate limiting, security audit outcomes, and production browser/session hardening |
| Public registration | Missing | User creation is admin-only and allows role selection | Add abuse-resistant registration that always creates an active `viewer`; never accept a client-selected role |
| RBAC and user administration | Partial | Viewer/analyst/admin guards, last-admin protection, audit view | Verify every mutating endpoint and add deny-path tests |
| Information architecture | Partial | Functional sidebar grouped by operations, sources, intelligence, administration | Add public landing/register flow, global search, clearer evidence/story paths, responsive accessibility pass |
| Executive dashboard | Partial | Counts, severities, pipelines, runs, sources, and processing center exist | Add health/readiness, trend/evidence clarity, actionable drill-downs, and trustworthy empty/degraded states |
| External Sources | Ready/Partial | Healthy service and canonical external implementation | Preserve ownership boundaries; expose provenance/freshness/failure evidence more clearly |
| Internal Sources | Ready/Partial | Gateway streams ready; Dionaea/host-auth/web-access views exist | Improve drill-down, sensor freshness, and safe outlier evidence display |
| Global search | Missing | Search is page-local only | Search events, indicators, entities, sources, and correlations with safe bounded queries |
| Indicator meaning and quality | Partial | Type, semantic role, validation, assessment, evidence fields exist | Explain reference vs suspicious/malicious values and surface evidence consistently |
| Cross-source evidence | Partial | Correlation records contain evidence JSON | Return/display evidence and source provenance; distinguish exact, semantic, and cross-pipeline links |
| Correlation explanation | Missing in UI/API projection | Backend stores reason/evidence but response exposes only reason | Add explainable factor list and drill-down to both events/observables |
| Threat storyline | Missing | No dedicated storyline model/service/UI | Build defensible event timeline/story from existing events, relationships, correlations, and ATT&CK mappings |
| MITRE ATT&CK | Partial | Built-in subset, evidence-bearing candidates, Navigator export, official links | Broaden safe catalog use, expose tactic/technique context, and retain candidate/confirmed distinction |
| STIX sharing | Partial | Per-event STIX endpoint exists | Add obvious UI download/export, validation feedback, and safe filename/content handling |
| MISP health/preview/send/history | Partial | Connected; preview/send/history UI and idempotent client exist | Add candidate queue/readiness, batch controls, explicit omission reasons, durable delivery records, and usable post-send links |
| MISP population | Partial by design | 13,994 ACTIT events versus one unpublished MISP event | Implement reviewed selection/delivery workflow; do not blindly mirror all PostgreSQL data |
| Enrichment | Missing live data | Enrichment table contains zero rows | Add controlled enrichment runs/status and make risk/assessment provenance visible |
| ML transparency | Partial | Runtime model and stored metrics endpoint exists | Show individual quality gates, model scope/limitations, inference evidence, and fallback/degraded state |
| Risk scoring | Partial | Deterministic risk factors stored in `raw_reference` | Project factors through API/UI and label score provenance |
| Outlier detection | Partial | 413 sessions and Isolation Forest/fallback metadata exist | Explain features, sample sufficiency, detector choice, and event relationship |
| Demo/readiness dataset | Missing | Live data is substantial but not curated for a deterministic demonstration | Add non-destructive seeded demo fixtures/workflow without polluting or replacing production data |
| App/API security | Partial | Loopback binding, CSP, default-deny firewall, separated networks, read-only/cap-drop on core services | Rate limits, stricter headers/cookies/token storage review, input/response controls, audit completeness, regression tests |
| SSRF controls | Partial | External manual URL policy/safe HTTP client and tests exist | Revalidate redirect, DNS rebinding, private range, metadata, size/time, and content-type controls end to end |
| Security scan/remediation | Pending | No final-branch Codex Security result yet | Run after P0 functionality stabilizes; triage and verify every accepted fix |
| Cloudflare/custom domain | Deferred | No domain exists in Contabo account; no domain is required for P0 | Keep optional; do not purchase or change DNS without explicit approval |
| Formal Figma alignment | Pending | Figma reference supplied; current implementation not yet compared node-by-node | Load approved design context and translate it into responsive accessible React components |

## Decisions and safety boundaries

- PostgreSQL remains the source of truth. MISP remains an unpublished-by-default, selective sharing destination.
- No bulk MISP mirror will be enabled without validation, evidence, deduplication, analyst review, rate/size bounds, and explicit publication controls.
- Existing Docker volumes and databases must never be removed, recreated, or migrated without a verified backup and rollback plan.
- The current production release remains the rollback point until a newer release passes smoke and regression tests.
- No force push, `main` branch mutation, destructive Git reset/clean, or secret output is permitted.
- A public-IP deployment must expose only the reverse proxy. PostgreSQL, MISP database/cache, backend, gateway, External Sources control, and Docker APIs remain private.
- Cloudflare and a custom domain are optional and are not P0 blockers.
- UI changes must preserve Arabic/English, RTL/LTR, responsive behavior, keyboard access, clear focus states, and existing functionality.
- Shared contracts or modules owned by another team require an impact report and compatibility tests before modification.

## Completed

- Recovered and verified the VPS-only architecture and active production release.
- Audited Git state, Docker projects/containers/volumes/networks, listeners, UFW, Tailscale Serve, health endpoints, database counts, MISP counts, and runtime ML status.
- Executed baseline frontend tests/build, Python test discovery, and the External Sources compile check.
- Audited existing authentication, RBAC, frontend routes, correlations, risk, ATT&CK, STIX, and MISP code paths.
- Established this isolated final-production branch/worktree and documented the gap matrix.

## Next Task

Create an isolated dependency-complete test environment from the committed requirements and rerun the full Python suite. Classify any remaining failures. Then implement P0 secure self-registration as a `viewer`-only flow with bounded abuse protection, audit evidence, backend tests, frontend landing/register pages, and no client-controlled role or privilege escalation.

Before major UI work, load the supplied Figma design context and run the installed `ui-ux-pro-max` design-system/React guidance. Record any unavailable connector guidance as a tool limitation, not as a product result.

## Remaining P0 sequence

1. Dependency-complete Python baseline and defect classification.
2. Secure registration/login hardening and complete RBAC regression coverage.
3. Public landing page and information-architecture foundation.
4. Figma/UI design foundation with Arabic/English and responsive accessibility.
5. Dashboard/readiness improvements.
6. Bounded global search.
7. Cross-source evidence and explainable correlations.
8. Threat storyline/timeline.
9. MISP candidate readiness, reviewed/batch delivery, durable evidence, and improved MISP center.
10. Deterministic non-destructive demo dataset and readiness checks.
11. Public-IP reverse proxy and network/application security hardening while preserving Tailscale.
12. SSRF regression, full regression suite, Codex Security scan, remediation, documentation, and final demo validation.

## Remaining P1 / deferred

- Optional custom domain and Cloudflare integration after explicit approval and domain availability.
- Broader ATT&CK catalog synchronization beyond the defensible P0 subset.
- Advanced notifications, collaboration workflow, and external organization sharing policies.
- Scale/performance work that is not required for the final P0 demonstration.

## Known blockers and non-blockers

- Non-blocker: no custom domain. Public IP is the P0 target.
- Non-blocker: MISP has one event. The connection works; the missing piece is a reviewed delivery workflow.
- Non-blocker pending retest: Python host dependencies were incomplete; use an isolated environment before diagnosing application failures.
- Tool dependency for UI phase: the Figma design-to-code guidance resource must be located/loaded before calling the design-context operation.
- Genuine stop boundaries: destructive database/volume migration, paid domain/service purchase, unavailable credentials, irreversible firewall/DNS action, or an external approval requirement.

## Background and scheduled work

None. No unattended process or automation was started during the baseline.

## Rollback and recovery

- Production rollback reference: `/opt/cti-platform/releases/20260914T172623Z-f9d0c31`.
- Source branch reference: `origin/codex/vps-production-integration` at `f9d0c31`.
- Do not deploy from the Windows worktree directly. Build an immutable VPS release, preserve the current symlink target, verify health/smoke tests, and switch the symlink only after validation.
- If a future release fails, restore the previous symlink target and container images without deleting volumes, then verify frontend, backend/database, External Sources, gateway, and MISP health.
