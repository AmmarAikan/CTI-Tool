# ACTIT Final Production Implementation Status

Last updated: 2026-09-16 (UTC)

## Objective

Deliver the ACTIT graduation platform as a defensible VPS-only production system while preserving the existing PostgreSQL and MISP data, Docker volumes, integrations, Tailscale access, and valid repository work.

This document is the durable continuation checkpoint. The `Next Task` section is authoritative for the next implementation session.

## Current checkpoint

- Phase: P0 Phases 1-5 complete in development: incremental UI/Auth foundation, real-data Dashboard investigation entry, bounded Global Intelligence / IOC Investigation Search, explainable Cross-Source Evidence, and the evidence-backed Threat Storyline.
- Working branch: `codex/actit-final-production`.
- Branch base: `origin/codex/vps-production-integration` at `f9d0c311be6e6fa6a19429825da7dfc5bf7e0e8d`.
- Development worktree: `/home/alaaldeen/.codex-worktrees/actit-final-production` on VPS `vmi3538777`; it is not a production path.
- UI/Auth implementation checkpoint: `ef2a2b262d6b5465913a75e2b2ecf7dcee92f2ce`.
- Dashboard implementation checkpoint: `af853e8d6f82d22ae9f319648c5b93efe28253bd`.
- Global search implementation checkpoint: `e29f83d`.
- Cross-source evidence implementation checkpoint: `7fa1ea9`.
- Threat Storyline implementation checkpoint: `8abb490b3f901860f5217187ffb7c7895164b980`.
- Production source checkout: `/home/alaaldeen/cti-vps-production-integration`.
- Active immutable release: `/opt/cti-platform/releases/20260914T172623Z-f9d0c31` through `/opt/cti-platform/current`.
- Production remains unchanged and still runs from `/opt`; no production container, network, firewall, volume, database, credential, symlink, or release was changed in Phases 1-5.
- Candidate-only Docker images `actit-backend:ui-auth-candidate`, `actit-frontend:ui-auth-candidate`, `actit-frontend:dashboard-candidate`, `actit-backend:search-candidate`, `actit-frontend:search-candidate`, `actit-backend:correlation-candidate`, `actit-frontend:correlation-candidate`, `actit-backend:storyline-candidate`, and `actit-frontend:storyline-candidate` were built from the VPS development worktree for isolated parity testing; they are not deployed.

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

Observed fact: MISP contained exactly one unpublished event, two attributes, and no objects while ACTIT had many events. Deterministic UUID reuse, dry-run behavior, and the absence of automatic pipeline synchronization are implementation hypotheses that may explain this state, but they are not yet the verified final root cause. The dedicated MISP phase must compare the live ACTIT event, audit, outbound request, MISP API, and MISP database evidence before applying a fix.

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
| Python unittest discovery in VPS disposable venv | 351 tests passed after installing the committed CPU-compatible requirements; the venv is test-only and not a production dependency |
| Backend production-image parity checkpoint | 100 backend tests passed in the isolated Docker backend environment before Phase 1 |
| Source Compose validation | Not completed because the ignored production `.env` is intentionally absent from the Git checkout; this is not a failure of the already-running immutable release |

Phase 1 validation: backend targeted tests passed 5/5 both in the VPS test environment and in the newly built backend candidate image with Compose-equivalent read-only ML report mount; frontend targeted tests passed 16/16; the frontend candidate image passed TypeScript validation, all 108 Vitest tests, production build, and isolated `/` plus `/register` HTTP smoke checks. Existing non-failing React `act(...)` warnings and the Vite 500 kB chunk warning remain documented technical debt.
Dashboard phase validation: the focused Dashboard, integration, and localization set passed 20/20 on the VPS. The `actit-frontend:dashboard-candidate` Docker build then passed TypeScript validation, all 108 Vitest tests, and the production build. This phase changed no backend contract and used the existing real events endpoint; no production data or service was connected or modified.
Global search phase validation: the focused frontend set passed 33/33, TypeScript lint and the production build passed, and the ordered Backend API module passed 10/10 in both the VPS disposable test environment and `actit-backend:search-candidate`. The `actit-frontend:search-candidate` Docker build passed TypeScript validation, all 112 Vitest tests, and the production build. Existing non-failing React `act(...)`, sklearn model-version, and Vite 500 kB chunk warnings remain documented technical debt.
Cross-source evidence phase validation: the focused frontend set passed 29/29 and TypeScript lint passed; the ordered Backend API module passed 11/11 in both the VPS disposable test environment and `actit-backend:correlation-candidate`. The `actit-frontend:correlation-candidate` Docker build passed TypeScript validation, all 112 Vitest tests, and the production build. Production's nine current correlation rows were inspected read-only and are all internal-to-internal; ACTIT now labels same-pipeline versus cross-source records honestly and does not fabricate an External-to-Internal link.
Threat Storyline phase validation: the ordered Backend API module passed 12/12 in both the VPS disposable test environment and `actit-backend:storyline-candidate` with the Compose-equivalent read-only ML reports mount. The focused Storyline frontend tests passed 2/2; `actit-frontend:storyline-candidate` passed TypeScript validation, all 114 Vitest tests, the production build, and an isolated Nginx `/healthz` container smoke check. Candidate image IDs are `sha256:4895ba2f1040879ba7d2ca8a83a983ac8d11edd23c1c82844bae45fa1d74267f` for backend and `sha256:3ebef06df8b7dba2db20b6c8ae35abdbd156059da29cccef330cfa6a3d08d548` for frontend.


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
| Login and session authentication | Ready in development, not deployed | Existing Scrypt/signed token flow preserved; bounded IP/account limits, timing-safe unknown-user verification, and success/rejection audit evidence added | Retain later reverse-proxy/session-storage hardening and validate after immutable deployment |
| Public registration | Ready in development, not deployed | Public API and bilingual form always create active `viewer`; extra/client role is rejected; duplicate and rate-limit states are safe | Deploy through immutable release only after the next meaningful checkpoint |
| RBAC and user administration | Partial | Viewer/analyst/admin guards, last-admin protection, audit view | Verify every mutating endpoint and add deny-path tests |
| Information architecture | Partial | Existing routes/pages/components preserved; added public Landing/Register, moved Dashboard to `/dashboard`, presented MISP as sharing, and added Dashboard, global-search, evidence, and Storyline investigation pivots | Continue page-by-page incremental accessibility and workflow improvements |
| Executive dashboard | Ready/Partial in development, not deployed | Existing real counts/health/distributions preserved; latest five real events and direct events/indicators/sources/analysis drill-downs added with loading/error/empty states | Add explicit system-readiness evidence and later trend clarity without mock metrics |
| External Sources | Ready/Partial | Healthy service and canonical external implementation | Preserve ownership boundaries; expose provenance/freshness/failure evidence more clearly |
| Internal Sources | Ready/Partial | Gateway streams ready; Dionaea/host-auth/web-access views exist | Improve drill-down, sensor freshness, and safe outlier evidence display |
| Global search | Ready in development, not deployed | Authenticated bounded search covers real events, indicators, entities, sources, and correlations with exact/prefix/contains ordering, safe projections, provenance, literal wildcard handling, viewer access, and existing-record pivots | Validate against the immutable release after deployment; consider database-specific index/performance work only if measured |
| Indicator meaning and quality | Partial | Type, semantic role, validation, assessment, evidence fields exist | Explain reference vs suspicious/malicious values and surface evidence consistently |
| Cross-source evidence | Ready/Partial in development, not deployed | Typed API endpoints expose real source provenance and derived same-pipeline/cross-source scope; UI links both events | Current production rows are same-pipeline; validate real External-to-Internal evidence when generated and cover it in the deterministic demo dataset |
| Correlation explanation | Ready in development, not deployed | Safe allowlisted factors explain exact observable match or normalized-text method/threshold; arbitrary evidence remains private | Validate against the immutable release after deployment and extend only when a new correlation method has a defined safe projection |
| Threat storyline | Ready in development, not deployed | Typed bounded endpoint and bilingual responsive investigation view project real provenance, chronology, observables, entities, relationships, correlations, ATT&CK candidates, and deterministic risk factors | Validate against the immutable release after deployment; preserve chronology-versus-causality and candidate-status labels |
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
| Reference-informed UI refinement | Partial | Exact ThreatIntel Figma was inspected and UI UX Pro Max guidance was applied to the existing ACTIT component/token/i18n architecture | Continue page-by-page; never replace ACTIT or copy Figma/OpenCTI mock code/data |

## Decisions and safety boundaries

- Existing ACTIT UI is the implementation baseline. Routes, pages, API integrations, components, i18n/RTL/LTR, dark/light themes, useful navigation, tables/forms, identity, backend contracts, and tests are preserved unless a narrowly justified improvement requires change.
- Major product decisions use the three-reference model:
  - Scientific/functional basis: `AI-Based_Holistic_Framework_for_Cyber_Threat_Intelligence_Management.pdf`.
  - Mature CTI workflow/IA pattern: current OpenCTI documentation and implementation concepts, without cloning or replacing ACTIT architecture.
  - Visual/interaction basis: only the approved ThreatIntel Figma Make file, without importing mock data or generated architecture.
- Phase 1 decision rationale:
  - Paper basis: communicate the internal/external collection, preprocessing/extraction, correlation, storage, and sharing lifecycle.
  - OpenCTI basis: keep analyst pivots grounded in observations/entities, relationships, source context, and provenance.
  - Figma basis: selectively use navy/cyan hierarchy, compact operational cards, clear evidence states, and responsive presentation.
  - ACTIT implementation: retain the existing React router, API client, auth context, translation catalog, design tokens, dashboard, and backend models; add only the public entry and viewer-only account path required by P0.
- Dashboard decision rationale:
  - Paper basis: make collected and processed CTI evidence directly reachable from the lifecycle summary.
  - OpenCTI basis: use observation-led analyst pivots from overview into concrete intelligence records.
  - Figma basis: apply a compact, scannable recent-intelligence list and clear action hierarchy.
  - ACTIT implementation: preserve every existing health card, statistic, distribution, state, and API contract; add one real-data component backed by the existing bounded events endpoint.
- Global search decision rationale:
  - Paper basis: make extracted observables/entities and correlated internal/external intelligence discoverable through the CTI lifecycle.
  - OpenCTI basis: start an investigation from an observation or entity and pivot to its source context and related records.
  - Figma basis: use a focused investigation entry, strong result hierarchy, evidence metadata, and responsive result cards.
  - ACTIT implementation: query existing relational records through one authenticated read-only endpoint with strict bounds and safe projections; preserve all current event/source routes and backend architecture.
- Cross-source evidence decision rationale:
  - Paper basis: make Internal and External CTI correlation inspectable as evidence in the lifecycle rather than a score without context.
  - OpenCTI basis: show both relationship endpoints, their provenance, and analyst pivots to the underlying observations.
  - Figma basis: use a compact evidence path, clear strength hierarchy, factor rows, and responsive endpoint cards.
  - ACTIT implementation: preserve the existing correlators and database model; add one batched typed response projection that allowlists shared observables, algorithm, and threshold while excluding raw evidence and internal text.
  - Data-truth rule: label a row cross-source only when the two stored event pipelines differ; the nine inspected production rows are currently same-pipeline.
- Threat Storyline decision rationale:
  - Paper basis: connect internal/external collection, extraction, correlation, analysis, storage, and sharing as an inspectable CTI lifecycle.
  - OpenCTI basis: present provenance, observations, entities, relationships, and analyst pivots without replacing ACTIT's relational architecture.
  - Figma basis: adapt the approved timeline, evidence-card, and risk-hierarchy patterns to ACTIT's existing visual system.
  - ACTIT implementation: add one bounded read-only projection and one incremental bilingual page backed only by existing real records; no mock production data or database migration.
  - Data-truth rule: milestones are chronological evidence, correlations remain scored associations, and rule-based ATT&CK results remain candidates rather than asserted causality.
- UI UX Pro Max influenced information density, focus visibility, keyboard/accessibility states, responsive breakpoints, and reduced-motion treatment; its generic visual palette was not used where it conflicted with ACTIT and the approved Figma.
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
- Added a public ACTIT landing page and a bilingual, responsive Login/Register experience on top of the existing design system.
- Added public self-registration with strict schema validation, server-enforced `viewer` role, no client role input, safe duplicate handling, and no credential/hash response.
- Added bounded in-process login/register abuse protection, non-reversible client keys, unknown-user password verification, and authentication audit outcomes.
- Preserved all existing protected feature routes while moving the protected Dashboard from `/` to `/dashboard` and updating internal fallbacks/links.
- Built isolated candidate backend/frontend Docker images and completed the Phase 1 targeted, full-frontend, build, and smoke validations without connecting to production data.
- Preserved the existing Dashboard and added direct investigation drill-downs plus the latest five real threat events from the existing API, with severity, risk, pipeline, provenance context, detail links, and explicit loading/error/empty behavior.
- Built the isolated Dashboard frontend candidate and completed focused and full Dockerized frontend validation without deploying it.
- Added an authenticated, read-only Global Intelligence / IOC Investigation Search across events, observables, entities, sources, and correlations with bounded per-type results and deterministic exact/prefix/contains relevance.
- Added safe provenance/result projections, wildcard escaping, internal `source_ip` suppression, viewer access, direct pivots into existing ACTIT pages, bilingual responsive states, strict frontend response validation, and VPS/Docker parity tests.
- Added typed, sanitized explainable correlation responses with both real event endpoints, source provenance, derived cross-source scope, score basis, evidence availability, and allowlisted factors.
- Reworked the existing Correlations page incrementally into bilingual, responsive evidence cards with direct event pivots while retaining the current route, API architecture, themes, and pagination.

- Added a first-class Threat Storyline investigation route with real event provenance, deterministic risk explanation, bounded evidence counts, chronological milestones, observables/entities/relationships, correlation pivots, and ATT&CK candidate context.
- Added strict safe response parsing and internal-evidence suppression, including sanitized ATT&CK projections for internal events, then validated the implementation in both backend and frontend candidate containers.
## Next Task

Perform a targeted MISP root-cause investigation by comparing the existing ACTIT candidate/preview/send/history code, production audit evidence, outbound event identity, MISP API state, and MISP database evidence without modifying data. Then implement the smallest safe multi-event sharing workflow: explicit readiness/omission reasons, bounded analyst selection and admin-confirmed batch delivery, deterministic idempotency, durable per-event outcomes, and usable post-send references while keeping MISP unpublished-by-default and PostgreSQL authoritative.

## Remaining P0 sequence

1. MISP candidate readiness, reviewed/batch delivery, durable evidence, and improved MISP center.
2. Deterministic non-destructive demo dataset and explicit System Readiness view.
3. Complete mutating-endpoint RBAC deny-path coverage and later reverse-proxy/session hardening.
4. Continue Figma/UI refinement incrementally per affected page with Arabic/English and responsive accessibility.
5. Public-IP reverse proxy and network/application security hardening while preserving Tailscale.
6. SSRF regression, full regression suite, Codex Security scan, remediation, documentation, and final demo validation.

## Remaining P1 / deferred

- Optional custom domain and Cloudflare integration after explicit approval and domain availability.
- Broader ATT&CK catalog synchronization beyond the defensible P0 subset.
- Advanced notifications, collaboration workflow, and external organization sharing policies.
- Scale/performance work that is not required for the final P0 demonstration.

## Known blockers and non-blockers

- Non-blocker: no custom domain. Public IP is the P0 target.
- Non-blocker: MISP has one observed event; the final root cause remains unproven until the dedicated targeted investigation.
- Non-blocker: the complete backend suite passed in the VPS disposable test environment; production remains Docker/Compose only.
- Non-blocker: the exact Figma Make reference and UI UX Pro Max were available and used for selective guidance.
- Genuine stop boundaries: destructive database/volume migration, paid domain/service purchase, unavailable credentials, irreversible firewall/DNS action, or an external approval requirement.

## Background and scheduled work

None. No unattended process or automation was started during the baseline.

## Rollback and recovery

- Production rollback reference: `/opt/cti-platform/releases/20260914T172623Z-f9d0c31`.
- Source branch reference: `origin/codex/vps-production-integration` at `f9d0c31`.
- Build immutable releases only on the VPS from a validated VPS worktree, preserve the current symlink target, verify health/smoke tests, and switch the `/opt/cti-platform/current` symlink only after validation.
- If a future release fails, restore the previous symlink target and container images without deleting volumes, then verify frontend, backend/database, External Sources, gateway, and MISP health.
