# ACTIT Final Production Implementation Status

Last updated: 2026-09-18 (UTC)

## Objective

Deliver the ACTIT graduation platform as a defensible VPS-only production system while preserving the existing PostgreSQL and MISP data, Docker volumes, integrations, Tailscale access, and valid repository work.

This document is the durable continuation checkpoint. The `Next Task` section is authoritative for the next implementation session.

## Current checkpoint

- Phase: P0 Phases 1-8 complete in development: incremental UI/Auth, real-data Dashboard, Global Intelligence Search, Cross-Source Evidence, Threat Storyline, reviewed multi-event MISP delivery, isolated Demo Dataset/System Readiness, and RBAC/session/reverse-proxy hardening.
- Working branch: `codex/actit-final-production`.
- Branch base: `origin/codex/vps-production-integration` at `f9d0c311be6e6fa6a19429825da7dfc5bf7e0e8d`.
- Development worktree: `/home/alaaldeen/.codex-worktrees/actit-final-production` on VPS `vmi3538777`; it is not a production path.
- UI/Auth implementation checkpoint: `ef2a2b262d6b5465913a75e2b2ecf7dcee92f2ce`.
- Dashboard implementation checkpoint: `af853e8d6f82d22ae9f319648c5b93efe28253bd`.
- Global search implementation checkpoint: `e29f83d`.
- Cross-source evidence implementation checkpoint: `7fa1ea9`.
- Threat Storyline implementation checkpoint: `8abb490b3f901860f5217187ffb7c7895164b980`.
- MISP workflow implementation checkpoint: `bd10ff757f34e6937042c05048e1277b1965b878`.
- Demo Dataset/System Readiness implementation checkpoint: `b3f0fd8`.
- RBAC/session/proxy security implementation checkpoint: `025929d`; review details and residual risks: `docs/security-hardening-checkpoint.md`.
- External URL DNS-pinning checkpoint: `6e82086`; details in `docs/security-hardening-checkpoint.md`.
- Production source checkout: `/home/alaaldeen/cti-vps-production-integration`.
- Active immutable release: `/opt/cti-platform/releases/20260914T172623Z-f9d0c31` through `/opt/cti-platform/current`.
- Production remains unchanged and still runs from `/opt`; no production container, network, firewall, volume, database, credential, symlink, or release was changed in Phases 1-8 or this SSRF follow-up.
- Candidate-only Docker images `actit-backend:ui-auth-candidate`, `actit-frontend:ui-auth-candidate`, `actit-frontend:dashboard-candidate`, `actit-backend:search-candidate`, `actit-frontend:search-candidate`, `actit-backend:correlation-candidate`, `actit-frontend:correlation-candidate`, `actit-backend:storyline-candidate`, and `actit-frontend:storyline-candidate` were built from the VPS development worktree for isolated parity testing; they are not deployed.
- Phase 7 candidate-only image: `actit-frontend:demo-readiness-candidate` (`sha256:f92846380794086b0e0bd66a0d085637fa5f6d91c18f839114870d36c6d7927e`). Backend code was unchanged; parity tests used the existing `actit-backend:misp-candidate` image.
- Phase 8 candidate-only images: `actit-backend:security-candidate` (`sha256:952e7b20a44985c95c4196905f1997b86cdcbf990f275a683d1893291622bcde`) and `actit-frontend:security-candidate` (`sha256:ea60abbaa6bcce091e2a4030ef0cf1c5f47a7a8aee1dedb2cdf2d5d97990d257`); neither was deployed.
- External Sources candidate-only image: `actit-external:ssrf-candidate` (`sha256:4aa727ffdd2edad9283e8e4feb4615589890d4c11a6f73afaab42602bf8da580`); it is not deployed.

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

Verified MISP root cause: seven ACTIT audit actions targeted one controlled event (three dry-runs, four sends). Its deterministic UUID matched the sole MISP event (ID 2), which the MISP API and database confirmed unpublished, distribution 0, with two attributes. Repeated sends correctly reused that event; no other ACTIT event had been submitted. The gap was the reviewed multi-event workflow, not connectivity. Production MISP data was not modified.

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
MISP phase validation: Backend API passed 13/13 in VPS venv and `actit-backend:misp-candidate` with read-only ML reports. Two MISP client idempotency tests passed in Docker. Focused frontend tests passed 13/13; `actit-frontend:misp-candidate` passed TypeScript, all 115 Vitest tests, build, and isolated Nginx `/healthz`. Candidate IDs: backend `sha256:1a0828aa092317c42f07a944da5f8fac60a724f074d95133bcfe42e2ff532255`; frontend `sha256:97d18472577f7ba7f6d8b70153a654655159957a52d239de4e6d4bed76fdf5a9`.

Demo/readiness phase validation: isolated demo tests passed 3/3 in both the VPS disposable venv and the existing backend Docker candidate (read-only fixture mounts, private temporary SQLite). The full VPS Python suite passed 361/361. The focused readiness UI test passed and `actit-frontend:demo-readiness-candidate` passed TypeScript, all 116 Vitest tests, and production build. Isolated Nginx `/healthz` returned `ok` with a non-production backend hostname alias; the earlier `--network none` smoke attempt failed before that alias was provided. Existing non-failing React `act(...)` and Vite chunk-size warnings remain. No production deploy or data mutation occurred.
Security phase validation: three focused RBAC/session tests passed in the VPS disposable venv and isolated backend Docker candidate. Full VPS Python regression passed 363/363. The frontend candidate build passed TypeScript, all 116 Vitest tests, and production compilation. An isolated private Docker network smoke returned Nginx `/healthz` 200, HTML/API `Cache-Control: no-store`, and the existing CSP. Six registration requests with rotating forged `X-Forwarded-For`/`Forwarded` headers yielded five 201 responses then 429, confirming the proxy strips the spoofed chain before rate limiting. Temporary smoke containers/network were removed; `git diff --check` passed. Existing non-failing React `act(...)` and Vite chunk warnings remain. A formal desktop Codex Security scan was not run because its target-path workflow requires a local checkout while the authoritative ACTIT worktree is VPS-only; manual changed-code review was completed. No production deploy or data mutation occurred.
Follow-up security inspection: active production has no `ACCESS_TOKEN_MINUTES` environment override; the old image retains its default until release. Tailscale Serve remains private on the tailnet and the frontend remains loopback-only; UFW has no public 80/443 rule. Nine manual URL policy/router tests passed in the VPS venv and the actual External Sources Docker image. An initial attempt in the Central Backend image failed because it intentionally lacks External Sources' `beautifulsoup4` dependency; the correct runtime passed. Source review identified an unpinned DNS-validation-to-connect race in the External-owned manual URL HTTP client. No real SSRF exploit was attempted; see `docs/security-hardening-checkpoint.md`.
Approved SSRF follow-up validation: DNS-pinned URL transport and regression tests were added under External Sources after explicit user approval. Focused manual/social/crawler tests passed 55/55 in the candidate External Sources image. Its complete isolated Docker test suite passed 232/232 with read-only source/tests, disposable tmpfs state/logs, and no network. Full VPS Python regression passed 368/368. The candidate image build passed its non-root/read-only and Playwright smoke checks. Tests cover vetted-IP socket use and fallback, original TLS SNI/certificate mode across urllib3 2.7/2.8, private redirect denial, per-hop repinning, IPv4/IPv6 and mixed DNS, bounded address attempts, proxy-env isolation, and response size/time limits. No production data or service was changed.

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
| Public-IP ACTIT access | Deferred, optional | Public 80/443 do not expose ACTIT; Tailscale Serve is the working presentation path | No public certificate or open port in this checkpoint; separate approval required |
| Login and session authentication | Ready/Partial in development, not deployed | Existing Scrypt/signed token flow preserved; bounded IP/account limits, timing-safe unknown-user verification, success/rejection audit evidence, and a 120-minute default token lifetime. Browser token stays in sessionStorage and clears on logout/401 | Verify any explicit production token-lifetime override and the Tailscale Serve client-rate-limit identity before immutable deployment |
| Public registration | Ready in development, not deployed | Public API and bilingual form always create active `viewer`; extra/client role is rejected; duplicate and rate-limit states are safe | Deploy through immutable release only after the next meaningful checkpoint |
| RBAC and user administration | Ready/Partial in development, not deployed | Viewer/analyst/admin guards, last-admin protection, audit view; all central FastAPI mutating routes have role dependencies and anonymous/viewer deny-path tests, plus admin-only analyst denial | Validate against immutable release after deployment; keep External Sources' separate authenticated control tests |
| Information architecture | Partial | Existing routes/pages/components preserved; added public Landing/Register, moved Dashboard to `/dashboard`, presented MISP as sharing, and added Dashboard, global-search, evidence, and Storyline investigation pivots | Continue page-by-page incremental accessibility and workflow improvements |
| Executive dashboard | Ready/Partial in development, not deployed | Existing real counts/health/distributions preserved; latest five real events and direct events/indicators/sources/analysis drill-downs added with loading/error/empty states | Add explicit system-readiness evidence and later trend clarity without mock metrics |
| External Sources | Ready/Partial | Healthy service and canonical external implementation | Preserve ownership boundaries; expose provenance/freshness/failure evidence more clearly |
| Internal Sources | Ready/Partial | Gateway streams ready; Dionaea/host-auth/web-access views exist | Improve drill-down, sensor freshness, and safe outlier evidence display |
| Global search | Ready in development, not deployed | Authenticated bounded search covers real events, indicators, entities, sources, and correlations with exact/prefix/contains ordering, safe projections, provenance, literal wildcard handling, viewer access, and existing-record pivots | Validate against the immutable release after deployment; consider database-specific index/performance work only if measured |
| Indicator meaning and quality | Partial | Type, semantic role, validation, assessment, evidence fields exist | Explain reference vs suspicious/malicious values and surface evidence consistently |
| Cross-source evidence | Ready/Partial in development, not deployed | Typed API endpoints expose real source provenance and derived same-pipeline/cross-source scope; UI links both events; isolated synthetic demo covers both scopes | Current production rows are same-pipeline; validate real External-to-Internal evidence when generated |
| Correlation explanation | Ready in development, not deployed | Safe allowlisted factors explain exact observable match or normalized-text method/threshold; arbitrary evidence remains private | Validate against the immutable release after deployment and extend only when a new correlation method has a defined safe projection |
| Threat storyline | Ready in development, not deployed | Typed bounded endpoint and bilingual responsive investigation view project real provenance, chronology, observables, entities, relationships, correlations, ATT&CK candidates, and deterministic risk factors | Validate against the immutable release after deployment; preserve chronology-versus-causality and candidate-status labels |
| MITRE ATT&CK | Partial | Built-in subset, evidence-bearing candidates, Navigator export, official links | Broaden safe catalog use, expose tactic/technique context, and retain candidate/confirmed distinction |
| STIX sharing | Partial | Per-event STIX endpoint exists | Add obvious UI download/export, validation feedback, and safe filename/content handling |
| MISP health/preview/send/history | Ready in development, not deployed | Candidate queue, readiness/omission reasons, admin-confirmed batch of at most 20, per-event audit outcomes, post-send links, and idempotent client passed Docker parity tests | Validate after immutable deployment; retain review and unpublished-by-default policy |
| MISP population | Partial by design | Sole production MISP event is the only ACTIT event actually sent; deterministic UUID prevents duplicates. Multi-event workflow exists only in development | Do not mirror PostgreSQL; admin deliberately selects and confirms eligible events after deployment |
| Enrichment | Missing live data | Enrichment table contains zero rows | Add controlled enrichment runs/status and make risk/assessment provenance visible |
| ML transparency | Partial | Runtime model and stored metrics endpoint exists | Show individual quality gates, model scope/limitations, inference evidence, and fallback/degraded state |
| Risk scoring | Partial | Deterministic risk factors stored in `raw_reference` | Project factors through API/UI and label score provenance |
| Outlier detection | Partial | 413 sessions and Isolation Forest/fallback metadata exist | Explain features, sample sufficiency, detector choice, and event relationship |
| Demo/readiness dataset | Ready in development, not deployed | Private disposable SQLite fixture with fixed external/internal evidence, Storyline/risk/ATT&CK/STIX/MISP projections and deterministic CLI walkthrough; protected readiness page reads existing live API contracts only | Keep demo synthetic and offline; after a separately approved immutable deployment, verify readiness UI against the release and demonstrate actual pipeline-generated cross-source evidence when available |
| App/API security | Partial in development, not deployed | Isolated two-client rate-limit and Auth/RBAC HTTPS ingress smoke passed; loopback, CSP, firewall, and network separation remain | Real two-user Tailscale fairness remains unverified because only one distinct peer user is online; public ingress is optional |
| SSRF controls | DNS race fixed in development, not deployed | Candidate External Sources pins each socket to a validated public IP while retaining original Host/TLS SNI/certificate checks; 232/232 External Docker tests and 368/368 VPS regression pass | Keep final holistic SSRF/security review and immutable-release validation before public ingress; do not represent this as a live production fix |
| Security scan/remediation | Partial; two open findings | Codex Security Standard scan completed on a clean local source-only checkout matching VPS commit `3500855`; 25 security-sensitive files fully reviewed, not exhaustive | Fix or explicitly accept medium gateway log-growth risk; track low MISP credential-scope issue |
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
- MISP decision: retain selective unpublished sharing, deterministic ACTIT-to-MISP identity, and PostgreSQL authority. The paper supports CTI sharing; OpenCTI informs review/provenance patterns; approved ThreatIntel informs queue/status presentation. ACTIT previews eligibility, permits admin-confirmed batches up to 20, records independent outcomes, and links verified MISP IDs. No automatic mirror or production mutation was introduced.
- Added an isolated synthetic graduation fixture and deterministic `scripts.demo_walkthrough` covering an external advisory, two internal observations, cross-source versus same-pipeline evidence, Storyline, explicit ATT&CK, risk factors, STIX, and unpublished MISP preview. It does not run the collection/ML pipelines or send to MISP; see `docs/graduation-demo.md`.
- Added a protected bilingual System Readiness page at `/system/readiness` using existing health, ML, MISP, and data-summary APIs, with honest limitations for public network, backup/restore, and synthetic data.
- Added rejection-path tests across central mutating routes and admin-only actions, prevented legacy live MISP sends from leaking missing-event existence to analysts, shortened the default token life, and made the frontend proxy discard untrusted forwarding headers while marking HTML/API responses non-cacheable. See `docs/security-hardening-checkpoint.md`.
- After explicit approval, closed the External Sources DNS validation-to-connect race for manual, Telegram, Reddit RSS, and social linked-article fetches without changing the collection architecture. See `docs/security-hardening-checkpoint.md`.
- Verified Serve's live XFF spoof stripping and the candidate Nginx last-hop real-IP behavior, prepared public-IP ACME/TLS edge configurations without activation, and completed focused VPS/Docker checks. Formal remote scan and real ACME issuance remain release gates; see `docs/public-ingress-security.md`.

## Next Task

Resolve and verify bounded gateway web-access log retention in the VPS development worktree, or obtain explicit project-owner acceptance of the medium residual availability risk. Track the low MISP service-key privilege issue separately; do not read or rotate live credentials without an approved procedure. Re-run affected targeted tests and Docker smoke after a fix, then update GO/NO-GO. Public HTTPS stays disabled and optional. Do not deploy to `/opt` without explicit approval.

## Remaining P0 sequence

1. Resolve or explicitly accept the medium gateway availability risk; track low MISP least-privilege work.
2. If a second distinct tailnet user becomes available, repeat live fairness testing without trusting supplied identity headers.
3. After security disposition and explicit approval, stage an immutable VPS release and validate before switching `/opt/cti-platform/current`.
4. Treat public-IP HTTPS, ACME, and firewall changes as separately approved optional work; preserve Tailscale.

## Remaining P1 / deferred

- Optional custom domain and Cloudflare integration after explicit approval and domain availability.
- Broader ATT&CK catalog synchronization beyond the defensible P0 subset.
- Advanced notifications, collaboration workflow, and external organization sharing policies.
- Scale/performance work that is not required for the final P0 demonstration.

## Known blockers and non-blockers

- Non-blocker: no custom domain or public-IP HTTPS; Tailscale is the approved presentation transport for this checkpoint.
- Non-blocker: production MISP still has one event by design; root cause verified. The multi-event workflow is developed but not deployed or exercised against live MISP.
- Non-blocker: the complete backend suite passed in the VPS disposable test environment; production remains Docker/Compose only.
- Non-blocker: the exact Figma Make reference and UI UX Pro Max were available and used for selective guidance.
- Non-blocker with honest limit: no active token-lifetime override, so the candidate's shorter default applies on release. Real two-user tailnet fairness was unavailable; isolated two-client behavior passed without trusting supplied headers.
- Codex Security Standard scan was source-only on a clean exact-commit local checkout, not a VPS runtime scan; its file coverage was partial. Scanner locality alone does not block release, but the medium finding needs disposition.
- Genuine stop boundaries: destructive database/volume migration, paid domain/service purchase, unavailable credentials, irreversible firewall/DNS action, or an external approval requirement.

## Background and scheduled work

None. No unattended process or automation was started during the baseline.

## Rollback and recovery

- Production rollback reference: `/opt/cti-platform/releases/20260914T172623Z-f9d0c31`.
- Source branch reference: `origin/codex/vps-production-integration` at `f9d0c31`.
- Build immutable releases only on the VPS from a validated VPS worktree, preserve the current symlink target, verify health/smoke tests, and switch the `/opt/cti-platform/current` symlink only after validation.
- If a future release fails, restore the previous symlink target and container images without deleting volumes, then verify frontend, backend/database, External Sources, gateway, and MISP health.

## Final pre-deployment verification (2026-09-17/18 UTC)

This dated checkpoint supersedes older public-IP, scan, and release-gate statements above where they conflict. Approved presentation transport is Tailscale; public HTTPS/certificates/ports are optional and were not activated.

- Reviewed VPS code commit: `3500855b8f8f934bc067af41141f32523538ddba` on `codex/actit-final-production`. `/opt/cti-platform/current` still resolves to `/opt/cti-platform/releases/20260914T172623Z-f9d0c31`. No production data, volume, service, symlink, firewall, certificate, or public port was changed.
- Only one distinct Tailscale peer user was online, so a real two-user tailnet fairness test remains **unverified**. Existing live Serve XFF stripping and the isolated two-client test support, but do not replace, that proof.
- Isolated private VPS Compose ingress: ephemeral PostgreSQL, exact candidate Backend/Frontend, and Nginx; no host-published ports or production volumes. Two fixed clients on `172.30.211.0/24`: client A received five registration 201 responses then 429 with `Retry-After`; forged forwarding headers did not evade the limit. Client B registered 201 as server-assigned `viewer` while A was limited. An initial auto-assigned `192.168.64.0/24` test network fell outside the Backend's trusted Docker proxy range and merged client identities; the corrected network matched the production `172.16.0.0/12` boundary. Temporary containers, networks, and self-signed test certificate were removed.
- Auth/RBAC through isolated HTTPS ingress: anonymous `/auth/me` 401; public registration 201 and `viewer`; client role injection 422; viewer login and `/auth/me` 200; viewer admin read/write 403; admin login/read 200.
- Docker parity: Backend image `actit-backend:predeploy-3500855` (`sha256:8ff8c3c11c7a924786ef008037dec006b6b68a90ae39a35382cd8e5295f0d3a0`) passed 18/18 targeted API/rate-limit tests with read-only fixture/report mounts. The first fixture-less harness attempt had four loading errors; rerun passed without code changes. Full VPS disposable-venv Python regression: 371/371. Frontend image `actit-frontend:predeploy-3500855` (`sha256:08ce32e7251f2ac99a13dbf5365b222fe6e2c8edd53aea157e8178664c6bf60f`) passed lint/TypeScript, 116/116 Vitest, and production build. Existing production-env Central Compose rendered with `config --quiet`; no secrets printed or services started. Existing non-failing sklearn model-version and Vite chunk-size warnings remain.
- Codex Security Standard scan `d29ae598-f13a-4766-9351-f217b70a403f` completed on a **clean local source-only checkout** matching the exact VPS commit. No ACTIT install, build, or tests ran on Windows; the scanner did not assess live VPS runtime. Focused coverage was partial: 25 security-sensitive files fully reviewed from 427 inventoried. Report: `C:\Users\ZBOOK\AppData\Local\Temp\codex-security-scans-IuB0I4\actit-security-3500855-37d6da1d4ad0429d8ea65fcef8257683\3500855b8f8f934bc067af41141f32523538ddba_20260917T163151Z__75brnpu\report.md`.
- Medium / CWE-400: `infra/vps/gateway/app.py` appends unauthenticated non-health requests to persistent `gateway_data:/data/web_access.jsonl` without size/retention bounds; web-access sensor reads reject files above 50 MiB. Tailnet-private; source-traced only, no DoS traffic or production log mutation. This is availability/telemetry risk, not an observed outage.
- Low / CWE-250: `infra/vps/scripts/deploy_misp.sh` copies MISP `ADMIN_KEY` into Backend `MISP_API_KEY` instead of a scoped service key. Root-owned private config and MISP network isolation mitigate exposure. Live key and actual account privileges were not read; this is conditional blast radius, not a demonstrated key leak.
- **NO-GO for deployment** until the medium gateway risk is fixed and verified or explicitly accepted by the project owner. Missing second live tailnet user, optional public HTTPS, and scanner locality are documented limitations, not independent blockers. No `/opt` deployment occurred.

### Prepared deployment and rollback (approval required; not executed)

1. On VPS record `hostname`, `pwd`, and `git branch --show-current`; confirm approved commit/clean tree, old `/opt/cti-platform/current` target, healthy services, and root-owned env-file presence without printing secrets. Stage a new immutable release under `/opt/cti-platform/releases/<timestamp>-<commit>` from the approved VPS commit. Render Central and External Compose configurations with existing env files. Do not run first-install/bootstrap scripts.
2. Run `<new-release>/infra/vps/scripts/deploy_central_stack.sh <new-release>` only after checking its `pg_dump -Fc`/restore-list backup, rollback image tags, and deployment state. Verify Backend/database, Frontend `/healthz`, tailnet auth/RBAC/rate limits, readiness, gateway, External, and MISP health.
3. For the External DNS-pinning change, record the previous External image ID/tag and exact Compose project/network/volume settings. Update only `external-sources` with `docker compose --env-file /etc/cti-platform/vps.env -f <new-release>/infra/vps/compose.yaml build external-sources` then `up -d --no-deps external-sources`; verify its health and existing schedules. Preserve all volumes and automations. Atomically switch `/opt/cti-platform/current` only after all services pass.
4. If checks fail, run `<new-release>/infra/vps/scripts/rollback_central_stack.sh /opt/cti-platform/deployments/<timestamp>`, restore the recorded previous External image/tag and prior release symlink, and recheck Frontend, Backend/database, External, gateway, Tailscale, and MISP. Retain the verified PostgreSQL dump; never restore the database automatically or delete volumes.
