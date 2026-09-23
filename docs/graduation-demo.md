# ACTIT defense-ready isolated full-stack demo

This browser demo is a disposable development environment for the graduation defense. It uses the current Backend, Frontend, Gateway, PostgreSQL schema, ML transparency, analyst-controlled CVE enrichment, Reviews adapter, and Web Access integration from `codex/actit-final-production`. It does not read from or write to production.

Every page carries an **Isolated synthetic defense environment** banner. All event titles also use the `[DEMO]` prefix. The records are deterministic fixtures, not collected observations or model-generated claims.

## Status vocabulary

| Label | Meaning in this guide |
| --- | --- |
| Deployed | Verified in the existing immutable production release. It does not imply that later development changes are live. |
| Development-verified | Implemented and tested in `codex/actit-final-production`, but not deployed to `/opt/cti-platform`. |
| Synthetic demo | Deterministic disposable data in the isolated `actit-defense-demo` PostgreSQL instance and Gateway volume. |
| Mocked/offline provider | A local contract-compatible provider used without live NVD, MISP delivery, or External collection. |
| Unresolved production behavior | A production observation that this demo does not fix or reclassify. |

ML transparency, analyst-controlled CVE enrichment, Web Access checkpoint-aware health, and bounded Reviews lifecycle projection are development-verified and included here. Stored NVD-like enrichment, Reviews artifacts, and MISP connectivity are offline demo evidence. The production scheduled External `state=failed` incident and historical Gateway OOM/`curl 52` incident remain separate and unresolved.

## Safety model

- Compose project name is fixed to `actit-defense-demo`.
- Only Frontend is published, on loopback `127.0.0.1:19090` by default.
- Backend, PostgreSQL, Gateway, and the offline provider have no host ports.
- The core service network is Docker-internal. After image preparation, the core demo requires no Internet access.
- PostgreSQL uses tmpfs. Gateway uses one project-scoped disposable volume.
- No production network, volume, secret, host path, MISP instance, External state, timer, Tailscale route, or `/opt/cti-platform` path is referenced.
- The offline provider rejects all MISP delivery mutations. The demo Frontend also removes live MISP send controls and external MISP links.
- No scheduled External collection is configured or started.
- `scripts/defense_demo.sh stop` targets only the exact demo project and removes only its disposable volume and networks.

## Prerequisites and preflight

Run from the development worktree:

```bash
cd /home/alaaldeen/.codex-worktrees/actit-final-production
git branch --show-current
./scripts/defense_demo.sh preflight
```

The branch check must print `codex/actit-final-production`. Preflight rejects a busy loopback port and any rendered Compose reference to known production paths, networks, or volumes.

The first preparation needs registry/package access to build current images and obtain the pinned Playwright validation image. Prepare once before the defense:

```bash
./scripts/defense_demo.sh prepare
```

After preparation, start the core demo offline:

```bash
./scripts/defense_demo.sh start
```

For a one-command development rebuild and start when Internet access is available:

```bash
./scripts/defense_demo.sh start-build
```

Open `http://127.0.0.1:19090`. Set a different loopback port only when necessary:

```bash
ACTIT_DEMO_PORT=19091 ./scripts/defense_demo.sh start
```

## Demo accounts

These credentials exist only in the disposable demo database.

| Role | Username | Password |
| --- | --- | --- |
| Viewer | `demo-viewer` | `ViewerDemo!2026` |
| Analyst | `demo-analyst` | `AnalystDemo!2026` |
| Administrator | `demo-admin` | `AdminDemo!2026` |

## Deterministic event IDs

| Purpose | Event ID |
| --- | --- |
| External advisory, CVE, explicit ATT&CK, STIX, MISP preview | `demo-external-0001` |
| Internal cross-source peer | `demo-internal-0001` |
| Internal same-pipeline follow-up | `demo-internal-0002` |
| Rule-based ATT&CK analyst-review candidate | `demo-external-attack-candidate` |
| Explainable Web Access outlier | `demo-internal-web-access` |
| Dionaea integration fixture | `demo-internal-dionaea` |

The reserved documentation values `command.example` and `192.0.2.0/24` prevent the fixture from representing a real organization or target.

## Defense walkthrough

Use English for the fixed labels below, or switch to Arabic to demonstrate localization and RTL support.

1. Sign in as `demo-viewer`. Point out the synthetic-environment banner, Dashboard counts, and System Readiness evidence. Attempt `/admin` to demonstrate both UI and API denial for a viewer.
2. Open Global Search and search for `CVE-2026-1234`. Pivot to `demo-external-0001` and show source provenance, severity, deterministic risk, complete observables, entities, and relationships.
3. On Event Details, show the stored offline NVD-like result: CVSS 9.8, CVSS 3.1, critical severity, CWE-78/CWE-20, stored timestamp, provider identity, and explainable risk factors. Do not run or refresh NVD enrichment.
4. Download STIX 2.1 for the event. Explain that the bundle contains portable ACTIT objects, including the fictional vulnerability, and is generated without sharing to MISP.
5. Sign in as `demo-analyst`. Open Threat Storyline for `demo-external-0001`. Show chronology, External provenance, the clearly synthetic External-to-Internal `shared_indicator` correlation, its internal peer, and the distinction from the internal-only correlation.
6. Open `demo-external-attack-candidate`. Show `T1053 Scheduled Task/Job` as an **Automated candidate for review**, not a confirmed technique. Contrast it with explicit `T1059.001` on the primary event.
7. Open Outliers. Show the `demo-internal-web-access` session and its allowlisted explanation factors: alert volume, maximum rule severity, rule diversity, failed actions, and credential attempts. Raw source IP and raw feature dictionaries are not projected.
8. Open Analysis. Show runtime state, primary/fallback availability, all nine quality gates, stored held-out and unique-unseen metrics, safe in-process counters, and limitations. State explicitly that saved metrics are offline evidence, not live production accuracy.
9. Open Reviews with the default `available` mode and show `[DEMO] Analyst review candidate`. In another terminal run `./scripts/defense_demo.sh reviews empty`, refresh, and show the normal **No reviews yet** empty state instead of service unavailable. Restore with `./scripts/defense_demo.sh reviews available`.
10. Open Internal Sources → Web Access. Show healthy configuration/reachability and the readable fixture. An analyst may confirm one pull in this isolated environment; it processes only the disposable Gateway fixture and preserves ACK/checkpoint semantics. It never reaches production.
11. Sign in as `demo-admin`. Open Administration to show viewer, analyst, and admin accounts plus audit evidence. Then open MISP.
12. On MISP, show the non-delivery banner, ready candidate, deterministic unpublished preview, transferable CVE attribute, omission of reserved/non-actionable values, and delivery history. The live send control is absent even for the administrator and the offline provider rejects direct delivery attempts.

This order demonstrates RBAC, readiness, investigation, CTI provenance/correlation, enrichment, analytics transparency, interoperability, and analyst-controlled sharing without relying on production or the Internet.

## Automated defense smoke

Run after startup:

```bash
./scripts/defense_demo.sh smoke
```

The pinned Playwright container joins only the internal demo network. It validates viewer denial, all three accounts, Dashboard/readiness contracts, search, event details, stored CVE evidence, STIX 2.1, Storyline correlation, risk evidence, ATT&CK candidate behavior, outlier explanation, ML transparency, Reviews available and empty modes, Web Access health/read plus exactly one isolated pull, and MISP preview with no send control. Reviews are restored to `available` when the smoke completes.

## Provider-independent fallback

The core walkthrough never requires a live optional provider:

- NVD: use the stored, explicitly synthetic offline NVD-like result. Never click refresh during the defense.
- MISP: use candidate readiness and deterministic preview. Live delivery is structurally disabled.
- External Sources: do not start collection. Use the seeded accepted record, Reviews contract, and stored CTI projection.
- Reviews: use `reviews available` or `reviews empty`; both states are local and deterministic.
- ML: present the reported fallback or unavailable state honestly, together with offline metrics, quality gates, and limitations. Do not claim live accuracy.
- Internet outage: start only after `prepare`; all core images and validation dependencies are then local.

If any isolated optional adapter is unavailable, continue with the stored event, Storyline, CVE, outlier, ATT&CK, STIX, and MISP preview pages. Do not connect the demo to production as a fallback.

## Status and cleanup

Inspect only this project:

```bash
./scripts/defense_demo.sh status
```

Safe cleanup:

```bash
./scripts/defense_demo.sh stop
```

Cleanup removes only `actit-defense-demo` containers, the two project networks, and `actit-defense-demo_demo_gateway_data`. PostgreSQL is already tmpfs-backed. It does not delete images and cannot target production volumes through this script.

## Known limitations

- The dataset is a deterministic stored projection; it does not claim that collectors, NER, correlation, outlier detection, or enrichment generated these fixture values live.
- The NVD-like result, Reviews adapter, and MISP health endpoint are mocked/offline and visibly labeled through the demo context.
- The isolated Backend does not include the large BERT artifact. It demonstrates the current fallback/unavailable contract and saved offline evidence, not production inference throughput or accuracy.
- The current production scheduled External workflow remains `state=failed` with an unverified exact root cause. The historical Gateway OOM/`curl 52` incident also remains unresolved. Neither is reproduced or fixed by this demo.
- No live MISP delivery, real NVD lookup, scheduled collection, Tailscale route, public ingress, backup/restore, or production deployment is validated here.
