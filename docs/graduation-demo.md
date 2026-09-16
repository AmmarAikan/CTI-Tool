# Graduation demonstration and readiness

This is a deliberately isolated development-only walkthrough. It does not seed the running ACTIT deployment, PostgreSQL, MISP, or any existing pipeline. Do not present these synthetic records as collected observations or trained-model output.

## On the Contabo VPS development worktree

From `/home/alaaldeen/.codex-worktrees/actit-final-production`:

```bash
hostname
pwd
git branch --show-current
.venv/bin/python -m scripts.demo_walkthrough
```

The command creates a private temporary SQLite database, runs existing ACTIT storyline, ATT&CK, STIX, and MISP payload projections, prints a deterministic JSON walkthrough, then removes the temporary database. It makes no HTTP request and never calls MISP send. For inspection of the fixture itself, `.venv/bin/python -m scripts.create_demo_dataset` prints a private temporary SQLite path; remove that disposable directory when done. Neither command is a production dependency.

The fixed scenario contains an external advisory, two internal host-auth observations, the reserved `command.example` domain, and a fictional CVE. It has one external-to-internal correlation and one internal-only correlation. The external Storyline shows the cross-source link, chronological milestones, manually specified demonstration risk factors, and explicit ATT&CK ID `T1059.001`. STIX export demonstrates structural interoperability. MISP preview is unpublished with organization-only distribution; the reserved domain is excluded as non-actionable. No live MISP event is created.

This fixture seeds the *stored CTI projection*, not source collection, preprocessing, NER training/inference, enrichment, risk computation, or correlation inference. The values are fixed to exercise the already implemented analyst views and contracts. A real cross-source claim still requires evidence collected through the live pipelines.

## System Readiness UI

The protected `/system/readiness` page is an incremental ACTIT page, linked under Operations. It reads only existing same-origin health, ML, and dashboard summary APIs. It distinguishes unconfigured, unreachable, degraded, and healthy service states; shows model quality gates separately from whether a model loads; and counts external/internal records without claiming that those counts prove cross-source correlation. MISP connectivity is not publication or delivery assurance. This page uses real current ACTIT data only; no demo fixture can appear there.

The page does not test public-IP reachability, TLS certificate trust, firewall policy, backup/restore, incident response, or actual end-to-end MISP sharing. Those checks remain separate release gates.

Decision basis: the academic CTI framework justifies internal/external correlation and sharing; OpenCTI informs provenance-first analyst review; the approved ThreatIntel design informs card hierarchy. ACTIT reuses its existing models, routes, tokens, and API contracts rather than importing another architecture or mock production data.
