# ACTIT Constitution

## Core Principles

### I. Preserve the Existing System and Ownership Boundaries
ACTIT changes MUST extend the established VPS architecture and service boundaries. Reuse the
existing Backend, Frontend, Gateway, External Sources, Dionaea, Tor, MISP, PostgreSQL,
collectors, pipelines, contracts, and tests; do not create parallel replacements or duplicate
implementations. Existing component ownership and service boundaries MUST be preserved unless a
change is explicitly approved and justified by the relevant specification. New frameworks or
dependencies require demonstrated need and compatibility with the existing architecture.

### II. VPS-Only, Compose-Managed Production
The VPS is ACTIT's sole production runtime, and Docker/Compose remains its production runtime.
Tailscale and existing systemd automation MUST be preserved unless their change is explicitly
approved. Production under `/opt/cti-platform` MUST be inspected read-only first and MUST NOT be
modified, deployed, rolled back, or reconfigured without explicit user approval. End-user access
continues through the existing Frontend and authenticated control paths; diagnostic access does
not create an alternative production deployment.

### III. Authoritative Data and Non-Destructive Operations
PostgreSQL is the authoritative ACTIT datastore. MISP is a selective, analyst-controlled sharing
destination and MUST NOT become a PostgreSQL replica. ACTIT MUST NOT automatically delete,
recreate, reset, restore, or overwrite PostgreSQL, MISP, Docker volumes, Gateway state, External
collection state, or persistent datasets. Data migrations, maintenance, recovery, and rollback
work MUST preserve data by default, state their exact boundaries, and require explicit approval
when they affect production or persistent state.

### IV. Diagnose First; Validate Proportionately
Changes MUST follow verified root cause analysis and use the smallest data-preserving correction.
Health endpoints alone never prove an end-to-end workflow is ready. Prefer existing logs,
evidence, targeted tests, isolated Docker/Compose environments, bounded fixtures, and parity
validation before live execution. Do not repeatedly run heavy, memory-intensive, data-producing,
or externally connected jobs merely to reproduce a failure. Production-affecting live tests require
explicit approval and run only when necessary.

### V. Secure, Evidence-Based Completion
ACTIT MUST preserve RBAC, authenticated control paths, SSRF/DNS protections, rate limiting,
reverse-proxy trust boundaries, safe logging, CSP and security headers, input validation, and
secret isolation. Credentials, passwords, tokens, API keys, environment secrets, and sensitive
production data MUST NOT appear in specifications, commits, logs, reports, or chat output.
Completion claims require recorded evidence; missing verification MUST be stated as unverified,
not inferred. Force-push, destructive `git reset`, destructive `git clean`, and unrelated branch
modification are prohibited.

## Change Planning and Delivery Evidence

Specifications MUST define bounded changes to the existing ACTIT system, never a rebuild from
scratch. Every plan and task MUST identify affected components, data-preservation boundaries,
production impact, validation strategy, rollback considerations where applicable, and the evidence
required for completion. Reuse the established architecture, conventions, and tests.

If documentation conflicts with verified live state, the discrepancy MUST be reported rather than
silently resolved in favor of stale documentation. `IMPLEMENTATION_STATUS.md` is the durable
operational continuation record and MUST be updated after meaningful completed implementation or
verification checkpoints. Dynamic operational facts—including commit hashes, release paths,
container IDs, live row counts, incidents, and current resource limits—belong there or in
feature-specific specifications, never in this constitution.

## Operational Safeguards

External Sources MUST NOT be declared production-ready until its complete applicable lifecycle has
succeeded: collection → durable state/export → Gateway publish/process → successful completion.
Partial lifecycle evidence, connector health, or a successful collection alone is insufficient.

Persistent-state and production actions require an explicit scope, confirmed target, and a
data-preserving execution plan. Isolated test environments MUST use bounded, non-production
fixtures and must not attach production volumes, networks, secrets, or state. Any production
rollback consideration MUST distinguish application rollback from database or data restoration;
the latter is never automatic.

## Governance

This constitution governs ACTIT engineering and takes precedence over conflicting informal
practice. Amendments require a documented rationale, impact review against the principles,
appropriate validation evidence, and an update to this file. Versioning follows semantic intent:
MAJOR for incompatible governance redefinition or removal, MINOR for a new or materially expanded
principle or section, and PATCH for non-semantic clarification. Reviews MUST confirm applicable
architecture, data-preservation, production-safety, security, and evidence requirements before
completion is claimed.

**Version**: 1.0.0 | **Ratified**: 2026-09-21 | **Last Amended**: 2026-09-21
