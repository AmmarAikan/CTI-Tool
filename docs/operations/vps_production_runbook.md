# VPS Production Cutover Runbook

## Invariants

- Run every production command as `root` on the VPS.
- Do not install or run Backend/PostgreSQL/NER on a personal computer.
- Do not run `docker compose down`, remove volumes, or import a second database.
- Keep Funnel disabled and application ports bound to loopback.
- Keep `/etc/cti-platform/*.env` and `/opt/cti-platform/clients/*.env` root-only.
- Preserve the current Backend until a candidate image, database dump, and
  rollback image have been verified.

## Required root-only environment

`/etc/cti-platform/central.env` contains the existing PostgreSQL/JWT/bootstrap
values plus deployment identity and model paths:

```text
CTI_COMPOSE_PROJECT_NAME=cti-backend-20260903-v1
CTI_BACKEND_PORT=18000
CTI_FRONTEND_PORT=18080
CTI_NER_MODEL_DIR=/opt/cti-backend-transfers/20260903-v1/cti-backend-20260903-v1/model
CTI_NER_REPORT_DIR=/opt/cti-backend-transfers/20260903-v1/cti-backend-20260903-v1/reports
```

The same file must retain the existing `POSTGRES_*`, `JWT_SECRET`, and bootstrap
values. Never replace them with example values.

`deploy_stack.sh` generates
`/opt/cti-platform/clients/backend-integrations.env`. `deploy_misp.sh` generates
`/opt/cti-platform/clients/misp-client.env`.

## Candidate release

Create an immutable release directory from the reviewed Git commit, validate
script syntax and Compose rendering, then point `/opt/cti-platform/current` to
it only after the files are complete. Do not edit a release after cutover.

## Ordered cutover

```bash
/opt/cti-platform/current/infra/vps/scripts/provision_backend_networks.sh
/opt/cti-platform/current/infra/vps/scripts/deploy_stack.sh /opt/cti-platform/current
/opt/cti-platform/current/infra/vps/scripts/deploy_misp.sh /opt/cti-platform/current
/opt/cti-platform/current/infra/vps/scripts/deploy_central_stack.sh /opt/cti-platform/current
/opt/cti-platform/current/infra/vps/scripts/configure_tailscale_serve.sh
```

`deploy_central_stack.sh` creates and validates a PostgreSQL custom-format dump,
tags the previous application images, writes a root-only state file under
`/opt/cti-platform/deployments/<UTC timestamp>`, builds Backend and Frontend, and
reconciles only those application services. It never recreates PostgreSQL.

## Rollback

If post-cutover validation fails:

```bash
/opt/cti-platform/current/infra/vps/scripts/rollback_central_stack.sh \
  /opt/cti-platform/deployments/<UTC timestamp>
```

Rollback restores the previous Backend/Frontend images. It does not restore or
replace PostgreSQL automatically. The verified pre-deployment dump path is
recorded in `state.env` for explicit disaster recovery only.

## Acceptance checks

1. `docker compose ps` shows Backend, PostgreSQL, and Frontend healthy.
2. Loopback Backend and Frontend health return HTTP 200.
3. Tailscale HTTPS loads the login page without a browser certificate warning.
4. Login, `/api/v1/auth/me`, dashboard summary, and External Sources render.
5. Gateway, External Control, Dionaea, Host Auth, Web Access, and MISP report
   reachable; Wazuh remains unconfigured.
6. A controlled BERT inference reports the transformer backend.
7. One immediate authenticated External Feed pull reports `not_modified=true`
   and zero processing.
8. No PostgreSQL, Backend, Frontend, Gateway, External Control, or MISP port is
   public.
9. Systemd timers and container restart policies survive a service restart.
