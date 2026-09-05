# VPS Production Integration Checkpoint

Last updated: 2026-09-05 (Asia/Riyadh)

## Branch

- Integration branch: `codex/vps-production-integration`
- Base: `origin/cti-result-quality-hardening` at `8f206f3`
- Backend network branch merged through `c076f65`
- Frontend commits preserved from `fd2877f` and `f110d61`

## Completed in source

- Isolated Backend-to-Gateway and Backend-to-External networks integrated.
- Production Frontend source preserved without merging the divergent VPS files.
- Hardened static Frontend container and same-origin API proxy added.
- Pairwise `cti-backend-misp` network and explicit internal HTTP policy added.
- Root-only integration fragments replace the former user-specific handoff.
- Production Compose, pre-deployment database dump, image rollback, and
  Tailscale Serve scripts added.
- VPS-only architecture and operations documentation synchronized.
- Targeted Backend/topology/deployment tests pass.

## Pending before completion

- Run full repository tests and Frontend test/build on the VPS candidate.
- Push the integration branch and create an immutable VPS release.
- Migrate the existing secret file to `/etc/cti-platform/central.env` without
  printing or changing secret values.
- Deploy MISP network, Backend, and Frontend using the runbook.
- Change Tailscale default HTTPS route from Gateway to Frontend.
- Run authenticated end-to-end acceptance, including MISP health, BERT, and
  External Feed `not_modified=true`.
- Verify rollback checkpoint, persistent volumes, timers, and public listeners.

## Safety state

- No production container, database, volume, Tailscale route, or server file was
  changed while preparing this checkpoint.
- The existing VPS Backend and PostgreSQL remain the rollback baseline.
- Do not run a second External Feed pull while another pipeline run is active.
