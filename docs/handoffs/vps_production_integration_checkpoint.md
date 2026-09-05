# VPS Production Integration Checkpoint

Last updated: 2026-09-06 (Asia/Riyadh)

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
- Existing PostgreSQL/upload Volumes and database/egress networks are declared
  as mandatory external resources so cutover cannot create an empty database.
- Frontend container build requires TypeScript lint, Vitest, and production
  build to pass before an image is created.
- VPS-only architecture and operations documentation synchronized.
- Targeted Backend/topology/deployment tests pass.
- VPS candidate tests pass by service boundary: Central Backend 93, External
  Sources 191, and Frontend 13 plus TypeScript and production build.

## Verified production state

- The reviewed branch is pushed and the active immutable release is
  `/opt/cti-platform/releases/20260905T222700Z-5d4991d`.
- Root-only Central, Gateway, External Control, and MISP environment fragments
  are in place; no secret value is committed or printed by the runbook.
- Backend, PostgreSQL, Frontend, Gateway, External Sources, and MISP Core report
  healthy. Wazuh remains deliberately unconfigured.
- The Frontend image was rebuilt from `5d4991d`; TypeScript, 13 Vitest tests,
  and the production build passed before the container was replaced.
- Tailscale Serve is tailnet-only: HTTPS 443 serves the Frontend, 8443 serves
  MISP, 8444 serves External Control, and 8445 serves the Gateway. Funnel is
  disabled.
- Authenticated end-to-end checks through the Frontend proxy passed for
  `/auth/me`, dashboard, model status, all configured integrations, and MISP.
  The Transformer model is loaded as the primary runtime.
- The long External Feed run completed with 13,939 collected, 136 processed,
  136 stored, and zero failed. The one immediate verification pull then
  returned `not_modified=true` with all four counts equal to zero.
- PostgreSQL and uploads still use the transferred external Volumes
  `cti-backend-20260903-v1_database` and
  `cti-backend-20260903-v1_uploads`; PostgreSQL was not recreated.
- Pairwise network membership is enforced for Backend-to-Gateway,
  Backend-to-External, Backend-to-MISP, and Frontend-to-Backend. The Frontend
  alone also joins the loopback ingress network.
- Central Backend, Frontend, Gateway, External Control, and MISP published
  ports are bound to `127.0.0.1` only.
- A Frontend rollback image and root-only state file were saved under
  `/opt/cti-platform/deployments/20260905T223009Z-frontend`.

## Safety state

- Backend and PostgreSQL were not restarted for the Frontend timeout fix.
- The transferred PostgreSQL and uploads Volumes remain the persistence
  anchors; prior release and rollback images remain available.
- Do not run a second External Feed pull while another pipeline run is active.

## Continuation note (2026-09-06 01:40 Asia/Riyadh)

The production cutover is complete. The only in-progress operation at this
checkpoint is the normal server-side External Sources collection/publish job
started automatically when its persistent systemd timer was re-enabled. This
is not a Central Backend/BERT pull and does not make the deployment incomplete.
Do not stop it, restart Docker, or start a duplicate collection.

The next operator should only:

1. Check `systemctl is-active cti-external-collection.service` until it reports
   `inactive` or `failed`; do not poll the Central pull endpoint.
2. If inactive, inspect the last sanitized journal lines and confirm the publish
   completed, then verify `cti-external-collection.timer` is enabled/active and
   has a future trigger in `systemctl list-timers`.
3. If failed, diagnose the unit and External Sources logs without restarting
   Backend, PostgreSQL, or deleting any Volume.

Do not repeat the immediate External Feed verification: run
`804ea504-a93e-4778-a936-a07b0fb87568` already proved
`not_modified=true` with zero collected, processed, stored, and failed counts.
Runtime code is commit `5d4991d`; documentation head is `05f10e6` on
`codex/vps-production-integration`. The active release, rollback checkpoint,
and previous release are recorded above and on the VPS.
