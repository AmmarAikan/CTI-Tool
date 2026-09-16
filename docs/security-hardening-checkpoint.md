# RBAC, session, and reverse-proxy security checkpoint

Scope: development branch only. This review inspected the changed authentication, role checks, legacy MISP send path, session settings, and Nginx configuration. It did not deploy to `/opt`, change the Contabo firewall or Tailscale Serve settings, or perform a final whole-repository Codex Security scan.

## Verified controls and changes

- Every registered protected POST, PUT, PATCH, and DELETE route in the Central FastAPI router is checked for a server-side `require_roles` dependency. A runtime regression then sends anonymous and viewer requests to every such route and expects 401/403. Public bootstrap, register, and login are the explicit exceptions. A second regression denies analyst requests to every admin-only mutation. The separate External Sources service retains its own authorization tests.
- The legacy `POST /api/v1/events/{event_id}/misp` path still permits analyst dry-runs, but its live-send admin check now occurs before event lookup. This prevents an analyst from distinguishing missing event IDs on an operation they cannot execute. The newer reviewed MISP workflow remains unchanged.
- The default bearer-token lifetime is reduced from 480 to 120 minutes; `ACCESS_TOKEN_MINUTES` remains an explicit deployment override. Tests verify the issued token's expiry interval. The frontend still keeps the token in per-tab sessionStorage and clears it on logout and backend 401, preserving current refresh behavior.
- Nginx no longer appends an incoming `X-Forwarded-For` chain. It sets XFF and X-Real-IP to its observed peer and drops `Forwarded` before proxying. This prevents an external caller from selecting the first XFF address used by ACTIT's in-process login/register limiter. API responses now inherit `Cache-Control: no-store`; existing immutable static-asset caching and CSP remain intact.

## Validation

- Targeted RBAC/session tests: 3/3 on the VPS and in the isolated backend Docker candidate.
- Full Python regression: 363/363 on the VPS disposable test venv.
- Frontend candidate Docker build: TypeScript, 116/116 Vitest tests, and production build passed.
- Isolated backend + Nginx containers ran on a temporary internal Docker network without host ports or production volumes. Nginx returned `/healthz` 200, HTML CSP and `no-store`, API `no-store`, and six registration attempts with six distinct spoofed XFF values yielded five 201 responses followed by 429. The temporary containers/network were removed afterward.

## Residual boundaries before a public release

- Tailscale Serve terminates HTTPS before the loopback frontend. Its identity headers are documented as spoof-stripped for tailnet traffic, but ACTIT does not use them for application auth or rate limiting. Replacing XFF with Nginx's observed peer may group multiple tailnet users under one rate-limit key. Measure this on a candidate release and design a trusted, explicit client identity if it causes availability problems; do not restore untrusted XFF. See [Tailscale Serve identity headers](https://tailscale.com/docs/features/tailscale-serve).
- The effective production `ACCESS_TOKEN_MINUTES` override was not inspected or changed; check it safely before an immutable deployment. Existing bearer tokens cannot be revoked individually before expiry; deactivating the user immediately blocks use because each request rechecks the database. A stronger revocation/session model would be a separate design choice, not part of this incremental patch.
- In-process rate limits are per backend process and reset on restart. They are not a distributed public-edge defense. Public-IP ingress, TLS/HSTS, firewall exposure, backup/restore, and a final SSRF/Codex Security assessment remain separate P0 release gates.
- The desktop Codex Security diff-scan tool accepts a local target path, while this branch is authoritative only on the Contabo VPS. A formal plugin scan was not run against a stale Windows checkout. This checkpoint is a manual, scope-limited source review plus measured tests, not a sealed scan result.
