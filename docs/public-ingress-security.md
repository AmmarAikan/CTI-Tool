# Public ingress security checkpoint

2026-09-16; VPS development branch only. No `/opt`, production data, firewall, Serve, public listener, or certificate change.

## Verified rate-limit boundary

- Live read-only Serve GET returned 200. Production frontend logged Docker peer `172.25.0.1` and XFF `100.91.28.22`. A forged XFF `203.0.113.9` was removed by Serve: the log still showed only `100.91.28.22`.
- The prior frontend candidate overwrote XFF with the Docker gateway, potentially putting every tailnet user in one login/register bucket. The revised candidate trusts only a Docker-local forwarding peer (`172.16.0.0/12`), selects the last forwarded address, and sends a single resolved address to FastAPI. The backend now accepts forwarded identity only from loopback or that Docker range, not from Python's broader `is_private` classification; limiter keys remain hashed.
- Isolated Nginx on loopback `19081` logged `172.17.0.1` without XFF and `100.91.28.22` for `203.0.113.9, 100.91.28.22`. Test container removed. This proves chain selection, not real multi-client fairness. Confirm with two distinct tailnet clients before release; tagged devices lack Tailscale user headers.
- The frontend must stay loopback-only. The public edge must overwrite XFF and remove Tailscale identity headers. A new direct mapping or compromised same-host container invalidates this trust boundary.

## Public-IP HTTPS candidate; not active

- `infra/vps/public-edge-acme.conf` serves only ACME challenges on the public IP and returns 404 otherwise. `infra/vps/public-edge.conf` binds only `169.58.249.3:80/443`, proxies to loopback frontend, sanitizes identity/forwarding headers, limits requests, and specifies TLS 1.2/1.3 and short initial HSTS.
- Host Nginx and Certbot are absent. There is no trusted IP certificate. Certbot 5.4+ supports the short-lived IP certificate profile and webroot. Automatic renewal and safe Nginx reload must be demonstrated; no certificate request or port opening was attempted.
- Safe activation order: reviewed immutable release and rollback; HTTP challenge-only listener; narrowly open public 80; staging IP ACME; trusted IP ACME; install TLS edge; verify certificate SAN/chain and local/external HTTPS; prove unattended renewal/reload; then open public 443. Preserve Serve on `100.91.28.22:443`. Do not run the final TLS config before a valid certificate exists.
- The edge Nginx syntax passed inside isolated Docker with a disposable self-signed IP SAN certificate and loopback-substituted listeners. That does not establish public certificate or renewal readiness.

## Review and decision

- Review covered forwarding identity, login/register limiter, loopback/Docker boundary, public header stripping, TLS bootstrap, and prior RBAC/session/SSRF checkpoint evidence. No new feature or production service was enabled.
- VPS focused tests: 16/16 (13 deployment and 3 rate-limit). Docker backend rate-limit tests: 3/3. The deployment suite cannot run inside that backend image because it has no Docker CLI; it passed on the VPS host. Frontend candidate Docker build passed lint, 116/116 Vitest tests, and build. Frontend and TLS-edge Nginx configs passed isolated syntax tests. `git diff --check` passed.
- Codex Security Standard scan was attempted on the authoritative VPS path and returned `Scan target must be an absolute local directory path.` No formal report was completed, and no stale Windows checkout was substituted.
- Release decision: **NO-GO** for public exposure or `/opt` cutover. Gates: supported remote formal scan or an explicit decision about its unavailability; two-client fairness and isolated auth/edge smoke; real ACME staging/issuance/renewal; final Docker/Compose regression; reviewed immutable release/rollback. Production remains private and unchanged.

References: [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve), [Nginx realip](https://nginx.org/en/docs/http/ngx_http_realip_module.html), [Certbot IP certificates](https://letsencrypt.org/2026/03/11/shorter-certs-certbot).
