#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "configure_tailscale_serve.sh must run as root" >&2
  exit 1
fi

frontend_port=${CTI_FRONTEND_PORT:-18080}
if ! tailscale status --json >/dev/null; then
  echo "Tailscale is not connected" >&2
  exit 1
fi
if ! curl --fail --silent "http://127.0.0.1:${frontend_port}/healthz" >/dev/null; then
  echo "Frontend is not healthy on loopback port ${frontend_port}" >&2
  exit 1
fi

# The default tailnet HTTPS endpoint is the only end-user entry point.
# Existing non-default endpoints remain private diagnostics/integration paths.
tailscale serve --bg --https=443 "http://127.0.0.1:${frontend_port}"
tailscale serve --bg --https=8443 https+insecure://127.0.0.1:8443
tailscale serve --bg --https=8444 http://127.0.0.1:8090
tailscale serve --bg --https=8445 http://127.0.0.1:8088
tailscale serve status
