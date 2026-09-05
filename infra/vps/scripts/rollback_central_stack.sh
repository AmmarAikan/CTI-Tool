#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "rollback_central_stack.sh must run as root" >&2
  exit 1
fi
if [[ $# -ne 1 || ! -s "$1/state.env" ]]; then
  echo "Usage: rollback_central_stack.sh /opt/cti-platform/deployments/<timestamp>" >&2
  exit 1
fi

state_dir=$1
# The state file is generated locally by deploy_central_stack.sh and is root-only.
# shellcheck disable=SC1090
source "${state_dir}/state.env"

central_env=/etc/cti-platform/central.env
integration_env=/opt/cti-platform/clients/backend-integrations.env
misp_env=/opt/cti-platform/clients/misp-client.env
compose=(
  docker compose
  --env-file "${central_env}"
  --env-file "${integration_env}"
  --env-file "${misp_env}"
  -f "${RELEASE_ROOT}/compose.yaml"
  -f "${RELEASE_ROOT}/infra/vps/central.compose.yaml"
)

if [[ -z "${BACKEND_ROLLBACK_IMAGE}" ]]; then
  echo "No previous Backend image was recorded; refusing an incomplete rollback" >&2
  exit 1
fi
docker image tag "${BACKEND_ROLLBACK_IMAGE}" cti-central-backend:current
"${compose[@]}" up -d --no-build --no-deps backend

if [[ -n "${FRONTEND_ROLLBACK_IMAGE}" ]]; then
  docker image tag "${FRONTEND_ROLLBACK_IMAGE}" cti-central-frontend:current
  "${compose[@]}" up -d --no-build --no-deps frontend
else
  "${compose[@]}" stop frontend >/dev/null 2>&1 || true
  "${compose[@]}" rm -f frontend >/dev/null 2>&1 || true
fi

echo "Application containers rolled back. PostgreSQL was not replaced."
echo "Pre-deployment database backup remains at ${DATABASE_BACKUP}."
