#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "deploy_external_worker_client_fix.sh must run as root" >&2
  exit 1
fi

mode=${1:-deploy}
release_root=${2:-}
central_env=/etc/cti-platform/central.env
integration_env=/opt/cti-platform/clients/backend-integrations.env
misp_env=/opt/cti-platform/clients/misp-client.env
vps_env=/etc/cti-platform/vps.env
state_root=/opt/cti-platform/deployments/external-worker-client-fix

read_env_value() {
  local file=$1 key=$2
  sed -n "s/^${key}=//p" "${file}" | tail -n 1
}

set_env_value() {
  local file=$1 key=$2 value=$3
  if grep -q "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    printf '\n%s=%s\n' "${key}" "${value}" >>"${file}"
  fi
}

resolve_runtime() {
  local port
  port=$(read_env_value "${central_env}" CTI_BACKEND_PORT)
  backend_port=${port:-18000}
  mapfile -t backend_ids < <(docker ps --filter "publish=${backend_port}" \
    --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}')
  mapfile -t gateway_ids < <(docker ps --filter 'publish=8088' \
    --filter 'label=com.docker.compose.service=gateway' --format '{{.ID}}')
  [[ ${#backend_ids[@]} -eq 1 && ${#gateway_ids[@]} -eq 1 ]] || {
    echo "Expected exactly one running Backend and Gateway" >&2; exit 1;
  }
  backend_id=${backend_ids[0]}
  project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${backend_id}")
  [[ ${project} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]] || {
    echo "Unable to resolve Backend Compose project" >&2; exit 1;
  }
  export CTI_COMPOSE_PROJECT_NAME=${project}
}

recreate_runtime() {
  local worker_state=$1
  set_env_value "${integration_env}" EXTERNAL_INGESTION_WORKER_ENABLED "${worker_state}"
  vps_compose=(docker compose --env-file "${vps_env}" -f "${release_root}/infra/vps/compose.yaml")
  central_compose=(docker compose --env-file "${central_env}" --env-file "${integration_env}" \
    --env-file "${misp_env}" -f "${release_root}/compose.yaml" \
    -f "${release_root}/infra/vps/central.compose.yaml")
  "${vps_compose[@]}" config --quiet
  "${central_compose[@]}" config --quiet
  "${vps_compose[@]}" up -d --no-build --no-deps --force-recreate gateway
  "${central_compose[@]}" up -d --no-build --no-deps --force-recreate backend
  for endpoint in 'http://127.0.0.1:8088/health' "http://127.0.0.1:${backend_port}/api/v1/health"; do
    ready=false
    for _attempt in $(seq 1 90); do
      if curl --fail --silent --max-time 5 "${endpoint}" >/dev/null 2>&1; then ready=true; break; fi
      sleep 2
    done
    [[ ${ready} == true ]] || { echo "Health check failed: ${endpoint}" >&2; return 1; }
  done
}

if [[ ${mode} == rollback ]]; then
  state_dir=${2:-}
  [[ -s ${state_dir}/state.env ]] || {
    echo "Usage: $0 rollback STATE_DIRECTORY" >&2; exit 1;
  }
  # shellcheck disable=SC1090
  source "${state_dir}/state.env"
  release_root=${RELEASE_ROOT}
  cp -- "${state_dir}/backend-integrations.env" "${integration_env}"
  cp -- "${state_dir}/vps.env" "${vps_env}"
  chmod 0600 "${integration_env}" "${vps_env}"
  bash "${release_root}/infra/vps/scripts/deploy_external_interactive_priority.sh" \
    rollback "${BASE_CHECKPOINT}"
  resolve_runtime
  recreate_runtime "${PREVIOUS_WORKER_STATE}"
  echo "Rollback completed; database rows and Gateway records were not changed."
  exit 0
fi

[[ ${mode} == deploy && -n ${release_root} ]] || {
  echo "Usage: $0 deploy RELEASE_ROOT" >&2; exit 1;
}
for path in "${release_root}/infra/vps/scripts/bootstrap_external_ingestion_drain.sh" \
            "${release_root}/infra/vps/scripts/deploy_external_interactive_priority.sh" \
            "${central_env}" "${integration_env}" "${misp_env}" "${vps_env}"; do
  [[ -s ${path} ]] || { echo "Required input is missing: ${path}" >&2; exit 1; }
done

previous_worker_state=$(read_env_value "${integration_env}" EXTERNAL_INGESTION_WORKER_ENABLED)
case ${previous_worker_state,,} in true|1) previous_worker_state=true;; false|0) previous_worker_state=false;;
  *) echo "Worker state must be explicitly true or false" >&2; exit 1;; esac

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
state_dir=${state_root}/${timestamp}
install -d -o root -g root -m 0700 "${state_dir}"
cp -- "${integration_env}" "${state_dir}/backend-integrations.env"
cp -- "${vps_env}" "${state_dir}/vps.env"
chmod 0600 "${state_dir}"/*.env

bootstrap_log=${state_dir}/bootstrap.log
bash "${release_root}/infra/vps/scripts/bootstrap_external_ingestion_drain.sh" "${release_root}" | tee "${bootstrap_log}"
base_checkpoint=$(sed -n 's/^Checkpoint: //p' "${bootstrap_log}" | tail -n 1)
[[ -s ${base_checkpoint}/state.env ]] || {
  echo "Base deployment checkpoint was not produced" >&2; exit 1;
}

resolve_runtime
# Verify the actual image, not only the release checkout. This catches stale or
# incorrectly rooted Docker build contexts before the worker is enabled.
docker exec "${backend_id}" python -c \
  'from backend.app.integrations.external_control_client import ExternalControlClient, configured_external_control_client; assert isinstance(configured_external_control_client(), ExternalControlClient)'

# The response-signing key appeared in diagnostic output. Rotate both ends as a
# single maintenance action and never print the replacement value.
new_hmac=$(openssl rand -hex 32)
set_env_value "${vps_env}" FEED_RESPONSE_HMAC_SECRET "${new_hmac}"
set_env_value "${integration_env}" EXTERNAL_FEED_HMAC_SECRET "${new_hmac}"

cat >"${state_dir}/state.env" <<EOF
RELEASE_ROOT=${release_root}
BASE_CHECKPOINT=${base_checkpoint}
PREVIOUS_WORKER_STATE=${previous_worker_state}
EOF
chmod 0600 "${state_dir}/state.env"

if ! recreate_runtime "${previous_worker_state}"; then
  echo "Post-rotation startup failed; run rollback below." >&2
  echo "sudo bash ${release_root}/infra/vps/scripts/deploy_external_worker_client_fix.sh rollback ${state_dir}" >&2
  exit 1
fi

resolve_runtime
docker exec "${backend_id}" python -c \
  'from backend.app.integrations.external_control_client import ExternalControlClient, configured_external_control_client; assert isinstance(configured_external_control_client(), ExternalControlClient)'

echo "Deployment healthy. Worker state restored to ${previous_worker_state}."
echo "The failed interactive operation was preserved and was not retried automatically."
echo "Checkpoint: ${state_dir}"
echo "Rollback: sudo bash ${release_root}/infra/vps/scripts/deploy_external_worker_client_fix.sh rollback ${state_dir}"
