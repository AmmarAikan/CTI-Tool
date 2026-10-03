#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "deploy_manual_source_classification.sh must run as root" >&2
  exit 1
fi

mode=${1:-deploy}
release_root=${2:-}
central_env=/etc/cti-platform/central.env
integration_env=/opt/cti-platform/clients/backend-integrations.env
misp_env=/opt/cti-platform/clients/misp-client.env
vps_env=/etc/cti-platform/vps.env
state_root=/opt/cti-platform/deployments/manual-source-classification

read_env_value() { sed -n "s/^${2}=//p" "${1}" | tail -n 1; }

resolve_runtime() {
  backend_port=$(read_env_value "${central_env}" CTI_BACKEND_PORT); backend_port=${backend_port:-18000}
  frontend_port=$(read_env_value "${central_env}" CTI_FRONTEND_PORT); frontend_port=${frontend_port:-18080}
  mapfile -t backend_ids < <(docker ps --filter "publish=${backend_port}" --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}')
  mapfile -t frontend_ids < <(docker ps --filter "publish=${frontend_port}" --filter 'label=com.docker.compose.service=frontend' --format '{{.ID}}')
  mapfile -t external_ids < <(docker ps --filter 'publish=8090' --filter 'label=com.docker.compose.service=external-sources' --format '{{.ID}}')
  [[ ${#backend_ids[@]} -eq 1 && ${#frontend_ids[@]} -eq 1 && ${#external_ids[@]} -eq 1 ]] || {
    echo "Expected exactly one running Backend, frontend, and External Sources container" >&2; exit 1;
  }
  backend_id=${backend_ids[0]}; frontend_id=${frontend_ids[0]}; external_id=${external_ids[0]}
  central_project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${backend_id}")
  vps_project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${external_id}")
  [[ ${central_project} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ && ${vps_project} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]] || {
    echo "Unable to resolve running Compose projects" >&2; exit 1;
  }
  mapfile -t db_ids < <(docker ps --filter "label=com.docker.compose.project=${central_project}" --filter 'label=com.docker.compose.service=db' --format '{{.ID}}')
  [[ ${#db_ids[@]} -eq 1 ]] || { echo "Expected exactly one project database" >&2; exit 1; }
  db_id=${db_ids[0]}
  db_user=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_USER=//p' | tail -1)
  db_name=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_DB=//p' | tail -1)
  [[ -n ${db_user} && -n ${db_name} ]] || { echo "Unable to resolve database identity" >&2; exit 1; }
  export CTI_COMPOSE_PROJECT_NAME=${central_project}
}

compose_runtime() {
  vps_compose=(docker compose --project-name "${vps_project}" --env-file "${vps_env}" -f "${release_root}/infra/vps/compose.yaml")
  central_compose=(docker compose --project-name "${central_project}" --env-file "${central_env}" --env-file "${integration_env}" \
    --env-file "${misp_env}" -f "${release_root}/compose.yaml" -f "${release_root}/infra/vps/central.compose.yaml")
}

preflight_idle() {
  if systemctl is-active --quiet cti-external-collection.service; then
    echo "A scheduled External collection is running; deployment refused" >&2; return 1
  fi
  local active_claims jobs_file
  active_claims=$(docker exec "${db_id}" psql -X -U "${db_user}" -d "${db_name}" -Atc \
    "SELECT count(*) FROM external_ingestion_operations WHERE claim_token IS NOT NULL AND (lease_expires_at IS NULL OR lease_expires_at > CURRENT_TIMESTAMP);")
  [[ ${active_claims} == 0 ]] || { echo "An ingestion operation has a live claim; deployment refused" >&2; return 1; }
  set -a
  # shellcheck disable=SC1090
  source "${vps_env}"
  set +a
  jobs_file=$(mktemp /run/cti-manual-source-jobs.XXXXXX)
  curl --fail --silent --show-error --max-time 20 -H "Authorization: Bearer ${EXTERNAL_CONTROL_TOKEN}" \
    'http://127.0.0.1:8090/api/v1/external-sources/jobs?limit=100' >"${jobs_file}"
  if ! python3 - "${jobs_file}" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
active = [item.get("job_id") for item in value.get("jobs", [])
          if item.get("state") in {"queued", "running", "cancellation_requested"}]
if active:
    raise SystemExit("External collection jobs are active; deployment refused")
PY
  then
    rm -f -- "${jobs_file}"
    return 1
  fi
  rm -f -- "${jobs_file}"
}

wait_health() {
  local endpoint=$1 ready=false
  for _attempt in $(seq 1 90); do
    if curl --fail --silent --max-time 5 "${endpoint}" >/dev/null 2>&1; then ready=true; break; fi
    sleep 2
  done
  [[ ${ready} == true ]] || { echo "Post-deployment health failed: ${endpoint}" >&2; return 1; }
}

wait_container_health() {
  local container_id=$1 ready=false status
  for _attempt in $(seq 1 60); do
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")
    if [[ ${status} == healthy || ${status} == running ]]; then ready=true; break; fi
    [[ ${status} != unhealthy && ${status} != exited && ${status} != dead ]] || break
    sleep 2
  done
  [[ ${ready} == true ]] || { echo "Tor container did not become healthy" >&2; return 1; }
}

if [[ ${mode} == rollback ]]; then
  state_dir=${2:-}
  [[ -s ${state_dir}/state.env ]] || { echo "Usage: $0 rollback STATE_DIRECTORY" >&2; exit 1; }
  # shellcheck disable=SC1090
  source "${state_dir}/state.env"
  release_root=${RELEASE_ROOT}
  central_project=${CENTRAL_PROJECT}
  vps_project=${VPS_PROJECT}
  backend_port=${BACKEND_PORT}
  frontend_port=${FRONTEND_PORT}
  export CTI_COMPOSE_PROJECT_NAME=${central_project}
  compose_runtime
  docker image tag "${EXTERNAL_ROLLBACK_IMAGE}" cti-external-sources:1.0.0
  docker image tag "${BACKEND_ROLLBACK_IMAGE}" cti-central-backend:current
  docker image tag "${FRONTEND_ROLLBACK_IMAGE}" cti-central-frontend:current
  "${vps_compose[@]}" up -d --no-build --no-deps --force-recreate external-sources
  "${central_compose[@]}" up -d --no-build --no-deps --force-recreate backend frontend
  wait_health 'http://127.0.0.1:8090/api/v1/external-sources/health'
  wait_health "http://127.0.0.1:${backend_port}/api/v1/health"
  wait_health "http://127.0.0.1:${frontend_port}/healthz"
  echo "Rollback completed; database, source state, and Gateway records were not modified."
  exit 0
fi

[[ ${mode} == deploy && -n ${release_root} ]] || { echo "Usage: $0 deploy RELEASE_ROOT" >&2; exit 1; }
for path in "${release_root}/Dockerfile.external" "${release_root}/compose.yaml" \
            "${release_root}/infra/vps/compose.yaml" "${release_root}/infra/vps/central.compose.yaml" \
            "${central_env}" "${integration_env}" "${misp_env}" "${vps_env}"; do
  [[ -s ${path} ]] || { echo "Required input is missing: ${path}" >&2; exit 1; }
done

resolve_runtime
compose_runtime
"${vps_compose[@]}" config --quiet
"${central_compose[@]}" config --quiet
preflight_idle

python_bin=/opt/cti-platform/src/cti-platform/.venv/bin/python
[[ -x ${python_bin} ]] || { echo "Production test interpreter is unavailable" >&2; exit 1; }
(
  cd "${release_root}"
  PYTHONWARNINGS=ignore "${python_bin}" -m unittest discover -s tests/external_sources -p 'test_*.py' -q
)

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
state_dir=${state_root}/${timestamp}
install -d -o root -g root -m 0700 "${state_dir}"
external_rollback=cti-external-sources:manual-source-rollback-${timestamp}
backend_rollback=cti-central-backend:manual-source-rollback-${timestamp}
frontend_rollback=cti-central-frontend:manual-source-rollback-${timestamp}
docker image tag "$(docker inspect --format '{{.Image}}' "${external_id}")" "${external_rollback}"
docker image tag "$(docker inspect --format '{{.Image}}' "${backend_id}")" "${backend_rollback}"
docker image tag "$(docker inspect --format '{{.Image}}' "${frontend_id}")" "${frontend_rollback}"
cat >"${state_dir}/state.env" <<EOF
RELEASE_ROOT=${release_root}
CENTRAL_PROJECT=${central_project}
VPS_PROJECT=${vps_project}
BACKEND_PORT=${backend_port}
FRONTEND_PORT=${frontend_port}
EXTERNAL_ROLLBACK_IMAGE=${external_rollback}
BACKEND_ROLLBACK_IMAGE=${backend_rollback}
FRONTEND_ROLLBACK_IMAGE=${frontend_rollback}
EOF
chmod 0600 "${state_dir}/state.env"
rollback_command="sudo bash ${release_root}/infra/vps/scripts/deploy_manual_source_classification.sh rollback ${state_dir}"
trap 'echo "Deployment did not complete. Rollback: ${rollback_command}" >&2' ERR

"${vps_compose[@]}" build external-sources
"${central_compose[@]}" build backend frontend

# Close the race between the initial checks and container replacement. Once the
# second check succeeds, stop the writers before any new job or claim can start.
resolve_runtime
preflight_idle
compose_runtime
"${vps_compose[@]}" stop external-sources
"${central_compose[@]}" stop backend frontend
"${vps_compose[@]}" up -d --no-build --no-deps --force-recreate tor
tor_id=$(docker ps --filter "label=com.docker.compose.project=${vps_project}" --filter 'label=com.docker.compose.service=tor' --format '{{.ID}}')
[[ -n ${tor_id} && ${tor_id} != *$'\n'* ]] || { echo "Expected exactly one Tor container" >&2; exit 1; }
wait_container_health "${tor_id}"
"${vps_compose[@]}" up -d --no-build --no-deps external-sources
"${central_compose[@]}" up -d --no-build --no-deps backend frontend

wait_health 'http://127.0.0.1:8090/api/v1/external-sources/health'
wait_health "http://127.0.0.1:${backend_port}/api/v1/health"
wait_health "http://127.0.0.1:${frontend_port}/healthz"

external_id=$(docker ps --filter 'publish=8090' --filter 'label=com.docker.compose.service=external-sources' --format '{{.ID}}')
backend_id=$(docker ps --filter "publish=${backend_port}" --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}')
docker exec "${external_id}" python -c \
  'import os, socket; from backend.app.pipeline.ingestion.external.manual_source.adapters import DarkWebManualAdapter; assert DarkWebManualAdapter.valid_candidate_url("http://" + "a" * 56 + ".onion/"); s=socket.create_connection((os.environ["TOR_PROXY_HOST"], int(os.environ["TOR_PROXY_PORT"])), timeout=5); s.close()'
docker exec "${backend_id}" python -c \
  'from backend.app.core.config import get_settings; assert get_settings().external_control_configured'

trap - ERR
echo "Deployment healthy. Manual source classification is active; worker configuration was preserved."
echo "Checkpoint: ${state_dir}"
echo "Rollback: ${rollback_command}"
