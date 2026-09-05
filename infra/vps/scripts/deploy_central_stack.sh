#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "deploy_central_stack.sh must run as root" >&2
  exit 1
fi

release_root="${1:-/opt/cti-platform/current}"
base_compose="${release_root}/compose.yaml"
production_compose="${release_root}/infra/vps/central.compose.yaml"
central_env=/etc/cti-platform/central.env
integration_env=/opt/cti-platform/clients/backend-integrations.env
misp_env=/opt/cti-platform/clients/misp-client.env

for required in "${base_compose}" "${production_compose}" "${central_env}" "${integration_env}" "${misp_env}"; do
  if [[ ! -s "${required}" ]]; then
    echo "Required deployment file is missing or empty: ${required}" >&2
    exit 1
  fi
done

chmod 0600 "${central_env}" "${integration_env}" "${misp_env}"

read_env_value() {
  local file=$1 key=$2
  sed -n "s/^${key}=//p" "${file}" | tail -n 1
}

project_name=$(read_env_value "${central_env}" CTI_COMPOSE_PROJECT_NAME)
backend_port=$(read_env_value "${central_env}" CTI_BACKEND_PORT)
frontend_port=$(read_env_value "${central_env}" CTI_FRONTEND_PORT)
model_dir=$(read_env_value "${central_env}" CTI_NER_MODEL_DIR)
report_dir=$(read_env_value "${central_env}" CTI_NER_REPORT_DIR)
postgres_volume=$(read_env_value "${central_env}" CTI_POSTGRES_VOLUME)
uploads_volume=$(read_env_value "${central_env}" CTI_UPLOADS_VOLUME)
database_network=$(read_env_value "${central_env}" CTI_DATABASE_NETWORK)
egress_network=$(read_env_value "${central_env}" CTI_EGRESS_NETWORK)
project_name=${project_name:-cti-central}
backend_port=${backend_port:-18000}
frontend_port=${frontend_port:-18080}

if [[ ! "${project_name}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]]; then
  echo "CTI_COMPOSE_PROJECT_NAME is invalid" >&2
  exit 1
fi
if [[ ! "${backend_port}" =~ ^[0-9]+$ || ! "${frontend_port}" =~ ^[0-9]+$ ]]; then
  echo "CTI backend/frontend ports must be numeric" >&2
  exit 1
fi
if [[ ! -s "${model_dir}/model.safetensors" || ! -d "${report_dir}" ]]; then
  echo "The configured NER model or report directory is incomplete" >&2
  exit 1
fi
for volume_name in "${postgres_volume}" "${uploads_volume}"; do
  if [[ -z "${volume_name}" ]] || ! docker volume inspect "${volume_name}" >/dev/null 2>&1; then
    echo "Required existing Docker volume is unavailable" >&2
    exit 1
  fi
done
for network_name in "${database_network}" "${egress_network}"; do
  if [[ -z "${network_name}" ]] || ! docker network inspect "${network_name}" >/dev/null 2>&1; then
    echo "Required existing Central Backend network is unavailable" >&2
    exit 1
  fi
done

compose=(
  docker compose
  --env-file "${central_env}"
  --env-file "${integration_env}"
  --env-file "${misp_env}"
  -f "${base_compose}"
  -f "${production_compose}"
)

"${release_root}/infra/vps/scripts/provision_backend_networks.sh"
"${compose[@]}" config --quiet

mapfile -t db_ids < <(docker ps --filter "label=com.docker.compose.project=${project_name}" --filter "label=com.docker.compose.service=db" --format '{{.ID}}')
if [[ ${#db_ids[@]} -ne 1 ]]; then
  echo "Expected exactly one running PostgreSQL container for ${project_name}; found ${#db_ids[@]}" >&2
  exit 1
fi
db_id=${db_ids[0]}
db_user=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_USER=//p' | tail -n 1)
db_name=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${db_id}" | sed -n 's/^POSTGRES_DB=//p' | tail -n 1)
if [[ -z "${db_user}" || -z "${db_name}" ]]; then
  echo "Unable to determine PostgreSQL database identity from the running container" >&2
  exit 1
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
state_dir="/opt/cti-platform/deployments/${timestamp}"
backup_dir=/opt/cti-platform/backups
install -d -o root -g root -m 0700 "${state_dir}" "${backup_dir}"
backup_file="${backup_dir}/central-predeploy-${timestamp}.dump"
docker exec "${db_id}" pg_dump -Fc -U "${db_user}" -d "${db_name}" >"${backup_file}"
chmod 0600 "${backup_file}"
docker exec -i "${db_id}" pg_restore --list <"${backup_file}" >/dev/null

backend_id=$(docker ps --filter "label=com.docker.compose.project=${project_name}" --filter 'label=com.docker.compose.service=backend' --format '{{.ID}}' | head -n 1)
frontend_id=$(docker ps --filter "label=com.docker.compose.project=${project_name}" --filter 'label=com.docker.compose.service=frontend' --format '{{.ID}}' | head -n 1)
backend_rollback=""
frontend_rollback=""
if [[ -n "${backend_id}" ]]; then
  backend_rollback="cti-central-backend:rollback-${timestamp}"
  docker image tag "$(docker inspect --format '{{.Image}}' "${backend_id}")" "${backend_rollback}"
fi
if [[ -n "${frontend_id}" ]]; then
  frontend_rollback="cti-central-frontend:rollback-${timestamp}"
  docker image tag "$(docker inspect --format '{{.Image}}' "${frontend_id}")" "${frontend_rollback}"
fi

cat >"${state_dir}/state.env" <<EOF
RELEASE_ROOT=${release_root}
PROJECT_NAME=${project_name}
BACKEND_ROLLBACK_IMAGE=${backend_rollback}
FRONTEND_ROLLBACK_IMAGE=${frontend_rollback}
DATABASE_BACKUP=${backup_file}
EOF
chmod 0600 "${state_dir}/state.env"

"${compose[@]}" build backend frontend
"${compose[@]}" up -d --no-deps backend

backend_ready=false
for _attempt in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:${backend_port}/api/v1/health" >/dev/null 2>&1; then
    backend_ready=true
    break
  fi
  sleep 2
done
if [[ "${backend_ready}" != "true" ]]; then
  "${compose[@]}" logs --tail 120 backend >&2
  "${release_root}/infra/vps/scripts/rollback_central_stack.sh" "${state_dir}"
  exit 1
fi

"${compose[@]}" up -d --no-deps frontend
frontend_ready=false
for _attempt in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${frontend_port}/healthz" >/dev/null 2>&1; then
    frontend_ready=true
    break
  fi
  sleep 2
done
if [[ "${frontend_ready}" != "true" ]]; then
  "${compose[@]}" logs --tail 120 frontend >&2
  "${release_root}/infra/vps/scripts/rollback_central_stack.sh" "${state_dir}"
  exit 1
fi

"${compose[@]}" ps
echo "Deployment checkpoint: ${state_dir}"
echo "Verified database backup: ${backup_file}"
